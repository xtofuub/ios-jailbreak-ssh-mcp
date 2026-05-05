import { randomUUID } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ALL_HOOK_TYPES,
  APPS_LIST_SCRIPT,
  buildAppInfoScript,
  buildLaunchAppScript,
  buildHookScript,
  buildUiTapScript,
  UI_DUMP_SCRIPT
} from "./fridaScripts.js";
import type { HookType, UiMatcher } from "./fridaScripts.js";
import type { SshExecService } from "./sshExecService.js";
import type { ServerConfig } from "./types.js";

export type { HookType, UiMatcher };
export { ALL_HOOK_TYPES };

export interface FridaEvent {
  ts: number;
  type: string;
  [key: string]: unknown;
}

export interface FridaSession {
  id: string;
  target: string;
  hookTypes: HookType[];
  events: FridaEvent[];
  startedAt: number;
  active: boolean;
  abort: AbortController;
}

export interface DetectResult {
  found: boolean;
  binaryPath?: string;
  psBinaryPath?: string;
  connectionMode?: "ssh" | "usb";
  jailbreakType?: "rootless" | "rootful" | "unknown";
  version?: string;
  error?: string;
}

export interface ProcessEntry {
  pid: number;
  name: string;
}

export interface AppEntry {
  bundleId: string;
  name: string;
  bundlePath: string | null;
  dataPath: string | null;
  version: string | null;
  shortVersion: string | null;
}

// Candidate paths — rootless first (Dopamine iOS 15-16, palera1n, Roothide), then rootful
const FRIDA_CANDIDATES: Array<{ frida: string; jailbreakType: "rootless" | "rootful" }> = [
  { frida: "/var/jb/usr/bin/frida", jailbreakType: "rootless" },
  { frida: "/var/roothide/usr/bin/frida", jailbreakType: "rootless" },
  { frida: "/usr/local/bin/frida", jailbreakType: "rootful" },
  { frida: "/usr/bin/frida", jailbreakType: "rootful" }
];

export class FridaService {
  private sessions = new Map<string, FridaSession>();
  private cachedBinaryPath: string | undefined;
  private cachedPsBinaryPath: string | undefined;
  private localPortForward: { localPort: number; close: () => void } | undefined;
  private resolvedConnectionMode: "ssh" | "usb" | undefined;

  constructor(
    private readonly execService: SshExecService,
    private readonly config: ServerConfig
  ) {}

  async detectFrida(): Promise<DetectResult> {
    const configuredMode = (this.config.frida?.connectionMode ?? "auto") as "auto" | "ssh" | "usb";

    // Always require local frida-tools. In SSH mode we connect to frida-server via forwarded TCP.
    const local = await this.detectLocalFridaTools();
    if (!local.found) {
      return {
        found: false,
        connectionMode: configuredMode === "auto" ? undefined : configuredMode,
        error:
          local.error ??
          "Local 'frida' CLI not found. Install frida-tools on this machine (e.g. `pip install frida-tools`)."
      };
    }

    try {
      // Sanity-check connectivity end-to-end.
      const mode = await this.resolveConnectionMode(configuredMode);
      const jailbreakType =
        mode === "ssh" ? await this.detectJailbreakTypeViaSsh() : "unknown";

      return {
        found: true,
        connectionMode: mode,
        binaryPath: this.getLocalFridaBin(),
        psBinaryPath: this.getLocalFridaPsBin(),
        jailbreakType,
        version: local.version
      };
    } catch (err) {
      return {
        found: false,
        connectionMode: configuredMode === "auto" ? undefined : configuredMode,
        error:
          err instanceof Error
            ? `Frida detected locally but cannot connect. ${err.message}`
            : `Frida detected locally but cannot connect.`
      };
    }
  }

  async listProcesses(): Promise<ProcessEntry[]> {
    const args = await this.buildDeviceArgs();
    const result = await this.execLocalFridaPs(args, {
      timeoutMs: this.config.frida?.commandTimeoutMs ?? 30_000
    });

    if (result.code !== 0 && !result.stdout.includes("PID")) {
      throw new Error(
        `frida-ps failed (exit ${result.code}): ${result.stderr.slice(0, 200)}`
      );
    }

    return parseFridaPs(result.stdout);
  }

  async listApps(): Promise<AppEntry[]> {
    const sessionId = randomUUID();
    const scriptPath = await this.writeTempScript(sessionId, APPS_LIST_SCRIPT);

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const baseArgs = await this.buildDeviceArgs();
    const commandArgs = [...baseArgs, "-n", "SpringBoard", "-l", scriptPath, "-q"];
    const timer = setTimeout(() => abort.abort(), 15_000);

    try {
      await this.execLocalFridaStream(
        commandArgs,
        (line) => {
          const event = parseFridaLine(line);
          if (event) {
            events.push(event);
            if (event.type === "apps" || event.type === "done") abort.abort();
          }
        },
        abort.signal
      );
    } finally {
      clearTimeout(timer);
      await this.cleanupLocalTempScript(scriptPath);
    }

    const appsEvent = events.find((e) => e.type === "apps");
    if (appsEvent && Array.isArray(appsEvent.apps)) {
      return appsEvent.apps as AppEntry[];
    }
    throw new Error("Failed to list apps via Frida");
  }

  async getAppInfo(bundleId: string): Promise<FridaEvent[]> {
    const sessionId = randomUUID();
    const scriptPath = await this.writeTempScript(sessionId, buildAppInfoScript(bundleId));

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const baseArgs = await this.buildDeviceArgs();
    const commandArgs = [...baseArgs, "-n", "SpringBoard", "-l", scriptPath, "-q"];
    const timer = setTimeout(() => abort.abort(), 10_000);

    try {
      await this.execLocalFridaStream(
        commandArgs,
        (line) => {
          const event = parseFridaLine(line);
          if (event) {
            events.push(event);
            if (event.type === "app_info" || event.type === "done") abort.abort();
          }
        },
        abort.signal
      );
    } finally {
      clearTimeout(timer);
      await this.cleanupLocalTempScript(scriptPath);
    }

    return events;
  }

  async startTrace(
    target: string,
    hookTypes: HookType[],
    durationMs: number
  ): Promise<FridaEvent[]> {
    const sessionId = randomUUID();
    const script = buildHookScript(hookTypes);
    const scriptPath = await this.writeTempScript(sessionId, script);

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const targetArgs = buildTargetArgs(target);
    const baseArgs = await this.buildDeviceArgs();
    const commandArgs = [...baseArgs, ...targetArgs, "-l", scriptPath, "-q"];

    const timer = setTimeout(() => abort.abort(), durationMs);

    try {
      await this.execLocalFridaStream(
        commandArgs,
        (line) => {
          const event = parseFridaLine(line);
          if (event) {
            const maxEvents = this.config.frida?.maxSessionEvents ?? 5_000;
            if (events.length < maxEvents) events.push(event);
          }
        },
        abort.signal
      );
    } finally {
      clearTimeout(timer);
      await this.cleanupLocalTempScript(scriptPath);
    }

    return events;
  }

  async beginSession(target: string, hookTypes: HookType[]): Promise<string> {
    const sessionId = randomUUID();
    const script = buildHookScript(hookTypes);
    const scriptPath = await this.writeTempScript(sessionId, script);

    const abort = new AbortController();
    const session: FridaSession = {
      id: sessionId,
      target,
      hookTypes,
      events: [],
      startedAt: Date.now(),
      active: true,
      abort
    };
    this.sessions.set(sessionId, session);

    const targetArgs = buildTargetArgs(target);
    const baseArgs = await this.buildDeviceArgs();
    const commandArgs = [...baseArgs, ...targetArgs, "-l", scriptPath, "-q"];
    const maxEvents = this.config.frida?.maxSessionEvents ?? 5_000;

    // Fire-and-forget: stream runs until aborted
    void this.execLocalFridaStream(
        commandArgs,
        (line) => {
          const event = parseFridaLine(line);
          if (event && session.events.length < maxEvents) {
            session.events.push(event);
          }
        },
        abort.signal
      )
      .catch((error) => {
        if (session.events.length < maxEvents) {
          session.events.push({
            ts: Date.now(),
            type: "frida_session_error",
            message: error instanceof Error ? error.message : String(error)
          });
        }
      })
      .finally(() => {
        session.active = false;
        void this.cleanupLocalTempScript(scriptPath);
      });

    return sessionId;
  }

  pollSession(sessionId: string, clearAfter = false): FridaEvent[] {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`No session: ${sessionId}`);
    const events = [...session.events];
    if (clearAfter) session.events.length = 0;
    return events;
  }

  async endSession(sessionId: string): Promise<FridaEvent[]> {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`No session: ${sessionId}`);
    session.abort.abort();
    this.sessions.delete(sessionId);
    return session.events;
  }

  async dumpUi(target: string): Promise<FridaEvent[]> {
    const sessionId = randomUUID();
    const scriptPath = await this.writeTempScript(sessionId, UI_DUMP_SCRIPT);

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const targetArgs = buildTargetArgs(target);
    const baseArgs = await this.buildDeviceArgs();
    const commandArgs = [...baseArgs, ...targetArgs, "-l", scriptPath, "-q"];

    // UI dump should finish quickly — 10s timeout
    const timer = setTimeout(() => abort.abort(), 10_000);

    try {
      await this.execLocalFridaStream(
        commandArgs,
        (line) => {
          const event = parseFridaLine(line);
          if (event) {
            events.push(event);
            if (event.type === "done") abort.abort();
          }
        },
        abort.signal
      );
    } finally {
      clearTimeout(timer);
      await this.cleanupLocalTempScript(scriptPath);
    }

    return events;
  }

  async tapElement(
    target: string,
    matcher: UiMatcher
  ): Promise<FridaEvent[]> {
    const sessionId = randomUUID();
    const scriptPath = await this.writeTempScript(sessionId, buildUiTapScript(matcher));

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const targetArgs = buildTargetArgs(target);
    const baseArgs = await this.buildDeviceArgs();
    const commandArgs = [...baseArgs, ...targetArgs, "-l", scriptPath, "-q"];

    const timer = setTimeout(() => abort.abort(), 8_000);

    try {
      await this.execLocalFridaStream(
        commandArgs,
        (line) => {
          const event = parseFridaLine(line);
          if (event) {
            events.push(event);
            if (event.type === "done" || event.type === "tapped") abort.abort();
          }
        },
        abort.signal
      );
    } finally {
      clearTimeout(timer);
      await this.cleanupLocalTempScript(scriptPath);
    }

    return events;
  }

  async runScript(
    target: string,
    script: string,
    durationMs: number
  ): Promise<FridaEvent[]> {
    const sessionId = randomUUID();
    const scriptPath = await this.writeTempScript(sessionId, script);

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const targetArgs = buildTargetArgs(target);
    const baseArgs = await this.buildDeviceArgs();
    const commandArgs = [...baseArgs, ...targetArgs, "-l", scriptPath, "-q"];

    const timer = setTimeout(() => abort.abort(), durationMs);

    try {
      await this.execLocalFridaStream(
        commandArgs,
        (line) => {
          const event = parseFridaLine(line);
          if (event) {
            const maxEvents = this.config.frida?.maxSessionEvents ?? 5_000;
            if (events.length < maxEvents) events.push(event);
          }
        },
        abort.signal
      );
    } finally {
      clearTimeout(timer);
      await this.cleanupLocalTempScript(scriptPath);
    }

    return events;
  }

  async launchApp(bundleId: string): Promise<{ launched: boolean; method?: string }> {
    // Preferred: launch via SpringBoard using LSApplicationWorkspace (works in both USB and SSH Frida modes).
    try {
      const events = await this.runSpringBoardScript(buildLaunchAppScript(bundleId), 8_000);
      const launchedEvent = events.find((e) => e.type === "launch_app") as
        | { type: "launch_app"; ok?: boolean }
        | undefined;
      if (launchedEvent && launchedEvent.ok) {
        return { launched: true, method: "frida:LSApplicationWorkspace" };
      }
    } catch {
      // Fall back to SSH launch methods below.
    }

    // Best-effort fallback: not all jailbreaks include uiopen. We try a few common strategies.
    const candidates = [
      { cmd: `uiopen --bundleid "${bundleId.replace(/"/g, '\\"')}"`, method: "uiopen --bundleid" },
      { cmd: `uiopen "${bundleId.replace(/"/g, '\\"')}"`, method: "uiopen" },
      { cmd: `open "${bundleId.replace(/"/g, '\\"')}"`, method: "open" }
    ];

    for (const c of candidates) {
      try {
        const r = await this.execService.exec(c.cmd, { timeoutMs: 8_000 });
        if (r.code === 0) return { launched: true, method: c.method };
      } catch {
        // try next
      }
    }
    return { launched: false };
  }

  async dynamicAnalyzeApp(args: {
    bundleId: string;
    hookTypes: HookType[];
    durationMs: number;
    tapCommonPrompts: boolean;
  }): Promise<{
    launched: boolean;
    launchMethod?: string;
    eventCount: number;
    eventsSample: FridaEvent[];
    truncated: boolean;
    fullEventsPath?: string;
  }> {
    const launch = await this.launchApp(args.bundleId);
    const sessionId = await this.beginSession(args.bundleId, args.hookTypes);
    const effectiveDurationMs = Math.max(3_000, args.durationMs);
    const bonusSettleMs = args.tapCommonPrompts ? 1_500 : 0;
    await new Promise((r) => setTimeout(r, effectiveDurationMs + bonusSettleMs));
    const events = await this.endSession(sessionId);
    const sampleLimit = 500;
    const eventsSample = events.slice(0, sampleLimit);
    const truncated = events.length > sampleLimit;

    return {
      launched: launch.launched,
      launchMethod: launch.method,
      eventCount: events.length,
      eventsSample,
      truncated,
      fullEventsPath: undefined
    };
  }

  async close(): Promise<void> {
    for (const session of this.sessions.values()) {
      session.abort.abort();
    }
    this.sessions.clear();
    if (this.localPortForward) {
      this.localPortForward.close();
      this.localPortForward = undefined;
    }
  }

  private getLocalFridaBin(): string {
    return this.config.frida?.binaryPath?.trim() || "frida";
  }

  private getLocalFridaPsBin(): string {
    // Allow override for frida but keep ps separate (common install puts both on PATH)
    return this.cachedPsBinaryPath ?? "frida-ps";
  }

  private async detectLocalFridaTools(): Promise<{ found: boolean; version?: string; error?: string }> {
    try {
      const r = await execFileAsync(this.getLocalFridaBin(), ["--version"], {
        timeoutMs: 8_000
      });
      this.cachedBinaryPath = this.getLocalFridaBin();
      this.cachedPsBinaryPath = "frida-ps";
      return { found: true, version: (r.stdout || r.stderr).trim() || "unknown" };
    } catch (e) {
      return {
        found: false,
        error: e instanceof Error ? e.message : "Failed to execute local frida CLI"
      };
    }
  }

  private async detectJailbreakTypeViaSsh(): Promise<DetectResult["jailbreakType"]> {
    // Non-fatal best-effort signal.
    for (const candidate of FRIDA_CANDIDATES) {
      try {
        const result = await this.execService.exec(
          `test -d ${candidate.frida.replace(/\/frida$/, "")} && echo "yes" || echo "no"`,
          { timeoutMs: 3_000 }
        );
        if (result.stdout.trim() === "yes") return candidate.jailbreakType;
      } catch {
        // ignore
      }
    }
    return "unknown";
  }

  private async ensureForwardedHostPort(forceRecreate = false): Promise<string> {
    if (forceRecreate && this.localPortForward) {
      try {
        this.localPortForward.close();
      } catch {
        /* ignore */
      }
      this.localPortForward = undefined;
    }
    if (!this.localPortForward) {
      this.localPortForward = await this.execService.createLocalPortForward("127.0.0.1", 27042);
    }
    return `127.0.0.1:${this.localPortForward.localPort}`;
  }

  private async buildDeviceArgs(): Promise<string[]> {
    const configuredMode = (this.config.frida?.connectionMode ?? "auto") as "auto" | "ssh" | "usb";
    const mode = await this.resolveConnectionMode(configuredMode);
    if (mode === "usb") return ["-U"];
    const host = await this.ensureForwardedHostPort(false);
    return ["-H", host];
  }

  private async resolveConnectionMode(configured: "auto" | "ssh" | "usb"): Promise<"ssh" | "usb"> {
    if (this.resolvedConnectionMode) return this.resolvedConnectionMode;

    // Explicit override always wins.
    if (configured === "usb" || configured === "ssh") {
      this.resolvedConnectionMode = configured;
      return configured;
    }

    // Auto: try USB first (most reliable if a cable is connected).
    try {
      const r = await this.execLocalFridaPs(["-U"], { timeoutMs: 4_000 });
      if (r.code === 0 && (r.stdout.includes("PID") || r.stdout.trim().length > 0)) {
        this.resolvedConnectionMode = "usb";
        return "usb";
      }
    } catch {
      // fall back to SSH probe
    }

    // Auto fallback: SSH over forwarded frida-server port.
    const host = await this.ensureForwardedHostPort();
    const sshProbe = await this.execLocalFridaPs(["-H", host], { timeoutMs: 5_000 });
    if (sshProbe.code !== 0) {
      throw new Error(
        `Auto Frida mode failed. USB not available; SSH probe failed (exit ${sshProbe.code}): ${sshProbe.stderr.slice(0, 200)}`
      );
    }

    this.resolvedConnectionMode = "ssh";
    return "ssh";
  }

  private async writeTempScript(sessionId: string, content: string): Promise<string> {
    const file = path.join(os.tmpdir(), `ios_mcp_frida_${sessionId}.js`);
    await fs.writeFile(file, content, "utf8");
    return file;
  }

  private async cleanupLocalTempScript(scriptPath: string): Promise<void> {
    try {
      await fs.unlink(scriptPath);
    } catch {
      /* best effort */
    }
  }

  private async execLocalFridaPs(
    args: string[],
    opts: { timeoutMs: number }
  ): Promise<{ stdout: string; stderr: string; code: number }> {
    const ps = this.getLocalFridaPsBin();
    return execFileAsync(ps, args, { timeoutMs: opts.timeoutMs });
  }

  private async execLocalFridaStream(
    args: string[],
    onData: (line: string) => void,
    signal: AbortSignal
  ): Promise<{ code: number }> {
    const frida = this.getLocalFridaBin();
    return spawnStreamLines(frida, args, onData, signal);
  }

  private async runSpringBoardScript(script: string, timeoutMs: number): Promise<FridaEvent[]> {
    const sessionId = randomUUID();
    const scriptPath = await this.writeTempScript(sessionId, script);
    const events: FridaEvent[] = [];
    const abort = new AbortController();

    const baseArgs = await this.buildDeviceArgs();
    const commandArgs = [...baseArgs, "-n", "SpringBoard", "-l", scriptPath, "-q"];
    const timer = setTimeout(() => abort.abort(), timeoutMs);

    try {
      await this.execLocalFridaStream(
        commandArgs,
        (line) => {
          const event = parseFridaLine(line);
          if (event) {
            events.push(event);
            if (event.type === "done") abort.abort();
          }
        },
        abort.signal
      );
    } finally {
      clearTimeout(timer);
      await this.cleanupLocalTempScript(scriptPath);
    }

    return events;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildTargetArg(target: string): string {
  return buildTargetArgs(target).join(" ");
}

function buildTargetArgs(target: string): string[] {
  const trimmed = target.trim();
  // All-digit string → attach by PID
  if (/^\d+$/.test(trimmed)) {
    return ["-p", trimmed];
  }
  // Use -n which works for both name and bundle ID on iOS
  return ["-n", trimmed];
}

function parseFridaLine(line: string): FridaEvent | null {
  try {
    let candidate = line.trim();
    if (!candidate.startsWith("{")) {
      const start = candidate.indexOf("{");
      const end = candidate.lastIndexOf("}");
      if (start >= 0 && end > start) {
        candidate = candidate.slice(start, end + 1);
      }
    }
    const obj = JSON.parse(candidate) as Record<string, unknown>;
    if (obj.type === "send" && obj.payload && typeof obj.payload === "object") {
      return { ts: Date.now(), ...(obj.payload as Record<string, unknown>) } as FridaEvent;
    }
    if (obj.type === "log") {
      return {
        ts: Date.now(),
        type: "frida_log",
        level: obj.level,
        message: obj.payload
      };
    }
    if (obj.type === "error") {
      return {
        ts: Date.now(),
        type: "frida_error",
        description: obj.description,
        stack: obj.stack
      };
    }
  } catch {
    // Not JSON — plain text output from frida CLI (banner, warnings)
    const trimmed = line.trim();
    if (trimmed) {
      return { ts: Date.now(), type: "frida_output", text: trimmed };
    }
  }
  return null;
}

function parseFridaPs(output: string): ProcessEntry[] {
  const lines = output.split("\n");
  const entries: ProcessEntry[] = [];
  let pastHeader = false;

  for (const line of lines) {
    // The separator line is all dashes and spaces: "----  ----"
    if (/^[\s\-]+$/.test(line) && line.includes("-")) {
      pastHeader = true;
      continue;
    }
    if (!pastHeader) continue;

    const match = /^\s*(\d+)\s+(.+?)\s*$/.exec(line);
    if (match) {
      entries.push({ pid: parseInt(match[1], 10), name: match[2] });
    }
  }

  return entries;
}

function execFileAsync(
  file: string,
  args: string[],
  opts: { timeoutMs: number }
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { windowsHide: true, timeout: opts.timeoutMs }, (error, stdout, stderr) => {
      if (error) {
        // execFile uses error for non-zero exits too; preserve output.
        const anyErr = error as unknown as { code?: number };
        resolve({ stdout: String(stdout ?? ""), stderr: String(stderr ?? error.message ?? ""), code: anyErr.code ?? 1 });
        return;
      }
      resolve({ stdout: String(stdout ?? ""), stderr: String(stderr ?? ""), code: 0 });
    });
    // Ensure we don't keep the process alive unnecessarily.
    child.unref?.();
  });
}

function spawnStreamLines(
  file: string,
  args: string[],
  onData: (line: string) => void,
  signal: AbortSignal
): Promise<{ code: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let buf = "";

    const kill = () => {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
    };
    signal.addEventListener("abort", kill, { once: true });

    const processChunk = (chunk: Buffer) => {
      buf += chunk.toString();
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trimEnd();
        if (trimmed.trim()) onData(trimmed);
      }
    };

    child.stdout.on("data", processChunk);
    child.stderr.on("data", processChunk);

    child.on("error", (err) => {
      signal.removeEventListener("abort", kill);
      reject(err);
    });

    child.on("close", (code) => {
      signal.removeEventListener("abort", kill);
      if (buf.trim()) onData(buf.trim());
      resolve({ code: code ?? 0 });
    });
  });
}
