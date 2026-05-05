import { randomUUID } from "node:crypto";
import {
  ALL_HOOK_TYPES,
  APPS_LIST_SCRIPT,
  buildAppInfoScript,
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

  constructor(
    private readonly execService: SshExecService,
    private readonly config: ServerConfig
  ) {}

  async detectFrida(): Promise<DetectResult> {
    // Check each candidate path via shell test
    for (const candidate of FRIDA_CANDIDATES) {
      try {
        const result = await this.execService.exec(
          `test -x ${candidate.frida} && echo "found" || echo "not_found"`,
          { timeoutMs: 5_000 }
        );
        if (result.stdout.trim() === "found") {
          this.cachedBinaryPath = candidate.frida;
          const psPath = candidate.frida.replace(/\/frida$/, "/frida-ps");
          this.cachedPsBinaryPath = psPath;

          let version = "unknown";
          try {
            const verResult = await this.execService.exec(
              `${candidate.frida} --version`,
              { timeoutMs: 5_000 }
            );
            version = verResult.stdout.trim() || verResult.stderr.trim() || "unknown";
          } catch {
            /* version is optional */
          }

          return {
            found: true,
            binaryPath: candidate.frida,
            psBinaryPath: psPath,
            jailbreakType: candidate.jailbreakType,
            version
          };
        }
      } catch {
        continue;
      }
    }

    return {
      found: false,
      error:
        "Frida not found. Install frida-server on your device via Cydia/Sileo/Zebra, then ensure frida-tools is installed."
    };
  }

  async listProcesses(): Promise<ProcessEntry[]> {
    const ps = await this.requirePsBinary();
    const result = await this.execService.exec(`${ps} -U`, {
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
    const frida = await this.requireBinary();
    const sessionId = randomUUID();
    const scriptPath = `/tmp/ios_mcp_frida_${sessionId}.js`;

    await this.execService.writeFile(scriptPath, APPS_LIST_SCRIPT);

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const command = `${frida} -U -n SpringBoard ${scriptPath} --no-pause -q 2>&1`;
    const timer = setTimeout(() => abort.abort(), 15_000);

    try {
      await this.execService.execStream(
        command,
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
      await this.cleanupScript(scriptPath);
    }

    const appsEvent = events.find((e) => e.type === "apps");
    if (appsEvent && Array.isArray(appsEvent.apps)) {
      return appsEvent.apps as AppEntry[];
    }
    throw new Error("Failed to list apps via Frida");
  }

  async getAppInfo(bundleId: string): Promise<FridaEvent[]> {
    const frida = await this.requireBinary();
    const sessionId = randomUUID();
    const scriptPath = `/tmp/ios_mcp_frida_${sessionId}.js`;

    await this.execService.writeFile(scriptPath, buildAppInfoScript(bundleId));

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const command = `${frida} -U -n SpringBoard ${scriptPath} --no-pause -q 2>&1`;
    const timer = setTimeout(() => abort.abort(), 10_000);

    try {
      await this.execService.execStream(
        command,
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
      await this.cleanupScript(scriptPath);
    }

    return events;
  }

  async startTrace(
    target: string,
    hookTypes: HookType[],
    durationMs: number
  ): Promise<FridaEvent[]> {
    const frida = await this.requireBinary();
    const sessionId = randomUUID();
    const scriptPath = `/tmp/ios_mcp_frida_${sessionId}.js`;
    const script = buildHookScript(hookTypes);

    await this.execService.writeFile(scriptPath, script);

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const targetArg = buildTargetArg(target);
    const command = `${frida} -U ${targetArg} ${scriptPath} --no-pause -q 2>&1`;

    const timer = setTimeout(() => abort.abort(), durationMs);

    try {
      await this.execService.execStream(
        command,
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
      await this.cleanupScript(scriptPath);
    }

    return events;
  }

  async beginSession(target: string, hookTypes: HookType[]): Promise<string> {
    const frida = await this.requireBinary();
    const sessionId = randomUUID();
    const scriptPath = `/tmp/ios_mcp_frida_${sessionId}.js`;
    const script = buildHookScript(hookTypes);

    await this.execService.writeFile(scriptPath, script);

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

    const targetArg = buildTargetArg(target);
    const command = `${frida} -U ${targetArg} ${scriptPath} --no-pause -q 2>&1`;
    const maxEvents = this.config.frida?.maxSessionEvents ?? 5_000;

    // Fire-and-forget: stream runs until aborted
    void this.execService
      .execStream(
        command,
        (line) => {
          const event = parseFridaLine(line);
          if (event && session.events.length < maxEvents) {
            session.events.push(event);
          }
        },
        abort.signal
      )
      .finally(() => {
        session.active = false;
        void this.cleanupScript(scriptPath);
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
    const frida = await this.requireBinary();
    const sessionId = randomUUID();
    const scriptPath = `/tmp/ios_mcp_frida_${sessionId}.js`;

    await this.execService.writeFile(scriptPath, UI_DUMP_SCRIPT);

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const targetArg = buildTargetArg(target);
    const command = `${frida} -U ${targetArg} ${scriptPath} --no-pause -q 2>&1`;

    // UI dump should finish quickly — 10s timeout
    const timer = setTimeout(() => abort.abort(), 10_000);

    try {
      await this.execService.execStream(
        command,
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
      await this.cleanupScript(scriptPath);
    }

    return events;
  }

  async tapElement(
    target: string,
    matcher: UiMatcher
  ): Promise<FridaEvent[]> {
    const frida = await this.requireBinary();
    const sessionId = randomUUID();
    const scriptPath = `/tmp/ios_mcp_frida_${sessionId}.js`;

    await this.execService.writeFile(scriptPath, buildUiTapScript(matcher));

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const targetArg = buildTargetArg(target);
    const command = `${frida} -U ${targetArg} ${scriptPath} --no-pause -q 2>&1`;

    const timer = setTimeout(() => abort.abort(), 8_000);

    try {
      await this.execService.execStream(
        command,
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
      await this.cleanupScript(scriptPath);
    }

    return events;
  }

  async runScript(
    target: string,
    script: string,
    durationMs: number
  ): Promise<FridaEvent[]> {
    const frida = await this.requireBinary();
    const sessionId = randomUUID();
    const scriptPath = `/tmp/ios_mcp_frida_${sessionId}.js`;

    await this.execService.writeFile(scriptPath, script);

    const events: FridaEvent[] = [];
    const abort = new AbortController();
    const targetArg = buildTargetArg(target);
    const command = `${frida} -U ${targetArg} ${scriptPath} --no-pause -q 2>&1`;

    const timer = setTimeout(() => abort.abort(), durationMs);

    try {
      await this.execService.execStream(
        command,
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
      await this.cleanupScript(scriptPath);
    }

    return events;
  }

  async close(): Promise<void> {
    for (const session of this.sessions.values()) {
      session.abort.abort();
    }
    this.sessions.clear();
  }

  private async requireBinary(): Promise<string> {
    if (this.cachedBinaryPath) return this.cachedBinaryPath;
    const result = await this.detectFrida();
    if (!result.found || !result.binaryPath) {
      throw new Error(result.error ?? "Frida not found on device");
    }
    return result.binaryPath;
  }

  private async requirePsBinary(): Promise<string> {
    if (this.cachedPsBinaryPath) return this.cachedPsBinaryPath;
    await this.requireBinary(); // populates cachedPsBinaryPath as a side-effect
    return this.cachedPsBinaryPath!;
  }

  private async cleanupScript(scriptPath: string): Promise<void> {
    try {
      await this.execService.deleteFile(scriptPath);
    } catch {
      /* best effort — don't fail if cleanup fails */
    }
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildTargetArg(target: string): string {
  // All-digit string → attach by PID
  if (/^\d+$/.test(target.trim())) {
    return `-p ${target.trim()}`;
  }
  // Contains '.' → likely a bundle ID — use -n which works for both name and bundle ID on iOS
  return `-n "${target.replace(/"/g, '\\"')}"`;
}

function parseFridaLine(line: string): FridaEvent | null {
  try {
    const obj = JSON.parse(line) as Record<string, unknown>;
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
