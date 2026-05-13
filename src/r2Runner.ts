import { createWriteStream } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename as posixBasename, join as joinLocal } from "node:path";
import type { Client as Ssh2Client, ClientChannel } from "ssh2";
import { ProcessRunnerError, runProcess } from "./processRunner.js";

export type R2ExecOptions = {
  timeoutMs: number;
  maxOutputBytes: number;
  allowNonZero?: boolean;
};

export type R2ExecResult = {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  truncated: boolean;
  durationMs: number;
};

export type R2BinarySource = {
  argvPath: string;
  remotePath: string;
  size: number;
  cleanup: () => Promise<void>;
};

export type CommandCheck = {
  available: boolean;
  version?: string;
  error?: string;
};

export type R2ProbeResult = {
  r2: CommandCheck;
  rabin2: CommandCheck;
  r2Path: string;
  rabin2Path: string;
};

export type SftpBinaryResolver = (remotePath: string) => Promise<{
  remotePath: string;
  size: number;
  download: (localPath: string) => Promise<void>;
}>;

export interface R2Runner {
  readonly mode: "device" | "local";
  readonly r2Path: string;
  readonly rabin2Path: string;
  probe(): Promise<R2ProbeResult>;
  resolveBinary(remotePath: string): Promise<R2BinarySource>;
  runR2(args: string[], opts: R2ExecOptions): Promise<R2ExecResult>;
  runRabin2(args: string[], opts: R2ExecOptions): Promise<R2ExecResult>;
}

export function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function buildRemoteCommand(command: string, args: string[]): string {
  return [command, ...args].map(shQuote).join(" ");
}

export type LocalR2RunnerOptions = {
  r2Path: string;
  rabin2Path: string;
  maxBinarySize: number;
  sftpResolver: SftpBinaryResolver;
};

export class LocalR2Runner implements R2Runner {
  readonly mode = "local" as const;
  readonly r2Path: string;
  readonly rabin2Path: string;
  private cachedProbe?: R2ProbeResult;

  constructor(private readonly opts: LocalR2RunnerOptions) {
    this.r2Path = opts.r2Path;
    this.rabin2Path = opts.rabin2Path;
  }

  async probe(): Promise<R2ProbeResult> {
    if (this.cachedProbe) {
      return this.cachedProbe;
    }
    const [r2, rabin2] = await Promise.all([
      this.checkVersion(this.opts.r2Path),
      this.checkVersion(this.opts.rabin2Path)
    ]);
    const result: R2ProbeResult = {
      r2,
      rabin2,
      r2Path: this.opts.r2Path,
      rabin2Path: this.opts.rabin2Path
    };
    if (r2.available && rabin2.available) {
      this.cachedProbe = result;
    }
    return result;
  }

  async resolveBinary(remotePath: string): Promise<R2BinarySource> {
    const resolved = await this.opts.sftpResolver(remotePath);
    if (resolved.size > this.opts.maxBinarySize) {
      throw new Error(
        `Binary is ${resolved.size} bytes, which exceeds r2.maxBinarySize=${this.opts.maxBinarySize}.`
      );
    }

    const tempDir = await mkdtemp(joinLocal(tmpdir(), "ios-files-mcp-r2-"));
    const safeName = (posixBasename(resolved.remotePath) || "binary").replace(/[^A-Za-z0-9._-]/g, "_");
    const localPath = joinLocal(tempDir, safeName);

    try {
      await resolved.download(localPath);
    } catch (error) {
      await rm(tempDir, { recursive: true, force: true });
      throw error;
    }

    return {
      argvPath: localPath,
      remotePath: resolved.remotePath,
      size: resolved.size,
      cleanup: async () => {
        await rm(tempDir, { recursive: true, force: true });
      }
    };
  }

  runR2(args: string[], opts: R2ExecOptions): Promise<R2ExecResult> {
    return this.runLocal(this.opts.r2Path, args, opts);
  }

  runRabin2(args: string[], opts: R2ExecOptions): Promise<R2ExecResult> {
    return this.runLocal(this.opts.rabin2Path, args, opts);
  }

  private async runLocal(command: string, args: string[], opts: R2ExecOptions): Promise<R2ExecResult> {
    const result = await runProcess(command, args, {
      timeoutMs: opts.timeoutMs,
      maxOutputBytes: opts.maxOutputBytes,
      allowNonZero: opts.allowNonZero
    });
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      exitCode: result.exitCode,
      signal: result.signal ?? null,
      timedOut: result.timedOut,
      truncated: result.truncated,
      durationMs: result.durationMs
    };
  }

  private async checkVersion(command: string): Promise<CommandCheck> {
    try {
      const result = await runProcess(command, ["-v"], {
        timeoutMs: 10_000,
        maxOutputBytes: 16 * 1024,
        allowNonZero: false
      });
      const version = (result.stdout || result.stderr).split(/\r?\n/).find(Boolean)?.trim();
      return { available: true, version };
    } catch (error) {
      return {
        available: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }
}

export type DeviceR2RunnerOptions = {
  r2Path?: string;
  rabin2Path?: string;
  probeTimeoutMs?: number;
  maxBinarySize: number;
  sshClient: () => Promise<Ssh2Client>;
  sftpResolver: SftpBinaryResolver;
};

const DEFAULT_DEVICE_R2 = "r2";
const DEFAULT_DEVICE_RABIN2 = "rabin2";

export class DeviceR2Runner implements R2Runner {
  readonly mode = "device" as const;
  private resolvedR2Path?: string;
  private resolvedRabin2Path?: string;
  private cachedProbe?: R2ProbeResult;

  constructor(private readonly opts: DeviceR2RunnerOptions) {}

  get r2Path(): string {
    return this.resolvedR2Path ?? this.opts.r2Path ?? DEFAULT_DEVICE_R2;
  }

  get rabin2Path(): string {
    return this.resolvedRabin2Path ?? this.opts.rabin2Path ?? DEFAULT_DEVICE_RABIN2;
  }

  async probe(): Promise<R2ProbeResult> {
    if (this.cachedProbe) {
      return this.cachedProbe;
    }

    const probeTimeout = this.opts.probeTimeoutMs ?? 5_000;
    const [r2, rabin2] = await Promise.all([
      this.probeOne(this.opts.r2Path, DEFAULT_DEVICE_R2, probeTimeout),
      this.probeOne(this.opts.rabin2Path, DEFAULT_DEVICE_RABIN2, probeTimeout)
    ]);

    if (r2.check.available) {
      this.resolvedR2Path = r2.path;
    }
    if (rabin2.check.available) {
      this.resolvedRabin2Path = rabin2.path;
    }

    const result: R2ProbeResult = {
      r2: r2.check,
      rabin2: rabin2.check,
      r2Path: this.r2Path,
      rabin2Path: this.rabin2Path
    };

    if (r2.check.available && rabin2.check.available) {
      this.cachedProbe = result;
    }

    return result;
  }

  async resolveBinary(remotePath: string): Promise<R2BinarySource> {
    const resolved = await this.opts.sftpResolver(remotePath);
    if (resolved.size > this.opts.maxBinarySize) {
      throw new Error(
        `Binary is ${resolved.size} bytes, which exceeds r2.maxBinarySize=${this.opts.maxBinarySize}.`
      );
    }
    return {
      argvPath: resolved.remotePath,
      remotePath: resolved.remotePath,
      size: resolved.size,
      cleanup: async () => {}
    };
  }

  runR2(args: string[], opts: R2ExecOptions): Promise<R2ExecResult> {
    return this.execRemote(this.r2Path, args, opts);
  }

  runRabin2(args: string[], opts: R2ExecOptions): Promise<R2ExecResult> {
    return this.execRemote(this.rabin2Path, args, opts);
  }

  private async probeOne(
    explicitPath: string | undefined,
    fallback: string,
    timeoutMs: number
  ): Promise<{ check: CommandCheck; path: string }> {
    if (explicitPath) {
      const check = await this.runVersion(explicitPath, timeoutMs);
      return { check, path: explicitPath };
    }

    const resolved = await this.runCommandV(fallback, timeoutMs);
    if (!resolved.ok || !resolved.path) {
      return {
        check: {
          available: false,
          error: resolved.error ?? `command -v ${fallback} returned no path on device`
        },
        path: fallback
      };
    }

    const check = await this.runVersion(resolved.path, timeoutMs);
    return { check, path: resolved.path };
  }

  private async runVersion(remoteCommand: string, timeoutMs: number): Promise<CommandCheck> {
    try {
      const result = await this.execRemote(remoteCommand, ["-v"], {
        timeoutMs,
        maxOutputBytes: 16 * 1024,
        allowNonZero: false
      });
      const version = (result.stdout || result.stderr).split(/\r?\n/).find(Boolean)?.trim();
      return { available: true, version };
    } catch (error) {
      return {
        available: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private async runCommandV(
    name: string,
    timeoutMs: number
  ): Promise<{ ok: boolean; path?: string; error?: string }> {
    try {
      const result = await this.execRaw(`command -v ${shQuote(name)}`, {
        timeoutMs,
        maxOutputBytes: 4 * 1024,
        allowNonZero: true
      });
      if (result.exitCode === 0) {
        const path = result.stdout.split(/\r?\n/).find(Boolean)?.trim();
        if (path) {
          return { ok: true, path };
        }
        return { ok: false, error: `command -v ${name} returned empty path` };
      }
      return { ok: false, error: `command -v ${name} exited ${result.exitCode}` };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  private execRemote(
    command: string,
    args: string[],
    opts: R2ExecOptions
  ): Promise<R2ExecResult> {
    return this.execRaw(buildRemoteCommand(command, args), opts);
  }

  private async execRaw(remoteCommand: string, opts: R2ExecOptions): Promise<R2ExecResult> {
    const client = await this.opts.sshClient();
    return new Promise<R2ExecResult>((resolve, reject) => {
      const start = Date.now();
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      let bytesSeen = 0;
      let truncated = false;
      let timedOut = false;
      let settled = false;
      let stream: ClientChannel | undefined;

      const finish = (
        outcome: "ok" | "timeout" | "truncated" | "error",
        err?: Error,
        code: number | null = null,
        sig: string | null = null
      ): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const result: R2ExecResult = {
          stdout: Buffer.concat(stdoutChunks).toString("utf8"),
          stderr: Buffer.concat(stderrChunks).toString("utf8"),
          exitCode: code,
          signal: sig,
          timedOut: outcome === "timeout" || timedOut,
          truncated: outcome === "truncated" || truncated,
          durationMs: Date.now() - start
        };

        if (outcome === "timeout") {
          reject(
            new ProcessRunnerError(
              `Device command timed out after ${opts.timeoutMs}ms: ${remoteCommand}`
            )
          );
          return;
        }

        if (outcome === "truncated") {
          reject(
            new ProcessRunnerError(
              `Device command output exceeded maxOutputBytes=${opts.maxOutputBytes}: ${remoteCommand}`
            )
          );
          return;
        }

        if (outcome === "error") {
          reject(err ?? new Error("Device command failed."));
          return;
        }

        if (!opts.allowNonZero && (code !== 0 || sig)) {
          const detail = result.stderr || result.stdout || `exit code ${code}, signal ${sig ?? "-"}`;
          reject(new ProcessRunnerError(`Device command failed: ${detail}`));
          return;
        }

        resolve(result);
      };

      const killStream = (): void => {
        if (!stream) return;
        try { stream.signal("TERM"); } catch { /* ignore */ }
        try { stream.close(); } catch { /* ignore */ }
      };

      const timer = setTimeout(() => {
        timedOut = true;
        killStream();
        finish("timeout");
      }, opts.timeoutMs);

      const capture = (target: Buffer[], chunk: Buffer): void => {
        const remaining = Math.max(0, opts.maxOutputBytes - bytesSeen);
        if (remaining > 0) {
          target.push(chunk.subarray(0, remaining));
        }
        bytesSeen += chunk.byteLength;
        if (bytesSeen > opts.maxOutputBytes && !truncated) {
          truncated = true;
          killStream();
          finish("truncated");
        }
      };

      client.exec(remoteCommand, (err, channel) => {
        if (err) {
          finish("error", err);
          return;
        }
        stream = channel;
        channel.on("data", (chunk: Buffer) => capture(stdoutChunks, chunk));
        channel.stderr.on("data", (chunk: Buffer) => capture(stderrChunks, chunk));
        channel.once("error", (channelErr: Error) => finish("error", channelErr));
        channel.once("close", (code: number | null, sig: string | null) => {
          finish("ok", undefined, code ?? null, sig ?? null);
        });
      });
    });
  }
}

export { ProcessRunnerError };
