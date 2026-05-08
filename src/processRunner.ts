import { spawn } from "node:child_process";

export type ProcessResult = {
  command: string;
  args: string[];
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
  bytesSeen: number;
  durationMs: number;
};

export type ProcessRunOptions = {
  timeoutMs: number;
  maxOutputBytes: number;
  allowNonZero?: boolean;
};

export class ProcessRunnerError extends Error {
  constructor(message: string, readonly result?: ProcessResult) {
    super(message);
    this.name = "ProcessRunnerError";
  }
}

export function runProcess(
  command: string,
  args: string[],
  options: ProcessRunOptions
): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let bytesSeen = 0;
    let truncated = false;
    let timedOut = false;
    let settled = false;

    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, options.timeoutMs);

    const capture = (target: Buffer[], chunk: Buffer): void => {
      const remaining = Math.max(0, options.maxOutputBytes - bytesSeen);
      if (remaining > 0) {
        target.push(chunk.subarray(0, remaining));
      }

      bytesSeen += chunk.byteLength;
      if (bytesSeen > options.maxOutputBytes) {
        truncated = true;
      }
    };

    child.stdout?.on("data", (chunk: Buffer) => capture(stdoutChunks, chunk));
    child.stderr?.on("data", (chunk: Buffer) => capture(stderrChunks, chunk));

    child.once("error", (error) => {
      clearTimeout(timer);
      if (settled) {
        return;
      }

      settled = true;
      reject(new ProcessRunnerError(`Failed to start ${command}: ${error.message}`));
    });

    child.once("close", (exitCode, signal) => {
      clearTimeout(timer);
      if (settled) {
        return;
      }

      settled = true;
      const result: ProcessResult = {
        command,
        args,
        exitCode,
        signal,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
        timedOut,
        truncated,
        bytesSeen,
        durationMs: Date.now() - start
      };

      if (timedOut) {
        reject(new ProcessRunnerError(`${command} timed out after ${options.timeoutMs}ms.`, result));
        return;
      }

      if (truncated) {
        reject(
          new ProcessRunnerError(
            `${command} output exceeded IOS_FILES_MCP_R2_MAX_OUTPUT_BYTES=${options.maxOutputBytes}.`,
            result
          )
        );
        return;
      }

      if (!options.allowNonZero && exitCode !== 0) {
        const detail = result.stderr || result.stdout || `exit code ${exitCode}`;
        reject(new ProcessRunnerError(`${command} failed: ${detail}`, result));
        return;
      }

      resolve(result);
    });
  });
}
