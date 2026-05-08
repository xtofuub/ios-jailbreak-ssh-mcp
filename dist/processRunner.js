import { spawn } from "node:child_process";
export class ProcessRunnerError extends Error {
    result;
    constructor(message, result) {
        super(message);
        this.result = result;
        this.name = "ProcessRunnerError";
    }
}
export function runProcess(command, args, options) {
    return new Promise((resolve, reject) => {
        const start = Date.now();
        const stdoutChunks = [];
        const stderrChunks = [];
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
        const capture = (target, chunk) => {
            const remaining = Math.max(0, options.maxOutputBytes - bytesSeen);
            if (remaining > 0) {
                target.push(chunk.subarray(0, remaining));
            }
            bytesSeen += chunk.byteLength;
            if (bytesSeen > options.maxOutputBytes) {
                truncated = true;
            }
        };
        child.stdout?.on("data", (chunk) => capture(stdoutChunks, chunk));
        child.stderr?.on("data", (chunk) => capture(stderrChunks, chunk));
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
            const result = {
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
                reject(new ProcessRunnerError(`${command} output exceeded IOS_FILES_MCP_R2_MAX_OUTPUT_BYTES=${options.maxOutputBytes}.`, result));
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
//# sourceMappingURL=processRunner.js.map