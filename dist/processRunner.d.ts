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
export declare class ProcessRunnerError extends Error {
    readonly result?: ProcessResult | undefined;
    constructor(message: string, result?: ProcessResult | undefined);
}
export declare function runProcess(command: string, args: string[], options: ProcessRunOptions): Promise<ProcessResult>;
