import type { OperationLogEntry, ServerConfig } from "./types.js";
export declare class OperationLogger {
    private readonly config;
    constructor(config: Pick<ServerConfig, "logPath">);
    log(entry: OperationLogEntry): Promise<void>;
}
export declare function publicError(error: unknown): string;
export declare function redactToolInput(input: Record<string, unknown>): Record<string, unknown>;
