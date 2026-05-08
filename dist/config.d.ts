import type { ServerConfig } from "./types.js";
export declare class ConfigError extends Error {
    constructor(message: string);
}
export declare function getConfigPathFromArgs(argv?: string[]): string | undefined;
export declare function hasHelpFlag(argv?: string[]): boolean;
export declare function helpText(): string;
export declare function loadConfig(): Promise<ServerConfig>;
