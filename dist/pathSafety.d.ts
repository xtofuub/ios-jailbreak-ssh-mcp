import type { ServerConfig } from "./types.js";
export declare const DEFAULT_ALLOWED_ROOTS: readonly ["/var/mobile", "/private/var/mobile", "/var/containers/Bundle/Application", "/private/var/containers/Bundle/Application", "/var/jb", "/tmp"];
export declare const BUILT_IN_BLOCKED_PATHS: readonly ["/var/Keychains", "/var/mobile/Library/Accounts", "/private/var/mobile/Library/Accounts", "/var/mobile/Library/SMS", "/private/var/mobile/Library/SMS", "/var/mobile/Library/Mail", "/private/var/mobile/Library/Mail", "/private/var/db", "/System", "/usr", "/bin", "/sbin"];
export declare class SafetyError extends Error {
    constructor(message: string);
}
export declare function normalizeRemotePath(input: string): string;
export declare function isPathWithin(path: string, root: string): boolean;
export declare function assertAllowedRootConfig(roots: string[]): string[];
export declare function assertSafePath(input: string, config: Pick<ServerConfig, "allowedRoots">): string;
export declare function assertWritable(config: ServerConfig, operation: string): void;
export declare function backupPathFor(path: string, now?: Date): string;
export declare function dirname(path: string): string;
export declare function basename(path: string): string;
export declare function joinRemote(...parts: string[]): string;
