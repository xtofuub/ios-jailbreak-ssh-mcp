import { posix } from "node:path";
export const DEFAULT_ALLOWED_ROOTS = [
    "/var/mobile",
    "/private/var/mobile",
    "/var/containers/Bundle/Application",
    "/private/var/containers/Bundle/Application",
    "/var/jb",
    "/tmp"
];
export const BUILT_IN_BLOCKED_PATHS = [
    "/var/Keychains",
    "/var/mobile/Library/Accounts",
    "/private/var/mobile/Library/Accounts",
    "/var/mobile/Library/SMS",
    "/private/var/mobile/Library/SMS",
    "/var/mobile/Library/Mail",
    "/private/var/mobile/Library/Mail",
    "/private/var/db",
    "/System",
    "/usr",
    "/bin",
    "/sbin"
];
export class SafetyError extends Error {
    constructor(message) {
        super(message);
        this.name = "SafetyError";
    }
}
export function normalizeRemotePath(input) {
    if (typeof input !== "string" || input.trim() === "") {
        throw new SafetyError("Path must be a non-empty string.");
    }
    if (input.includes("\0")) {
        throw new SafetyError("Path must not contain NUL bytes.");
    }
    if (!input.startsWith("/")) {
        throw new SafetyError(`Path must be absolute: ${input}`);
    }
    const normalized = posix.normalize(input);
    return normalized === "." ? "/" : normalized;
}
export function isPathWithin(path, root) {
    return path === root || path.startsWith(`${root}/`);
}
export function assertAllowedRootConfig(roots) {
    const normalizedRoots = roots.map(normalizeRemotePath);
    const deduped = [...new Set(normalizedRoots)];
    for (const root of deduped) {
        const underBuiltInRoot = DEFAULT_ALLOWED_ROOTS.some((builtInRoot) => isPathWithin(root, builtInRoot));
        if (!underBuiltInRoot) {
            throw new SafetyError(`Configured allowed root is outside the built-in safe roots: ${root}`);
        }
    }
    return deduped;
}
export function assertSafePath(input, config) {
    const path = normalizeRemotePath(input);
    const blocked = BUILT_IN_BLOCKED_PATHS.find((blockedPath) => isPathWithin(path, blockedPath));
    if (blocked) {
        throw new SafetyError(`Path is blocked by default safety policy: ${blocked}`);
    }
    const allowed = config.allowedRoots.some((root) => isPathWithin(path, root));
    if (!allowed) {
        throw new SafetyError(`Path is outside allowed roots: ${path}. Allowed roots: ${config.allowedRoots.join(", ")}`);
    }
    return path;
}
export function assertWritable(config, operation) {
    if (config.readOnly || !config.allowWrites) {
        throw new SafetyError(`${operation} is disabled. Set readOnly=false and allowWrites=true to enable write operations.`);
    }
}
export function backupPathFor(path, now = new Date()) {
    const stamp = now
        .toISOString()
        .replace(/[-:]/g, "")
        .replace(".", "")
        .replace("Z", "Z");
    return `${path}.bak.${stamp}`;
}
export function dirname(path) {
    return posix.dirname(path);
}
export function basename(path) {
    return posix.basename(path);
}
export function joinRemote(...parts) {
    return posix.join(...parts);
}
//# sourceMappingURL=pathSafety.js.map