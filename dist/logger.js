import { appendFile } from "node:fs/promises";
export class OperationLogger {
    config;
    constructor(config) {
        this.config = config;
    }
    async log(entry) {
        const record = {
            timestamp: new Date().toISOString(),
            ...entry
        };
        try {
            await appendFile(this.config.logPath, `${JSON.stringify(record)}\n`, "utf8");
        }
        catch (error) {
            process.stderr.write(`ios-files-mcp: failed to write operation log: ${error instanceof Error ? error.message : String(error)}\n`);
        }
    }
}
export function publicError(error) {
    if (error instanceof Error) {
        return error.message;
    }
    return String(error);
}
export function redactToolInput(input) {
    const redacted = {};
    for (const [key, value] of Object.entries(input)) {
        if (key === "content" && typeof value === "string") {
            redacted[key] = `[${Buffer.byteLength(value, "utf8")} utf8 bytes]`;
        }
        else {
            redacted[key] = value;
        }
    }
    return redacted;
}
//# sourceMappingURL=logger.js.map