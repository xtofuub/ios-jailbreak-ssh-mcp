import { appendFile } from "node:fs/promises";
import type { OperationLogEntry, ServerConfig } from "./types.js";

export class OperationLogger {
  constructor(private readonly config: Pick<ServerConfig, "logPath">) {}

  async log(entry: OperationLogEntry): Promise<void> {
    const record = {
      timestamp: new Date().toISOString(),
      ...entry
    };

    try {
      await appendFile(this.config.logPath, `${JSON.stringify(record)}\n`, "utf8");
    } catch (error) {
      process.stderr.write(
        `ios-files-mcp: failed to write operation log: ${error instanceof Error ? error.message : String(error)}\n`
      );
    }
  }
}

export function publicError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

export function redactToolInput(input: Record<string, unknown>): Record<string, unknown> {
  const redacted: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input)) {
    if (key === "content" && typeof value === "string") {
      redacted[key] = `[${Buffer.byteLength(value, "utf8")} utf8 bytes]`;
    } else {
      redacted[key] = value;
    }
  }

  return redacted;
}
