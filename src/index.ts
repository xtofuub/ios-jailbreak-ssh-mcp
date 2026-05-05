#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { hasHelpFlag, helpText, loadConfig } from "./config.js";
import { FridaService } from "./fridaService.js";
import { OperationLogger } from "./logger.js";
import { createMcpServer } from "./mcpServer.js";
import { SftpFileService } from "./sftpFileService.js";
import { SshExecService } from "./sshExecService.js";

function formatErr(error: unknown): string {
  if (error instanceof Error) return error.stack ?? error.message;
  return String(error);
}

function writeFatal(prefix: string, error: unknown): void {
  process.stderr.write(`${prefix}: ${formatErr(error)}\n`);
}

async function main(): Promise<void> {
  if (hasHelpFlag()) {
    process.stdout.write(`${helpText()}\n`);
    return;
  }

  const config = await loadConfig();
  process.stderr.write(
    `ios-files-mcp config: readOnly=${config.readOnly} allowWrites=${config.allowWrites} requireWriteApproval=${config.requireWriteApproval}\n`
  );
  const logger = new OperationLogger(config);
  const service = new SftpFileService(config);

  const execService = new SshExecService(config);
  const fridaService = config.frida?.enabled
    ? new FridaService(execService, config)
    : undefined;

  const server = createMcpServer(service, logger, config, fridaService);
  const transport = new StdioServerTransport();

  const shutdown = async () => {
    await fridaService?.close();
    await execService.close();
    await service.close();
  };

  process.once("SIGINT", () => {
    void shutdown().finally(() => process.exit(0));
  });
  process.once("SIGTERM", () => {
    void shutdown().finally(() => process.exit(0));
  });

  process.on("unhandledRejection", (reason) => {
    writeFatal("ios-files-mcp unhandledRejection", reason);
  });

  process.on("uncaughtException", (error) => {
    writeFatal("ios-files-mcp uncaughtException", error);
  });

  await server.connect(transport);
}

main().catch((error) => {
  writeFatal("ios-files-mcp failed to start", error);
  process.exit(1);
});
