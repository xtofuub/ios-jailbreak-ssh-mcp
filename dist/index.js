#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { hasHelpFlag, helpText, loadConfig } from "./config.js";
import { OperationLogger } from "./logger.js";
import { createMcpServer } from "./mcpServer.js";
import { SftpFileService } from "./sftpFileService.js";
async function main() {
    if (hasHelpFlag()) {
        process.stdout.write(`${helpText()}\n`);
        return;
    }
    const config = await loadConfig();
    const logger = new OperationLogger(config);
    const service = new SftpFileService(config);
    const server = createMcpServer(service, logger, config);
    const transport = new StdioServerTransport();
    const shutdown = async () => {
        await service.close();
    };
    process.once("SIGINT", () => {
        void shutdown().finally(() => process.exit(0));
    });
    process.once("SIGTERM", () => {
        void shutdown().finally(() => process.exit(0));
    });
    await server.connect(transport);
}
main().catch((error) => {
    const message = error instanceof Error ? error.stack ?? error.message : String(error);
    process.stderr.write(`ios-files-mcp failed to start: ${message}\n`);
    process.exit(1);
});
//# sourceMappingURL=index.js.map