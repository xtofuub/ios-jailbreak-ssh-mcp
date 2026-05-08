import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { type OperationLogger } from "./logger.js";
import type { SftpFileService } from "./sftpFileService.js";
import type { ServerConfig } from "./types.js";
export declare function createMcpServer(service: SftpFileService, logger: OperationLogger, config: ServerConfig): McpServer;
