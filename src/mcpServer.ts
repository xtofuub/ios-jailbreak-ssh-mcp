import { McpServer, type ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ShapeOutput, ZodRawShapeCompat } from "@modelcontextprotocol/sdk/server/zod-compat.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { publicError, redactToolInput, type OperationLogger } from "./logger.js";
import type { SftpFileService } from "./sftpFileService.js";
import type { ServerConfig } from "./types.js";
import { WriteApprovalManager, WriteApprovalRequiredError } from "./writeApproval.js";

type ToolResult = CallToolResult;

type ToolHandler<T extends ZodRawShapeCompat> = (args: ShapeOutput<T>) => Promise<unknown>;

export function createMcpServer(
  service: SftpFileService,
  logger: OperationLogger,
  config: ServerConfig
): McpServer {
  const server = new McpServer({
    name: "ios-jailbreak-ssh-mcp",
    version: "0.1.0"
  });
  const writeApprovals = new WriteApprovalManager(config);

  registerTool(
    server,
    logger,
    "ios_list_dir",
    "List entries in a safe allowed iOS directory.",
    { path: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.listDir(args.path)
  );

  registerTool(
    server,
    logger,
    "ios_read_file",
    "Read a UTF-8 file from a safe allowed iOS path, subject to maxReadSize.",
    { path: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.readFile(args.path)
  );

  registerTool(
    server,
    logger,
    "ios_read_file_chunk",
    "Read a bounded chunk from a safe allowed iOS file. Use for large files instead of repeated full reads.",
    {
      path: z.string(),
      offset: z.number().int().nonnegative().optional(),
      length: z.number().int().positive().optional(),
      encoding: z.enum(["utf8", "base64"]).optional()
    },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.readFileChunk(args.path, args.offset, args.length, args.encoding)
  );

  registerTool(
    server,
    logger,
    "ios_tail_file",
    "Read the last bytes of a safe allowed iOS text/log file.",
    {
      path: z.string(),
      maxBytes: z.number().int().positive().optional()
    },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.tailFile(args.path, args.maxBytes)
  );

  registerTool(
    server,
    logger,
    "ios_read_last_lines",
    "Read the last N lines of a safe allowed iOS text/log file.",
    {
      path: z.string(),
      lines: z.number().int().positive().max(5000).optional(),
      maxBytes: z.number().int().positive().optional()
    },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.readLastLines(args.path, args.lines, args.maxBytes)
  );

  registerTool(
    server,
    logger,
    "ios_download_file",
    "Download a file from the iPhone to a safe local path on this computer without using maxReadSize.",
    {
      remotePath: z.string(),
      localPath: z.string(),
      overwrite: z.boolean().optional()
    },
    { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    (args) => service.downloadFile(args.remotePath, args.localPath, args.overwrite)
  );

  registerTool(
    server,
    logger,
    "ios_zip_download",
    "Download one or more safe allowed iOS files/directories as a ZIP to a safe local path on this computer.",
    {
      paths: z.array(z.string()).min(1),
      localPath: z.string(),
      overwrite: z.boolean().optional()
    },
    { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    (args) => service.zipDownload(args.paths, args.localPath, args.overwrite)
  );

  registerWriteTool(
    server,
    logger,
    writeApprovals,
    "ios_write_file",
    "Write UTF-8 content to a safe allowed iOS path. Existing files are backed up when configured.",
    {
      path: z.string(),
      content: z.string(),
      approvalId: z.string().optional()
    },
    { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    (args) => service.writeFile(args.path, args.content)
  );

  registerWriteTool(
    server,
    logger,
    writeApprovals,
    "ios_append_file",
    "Append UTF-8 content to a safe allowed iOS path.",
    {
      path: z.string(),
      content: z.string(),
      approvalId: z.string().optional()
    },
    { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    (args) => service.appendFile(args.path, args.content)
  );

  registerWriteTool(
    server,
    logger,
    writeApprovals,
    "ios_delete_file",
    "Delete a file or empty directory at a safe allowed iOS path.",
    { path: z.string(), approvalId: z.string().optional() },
    { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    (args) => service.deleteFile(args.path)
  );

  registerWriteTool(
    server,
    logger,
    writeApprovals,
    "ios_move_file",
    "Move or rename a file within safe allowed iOS paths. Existing destinations are backed up when configured.",
    {
      from: z.string(),
      to: z.string(),
      approvalId: z.string().optional()
    },
    { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    (args) => service.moveFile(args.from, args.to)
  );

  registerWriteTool(
    server,
    logger,
    writeApprovals,
    "ios_copy_file",
    "Copy a file between safe allowed iOS paths. Existing destinations are backed up when configured.",
    {
      from: z.string(),
      to: z.string(),
      approvalId: z.string().optional()
    },
    { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    (args) => service.copyFile(args.from, args.to)
  );

  registerWriteTool(
    server,
    logger,
    writeApprovals,
    "ios_mkdir",
    "Create a directory within safe allowed iOS paths.",
    { path: z.string(), approvalId: z.string().optional() },
    { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    (args) => service.mkdir(args.path)
  );

  registerTool(
    server,
    logger,
    "ios_stat",
    "Return stat metadata for a safe allowed iOS path.",
    { path: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.stat(args.path)
  );

  registerTool(
    server,
    logger,
    "ios_exists",
    "Check whether a safe allowed iOS path exists without throwing for missing files.",
    { path: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.existsPath(args.path)
  );

  registerTool(
    server,
    logger,
    "ios_search_files",
    "Bounded recursive search under a safe allowed iOS root. Prefer ios_find_app for app lookup.",
    {
      root: z.string(),
      pattern: z.string(),
      maxResults: z.number().int().positive().max(500).optional(),
      maxDepth: z.number().int().nonnegative().max(25).optional(),
      includeMetadata: z.boolean().optional(),
      useCache: z.boolean().optional()
    },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) =>
      service.searchFiles(args.root, args.pattern, {
        maxResults: args.maxResults,
        maxDepth: args.maxDepth,
        includeMetadata: args.includeMetadata,
        useCache: args.useCache
      })
  );

  registerTool(
    server,
    logger,
    "ios_read_plist",
    "Parse an XML or binary plist at a safe allowed iOS path.",
    { path: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.readPlist(args.path)
  );

  registerTool(
    server,
    logger,
    "ios_find_app",
    "Quickly locate an App Store app by name or bundle id without recursively crawling app bundles.",
    { query: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.findApp(args.query)
  );

  registerTool(
    server,
    logger,
    "ios_list_apps",
    "List installed App Store app bundles from the shallow app bundle roots. Optional query filters names and bundle ids.",
    {
      query: z.string().optional(),
      limit: z.number().int().positive().max(500).optional()
    },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.listApps(args.query, args.limit)
  );

  registerTool(
    server,
    logger,
    "ios_resolve_app_container",
    "Resolve an app bundle id to its .app bundle, data container, and app group containers.",
    { bundleId: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.resolveAppContainer(args.bundleId)
  );

  registerTool(
    server,
    logger,
    "ios_list_preferences",
    "List readable Library/Preferences plist files for an app bundle id.",
    { bundleId: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.listPreferences(args.bundleId)
  );

  registerTool(
    server,
    logger,
    "ios_read_preferences",
    "Read app preference plists for a bundle id. By default reads only the exact bundle-id plist.",
    {
      bundleId: z.string(),
      includeAll: z.boolean().optional(),
      maxFiles: z.number().int().positive().max(50).optional()
    },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.readPreferences(args.bundleId, args.includeAll, args.maxFiles)
  );

  registerTool(
    server,
    logger,
    "ios_read_sqlite_schema",
    "Read table/view schema from a safe allowed SQLite database on the iPhone.",
    { path: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.readSqliteSchema(args.path)
  );

  registerTool(
    server,
    logger,
    "ios_query_sqlite",
    "Run one read-only SQL statement against a safe allowed SQLite database on the iPhone.",
    {
      path: z.string(),
      sql: z.string(),
      limit: z.number().int().positive().max(500).optional()
    },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.querySqlite(args.path, args.sql, args.limit)
  );

  registerTool(
    server,
    logger,
    "ios_diagnose_roots",
    "Check which expected iOS app filesystem roots are visible over the current SFTP login.",
    {},
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    async () => service.diagnoseRoots()
  );

  registerTool(
    server,
    logger,
    "ios_hash_file",
    "Compute a SHA-256 hash for a safe allowed iOS file, subject to maxReadSize.",
    { path: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.hashFile(args.path)
  );

  return server;
}

function registerTool<T extends ZodRawShapeCompat>(
  server: McpServer,
  logger: OperationLogger,
  name: string,
  description: string,
  schema: T,
  annotations: ToolAnnotations,
  handler: ToolHandler<T>
): void {
  const callback = (async (args: ShapeOutput<T>) => {
    const start = Date.now();
    const input = redactToolInput(args as Record<string, unknown>);

    try {
      const result = await handler(args);
      await logger.log({
        operation: name,
        input,
        ok: true,
        durationMs: Date.now() - start
      });

      return textResult(result);
    } catch (error) {
      const message = publicError(error);
      await logger.log({
        operation: name,
        input,
        ok: false,
        error: message,
        durationMs: Date.now() - start
      });

      if (error instanceof WriteApprovalRequiredError) {
        return textResult(error.request, true);
      }

      return textResult({ error: message }, true);
    }
  }) as unknown as ToolCallback<T>;

  server.registerTool<ZodRawShapeCompat, T>(
    name,
    {
      description,
      inputSchema: schema,
      annotations
    },
    callback
  );
}

function registerWriteTool<T extends ZodRawShapeCompat>(
  server: McpServer,
  logger: OperationLogger,
  writeApprovals: WriteApprovalManager,
  name: string,
  description: string,
  schema: T,
  annotations: ToolAnnotations,
  handler: ToolHandler<T>
): void {
  registerTool(server, logger, name, description, schema, annotations, async (args) => {
    writeApprovals.requireApproval(name, args as Record<string, unknown>);
    return handler(args);
  });
}

function textResult(value: unknown, isError = false): ToolResult {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return {
    content: [{ type: "text", text }],
    isError
  };
}
