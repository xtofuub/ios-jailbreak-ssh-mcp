import { McpServer, type ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ShapeOutput, ZodRawShapeCompat } from "@modelcontextprotocol/sdk/server/zod-compat.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { publicError, redactToolInput, type OperationLogger } from "./logger.js";
import type { FridaService } from "./fridaService.js";
import { registerFridaTools } from "./fridaTools.js";
import type { SftpFileService } from "./sftpFileService.js";
import type { ServerConfig } from "./types.js";
import { WriteApprovalManager, WriteApprovalRequiredError } from "./writeApproval.js";

type ToolResult = CallToolResult;

type ToolHandler<T extends ZodRawShapeCompat> = (args: ShapeOutput<T>) => Promise<unknown>;

export function createMcpServer(
  service: SftpFileService,
  logger: OperationLogger,
  config: ServerConfig,
  fridaService?: FridaService
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
    "ios_inspect_js_bundle",
    "Detect whether a React Native bundle is plain JavaScript, Hermes bytecode, or unknown binary.",
    { path: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    (args) => service.inspectJsBundle(args.path)
  );

  registerTool(
    server,
    logger,
    "ios_decode_js_bundle",
    "Decode a React Native JS bundle. Plain jsbundle files are beautified; Hermes bytecode uses the configured local decoder command.",
    {
      path: z.string(),
      mode: z.enum(["preview", "save"]).optional(),
      localPath: z.string().optional(),
      maxOutputBytes: z.number().int().positive().optional(),
      beautify: z.boolean().optional()
    },
    { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    (args) =>
      service.decodeJsBundle(args.path, {
        mode: args.mode,
        localPath: args.localPath,
        maxOutputBytes: args.maxOutputBytes,
        beautify: args.beautify
      })
  );

  registerTool(
    server,
    logger,
    "ios_list_hermes_decoders",
    "Show configured and auto-detected local Hermes bytecode decoders such as hermes-dec, hermesc, and hbctool.",
    {},
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    async () => service.listHermesDecoders()
  );

  registerTool(
    server,
    logger,
    "ios_find_app",
    "Quickly locate an App Store app by name or bundle id without recursively crawling app bundles.",
    { query: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    async (args) => {
      const query = args.query.trim();
      if (fridaService && config.frida?.enabled) {
        try {
          const detected = await fridaService.detectFrida();
          if (detected.found) {
            const apps = await fridaService.listApps();
            const q = query.toLowerCase();
            const filtered = apps.filter((a) => {
              const name = (a.name ?? "").toLowerCase();
              const bid = (a.bundleId ?? "").toLowerCase();
              return name.includes(q) || bid.includes(q);
            });

            const bundleMatches = filtered.map((a) => toAppBundleMatchFromFrida(a));
            const dataContainerMatches = filtered
              .map((a) => toDataContainerMatchFromFrida(a))
              .filter(Boolean);

            return {
              query,
              bundleMatches,
              dataContainerMatches,
              appGroupMatches: [],
              searchedRoots: [`frida:${detected.connectionMode ?? "unknown"}`],
              truncated: false,
              notes: ["Found apps via Frida (LSApplicationWorkspace)."]
            };
          }
        } catch {
          // Fall back to SSH/SFTP scan below.
        }
      }
      return service.findApp(query);
    }
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
    async (args) => {
      const query = args.query?.trim();
      const limit = args.limit ?? 200;
      if (fridaService && config.frida?.enabled) {
        try {
          const detected = await fridaService.detectFrida();
          if (detected.found) {
            const apps = await fridaService.listApps();
            const q = query ? query.toLowerCase() : undefined;
            const filtered = q
              ? apps.filter((a) => {
                  const name = (a.name ?? "").toLowerCase();
                  const bid = (a.bundleId ?? "").toLowerCase();
                  return name.includes(q) || bid.includes(q);
                })
              : apps;
            const mapped = filtered.map((a) => toAppBundleMatchFromFrida(a)).slice(0, limit);
            return {
              apps: mapped,
              appCount: mapped.length,
              searchedRoots: [`frida:${detected.connectionMode ?? "unknown"}`],
              truncated: filtered.length > limit,
              notes: ["Listed apps via Frida (LSApplicationWorkspace)."]
            };
          }
        } catch {
          // Fall back to SSH/SFTP scan below.
        }
      }
      return service.listApps(query, limit);
    }
  );

  registerTool(
    server,
    logger,
    "ios_resolve_app_container",
    "Resolve an app bundle id to its .app bundle, data container, and app group containers.",
    { bundleId: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    async (args) => {
      const bundleId = args.bundleId.trim();
      if (fridaService && config.frida?.enabled) {
        try {
          const detected = await fridaService.detectFrida();
          if (detected.found) {
            const infoEvents = await fridaService.getAppInfo(bundleId);
            const appInfo = infoEvents.find((e) => e.type === "app_info") as
              | { type: "app_info"; found?: boolean; info?: Record<string, unknown> }
              | undefined;
            const info = appInfo?.info;

            const name = typeof info?.name === "string" ? info.name : bundleId;
            const bundlePath = typeof info?.bundlePath === "string" ? info.bundlePath : null;
            const dataPath = typeof info?.dataPath === "string" ? info.dataPath : null;
            const version = typeof info?.shortVersion === "string" ? info.shortVersion : (typeof info?.version === "string" ? info.version : undefined);

            const primaryBundle = bundlePath
              ? toAppBundleMatchFromParts({
                  appName: name,
                  bundleId,
                  bundlePath,
                  version
                })
              : undefined;

            const primaryDataContainer = dataPath
              ? toContainerMatchFromPath(dataPath, bundleId, "data")
              : undefined;

            const appGroupMatches = [];
            const appGroups = info && typeof info === "object" ? (info as any).appGroups : undefined;
            if (appGroups && typeof appGroups === "object") {
              for (const [groupId, groupPath] of Object.entries(appGroups as Record<string, unknown>)) {
                if (typeof groupId === "string" && typeof groupPath === "string") {
                  appGroupMatches.push(toContainerMatchFromPath(groupPath, groupId, "app_group"));
                }
              }
            }

            return {
              query: bundleId,
              bundleId,
              bundleMatches: primaryBundle ? [primaryBundle] : [],
              dataContainerMatches: primaryDataContainer ? [primaryDataContainer] : [],
              appGroupMatches,
              searchedRoots: [`frida:${detected.connectionMode ?? "unknown"}`],
              truncated: false,
              notes: ["Resolved app info via Frida (LSApplicationProxy)."],
              primaryBundle,
              primaryDataContainer,
              primaryAppGroup: appGroupMatches[0]
            };
          }
        } catch {
          // Fall back to SSH/SFTP scan below.
        }
      }
      return service.resolveAppContainer(bundleId);
    }
  );

  registerTool(
    server,
    logger,
    "ios_list_preferences",
    "List readable Library/Preferences plist files for an app bundle id.",
    { bundleId: z.string() },
    { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    async (args) => {
      const bundleId = args.bundleId.trim();
      if (fridaService && config.frida?.enabled) {
        try {
          const detected = await fridaService.detectFrida();
          if (detected.found) {
            const resolved = (await (async () => {
              const infoEvents = await fridaService.getAppInfo(bundleId);
              const appInfo = infoEvents.find((e) => e.type === "app_info") as
                | { type: "app_info"; found?: boolean; info?: Record<string, unknown> }
                | undefined;
              const info = appInfo?.info;
              const dataPath = typeof info?.dataPath === "string" ? info.dataPath : null;
              return dataPath ? [dataPath] : [];
            })());

            const preferenceDirectories: string[] = [];
            const preferenceFiles: Array<{ path: string; name: string; size: number; modifyTime: string | null }> = [];

            for (const dataPath of resolved) {
              const prefDir = `${dataPath.replace(/\/$/, "")}/Library/Preferences`;
              try {
                const entries = await service.listDir(prefDir);
                preferenceDirectories.push(prefDir);
                for (const e of entries) {
                  if (e.type !== "file" || !e.name.endsWith(".plist")) continue;
                  preferenceFiles.push({
                    path: `${prefDir}/${e.name}`,
                    name: e.name,
                    size: e.size,
                    modifyTime: e.modifyTime ?? null
                  });
                }
              } catch {
                // If the dir doesn't exist or isn't readable, just skip it.
              }
            }

            const notes: string[] = [
              `Resolved data container via Frida (${detected.connectionMode ?? "unknown"}).`
            ];
            if (preferenceFiles.length === 0) {
              notes.push("No readable preference plist files were found in the matched data containers.");
            }

            return {
              bundleId,
              preferenceDirectories,
              preferenceFiles,
              notes
            };
          }
        } catch {
          // Fall back to SSH/SFTP scan below.
        }
      }
      return service.listPreferences(bundleId);
    }
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
    async (args) => {
      const bundleId = args.bundleId.trim();
      const includeAll = args.includeAll ?? false;
      const maxFiles = args.maxFiles ?? 10;

      if (fridaService && config.frida?.enabled) {
        try {
          const detected = await fridaService.detectFrida();
          if (detected.found) {
            const infoEvents = await fridaService.getAppInfo(bundleId);
            const appInfo = infoEvents.find((e) => e.type === "app_info") as
              | { type: "app_info"; found?: boolean; info?: Record<string, unknown> }
              | undefined;
            const info = appInfo?.info;
            const dataPath = typeof info?.dataPath === "string" ? info.dataPath : null;
            const preferenceDirectories: string[] = [];
            const preferenceFiles: Array<{ path: string; name: string; size: number; modifyTime: string | null }> = [];

            if (dataPath) {
              const prefDir = `${dataPath.replace(/\/$/, "")}/Library/Preferences`;
              try {
                const entries = await service.listDir(prefDir);
                preferenceDirectories.push(prefDir);
                for (const e of entries) {
                  if (e.type !== "file" || !e.name.endsWith(".plist")) continue;
                  preferenceFiles.push({
                    path: `${prefDir}/${e.name}`,
                    name: e.name,
                    size: e.size,
                    modifyTime: e.modifyTime ?? null
                  });
                }
              } catch {
                // ignore
              }
            }

            const bundleIdLower = bundleId.toLowerCase();
            const selected = preferenceFiles
              .filter((f) => includeAll || f.name.toLowerCase() === `${bundleIdLower}.plist`)
              .slice(0, maxFiles);

            const values: Array<{ path: string; name: string; format: string; value: unknown }> = [];
            for (const f of selected) {
              const parsed = await service.readPlist(f.path);
              values.push({
                path: f.path,
                name: f.name,
                format: (parsed as any).format ?? "unknown",
                value: (parsed as any).value ?? parsed
              });
            }

            const notes: string[] = [
              `Resolved data container via Frida (${detected.connectionMode ?? "unknown"}).`
            ];
            if (!includeAll && values.length === 0 && preferenceFiles.length > 0) {
              notes.push("No exact bundle-id preference plist was found. Retry with includeAll=true to read nearby preference files.");
            }

            return {
              bundleId,
              preferenceDirectories,
              preferenceFiles,
              notes,
              values
            };
          }
        } catch {
          // Fall back to SSH/SFTP scan below.
        }
      }

      return service.readPreferences(bundleId, includeAll, maxFiles);
    }
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

  if (fridaService && config.frida?.enabled) {
    registerFridaTools(server, logger, fridaService);
  }

  return server;
}

type ResolvedAppInfo = {
  bundleId: string;
  name: string;
  bundlePath: string | null;
  dataPath: string | null;
  executableName: string | null;
};

async function resolveBundleIdFromQuery(
  query: string,
  service: SftpFileService,
  fridaService: FridaService | undefined,
  config: ServerConfig
): Promise<string> {
  // If it already looks like a bundle id, just return it.
  if (query.includes(".") && !query.includes(" ")) return query;

  // Prefer Frida list-apps when possible.
  if (fridaService && config.frida?.enabled) {
    const detected = await fridaService.detectFrida();
    if (detected.found) {
      const apps = await fridaService.listApps();
      const q = query.toLowerCase();
      const match = apps.find((a) => (a.name ?? "").toLowerCase().includes(q)) ?? apps.find((a) => (a.bundleId ?? "").toLowerCase().includes(q));
      if (match?.bundleId) return match.bundleId;
    }
  }

  const found = await service.findApp(query);
  const primary = found.bundleMatches.find((m) => m.bundleId) ?? found.bundleMatches[0];
  if (!primary?.bundleId) throw new Error(`Could not resolve bundle id from query '${query}'.`);
  return primary.bundleId;
}

async function resolveAppInfo(
  bundleId: string,
  service: SftpFileService,
  fridaService: FridaService | undefined,
  config: ServerConfig
): Promise<ResolvedAppInfo> {
  if (fridaService && config.frida?.enabled) {
    const detected = await fridaService.detectFrida();
    if (detected.found) {
      const events = await fridaService.getAppInfo(bundleId);
      const appInfo = events.find((e) => e.type === "app_info") as any;
      const info = appInfo?.info ?? {};
      const name = typeof info.name === "string" ? info.name : bundleId;
      const bundlePath = typeof info.bundlePath === "string" ? info.bundlePath : null;
      const dataPath = typeof info.dataPath === "string" ? info.dataPath : null;
      const executableName = await tryGetExecutableName(service, bundlePath);
      return { bundleId, name, bundlePath, dataPath, executableName };
    }
  }

  const resolved = await service.resolveAppContainer(bundleId);
  const primaryBundle: any = (resolved as any).primaryBundle;
  const name = primaryBundle?.displayName || primaryBundle?.bundleName || primaryBundle?.appName || bundleId;
  const bundlePath = primaryBundle?.path ?? null;
  const executableName = await tryGetExecutableName(service, bundlePath);
  // data container
  const primaryData: any = (resolved as any).primaryDataContainer ?? (resolved as any).dataContainerMatches?.[0];
  const dataPath = primaryData?.path ?? null;
  return { bundleId, name, bundlePath, dataPath, executableName };
}

async function tryGetExecutableName(service: SftpFileService, bundlePath: string | null): Promise<string | null> {
  if (!bundlePath) return null;
  try {
    const plist = await service.readPlist(`${bundlePath.replace(/\/$/, "")}/Info.plist`);
    const value = (plist as any)?.value ?? (plist as any);
    const exe = value?.CFBundleExecutable;
    return typeof exe === "string" && exe.trim() ? exe.trim() : null;
  } catch {
    return null;
  }
}

async function tryGetRemoteFileSize(service: SftpFileService, remotePath: string): Promise<number | null> {
  try {
    const parent = remotePath.replace(/\/[^/]+$/, "");
    const name = remotePath.split("/").pop();
    if (!name) return null;
    const entries = await service.listDir(parent);
    const hit = entries.find((e) => e.name === name);
    return typeof hit?.size === "number" ? hit.size : null;
  } catch {
    return null;
  }
}

async function ensureArtifactsDir(bundleId: string): Promise<string> {
  const safe = bundleId.replace(/[^a-zA-Z0-9._-]+/g, "_");
  const dir = path.join(process.cwd(), "artifacts", safe, String(Date.now()));
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

async function fingerprintApp(app: ResolvedAppInfo, service: SftpFileService): Promise<{ stack: string; evidence: string[] }> {
  const evidence: string[] = [];
  let stack = "unknown";
  if (!app.bundlePath) return { stack, evidence };

  try {
    const entries = await service.listDir(app.bundlePath);
    const names = new Set(entries.map((e) => e.name));
    if (names.has("main.jsbundle")) {
      stack = "react_native";
      evidence.push("main.jsbundle");
    }
    if (names.has("flutter_assets")) {
      stack = "flutter";
      evidence.push("flutter_assets");
    }
    if (names.has("Frameworks")) {
      try {
        const fw = await service.listDir(`${app.bundlePath.replace(/\/$/, "")}/Frameworks`);
        const fwNames = fw.map((e) => e.name);
        if (fwNames.some((n) => n.toLowerCase() === "flutter.framework")) {
          stack = "flutter";
          evidence.push("Frameworks/Flutter.framework");
        }
        if (fwNames.some((n) => n.toLowerCase() === "unityframework.framework")) {
          stack = "unity";
          evidence.push("Frameworks/UnityFramework.framework");
        }
      } catch {
        // ignore
      }
    }
  } catch {
    // ignore
  }
  if (stack === "unknown") {
    stack = "native_or_unknown";
    evidence.push("no RN/Flutter/Unity markers found");
  }
  return { stack, evidence };
}

type ScanResult = { endpoints: string[]; hosts: string[]; hardcoded: string[] };

function mergeScan(target: { endpoints: string[]; hosts: string[]; hardcoded: string[] }, scan: ScanResult): void {
  target.endpoints.push(...scan.endpoints);
  target.hosts.push(...scan.hosts);
  target.hardcoded.push(...scan.hardcoded);
}

async function scanTextFileForEndpointsAndSecrets(localPath: string, maxBytes: number): Promise<ScanResult> {
  const text = await readLocalTextSlice(localPath, maxBytes, "utf8");
  return scanTextForEndpointsAndSecrets(text);
}

async function scanFileForEndpointsAndSecrets(localPath: string, maxBytes: number): Promise<ScanResult> {
  const text = await readLocalTextSlice(localPath, maxBytes, "latin1");
  return scanTextForEndpointsAndSecrets(text);
}

async function readLocalTextSlice(localPath: string, maxBytes: number, encoding: BufferEncoding): Promise<string> {
  const fh = await fs.open(localPath, "r");
  try {
    const buf = Buffer.allocUnsafe(Math.min(maxBytes, 8 * 1024 * 1024)); // cap single read to 8MiB
    let offset = 0;
    const chunks: Buffer[] = [];
    while (offset < maxBytes) {
      const toRead = Math.min(buf.byteLength, maxBytes - offset);
      const { bytesRead } = await fh.read(buf, 0, toRead, offset);
      if (bytesRead <= 0) break;
      chunks.push(Buffer.from(buf.subarray(0, bytesRead)));
      offset += bytesRead;
      if (chunks.length >= 50) break; // hard cap to avoid memory blowups
    }
    return Buffer.concat(chunks).toString(encoding);
  } finally {
    await fh.close();
  }
}

function scanTextForEndpointsAndSecrets(text: string): ScanResult {
  const endpoints: string[] = [];
  const hosts: string[] = [];
  const hardcoded: string[] = [];

  const urlRe = /\bhttps?:\/\/[^\s"'<>\\]+/gi;
  for (const m of text.matchAll(urlRe)) {
    const u = m[0];
    endpoints.push(u);
    try {
      const host = new URL(u).host;
      if (host) hosts.push(host);
    } catch {
      // ignore
    }
  }

  // JWT-like
  const jwtRe = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
  for (const m of text.matchAll(jwtRe)) hardcoded.push(`jwt:${m[0].slice(0, 60)}…`);

  // API-key-ish tokens (very heuristic)
  const keyRe = /\b(api[_-]?key|client[_-]?secret|secret|token)\b\s*[:=]\s*["']([^"']{8,200})["']/gi;
  for (const m of text.matchAll(keyRe)) {
    hardcoded.push(`${m[1]}=${m[2].slice(0, 80)}${m[2].length > 80 ? "…" : ""}`);
  }

  // Sentry DSN
  const sentryRe = /\bhttps?:\/\/[a-f0-9]{16,32}@[a-z0-9.-]+\/\d+\b/gi;
  for (const m of text.matchAll(sentryRe)) hardcoded.push(`sentry_dsn:${m[0]}`);

  return { endpoints, hosts, hardcoded };
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function parseContainerUuidFromPath(p: string): string {
  // /var/containers/Bundle/Application/<UUID>/App.app
  // /var/mobile/Containers/Data/Application/<UUID>/
  const match = /\/Application\/([0-9A-Fa-f-]{8,})\b/.exec(p);
  return match?.[1] ?? "unknown";
}

function toAppBundleMatchFromParts(input: {
  appName: string;
  bundleId?: string;
  bundlePath: string;
  version?: string;
}): Record<string, unknown> {
  const containerUuid = parseContainerUuidFromPath(input.bundlePath);
  const infoPlistPath = input.bundlePath.endsWith(".app")
    ? `${input.bundlePath.replace(/\/$/, "")}/Info.plist`
    : `${input.bundlePath.replace(/\/$/, "")}/Info.plist`;

  return {
    appName: input.appName,
    path: input.bundlePath,
    infoPlistPath,
    containerUuid,
    bundleId: input.bundleId,
    displayName: input.appName,
    bundleName: input.appName,
    version: input.version
  };
}

function toAppBundleMatchFromFrida(a: { bundleId: string; name: string; bundlePath: string | null; shortVersion: string | null; version: string | null }): Record<string, unknown> {
  const name = a.name || a.bundleId;
  const bundlePath = a.bundlePath ?? "";
  return toAppBundleMatchFromParts({
    appName: name,
    bundleId: a.bundleId,
    bundlePath,
    version: a.shortVersion ?? a.version ?? undefined
  });
}

function toContainerMatchFromPath(pathValue: string, identifier: string, kind: "data" | "app_group"): Record<string, unknown> {
  const containerUuid = parseContainerUuidFromPath(pathValue);
  const metadataPlistPath = `${pathValue.replace(/\/$/, "")}/.com.apple.mobile_container_manager.metadata.plist`;
  return {
    path: pathValue,
    metadataPlistPath,
    containerUuid,
    identifiers: [identifier],
    matchedBy: [`frida_${kind}`]
  };
}

function toDataContainerMatchFromFrida(a: { bundleId: string; dataPath: string | null }): Record<string, unknown> | null {
  if (!a.dataPath) return null;
  return toContainerMatchFromPath(a.dataPath, a.bundleId, "data");
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
