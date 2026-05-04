import { createWriteStream, existsSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat as localStat,
  writeFile as writeLocalFile
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname as localDirname, join as joinLocal, relative, resolve as resolveLocal } from "node:path";
import { spawn } from "node:child_process";
import archiver from "archiver";
import beautify from "js-beautify";
import { parse as parseXmlPlist, parseBinary as parseBinaryPlist, type PlistValue } from "plist";
import Client from "ssh2-sftp-client";
import {
  assertSafePath,
  assertWritable,
  backupPathFor,
  basename,
  dirname,
  joinRemote,
  normalizeRemotePath
} from "./pathSafety.js";
import type { ServerConfig } from "./types.js";

type FileEntry = {
  name: string;
  type: "file" | "directory" | "symlink" | "other";
  size: number;
  modifyTime: string | null;
  accessTime: string | null;
  rights?: unknown;
  owner?: number;
  group?: number;
};

type StatResult = {
  path: string;
  type: "file" | "directory" | "symlink" | "other";
  size: number;
  modifyTime: string | null;
  accessTime: string | null;
  mode?: number;
  owner?: number;
  group?: number;
};

type SearchResult = {
  path: string;
  type: FileEntry["type"];
  size?: number;
  modifyTime?: string | null;
};

type SearchFilesOptions = {
  maxResults?: number;
  maxDepth?: number;
  includeMetadata?: boolean;
  useCache?: boolean;
};

type SearchFilesResult = {
  root: string;
  pattern: string;
  results: SearchResult[];
  resultCount: number;
  visitedDirectories: number;
  maxResults: number;
  maxDepth: number;
  cached: boolean;
  truncated: boolean;
  notes: string[];
};

type SearchCacheEntry = {
  expiresAt: number;
  value: Omit<SearchFilesResult, "cached">;
};

type PlistReadResult = {
  path: string;
  format: "binary" | "xml";
  value: unknown;
};

type AppBundleMatch = {
  appName: string;
  path: string;
  infoPlistPath: string;
  containerUuid: string;
  bundleId?: string;
  displayName?: string;
  bundleName?: string;
  version?: string;
  build?: string;
};

type AppContainerMatch = {
  path: string;
  metadataPlistPath: string;
  containerUuid: string;
  identifiers: string[];
  matchedBy: string[];
};

type FindAppResult = {
  query: string;
  bundleMatches: AppBundleMatch[];
  dataContainerMatches: AppContainerMatch[];
  appGroupMatches: AppContainerMatch[];
  searchedRoots: string[];
  truncated: boolean;
  notes: string[];
};

type ListAppsResult = {
  apps: AppBundleMatch[];
  appCount: number;
  searchedRoots: string[];
  truncated: boolean;
  notes: string[];
};

type ResolveAppContainerResult = FindAppResult & {
  bundleId: string;
  primaryBundle?: AppBundleMatch;
  primaryDataContainer?: AppContainerMatch;
  primaryAppGroup?: AppContainerMatch;
};

type ExistsResult = {
  path: string;
  exists: boolean;
  type?: FileEntry["type"];
  size?: number;
};

type FileChunkResult = {
  path: string;
  offset: number;
  length: number;
  bytesRead: number;
  encoding: "utf8" | "base64";
  content: string;
  fileSize: number;
};

type LastLinesResult = {
  path: string;
  lines: number;
  maxBytes: number;
  bytesRead: number;
  content: string;
  truncated: boolean;
  fileSize: number;
};

type PreferenceFile = {
  path: string;
  name: string;
  size: number;
  modifyTime: string | null;
};

type ListPreferencesResult = {
  bundleId: string;
  preferenceDirectories: string[];
  preferenceFiles: PreferenceFile[];
  notes: string[];
};

type ReadPreferencesResult = ListPreferencesResult & {
  values: Array<PlistReadResult & { name: string }>;
};

type SqliteSchemaResult = {
  path: string;
  size: number;
  tables: Array<{
    name: string;
    type: string;
    sql?: string;
    columns?: Array<{ cid: number; name: string; type: string; notnull: number; defaultValue: unknown; pk: number }>;
  }>;
};

type SqliteQueryResult = {
  path: string;
  columns: string[];
  rows: Array<Record<string, unknown>>;
  rowCount: number;
  returnedRows: number;
  limit: number;
};

type ZipDownloadResult = {
  paths: string[];
  localPath: string;
  entriesAdded: number;
  bytesWritten: number;
};

type JsBundleFormat = "hermes-bytecode" | "plain-js" | "unknown-binary";

type JsBundleInspectResult = {
  path: string;
  size: number;
  format: JsBundleFormat;
  magic: string;
  notes: string[];
};

type JsBundleDecodeResult = JsBundleInspectResult & {
  mode: "preview" | "save";
  decodedKind: "beautified-js" | "hermes-disassembly" | "raw-text";
  decoder?: string;
  content?: string;
  localPath?: string;
  bytesWritten?: number;
  stderr?: string;
};

type HermesDecoderPreset = ServerConfig["hermesDecoderPreset"];

type HermesDecoderInfo = {
  preset: HermesDecoderPreset;
  commandName?: string;
  commandTemplate?: string;
  available: boolean;
  notes: string[];
};

type HermesDecoderChoice = {
  preset: HermesDecoderPreset;
  commandTemplate: string;
};

type RootDiagnostic = {
  path: string;
  allowed: boolean;
  exists: boolean;
  realPath?: string;
  entryCount?: number;
  sampleEntries?: string[];
  error?: string;
};

type DiagnoseRootsResult = {
  username: string;
  host: string;
  allowedRoots: string[];
  roots: RootDiagnostic[];
  notes: string[];
};

const SEARCH_ABSOLUTE_MAX_RESULTS = 500;
const SEARCH_ABSOLUTE_MAX_DEPTH = 25;
const APP_CONTAINER_SCAN_LIMIT = 1_000;
const APP_METADATA_READ_LIMIT = 512 * 1024;
const ZIP_ENTRY_LIMIT = 5_000;
const HERMES_DECODER_PRESETS: Array<{
  preset: Exclude<HermesDecoderPreset, "auto" | "custom" | "jsc2llvm">;
  commandName: string;
  commandTemplate: string;
  notes: string[];
}> = [
  {
    preset: "hbc-decompiler",
    commandName: "hbc-decompiler",
    commandTemplate: "hbc-decompiler {input} {output}",
    notes: ["hermes-dec pseudo-code decompiler. Output is easier to scan but is not original source JavaScript."]
  },
  {
    preset: "hbc-disassembler",
    commandName: "hbc-disassembler",
    commandTemplate: "hbc-disassembler {input} {output}",
    notes: ["hermes-dec disassembler. Output is Hermes assembly/disassembly."]
  },
  {
    preset: "hermesc",
    commandName: "hermesc",
    commandTemplate: "hermesc -dump-bytecode {input}",
    notes: ["Official Hermes compiler binary dump mode. Output is bytecode/disassembly, not source."]
  },
  {
    preset: "hbctool",
    commandName: "hbctool",
    commandTemplate: "hbctool disasm {input} {output}",
    notes: ["hbctool disassembles to a directory of HASM files. Some newer HBC versions may not be supported by older hbctool builds."]
  }
];
const APP_BUNDLE_ROOTS = [
  "/private/var/containers/Bundle/Application",
  "/var/containers/Bundle/Application"
] as const;
const APP_DATA_ROOTS = [
  "/private/var/mobile/Containers/Data/Application",
  "/var/mobile/Containers/Data/Application"
] as const;
const APP_GROUP_ROOTS = [
  "/private/var/mobile/Containers/Shared/AppGroup",
  "/var/mobile/Containers/Shared/AppGroup"
] as const;
const CONTAINER_METADATA_PLIST = ".com.apple.mobile_container_manager.metadata.plist";
const DIAGNOSTIC_ROOTS = [
  "/var/mobile",
  "/private/var/mobile",
  "/var/mobile/Containers",
  "/private/var/mobile/Containers",
  "/var/mobile/Containers/Data/Application",
  "/private/var/mobile/Containers/Data/Application",
  "/var/mobile/Containers/Shared/AppGroup",
  "/private/var/mobile/Containers/Shared/AppGroup",
  "/var/containers",
  "/private/var/containers",
  "/var/containers/Bundle/Application",
  "/private/var/containers/Bundle/Application",
  "/var/jb",
  "/tmp"
] as const;

export class SftpNotConnectedError extends Error {
  constructor(message = "SFTP is not connected.") {
    super(message);
    this.name = "SftpNotConnectedError";
  }
}

export class SftpFileService {
  private client: Client | undefined;
  private connecting: Promise<Client> | undefined;
  private canonicalAllowedRoots: string[] = [];
  private readonly searchCache = new Map<string, SearchCacheEntry>();

  constructor(private readonly config: ServerConfig) {}

  async close(): Promise<void> {
    if (this.client) {
      await this.client.end();
      this.client = undefined;
      this.canonicalAllowedRoots = [];
    }
  }

  async listDir(path: string): Promise<FileEntry[]> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const entries = await client.list(safePath);

    return entries.map((entry) => ({
      name: entry.name,
      type: this.mapEntryType(entry.type),
      size: Number(entry.size ?? 0),
      modifyTime: this.dateFromMillis(entry.modifyTime),
      accessTime: this.dateFromMillis(entry.accessTime),
      rights: entry.rights,
      owner: entry.owner,
      group: entry.group
    }));
  }

  async readFile(path: string): Promise<string> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);
    const size = Number(stat.size ?? 0);

    if (size > this.config.maxReadSize) {
      throw new Error(
        `File is ${size} bytes, which exceeds maxReadSize=${this.config.maxReadSize}.`
      );
    }

    const content = await client.get(safePath);
    return this.bufferFromGetResult(content).toString("utf8");
  }

  async downloadFile(
    remotePath: string,
    localPath: string,
    overwrite = false
  ): Promise<{ remotePath: string; localPath: string; bytesCopied: number }> {
    const lexicalRemotePath = assertSafePath(remotePath, this.config);
    const safeLocalPath = this.assertSafeLocalPath(localPath);
    const client = await this.connectedClient();
    const safeRemotePath = await this.resolveExistingSafePath(client, lexicalRemotePath);
    const stat = await client.stat(safeRemotePath);
    const size = Number(stat.size ?? 0);

    if (this.mapStatsType(stat) !== "file") {
      throw new Error(`Remote path is not a regular file: ${safeRemotePath}`);
    }

    if (existsSync(safeLocalPath) && !overwrite) {
      throw new Error(`Local path already exists. Set overwrite=true to replace: ${safeLocalPath}`);
    }

    await mkdir(localDirname(safeLocalPath), { recursive: true });
    await client.get(safeRemotePath, createWriteStream(safeLocalPath));

    return {
      remotePath: safeRemotePath,
      localPath: safeLocalPath,
      bytesCopied: size
    };
  }

  async writeFile(path: string, content: string): Promise<{ path: string; bytesWritten: number; backupPath?: string }> {
    assertWritable(this.config, "ios_write_file");
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveWritableTarget(client, lexicalPath);
    const backupPath = await this.backupIfExisting(client, safePath);
    const buffer = Buffer.from(content, "utf8");

    await client.put(buffer, safePath);

    return {
      path: safePath,
      bytesWritten: buffer.byteLength,
      backupPath
    };
  }

  async appendFile(path: string, content: string): Promise<{ path: string; bytesAppended: number }> {
    assertWritable(this.config, "ios_append_file");
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveWritableTarget(client, lexicalPath);
    const buffer = Buffer.from(content, "utf8");
    const existing = await this.exists(client, safePath);

    if (existing) {
      const writeStream = client.createWriteStream(safePath, { flags: "a" });
      await this.writeBufferToStream(writeStream, buffer);
    } else {
      await client.put(buffer, safePath);
    }

    return {
      path: safePath,
      bytesAppended: buffer.byteLength
    };
  }

  async deleteFile(path: string): Promise<{ path: string; deleted: true }> {
    assertWritable(this.config, "ios_delete_file");
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);

    if (this.mapStatsType(stat) === "directory") {
      await client.rmdir(safePath, false);
    } else {
      await client.delete(safePath);
    }

    return { path: safePath, deleted: true };
  }

  async moveFile(from: string, to: string): Promise<{ from: string; to: string; backupPath?: string }> {
    assertWritable(this.config, "ios_move_file");
    const lexicalFrom = assertSafePath(from, this.config);
    const lexicalTo = assertSafePath(to, this.config);
    const client = await this.connectedClient();
    const safeFrom = await this.resolveExistingSafePath(client, lexicalFrom);
    const safeTo = await this.resolveWritableTarget(client, lexicalTo);
    const targetExisted = await this.exists(client, safeTo);
    const backupPath = await this.backupIfExisting(client, safeTo);

    if (targetExisted) {
      await this.deleteExistingFileTarget(client, safeTo);
    }

    await client.rename(safeFrom, safeTo);

    return { from: safeFrom, to: safeTo, backupPath };
  }

  async copyFile(from: string, to: string): Promise<{ from: string; to: string; bytesCopied: number; backupPath?: string }> {
    assertWritable(this.config, "ios_copy_file");
    const lexicalFrom = assertSafePath(from, this.config);
    const lexicalTo = assertSafePath(to, this.config);
    const client = await this.connectedClient();
    const safeFrom = await this.resolveExistingSafePath(client, lexicalFrom);
    const safeTo = await this.resolveWritableTarget(client, lexicalTo);
    const stat = await client.stat(safeFrom);
    const size = Number(stat.size ?? 0);

    if (size > this.config.maxReadSize) {
      throw new Error(
        `Refusing to copy ${size} bytes through the MCP process because maxReadSize=${this.config.maxReadSize}.`
      );
    }

    const targetExisted = await this.exists(client, safeTo);
    const backupPath = await this.backupIfExisting(client, safeTo);
    if (targetExisted) {
      await this.deleteExistingFileTarget(client, safeTo);
    }

    await client.rcopy(safeFrom, safeTo);

    return {
      from: safeFrom,
      to: safeTo,
      bytesCopied: size,
      backupPath
    };
  }

  async mkdir(path: string): Promise<{ path: string; created: true }> {
    assertWritable(this.config, "ios_mkdir");
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveCreatableDirectory(client, lexicalPath);
    await client.mkdir(safePath, true);

    return { path: safePath, created: true };
  }

  async stat(path: string): Promise<StatResult> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);

    return {
      path: safePath,
      type: this.mapStatsType(stat),
      size: Number(stat.size ?? 0),
      modifyTime: this.dateFromMillis(stat.modifyTime),
      accessTime: this.dateFromMillis(stat.accessTime),
      mode: stat.mode,
      owner: stat.uid,
      group: stat.gid
    };
  }

  async searchFiles(
    root: string,
    pattern: string,
    options: SearchFilesOptions = {}
  ): Promise<SearchFilesResult> {
    const lexicalRoot = assertSafePath(root, this.config);
    const client = await this.connectedClient();
    const safeRoot = await this.resolveExistingSafePath(client, lexicalRoot);
    const matcher = this.matcherFromPattern(pattern);
    const maxResults = Math.min(
      options.maxResults ?? this.config.searchDefaultMaxResults,
      SEARCH_ABSOLUTE_MAX_RESULTS
    );
    const maxDepth = Math.min(
      options.maxDepth ?? this.config.searchDefaultMaxDepth,
      SEARCH_ABSOLUTE_MAX_DEPTH
    );
    const includeMetadata = options.includeMetadata ?? false;
    const useCache = options.useCache ?? true;
    const notes = this.searchNotes(safeRoot, pattern, maxDepth, maxResults);
    const cacheKey = this.searchCacheKey(safeRoot, pattern, {
      maxResults,
      maxDepth,
      includeMetadata
    });

    if (useCache) {
      const cached = this.getSearchCache(cacheKey);
      if (cached) {
        return {
          ...cached,
          cached: true
        };
      }
    }

    const pending: Array<{ path: string; depth: number }> = [{ path: safeRoot, depth: 0 }];
    const visitedPaths = new Set<string>([safeRoot]);
    const results: SearchResult[] = [];
    let visitedDirectories = 0;
    let truncated = false;

    while (pending.length > 0) {
      const current = pending.shift()!;
      visitedDirectories += 1;

      if (
        visitedDirectories > this.config.searchMaxEntries ||
        results.length >= maxResults
      ) {
        truncated = true;
        break;
      }

      let entries: Client.FileInfo[];
      try {
        entries = await client.list(current.path);
      } catch {
        continue;
      }

      for (const entry of entries) {
        const entryType = this.mapEntryType(entry.type);
        let safeChild: string;
        try {
          const childPath = this.assertCanonicalSafePath(joinRemote(current.path, entry.name));
          safeChild = assertSafePath(childPath, {
            allowedRoots: this.canonicalAllowedRoots.length
              ? this.canonicalAllowedRoots
              : this.config.allowedRoots
          });
        } catch {
          continue;
        }

        if (matcher(entry.name) || matcher(safeChild)) {
          const result: SearchResult = {
            path: safeChild,
            type: entryType
          };

          if (includeMetadata) {
            result.size = Number(entry.size ?? 0);
            result.modifyTime = this.dateFromMillis(entry.modifyTime);
          }

          results.push(result);

          if (results.length >= maxResults) {
            truncated = true;
            break;
          }
        }

        if (
          entryType === "directory" &&
          current.depth < maxDepth &&
          !visitedPaths.has(safeChild)
        ) {
          visitedPaths.add(safeChild);
          pending.push({ path: safeChild, depth: current.depth + 1 });
        }
      }
    }

    const value: Omit<SearchFilesResult, "cached"> = {
      root: safeRoot,
      pattern,
      results,
      resultCount: results.length,
      visitedDirectories,
      maxResults,
      maxDepth,
      truncated,
      notes
    };

    if (useCache) {
      this.setSearchCache(cacheKey, value);
    }

    return {
      ...value,
      cached: false
    };
  }

  async readPlist(path: string): Promise<PlistReadResult> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const parsed = await this.readPlistAt(client, safePath, this.config.maxReadSize);

    return {
      path: safePath,
      format: parsed.format,
      value: this.toJsonSafe(parsed.value)
    };
  }

  async inspectJsBundle(path: string): Promise<JsBundleInspectResult> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);
    const size = Number(stat.size ?? 0);

    if (this.mapStatsType(stat) !== "file") {
      throw new Error(`Path is not a regular file: ${safePath}`);
    }

    const header = size === 0 ? Buffer.alloc(0) : await this.readRemoteRange(client, safePath, 0, Math.min(size, 32) - 1);
    const format = this.detectJsBundleFormat(header);
    const notes = this.jsBundleNotes(format);

    return {
      path: safePath,
      size,
      format,
      magic: header.subarray(0, 16).toString("hex"),
      notes
    };
  }

  async decodeJsBundle(
    path: string,
    options: {
      mode?: "preview" | "save";
      localPath?: string;
      maxOutputBytes?: number;
      beautify?: boolean;
    } = {}
  ): Promise<JsBundleDecodeResult> {
    const inspect = await this.inspectJsBundle(path);
    const mode = options.mode ?? (options.localPath ? "save" : "preview");
    const outputLimit = Math.min(
      options.maxOutputBytes ?? this.config.hermesDecoderOutputLimit,
      this.config.hermesDecoderOutputLimit
    );
    const client = await this.connectedClient();

    if (inspect.size > this.config.jsBundleMaxReadSize) {
      throw new Error(
        `Bundle is ${inspect.size} bytes, which exceeds jsBundleMaxReadSize=${this.config.jsBundleMaxReadSize}. Use ios_download_file first or raise the limit.`
      );
    }

    const buffer = await this.readRemoteBufferLimited(client, inspect.path, this.config.jsBundleMaxReadSize);

    if (inspect.format === "plain-js") {
      const rawText = buffer.toString("utf8");
      const content = options.beautify ?? true ? beautify.js(rawText, { indent_size: 2 }) : rawText;
      return this.bundleDecodeOutput({
        inspect,
        mode,
        decodedKind: options.beautify === false ? "raw-text" : "beautified-js",
        content,
        localPath: options.localPath,
        outputLimit
      });
    }

    if (inspect.format !== "hermes-bytecode") {
      throw new Error(
        "Bundle does not look like plain JavaScript or Hermes bytecode. Download it and inspect it with a local binary tool."
      );
    }

    const decoder = await this.resolveHermesDecoder();
    const decoded = await this.runHermesDecoder(buffer, decoder.commandTemplate, outputLimit);
    return this.bundleDecodeOutput({
      inspect,
      mode,
      decodedKind: "hermes-disassembly",
      decoder: decoder.preset,
      content: decoded.stdout,
      localPath: options.localPath,
      outputLimit,
      stderr: decoded.stderr
    });
  }

  async listHermesDecoders(): Promise<{
    configuredPreset: HermesDecoderPreset;
    configuredCommand?: string;
    selected?: HermesDecoderChoice;
    decoders: HermesDecoderInfo[];
    notes: string[];
  }> {
    const decoders = await this.hermesDecoderInfos();
    let selected: HermesDecoderChoice | undefined;
    const notes: string[] = [];

    try {
      selected = await this.resolveHermesDecoder();
    } catch (error) {
      notes.push(error instanceof Error ? error.message : String(error));
    }

    notes.push("Use hermesDecoderCommand for any decoder not covered by a built-in preset, including jsc2llvm if you have a working command template.");

    return {
      configuredPreset: this.config.hermesDecoderPreset,
      configuredCommand: this.config.hermesDecoderCommand,
      selected,
      decoders,
      notes
    };
  }

  async findApp(query: string): Promise<FindAppResult> {
    const normalizedQuery = query.trim();
    if (!normalizedQuery) {
      throw new Error("App query must be non-empty.");
    }

    const client = await this.connectedClient();
    const queryLower = normalizedQuery.toLowerCase();
    const bundleMatches: AppBundleMatch[] = [];
    const dataContainerMatches: AppContainerMatch[] = [];
    const appGroupMatches: AppContainerMatch[] = [];
    const searchedRoots: string[] = [];
    const notes: string[] = [];
    const seenPaths = new Set<string>();
    let truncated = false;

    for (const root of APP_BUNDLE_ROOTS) {
      const safeRoot = await this.safeAppRoot(client, root, notes);
      if (!safeRoot || seenPaths.has(safeRoot)) {
        continue;
      }

      seenPaths.add(safeRoot);
      searchedRoots.push(safeRoot);
      const scan = await this.scanBundleRoot(client, safeRoot, queryLower);
      bundleMatches.push(...scan.matches);
      truncated ||= scan.truncated;
    }

    const bundleIds = new Set(
      bundleMatches
        .map((match) => match.bundleId?.toLowerCase())
        .filter((value): value is string => Boolean(value))
    );

    for (const root of APP_DATA_ROOTS) {
      const safeRoot = await this.safeAppRoot(client, root, notes);
      if (!safeRoot || seenPaths.has(safeRoot)) {
        continue;
      }

      seenPaths.add(safeRoot);
      searchedRoots.push(safeRoot);
      const scan = await this.scanMetadataRoot(client, safeRoot, queryLower, bundleIds);
      dataContainerMatches.push(...scan.matches);
      truncated ||= scan.truncated;
    }

    for (const root of APP_GROUP_ROOTS) {
      const safeRoot = await this.safeAppRoot(client, root, notes);
      if (!safeRoot || seenPaths.has(safeRoot)) {
        continue;
      }

      seenPaths.add(safeRoot);
      searchedRoots.push(safeRoot);
      const scan = await this.scanMetadataRoot(client, safeRoot, queryLower, bundleIds);
      appGroupMatches.push(...scan.matches);
      truncated ||= scan.truncated;
    }

    if (bundleMatches.length === 0) {
      notes.push(
        "No app bundle matched by shallow app-directory scan. Try the visible app name, the .app name, or the bundle id."
      );
    }

    if (dataContainerMatches.length === 0 && bundleMatches.length > 0) {
      notes.push(
        "No data container metadata matched. This can happen if metadata plists are unreadable or use a different identifier."
      );
    }

    return {
      query: normalizedQuery,
      bundleMatches: this.uniqueByPath(bundleMatches),
      dataContainerMatches: this.uniqueByPath(dataContainerMatches),
      appGroupMatches: this.uniqueByPath(appGroupMatches),
      searchedRoots,
      truncated,
      notes
    };
  }

  async listApps(query?: string, limit = 200): Promise<ListAppsResult> {
    const client = await this.connectedClient();
    const queryLower = query?.trim().toLowerCase();
    const apps: AppBundleMatch[] = [];
    const searchedRoots: string[] = [];
    const notes: string[] = [];
    const seenPaths = new Set<string>();
    let truncated = false;

    for (const root of APP_BUNDLE_ROOTS) {
      const safeRoot = await this.safeAppRoot(client, root, notes);
      if (!safeRoot || seenPaths.has(safeRoot)) {
        continue;
      }

      seenPaths.add(safeRoot);
      searchedRoots.push(safeRoot);
      const scan = await this.scanBundleRoot(client, safeRoot, queryLower);
      apps.push(...scan.matches);
      truncated ||= scan.truncated;

      if (apps.length >= limit) {
        truncated = true;
        break;
      }
    }

    return {
      apps: this.uniqueByPath(apps).slice(0, limit),
      appCount: Math.min(this.uniqueByPath(apps).length, limit),
      searchedRoots,
      truncated,
      notes
    };
  }

  async resolveAppContainer(bundleId: string): Promise<ResolveAppContainerResult> {
    const normalizedBundleId = bundleId.trim();
    if (!normalizedBundleId) {
      throw new Error("bundleId must be non-empty.");
    }

    const result = await this.findApp(normalizedBundleId);
    const bundleIdLower = normalizedBundleId.toLowerCase();
    const primaryBundle =
      result.bundleMatches.find((match) => match.bundleId?.toLowerCase() === bundleIdLower) ??
      result.bundleMatches[0];
    const primaryDataContainer = result.dataContainerMatches[0];
    const primaryAppGroup = result.appGroupMatches[0];

    return {
      ...result,
      bundleId: normalizedBundleId,
      primaryBundle,
      primaryDataContainer,
      primaryAppGroup
    };
  }

  async existsPath(path: string): Promise<ExistsResult> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();

    try {
      const safePath = await this.resolveExistingSafePath(client, lexicalPath);
      const stat = await client.stat(safePath);
      return {
        path: safePath,
        exists: true,
        type: this.mapStatsType(stat),
        size: Number(stat.size ?? 0)
      };
    } catch {
      return {
        path: lexicalPath,
        exists: false
      };
    }
  }

  async readFileChunk(
    path: string,
    offset = 0,
    length = this.config.maxReadSize,
    encoding: "utf8" | "base64" = "utf8"
  ): Promise<FileChunkResult> {
    if (!Number.isInteger(offset) || offset < 0) {
      throw new Error("offset must be a non-negative integer.");
    }

    if (!Number.isInteger(length) || length <= 0) {
      throw new Error("length must be a positive integer.");
    }

    const cappedLength = Math.min(length, this.config.maxReadSize);
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);
    const fileSize = Number(stat.size ?? 0);

    if (this.mapStatsType(stat) !== "file") {
      throw new Error(`Path is not a regular file: ${safePath}`);
    }

    if (offset >= fileSize) {
      return { path: safePath, offset, length: cappedLength, bytesRead: 0, encoding, content: "", fileSize };
    }

    const end = Math.min(offset + cappedLength, fileSize) - 1;
    const buffer = await this.readRemoteRange(client, safePath, offset, end);

    return {
      path: safePath,
      offset,
      length: cappedLength,
      bytesRead: buffer.byteLength,
      encoding,
      content: encoding === "base64" ? buffer.toString("base64") : buffer.toString("utf8"),
      fileSize
    };
  }

  async tailFile(path: string, maxBytes = 64 * 1024): Promise<FileChunkResult> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);
    const fileSize = Number(stat.size ?? 0);
    const cappedMaxBytes = Math.min(Math.max(maxBytes, 1), this.config.maxReadSize);
    const offset = Math.max(0, fileSize - cappedMaxBytes);

    return this.readFileChunk(safePath, offset, cappedMaxBytes, "utf8");
  }

  async readLastLines(path: string, lines = 100, maxBytes = 256 * 1024): Promise<LastLinesResult> {
    if (!Number.isInteger(lines) || lines <= 0) {
      throw new Error("lines must be a positive integer.");
    }

    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);
    const fileSize = Number(stat.size ?? 0);
    const cappedMaxBytes = Math.min(Math.max(maxBytes, 1), this.config.maxReadSize);
    const offset = Math.max(0, fileSize - cappedMaxBytes);
    const buffer = fileSize === 0 ? Buffer.alloc(0) : await this.readRemoteRange(client, safePath, offset, fileSize - 1);
    const text = buffer.toString("utf8");
    const selectedLines = text.split(/\r?\n/).slice(-lines);

    return {
      path: safePath,
      lines,
      maxBytes: cappedMaxBytes,
      bytesRead: buffer.byteLength,
      content: selectedLines.join("\n"),
      truncated: offset > 0,
      fileSize
    };
  }

  async listPreferences(bundleId: string): Promise<ListPreferencesResult> {
    const resolved = await this.resolveAppContainer(bundleId);
    const client = await this.connectedClient();
    const preferenceDirectories: string[] = [];
    const preferenceFiles: PreferenceFile[] = [];
    const notes = [...resolved.notes];

    for (const container of resolved.dataContainerMatches) {
      const preferenceDirectory = this.assertCanonicalSafePath(joinRemote(container.path, "Library/Preferences"));
      if (!(await this.exists(client, preferenceDirectory))) {
        continue;
      }

      preferenceDirectories.push(preferenceDirectory);

      for (const entry of await client.list(preferenceDirectory)) {
        if (this.mapEntryType(entry.type) !== "file" || !entry.name.endsWith(".plist")) {
          continue;
        }

        preferenceFiles.push({
          path: this.assertCanonicalSafePath(joinRemote(preferenceDirectory, entry.name)),
          name: entry.name,
          size: Number(entry.size ?? 0),
          modifyTime: this.dateFromMillis(entry.modifyTime)
        });
      }
    }

    if (preferenceFiles.length === 0) {
      notes.push("No readable preference plist files were found in the matched data containers.");
    }

    return {
      bundleId,
      preferenceDirectories: this.uniqueStrings(preferenceDirectories),
      preferenceFiles: this.uniqueByPath(preferenceFiles),
      notes
    };
  }

  async readPreferences(
    bundleId: string,
    includeAll = false,
    maxFiles = 10
  ): Promise<ReadPreferencesResult> {
    const listed = await this.listPreferences(bundleId);
    const client = await this.connectedClient();
    const bundleIdLower = bundleId.toLowerCase();
    const selectedFiles = listed.preferenceFiles
      .filter((file) => includeAll || file.name.toLowerCase() === `${bundleIdLower}.plist`)
      .slice(0, maxFiles);
    const values: Array<PlistReadResult & { name: string }> = [];
    const notes = [...listed.notes];

    for (const file of selectedFiles) {
      const parsed = await this.readPlistAt(client, file.path, this.config.maxReadSize);
      values.push({
        path: file.path,
        name: file.name,
        format: parsed.format,
        value: this.toJsonSafe(parsed.value)
      });
    }

    if (!includeAll && values.length === 0 && listed.preferenceFiles.length > 0) {
      notes.push("No exact bundle-id preference plist was found. Retry with includeAll=true to read nearby preference files.");
    }

    return {
      ...listed,
      notes,
      values
    };
  }

  async readSqliteSchema(path: string): Promise<SqliteSchemaResult> {
    const { db, safePath, size } = await this.openRemoteSqlite(path);

    try {
      const schemaRows = this.execSqliteRows(
        db,
        "SELECT type, name, sql FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY type, name",
        500
      );
      const tables: SqliteSchemaResult["tables"] = [];

      for (const row of schemaRows.rows) {
        const name = String(row.name ?? "");
        const type = String(row.type ?? "");
        const columns =
          type === "table"
            ? this.execSqliteRows(db, `PRAGMA table_info(${this.sqliteIdentifier(name)})`, 500).rows.map((column) => ({
                cid: Number(column.cid ?? 0),
                name: String(column.name ?? ""),
                type: String(column.type ?? ""),
                notnull: Number(column.notnull ?? 0),
                defaultValue: column.dflt_value,
                pk: Number(column.pk ?? 0)
              }))
            : undefined;

        tables.push({
          name,
          type,
          sql: typeof row.sql === "string" ? row.sql : undefined,
          columns
        });
      }

      return { path: safePath, size, tables };
    } finally {
      db.close();
    }
  }

  async querySqlite(path: string, sql: string, limit = 50): Promise<SqliteQueryResult> {
    if (!Number.isInteger(limit) || limit <= 0 || limit > 500) {
      throw new Error("limit must be an integer between 1 and 500.");
    }

    this.assertReadOnlySql(sql);
    const { db, safePath } = await this.openRemoteSqlite(path);

    try {
      const result = this.execSqliteRows(db, sql, limit);
      return {
        path: safePath,
        columns: result.columns,
        rows: result.rows,
        rowCount: result.rowCount,
        returnedRows: result.rows.length,
        limit
      };
    } finally {
      db.close();
    }
  }

  async zipDownload(
    paths: string[],
    localPath: string,
    overwrite = false
  ): Promise<ZipDownloadResult> {
    if (!Array.isArray(paths) || paths.length === 0) {
      throw new Error("paths must contain at least one remote path.");
    }

    const safeLocalPath = this.assertSafeLocalPath(localPath);
    if (existsSync(safeLocalPath) && !overwrite) {
      throw new Error(`Local path already exists. Set overwrite=true to replace: ${safeLocalPath}`);
    }

    const client = await this.connectedClient();
    const safePaths: string[] = [];
    for (const path of paths) {
      safePaths.push(await this.resolveExistingSafePath(client, assertSafePath(path, this.config)));
    }

    await mkdir(localDirname(safeLocalPath), { recursive: true });
    const output = createWriteStream(safeLocalPath);
    const archive = archiver("zip", { zlib: { level: 6 } });
    let entriesAdded = 0;

    const archiveDone = new Promise<void>((resolve, reject) => {
      output.once("close", resolve);
      output.once("error", reject);
      archive.once("error", reject);
    });

    archive.pipe(output);

    for (const safePath of safePaths) {
      const rootName = this.safeZipEntryName(basename(safePath) || "root");
      entriesAdded += await this.addRemotePathToArchive(client, archive, safePath, rootName);
    }

    await archive.finalize();
    await archiveDone;

    return {
      paths: safePaths,
      localPath: safeLocalPath,
      entriesAdded,
      bytesWritten: archive.pointer()
    };
  }

  async diagnoseRoots(): Promise<DiagnoseRootsResult> {
    const client = await this.connectedClient();
    const roots: RootDiagnostic[] = [];

    for (const path of DIAGNOSTIC_ROOTS) {
      const diagnostic: RootDiagnostic = {
        path,
        allowed: true,
        exists: false
      };

      try {
        assertSafePath(path, this.config);
      } catch (error) {
        diagnostic.allowed = false;
        diagnostic.error = error instanceof Error ? error.message : String(error);
        roots.push(diagnostic);
        continue;
      }

      try {
        diagnostic.realPath = normalizeRemotePath(await client.realPath(path));
        this.assertCanonicalSafePath(diagnostic.realPath);
        diagnostic.exists = true;
      } catch (error) {
        diagnostic.error = error instanceof Error ? error.message : String(error);
        roots.push(diagnostic);
        continue;
      }

      try {
        const entries = await client.list(diagnostic.realPath);
        diagnostic.entryCount = entries.length;
        diagnostic.sampleEntries = entries.slice(0, 12).map((entry) => entry.name);
      } catch (error) {
        diagnostic.error = error instanceof Error ? error.message : String(error);
      }

      roots.push(diagnostic);
    }

    return {
      username: this.config.username,
      host: this.config.host,
      allowedRoots: this.config.allowedRoots,
      roots,
      notes: this.rootDiagnosticNotes(roots)
    };
  }

  async hashFile(path: string): Promise<{ path: string; algorithm: "sha256"; hash: string; size: number }> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);
    const size = Number(stat.size ?? 0);

    if (size > this.config.maxReadSize) {
      throw new Error(
        `File is ${size} bytes, which exceeds maxReadSize=${this.config.maxReadSize}.`
      );
    }

    const content = await client.get(safePath);
    const buffer = this.bufferFromGetResult(content);
    const { createHash } = await import("node:crypto");
    const hash = createHash("sha256").update(buffer).digest("hex");

    return {
      path: safePath,
      algorithm: "sha256",
      hash,
      size
    };
  }

  private async connectedClient(): Promise<Client> {
    if (this.client) {
      return this.client;
    }

    if (this.connecting) {
      return this.connecting;
    }

    this.connecting = this.connect();

    try {
      this.client = await this.connecting;
      this.canonicalAllowedRoots = await this.resolveAllowedRoots(this.client);
      return this.client;
    } catch (error) {
      this.client = undefined;
      throw new SftpNotConnectedError(
        `SFTP is not connected: ${error instanceof Error ? error.message : String(error)}`
      );
    } finally {
      this.connecting = undefined;
    }
  }

  private async connect(): Promise<Client> {
    const client = new Client("ios-files-mcp");
    const privateKey = this.config.privateKeyPath
      ? await readFile(this.config.privateKeyPath, "utf8")
      : undefined;

    await client.connect({
      host: this.config.host,
      port: this.config.port,
      username: this.config.username,
      password: this.config.password,
      privateKey,
      passphrase: this.config.passphrase,
      timeout: this.config.connectTimeoutMs,
      readyTimeout: this.config.readyTimeoutMs,
      keepaliveInterval: 10_000
    });

    return client;
  }

  private async resolveAllowedRoots(client: Client): Promise<string[]> {
    const roots = new Set(this.config.allowedRoots);

    for (const root of this.config.allowedRoots) {
      try {
        roots.add(normalizeRemotePath(await client.realPath(root)));
      } catch {
        roots.add(root);
      }
    }

    return [...roots];
  }

  private async resolveExistingSafePath(client: Client, input: string): Promise<string> {
    const lexicalPath = assertSafePath(input, this.config);

    let realPath: string;
    try {
      realPath = normalizeRemotePath(await client.realPath(lexicalPath));
    } catch (error) {
      throw new Error(
        `Path does not exist or permission was denied: ${lexicalPath}. ${error instanceof Error ? error.message : String(error)}`
      );
    }

    return this.assertCanonicalSafePath(realPath);
  }

  private async resolveWritableTarget(client: Client, input: string): Promise<string> {
    const lexicalPath = assertSafePath(input, this.config);
    const exists = await this.exists(client, lexicalPath);

    if (exists) {
      return this.resolveExistingSafePath(client, lexicalPath);
    }

    const parent = dirname(lexicalPath);
    const safeParent = await this.resolveExistingSafePath(client, parent);
    return this.assertCanonicalSafePath(joinRemote(safeParent, basename(lexicalPath)));
  }

  private async resolveCreatableDirectory(client: Client, input: string): Promise<string> {
    const lexicalPath = assertSafePath(input, this.config);
    const exists = await this.exists(client, lexicalPath);

    if (exists) {
      return this.resolveExistingSafePath(client, lexicalPath);
    }

    const ancestor = await this.resolveNearestExistingAncestor(client, lexicalPath);
    const suffix = lexicalPath.slice(ancestor.lexicalPath.length).replace(/^\/+/, "");
    return this.assertCanonicalSafePath(joinRemote(ancestor.realPath, suffix));
  }

  private async resolveNearestExistingAncestor(
    client: Client,
    lexicalPath: string
  ): Promise<{ lexicalPath: string; realPath: string }> {
    let current = dirname(lexicalPath);

    while (current !== "/") {
      if (await this.exists(client, current)) {
        return {
          lexicalPath: current,
          realPath: await this.resolveExistingSafePath(client, current)
        };
      }

      current = dirname(current);
    }

    throw new Error(`No existing safe parent directory found for: ${lexicalPath}`);
  }

  private assertCanonicalSafePath(path: string): string {
    const normalized = normalizeRemotePath(path);
    const canonicalConfig = {
      allowedRoots: this.canonicalAllowedRoots.length
        ? this.canonicalAllowedRoots
        : this.config.allowedRoots
    };

    return assertSafePath(normalized, canonicalConfig);
  }

  private async backupIfExisting(client: Client, path: string): Promise<string | undefined> {
    if (!(await this.exists(client, path))) {
      return undefined;
    }

    const backupPath = this.assertCanonicalSafePath(backupPathFor(path));
    const stat = await client.stat(path);
    if (this.mapStatsType(stat) === "directory") {
      throw new Error(`Destination exists and is a directory; refusing to overwrite: ${path}`);
    }

    if (!this.config.backupBeforeWrite) {
      throw new Error(
        `Destination exists and backupBeforeWrite=false; refusing to overwrite: ${path}`
      );
    }

    await client.rcopy(path, backupPath);
    return backupPath;
  }

  private async deleteExistingFileTarget(client: Client, path: string): Promise<void> {
    const stat = await client.stat(path);
    if (this.mapStatsType(stat) === "directory") {
      throw new Error(`Destination exists and is a directory; refusing to overwrite: ${path}`);
    }

    await client.delete(path);
  }

  private async exists(client: Client, path: string): Promise<boolean> {
    try {
      return await client.exists(path) !== false;
    } catch {
      return false;
    }
  }

  private detectJsBundleFormat(header: Buffer): JsBundleFormat {
    const asText = header.toString("utf8");

    if (asText.startsWith("c61 c03 bc")) {
      return "hermes-bytecode";
    }

    if (header.length >= 4 && header[0] === 0xc6 && header[1] === 0x1f && header[2] === 0xbc && header[3] === 0x03) {
      return "hermes-bytecode";
    }

    const firstNonWhitespace = asText.trimStart()[0];
    if (firstNonWhitespace && ["!", "(", "/", "{", "[", "\"", "'", "v", "c", "f", "i"].includes(firstNonWhitespace)) {
      return "plain-js";
    }

    return "unknown-binary";
  }

  private jsBundleNotes(format: JsBundleFormat): string[] {
    if (format === "plain-js") {
      return ["Plain JavaScript bundle detected. ios_decode_js_bundle can beautify it or save it locally."];
    }

    if (format === "hermes-bytecode") {
      return [
        "Hermes bytecode detected. This is compiled React Native JavaScript, not source text.",
        "ios_decode_js_bundle can run a configured local decoder/disassembler command such as hermesc -dump-bytecode {input}."
      ];
    }

    return ["Unknown binary format. Use ios_download_file to inspect it with a local tool."];
  }

  private async hermesDecoderInfos(): Promise<HermesDecoderInfo[]> {
    const infos: HermesDecoderInfo[] = [];

    for (const preset of HERMES_DECODER_PRESETS) {
      infos.push({
        preset: preset.preset,
        commandName: preset.commandName,
        commandTemplate: preset.commandTemplate,
        available: await this.commandExists(preset.commandName),
        notes: preset.notes
      });
    }

    infos.push({
      preset: "jsc2llvm",
      commandName: "jsc2llvm",
      commandTemplate: this.config.hermesDecoderCommand,
      available: await this.commandExists("jsc2llvm"),
      notes: [
        "jsc2llvm does not have a verified built-in command template in this project.",
        "Set hermesDecoderCommand to the exact jsc2llvm command you use, with {input} and optional {output}."
      ]
    });

    if (this.config.hermesDecoderCommand) {
      infos.push({
        preset: "custom",
        commandTemplate: this.config.hermesDecoderCommand,
        available: true,
        notes: ["Custom hermesDecoderCommand is configured."]
      });
    }

    return infos;
  }

  private async resolveHermesDecoder(): Promise<HermesDecoderChoice> {
    if (this.config.hermesDecoderCommand) {
      return {
        preset: this.config.hermesDecoderPreset === "auto" ? "custom" : this.config.hermesDecoderPreset,
        commandTemplate: this.config.hermesDecoderCommand
      };
    }

    if (this.config.hermesDecoderPreset === "custom") {
      throw new Error(
        "Hermes decoder preset is custom, but hermesDecoderCommand is empty. Set hermesDecoderCommand or IOS_FILES_MCP_HERMES_DECODER_COMMAND."
      );
    }

    if (this.config.hermesDecoderPreset === "jsc2llvm") {
      throw new Error(
        "jsc2llvm preset needs an explicit hermesDecoderCommand because this project does not know your jsc2llvm command syntax. Example shape: jsc2llvm ... {input} ... {output}"
      );
    }

    if (this.config.hermesDecoderPreset !== "auto") {
      const preset = HERMES_DECODER_PRESETS.find((candidate) => candidate.preset === this.config.hermesDecoderPreset);
      if (!preset) {
        throw new Error(`Unsupported Hermes decoder preset: ${this.config.hermesDecoderPreset}`);
      }

      if (!(await this.commandExists(preset.commandName))) {
        throw new Error(
          `Hermes decoder preset '${preset.preset}' requires '${preset.commandName}' on PATH. Install it, use preset auto, or set hermesDecoderCommand.`
        );
      }

      return {
        preset: preset.preset,
        commandTemplate: preset.commandTemplate
      };
    }

    for (const preset of HERMES_DECODER_PRESETS) {
      if (await this.commandExists(preset.commandName)) {
        return {
          preset: preset.preset,
          commandTemplate: preset.commandTemplate
        };
      }
    }

    throw new Error(
      "Hermes bytecode detected, but no supported decoder was found on PATH. Install hermes-dec (hbc-decompiler/hbc-disassembler), hermesc, or hbctool; or set hermesDecoderCommand / IOS_FILES_MCP_HERMES_DECODER_COMMAND for a custom decoder such as jsc2llvm."
    );
  }

  private async bundleDecodeOutput(options: {
    inspect: JsBundleInspectResult;
    mode: "preview" | "save";
    decodedKind: JsBundleDecodeResult["decodedKind"];
    decoder?: string;
    content: string;
    localPath?: string;
    outputLimit: number;
    stderr?: string;
  }): Promise<JsBundleDecodeResult> {
    if (options.mode === "save" || options.localPath) {
      if (!options.localPath) {
        throw new Error("localPath is required when mode=save.");
      }

      const safeLocalPath = this.assertSafeLocalPath(options.localPath);
      await mkdir(localDirname(safeLocalPath), { recursive: true });
      await writeLocalFile(safeLocalPath, options.content, "utf8");

      return {
        ...options.inspect,
        mode: "save",
        decodedKind: options.decodedKind,
        decoder: options.decoder,
        localPath: safeLocalPath,
        bytesWritten: Buffer.byteLength(options.content, "utf8"),
        stderr: options.stderr
      };
    }

    const contentBuffer = Buffer.from(options.content, "utf8");
    const clipped =
      contentBuffer.byteLength > options.outputLimit
        ? contentBuffer.subarray(0, options.outputLimit).toString("utf8")
        : options.content;

    return {
      ...options.inspect,
      mode: "preview",
      decodedKind: options.decodedKind,
      decoder: options.decoder,
      content: clipped,
      stderr: options.stderr,
      notes:
        contentBuffer.byteLength > options.outputLimit
          ? [...options.inspect.notes, `Output was clipped to ${options.outputLimit} bytes. Use mode=save with localPath for the full decoded output.`]
          : options.inspect.notes
    };
  }

  private async runHermesDecoder(
    input: Buffer,
    commandTemplate: string,
    outputLimit: number
  ): Promise<{ stdout: string; stderr: string }> {
    const tempDir = await mkdtemp(joinLocal(tmpdir(), "ios-files-mcp-hermes-"));
    const inputPath = joinLocal(tempDir, "bundle.hbc");
    const outputPath = joinLocal(tempDir, "decoder-output");

    try {
      await writeLocalFile(inputPath, input);
      const command = commandTemplate
        .replaceAll("{input}", this.shellQuote(inputPath))
        .replaceAll("{output}", this.shellQuote(outputPath));
      const result = await this.runCommand(command, outputLimit);

      if (commandTemplate.includes("{output}") && existsSync(outputPath)) {
        return {
          stdout: await this.readDecoderOutputPath(outputPath, outputLimit),
          stderr: result.stderr
        };
      }

      return result;
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  }

  private async readDecoderOutputPath(path: string, outputLimit: number): Promise<string> {
    const info = await localStat(path);

    if (info.isFile()) {
      const output = await readFile(path);
      return output.subarray(0, outputLimit).toString("utf8");
    }

    if (!info.isDirectory()) {
      return "";
    }

    const parts: string[] = [];
    let remaining = outputLimit;
    const pending = [path];

    while (pending.length > 0 && remaining > 0) {
      const current = pending.shift()!;
      const entries = await readdir(current, { withFileTypes: true });

      for (const entry of entries) {
        const entryPath = joinLocal(current, entry.name);
        if (entry.isDirectory()) {
          pending.push(entryPath);
          continue;
        }

        if (!entry.isFile()) {
          continue;
        }

        const relativePath = relative(path, entryPath);
        const header = `\n\n# ${relativePath}\n`;
        parts.push(header);
        remaining -= Buffer.byteLength(header, "utf8");

        if (remaining <= 0) {
          break;
        }

        const output = await readFile(entryPath);
        const clipped = output.subarray(0, Math.max(0, remaining)).toString("utf8");
        parts.push(clipped);
        remaining -= Buffer.byteLength(clipped, "utf8");
      }
    }

    return parts.join("").trimStart();
  }

  private async commandExists(commandName: string): Promise<boolean> {
    const checkCommand =
      process.platform === "win32"
        ? `where ${this.shellQuote(commandName)}`
        : `command -v ${this.shellQuote(commandName)}`;

    try {
      await this.runCommand(checkCommand, 1024);
      return true;
    } catch {
      return false;
    }
  }

  private runCommand(command: string, outputLimit: number): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn(command, {
        shell: true,
        windowsHide: true
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;

      child.stdout.on("data", (chunk: Buffer) => {
        if (stdoutBytes < outputLimit) {
          stdout.push(chunk.subarray(0, Math.max(0, outputLimit - stdoutBytes)));
        }
        stdoutBytes += chunk.byteLength;
      });

      child.stderr.on("data", (chunk: Buffer) => {
        if (stderrBytes < outputLimit) {
          stderr.push(chunk.subarray(0, Math.max(0, outputLimit - stderrBytes)));
        }
        stderrBytes += chunk.byteLength;
      });

      child.once("error", reject);
      child.once("close", (code) => {
        const stdoutText = Buffer.concat(stdout).toString("utf8");
        const stderrText = Buffer.concat(stderr).toString("utf8");
        if (code !== 0) {
          reject(new Error(`Hermes decoder command failed with exit code ${code}: ${stderrText || stdoutText}`));
          return;
        }

        resolve({ stdout: stdoutText, stderr: stderrText });
      });
    });
  }

  private shellQuote(value: string): string {
    return `"${value.replace(/"/g, "\\\"")}"`;
  }

  private async readRemoteRange(
    client: Client,
    path: string,
    start: number,
    end: number
  ): Promise<Buffer> {
    if (end < start) {
      return Buffer.alloc(0);
    }

    const stream = client.createReadStream(path, { start, end });
    const chunks: Buffer[] = [];

    await new Promise<void>((resolve, reject) => {
      stream.on("data", (chunk: Buffer | string) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      stream.once("error", reject);
      stream.once("end", resolve);
    });

    return Buffer.concat(chunks);
  }

  private async openRemoteSqlite(path: string): Promise<{
    db: {
      exec(sql: string): Array<{ columns: string[]; values: unknown[][] }>;
      close(): void;
    };
    safePath: string;
    size: number;
  }> {
    const lexicalPath = assertSafePath(path, this.config);
    const client = await this.connectedClient();
    const safePath = await this.resolveExistingSafePath(client, lexicalPath);
    const stat = await client.stat(safePath);
    const size = Number(stat.size ?? 0);

    if (this.mapStatsType(stat) !== "file") {
      throw new Error(`Path is not a regular file: ${safePath}`);
    }

    if (size > this.config.sqliteMaxReadSize) {
      throw new Error(
        `SQLite file is ${size} bytes, which exceeds sqliteMaxReadSize=${this.config.sqliteMaxReadSize}. Download it first if you need offline analysis.`
      );
    }

    const buffer = await this.readRemoteBufferLimited(client, safePath, this.config.sqliteMaxReadSize);
    const initSqlJs = (await import("sql.js")).default;
    const SQL = await initSqlJs();
    return {
      db: new SQL.Database(buffer),
      safePath,
      size
    };
  }

  private execSqliteRows(
    db: { exec(sql: string): Array<{ columns: string[]; values: unknown[][] }> },
    sql: string,
    limit: number
  ): { columns: string[]; rows: Array<Record<string, unknown>>; rowCount: number } {
    const results = db.exec(sql);
    const first = results[0];

    if (!first) {
      return { columns: [], rows: [], rowCount: 0 };
    }

    const rows = first.values.map((row) =>
      Object.fromEntries(first.columns.map((column, index) => [column, this.toJsonSafe(row[index])]))
    );

    return {
      columns: first.columns,
      rows: rows.slice(0, limit),
      rowCount: rows.length
    };
  }

  private assertReadOnlySql(sql: string): void {
    const trimmed = sql.trim();
    if (!trimmed) {
      throw new Error("sql must be non-empty.");
    }

    const withoutTrailingSemicolon = trimmed.replace(/;\s*$/, "");
    if (withoutTrailingSemicolon.includes(";")) {
      throw new Error("Only one read-only SQL statement is allowed.");
    }

    if (!/^(select|pragma|with|explain)\b/i.test(withoutTrailingSemicolon)) {
      throw new Error("Only read-only SQL is allowed. Use SELECT, PRAGMA, WITH, or EXPLAIN.");
    }

    if (/\b(insert|update|delete|replace|drop|alter|create|attach|detach|vacuum|reindex)\b/i.test(withoutTrailingSemicolon)) {
      throw new Error("SQL contains a blocked write or schema-changing keyword.");
    }
  }

  private sqliteIdentifier(name: string): string {
    return `"${name.replace(/"/g, "\"\"")}"`;
  }

  private async addRemotePathToArchive(
    client: Client,
    archive: archiver.Archiver,
    path: string,
    zipName: string
  ): Promise<number> {
    const stat = await client.stat(path);
    const type = this.mapStatsType(stat);

    if (type === "file") {
      archive.append(client.createReadStream(path), { name: zipName });
      return 1;
    }

    if (type !== "directory") {
      return 0;
    }

    archive.append("", { name: `${zipName.replace(/\/+$/, "")}/` });
    let entriesAdded = 1;
    const pending: Array<{ remotePath: string; zipPrefix: string }> = [{ remotePath: path, zipPrefix: zipName }];

    while (pending.length > 0) {
      const current = pending.shift()!;
      const entries = await client.list(current.remotePath);

      for (const entry of entries) {
        if (entriesAdded >= ZIP_ENTRY_LIMIT) {
          throw new Error(`ZIP export exceeded entry limit ${ZIP_ENTRY_LIMIT}. Export a smaller path set.`);
        }

        const childPath = this.assertCanonicalSafePath(joinRemote(current.remotePath, entry.name));
        const childZipName = `${current.zipPrefix.replace(/\/+$/, "")}/${this.safeZipEntryName(entry.name)}`;
        const entryType = this.mapEntryType(entry.type);

        if (entryType === "file") {
          archive.append(client.createReadStream(childPath), { name: childZipName });
          entriesAdded += 1;
        } else if (entryType === "directory") {
          archive.append("", { name: `${childZipName}/` });
          entriesAdded += 1;
          pending.push({ remotePath: childPath, zipPrefix: childZipName });
        }
      }
    }

    return entriesAdded;
  }

  private safeZipEntryName(name: string): string {
    return name.replace(/\\/g, "/").split("/").filter(Boolean).join("_") || "entry";
  }

  private uniqueStrings(values: string[]): string[] {
    return [...new Set(values)];
  }

  private assertSafeLocalPath(input: string): string {
    if (typeof input !== "string" || input.trim() === "") {
      throw new Error("Local path must be a non-empty string.");
    }

    const resolved = resolveLocal(input);
    const allowed = this.config.localArtifactRoots.some((root) => {
      const resolvedRoot = resolveLocal(root);
      const rel = relative(resolvedRoot, resolved);
      return rel === "" || (!rel.startsWith("..") && !rel.includes(":"));
    });

    if (!allowed) {
      throw new Error(
        `Local path is outside allowed local artifact roots: ${resolved}. Allowed roots: ${this.config.localArtifactRoots.join(", ")}`
      );
    }

    return resolved;
  }

  private async safeAppRoot(
    client: Client,
    root: string,
    notes: string[]
  ): Promise<string | undefined> {
    try {
      assertSafePath(root, this.config);
      return await this.resolveExistingSafePath(client, root);
    } catch (error) {
      notes.push(
        `Skipped ${root}: ${error instanceof Error ? error.message : String(error)}`
      );
      return undefined;
    }
  }

  private async scanBundleRoot(
    client: Client,
    root: string,
    queryLower?: string
  ): Promise<{ matches: AppBundleMatch[]; truncated: boolean }> {
    const matches: AppBundleMatch[] = [];
    const uuidEntries = await client.list(root);
    let scanned = 0;
    let truncated = false;

    for (const uuidEntry of uuidEntries) {
      if (this.mapEntryType(uuidEntry.type) !== "directory") {
        continue;
      }

      scanned += 1;
      if (scanned > APP_CONTAINER_SCAN_LIMIT) {
        truncated = true;
        break;
      }

      const uuidPath = this.assertCanonicalSafePath(joinRemote(root, uuidEntry.name));
      let appEntries: Client.FileInfo[];
      try {
        appEntries = await client.list(uuidPath);
      } catch {
        continue;
      }

      for (const appEntry of appEntries) {
        const entryType = this.mapEntryType(appEntry.type);
        if (entryType !== "directory" || !appEntry.name.endsWith(".app")) {
          continue;
        }

        const appPath = this.assertCanonicalSafePath(joinRemote(uuidPath, appEntry.name));
        const infoPlistPath = this.assertCanonicalSafePath(joinRemote(appPath, "Info.plist"));
        const parsed = await this.tryReadPlistAt(client, infoPlistPath, APP_METADATA_READ_LIMIT);
        const plistObject = this.asRecord(parsed?.value);
        const appName = appEntry.name.replace(/\.app$/i, "");
        const bundleId = this.stringValue(plistObject?.CFBundleIdentifier);
        const displayName = this.stringValue(plistObject?.CFBundleDisplayName);
        const bundleName = this.stringValue(plistObject?.CFBundleName);
        const version = this.stringValue(plistObject?.CFBundleShortVersionString);
        const build = this.stringValue(plistObject?.CFBundleVersion);

        if (
          !queryLower ||
          this.valuesMatchQuery(queryLower, [
            appEntry.name,
            appName,
            bundleId,
            displayName,
            bundleName
          ])
        ) {
          matches.push({
            appName,
            path: appPath,
            infoPlistPath,
            containerUuid: uuidEntry.name,
            bundleId,
            displayName,
            bundleName,
            version,
            build
          });
        }
      }
    }

    return { matches, truncated };
  }

  private async scanMetadataRoot(
    client: Client,
    root: string,
    queryLower: string,
    bundleIds: Set<string>
  ): Promise<{ matches: AppContainerMatch[]; truncated: boolean }> {
    const matches: AppContainerMatch[] = [];
    const entries = await client.list(root);
    let scanned = 0;
    let truncated = false;

    for (const entry of entries) {
      if (this.mapEntryType(entry.type) !== "directory") {
        continue;
      }

      scanned += 1;
      if (scanned > APP_CONTAINER_SCAN_LIMIT) {
        truncated = true;
        break;
      }

      const containerPath = this.assertCanonicalSafePath(joinRemote(root, entry.name));
      const metadataPlistPath = this.assertCanonicalSafePath(
        joinRemote(containerPath, CONTAINER_METADATA_PLIST)
      );
      const parsed = await this.tryReadPlistAt(client, metadataPlistPath, APP_METADATA_READ_LIMIT);
      if (!parsed) {
        continue;
      }

      const strings = this.collectStrings(parsed.value);
      const lowerStrings = strings.map((value) => value.toLowerCase());
      const matchedBy: string[] = [];

      if (lowerStrings.some((value) => value.includes(queryLower))) {
        matchedBy.push("query");
      }

      for (const bundleId of bundleIds) {
        if (lowerStrings.some((value) => value.includes(bundleId))) {
          matchedBy.push(`bundleId:${bundleId}`);
        }
      }

      if (matchedBy.length === 0) {
        continue;
      }

      matches.push({
        path: containerPath,
        metadataPlistPath,
        containerUuid: entry.name,
        identifiers: this.interestingIdentifiers(strings, queryLower, bundleIds),
        matchedBy
      });
    }

    return { matches, truncated };
  }

  private async readPlistAt(
    client: Client,
    path: string,
    maxBytes: number
  ): Promise<{ format: "binary" | "xml"; value: PlistValue }> {
    const buffer = await this.readRemoteBufferLimited(client, path, maxBytes);
    const header = buffer.subarray(0, 8).toString("utf8");

    if (header === "bplist00") {
      return {
        format: "binary",
        value: parseBinaryPlist(buffer)
      };
    }

    return {
      format: "xml",
      value: parseXmlPlist(buffer)
    };
  }

  private async tryReadPlistAt(
    client: Client,
    path: string,
    maxBytes: number
  ): Promise<{ format: "binary" | "xml"; value: PlistValue } | undefined> {
    try {
      return await this.readPlistAt(client, path, maxBytes);
    } catch {
      return undefined;
    }
  }

  private async readRemoteBufferLimited(
    client: Client,
    path: string,
    maxBytes: number
  ): Promise<Buffer> {
    const stat = await client.stat(path);
    const size = Number(stat.size ?? 0);

    if (size > maxBytes) {
      throw new Error(`File is ${size} bytes, which exceeds max read limit ${maxBytes}.`);
    }

    const content = await client.get(path);
    return this.bufferFromGetResult(content);
  }

  private valuesMatchQuery(queryLower: string, values: Array<string | undefined>): boolean {
    return values.some((value) => value?.toLowerCase().includes(queryLower));
  }

  private rootDiagnosticNotes(roots: RootDiagnostic[]): string[] {
    const notes: string[] = [];
    const dataRoots = roots.filter((root) =>
      root.path.endsWith("/Containers/Data/Application")
    );
    const bundleRoots = roots.filter((root) =>
      root.path.endsWith("/containers/Bundle/Application")
    );
    const anyDataEntries = dataRoots.some((root) => (root.entryCount ?? 0) > 0);
    const anyBundleEntries = bundleRoots.some((root) => (root.entryCount ?? 0) > 0);

    if (!anyBundleEntries) {
      notes.push(
        "No app bundle entries were visible. If the directories exist but are empty, try SSH/SFTP as root or check that OpenSSH on the jailbreak is exposing the full filesystem."
      );
    }

    if (!anyDataEntries) {
      notes.push(
        "No app data container entries were visible. App data should normally appear under /var/mobile/Containers/Data/Application or /private/var/mobile/Containers/Data/Application."
      );
    }

    if (this.config.username === "mobile" && (!anyBundleEntries || !anyDataEntries)) {
      notes.push(
        "The current SSH username is mobile. Some jailbreak setups require username root to browse all app bundle/container directories."
      );
    }

    return notes;
  }

  private collectStrings(value: unknown): string[] {
    const strings = new Set<string>();
    const visit = (current: unknown): void => {
      if (typeof current === "string") {
        strings.add(current);
        return;
      }

      if (Array.isArray(current)) {
        for (const item of current) {
          visit(item);
        }
        return;
      }

      if (current && typeof current === "object") {
        for (const [key, nestedValue] of Object.entries(current)) {
          strings.add(key);
          visit(nestedValue);
        }
      }
    };

    visit(value);
    return [...strings];
  }

  private interestingIdentifiers(
    strings: string[],
    queryLower: string,
    bundleIds: Set<string>
  ): string[] {
    const result = strings.filter((value) => {
      const lower = value.toLowerCase();
      return (
        lower.includes(queryLower) ||
        [...bundleIds].some((bundleId) => lower.includes(bundleId)) ||
        /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(value)
      );
    });

    return [...new Set(result)].slice(0, 20);
  }

  private asRecord(value: unknown): Record<string, unknown> | undefined {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return undefined;
    }

    return value as Record<string, unknown>;
  }

  private stringValue(value: unknown): string | undefined {
    return typeof value === "string" ? value : undefined;
  }

  private toJsonSafe(value: unknown): unknown {
    if (value instanceof Date) {
      return value.toISOString();
    }

    if (value instanceof Uint8Array) {
      return {
        type: "bytes",
        length: value.byteLength,
        base64: Buffer.from(value).toString("base64")
      };
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.toJsonSafe(item));
    }

    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value).map(([key, nestedValue]) => [key, this.toJsonSafe(nestedValue)])
      );
    }

    return value;
  }

  private uniqueByPath<T extends { path: string }>(items: T[]): T[] {
    const seen = new Set<string>();
    const unique: T[] = [];

    for (const item of items) {
      if (seen.has(item.path)) {
        continue;
      }

      seen.add(item.path);
      unique.push(item);
    }

    return unique;
  }

  private searchCacheKey(
    root: string,
    pattern: string,
    options: Pick<SearchFilesOptions, "maxResults" | "maxDepth" | "includeMetadata">
  ): string {
    return JSON.stringify({
      root,
      pattern,
      maxResults: options.maxResults,
      maxDepth: options.maxDepth,
      includeMetadata: options.includeMetadata
    });
  }

  private getSearchCache(key: string): Omit<SearchFilesResult, "cached"> | undefined {
    const cached = this.searchCache.get(key);
    if (!cached) {
      return undefined;
    }

    if (cached.expiresAt <= Date.now()) {
      this.searchCache.delete(key);
      return undefined;
    }

    return cached.value;
  }

  private setSearchCache(key: string, value: Omit<SearchFilesResult, "cached">): void {
    if (this.config.searchCacheTtlMs <= 0) {
      return;
    }

    this.searchCache.set(key, {
      expiresAt: Date.now() + this.config.searchCacheTtlMs,
      value
    });

    if (this.searchCache.size > 100) {
      const oldestKey = this.searchCache.keys().next().value as string | undefined;
      if (oldestKey) {
        this.searchCache.delete(oldestKey);
      }
    }
  }

  private searchNotes(
    root: string,
    pattern: string,
    maxDepth: number,
    maxResults: number
  ): string[] {
    const notes: string[] = [];
    const loweredRoot = root.toLowerCase();
    const loweredPattern = pattern.toLowerCase();

    if (
      loweredRoot.includes("/containers/bundle/application") ||
      loweredRoot.includes("/containers/data/application")
    ) {
      notes.push("For installed apps, prefer ios_find_app(query) before recursive search.");
    }

    if (["youtube", "tiktok", "instagram", "snapchat", "google", "com."].some((hint) =>
      loweredPattern.includes(hint)
    )) {
      notes.push("This looks like an app lookup. ios_find_app(query) is faster and uses fewer tokens.");
    }

    notes.push(
      `Recursive search is capped at maxDepth=${maxDepth}, maxResults=${maxResults}, and searchMaxEntries=${this.config.searchMaxEntries}.`
    );

    return notes;
  }

  private matcherFromPattern(pattern: string): (value: string) => boolean {
    if (pattern.trim() === "") {
      throw new Error("Search pattern must be non-empty.");
    }

    if (pattern.startsWith("/") && pattern.endsWith("/") && pattern.length > 2) {
      const regex = new RegExp(pattern.slice(1, -1), "i");
      return (value) => regex.test(value);
    }

    const lowered = pattern.toLowerCase();
    return (value) => value.toLowerCase().includes(lowered);
  }

  private mapEntryType(type: unknown): FileEntry["type"] {
    if (type === "d" || type === 2 || type === "directory") {
      return "directory";
    }

    if (type === "-" || type === 1 || type === "file") {
      return "file";
    }

    if (type === "l" || type === "symlink") {
      return "symlink";
    }

    return "other";
  }

  private mapStatsType(stat: Client.FileStats): FileEntry["type"] {
    if (stat.isDirectory) {
      return "directory";
    }

    if (stat.isFile) {
      return "file";
    }

    if (stat.isSymbolicLink) {
      return "symlink";
    }

    return "other";
  }

  private bufferFromGetResult(value: string | NodeJS.WritableStream | Buffer): Buffer {
    if (Buffer.isBuffer(value)) {
      return value;
    }

    if (typeof value === "string") {
      return Buffer.from(value, "utf8");
    }

    throw new Error("Unexpected stream result while reading remote file.");
  }

  private dateFromMillis(value: unknown): string | null {
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      return null;
    }

    return new Date(value).toISOString();
  }

  private writeBufferToStream(stream: NodeJS.WritableStream, buffer: Buffer): Promise<void> {
    return new Promise((resolve, reject) => {
      stream.once("error", reject);
      stream.once("finish", resolve);
      stream.end(buffer);
    });
  }
}
