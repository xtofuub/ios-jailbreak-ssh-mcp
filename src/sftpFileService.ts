import { readFile } from "node:fs/promises";
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
    queryLower: string
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
