import { RadareService, type R2CheckResult } from "./radareService.js";
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
    values: Array<PlistReadResult & {
        name: string;
    }>;
};
type SqliteSchemaResult = {
    path: string;
    size: number;
    tables: Array<{
        name: string;
        type: string;
        sql?: string;
        columns?: Array<{
            cid: number;
            name: string;
            type: string;
            notnull: number;
            defaultValue: unknown;
            pk: number;
        }>;
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
type LocalPathStatus = {
    path: string;
    exists: boolean;
    type?: "file" | "directory" | "other";
    error?: string;
};
type McpConfigFileStatus = {
    client: "codex" | "claude" | "opencode" | "vscode";
    path: string;
    exists: boolean;
    configured: boolean;
    expectedShape: string;
    notes: string[];
    error?: string;
};
type McpConfigStatusResult = {
    packageSpec: string;
    serverName: string;
    serverCommand: string;
    process: {
        cwd: string;
        argv: string[];
        node: string;
        platform: NodeJS.Platform;
    };
    runtimeConfig: {
        host: string;
        port: number;
        username: string;
        authMethod: "password" | "privateKey" | "none";
        readOnly: boolean;
        allowWrites: boolean;
        requireWriteApproval: boolean;
        allowedRoots: string[];
        localArtifactRoots: string[];
        logPath: string;
        r2: {
            enabled: boolean;
            r2Path: string;
            rabin2Path: string;
            timeoutMs: number;
            maxOutputBytes: number;
            maxBinarySize: number;
        };
    };
    env: Record<string, {
        present: boolean;
        value?: string;
    }>;
    commandAvailability: {
        npx: boolean;
    };
    configFiles: McpConfigFileStatus[];
    notes: string[];
};
type ConnectionDoctorResult = {
    ok: boolean;
    connection: {
        ok: boolean;
        host: string;
        port: number;
        username: string;
        authMethod: "password" | "privateKey" | "none";
        error?: string;
    };
    runtimeConfig: McpConfigStatusResult["runtimeConfig"];
    localArtifactRoots: LocalPathStatus[];
    roots?: DiagnoseRootsResult;
    hermesDecoders?: Awaited<ReturnType<SftpFileService["listHermesDecoders"]>>;
    radare2?: R2CheckResult;
    mcpConfig: McpConfigStatusResult;
    nextSteps: string[];
};
type AppSnapshotResult = {
    bundleId: string;
    resolved: ResolveAppContainerResult;
    infoPlist?: {
        path: string;
        format: "binary" | "xml";
        summary: Record<string, unknown>;
    };
    directories: {
        bundleTopLevel: FileEntry[];
        dataTopLevel: FileEntry[];
        appGroupTopLevel: Array<{
            path: string;
            entries: FileEntry[];
        }>;
    };
    preferences: ListPreferencesResult;
    sqliteFiles: SearchResult[];
    jsBundleFiles: SearchResult[];
    notes: string[];
};
export declare class SftpNotConnectedError extends Error {
    constructor(message?: string);
}
export declare class SftpFileService {
    private readonly config;
    private client;
    private connecting;
    private canonicalAllowedRoots;
    private readonly searchCache;
    private readonly appFindCache;
    private readonly radare;
    constructor(config: ServerConfig);
    close(): Promise<void>;
    listDir(path: string): Promise<FileEntry[]>;
    readFile(path: string): Promise<string>;
    downloadFile(remotePath: string, localPath: string, overwrite?: boolean): Promise<{
        remotePath: string;
        localPath: string;
        bytesCopied: number;
    }>;
    writeFile(path: string, content: string): Promise<{
        path: string;
        bytesWritten: number;
        backupPath?: string;
    }>;
    appendFile(path: string, content: string): Promise<{
        path: string;
        bytesAppended: number;
    }>;
    deleteFile(path: string): Promise<{
        path: string;
        deleted: true;
    }>;
    moveFile(from: string, to: string): Promise<{
        from: string;
        to: string;
        backupPath?: string;
    }>;
    copyFile(from: string, to: string): Promise<{
        from: string;
        to: string;
        bytesCopied: number;
        backupPath?: string;
    }>;
    mkdir(path: string): Promise<{
        path: string;
        created: true;
    }>;
    stat(path: string): Promise<StatResult>;
    searchFiles(root: string, pattern: string, options?: SearchFilesOptions): Promise<SearchFilesResult>;
    readPlist(path: string): Promise<PlistReadResult>;
    inspectJsBundle(path: string): Promise<JsBundleInspectResult>;
    decodeJsBundle(path: string, options?: {
        mode?: "preview" | "save";
        localPath?: string;
        maxOutputBytes?: number;
        beautify?: boolean;
    }): Promise<JsBundleDecodeResult>;
    listHermesDecoders(): Promise<{
        configuredPreset: HermesDecoderPreset;
        configuredCommand?: string;
        selected?: HermesDecoderChoice;
        decoders: HermesDecoderInfo[];
        notes: string[];
    }>;
    mcpConfigStatus(): Promise<McpConfigStatusResult>;
    connectionDoctor(): Promise<ConnectionDoctorResult>;
    findApp(query: string): Promise<FindAppResult>;
    listApps(query?: string, limit?: number): Promise<ListAppsResult>;
    resolveAppContainer(bundleId: string): Promise<ResolveAppContainerResult>;
    snapshotApp(bundleId: string): Promise<AppSnapshotResult>;
    existsPath(path: string): Promise<ExistsResult>;
    readFileChunk(path: string, offset?: number, length?: number, encoding?: "utf8" | "base64"): Promise<FileChunkResult>;
    tailFile(path: string, maxBytes?: number): Promise<FileChunkResult>;
    readLastLines(path: string, lines?: number, maxBytes?: number): Promise<LastLinesResult>;
    listPreferences(bundleId: string): Promise<ListPreferencesResult>;
    readPreferences(bundleId: string, includeAll?: boolean, maxFiles?: number): Promise<ReadPreferencesResult>;
    readSqliteSchema(path: string): Promise<SqliteSchemaResult>;
    querySqlite(path: string, sql: string, limit?: number): Promise<SqliteQueryResult>;
    zipDownload(paths: string[], localPath: string, overwrite?: boolean): Promise<ZipDownloadResult>;
    diagnoseRoots(): Promise<DiagnoseRootsResult>;
    hashFile(path: string): Promise<{
        path: string;
        algorithm: "sha256";
        hash: string;
        size: number;
    }>;
    r2Check(): Promise<R2CheckResult>;
    r2BinaryInfo(remotePath: string): Promise<{
        remotePath: string;
        size: number;
    } & Awaited<ReturnType<RadareService["binaryInfo"]>>>;
    r2AppTriage(bundleId: string): Promise<Awaited<ReturnType<RadareService["appTriage"]>>>;
    r2Strings(remotePath: string, query?: string, limit?: number): Promise<{
        remotePath: string;
        size: number;
    } & Awaited<ReturnType<RadareService["strings"]>>>;
    r2Imports(remotePath: string, query?: string, limit?: number): Promise<{
        remotePath: string;
        size: number;
    } & Awaited<ReturnType<RadareService["imports"]>>>;
    r2Functions(remotePath: string, limit?: number): Promise<{
        remotePath: string;
        size: number;
    } & Awaited<ReturnType<RadareService["functions"]>>>;
    r2FunctionDisasm(remotePath: string, functionNameOrAddress: string): Promise<{
        remotePath: string;
        size: number;
    } & Awaited<ReturnType<RadareService["functionDisasm"]>>>;
    private withTempR2Binary;
    private assertR2Enabled;
    private runtimeConfigSummary;
    private authMethod;
    private envPresenceSummary;
    private mcpConfigPaths;
    private inspectMcpConfigFile;
    private jsonMcpServerConfigured;
    private localPathStatus;
    private safeListTopLevel;
    private snapshotSearchFiles;
    private infoPlistSummary;
    private stripJsonComments;
    private redactCliArg;
    private connectedClient;
    private connect;
    private resolveAllowedRoots;
    private resolveExistingSafePath;
    private resolveWritableTarget;
    private resolveCreatableDirectory;
    private resolveNearestExistingAncestor;
    private assertCanonicalSafePath;
    private backupIfExisting;
    private deleteExistingFileTarget;
    private exists;
    private detectJsBundleFormat;
    private jsBundleNotes;
    private hermesDecoderInfos;
    private resolveHermesDecoder;
    private bundleDecodeOutput;
    private runHermesDecoder;
    private readDecoderOutputPath;
    private commandExists;
    private runCommand;
    private shellQuote;
    private readRemoteRange;
    private openRemoteSqlite;
    private execSqliteRows;
    private assertReadOnlySql;
    private sqliteIdentifier;
    private addRemotePathToArchive;
    private safeZipEntryName;
    private uniqueStrings;
    private assertSafeLocalPath;
    private safeAppRoot;
    private scanBundleRoot;
    private scanBundleCandidates;
    private appBundleMatchFromCandidate;
    private scanMetadataRoot;
    private readPlistAt;
    private tryReadPlistAt;
    private readRemoteBufferLimited;
    private valuesMatchQuery;
    private rootDiagnosticNotes;
    private collectStrings;
    private interestingIdentifiers;
    private asRecord;
    private stringValue;
    private toJsonSafe;
    private uniqueByPath;
    private mapLimit;
    private getAppFindCache;
    private setAppFindCache;
    private searchCacheKey;
    private getSearchCache;
    private setSearchCache;
    private searchNotes;
    private matcherFromPattern;
    private mapEntryType;
    private fileEntryFromClientInfo;
    private mapStatsType;
    private bufferFromGetResult;
    private dateFromMillis;
    private writeBufferToStream;
}
export {};
