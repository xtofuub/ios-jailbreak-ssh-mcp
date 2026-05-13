import { createWriteStream, existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, readdir, rm, stat as localStat, writeFile as writeLocalFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname as localDirname, join as joinLocal, relative, resolve as resolveLocal } from "node:path";
import { spawn } from "node:child_process";
import archiver from "archiver";
import beautify from "js-beautify";
import { parse as parseXmlPlist, parseBinary as parseBinaryPlist } from "plist";
import Client from "ssh2-sftp-client";
import { assertSafePath, assertWritable, backupPathFor, basename, dirname, joinRemote, normalizeRemotePath } from "./pathSafety.js";
import { RadareService } from "./radareService.js";
import { DeviceR2Runner, LocalR2Runner } from "./r2Runner.js";
const PACKAGE_SPEC = "github:xtofuub/ios-files-mcp";
const MCP_SERVER_NAME = "ios-files";
const SEARCH_ABSOLUTE_MAX_RESULTS = 500;
const SEARCH_ABSOLUTE_MAX_DEPTH = 25;
const APP_CONTAINER_SCAN_LIMIT = 1_000;
const APP_METADATA_READ_LIMIT = 512 * 1024;
const APP_SCAN_CONCURRENCY = 8;
const ZIP_ENTRY_LIMIT = 5_000;
const HERMES_DECODER_PRESETS = [
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
];
const APP_DATA_ROOTS = [
    "/private/var/mobile/Containers/Data/Application",
    "/var/mobile/Containers/Data/Application"
];
const APP_GROUP_ROOTS = [
    "/private/var/mobile/Containers/Shared/AppGroup",
    "/var/mobile/Containers/Shared/AppGroup"
];
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
];
export class SftpNotConnectedError extends Error {
    constructor(message = "SFTP is not connected.") {
        super(message);
        this.name = "SftpNotConnectedError";
    }
}
export class SftpFileService {
    config;
    client;
    connecting;
    canonicalAllowedRoots = [];
    searchCache = new Map();
    appFindCache = new Map();
    runnerPromise;
    radarePromise;
    activeRunnerMode = "none";
    autoFallbackReason;
    constructor(config) {
        this.config = config;
    }
    async close() {
        if (this.client) {
            await this.client.end();
            this.client = undefined;
            this.canonicalAllowedRoots = [];
        }
    }
    async listDir(path) {
        const lexicalPath = assertSafePath(path, this.config);
        const client = await this.connectedClient();
        const safePath = await this.resolveExistingSafePath(client, lexicalPath);
        const entries = await this.withSftpTimeout(client.list(safePath), `list ${safePath}`);
        return entries.map((entry) => this.fileEntryFromClientInfo(entry));
    }
    async readFile(path) {
        const lexicalPath = assertSafePath(path, this.config);
        const client = await this.connectedClient();
        const safePath = await this.resolveExistingSafePath(client, lexicalPath);
        const stat = await client.stat(safePath);
        const size = Number(stat.size ?? 0);
        if (size > this.config.maxReadSize) {
            throw new Error(`File is ${size} bytes, which exceeds maxReadSize=${this.config.maxReadSize}.`);
        }
        const content = await client.get(safePath);
        return this.bufferFromGetResult(content).toString("utf8");
    }
    async downloadFile(remotePath, localPath, overwrite = false) {
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
    async writeFile(path, content) {
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
    async appendFile(path, content) {
        assertWritable(this.config, "ios_append_file");
        const lexicalPath = assertSafePath(path, this.config);
        const client = await this.connectedClient();
        const safePath = await this.resolveWritableTarget(client, lexicalPath);
        const buffer = Buffer.from(content, "utf8");
        const existing = await this.exists(client, safePath);
        if (existing) {
            const writeStream = client.createWriteStream(safePath, { flags: "a" });
            await this.writeBufferToStream(writeStream, buffer);
        }
        else {
            await client.put(buffer, safePath);
        }
        return {
            path: safePath,
            bytesAppended: buffer.byteLength
        };
    }
    async deleteFile(path) {
        assertWritable(this.config, "ios_delete_file");
        const lexicalPath = assertSafePath(path, this.config);
        const client = await this.connectedClient();
        const safePath = await this.resolveExistingSafePath(client, lexicalPath);
        const stat = await client.stat(safePath);
        if (this.mapStatsType(stat) === "directory") {
            await client.rmdir(safePath, false);
        }
        else {
            await client.delete(safePath);
        }
        return { path: safePath, deleted: true };
    }
    async moveFile(from, to) {
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
    async copyFile(from, to) {
        assertWritable(this.config, "ios_copy_file");
        const lexicalFrom = assertSafePath(from, this.config);
        const lexicalTo = assertSafePath(to, this.config);
        const client = await this.connectedClient();
        const safeFrom = await this.resolveExistingSafePath(client, lexicalFrom);
        const safeTo = await this.resolveWritableTarget(client, lexicalTo);
        const stat = await client.stat(safeFrom);
        const size = Number(stat.size ?? 0);
        if (size > this.config.maxReadSize) {
            throw new Error(`Refusing to copy ${size} bytes through the MCP process because maxReadSize=${this.config.maxReadSize}.`);
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
    async mkdir(path) {
        assertWritable(this.config, "ios_mkdir");
        const lexicalPath = assertSafePath(path, this.config);
        const client = await this.connectedClient();
        const safePath = await this.resolveCreatableDirectory(client, lexicalPath);
        await client.mkdir(safePath, true);
        return { path: safePath, created: true };
    }
    async stat(path) {
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
    async searchFiles(root, pattern, options = {}) {
        const lexicalRoot = assertSafePath(root, this.config);
        const client = await this.connectedClient();
        const safeRoot = await this.resolveExistingSafePath(client, lexicalRoot);
        const matcher = this.matcherFromPattern(pattern);
        const maxResults = Math.min(options.maxResults ?? this.config.searchDefaultMaxResults, SEARCH_ABSOLUTE_MAX_RESULTS);
        const maxDepth = Math.min(options.maxDepth ?? this.config.searchDefaultMaxDepth, SEARCH_ABSOLUTE_MAX_DEPTH);
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
        const pending = [{ path: safeRoot, depth: 0 }];
        const visitedPaths = new Set([safeRoot]);
        const results = [];
        let visitedDirectories = 0;
        let truncated = false;
        while (pending.length > 0) {
            const current = pending.shift();
            visitedDirectories += 1;
            if (visitedDirectories > this.config.searchMaxEntries ||
                results.length >= maxResults) {
                truncated = true;
                break;
            }
            let entries;
            try {
                entries = await client.list(current.path);
            }
            catch {
                continue;
            }
            for (const entry of entries) {
                const entryType = this.mapEntryType(entry.type);
                let safeChild;
                try {
                    const childPath = this.assertCanonicalSafePath(joinRemote(current.path, entry.name));
                    safeChild = assertSafePath(childPath, {
                        allowedRoots: this.canonicalAllowedRoots.length
                            ? this.canonicalAllowedRoots
                            : this.config.allowedRoots
                    });
                }
                catch {
                    continue;
                }
                if (matcher(entry.name) || matcher(safeChild)) {
                    const result = {
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
                if (entryType === "directory" &&
                    current.depth < maxDepth &&
                    !visitedPaths.has(safeChild)) {
                    visitedPaths.add(safeChild);
                    pending.push({ path: safeChild, depth: current.depth + 1 });
                }
            }
        }
        const value = {
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
    async readPlist(path) {
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
    async inspectJsBundle(path) {
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
    async decodeJsBundle(path, options = {}) {
        const inspect = await this.inspectJsBundle(path);
        const mode = options.mode ?? (options.localPath ? "save" : "preview");
        const outputLimit = Math.min(options.maxOutputBytes ?? this.config.hermesDecoderOutputLimit, this.config.hermesDecoderOutputLimit);
        const client = await this.connectedClient();
        if (inspect.size > this.config.jsBundleMaxReadSize) {
            throw new Error(`Bundle is ${inspect.size} bytes, which exceeds jsBundleMaxReadSize=${this.config.jsBundleMaxReadSize}. Use ios_download_file first or raise the limit.`);
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
            throw new Error("Bundle does not look like plain JavaScript or Hermes bytecode. Download it and inspect it with a local binary tool.");
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
    async listHermesDecoders() {
        const decoders = await this.hermesDecoderInfos();
        let selected;
        const notes = [];
        try {
            selected = await this.resolveHermesDecoder();
        }
        catch (error) {
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
    async mcpConfigStatus() {
        const configFiles = await Promise.all(this.mcpConfigPaths().map((config) => this.inspectMcpConfigFile(config)));
        const notes = [];
        const configuredClients = configFiles.filter((config) => config.configured).map((config) => config.client);
        if (configuredClients.length === 0) {
            notes.push("No supported MCP client config currently contains an ios-files entry.");
        }
        else {
            notes.push(`Configured clients: ${configuredClients.join(", ")}.`);
        }
        if (!this.config.password && !this.config.privateKeyPath) {
            notes.push("No SSH credential is configured. Set IOS_FILES_MCP_PASSWORD or IOS_FILES_MCP_KEY_PATH.");
        }
        return {
            packageSpec: PACKAGE_SPEC,
            serverName: MCP_SERVER_NAME,
            serverCommand: "npx --yes --quiet github:xtofuub/ios-files-mcp",
            process: {
                cwd: process.cwd(),
                argv: process.argv.map((arg) => this.redactCliArg(arg)),
                node: process.version,
                platform: process.platform
            },
            runtimeConfig: this.runtimeConfigSummary(),
            env: this.envPresenceSummary(),
            commandAvailability: {
                npx: await this.commandExists("npx")
            },
            configFiles,
            notes
        };
    }
    async connectionDoctor() {
        const mcpConfig = await this.mcpConfigStatus();
        const localArtifactRoots = await Promise.all(this.config.localArtifactRoots.map((path) => this.localPathStatus(path)));
        const connection = {
            ok: false,
            host: this.config.host,
            port: this.config.port,
            username: this.config.username,
            authMethod: this.authMethod()
        };
        const nextSteps = [];
        let roots;
        try {
            await this.connectedClient();
            connection.ok = true;
            roots = await this.diagnoseRoots();
        }
        catch (error) {
            connection.error = error instanceof Error ? error.message : String(error);
            nextSteps.push("Fix SSH/SFTP connectivity first: verify host, port, username, credential, and that OpenSSH is reachable.");
        }
        const [hermesDecoders, radare2] = await Promise.all([
            this.listHermesDecoders(),
            this.r2Check()
        ]);
        if (!mcpConfig.commandAvailability.npx) {
            nextSteps.push("Install Node.js/npm or make sure npx is available on PATH for the MCP client.");
        }
        if (radare2.enabled && radare2.activeRunner === "none") {
            if (radare2.mode === "device") {
                nextSteps.push("radare2 is enabled with mode=device but r2/rabin2 were not found on the iOS device. Install via Sileo (Procursus 'radare2'), or set IOS_FILES_MCP_R2_MODE=auto.");
            }
            else if (radare2.mode === "local") {
                nextSteps.push("radare2 is enabled with mode=local but r2/rabin2 are not available on this computer. Install r2 locally or set IOS_FILES_MCP_R2_MODE=device.");
            }
            else {
                nextSteps.push("radare2 is enabled but no working runner was found. Install radare2 on the iOS device via Sileo (recommended), or install r2 locally.");
            }
        }
        const missingLocalRoots = localArtifactRoots.filter((root) => !root.exists);
        if (missingLocalRoots.length > 0) {
            nextSteps.push(`Create or change localArtifactRoots that do not exist: ${missingLocalRoots.map((root) => root.path).join(", ")}.`);
        }
        if (roots && roots.roots.every((root) => !root.exists || (root.entryCount ?? 0) === 0)) {
            nextSteps.push("Expected app roots were empty or unavailable. Try a different SSH username if your device restricts app paths.");
        }
        if (nextSteps.length === 0) {
            nextSteps.push("Connection and local setup look usable. Try ios_find_app(bundle id or app name) next.");
        }
        return {
            ok: connection.ok && nextSteps.length === 1 && nextSteps[0].startsWith("Connection and local setup"),
            connection,
            runtimeConfig: mcpConfig.runtimeConfig,
            localArtifactRoots,
            roots,
            hermesDecoders,
            radare2,
            mcpConfig,
            nextSteps
        };
    }
    async findApp(query) {
        const normalizedQuery = query.trim();
        if (!normalizedQuery) {
            throw new Error("App query must be non-empty.");
        }
        const cached = this.getAppFindCache(normalizedQuery);
        if (cached) {
            return {
                ...cached,
                notes: [...cached.notes, "Returned from in-memory app lookup cache."]
            };
        }
        const client = await this.connectedClient();
        const queryLower = normalizedQuery.toLowerCase();
        const bundleMatches = [];
        const dataContainerMatches = [];
        const appGroupMatches = [];
        const searchedRoots = [];
        const notes = [];
        const seenPaths = new Set();
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
        const bundleIds = new Set(bundleMatches
            .map((match) => match.bundleId?.toLowerCase())
            .filter((value) => Boolean(value)));
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
            notes.push("No app bundle matched by shallow app-directory scan. Try the visible app name, the .app name, or the bundle id.");
        }
        if (dataContainerMatches.length === 0 && bundleMatches.length > 0) {
            notes.push("No data container metadata matched. This can happen if metadata plists are unreadable or use a different identifier.");
        }
        const result = {
            query: normalizedQuery,
            bundleMatches: this.uniqueByPath(bundleMatches),
            dataContainerMatches: this.uniqueByPath(dataContainerMatches),
            appGroupMatches: this.uniqueByPath(appGroupMatches),
            searchedRoots,
            truncated,
            notes
        };
        this.setAppFindCache(normalizedQuery, result);
        return result;
    }
    async listApps(query, limit = 200) {
        const client = await this.connectedClient();
        const queryLower = query?.trim().toLowerCase();
        const apps = [];
        const searchedRoots = [];
        const notes = [];
        const seenPaths = new Set();
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
    async resolveAppContainer(bundleId) {
        const normalizedBundleId = bundleId.trim();
        if (!normalizedBundleId) {
            throw new Error("bundleId must be non-empty.");
        }
        const result = await this.findApp(normalizedBundleId);
        const bundleIdLower = normalizedBundleId.toLowerCase();
        const primaryBundle = result.bundleMatches.find((match) => match.bundleId?.toLowerCase() === bundleIdLower) ??
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
    async snapshotApp(bundleId) {
        const resolved = await this.resolveAppContainer(bundleId);
        const client = await this.connectedClient();
        const notes = [...resolved.notes];
        const bundlePath = resolved.primaryBundle?.path;
        const dataPath = resolved.primaryDataContainer?.path;
        const appGroupPaths = resolved.appGroupMatches.map((match) => match.path);
        let infoPlist;
        if (resolved.primaryBundle) {
            try {
                const parsed = await this.readPlistAt(client, resolved.primaryBundle.infoPlistPath, this.config.maxReadSize);
                infoPlist = {
                    path: resolved.primaryBundle.infoPlistPath,
                    format: parsed.format,
                    summary: this.infoPlistSummary(parsed.value)
                };
            }
            catch (error) {
                notes.push(`Could not read Info.plist: ${error instanceof Error ? error.message : String(error)}`);
            }
        }
        else {
            notes.push("No primary app bundle was found for this bundle id.");
        }
        const [bundleTopLevel, dataTopLevel, preferences, sqliteFiles, jsBundleFiles] = await Promise.all([
            bundlePath ? this.safeListTopLevel(client, bundlePath, notes) : Promise.resolve([]),
            dataPath ? this.safeListTopLevel(client, dataPath, notes) : Promise.resolve([]),
            this.listPreferences(bundleId).catch((error) => ({
                bundleId,
                preferenceDirectories: [],
                preferenceFiles: [],
                notes: [`Could not list preferences: ${error instanceof Error ? error.message : String(error)}`]
            })),
            this.snapshotSearchFiles([dataPath, ...appGroupPaths].filter((path) => Boolean(path)), "/\\.(sqlite|sqlite3|db)$/"),
            this.snapshotSearchFiles([bundlePath, dataPath, ...appGroupPaths].filter((path) => Boolean(path)), "/\\.(jsbundle|bundle|hbc)$/")
        ]);
        const appGroupTopLevel = [];
        for (const path of appGroupPaths.slice(0, 10)) {
            appGroupTopLevel.push({
                path,
                entries: await this.safeListTopLevel(client, path, notes)
            });
        }
        notes.push("Snapshot is metadata-focused. It lists likely files but does not read preference values or database rows.");
        return {
            bundleId,
            resolved,
            infoPlist,
            directories: {
                bundleTopLevel,
                dataTopLevel,
                appGroupTopLevel
            },
            preferences: {
                ...preferences,
                notes: preferences.notes
            },
            sqliteFiles,
            jsBundleFiles,
            notes: this.uniqueStrings(notes)
        };
    }
    async existsPath(path) {
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
        }
        catch {
            return {
                path: lexicalPath,
                exists: false
            };
        }
    }
    async readFileChunk(path, offset = 0, length = this.config.maxReadSize, encoding = "utf8") {
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
    async tailFile(path, maxBytes = 64 * 1024) {
        const lexicalPath = assertSafePath(path, this.config);
        const client = await this.connectedClient();
        const safePath = await this.resolveExistingSafePath(client, lexicalPath);
        const stat = await client.stat(safePath);
        const fileSize = Number(stat.size ?? 0);
        const cappedMaxBytes = Math.min(Math.max(maxBytes, 1), this.config.maxReadSize);
        const offset = Math.max(0, fileSize - cappedMaxBytes);
        return this.readFileChunk(safePath, offset, cappedMaxBytes, "utf8");
    }
    async readLastLines(path, lines = 100, maxBytes = 256 * 1024) {
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
    async listPreferences(bundleId) {
        const resolved = await this.resolveAppContainer(bundleId);
        const client = await this.connectedClient();
        const preferenceDirectories = [];
        const preferenceFiles = [];
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
    async readPreferences(bundleId, includeAll = false, maxFiles = 10) {
        const listed = await this.listPreferences(bundleId);
        const client = await this.connectedClient();
        const bundleIdLower = bundleId.toLowerCase();
        const selectedFiles = listed.preferenceFiles
            .filter((file) => includeAll || file.name.toLowerCase() === `${bundleIdLower}.plist`)
            .slice(0, maxFiles);
        const values = [];
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
    async readSqliteSchema(path) {
        const { db, safePath, size } = await this.openRemoteSqlite(path);
        try {
            const schemaRows = this.execSqliteRows(db, "SELECT type, name, sql FROM sqlite_master WHERE type IN ('table', 'view') ORDER BY type, name", 500);
            const tables = [];
            for (const row of schemaRows.rows) {
                const name = String(row.name ?? "");
                const type = String(row.type ?? "");
                const columns = type === "table"
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
        }
        finally {
            db.close();
        }
    }
    async querySqlite(path, sql, limit = 50) {
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
        }
        finally {
            db.close();
        }
    }
    async zipDownload(paths, localPath, overwrite = false) {
        if (!Array.isArray(paths) || paths.length === 0) {
            throw new Error("paths must contain at least one remote path.");
        }
        const safeLocalPath = this.assertSafeLocalPath(localPath);
        if (existsSync(safeLocalPath) && !overwrite) {
            throw new Error(`Local path already exists. Set overwrite=true to replace: ${safeLocalPath}`);
        }
        const client = await this.connectedClient();
        const safePaths = [];
        for (const path of paths) {
            safePaths.push(await this.resolveExistingSafePath(client, assertSafePath(path, this.config)));
        }
        await mkdir(localDirname(safeLocalPath), { recursive: true });
        const output = createWriteStream(safeLocalPath);
        const archive = archiver("zip", { zlib: { level: 6 } });
        let entriesAdded = 0;
        const archiveDone = new Promise((resolve, reject) => {
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
    async diagnoseRoots() {
        const client = await this.connectedClient();
        const roots = [];
        for (const path of DIAGNOSTIC_ROOTS) {
            const diagnostic = {
                path,
                allowed: true,
                exists: false
            };
            try {
                assertSafePath(path, this.config);
            }
            catch (error) {
                diagnostic.allowed = false;
                diagnostic.error = error instanceof Error ? error.message : String(error);
                roots.push(diagnostic);
                continue;
            }
            try {
                diagnostic.realPath = normalizeRemotePath(await client.realPath(path));
                this.assertCanonicalSafePath(diagnostic.realPath);
                diagnostic.exists = true;
            }
            catch (error) {
                diagnostic.error = error instanceof Error ? error.message : String(error);
                roots.push(diagnostic);
                continue;
            }
            try {
                const entries = await client.list(diagnostic.realPath);
                diagnostic.entryCount = entries.length;
                diagnostic.sampleEntries = entries.slice(0, 12).map((entry) => entry.name);
            }
            catch (error) {
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
    async hashFile(path) {
        const lexicalPath = assertSafePath(path, this.config);
        const client = await this.connectedClient();
        const safePath = await this.resolveExistingSafePath(client, lexicalPath);
        const stat = await client.stat(safePath);
        const size = Number(stat.size ?? 0);
        if (size > this.config.maxReadSize) {
            throw new Error(`File is ${size} bytes, which exceeds maxReadSize=${this.config.maxReadSize}.`);
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
    async r2Check() {
        const mode = this.config.r2.mode;
        if (!this.config.r2.enabled) {
            const disabled = { available: false, error: "radare2 tools are disabled" };
            return {
                enabled: false,
                mode,
                activeRunner: "none",
                r2: disabled,
                rabin2: disabled,
                notes: ["radare2 tools are disabled by config. Remove IOS_FILES_MCP_ENABLE_R2=false or set it to true."]
            };
        }
        let device;
        let local;
        const notes = [];
        if (mode !== "local") {
            device = await this.probeDeviceRunner();
        }
        if (mode !== "device") {
            local = await this.probeLocalRunner();
        }
        let activeRunner = "none";
        let r2;
        let rabin2;
        if (mode === "device") {
            activeRunner = device && device.r2.available && device.rabin2.available ? "device" : "none";
            r2 = device?.r2 ?? { available: false, error: "device probe skipped" };
            rabin2 = device?.rabin2 ?? { available: false, error: "device probe skipped" };
            if (activeRunner !== "device") {
                notes.push(`radare2 not found on the iOS device (r2.mode=device). Install via Sileo (Procursus 'radare2'), or set IOS_FILES_MCP_R2_MODE=auto to allow a local fallback.`);
            }
            else if (device?.r2.version) {
                notes.push(`Using device-side radare2 at ${device.r2Path} (${device.r2.version}).`);
            }
        }
        else if (mode === "local") {
            activeRunner = local && local.r2.available && local.rabin2.available ? "local" : "none";
            r2 = local?.r2 ?? { available: false, error: "local probe skipped" };
            rabin2 = local?.rabin2 ?? { available: false, error: "local probe skipped" };
            if (activeRunner !== "local") {
                notes.push("radare2 not available locally. Install r2/rabin2 on this computer or set IOS_FILES_MCP_R2_MODE=device to use the iOS device install.");
            }
            else if (local?.r2.version) {
                notes.push(`Using local radare2 at ${local.r2Path} (${local.r2.version}).`);
            }
        }
        else {
            // auto
            if (device && device.r2.available && device.rabin2.available) {
                activeRunner = "device";
                r2 = device.r2;
                rabin2 = device.rabin2;
                if (device.r2.version) {
                    notes.push(`Using device-side radare2 at ${device.r2Path} (${device.r2.version}).`);
                }
            }
            else if (local && local.r2.available && local.rabin2.available) {
                activeRunner = "local";
                r2 = local.r2;
                rabin2 = local.rabin2;
                const deviceErr = device?.r2.error ?? device?.rabin2.error ?? "device probe failed";
                notes.push(`Device r2 unavailable (${deviceErr}); falling back to local radare2 at ${local.r2Path}.`);
            }
            else {
                activeRunner = "none";
                r2 = device?.r2 ?? local?.r2 ?? { available: false, error: "no runner available" };
                rabin2 = device?.rabin2 ?? local?.rabin2 ?? { available: false, error: "no runner available" };
                notes.push("radare2 is not available on the iOS device or locally. Install via Sileo (Procursus 'radare2') on the device, or install r2 on this computer.");
            }
        }
        return { enabled: true, mode, activeRunner, r2, rabin2, device, local, notes };
    }
    async r2BinaryInfo(remotePath) {
        return this.withR2Binary(remotePath, async (binary, radare) => ({
            remotePath: binary.remotePath,
            size: binary.size,
            ...(await radare.binaryInfo(binary.argvPath))
        }));
    }
    async r2AppTriage(bundleId) {
        this.assertR2Enabled();
        const normalizedBundleId = bundleId.trim();
        if (!normalizedBundleId) {
            throw new Error("bundleId must be non-empty.");
        }
        const resolved = await this.resolveAppContainer(normalizedBundleId);
        const bundle = resolved.primaryBundle;
        if (!bundle) {
            throw new Error(`No app bundle was found for bundle id: ${normalizedBundleId}`);
        }
        const client = await this.connectedClient();
        const parsed = await this.readPlistAt(client, bundle.infoPlistPath, APP_METADATA_READ_LIMIT);
        const infoRecord = this.asRecord(parsed.value);
        const executable = this.stringValue(infoRecord?.CFBundleExecutable) ?? bundle.appName;
        if (!executable) {
            throw new Error(`Info.plist did not include CFBundleExecutable for ${normalizedBundleId}.`);
        }
        if (executable.includes("/") || executable.includes("\\")) {
            throw new Error("CFBundleExecutable must be a file name, not a path.");
        }
        const remoteBinaryPath = this.assertCanonicalSafePath(joinRemote(bundle.path, executable));
        return this.withR2Binary(remoteBinaryPath, (binary, radare) => radare.appTriage({
            bundleId: normalizedBundleId,
            argvPath: binary.argvPath,
            remoteBinaryPath: binary.remotePath
        }));
    }
    async r2Strings(remotePath, query, limit) {
        return this.withR2Binary(remotePath, async (binary, radare) => ({
            remotePath: binary.remotePath,
            size: binary.size,
            ...(await radare.strings(binary.argvPath, query, limit))
        }));
    }
    async r2Imports(remotePath, query, limit) {
        return this.withR2Binary(remotePath, async (binary, radare) => ({
            remotePath: binary.remotePath,
            size: binary.size,
            ...(await radare.imports(binary.argvPath, query, limit))
        }));
    }
    async r2Functions(remotePath, limit) {
        return this.withR2Binary(remotePath, async (binary, radare) => ({
            remotePath: binary.remotePath,
            size: binary.size,
            ...(await radare.functions(binary.argvPath, limit))
        }));
    }
    async r2FunctionDisasm(remotePath, functionNameOrAddress) {
        return this.withR2Binary(remotePath, async (binary, radare) => ({
            remotePath: binary.remotePath,
            size: binary.size,
            ...(await radare.functionDisasm(binary.argvPath, functionNameOrAddress))
        }));
    }
    async withR2Binary(remotePath, handler) {
        this.assertR2Enabled();
        const runner = await this.getR2Runner();
        const radare = await this.getRadare();
        const source = await runner.resolveBinary(remotePath);
        try {
            return await handler({ remotePath: source.remotePath, argvPath: source.argvPath, size: source.size }, radare);
        }
        finally {
            await source.cleanup();
        }
    }
    async getR2Runner() {
        if (!this.runnerPromise) {
            this.runnerPromise = this.selectR2Runner().catch((error) => {
                this.runnerPromise = undefined;
                throw error;
            });
        }
        return this.runnerPromise;
    }
    async getRadare() {
        if (!this.radarePromise) {
            this.radarePromise = this.getR2Runner().then((runner) => new RadareService(runner, {
                timeoutMs: this.config.r2.timeoutMs,
                maxOutputBytes: this.config.r2.maxOutputBytes
            }));
        }
        return this.radarePromise;
    }
    buildLocalRunner() {
        return new LocalR2Runner({
            r2Path: this.config.r2.r2Path,
            rabin2Path: this.config.r2.rabin2Path,
            maxBinarySize: this.config.r2.maxBinarySize,
            sftpResolver: this.sftpResolverFactory()
        });
    }
    buildDeviceRunner() {
        return new DeviceR2Runner({
            r2Path: this.config.r2.deviceR2Path,
            rabin2Path: this.config.r2.deviceRabin2Path,
            probeTimeoutMs: 5_000,
            maxBinarySize: this.config.r2.maxBinarySize,
            sshClient: () => this.sshClient(),
            sftpResolver: this.sftpResolverFactory()
        });
    }
    async selectR2Runner() {
        this.assertR2Enabled();
        const mode = this.config.r2.mode;
        if (mode === "local") {
            const local = this.buildLocalRunner();
            await local.probe();
            this.activeRunnerMode = "local";
            this.autoFallbackReason = undefined;
            return local;
        }
        if (mode === "device") {
            const device = this.buildDeviceRunner();
            const probe = await device.probe();
            if (!probe.r2.available || !probe.rabin2.available) {
                const err = probe.r2.error ?? probe.rabin2.error ?? "r2/rabin2 not found on device";
                throw new Error(`r2.mode=device but radare2 is not available on the iOS device: ${err}. Install via Sileo (Procursus 'radare2'), or set IOS_FILES_MCP_R2_MODE=auto to allow a local fallback.`);
            }
            this.activeRunnerMode = "device";
            this.autoFallbackReason = undefined;
            return device;
        }
        // auto
        const device = this.buildDeviceRunner();
        let deviceFailure;
        try {
            const probe = await device.probe();
            if (probe.r2.available && probe.rabin2.available) {
                this.activeRunnerMode = "device";
                this.autoFallbackReason = undefined;
                return device;
            }
            deviceFailure = probe.r2.error ?? probe.rabin2.error ?? "r2 not found on device";
        }
        catch (error) {
            deviceFailure = error instanceof Error ? error.message : String(error);
        }
        this.autoFallbackReason = deviceFailure;
        const local = this.buildLocalRunner();
        await local.probe();
        this.activeRunnerMode = "local";
        return local;
    }
    async probeDeviceRunner() {
        const runner = this.buildDeviceRunner();
        try {
            const probe = await runner.probe();
            return {
                r2Path: probe.r2Path,
                rabin2Path: probe.rabin2Path,
                r2: probe.r2,
                rabin2: probe.rabin2
            };
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return {
                r2Path: runner.r2Path,
                rabin2Path: runner.rabin2Path,
                r2: { available: false, error: message },
                rabin2: { available: false, error: message }
            };
        }
    }
    async probeLocalRunner() {
        const runner = this.buildLocalRunner();
        const probe = await runner.probe();
        return {
            r2Path: probe.r2Path,
            rabin2Path: probe.rabin2Path,
            r2: probe.r2,
            rabin2: probe.rabin2
        };
    }
    sftpResolverFactory() {
        return async (remotePath) => {
            this.assertR2Enabled();
            const lexicalPath = assertSafePath(remotePath, this.config);
            const client = await this.connectedClient();
            const safeRemotePath = await this.resolveExistingSafePath(client, lexicalPath);
            const stat = await client.stat(safeRemotePath);
            if (this.mapStatsType(stat) !== "file") {
                throw new Error(`Remote path is not a regular file: ${safeRemotePath}`);
            }
            const size = Number(stat.size ?? 0);
            return {
                remotePath: safeRemotePath,
                size,
                download: async (localPath) => {
                    await client.get(safeRemotePath, createWriteStream(localPath));
                }
            };
        };
    }
    async sshClient() {
        const sftp = await this.connectedClient();
        const inner = sftp.client;
        if (!inner) {
            throw new Error("Underlying ssh2 client is not exposed by the SFTP wrapper. This usually indicates an unexpected ssh2-sftp-client version.");
        }
        return inner;
    }
    assertR2Enabled() {
        if (!this.config.r2.enabled) {
            throw new Error("radare2 tools are disabled by config. Remove IOS_FILES_MCP_ENABLE_R2=false or set it to true in the MCP env block.");
        }
    }
    runtimeConfigSummary() {
        return {
            host: this.config.host,
            port: this.config.port,
            username: this.config.username,
            authMethod: this.authMethod(),
            readOnly: this.config.readOnly,
            allowWrites: this.config.allowWrites,
            requireWriteApproval: this.config.requireWriteApproval,
            allowedRoots: this.config.allowedRoots,
            localArtifactRoots: this.config.localArtifactRoots,
            logPath: this.config.logPath,
            sftpOpTimeoutMs: this.config.sftpOpTimeoutMs,
            r2: {
                enabled: this.config.r2.enabled,
                mode: this.config.r2.mode,
                activeRunner: this.activeRunnerMode,
                r2Path: this.config.r2.r2Path,
                rabin2Path: this.config.r2.rabin2Path,
                deviceR2Path: this.config.r2.deviceR2Path,
                deviceRabin2Path: this.config.r2.deviceRabin2Path,
                timeoutMs: this.config.r2.timeoutMs,
                maxOutputBytes: this.config.r2.maxOutputBytes,
                maxBinarySize: this.config.r2.maxBinarySize
            }
        };
    }
    authMethod() {
        if (this.config.privateKeyPath) {
            return "privateKey";
        }
        if (this.config.password) {
            return "password";
        }
        return "none";
    }
    envPresenceSummary() {
        const envNames = [
            "IOS_FILES_MCP_HOST",
            "IOS_FILES_MCP_PORT",
            "IOS_FILES_MCP_USERNAME",
            "IOS_FILES_MCP_PASSWORD",
            "IOS_FILES_MCP_KEY_PATH",
            "IOS_FILES_MCP_ALLOWED_ROOTS",
            "IOS_FILES_MCP_LOCAL_ARTIFACT_ROOTS",
            "IOS_FILES_MCP_READ_ONLY",
            "IOS_FILES_MCP_ALLOW_WRITES",
            "IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL",
            "IOS_FILES_MCP_ENABLE_R2",
            "IOS_FILES_MCP_R2_MODE",
            "IOS_FILES_MCP_R2_PATH",
            "IOS_FILES_MCP_RABIN2_PATH",
            "IOS_FILES_MCP_R2_DEVICE_R2_PATH",
            "IOS_FILES_MCP_R2_DEVICE_RABIN2_PATH",
            "IOS_FILES_MCP_R2_TIMEOUT_MS",
            "IOS_FILES_MCP_R2_MAX_OUTPUT_BYTES",
            "IOS_FILES_MCP_R2_MAX_BINARY_SIZE",
            "IOS_FILES_MCP_SFTP_OP_TIMEOUT_MS",
            "IOS_FILES_MCP_CONFIG"
        ];
        return Object.fromEntries(envNames.map((name) => {
            const value = process.env[name];
            const safeValue = value && !/(PASSWORD|PASSPHRASE|KEY)/.test(name) ? value : undefined;
            return [name, { present: value !== undefined, value: safeValue }];
        }));
    }
    mcpConfigPaths() {
        const appData = process.env.APPDATA ?? joinLocal(homedir(), "AppData", "Roaming");
        const claudePath = process.platform === "win32"
            ? joinLocal(appData, "Claude", "claude_desktop_config.json")
            : process.platform === "darwin"
                ? joinLocal(homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json")
                : joinLocal(homedir(), ".config", "Claude", "claude_desktop_config.json");
        return [
            {
                client: "codex",
                path: joinLocal(homedir(), ".codex", "config.toml"),
                expectedShape: `[mcp_servers.${MCP_SERVER_NAME}]`
            },
            {
                client: "claude",
                path: claudePath,
                expectedShape: `mcpServers.${MCP_SERVER_NAME}`
            },
            {
                client: "opencode",
                path: process.env.OPENCODE_CONFIG ? resolveLocal(process.env.OPENCODE_CONFIG) : joinLocal(homedir(), ".config", "opencode", "opencode.json"),
                expectedShape: `mcp.${MCP_SERVER_NAME}`
            },
            {
                client: "vscode",
                path: resolveLocal(process.cwd(), ".vscode", "mcp.json"),
                expectedShape: `servers.${MCP_SERVER_NAME}`
            }
        ];
    }
    async inspectMcpConfigFile(config) {
        const notes = [];
        try {
            await localStat(config.path);
        }
        catch (error) {
            return {
                ...config,
                exists: false,
                configured: false,
                notes: ["Config file does not exist."]
            };
        }
        try {
            const content = await readFile(config.path, "utf8");
            let configured = false;
            if (config.client === "codex") {
                configured =
                    content.includes(`[mcp_servers.${MCP_SERVER_NAME}]`) &&
                        content.includes(PACKAGE_SPEC);
            }
            else {
                const parsed = JSON.parse(this.stripJsonComments(content));
                configured = this.jsonMcpServerConfigured(parsed, config.client);
            }
            if (!configured) {
                notes.push("ios-files entry was not found or does not point at the expected GitHub package.");
            }
            return {
                ...config,
                exists: true,
                configured,
                notes
            };
        }
        catch (error) {
            return {
                ...config,
                exists: true,
                configured: false,
                notes,
                error: error instanceof Error ? error.message : String(error)
            };
        }
    }
    jsonMcpServerConfigured(input, client) {
        if (!input || typeof input !== "object" || Array.isArray(input)) {
            return false;
        }
        const root = input;
        const containerName = client === "opencode" ? "mcp" : client === "vscode" ? "servers" : "mcpServers";
        const container = root[containerName];
        if (!container || typeof container !== "object" || Array.isArray(container)) {
            return false;
        }
        const server = container[MCP_SERVER_NAME];
        if (!server || typeof server !== "object" || Array.isArray(server)) {
            return false;
        }
        return JSON.stringify(server).includes(PACKAGE_SPEC);
    }
    async localPathStatus(path) {
        try {
            const stats = await localStat(path);
            return {
                path,
                exists: true,
                type: stats.isDirectory() ? "directory" : stats.isFile() ? "file" : "other"
            };
        }
        catch (error) {
            return {
                path,
                exists: false,
                error: error instanceof Error ? error.message : String(error)
            };
        }
    }
    async safeListTopLevel(client, path, notes, limit = 75) {
        try {
            const safePath = await this.resolveExistingSafePath(client, path);
            const entries = await client.list(safePath);
            return entries.slice(0, limit).map((entry) => this.fileEntryFromClientInfo(entry));
        }
        catch (error) {
            notes.push(`Could not list ${path}: ${error instanceof Error ? error.message : String(error)}`);
            return [];
        }
    }
    async snapshotSearchFiles(roots, pattern) {
        const results = [];
        const seenPaths = new Set();
        for (const root of roots.slice(0, 12)) {
            try {
                const search = await this.searchFiles(root, pattern, {
                    maxResults: 25,
                    maxDepth: 4,
                    includeMetadata: true,
                    useCache: true
                });
                for (const result of search.results) {
                    if (!seenPaths.has(result.path)) {
                        seenPaths.add(result.path);
                        results.push(result);
                    }
                }
            }
            catch {
                // Snapshot search should be best-effort.
            }
        }
        return results.slice(0, 50);
    }
    infoPlistSummary(value) {
        const record = value && typeof value === "object" && !Array.isArray(value)
            ? value
            : {};
        const keys = [
            "CFBundleIdentifier",
            "CFBundleDisplayName",
            "CFBundleName",
            "CFBundleExecutable",
            "CFBundleShortVersionString",
            "CFBundleVersion",
            "MinimumOSVersion",
            "UIDeviceFamily",
            "UIRequiredDeviceCapabilities",
            "DTPlatformName"
        ];
        return Object.fromEntries(keys
            .filter((key) => record[key] !== undefined)
            .map((key) => [key, this.toJsonSafe(record[key])]));
    }
    stripJsonComments(input) {
        return input
            .replace(/^\uFEFF/, "")
            .replace(/\/\*[\s\S]*?\*\//g, "")
            .replace(/(^|[^:])\/\/.*$/gm, "$1");
    }
    redactCliArg(arg) {
        if (/password|passphrase|token|secret/i.test(arg)) {
            return "<redacted>";
        }
        return arg;
    }
    async connectedClient() {
        if (this.client) {
            return this.client;
        }
        if (this.connecting) {
            return this.connecting;
        }
        this.connecting = this.connectWithRetry();
        try {
            this.client = await this.connecting;
            this.canonicalAllowedRoots = await this.resolveAllowedRoots(this.client);
            return this.client;
        }
        catch (error) {
            this.client = undefined;
            const detail = error instanceof Error ? error.message : String(error);
            throw new SftpNotConnectedError(`SFTP connection to ${this.config.host}:${this.config.port} failed: ${detail}. Check IOS_FILES_MCP_HOST, IOS_FILES_MCP_PASSWORD or IOS_FILES_MCP_KEY_PATH, and that OpenSSH is reachable on the iOS device.`);
        }
        finally {
            this.connecting = undefined;
        }
    }
    async connectWithRetry() {
        try {
            return await this.connect();
        }
        catch (firstError) {
            await new Promise((resolve) => setTimeout(resolve, 500));
            try {
                return await this.connect();
            }
            catch {
                throw firstError;
            }
        }
    }
    async connect() {
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
    withSftpTimeout(op, label) {
        const ms = this.config.sftpOpTimeoutMs;
        let timer;
        const timeout = new Promise((_resolve, reject) => {
            timer = setTimeout(() => {
                reject(new Error(`SFTP ${label} timed out after ${ms}ms. Tune IOS_FILES_MCP_SFTP_OP_TIMEOUT_MS if the device is slow.`));
            }, ms);
        });
        return Promise.race([op, timeout]).finally(() => {
            if (timer)
                clearTimeout(timer);
        });
    }
    async resolveAllowedRoots(client) {
        const roots = new Set(this.config.allowedRoots);
        for (const root of this.config.allowedRoots) {
            try {
                roots.add(normalizeRemotePath(await this.withSftpTimeout(client.realPath(root), `realPath ${root}`)));
            }
            catch {
                roots.add(root);
            }
        }
        return [...roots];
    }
    async resolveExistingSafePath(client, input) {
        const lexicalPath = assertSafePath(input, this.config);
        let realPath;
        try {
            realPath = normalizeRemotePath(await this.withSftpTimeout(client.realPath(lexicalPath), `realPath ${lexicalPath}`));
        }
        catch (error) {
            throw new Error(`Path does not exist or permission was denied: ${lexicalPath}. ${error instanceof Error ? error.message : String(error)}`);
        }
        return this.assertCanonicalSafePath(realPath);
    }
    async resolveWritableTarget(client, input) {
        const lexicalPath = assertSafePath(input, this.config);
        const exists = await this.exists(client, lexicalPath);
        if (exists) {
            return this.resolveExistingSafePath(client, lexicalPath);
        }
        const parent = dirname(lexicalPath);
        const safeParent = await this.resolveExistingSafePath(client, parent);
        return this.assertCanonicalSafePath(joinRemote(safeParent, basename(lexicalPath)));
    }
    async resolveCreatableDirectory(client, input) {
        const lexicalPath = assertSafePath(input, this.config);
        const exists = await this.exists(client, lexicalPath);
        if (exists) {
            return this.resolveExistingSafePath(client, lexicalPath);
        }
        const ancestor = await this.resolveNearestExistingAncestor(client, lexicalPath);
        const suffix = lexicalPath.slice(ancestor.lexicalPath.length).replace(/^\/+/, "");
        return this.assertCanonicalSafePath(joinRemote(ancestor.realPath, suffix));
    }
    async resolveNearestExistingAncestor(client, lexicalPath) {
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
    assertCanonicalSafePath(path) {
        const normalized = normalizeRemotePath(path);
        const canonicalConfig = {
            allowedRoots: this.canonicalAllowedRoots.length
                ? this.canonicalAllowedRoots
                : this.config.allowedRoots
        };
        return assertSafePath(normalized, canonicalConfig);
    }
    async backupIfExisting(client, path) {
        if (!(await this.exists(client, path))) {
            return undefined;
        }
        const backupPath = this.assertCanonicalSafePath(backupPathFor(path));
        const stat = await client.stat(path);
        if (this.mapStatsType(stat) === "directory") {
            throw new Error(`Destination exists and is a directory; refusing to overwrite: ${path}`);
        }
        if (!this.config.backupBeforeWrite) {
            throw new Error(`Destination exists and backupBeforeWrite=false; refusing to overwrite: ${path}`);
        }
        await client.rcopy(path, backupPath);
        return backupPath;
    }
    async deleteExistingFileTarget(client, path) {
        const stat = await client.stat(path);
        if (this.mapStatsType(stat) === "directory") {
            throw new Error(`Destination exists and is a directory; refusing to overwrite: ${path}`);
        }
        await client.delete(path);
    }
    async exists(client, path) {
        try {
            return await client.exists(path) !== false;
        }
        catch {
            return false;
        }
    }
    detectJsBundleFormat(header) {
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
    jsBundleNotes(format) {
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
    async hermesDecoderInfos() {
        const infos = [];
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
    async resolveHermesDecoder() {
        if (this.config.hermesDecoderCommand) {
            return {
                preset: this.config.hermesDecoderPreset === "auto" ? "custom" : this.config.hermesDecoderPreset,
                commandTemplate: this.config.hermesDecoderCommand
            };
        }
        if (this.config.hermesDecoderPreset === "custom") {
            throw new Error("Hermes decoder preset is custom, but hermesDecoderCommand is empty. Set hermesDecoderCommand or IOS_FILES_MCP_HERMES_DECODER_COMMAND.");
        }
        if (this.config.hermesDecoderPreset === "jsc2llvm") {
            throw new Error("jsc2llvm preset needs an explicit hermesDecoderCommand because this project does not know your jsc2llvm command syntax. Example shape: jsc2llvm ... {input} ... {output}");
        }
        if (this.config.hermesDecoderPreset !== "auto") {
            const preset = HERMES_DECODER_PRESETS.find((candidate) => candidate.preset === this.config.hermesDecoderPreset);
            if (!preset) {
                throw new Error(`Unsupported Hermes decoder preset: ${this.config.hermesDecoderPreset}`);
            }
            if (!(await this.commandExists(preset.commandName))) {
                throw new Error(`Hermes decoder preset '${preset.preset}' requires '${preset.commandName}' on PATH. Install it, use preset auto, or set hermesDecoderCommand.`);
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
        throw new Error("Hermes bytecode detected, but no supported decoder was found on PATH. Install hermes-dec (hbc-decompiler/hbc-disassembler), hermesc, or hbctool; or set hermesDecoderCommand / IOS_FILES_MCP_HERMES_DECODER_COMMAND for a custom decoder such as jsc2llvm.");
    }
    async bundleDecodeOutput(options) {
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
        const clipped = contentBuffer.byteLength > options.outputLimit
            ? contentBuffer.subarray(0, options.outputLimit).toString("utf8")
            : options.content;
        return {
            ...options.inspect,
            mode: "preview",
            decodedKind: options.decodedKind,
            decoder: options.decoder,
            content: clipped,
            stderr: options.stderr,
            notes: contentBuffer.byteLength > options.outputLimit
                ? [...options.inspect.notes, `Output was clipped to ${options.outputLimit} bytes. Use mode=save with localPath for the full decoded output.`]
                : options.inspect.notes
        };
    }
    async runHermesDecoder(input, commandTemplate, outputLimit) {
        const tokens = this.parseCommandTemplate(commandTemplate);
        const tempDir = await mkdtemp(joinLocal(tmpdir(), "ios-files-mcp-hermes-"));
        const inputPath = joinLocal(tempDir, "bundle.hbc");
        const outputPath = joinLocal(tempDir, "decoder-output");
        try {
            await writeLocalFile(inputPath, input);
            const { command, args } = this.substituteTokens(tokens, {
                input: inputPath,
                output: outputPath
            });
            const result = await this.runCommand(command, args, outputLimit);
            if (commandTemplate.includes("{output}") && existsSync(outputPath)) {
                return {
                    stdout: await this.readDecoderOutputPath(outputPath, outputLimit),
                    stderr: result.stderr
                };
            }
            return result;
        }
        finally {
            await rm(tempDir, { recursive: true, force: true });
        }
    }
    async readDecoderOutputPath(path, outputLimit) {
        const info = await localStat(path);
        if (info.isFile()) {
            const output = await readFile(path);
            return output.subarray(0, outputLimit).toString("utf8");
        }
        if (!info.isDirectory()) {
            return "";
        }
        const parts = [];
        let remaining = outputLimit;
        const pending = [path];
        while (pending.length > 0 && remaining > 0) {
            const current = pending.shift();
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
    async commandExists(commandName) {
        const isWin = process.platform === "win32";
        const command = isWin ? "where" : "command";
        const args = isWin ? [commandName] : ["-v", commandName];
        try {
            await this.runCommand(command, args, 1024);
            return true;
        }
        catch {
            return false;
        }
    }
    parseCommandTemplate(template) {
        if (!template || !template.trim()) {
            throw new Error("Command template is empty.");
        }
        const tokens = [];
        let current = "";
        let inSingle = false;
        let inDouble = false;
        let started = false;
        const flushIfStarted = () => {
            if (started) {
                tokens.push(current);
                current = "";
                started = false;
            }
        };
        for (let i = 0; i < template.length; i += 1) {
            const ch = template[i];
            if (!inSingle && !inDouble && /\s/.test(ch)) {
                flushIfStarted();
                continue;
            }
            if (!inDouble && ch === "'") {
                started = true;
                inSingle = !inSingle;
                continue;
            }
            if (!inSingle && ch === "\"") {
                started = true;
                inDouble = !inDouble;
                continue;
            }
            if (inDouble && ch === "\\" && i + 1 < template.length) {
                const next = template[i + 1];
                if (next === "\"" || next === "\\" || next === "$" || next === "`") {
                    current += next;
                    started = true;
                    i += 1;
                    continue;
                }
            }
            if (!inSingle && !inDouble) {
                if (ch === "$" && template[i + 1] === "(") {
                    throw new Error(`Command template contains shell substitution \"$(\": ${template}`);
                }
                if (ch === "`") {
                    throw new Error(`Command template contains backtick: ${template}`);
                }
                if (ch === ";" || ch === "|" || ch === "&" || ch === ">" || ch === "<") {
                    throw new Error(`Command template contains shell metacharacter '${ch}': ${template}`);
                }
            }
            current += ch;
            started = true;
        }
        if (inSingle || inDouble) {
            throw new Error(`Command template has an unterminated quote: ${template}`);
        }
        flushIfStarted();
        if (tokens.length === 0) {
            throw new Error("Command template is empty.");
        }
        return tokens;
    }
    substituteTokens(tokens, substitutions) {
        const replaced = tokens.map((token) => {
            let out = token;
            for (const [key, value] of Object.entries(substitutions)) {
                out = out.split(`{${key}}`).join(value);
            }
            return out;
        });
        const [command, ...args] = replaced;
        return { command, args };
    }
    runCommand(command, args, outputLimit) {
        return new Promise((resolve, reject) => {
            const child = spawn(command, args, {
                shell: false,
                windowsHide: true
            });
            const stdout = [];
            const stderr = [];
            let stdoutBytes = 0;
            let stderrBytes = 0;
            child.stdout?.on("data", (chunk) => {
                if (stdoutBytes < outputLimit) {
                    stdout.push(chunk.subarray(0, Math.max(0, outputLimit - stdoutBytes)));
                }
                stdoutBytes += chunk.byteLength;
            });
            child.stderr?.on("data", (chunk) => {
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
                    reject(new Error(`Command failed (exit ${code}): ${stderrText || stdoutText}`));
                    return;
                }
                resolve({ stdout: stdoutText, stderr: stderrText });
            });
        });
    }
    async readRemoteRange(client, path, start, end) {
        if (end < start) {
            return Buffer.alloc(0);
        }
        const stream = client.createReadStream(path, { start, end });
        const chunks = [];
        await new Promise((resolve, reject) => {
            stream.on("data", (chunk) => {
                chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            });
            stream.once("error", reject);
            stream.once("end", resolve);
        });
        return Buffer.concat(chunks);
    }
    async openRemoteSqlite(path) {
        const lexicalPath = assertSafePath(path, this.config);
        const client = await this.connectedClient();
        const safePath = await this.resolveExistingSafePath(client, lexicalPath);
        const stat = await client.stat(safePath);
        const size = Number(stat.size ?? 0);
        if (this.mapStatsType(stat) !== "file") {
            throw new Error(`Path is not a regular file: ${safePath}`);
        }
        if (size > this.config.sqliteMaxReadSize) {
            throw new Error(`SQLite file is ${size} bytes, which exceeds sqliteMaxReadSize=${this.config.sqliteMaxReadSize}. Download it first if you need offline analysis.`);
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
    execSqliteRows(db, sql, limit) {
        const results = db.exec(sql);
        const first = results[0];
        if (!first) {
            return { columns: [], rows: [], rowCount: 0 };
        }
        const rows = first.values.map((row) => Object.fromEntries(first.columns.map((column, index) => [column, this.toJsonSafe(row[index])])));
        return {
            columns: first.columns,
            rows: rows.slice(0, limit),
            rowCount: rows.length
        };
    }
    assertReadOnlySql(sql) {
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
    sqliteIdentifier(name) {
        return `"${name.replace(/"/g, "\"\"")}"`;
    }
    async addRemotePathToArchive(client, archive, path, zipName) {
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
        const pending = [{ remotePath: path, zipPrefix: zipName }];
        while (pending.length > 0) {
            const current = pending.shift();
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
                }
                else if (entryType === "directory") {
                    archive.append("", { name: `${childZipName}/` });
                    entriesAdded += 1;
                    pending.push({ remotePath: childPath, zipPrefix: childZipName });
                }
            }
        }
        return entriesAdded;
    }
    safeZipEntryName(name) {
        return name.replace(/\\/g, "/").split("/").filter(Boolean).join("_") || "entry";
    }
    uniqueStrings(values) {
        return [...new Set(values)];
    }
    assertSafeLocalPath(input) {
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
            throw new Error(`Local path is outside allowed local artifact roots: ${resolved}. Allowed roots: ${this.config.localArtifactRoots.join(", ")}`);
        }
        return resolved;
    }
    async safeAppRoot(client, root, notes) {
        try {
            assertSafePath(root, this.config);
            return await this.resolveExistingSafePath(client, root);
        }
        catch (error) {
            notes.push(`Skipped ${root}: ${error instanceof Error ? error.message : String(error)}`);
            return undefined;
        }
    }
    async scanBundleRoot(client, root, queryLower) {
        const matches = [];
        const candidatesScan = await this.scanBundleCandidates(client, root);
        let truncated = candidatesScan.truncated;
        let candidates = candidatesScan.candidates;
        if (queryLower) {
            const nameMatches = candidates.filter((candidate) => this.valuesMatchQuery(queryLower, [candidate.appEntryName, candidate.appName]));
            if (nameMatches.length > 0) {
                candidates = nameMatches;
            }
        }
        const parsedMatches = await this.mapLimit(candidates, APP_SCAN_CONCURRENCY, async (candidate) => {
            const match = await this.appBundleMatchFromCandidate(client, candidate);
            if (queryLower &&
                !this.valuesMatchQuery(queryLower, [
                    candidate.appEntryName,
                    match.appName,
                    match.bundleId,
                    match.displayName,
                    match.bundleName
                ])) {
                return undefined;
            }
            return match;
        });
        matches.push(...parsedMatches.filter((match) => Boolean(match)));
        return { matches, truncated };
    }
    async scanBundleCandidates(client, root) {
        const uuidEntries = await client.list(root);
        const uuidDirectories = uuidEntries
            .filter((entry) => this.mapEntryType(entry.type) === "directory")
            .slice(0, APP_CONTAINER_SCAN_LIMIT);
        const truncated = uuidEntries.length > uuidDirectories.length;
        const candidateGroups = await this.mapLimit(uuidDirectories, APP_SCAN_CONCURRENCY, async (uuidEntry) => {
            const uuidPath = this.assertCanonicalSafePath(joinRemote(root, uuidEntry.name));
            let appEntries;
            try {
                appEntries = await client.list(uuidPath);
            }
            catch {
                return [];
            }
            const candidates = [];
            for (const appEntry of appEntries) {
                if (this.mapEntryType(appEntry.type) !== "directory" || !appEntry.name.endsWith(".app")) {
                    continue;
                }
                const appPath = this.assertCanonicalSafePath(joinRemote(uuidPath, appEntry.name));
                candidates.push({
                    appName: appEntry.name.replace(/\.app$/i, ""),
                    appEntryName: appEntry.name,
                    path: appPath,
                    infoPlistPath: this.assertCanonicalSafePath(joinRemote(appPath, "Info.plist")),
                    containerUuid: uuidEntry.name
                });
            }
            return candidates;
        });
        return {
            candidates: candidateGroups.flat(),
            truncated
        };
    }
    async appBundleMatchFromCandidate(client, candidate) {
        const parsed = await this.tryReadPlistAt(client, candidate.infoPlistPath, APP_METADATA_READ_LIMIT);
        const plistObject = this.asRecord(parsed?.value);
        return {
            appName: candidate.appName,
            path: candidate.path,
            infoPlistPath: candidate.infoPlistPath,
            containerUuid: candidate.containerUuid,
            bundleId: this.stringValue(plistObject?.CFBundleIdentifier),
            displayName: this.stringValue(plistObject?.CFBundleDisplayName),
            bundleName: this.stringValue(plistObject?.CFBundleName),
            version: this.stringValue(plistObject?.CFBundleShortVersionString),
            build: this.stringValue(plistObject?.CFBundleVersion)
        };
    }
    async scanMetadataRoot(client, root, queryLower, bundleIds) {
        const entries = await client.list(root);
        const directories = entries
            .filter((entry) => this.mapEntryType(entry.type) === "directory")
            .slice(0, APP_CONTAINER_SCAN_LIMIT);
        const truncated = entries.length > directories.length;
        const matches = await this.mapLimit(directories, APP_SCAN_CONCURRENCY, async (entry) => {
            const containerPath = this.assertCanonicalSafePath(joinRemote(root, entry.name));
            const metadataPlistPath = this.assertCanonicalSafePath(joinRemote(containerPath, CONTAINER_METADATA_PLIST));
            const parsed = await this.tryReadPlistAt(client, metadataPlistPath, APP_METADATA_READ_LIMIT);
            if (!parsed) {
                return undefined;
            }
            const strings = this.collectStrings(parsed.value);
            const lowerStrings = strings.map((value) => value.toLowerCase());
            const matchedBy = [];
            if (lowerStrings.some((value) => value.includes(queryLower))) {
                matchedBy.push("query");
            }
            for (const bundleId of bundleIds) {
                if (lowerStrings.some((value) => value.includes(bundleId))) {
                    matchedBy.push(`bundleId:${bundleId}`);
                }
            }
            if (matchedBy.length === 0) {
                return undefined;
            }
            return {
                path: containerPath,
                metadataPlistPath,
                containerUuid: entry.name,
                identifiers: this.interestingIdentifiers(strings, queryLower, bundleIds),
                matchedBy
            };
        });
        return {
            matches: matches.filter((match) => Boolean(match)),
            truncated
        };
    }
    async readPlistAt(client, path, maxBytes) {
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
    async tryReadPlistAt(client, path, maxBytes) {
        try {
            return await this.readPlistAt(client, path, maxBytes);
        }
        catch {
            return undefined;
        }
    }
    async readRemoteBufferLimited(client, path, maxBytes) {
        const stat = await client.stat(path);
        const size = Number(stat.size ?? 0);
        if (size > maxBytes) {
            throw new Error(`File is ${size} bytes, which exceeds max read limit ${maxBytes}.`);
        }
        const content = await client.get(path);
        return this.bufferFromGetResult(content);
    }
    valuesMatchQuery(queryLower, values) {
        return values.some((value) => value?.toLowerCase().includes(queryLower));
    }
    rootDiagnosticNotes(roots) {
        const notes = [];
        const dataRoots = roots.filter((root) => root.path.endsWith("/Containers/Data/Application"));
        const bundleRoots = roots.filter((root) => root.path.endsWith("/containers/Bundle/Application"));
        const anyDataEntries = dataRoots.some((root) => (root.entryCount ?? 0) > 0);
        const anyBundleEntries = bundleRoots.some((root) => (root.entryCount ?? 0) > 0);
        if (!anyBundleEntries) {
            notes.push("No app bundle entries were visible. If the directories exist but are empty, try SSH/SFTP as root or check that the SSH service exposes the expected filesystem paths.");
        }
        if (!anyDataEntries) {
            notes.push("No app data container entries were visible. App data should normally appear under /var/mobile/Containers/Data/Application or /private/var/mobile/Containers/Data/Application.");
        }
        if (this.config.username === "mobile" && (!anyBundleEntries || !anyDataEntries)) {
            notes.push("The current SSH username is mobile. Some SSH setups require username root to browse all app bundle/container directories.");
        }
        return notes;
    }
    collectStrings(value) {
        const strings = new Set();
        const visit = (current) => {
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
    interestingIdentifiers(strings, queryLower, bundleIds) {
        const result = strings.filter((value) => {
            const lower = value.toLowerCase();
            return (lower.includes(queryLower) ||
                [...bundleIds].some((bundleId) => lower.includes(bundleId)) ||
                /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(value));
        });
        return [...new Set(result)].slice(0, 20);
    }
    asRecord(value) {
        if (!value || typeof value !== "object" || Array.isArray(value)) {
            return undefined;
        }
        return value;
    }
    stringValue(value) {
        return typeof value === "string" ? value : undefined;
    }
    toJsonSafe(value) {
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
            return Object.fromEntries(Object.entries(value).map(([key, nestedValue]) => [key, this.toJsonSafe(nestedValue)]));
        }
        return value;
    }
    uniqueByPath(items) {
        const seen = new Set();
        const unique = [];
        for (const item of items) {
            if (seen.has(item.path)) {
                continue;
            }
            seen.add(item.path);
            unique.push(item);
        }
        return unique;
    }
    async mapLimit(items, limit, mapper) {
        const results = new Array(items.length);
        let nextIndex = 0;
        const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
            while (nextIndex < items.length) {
                const currentIndex = nextIndex;
                nextIndex += 1;
                results[currentIndex] = await mapper(items[currentIndex], currentIndex);
            }
        });
        await Promise.all(workers);
        return results;
    }
    getAppFindCache(query) {
        const key = query.toLowerCase();
        const cached = this.appFindCache.get(key);
        if (!cached) {
            return undefined;
        }
        if (cached.expiresAt <= Date.now()) {
            this.appFindCache.delete(key);
            return undefined;
        }
        return cached.value;
    }
    setAppFindCache(query, value) {
        if (this.config.searchCacheTtlMs <= 0) {
            return;
        }
        this.appFindCache.set(query.toLowerCase(), {
            expiresAt: Date.now() + this.config.searchCacheTtlMs,
            value
        });
        if (this.appFindCache.size > 50) {
            const oldestKey = this.appFindCache.keys().next().value;
            if (oldestKey) {
                this.appFindCache.delete(oldestKey);
            }
        }
    }
    searchCacheKey(root, pattern, options) {
        return JSON.stringify({
            root,
            pattern,
            maxResults: options.maxResults,
            maxDepth: options.maxDepth,
            includeMetadata: options.includeMetadata
        });
    }
    getSearchCache(key) {
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
    setSearchCache(key, value) {
        if (this.config.searchCacheTtlMs <= 0) {
            return;
        }
        this.searchCache.set(key, {
            expiresAt: Date.now() + this.config.searchCacheTtlMs,
            value
        });
        if (this.searchCache.size > 100) {
            const oldestKey = this.searchCache.keys().next().value;
            if (oldestKey) {
                this.searchCache.delete(oldestKey);
            }
        }
    }
    searchNotes(root, pattern, maxDepth, maxResults) {
        const notes = [];
        const loweredRoot = root.toLowerCase();
        const loweredPattern = pattern.toLowerCase();
        if (loweredRoot.includes("/containers/bundle/application") ||
            loweredRoot.includes("/containers/data/application")) {
            notes.push("For installed apps, prefer ios_find_app(query) before recursive search.");
        }
        if (["youtube", "tiktok", "instagram", "snapchat", "google", "com."].some((hint) => loweredPattern.includes(hint))) {
            notes.push("This looks like an app lookup. ios_find_app(query) is faster and uses fewer tokens.");
        }
        notes.push(`Recursive search is capped at maxDepth=${maxDepth}, maxResults=${maxResults}, and searchMaxEntries=${this.config.searchMaxEntries}.`);
        return notes;
    }
    matcherFromPattern(pattern) {
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
    mapEntryType(type) {
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
    fileEntryFromClientInfo(entry) {
        return {
            name: entry.name,
            type: this.mapEntryType(entry.type),
            size: Number(entry.size ?? 0),
            modifyTime: this.dateFromMillis(entry.modifyTime),
            accessTime: this.dateFromMillis(entry.accessTime),
            rights: entry.rights,
            owner: entry.owner,
            group: entry.group
        };
    }
    mapStatsType(stat) {
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
    bufferFromGetResult(value) {
        if (Buffer.isBuffer(value)) {
            return value;
        }
        if (typeof value === "string") {
            return Buffer.from(value, "utf8");
        }
        throw new Error("Unexpected stream result while reading remote file.");
    }
    dateFromMillis(value) {
        if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
            return null;
        }
        return new Date(value).toISOString();
    }
    writeBufferToStream(stream, buffer) {
        return new Promise((resolve, reject) => {
            stream.once("error", reject);
            stream.once("finish", resolve);
            stream.end(buffer);
        });
    }
}
//# sourceMappingURL=sftpFileService.js.map