import { ProcessRunnerError, runProcess } from "./processRunner.js";
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;
const INTERESTING_IMPORT_QUERIES = [
    "Security",
    "SecItem",
    "SecKey",
    "SecTrust",
    "SecRandom",
    "CommonCrypto",
    "CCCrypt",
    "CryptoKit",
    "NSURLSession",
    "URLSession",
    "CFNetwork",
    "Network",
    "SQLite",
    "sqlite",
    "WKWebView",
    "WebKit",
    "LAContext",
    "ptrace",
    "sysctl",
    "dlopen",
    "dlsym",
    "fork",
    "kill"
];
const INTERESTING_STRING_QUERIES = [
    "http",
    "api",
    "firebase",
    "token",
    "auth",
    "key",
    "secret",
    "password",
    "bearer",
    "graphql",
    "debug",
    "feature",
    "flag",
    "SecItem",
    "CommonCrypto",
    "CryptoKit",
    "sqlite",
    "WKWebView"
];
export class RadareService {
    config;
    constructor(config) {
        this.config = config;
    }
    async check() {
        const [r2, rabin2] = await Promise.all([
            this.checkCommand(this.config.r2Path, ["-v"]),
            this.checkCommand(this.config.rabin2Path, ["-v"])
        ]);
        const notes = [];
        if (!this.config.enabled) {
            notes.push("radare2 tools are disabled. Set IOS_FILES_MCP_ENABLE_R2=true to enable them.");
        }
        if (!r2.available || !rabin2.available) {
            notes.push("Install radare2 locally and make r2/rabin2 available on PATH, or set IOS_FILES_MCP_R2_PATH and IOS_FILES_MCP_RABIN2_PATH.");
        }
        return {
            enabled: this.config.enabled,
            r2Path: this.config.r2Path,
            rabin2Path: this.config.rabin2Path,
            r2,
            rabin2,
            notes
        };
    }
    async binaryInfo(localPath) {
        const [info, linkedLibraries] = await Promise.all([
            this.readInfo(localPath),
            this.readLinkedLibraries(localPath)
        ]);
        return {
            info,
            linkedLibraries,
            notes: this.analysisNotes(info)
        };
    }
    async imports(localPath, query, limit) {
        const normalizedLimit = this.normalizeLimit(limit);
        const imports = await this.readImports(localPath);
        const filtered = this.filterItems(imports, query, (item) => [
            item.name,
            item.library,
            item.type,
            item.bind
        ]);
        return {
            query,
            imports: filtered.slice(0, normalizedLimit),
            returned: Math.min(filtered.length, normalizedLimit),
            limit: normalizedLimit
        };
    }
    async strings(localPath, query, limit) {
        const normalizedLimit = this.normalizeLimit(limit);
        const strings = await this.readStrings(localPath);
        const filtered = this.filterItems(strings, query, (item) => [
            item.string,
            item.section,
            item.type
        ]);
        return {
            query,
            strings: filtered.slice(0, normalizedLimit),
            returned: Math.min(filtered.length, normalizedLimit),
            limit: normalizedLimit
        };
    }
    async functions(localPath, limit) {
        const normalizedLimit = this.normalizeLimit(limit);
        const functions = await this.readFunctions(localPath);
        return {
            functions: functions.slice(0, normalizedLimit),
            returned: Math.min(functions.length, normalizedLimit),
            limit: normalizedLimit
        };
    }
    async functionDisasm(localPath, functionNameOrAddress) {
        const target = functionNameOrAddress.trim();
        if (!target) {
            throw new Error("functionNameOrAddress must be non-empty.");
        }
        const resolved = await this.resolveFunctionTarget(localPath, target);
        const json = await this.r2Json(localPath, ["-q", "-2", "-c", "aaa", "-c", `s ${resolved.address}`, "-c", "pdfj", "-c", "q"]);
        const record = this.asRecord(json) ?? {};
        const ops = this.arrayValue(record.ops)
            .map((item) => this.normalizeOperation(item))
            .filter((item) => Boolean(item));
        return {
            functionNameOrAddress,
            resolvedAddress: resolved.address,
            name: resolved.name ?? this.stringValue(record.name),
            size: this.numberValue(record.size),
            ops,
            opCount: ops.length
        };
    }
    async appTriage(input) {
        const [info, linkedLibraries, imports, strings, functions] = await Promise.all([
            this.readInfo(input.localPath),
            this.readLinkedLibraries(input.localPath),
            this.readImports(input.localPath),
            this.readStrings(input.localPath),
            this.readFunctions(input.localPath)
        ]);
        const interestingImports = this.interestingImports(imports).slice(0, DEFAULT_LIMIT);
        const interestingStrings = this.interestingStrings(strings).slice(0, DEFAULT_LIMIT);
        const functionsPreview = functions.slice(0, DEFAULT_LIMIT);
        return {
            bundleId: input.bundleId,
            remoteBinaryPath: input.remoteBinaryPath,
            info,
            linkedLibraries,
            interestingImports,
            interestingStrings,
            functionsPreview,
            limits: {
                stringsReturned: interestingStrings.length,
                importsReturned: interestingImports.length,
                functionsReturned: functionsPreview.length
            },
            notes: this.triageNotes(info, functions),
            suggestedNextActions: this.suggestedNextActions(input.remoteBinaryPath, {
                interestingImports,
                interestingStrings,
                functions
            })
        };
    }
    async checkCommand(command, args) {
        try {
            const result = await runProcess(command, args, {
                timeoutMs: Math.min(this.config.timeoutMs, 10_000),
                maxOutputBytes: 16 * 1024,
                allowNonZero: false
            });
            const version = (result.stdout || result.stderr).split(/\r?\n/).find(Boolean)?.trim();
            return { available: true, version };
        }
        catch (error) {
            return {
                available: false,
                error: error instanceof Error ? error.message : String(error)
            };
        }
    }
    async readInfo(localPath) {
        const json = await this.rabinJson(["-Ij", localPath]);
        const record = this.asRecord(json) ?? {};
        const bin = this.asRecord(record.bin) ?? record;
        return {
            arch: this.stringValue(bin.arch),
            bits: this.numberValue(bin.bits),
            format: this.stringValue(bin.format),
            class: this.stringValue(bin.class),
            type: this.stringValue(bin.type),
            os: this.stringValue(bin.os),
            machine: this.stringValue(bin.machine),
            bintype: this.stringValue(bin.bintype),
            lang: this.stringValue(bin.lang),
            compiler: this.stringValue(bin.compiler),
            stripped: this.booleanValue(bin.stripped),
            encrypted: this.encryptedValue(bin),
            pic: this.booleanValue(bin.pic),
            nx: this.booleanValue(bin.nx),
            canary: this.booleanValue(bin.canary),
            relocs: this.booleanValue(bin.relocs),
            size: this.numberValue(bin.binsz) ?? this.numberValue(bin.size),
            baseAddress: this.addressValue(bin.baddr)
        };
    }
    async readLinkedLibraries(localPath) {
        const json = await this.rabinJson(["-lj", localPath]);
        const items = this.arrayValue(json);
        return items
            .map((item) => {
            if (typeof item === "string") {
                return item;
            }
            const record = this.asRecord(item);
            return record ? this.stringValue(record.name) ?? this.stringValue(record.lib) : undefined;
        })
            .filter((item) => Boolean(item));
    }
    async readImports(localPath) {
        const json = await this.rabinJson(["-ij", localPath]);
        return this.arrayValue(json)
            .map((item) => this.normalizeImport(item))
            .filter((item) => Boolean(item));
    }
    async readStrings(localPath) {
        const json = await this.rabinJson(["-zzj", localPath]);
        return this.arrayValue(json)
            .map((item) => this.normalizeString(item))
            .filter((item) => Boolean(item));
    }
    async readFunctions(localPath) {
        const json = await this.r2Json(localPath, ["-q", "-2", "-c", "aaa", "-c", "aflj", "-c", "q"]);
        return this.arrayValue(json)
            .map((item) => this.normalizeFunction(item))
            .filter((item) => Boolean(item));
    }
    async rabinJson(args) {
        this.assertEnabled();
        const result = await runProcess(this.config.rabin2Path, args, {
            timeoutMs: this.config.timeoutMs,
            maxOutputBytes: this.config.maxOutputBytes,
            allowNonZero: false
        });
        return this.parseJsonOutput(result.stdout, "rabin2");
    }
    async r2Json(localPath, args) {
        this.assertEnabled();
        const result = await runProcess(this.config.r2Path, [...args, localPath], {
            timeoutMs: this.config.timeoutMs,
            maxOutputBytes: this.config.maxOutputBytes,
            allowNonZero: false
        });
        return this.parseJsonOutput(result.stdout, "r2");
    }
    parseJsonOutput(stdout, command) {
        const trimmed = stdout.trim();
        if (!trimmed) {
            return [];
        }
        try {
            return JSON.parse(trimmed);
        }
        catch (error) {
            if (error instanceof SyntaxError) {
                throw new Error(`${command} did not return valid JSON. Check that radare2 supports the requested JSON mode.`);
            }
            throw error;
        }
    }
    async resolveFunctionTarget(localPath, target) {
        const directAddress = this.parseAddress(target);
        if (directAddress) {
            return { address: directAddress };
        }
        if (/[\r\n;]/.test(target)) {
            throw new Error("Function names cannot contain r2 command separators. Pass the address from ios_r2_functions instead.");
        }
        const functions = await this.readFunctions(localPath);
        const exact = functions.find((item) => item.name === target);
        const loose = exact ?? functions.find((item) => item.name.toLowerCase() === target.toLowerCase());
        if (!loose?.address) {
            throw new Error("Function was not found by name. Run ios_r2_functions and pass the exact address.");
        }
        return {
            address: loose.address,
            name: loose.name
        };
    }
    normalizeImport(item) {
        const record = this.asRecord(item);
        if (!record) {
            return undefined;
        }
        const name = this.stringValue(record.name) ??
            this.stringValue(record.impname) ??
            this.stringValue(record.demname) ??
            this.stringValue(record.realname);
        if (!name) {
            return undefined;
        }
        return {
            name,
            library: this.stringValue(record.lib) ?? this.stringValue(record.library),
            type: this.stringValue(record.type),
            bind: this.stringValue(record.bind),
            address: this.addressValue(record.vaddr) ?? this.addressValue(record.plt)
        };
    }
    normalizeString(item) {
        const record = this.asRecord(item);
        if (!record) {
            return undefined;
        }
        const value = this.stringValue(record.string) ?? this.stringValue(record.name);
        if (!value) {
            return undefined;
        }
        return {
            string: value,
            address: this.addressValue(record.vaddr) ?? this.addressValue(record.paddr),
            section: this.stringValue(record.section),
            type: this.stringValue(record.type),
            length: this.numberValue(record.length) ?? this.numberValue(record.size)
        };
    }
    normalizeFunction(item) {
        const record = this.asRecord(item);
        if (!record) {
            return undefined;
        }
        const name = this.stringValue(record.name);
        if (!name) {
            return undefined;
        }
        return {
            name,
            address: this.addressValue(record.offset) ?? this.addressValue(record.addr),
            size: this.numberValue(record.size),
            basicBlocks: this.numberValue(record.nbbs),
            complexity: this.numberValue(record.cc),
            type: this.stringValue(record.type)
        };
    }
    normalizeOperation(item) {
        const record = this.asRecord(item);
        if (!record) {
            return undefined;
        }
        return {
            address: this.addressValue(record.offset),
            opcode: this.stringValue(record.opcode),
            disasm: this.stringValue(record.disasm),
            type: this.stringValue(record.type),
            jump: this.addressValue(record.jump),
            fail: this.addressValue(record.fail),
            comment: this.stringValue(record.comment)
        };
    }
    interestingImports(imports) {
        return imports.filter((item) => this.matchesAny([item.name, item.library, item.type], INTERESTING_IMPORT_QUERIES));
    }
    interestingStrings(strings) {
        return strings.filter((item) => this.matchesAny([item.string, item.section, item.type], INTERESTING_STRING_QUERIES));
    }
    suggestedNextActions(remotePath, findings) {
        const actions = [];
        actions.push({
            tool: "ios_r2_strings",
            reason: findings.interestingStrings.length > 0
                ? "Narrow the string search around URLs, API paths, tokens, Firebase, auth, or debug text."
                : "Search for URLs, API paths, Firebase config, tokens, auth text, and debug strings.",
            exampleArgs: {
                remotePath,
                query: findings.interestingStrings.some((item) => item.string.toLowerCase().includes("http")) ? "http" : "api",
                limit: 50
            }
        });
        actions.push({
            tool: "ios_r2_imports",
            reason: findings.interestingImports.length > 0
                ? "Check related framework/API imports before choosing functions to inspect."
                : "Check whether the app uses Keychain, crypto, networking, SQLite, WebKit, or anti-debug APIs.",
            exampleArgs: {
                remotePath,
                query: findings.interestingImports.some((item) => item.name.includes("SecItem")) ? "SecItem" : "NSURLSession",
                limit: 50
            }
        });
        if (findings.interestingImports.length > 0 || findings.functions.length > DEFAULT_LIMIT) {
            actions.push({
                tool: "ios_r2_functions",
                reason: findings.interestingImports.length > 0
                    ? "Map nearby or related function names before selecting one import-related function to disassemble."
                    : "The binary has many functions. Review and filter function names before selecting one to disassemble.",
                exampleArgs: {
                    remotePath,
                    limit: 100
                }
            });
        }
        const firstFunction = findings.functions.find((item) => item.address);
        if (firstFunction?.address) {
            actions.push({
                tool: "ios_r2_function_disasm",
                reason: "Disassemble one selected function only after choosing an interesting function or address.",
                exampleArgs: {
                    remotePath,
                    functionNameOrAddress: firstFunction.address
                }
            });
        }
        return actions;
    }
    triageNotes(info, functions) {
        const notes = this.analysisNotes(info);
        if (functions.length > DEFAULT_LIMIT) {
            notes.push("Many functions were found. Use ios_r2_functions with a focused limit before disassembling.");
        }
        return notes;
    }
    analysisNotes(info) {
        const notes = [];
        if (info.encrypted) {
            notes.push("The binary appears encrypted. Static analysis may be limited; use an authorized decrypted or test build.");
        }
        if (info.stripped) {
            notes.push("The binary appears stripped. Symbols may be limited, so strings and imports are more useful.");
        }
        return notes;
    }
    normalizeLimit(limit) {
        return Math.min(Math.max(limit ?? DEFAULT_LIMIT, 1), MAX_LIMIT);
    }
    filterItems(items, query, values) {
        const normalized = query?.trim().toLowerCase();
        if (!normalized) {
            return items;
        }
        return items.filter((item) => values(item).some((value) => value?.toLowerCase().includes(normalized)));
    }
    matchesAny(values, queries) {
        const haystack = values.filter(Boolean).join("\n").toLowerCase();
        return queries.some((query) => haystack.includes(query.toLowerCase()));
    }
    parseAddress(value) {
        const trimmed = value.trim();
        if (/^0x[0-9a-f]+$/i.test(trimmed)) {
            return trimmed.toLowerCase();
        }
        if (/^[0-9]+$/.test(trimmed)) {
            return `0x${Number(trimmed).toString(16)}`;
        }
        return undefined;
    }
    addressValue(value) {
        if (typeof value === "number" && Number.isFinite(value)) {
            return `0x${Math.trunc(value).toString(16)}`;
        }
        if (typeof value === "string" && value.trim() !== "") {
            return this.parseAddress(value) ?? value;
        }
        return undefined;
    }
    encryptedValue(record) {
        const cryptid = this.numberValue(record.cryptid) ?? this.numberValue(record.crypt);
        if (cryptid !== undefined) {
            return cryptid !== 0;
        }
        return this.booleanValue(record.encrypted);
    }
    stringValue(value) {
        return typeof value === "string" ? value : undefined;
    }
    numberValue(value) {
        if (typeof value === "number" && Number.isFinite(value)) {
            return value;
        }
        if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) {
            return Number(value);
        }
        return undefined;
    }
    booleanValue(value) {
        if (typeof value === "boolean") {
            return value;
        }
        if (typeof value === "number") {
            return value !== 0;
        }
        if (typeof value === "string") {
            if (["true", "yes", "1"].includes(value.toLowerCase())) {
                return true;
            }
            if (["false", "no", "0"].includes(value.toLowerCase())) {
                return false;
            }
        }
        return undefined;
    }
    asRecord(value) {
        if (!value || typeof value !== "object" || Array.isArray(value)) {
            return undefined;
        }
        return value;
    }
    arrayValue(value) {
        if (Array.isArray(value)) {
            return value;
        }
        const record = this.asRecord(value);
        if (!record) {
            return [];
        }
        for (const key of ["imports", "strings", "libs", "functions", "symbols"]) {
            const nested = record[key];
            if (Array.isArray(nested)) {
                return nested;
            }
        }
        return [];
    }
    assertEnabled() {
        if (!this.config.enabled) {
            throw new Error("radare2 tools are disabled. Set IOS_FILES_MCP_ENABLE_R2=true in the MCP env block.");
        }
    }
}
export { ProcessRunnerError };
//# sourceMappingURL=radareService.js.map