import type { R2Runner } from "./r2Runner.js";
import { ProcessRunnerError } from "./r2Runner.js";
export type R2InfoSummary = {
    arch?: string;
    bits?: number;
    format?: string;
    class?: string;
    type?: string;
    os?: string;
    machine?: string;
    bintype?: string;
    lang?: string;
    compiler?: string;
    stripped?: boolean;
    encrypted?: boolean;
    pic?: boolean;
    nx?: boolean;
    canary?: boolean;
    relocs?: boolean;
    size?: number;
    baseAddress?: string;
};
export type R2Import = {
    name: string;
    library?: string;
    type?: string;
    bind?: string;
    address?: string;
};
export type R2String = {
    string: string;
    address?: string;
    section?: string;
    type?: string;
    length?: number;
};
export type R2Function = {
    name: string;
    address?: string;
    size?: number;
    basicBlocks?: number;
    complexity?: number;
    type?: string;
};
export type R2DisasmOperation = {
    address?: string;
    opcode?: string;
    disasm?: string;
    type?: string;
    jump?: string;
    fail?: string;
    comment?: string;
};
export type R2SuggestedAction = {
    tool: string;
    reason: string;
    exampleArgs: Record<string, unknown>;
};
export type R2RunnerCheck = {
    available: boolean;
    version?: string;
    error?: string;
};
export type R2CheckResult = {
    enabled: boolean;
    mode: "auto" | "device" | "local";
    activeRunner: "device" | "local" | "none";
    r2: R2RunnerCheck;
    rabin2: R2RunnerCheck;
    device?: {
        r2Path: string;
        rabin2Path: string;
        r2: R2RunnerCheck;
        rabin2: R2RunnerCheck;
    };
    local?: {
        r2Path: string;
        rabin2Path: string;
        r2: R2RunnerCheck;
        rabin2: R2RunnerCheck;
    };
    notes: string[];
};
export type RadareServiceOptions = {
    timeoutMs: number;
    maxOutputBytes: number;
};
export declare class RadareService {
    private readonly runner;
    private readonly opts;
    constructor(runner: R2Runner, opts: RadareServiceOptions);
    get mode(): "device" | "local";
    get r2Path(): string;
    get rabin2Path(): string;
    binaryInfo(argvPath: string): Promise<{
        info: R2InfoSummary;
        linkedLibraries: string[];
        notes: string[];
    }>;
    imports(argvPath: string, query?: string, limit?: number): Promise<{
        query?: string;
        imports: R2Import[];
        returned: number;
        limit: number;
    }>;
    strings(argvPath: string, query?: string, limit?: number): Promise<{
        query?: string;
        strings: R2String[];
        returned: number;
        limit: number;
    }>;
    functions(argvPath: string, limit?: number): Promise<{
        functions: R2Function[];
        returned: number;
        limit: number;
    }>;
    functionDisasm(argvPath: string, functionNameOrAddress: string): Promise<{
        functionNameOrAddress: string;
        resolvedAddress: string;
        name?: string;
        size?: number;
        ops: R2DisasmOperation[];
        opCount: number;
    }>;
    appTriage(input: {
        bundleId: string;
        argvPath: string;
        remoteBinaryPath: string;
    }): Promise<{
        bundleId: string;
        remoteBinaryPath: string;
        info: R2InfoSummary;
        linkedLibraries: string[];
        interestingImports: R2Import[];
        interestingStrings: R2String[];
        functionsPreview: R2Function[];
        limits: {
            stringsReturned: number;
            importsReturned: number;
            functionsReturned: number;
        };
        notes: string[];
        suggestedNextActions: R2SuggestedAction[];
    }>;
    private execOpts;
    private readInfo;
    private readLinkedLibraries;
    private readImports;
    private readStrings;
    private readFunctions;
    private rabinJson;
    private r2Json;
    private parseJsonOutput;
    private resolveFunctionTarget;
    private normalizeImport;
    private normalizeString;
    private normalizeFunction;
    private normalizeOperation;
    private interestingImports;
    private interestingStrings;
    private suggestedNextActions;
    private triageNotes;
    private analysisNotes;
    private normalizeLimit;
    private filterItems;
    private matchesAny;
    private parseAddress;
    private addressValue;
    private encryptedValue;
    private stringValue;
    private numberValue;
    private booleanValue;
    private asRecord;
    private arrayValue;
}
export { ProcessRunnerError };
