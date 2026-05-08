import { ProcessRunnerError } from "./processRunner.js";
import type { ServerConfig } from "./types.js";
type R2Config = ServerConfig["r2"];
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
export type R2CheckResult = {
    enabled: boolean;
    r2Path: string;
    rabin2Path: string;
    r2: CommandCheck;
    rabin2: CommandCheck;
    notes: string[];
};
type CommandCheck = {
    available: boolean;
    version?: string;
    error?: string;
};
export declare class RadareService {
    private readonly config;
    constructor(config: R2Config);
    check(): Promise<R2CheckResult>;
    binaryInfo(localPath: string): Promise<{
        info: R2InfoSummary;
        linkedLibraries: string[];
        notes: string[];
    }>;
    imports(localPath: string, query?: string, limit?: number): Promise<{
        query?: string;
        imports: R2Import[];
        returned: number;
        limit: number;
    }>;
    strings(localPath: string, query?: string, limit?: number): Promise<{
        query?: string;
        strings: R2String[];
        returned: number;
        limit: number;
    }>;
    functions(localPath: string, limit?: number): Promise<{
        functions: R2Function[];
        returned: number;
        limit: number;
    }>;
    functionDisasm(localPath: string, functionNameOrAddress: string): Promise<{
        functionNameOrAddress: string;
        resolvedAddress: string;
        name?: string;
        size?: number;
        ops: R2DisasmOperation[];
        opCount: number;
    }>;
    appTriage(input: {
        bundleId: string;
        localPath: string;
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
    private checkCommand;
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
    private assertEnabled;
}
export { ProcessRunnerError };
