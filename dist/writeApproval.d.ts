import type { ServerConfig } from "./types.js";
type ApprovalArgs = Record<string, unknown>;
export declare class WriteApprovalRequiredError extends Error {
    readonly request: Record<string, unknown>;
    constructor(request: Record<string, unknown>);
}
export declare class WriteApprovalManager {
    private readonly config;
    private readonly approvals;
    constructor(config: Pick<ServerConfig, "readOnly" | "allowWrites" | "requireWriteApproval" | "writeApprovalTtlMs">);
    requireApproval(operation: string, args: ApprovalArgs): void;
    private createRequest;
    private deleteExpired;
    private requestKey;
    private omitApprovalId;
    private summaryArgs;
    private stableValue;
}
export {};
