import { createHash, randomUUID } from "node:crypto";
export class WriteApprovalRequiredError extends Error {
    request;
    constructor(request) {
        super("Write approval required.");
        this.request = request;
        this.name = "WriteApprovalRequiredError";
    }
}
export class WriteApprovalManager {
    config;
    approvals = new Map();
    constructor(config) {
        this.config = config;
    }
    requireApproval(operation, args) {
        if (this.config.readOnly || !this.config.allowWrites) {
            throw new Error(`${operation} is disabled. Set readOnly=false and allowWrites=true to enable write operations.`);
        }
        if (!this.config.requireWriteApproval) {
            return;
        }
        this.deleteExpired();
        const approvalId = typeof args.approvalId === "string" ? args.approvalId : undefined;
        const argsWithoutApproval = this.omitApprovalId(args);
        const key = this.requestKey(operation, argsWithoutApproval);
        if (approvalId) {
            const record = this.approvals.get(approvalId);
            if (!record) {
                throw new WriteApprovalRequiredError(this.createRequest(operation, argsWithoutApproval, "approvalId was not found or expired"));
            }
            if (record.key !== key) {
                throw new WriteApprovalRequiredError(this.createRequest(operation, argsWithoutApproval, "approvalId does not match this exact operation and arguments"));
            }
            this.approvals.delete(approvalId);
            return;
        }
        throw new WriteApprovalRequiredError(this.createRequest(operation, argsWithoutApproval));
    }
    createRequest(operation, args, reason = "missing approvalId") {
        const now = Date.now();
        const record = {
            id: randomUUID(),
            operation,
            key: this.requestKey(operation, args),
            summary: this.summaryArgs(args),
            createdAt: now,
            expiresAt: now + this.config.writeApprovalTtlMs
        };
        this.approvals.set(record.id, record);
        return {
            approvalRequired: true,
            reason,
            approvalId: record.id,
            operation,
            expiresAt: new Date(record.expiresAt).toISOString(),
            summary: record.summary,
            nextStep: `Ask the user to approve this ${operation} request. If approved, call ${operation} again with the same arguments plus approvalId.`
        };
    }
    deleteExpired() {
        const now = Date.now();
        for (const [id, record] of this.approvals.entries()) {
            if (record.expiresAt <= now) {
                this.approvals.delete(id);
            }
        }
    }
    requestKey(operation, args) {
        return createHash("sha256")
            .update(JSON.stringify({ operation, args: this.stableValue(args) }))
            .digest("hex");
    }
    omitApprovalId(args) {
        const { approvalId: _approvalId, ...rest } = args;
        return rest;
    }
    summaryArgs(args) {
        const summary = {};
        for (const [key, value] of Object.entries(args)) {
            if (key === "content" && typeof value === "string") {
                summary[key] = {
                    bytes: Buffer.byteLength(value, "utf8"),
                    sha256: createHash("sha256").update(value, "utf8").digest("hex")
                };
            }
            else {
                summary[key] = value;
            }
        }
        return summary;
    }
    stableValue(value) {
        if (Array.isArray(value)) {
            return value.map((item) => this.stableValue(item));
        }
        if (value && typeof value === "object") {
            return Object.fromEntries(Object.entries(value)
                .sort(([left], [right]) => left.localeCompare(right))
                .map(([key, nestedValue]) => [key, this.stableValue(nestedValue)]));
        }
        return value;
    }
}
//# sourceMappingURL=writeApproval.js.map