import { createHash, randomUUID } from "node:crypto";
import type { ServerConfig } from "./types.js";

type ApprovalArgs = Record<string, unknown>;

type ApprovalRecord = {
  id: string;
  operation: string;
  key: string;
  summary: Record<string, unknown>;
  createdAt: number;
  expiresAt: number;
};

export class WriteApprovalRequiredError extends Error {
  constructor(readonly request: Record<string, unknown>) {
    super("Write approval required.");
    this.name = "WriteApprovalRequiredError";
  }
}

export class WriteApprovalManager {
  private readonly approvals = new Map<string, ApprovalRecord>();

  constructor(
    private readonly config: Pick<
      ServerConfig,
      "readOnly" | "allowWrites" | "requireWriteApproval" | "writeApprovalTtlMs"
    >
  ) {}

  requireApproval(operation: string, args: ApprovalArgs): void {
    if (this.config.readOnly && !this.config.allowWrites) {
      throw new Error(
        `${operation} is disabled. Set readOnly=false or allowWrites=true to enable write operations.`
      );
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
        throw new WriteApprovalRequiredError(
          this.createRequest(operation, argsWithoutApproval, "approvalId was not found or expired")
        );
      }

      if (record.key !== key) {
        throw new WriteApprovalRequiredError(
          this.createRequest(operation, argsWithoutApproval, "approvalId does not match this exact operation and arguments")
        );
      }

      this.approvals.delete(approvalId);
      return;
    }

    throw new WriteApprovalRequiredError(this.createRequest(operation, argsWithoutApproval));
  }

  private createRequest(
    operation: string,
    args: ApprovalArgs,
    reason = "missing approvalId"
  ): Record<string, unknown> {
    const now = Date.now();
    const record: ApprovalRecord = {
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

  private deleteExpired(): void {
    const now = Date.now();
    for (const [id, record] of this.approvals.entries()) {
      if (record.expiresAt <= now) {
        this.approvals.delete(id);
      }
    }
  }

  private requestKey(operation: string, args: ApprovalArgs): string {
    return createHash("sha256")
      .update(JSON.stringify({ operation, args: this.stableValue(args) }))
      .digest("hex");
  }

  private omitApprovalId(args: ApprovalArgs): ApprovalArgs {
    const { approvalId: _approvalId, ...rest } = args;
    return rest;
  }

  private summaryArgs(args: ApprovalArgs): Record<string, unknown> {
    const summary: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(args)) {
      if (key === "content" && typeof value === "string") {
        summary[key] = {
          bytes: Buffer.byteLength(value, "utf8"),
          sha256: createHash("sha256").update(value, "utf8").digest("hex")
        };
      } else {
        summary[key] = value;
      }
    }

    return summary;
  }

  private stableValue(value: unknown): unknown {
    if (Array.isArray(value)) {
      return value.map((item) => this.stableValue(item));
    }

    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([key, nestedValue]) => [key, this.stableValue(nestedValue)])
      );
    }

    return value;
  }
}
