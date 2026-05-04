export type ServerConfig = {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKeyPath?: string;
  passphrase?: string;
  allowedRoots: string[];
  readOnly: boolean;
  allowWrites: boolean;
  maxReadSize: number;
  searchCacheTtlMs: number;
  searchDefaultMaxResults: number;
  searchDefaultMaxDepth: number;
  searchMaxEntries: number;
  backupBeforeWrite: boolean;
  requireWriteApproval: boolean;
  writeApprovalTtlMs: number;
  connectTimeoutMs: number;
  readyTimeoutMs: number;
  logPath: string;
};

export type OperationLogEntry = {
  operation: string;
  input?: Record<string, unknown>;
  ok: boolean;
  error?: string;
  durationMs: number;
};
