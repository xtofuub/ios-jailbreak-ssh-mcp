export type ServerConfig = {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKeyPath?: string;
  passphrase?: string;
  allowedRoots: string[];
  localArtifactRoots: string[];
  readOnly: boolean;
  allowWrites: boolean;
  maxReadSize: number;
  jsBundleMaxReadSize: number;
  sqliteMaxReadSize: number;
  hermesDecoderPreset: "auto" | "hermesc" | "hbc-decompiler" | "hbc-disassembler" | "hbctool" | "jsc2llvm" | "custom";
  hermesDecoderCommand?: string;
  hermesDecoderOutputLimit: number;
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
  frida?: {
    enabled: boolean;
    connectionMode?: "auto" | "ssh" | "usb";
    jailbreakType?: "auto" | "rootless" | "rootful";
    binaryPath?: string;
    traceDefaultDurationMs: number;
    maxSessionEvents: number;
    commandTimeoutMs: number;
  };
};

export type OperationLogEntry = {
  operation: string;
  input?: Record<string, unknown>;
  ok: boolean;
  error?: string;
  durationMs: number;
};
