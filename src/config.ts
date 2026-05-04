import { constants } from "node:fs";
import { access, readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { assertAllowedRootConfig, DEFAULT_ALLOWED_ROOTS } from "./pathSafety.js";
import type { ServerConfig } from "./types.js";

const ONE_MIB = 1024 * 1024;
const FIVE_MINUTES_MS = 5 * 60 * 1000;
const TWO_MINUTES_MS = 2 * 60 * 1000;

const rawConfigSchema = z
  .object({
    host: z.string().min(1).optional(),
    port: z.coerce.number().int().min(1).max(65535).optional(),
    username: z.string().min(1).optional(),
    password: z.string().optional().nullable(),
    privateKeyPath: z.string().min(1).optional().nullable(),
    passphrase: z.string().optional().nullable(),
    allowedRoots: z.array(z.string().min(1)).optional(),
    readOnly: z.boolean().optional(),
    allowWrites: z.boolean().optional(),
    maxReadSize: z.coerce.number().int().positive().optional(),
    searchCacheTtlMs: z.coerce.number().int().nonnegative().optional(),
    searchDefaultMaxResults: z.coerce.number().int().positive().optional(),
    searchDefaultMaxDepth: z.coerce.number().int().nonnegative().optional(),
    searchMaxEntries: z.coerce.number().int().positive().optional(),
    backupBeforeWrite: z.boolean().optional(),
    requireWriteApproval: z.boolean().optional(),
    writeApprovalTtlMs: z.coerce.number().int().positive().optional(),
    connectTimeoutMs: z.coerce.number().int().positive().optional(),
    readyTimeoutMs: z.coerce.number().int().positive().optional(),
    logPath: z.string().min(1).optional()
  })
  .strict();

type RawConfig = z.infer<typeof rawConfigSchema>;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export function getConfigPathFromArgs(argv = process.argv.slice(2)): string | undefined {
  const configFlagIndex = argv.findIndex((arg) => arg === "--config" || arg === "-c");
  if (configFlagIndex >= 0) {
    return argv[configFlagIndex + 1];
  }

  const inlineConfig = argv.find((arg) => arg.startsWith("--config="));
  if (inlineConfig) {
    return inlineConfig.slice("--config=".length);
  }

  return process.env.IOS_FILES_MCP_CONFIG;
}

export function hasHelpFlag(argv = process.argv.slice(2)): boolean {
  return argv.includes("--help") || argv.includes("-h");
}

export function helpText(): string {
  return [
    "ios-jailbreak-ssh-mcp",
    "",
    "Usage:",
    "  ios-jailbreak-ssh-mcp --config /path/to/ios-files-mcp.config.json",
    "  IOS_FILES_MCP_HOST=192.168.1.23 ios-jailbreak-ssh-mcp",
    "",
    "Required:",
    "  host via config file or IOS_FILES_MCP_HOST",
    "",
    "Safety:",
    "  The server is read-only by default. Writes require readOnly=false and allowWrites=true."
  ].join("\n");
}

type LoadedJsonConfig = {
  path?: string;
  baseDir: string;
  data: RawConfig;
};

async function discoverDefaultConfigPath(): Promise<string | undefined> {
  const moduleDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(process.cwd(), "ios-files-mcp.config.json"),
    resolve(moduleDir, "..", "ios-files-mcp.config.json")
  ];

  for (const candidate of [...new Set(candidates)]) {
    try {
      await access(candidate, constants.R_OK);
      return candidate;
    } catch {
      // Keep looking.
    }
  }

  return undefined;
}

async function loadJsonConfig(path: string | undefined): Promise<LoadedJsonConfig> {
  if (!path) {
    return {
      baseDir: process.cwd(),
      data: {}
    };
  }

  const absolutePath = resolve(path);
  const content = await readFile(absolutePath, "utf8");
  const parsed = JSON.parse(content) as unknown;
  const result = rawConfigSchema.safeParse(parsed);

  if (!result.success) {
    throw new ConfigError(
      `Invalid config file ${absolutePath}: ${result.error.issues
        .map((issue) => `${issue.path.join(".") || "root"} ${issue.message}`)
        .join("; ")}`
    );
  }

  return {
    path: absolutePath,
    baseDir: dirname(absolutePath),
    data: result.data
  };
}

function readBooleanEnv(name: string): boolean | undefined {
  const value = process.env[name];
  if (value === undefined) {
    return undefined;
  }

  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }

  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  throw new ConfigError(`${name} must be a boolean value.`);
}

function readNumberEnv(name: string): number | undefined {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    return undefined;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new ConfigError(`${name} must be a number.`);
  }

  return parsed;
}

function envConfig(): RawConfig {
  const allowedRoots = process.env.IOS_FILES_MCP_ALLOWED_ROOTS
    ?.split(",")
    .map((root) => root.trim())
    .filter(Boolean);

  return {
    host: process.env.IOS_FILES_MCP_HOST,
    port: readNumberEnv("IOS_FILES_MCP_PORT"),
    username: process.env.IOS_FILES_MCP_USERNAME,
    password: process.env.IOS_FILES_MCP_PASSWORD,
    privateKeyPath: process.env.IOS_FILES_MCP_KEY_PATH,
    passphrase: process.env.IOS_FILES_MCP_KEY_PASSPHRASE,
    allowedRoots,
    readOnly: readBooleanEnv("IOS_FILES_MCP_READ_ONLY"),
    allowWrites: readBooleanEnv("IOS_FILES_MCP_ALLOW_WRITES"),
    maxReadSize: readNumberEnv("IOS_FILES_MCP_MAX_READ_SIZE"),
    searchCacheTtlMs: readNumberEnv("IOS_FILES_MCP_SEARCH_CACHE_TTL_MS"),
    searchDefaultMaxResults: readNumberEnv("IOS_FILES_MCP_SEARCH_DEFAULT_MAX_RESULTS"),
    searchDefaultMaxDepth: readNumberEnv("IOS_FILES_MCP_SEARCH_DEFAULT_MAX_DEPTH"),
    searchMaxEntries: readNumberEnv("IOS_FILES_MCP_SEARCH_MAX_ENTRIES"),
    backupBeforeWrite: readBooleanEnv("IOS_FILES_MCP_BACKUP_BEFORE_WRITE"),
    requireWriteApproval: readBooleanEnv("IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL"),
    writeApprovalTtlMs: readNumberEnv("IOS_FILES_MCP_WRITE_APPROVAL_TTL_MS"),
    connectTimeoutMs: readNumberEnv("IOS_FILES_MCP_CONNECT_TIMEOUT_MS"),
    readyTimeoutMs: readNumberEnv("IOS_FILES_MCP_READY_TIMEOUT_MS"),
    logPath: process.env.IOS_FILES_MCP_LOG
  };
}

function pruneUndefined<T extends Record<string, unknown>>(input: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(input).filter(([, value]) => value !== undefined)
  ) as Partial<T>;
}

function resolveFromBase(path: string, baseDir: string): string {
  return isAbsolute(path) ? path : resolve(baseDir, path);
}

export async function loadConfig(): Promise<ServerConfig> {
  const configPath = getConfigPathFromArgs() ?? (await discoverDefaultConfigPath());
  const loadedConfig = await loadJsonConfig(configPath);
  const fileConfig = loadedConfig.data;
  const envOverrides = pruneUndefined(envConfig());
  const merged = {
    ...fileConfig,
    ...envOverrides
  };

  const host = merged.host;
  if (!host) {
    throw new ConfigError(
      "Missing iPhone host. Set host in ios-files-mcp.config.json, pass --config, set IOS_FILES_MCP_CONFIG, or set IOS_FILES_MCP_HOST."
    );
  }

  if (!merged.password && !merged.privateKeyPath) {
    throw new ConfigError(
      "Missing SSH credential. Set password or privateKeyPath in config, or IOS_FILES_MCP_PASSWORD / IOS_FILES_MCP_KEY_PATH."
    );
  }

  const allowedRoots = assertAllowedRootConfig(
    merged.allowedRoots ?? [...DEFAULT_ALLOWED_ROOTS]
  );

  return {
    host,
    port: merged.port ?? 22,
    username: merged.username ?? "mobile",
    password: merged.password ?? undefined,
    privateKeyPath: envOverrides.privateKeyPath
      ? resolve(envOverrides.privateKeyPath)
      : fileConfig.privateKeyPath
        ? resolveFromBase(fileConfig.privateKeyPath, loadedConfig.baseDir)
        : undefined,
    passphrase: merged.passphrase ?? undefined,
    allowedRoots,
    readOnly: merged.readOnly ?? true,
    allowWrites: merged.allowWrites ?? false,
    maxReadSize: merged.maxReadSize ?? ONE_MIB,
    searchCacheTtlMs: merged.searchCacheTtlMs ?? TWO_MINUTES_MS,
    searchDefaultMaxResults: Math.min(merged.searchDefaultMaxResults ?? 25, 500),
    searchDefaultMaxDepth: Math.min(merged.searchDefaultMaxDepth ?? 5, 25),
    searchMaxEntries: Math.min(merged.searchMaxEntries ?? 1_500, 25_000),
    backupBeforeWrite: merged.backupBeforeWrite ?? true,
    requireWriteApproval: merged.requireWriteApproval ?? true,
    writeApprovalTtlMs: merged.writeApprovalTtlMs ?? FIVE_MINUTES_MS,
    connectTimeoutMs: merged.connectTimeoutMs ?? 15_000,
    readyTimeoutMs: merged.readyTimeoutMs ?? 15_000,
    logPath: envOverrides.logPath
      ? resolve(envOverrides.logPath)
      : resolveFromBase(fileConfig.logPath ?? "ios-files-mcp.log", loadedConfig.baseDir)
  };
}
