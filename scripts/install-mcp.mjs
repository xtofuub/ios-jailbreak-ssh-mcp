#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_SPEC = "github:xtofuub/ios-files-mcp";
const SERVER_NAME = "ios-files";
const MARKER_START = "# ios-files-mcp start";
const MARKER_END = "# ios-files-mcp end";

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}

try {
  await main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`ios-files-mcp MCP install failed: ${message}`);
  process.exit(1);
}

async function main() {
  const clients = parseClients(args.client ?? args.clients ?? process.env.IOS_FILES_MCP_INSTALL_CLIENTS ?? "all");
  const env = buildServerEnv();
  const dryRun = Boolean(args["dry-run"]);
  const shouldInstallHermes = Boolean(args["install-hermes"] || args["with-hermes"]);

  for (const client of clients) {
    const target = configPathFor(client);

    if (client === "codex") {
      await installCodex(target, env, dryRun);
    } else if (client === "opencode") {
      await installOpenCode(target, env, dryRun);
    } else if (client === "claude") {
      await installMcpServersJson(target, env, dryRun);
    } else if (client === "vscode") {
      await installVsCode(target, env, dryRun);
    } else {
      throw new Error(`Unsupported client '${client}'. Use claude, codex, opencode, vscode, or all.`);
    }
  }

  if (shouldInstallHermes) {
    await installHermesDecoders(dryRun);
  }

  const suffix = dryRun ? "Dry run complete." : "Done. Restart your MCP client.";
  console.log(suffix);
}

function buildServerEnv() {
  const host = stringArg("host", "IOS_FILES_MCP_HOST");
  const password = stringArg("password", "IOS_FILES_MCP_PASSWORD");
  const keyPath = stringArg("key-path", "IOS_FILES_MCP_KEY_PATH");

  if (!host) {
    throw new Error("Missing --host or IOS_FILES_MCP_HOST.");
  }

  if (!password && !keyPath) {
    throw new Error("Missing --password / IOS_FILES_MCP_PASSWORD or --key-path / IOS_FILES_MCP_KEY_PATH.");
  }

  const env = {
    IOS_FILES_MCP_HOST: host,
    IOS_FILES_MCP_PORT: stringArg("port", "IOS_FILES_MCP_PORT") ?? "22",
    IOS_FILES_MCP_USERNAME: stringArg("username", "IOS_FILES_MCP_USERNAME") ?? "mobile",
    IOS_FILES_MCP_ALLOWED_ROOTS:
      stringArg("allowed-roots", "IOS_FILES_MCP_ALLOWED_ROOTS") ??
      "/var/mobile,/private/var/mobile,/var/containers/Bundle/Application,/private/var/containers/Bundle/Application,/var/jb,/tmp",
    IOS_FILES_MCP_LOCAL_ARTIFACT_ROOTS:
      stringArg("local-artifact-roots", "IOS_FILES_MCP_LOCAL_ARTIFACT_ROOTS") ?? "~/Desktop,~/Downloads",
    IOS_FILES_MCP_READ_ONLY: stringArg("read-only", "IOS_FILES_MCP_READ_ONLY") ?? "true",
    IOS_FILES_MCP_ALLOW_WRITES: stringArg("allow-writes", "IOS_FILES_MCP_ALLOW_WRITES") ?? "false",
    IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL:
      stringArg("require-write-approval", "IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL") ?? "true"
  };

  if (password) {
    env.IOS_FILES_MCP_PASSWORD = password;
  }
  if (keyPath) {
    env.IOS_FILES_MCP_KEY_PATH = keyPath;
  }
  const passphrase = stringArg("passphrase", "IOS_FILES_MCP_KEY_PASSPHRASE");
  if (passphrase) {
    env.IOS_FILES_MCP_KEY_PASSPHRASE = passphrase;
  }

  return env;
}

async function installMcpServersJson(path, env, dryRun) {
  const config = await readJsonConfig(path);
  config.mcpServers = objectValue(config.mcpServers);
  config.mcpServers[SERVER_NAME] = {
    command: "npx",
    args: ["--yes", "--quiet", PACKAGE_SPEC],
    env
  };

  await writeJsonConfig(path, config, dryRun);
  console.log(`${dryRun ? "Would update" : "Updated"} Claude MCP config: ${path}`);
}

async function installVsCode(path, env, dryRun) {
  const config = await readJsonConfig(path);
  config.servers = objectValue(config.servers);
  config.servers[SERVER_NAME] = {
    command: "npx",
    args: ["--yes", "--quiet", PACKAGE_SPEC],
    env
  };

  await writeJsonConfig(path, config, dryRun);
  console.log(`${dryRun ? "Would update" : "Updated"} VS Code MCP config: ${path}`);
}

async function installOpenCode(path, env, dryRun) {
  const config = await readJsonConfig(path);
  config.$schema ??= "https://opencode.ai/config.json";
  config.mcp = objectValue(config.mcp);
  config.mcp[SERVER_NAME] = {
    type: "local",
    command: ["npx", "--yes", "--quiet", PACKAGE_SPEC],
    enabled: true,
    environment: env
  };

  await writeJsonConfig(path, config, dryRun);
  console.log(`${dryRun ? "Would update" : "Updated"} OpenCode config: ${path}`);
}

async function installCodex(path, env, dryRun) {
  const existing = await readTextIfExists(path);
  const block = codexTomlBlock(env);
  const updated = upsertTomlBlock(existing, block);

  await writeTextConfig(path, updated, dryRun);
  console.log(`${dryRun ? "Would update" : "Updated"} Codex config: ${path}`);
}

function installHermesDecoders(dryRun) {
  if (dryRun) {
    console.log("Would install Hermes decoders with scripts/install-hermes-dec.mjs.");
    return Promise.resolve();
  }

  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const installer = join(scriptDir, "install-hermes-dec.mjs");

  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [installer], {
      stdio: "inherit",
      windowsHide: true
    });

    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`Hermes decoder installer exited with code ${code}.`));
    });
  });
}

function codexTomlBlock(env) {
  return [
    MARKER_START,
    `[mcp_servers.${SERVER_NAME}]`,
    `command = "npx"`,
    `args = ["--yes", "--quiet", "${tomlString(PACKAGE_SPEC)}"]`,
    `env = { ${Object.entries(env)
      .map(([key, value]) => `${key} = "${tomlString(value)}"`)
      .join(", ")} }`,
    MARKER_END
  ].join("\n");
}

function upsertTomlBlock(existing, block) {
  const markerPattern = new RegExp(`${escapeRegExp(MARKER_START)}[\\s\\S]*?${escapeRegExp(MARKER_END)}`);
  if (markerPattern.test(existing)) {
    return `${existing.replace(markerPattern, block).trimEnd()}\n`;
  }

  const sectionPattern = /\[mcp_servers\.ios-files\][\s\S]*?(?=\n\[|$)/;
  if (sectionPattern.test(existing)) {
    return `${existing.replace(sectionPattern, block).trimEnd()}\n`;
  }

  return `${existing.trimEnd()}${existing.trim() ? "\n\n" : ""}${block}\n`;
}

async function readJsonConfig(path) {
  const text = await readTextIfExists(path);
  if (!text.trim()) {
    return {};
  }

  try {
    return JSON.parse(stripJsonComments(text));
  } catch (error) {
    throw new Error(`Could not parse JSON config ${path}: ${error.message}`);
  }
}

async function writeJsonConfig(path, config, dryRun) {
  await writeTextConfig(path, `${JSON.stringify(config, null, 2)}\n`, dryRun);
}

async function writeTextConfig(path, content, dryRun) {
  if (dryRun) {
    console.log(content);
    return;
  }

  await mkdir(dirname(path), { recursive: true });
  if (existsSync(path)) {
    await copyFile(path, `${path}.bak`);
  }
  await writeFile(path, content, "utf8");
}

async function readTextIfExists(path) {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return "";
    }
    throw error;
  }
}

function configPathFor(client) {
  if (args["config-path"]) {
    return resolve(args["config-path"]);
  }

  if (client === "codex") {
    return join(homedir(), ".codex", "config.toml");
  }

  if (client === "opencode") {
    if (process.env.OPENCODE_CONFIG) {
      return resolve(process.env.OPENCODE_CONFIG);
    }
    return join(homedir(), ".config", "opencode", "opencode.json");
  }

  if (client === "claude") {
    if (process.platform === "win32") {
      return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
    }
    if (process.platform === "darwin") {
      return join(homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
    }
    return join(homedir(), ".config", "Claude", "claude_desktop_config.json");
  }

  if (client === "vscode") {
    return resolve(process.cwd(), ".vscode", "mcp.json");
  }

  throw new Error(`No config path for client '${client}'.`);
}

function parseClients(input) {
  const clients = input
    .split(",")
    .map((client) => normalizeClient(client.trim().toLowerCase()))
    .filter(Boolean);

  return clients.includes("all") ? ["claude", "codex", "opencode", "vscode"] : clients;
}

function normalizeClient(client) {
  if (["code", "vs-code", "vsc"].includes(client)) {
    return "vscode";
  }
  return client;
}

function stringArg(name, envName) {
  const value = args[name] ?? process.env[envName];
  if (value === undefined || value === null || String(value).trim() === "") {
    return undefined;
  }
  return String(value);
}

function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function tomlString(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function stripJsonComments(input) {
  return input
    .replace(/^\uFEFF/, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

function parseArgs(argv) {
  const parsed = {};

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
      continue;
    }
    if (!arg.startsWith("--")) {
      continue;
    }

    const normalized = arg.slice(2);
    const equalsIndex = normalized.indexOf("=");
    if (equalsIndex >= 0) {
      parsed[normalized.slice(0, equalsIndex)] = normalized.slice(equalsIndex + 1);
      continue;
    }

    const next = argv[index + 1];
    if (next && !next.startsWith("--")) {
      parsed[normalized] = next;
      index += 1;
    } else {
      parsed[normalized] = true;
    }
  }

  return parsed;
}

function printHelp() {
  console.log(`Install ios-files-mcp into MCP client config.

Usage:
  iosfiles-mcp --client codex --host 192.168.1.23 --password change-me
  iosfiles-mcp --client claude,opencode,vscode --host 127.0.0.1 --port 2222 --password change-me

Clients:
  claude, codex, opencode, vscode, all

Options:
  --client <list>              Clients to update. Default: all
  --config-path <path>         Override config path for one client. VS Code default: .vscode/mcp.json
  --host <host>                iOS device SSH host
  --port <port>                iOS device SSH port. Default: 22
  --username <name>            SSH username. Default: mobile
  --password <password>        SSH password
  --key-path <path>            SSH private key path
  --passphrase <passphrase>    SSH key passphrase
  --install-hermes             Also install optional Hermes bytecode decoders
  --dry-run                    Print config instead of writing files

Postinstall auto mode:
  IOS_FILES_MCP_INSTALL_CLIENTS=codex IOS_FILES_MCP_HOST=192.168.1.23 IOS_FILES_MCP_PASSWORD=change-me npm install github:xtofuub/ios-files-mcp
  IOS_FILES_MCP_INSTALL_HERMES=true also installs optional Hermes decoders`);
}
