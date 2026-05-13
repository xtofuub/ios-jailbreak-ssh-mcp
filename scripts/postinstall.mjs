#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const clients = process.env.IOS_FILES_MCP_INSTALL_CLIENTS;

if (!clients) {
  process.exit(0);
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const installer = join(scriptDir, "install-mcp.mjs");
const args = [installer, "--client", clients];

if (isTruthy(process.env.IOS_FILES_MCP_INSTALL_HERMES)) {
  args.push("--install-hermes");
}

const result = spawnSync(process.execPath, args, {
  stdio: "inherit",
  windowsHide: true
});

process.exit(result.status ?? 1);

function isTruthy(value) {
  return value !== undefined && ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
}
