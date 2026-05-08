#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const clients = process.env.IOS_FILES_MCP_INSTALL_CLIENTS;

if (!clients) {
  console.log("ios-jailbreak-ssh-mcp installed.");
  console.log("Add it to MCP config:");
  console.log("  npx -p github:xtofuub/test ios-jailbreak-ssh-mcp-install-mcp --client codex --host 192.168.1.23 --password change-me");
  console.log("Auto-install during npm install:");
  console.log("  IOS_FILES_MCP_INSTALL_CLIENTS=codex IOS_FILES_MCP_HOST=192.168.1.23 IOS_FILES_MCP_PASSWORD=change-me npm install github:xtofuub/test");
  process.exit(0);
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const installer = join(scriptDir, "install-mcp.mjs");
const args = [installer, "--client", clients];

const result = spawnSync(process.execPath, args, {
  stdio: "inherit",
  windowsHide: true
});

process.exit(result.status ?? 1);
