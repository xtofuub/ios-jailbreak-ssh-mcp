#!/usr/bin/env node
import { spawn } from "node:child_process";

const decoders = [
  {
    name: "hbc-decompiler",
    purpose: "hermes-dec pseudo-code decompiler"
  },
  {
    name: "hbc-disassembler",
    purpose: "hermes-dec bytecode disassembler"
  },
  {
    name: "hermesc",
    purpose: "official Hermes bytecode dump"
  },
  {
    name: "hbctool",
    purpose: "Hermes HASM disassembler/assembler"
  },
  {
    name: "jsc2llvm",
    purpose: "custom external decoder target"
  }
];

const isWindows = process.platform === "win32";

for (const decoder of decoders) {
  const available = await commandExists(decoder.name);
  const mark = available ? "FOUND" : "missing";
  console.log(`${mark.padEnd(7)} ${decoder.name.padEnd(18)} ${decoder.purpose}`);
}

console.log("");
console.log("The MCP server uses the same PATH as the app that launches it.");
console.log("After installing a decoder, restart VS Code/Cline/Codex and run ios_list_hermes_decoders().");

function commandExists(command) {
  return new Promise((resolve) => {
    const child = spawn(isWindows ? "where" : "command", isWindows ? [command] : ["-v", command], {
      shell: !isWindows,
      windowsHide: true,
      stdio: "ignore"
    });

    child.once("error", () => resolve(false));
    child.once("close", (code) => resolve(code === 0));
  });
}
