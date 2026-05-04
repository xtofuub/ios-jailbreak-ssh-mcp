import { spawn } from "node:child_process";

const hermesDecSpec = "git+https://github.com/P1sec/hermes-dec";

console.log("Installing hermes-dec with pipx.");
console.log("This adds hbc-decompiler, hbc-disassembler, and hbc-file-parser if Python/pipx are available.");
console.log("");

const python = await findPython();
if (!python) {
  console.error("Could not find Python. Install Python 3 first, then rerun: npm run install:hermes-dec");
  process.exit(1);
}

await run(python.command, [...python.prefixArgs, "-m", "pip", "install", "--user", "pipx"]);
await run(python.command, [...python.prefixArgs, "-m", "pipx", "install", hermesDecSpec]);

console.log("");
console.log("Done. Restart VS Code/Cline/Codex, then run:");
console.log("  npm run check:hermes-decoders");
console.log("  ios_list_hermes_decoders()");

async function findPython() {
  const candidates =
    process.platform === "win32"
      ? [
          { command: "py", prefixArgs: ["-3"] },
          { command: "python", prefixArgs: [] },
          { command: "python3", prefixArgs: [] }
        ]
      : [
          { command: "python3", prefixArgs: [] },
          { command: "python", prefixArgs: [] }
        ];

  for (const candidate of candidates) {
    const ok = await run(candidate.command, [...candidate.prefixArgs, "--version"], {
      allowFailure: true,
      silent: true
    });

    if (ok) {
      return candidate;
    }
  }

  return undefined;
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    if (!options.silent) {
      console.log(`> ${[command, ...args].join(" ")}`);
    }

    const child = spawn(command, args, {
      shell: false,
      windowsHide: true,
      stdio: options.silent ? "ignore" : "inherit"
    });

    child.once("error", (error) => {
      if (options.allowFailure) {
        resolve(false);
        return;
      }

      reject(error);
    });

    child.once("close", (code) => {
      if (code === 0) {
        resolve(true);
        return;
      }

      if (options.allowFailure) {
        resolve(false);
        return;
      }

      reject(new Error(`${command} exited with code ${code}`));
    });
  });
}
