#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printHelp();
  process.exit(0);
}

try {
  await main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`radare2 install failed: ${message}`);
  process.exit(1);
}

async function main() {
  const dryRun = Boolean(args["dry-run"]);
  const force = Boolean(args.force);

  if (!force && commandWorks("r2", ["-v"]) && commandWorks("rabin2", ["-v"])) {
    console.log("radare2 already looks installed: r2 and rabin2 are available.");
    return;
  }

  const manager = stringArg("package-manager", "IOS_FILES_MCP_R2_PACKAGE_MANAGER") ?? "auto";
  const plan = installPlan(manager);

  if (dryRun) {
    console.log(`Would install radare2 with ${plan.name}:`);
    for (const step of plan.commands) {
      console.log(`  ${formatCommand(step.command, step.args)}`);
    }
    return;
  }

  console.log(`Installing radare2 with ${plan.name}. This may prompt for admin/sudo approval.`);
  for (const step of plan.commands) {
    await run(step.command, step.args);
  }

  if (!commandWorks("r2", ["-v"]) || !commandWorks("rabin2", ["-v"])) {
    console.warn("Install finished, but r2/rabin2 were not found on the current PATH. Restart the terminal/MCP client or add radare2 to PATH.");
    return;
  }

  console.log("radare2 installed and available: r2 and rabin2 were found.");
}

function installPlan(requestedManager) {
  const manager = requestedManager.toLowerCase();
  if (manager !== "auto") {
    return planForManager(manager);
  }

  const candidates =
    process.platform === "win32"
      ? ["winget", "choco", "scoop"]
      : process.platform === "darwin"
        ? ["brew"]
        : ["apt", "dnf", "yum", "pacman", "zypper", "apk", "brew"];

  for (const candidate of candidates) {
    const plan = planForManager(candidate, false);
    if (plan && commandExists(plan.detectCommand)) {
      return plan;
    }
  }

  throw new Error(
    "No supported package manager was found. Install radare2 manually, or retry with --package-manager winget|brew|apt|dnf|yum|pacman|zypper|apk|choco|scoop."
  );
}

function planForManager(manager, strict = true) {
  const sudo = (command, args) => withSudo(command, args);
  const plans = {
    winget: {
      name: "winget",
      detectCommand: "winget",
      commands: [
        {
          command: "winget",
          args: [
            "install",
            "radare2",
            "--source",
            "winget",
            "--accept-package-agreements",
            "--accept-source-agreements"
          ]
        }
      ]
    },
    choco: {
      name: "Chocolatey",
      detectCommand: "choco",
      commands: [{ command: "choco", args: ["install", "radare2", "-y"] }]
    },
    scoop: {
      name: "Scoop",
      detectCommand: "scoop",
      commands: [{ command: "scoop", args: ["install", "radare2"] }]
    },
    brew: {
      name: "Homebrew",
      detectCommand: "brew",
      commands: [{ command: "brew", args: ["install", "radare2"] }]
    },
    apt: {
      name: "apt",
      detectCommand: "apt-get",
      commands: [
        sudo("apt-get", ["update"]),
        sudo("apt-get", ["install", "-y", "radare2"])
      ]
    },
    dnf: {
      name: "dnf",
      detectCommand: "dnf",
      commands: [sudo("dnf", ["install", "-y", "radare2"])]
    },
    yum: {
      name: "yum",
      detectCommand: "yum",
      commands: [sudo("yum", ["install", "-y", "radare2"])]
    },
    pacman: {
      name: "pacman",
      detectCommand: "pacman",
      commands: [sudo("pacman", ["-Sy", "--noconfirm", "radare2"])]
    },
    zypper: {
      name: "zypper",
      detectCommand: "zypper",
      commands: [sudo("zypper", ["install", "-y", "radare2"])]
    },
    apk: {
      name: "apk",
      detectCommand: "apk",
      commands: [sudo("apk", ["add", "radare2"])]
    }
  };

  const plan = plans[manager];
  if (!plan && strict) {
    throw new Error(`Unsupported package manager '${manager}'.`);
  }
  return plan;
}

function withSudo(command, args) {
  if (process.platform === "win32" || process.getuid?.() === 0) {
    return { command, args };
  }

  return commandExists("sudo")
    ? { command: "sudo", args: [command, ...args] }
    : { command, args };
}

function commandExists(command) {
  const result = spawnSync(command, ["--version"], {
    stdio: "ignore",
    windowsHide: true
  });
  return !result.error;
}

function commandWorks(command, commandArgs) {
  const result = spawnSync(command, commandArgs, {
    stdio: "ignore",
    windowsHide: true
  });
  return !result.error && result.status === 0;
}

function run(command, commandArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, commandArgs, {
      stdio: "inherit",
      windowsHide: true
    });

    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`${formatCommand(command, commandArgs)} exited with code ${code}.`));
    });
  });
}

function formatCommand(command, commandArgs) {
  return [command, ...commandArgs].map((part) => quoteArg(part)).join(" ");
}

function quoteArg(value) {
  return /^[A-Za-z0-9_./:=@+-]+$/.test(value) ? value : JSON.stringify(value);
}

function stringArg(name, envName) {
  const value = args[name] ?? process.env[envName];
  if (value === undefined || value === null || String(value).trim() === "") {
    return undefined;
  }
  return String(value);
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
  console.log(`Install radare2 for ios-files-mcp static analysis.

Usage:
  ios-files-mcp-install-radare2
  ios-files-mcp-install-radare2 --package-manager winget
  ios-files-mcp-install-radare2 --dry-run

Supported package managers:
  Windows: winget, choco, scoop
  macOS:   brew
  Linux:   apt, dnf, yum, pacman, zypper, apk, brew

Options:
  --package-manager <name>     auto, winget, brew, apt, dnf, yum, pacman, zypper, apk, choco, scoop
  --force                      Run installer even if r2/rabin2 already exist
  --dry-run                    Print commands instead of running them`);
}
