# ios-files-mcp

MCP stdio server for controlled SSH/SFTP access to an iOS device filesystem.

```text
AI MCP client -> ios-files-mcp on your computer -> SSH/SFTP -> iOS device
```

## Quick Install

Requirements:

- Node.js 20+
- OpenSSH running on your iOS device
- Your computer can SSH to the device

Find the iOS device IP in `Settings -> Wi-Fi -> your network -> IP Address`, then test:

```powershell
ssh mobile@192.168.1.23
```

Run the command for your coding agent. Replace `192.168.1.23` and `change-me`. Your default ssh password is alpine if you haven't changed it.

### Codex

```powershell
npx -p github:xtofuub/ios-files-mcp iosfiles-mcp --client codex --host 192.168.1.23 --password change-me
```

Writes to `~/.codex/config.toml`.

### Claude Desktop

```powershell
npx -p github:xtofuub/ios-files-mcp iosfiles-mcp --client claude --host 192.168.1.23 --password change-me
```

Writes to Claude Desktop's MCP config.

### OpenCode

```powershell
npx -p github:xtofuub/ios-files-mcp iosfiles-mcp --client opencode --host 192.168.1.23 --password change-me
```

Writes to `~/.config/opencode/opencode.json`.

### VS Code

Run this from the workspace folder where you want the MCP server enabled.

```powershell
npx -p github:xtofuub/ios-files-mcp iosfiles-mcp --client vscode --host 192.168.1.23 --password change-me
```

Writes to `.vscode/mcp.json`.

### All Supported Clients

```powershell
npx -p github:xtofuub/ios-files-mcp iosfiles-mcp --client all --host 192.168.1.23 --password change-me
```

Supported `--client` values:

```text
codex      -> ~/.codex/config.toml
claude     -> Claude Desktop config
opencode   -> ~/.config/opencode/opencode.json
vscode     -> .vscode/mcp.json in the current folder
all        -> all supported clients
```

The installer writes an `ios-files` MCP server entry and backs up existing config files to `.bak`.

Install with optional Hermes bytecode decoders:

```powershell
npx -p github:xtofuub/ios-files-mcp iosfiles-mcp --client codex --host 192.168.1.23 --password change-me --install-hermes
```

Hermes decoders are only needed for React Native Hermes bytecode bundle decoding. The flag installs `hermes-dec` with Python/pipx when available.

For radare2 static analysis, see the [radare2 section](#radare2-static-analysis-tools) below — recommended path is to install `radare2` on the iOS device itself via Sileo.

## USB SSH

Forward iOS device SSH to a local port with `iproxy`, then install using localhost:

```powershell
ssh -p 2222 mobile@127.0.0.1
npx -p github:xtofuub/ios-files-mcp iosfiles-mcp --client codex --host 127.0.0.1 --port 2222 --password change-me
```

USB SSH still uses normal SSH auth, so use a password or SSH key.

## Manual MCP Config

The installer writes this command:

```json
{
  "command": "npx",
  "args": ["--yes", "--quiet", "github:xtofuub/ios-files-mcp"],
  "env": {
    "IOS_FILES_MCP_HOST": "192.168.1.23",
    "IOS_FILES_MCP_USERNAME": "mobile",
    "IOS_FILES_MCP_PASSWORD": "change-me"
  }
}
```

Use that under `mcpServers.ios-files` for Claude/Cline-style clients, or under `servers.ios-files` for VS Code.

For an explicit package install:

```powershell
npm install github:xtofuub/ios-files-mcp
```

To make `npm install` also write MCP config, set installer env vars first:

```powershell
$env:IOS_FILES_MCP_INSTALL_CLIENTS="codex"
$env:IOS_FILES_MCP_HOST="192.168.1.23"
$env:IOS_FILES_MCP_USERNAME="mobile"
$env:IOS_FILES_MCP_PASSWORD="change-me"
npm install github:xtofuub/ios-files-mcp
```

Add this env var if you also want Hermes decoders:

```powershell
$env:IOS_FILES_MCP_INSTALL_HERMES="true"
```

Useful env vars:

```text
IOS_FILES_MCP_HOST
IOS_FILES_MCP_PORT
IOS_FILES_MCP_USERNAME
IOS_FILES_MCP_PASSWORD
IOS_FILES_MCP_KEY_PATH
IOS_FILES_MCP_ALLOWED_ROOTS
IOS_FILES_MCP_READ_ONLY
IOS_FILES_MCP_ALLOW_WRITES
IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL
IOS_FILES_MCP_ENABLE_R2
IOS_FILES_MCP_R2_MODE
IOS_FILES_MCP_R2_DEVICE_R2_PATH
IOS_FILES_MCP_R2_DEVICE_RABIN2_PATH
IOS_FILES_MCP_R2_PATH
IOS_FILES_MCP_RABIN2_PATH
IOS_FILES_MCP_R2_TIMEOUT_MS
IOS_FILES_MCP_R2_MAX_OUTPUT_BYTES
IOS_FILES_MCP_R2_MAX_BINARY_SIZE
IOS_FILES_MCP_SFTP_OP_TIMEOUT_MS
IOS_FILES_MCP_CONFIG
```

## Optional JSON Config File

Most users should use MCP `env`. JSON config files are only needed for advanced/local setups.

Minimal example:

```json
{
  "host": "192.168.1.23",
  "port": 22,
  "username": "mobile",
  "password": "change-me",
  "readOnly": true,
  "allowWrites": false
}
```

See `ios-files-mcp.config.example.json` for every option.

Point MCP at the config file with `IOS_FILES_MCP_CONFIG`:

```json
{
  "servers": {
    "ios-files": {
      "command": "npx",
      "args": [
        "--yes",
        "--quiet",
        "github:xtofuub/ios-files-mcp"
      ],
      "env": {
        "IOS_FILES_MCP_CONFIG": "/path/to/ios-files-mcp/ios-files-mcp.config.json"
      }
    }
  }
}
```

Or pass it as an arg:

```json
{
  "mcpServers": {
    "ios-files": {
      "command": "npx",
      "args": [
        "--yes",
        "--quiet",
        "github:xtofuub/ios-files-mcp",
        "--config",
        "/path/to/ios-files-mcp/ios-files-mcp.config.json"
      ]
    }
  }
}
```

## Local Test

This should print help and exit:

```powershell
npx --yes --quiet github:xtofuub/ios-files-mcp --help
```

This starts the MCP server and waits for an MCP client:

```powershell
$env:IOS_FILES_MCP_HOST="192.168.1.23"
$env:IOS_FILES_MCP_USERNAME="mobile"
$env:IOS_FILES_MCP_PASSWORD="change-me"
npx --yes --quiet github:xtofuub/ios-files-mcp
```

Press `Ctrl+C` to stop it.

## Development

From a clone:

```powershell
npm install
npm run build
npm run typecheck
node dist/index.js --help
```

For local MCP testing without NPX, point your MCP client at `node dist/index.js` with an absolute path.

## First MCP Calls

If app directories look empty, start here:

```text
ios_connection_doctor()
ios_doctor()
ios_diagnose_roots()
```

Check local MCP client config:

```text
ios_mcp_config_status()
ios_config()
```

To find YouTube:

```text
ios_find_app("YouTube")
ios_find_app("com.google.ios.youtube")
ios_snapshot_app("com.google.ios.youtube")
ios_app("com.google.ios.youtube")
```

To inspect an app plist:

```text
ios_read_plist("/private/var/containers/Bundle/Application/<UUID>/YouTube.app/Info.plist")
```

## App Paths

App data containers:

```text
/var/mobile/Containers/Data/Application/<UUID>
/private/var/mobile/Containers/Data/Application/<UUID>
```

App Store `.app` bundles:

```text
/var/containers/Bundle/Application/<UUID>/<AppName>.app
/private/var/containers/Bundle/Application/<UUID>/<AppName>.app
```

`Info.plist` is usually in the `.app` bundle, not the data container.

## Safety

The server is read-only by default. Writes require both:

```json
{
  "readOnly": false,
  "allowWrites": true
}
```

When writes are enabled, write approval is still required by default:

```json
{
  "requireWriteApproval": true,
  "writeApprovalTtlMs": 300000
}
```

Write-capable tools do not write on the first call. They return an approval request with an `approvalId`. If you approve the exact operation, call the same tool again with the same arguments plus that `approvalId`.

Approval ids are:

```text
one-use
time-limited
bound to the exact tool name and arguments
```

Example:

```text
ios_write_file("/var/mobile/test.txt", "hello")
```

Returns an approval request. Then, only if approved:

```text
ios_write_file("/var/mobile/test.txt", "hello", approvalId="the-id-from-the-request")
```

Blocked by default:

```text
/var/Keychains
/var/mobile/Library/Accounts
/var/mobile/Library/SMS
/var/mobile/Library/Mail
/private/var/db
/System
/usr
/bin
/sbin
```

Every operation is logged to `ios-files-mcp.log`. File contents and secrets are not logged.

## Tools

### Basic Filesystem

| Tool | What it does |
| --- | --- |
| `ios_list_dir(path)` | Lists files and folders in one directory. |
| `ios_stat(path)` | Returns file metadata such as type, size, owner, mode, and modified time. |
| `ios_exists(path)` | Checks whether a path exists without failing if it is missing. |
| `ios_hash_file(path)` | Computes a SHA-256 hash for a file. |
| `ios_search_files(root, pattern, maxResults, maxDepth, includeMetadata, useCache)` | Runs a capped recursive filename/path search. Use app tools first for installed apps. |

### Reading Files

| Tool | What it does |
| --- | --- |
| `ios_read_file(path)` | Reads a UTF-8 text file into the chat, capped by `maxReadSize`. |
| `ios_read_file_chunk(path, offset, length, encoding)` | Reads one bounded section of a file. Use this for large text or binary files. |
| `ios_tail_file(path, maxBytes)` | Reads the last bytes of a file, useful for logs. |
| `ios_read_last_lines(path, lines, maxBytes)` | Reads the last N lines of a text file. |
| `ios_read_plist(path)` | Parses XML or binary plist files and returns JSON-safe data. |
| `ios_inspect_js_bundle(path)` | Detects whether a React Native bundle is plain JavaScript, Hermes bytecode, or unknown binary. |
| `ios_decode_js_bundle(path, mode, localPath, maxOutputBytes, beautify)` | Beautifies plain `.jsbundle` files or runs the configured Hermes decoder for bytecode bundles. |
| `ios_list_hermes_decoders()` | Shows the configured decoder, auto-detected decoder commands, and setup notes. |

### Copying Files To Your Computer

| Tool | What it does |
| --- | --- |
| `ios_download_file(remotePath, localPath, overwrite)` | Copies one file from the iOS device to an allowed local folder on your computer. This is not limited by `maxReadSize`. |
| `ios_zip_download(paths, localPath, overwrite)` | Creates a local ZIP containing one or more iOS device files/folders. Use this for app folders, logs, or grouped exports. |

`localPath` must be inside `localArtifactRoots`.

### App Store App Helpers

| Tool | What it does |
| --- | --- |
| `ios_find_app(query)` | Finds an installed app by visible name, `.app` name, or bundle id without doing a slow recursive search. |
| `ios_list_apps(query, limit)` | Lists installed app bundles, optionally filtered by name or bundle id. |
| `ios_resolve_app_container(bundleId)` | Resolves a bundle id to its `.app` bundle, app data container, and app group containers when visible. |
| `ios_list_preferences(bundleId)` | Lists plist files in the app data container's `Library/Preferences` folder. |
| `ios_read_preferences(bundleId, includeAll, maxFiles)` | Reads app preference plist files. By default it only reads the exact bundle-id plist. |

### SQLite

| Tool | What it does |
| --- | --- |
| `ios_read_sqlite_schema(path)` | Reads table/view names, SQL definitions, and table columns from a SQLite database. |
| `ios_query_sqlite(path, sql, limit)` | Runs one read-only SQL statement and returns limited rows. Allows `SELECT`, `PRAGMA`, `WITH`, and `EXPLAIN`. |

### React Native Bundles

Plain React Native `.jsbundle` files are JavaScript text. `ios_decode_js_bundle` can beautify them and either preview the result in the MCP response or save it to a local file.

Hermes bundles are bytecode. The server can detect them and auto-use `hbc-decompiler`, `hbc-disassembler`, `hermesc`, or `hbctool` if one is on PATH. The output is usually pseudo-code, HASM, or bytecode/disassembly, not the original source code.

Run `ios_list_hermes_decoders()` when decoding fails. It tells you what the MCP server can see from its own process.

Optional decoder helper:

```powershell
npx -p github:xtofuub/ios-files-mcp ios-files-mcp-install-hermes-dec
npx -p github:xtofuub/ios-files-mcp ios-files-mcp-check-hermes-decoders
```

### radare2 static analysis tools

By default these tools detect `radare2` on the iOS device and run it there over SSH — no binary copy needed. If `r2` is not installed on the device, the MCP falls back to running `r2`/`rabin2` on your computer after copying the binary to a temporary local folder. Run `ios_r2_check` to see which runner is active.

Recommended install (on the iOS device, via Sileo):

1. Open Sileo on the jailbroken device.
2. Install the `radare2` package from the Procursus repo (default on modern jailbreaks like Dopamine and palera1n).
3. From your computer, run `ssh mobile@<device-ip> 'r2 -v'` to confirm.

Common device paths after Sileo install:

```text
/usr/bin/r2          (rootful jailbreaks: unc0ver, checkra1n, classic palera1n)
/var/jb/usr/bin/r2   (rootless jailbreaks: Dopamine, palera1n rootless)
```

The MCP probes `command -v r2` over SSH, so it picks up whatever is on the device's `$PATH`. Override with `IOS_FILES_MCP_R2_DEVICE_R2_PATH=/your/path` if the binary is in a non-standard location.

Modes:

- `IOS_FILES_MCP_R2_MODE=auto` (default) — try device first, fall back to local.
- `IOS_FILES_MCP_R2_MODE=device` — require device-side r2; fail fast if missing.
- `IOS_FILES_MCP_R2_MODE=local` — always run on this computer (copies binary to a temp folder).

Optional env:

```text
IOS_FILES_MCP_ENABLE_R2=true
IOS_FILES_MCP_R2_MODE=auto
IOS_FILES_MCP_R2_DEVICE_R2_PATH=/var/jb/usr/bin/r2
IOS_FILES_MCP_R2_DEVICE_RABIN2_PATH=/var/jb/usr/bin/rabin2
IOS_FILES_MCP_R2_PATH=r2
IOS_FILES_MCP_RABIN2_PATH=rabin2
IOS_FILES_MCP_R2_TIMEOUT_MS=30000
IOS_FILES_MCP_R2_MAX_OUTPUT_BYTES=16777216
IOS_FILES_MCP_R2_MAX_BINARY_SIZE=134217728
```

Migration note: the previous host-side installer (`ios-files-mcp-install-radare2`) and the `IOS_FILES_MCP_INSTALL_R2` postinstall flag have been removed. Install radare2 on the iOS device via Sileo, or install locally with your own package manager if you prefer `IOS_FILES_MCP_R2_MODE=local`.

When to use:

- Use `ios_r2_app_triage(bundleId)` for the fastest overview of an installed app.
- Use `ios_r2_binary_info(remotePath)` when you already know the binary path.
- Use `ios_r2_strings(remotePath, query, limit)` for endpoints, secrets, Firebase, URLs, debug strings, and feature flags.
- Use `ios_r2_imports(remotePath, query, limit)` for framework/API usage such as Keychain, crypto, networking, SQLite, WebKit, device integrity, and anti-debug checks.
- Use `ios_r2_functions(remotePath, limit)` to map available functions.
- Use `ios_r2_function_disasm(remotePath, functionNameOrAddress)` to inspect one selected function or address.

Recommended analysis flow:

1. `ios_find_app("App Name")` or `ios_resolve_app_container("com.example.app")`
2. `ios_r2_app_triage("com.example.app")`
3. `ios_r2_strings(remotePath, query, limit)` with queries like `http`, `api`, `firebase`, `token`, `auth`, `key`, `debug`
4. `ios_r2_imports(remotePath, query, limit)` with queries like `SecItem`, `CommonCrypto`, `CryptoKit`, `NSURLSession`, `SQLite`, `WKWebView`
5. `ios_r2_functions(remotePath, limit)`
6. `ios_r2_function_disasm(remotePath, functionNameOrAddress)` on a specific interesting function or address

| Tool | What it does |
| --- | --- |
| `ios_r2_check()` | Shows whether r2 support is enabled and whether local `r2`/`rabin2` are available. |
| `ios_r2_binary_info(remotePath)` | Returns Mach-O metadata and linked libraries for one binary path. |
| `ios_r2_app_triage(bundleId)` | Resolves an installed app, finds its executable, and returns binary info, interesting imports/strings, functions preview, and next actions. |
| `ios_r2_strings(remotePath, query, limit)` | Searches binary strings for URLs, endpoints, tokens, Firebase config, debug text, and feature flags. |
| `ios_r2_imports(remotePath, query, limit)` | Searches imported symbols/framework APIs such as Keychain, crypto, networking, SQLite, WebKit, and anti-debug calls. |
| `ios_r2_functions(remotePath, limit)` | Lists function names and addresses before deeper inspection. |
| `ios_r2_function_disasm(remotePath, functionNameOrAddress)` | Returns structured JSON disassembly for one selected function or address. |

### Writing Files

These tools are disabled unless `readOnly=false` and `allowWrites=true`.

| Tool | What it does |
| --- | --- |
| `ios_write_file(path, content)` | Writes UTF-8 content to a file. Existing files are backed up when `backupBeforeWrite=true`. |
| `ios_append_file(path, content)` | Appends UTF-8 content to a file, or creates it if missing. |
| `ios_delete_file(path)` | Deletes a file or empty directory. |
| `ios_move_file(from, to)` | Moves or renames a file. Existing destinations are backed up when configured. |
| `ios_copy_file(from, to)` | Copies a file on the iOS device. Existing destinations are backed up when configured. |
| `ios_mkdir(path)` | Creates a directory. |

Write-capable tools also accept optional `approvalId`. If `requireWriteApproval=true`, the first call returns an approval request and does not write. Retry the same tool with the returned `approvalId` only after approving the exact operation.

### Diagnostics

| Tool | What it does |
| --- | --- |
| `ios_doctor()` | Finds setup problems: SSH/SFTP connection, visible app roots, local export folders, MCP config, and Hermes decoder availability. |
| `ios_connection_doctor()` | Checks SSH/SFTP connection, visible roots, local artifact roots, MCP config, and Hermes decoder availability. |
| `ios_config()` | Checks whether Codex, Claude, OpenCode, and VS Code are configured to launch this MCP server correctly. |
| `ios_mcp_config_status()` | Shows whether Codex, Claude, OpenCode, and VS Code config files contain the expected `ios-files` server entry. |
| `ios_app(bundleId)` | Gives a quick app overview: bundle path, data container, app groups, Info.plist summary, preference files, SQLite files, and JS bundles. |
| `ios_snapshot_app(bundleId)` | Builds a metadata-focused app snapshot: bundle/data/app-group paths, Info.plist summary, preference files, SQLite files, and JS bundles. |
| `ios_diagnose_roots()` | Checks whether common iOS app roots are visible over the current SSH/SFTP login and gives notes for empty directories. |

## Notes

- Restart the MCP client after rebuilding.
- If directories are empty as `mobile`, try SSH/SFTP as `root` if your device exposes those directories only to root.
- `ios_search_files` is recursive and can be slow over SFTP. Use `ios_find_app`, `ios_list_apps`, or `ios_resolve_app_container` for apps.
- `ios_search_files` is capped and cached by default. Repeating the same search should return from memory for `searchCacheTtlMs`.
- Keep recursive searches small first, for example `maxResults=10` and `maxDepth=2`.
- `ios_search_files` returns concise path/type results by default. Set `includeMetadata=true` only when size and modified time are needed.
- `ios_read_file` defaults to a 4 MiB cap through `maxReadSize`.
- Use `ios_read_file_chunk`, `ios_tail_file`, or `ios_read_last_lines` instead of repeated full-file reads.
- Use `ios_download_file` for one large file, or `ios_zip_download` for folders/multiple files you want copied from the iOS device to your computer.
- Use `ios_read_sqlite_schema` and `ios_query_sqlite` for read-only SQLite inspection instead of dumping whole database files into chat.
- Use `ios_inspect_js_bundle` before `ios_decode_js_bundle` when you are not sure whether a React Native bundle is plain JavaScript or Hermes bytecode.
- More app lookup guidance is in `SKILLS.md`.
