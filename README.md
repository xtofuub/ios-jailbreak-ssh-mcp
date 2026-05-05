# ios-jailbreak-ssh-mcp

Local MCP stdio server for safe SFTP access to your own jailbroken iPhone filesystem.

```text
AI MCP client -> ios-jailbreak-ssh-mcp on your PC -> SSH/SFTP -> iPhone
```

## Requirements

- Node.js 20+
- OpenSSH installed and running on the jailbroken iPhone
- Your PC can SSH to the phone:

```powershell
ssh mobile@<iphone-ip>
```

## Find Your iPhone IP

Most people should use the iPhone's normal Wi-Fi/LAN IP:

```text
iPhone Settings -> Wi-Fi -> tap your connected network -> IP Address
```

It usually looks like:

```text
192.168.1.23
10.0.0.42
```

Test it from your computer:

```powershell
ssh mobile@192.168.1.23
```

If you are using iPhone Personal Hotspot instead of normal Wi-Fi, the phone is often:

```text
172.20.10.1
```

If that does not work, run `ipconfig` on Windows and use the default gateway for the hotspot adapter.

## USB SSH

USB SSH works too. The MCP server does not need a special transport for it.

Forward a local TCP port to the iPhone's SSH port with a tool such as `iproxy`, then point the MCP server at the forwarded local port.

Typical example:

```text
host = 127.0.0.1
port = 2222
```

Then test from your computer:

```powershell
ssh -p 2222 mobile@127.0.0.1
```

In MCP config, that means:

```json
"env": {
  "IOS_FILES_MCP_HOST": "127.0.0.1",
  "IOS_FILES_MCP_PORT": "2222",
  "IOS_FILES_MCP_USERNAME": "mobile",
  "IOS_FILES_MCP_PASSWORD": "change-me"
}
```

USB SSH still uses normal SSH authentication. You still need either:

```text
- a password
- or an SSH private key
```

So yes: USB SSH needs a password unless you set up key-based auth.

## Install

From this folder:

```powershell
cd /path/to/ios-jailbreak-ssh-mcp
npm install
npm run build
```

## MCP Server Path

MCP clients must launch the built server file with an exact absolute path.

Use this server file:

```text
/path/to/ios-jailbreak-ssh-mcp/dist/index.js
```

Replace `/path/to/ios-jailbreak-ssh-mcp` with the actual folder where you cloned or built this repo.

Windows example:

```text
C:/Users/you/path/to/ios-jailbreak-ssh-mcp/dist/index.js
```

Do not use:

```text
.\dist\index.js
src/index.ts
ios-files-mcp.config.json as the command
```

For JSON strings on Windows, forward slashes are easiest:

```json
"C:/Users/you/path/to/ios-jailbreak-ssh-mcp/dist/index.js"
```

Backslashes also work, but they must be escaped:

```json
"C:\\Users\\you\\path\\to\\ios-jailbreak-ssh-mcp\\dist\\index.js"
```

## MCP Config With Credentials

Recommended: put the iPhone SSH settings in the MCP server `env` block.

### VS Code

VS Code uses `servers`.

```json
{
  "servers": {
    "ios-files": {
      "command": "node",
      "args": [
        "/path/to/ios-jailbreak-ssh-mcp/dist/index.js"
      ],
      "env": {
        "IOS_FILES_MCP_HOST": "192.168.1.23",
        "IOS_FILES_MCP_PORT": "22",
        "IOS_FILES_MCP_USERNAME": "mobile",
        "IOS_FILES_MCP_PASSWORD": "change-me",
        "IOS_FILES_MCP_ALLOWED_ROOTS": "/var/mobile,/private/var/mobile,/var/containers/Bundle/Application,/private/var/containers/Bundle/Application,/var/jb,/tmp",
        "IOS_FILES_MCP_LOCAL_ARTIFACT_ROOTS": "/path/to/ios-jailbreak-ssh-mcp,/Users/you/Desktop,/Users/you/Downloads",
        "IOS_FILES_MCP_READ_ONLY": "true",
        "IOS_FILES_MCP_ALLOW_WRITES": "false",
        "IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL": "true"
      }
    }
  }
}
```

### Claude / Cline

Many other MCP clients use `mcpServers`.

```json
{
  "mcpServers": {
    "ios-files": {
      "command": "node",
      "args": [
        "/path/to/ios-jailbreak-ssh-mcp/dist/index.js"
      ],
      "env": {
        "IOS_FILES_MCP_HOST": "192.168.1.23",
        "IOS_FILES_MCP_PORT": "22",
        "IOS_FILES_MCP_USERNAME": "mobile",
        "IOS_FILES_MCP_PASSWORD": "change-me",
        "IOS_FILES_MCP_ALLOWED_ROOTS": "/var/mobile,/private/var/mobile,/var/containers/Bundle/Application,/private/var/containers/Bundle/Application,/var/jb,/tmp",
        "IOS_FILES_MCP_READ_ONLY": "true",
        "IOS_FILES_MCP_ALLOW_WRITES": "false",
        "IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL": "true"
      }
    }
  }
}
```

Supported env vars:

```text
IOS_FILES_MCP_HOST
IOS_FILES_MCP_PORT
IOS_FILES_MCP_USERNAME
IOS_FILES_MCP_PASSWORD
IOS_FILES_MCP_KEY_PATH
IOS_FILES_MCP_KEY_PASSPHRASE
IOS_FILES_MCP_ALLOWED_ROOTS
IOS_FILES_MCP_LOCAL_ARTIFACT_ROOTS
IOS_FILES_MCP_READ_ONLY
IOS_FILES_MCP_ALLOW_WRITES
IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL
IOS_FILES_MCP_MAX_READ_SIZE
IOS_FILES_MCP_JS_BUNDLE_MAX_READ_SIZE
IOS_FILES_MCP_SQLITE_MAX_READ_SIZE
IOS_FILES_MCP_HERMES_DECODER_PRESET
IOS_FILES_MCP_HERMES_DECODER_COMMAND
IOS_FILES_MCP_HERMES_DECODER_OUTPUT_LIMIT
IOS_FILES_MCP_SEARCH_CACHE_TTL_MS
IOS_FILES_MCP_SEARCH_DEFAULT_MAX_RESULTS
IOS_FILES_MCP_SEARCH_DEFAULT_MAX_DEPTH
IOS_FILES_MCP_SEARCH_MAX_ENTRIES
IOS_FILES_MCP_BACKUP_BEFORE_WRITE
IOS_FILES_MCP_WRITE_APPROVAL_TTL_MS
IOS_FILES_MCP_LOG
IOS_FILES_MCP_CONFIG
```

## Optional JSON Config File

Use your real local config file:

```text
/path/to/ios-jailbreak-ssh-mcp/ios-files-mcp.config.json
```

Create it from the example if it does not exist:

```powershell
Copy-Item .\ios-files-mcp.config.example.json .\ios-files-mcp.config.json
```

Edit `ios-files-mcp.config.json`:

```json
{
  "host": "192.168.1.23",
  "port": 22,
  "username": "mobile",
  "password": "change-me",
  "privateKeyPath": null,
  "allowedRoots": [
    "/var/mobile",
    "/private/var/mobile",
    "/var/containers/Bundle/Application",
    "/private/var/containers/Bundle/Application",
    "/var/jb",
    "/tmp"
  ],
  "localArtifactRoots": [
    ".",
    "~/Desktop",
    "~/Downloads"
  ],
  "readOnly": true,
  "allowWrites": false,
  "maxReadSize": 4194304,
  "jsBundleMaxReadSize": 67108864,
  "sqliteMaxReadSize": 67108864,
  "hermesDecoderPreset": "auto",
  "hermesDecoderCommand": null,
  "hermesDecoderOutputLimit": 4194304,
  "searchCacheTtlMs": 120000,
  "searchDefaultMaxResults": 25,
  "searchDefaultMaxDepth": 5,
  "searchMaxEntries": 1500,
  "backupBeforeWrite": true,
  "requireWriteApproval": true,
  "writeApprovalTtlMs": 300000
}
```

`maxReadSize` defaults to `4194304` bytes, which is 4 MiB. `sqliteMaxReadSize` and `jsBundleMaxReadSize` default to `67108864` bytes, which is 64 MiB for read-only SQLite and React Native bundle inspection.

`hermesDecoderPreset` defaults to `auto`. Plain `.jsbundle` files can be beautified without a decoder. Hermes bytecode needs an external local decoder/disassembler because Hermes bytecode is compiled binary data, not JavaScript source.

Decoder binaries are not bundled in this repo. They are separate tools because they are platform-specific and can change faster than the MCP server. The repo includes helper scripts to install/check them.

Recommended install:

```powershell
npm run install:hermes-dec
npm run check:hermes-decoders
```

Then restart VS Code/Cline/Codex so the MCP server sees the updated PATH.

Auto mode checks for these commands on your computer:

```text
hbc-decompiler
hbc-disassembler
hermesc
hbctool
```

You can force a preset:

```json
"hermesDecoderPreset": "hbctool"
```

Or use an exact custom command:

```json
"hermesDecoderPreset": "custom",
"hermesDecoderCommand": "hermesc -dump-bytecode {input}"
```

Use `{input}` for the temporary local Hermes bytecode file. If your decoder writes to a file or folder, use `{output}` too.

Useful command templates:

```json
"hermesDecoderCommand": "hbc-decompiler {input} {output}"
"hermesDecoderCommand": "hbc-disassembler {input} {output}"
"hermesDecoderCommand": "hermesc -dump-bytecode {input}"
"hermesDecoderCommand": "hbctool disasm {input} {output}"
```

For `jsc2llvm`, set `hermesDecoderPreset` to `custom` and provide the exact command your install uses:

```json
"hermesDecoderPreset": "custom",
"hermesDecoderCommand": "jsc2llvm ... {input} ... {output}"
```

`ios-files-mcp.config.example.json` is only a template. If you use this file, point the MCP server at your real config with `IOS_FILES_MCP_CONFIG`.

```json
{
  "servers": {
    "ios-files": {
      "command": "node",
      "args": [
        "/path/to/ios-jailbreak-ssh-mcp/dist/index.js"
      ],
      "env": {
        "IOS_FILES_MCP_CONFIG": "/path/to/ios-jailbreak-ssh-mcp/ios-files-mcp.config.json"
      }
    }
  }
}
```

Other MCP clients may prefer passing the config path as args:

```json
{
  "mcpServers": {
    "ios-files": {
      "command": "node",
      "args": [
        "/path/to/ios-jailbreak-ssh-mcp/dist/index.js",
        "--config",
        "/path/to/ios-jailbreak-ssh-mcp/ios-files-mcp.config.json"
      ]
    }
  }
}
```

## Local Test

This should print help and exit:

```powershell
node "/path/to/ios-jailbreak-ssh-mcp/dist/index.js" --help
```

This starts the MCP server and waits for an MCP client:

```powershell
node "/path/to/ios-jailbreak-ssh-mcp/dist/index.js" --config "/path/to/ios-jailbreak-ssh-mcp/ios-files-mcp.config.json"
```

Press `Ctrl+C` to stop it.

## First MCP Calls

If app directories look empty, start here:

```text
ios_diagnose_roots()
```

To find YouTube:

```text
ios_find_app("YouTube")
ios_find_app("com.google.ios.youtube")
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

## Frida Dynamic Analysis (Optional)

Frida enables real-time runtime analysis of iOS apps — intercepting network traffic, keychain access, crypto operations, and more. Requires Frida server installed on your jailbroken iPhone.

### Installation

1. **Install Frida server on your iPhone:**

   - Open Cydia, Sileo, or Zebra
   - Search for `Frida` and install the latest version
   - Or via SSH: `ssh mobile@YOUR_IP` and check `/usr/bin/frida` or `/var/jb/usr/bin/frida`

2. **Enable Frida in config:**

   Edit `ios-files-mcp.config.json`:

   ```json
   "frida": {
     "enabled": true,
     "jailbreakType": "auto",
     "binaryPath": null,
     "traceDefaultDurationMs": 10000,
     "maxSessionEvents": 5000,
     "commandTimeoutMs": 30000
   }
   ```

   - `enabled`: Set to `true` to activate Frida tools
   - `jailbreakType`: `"auto"` auto-detects rootless (palera1n, Dopamine) vs rootful jailbreaks. Set to `"rootless"` or `"rootful"` if auto-detection fails.
   - `binaryPath`: Override the auto-detected Frida binary path (leave `null` to auto-detect)
   - `traceDefaultDurationMs`: Default duration for timed traces (milliseconds)
   - `maxSessionEvents`: Maximum events buffered per background session
   - `commandTimeoutMs`: SSH exec timeout for Frida commands

3. **Test the connection:**

   Once enabled, call `ios_frida_check` to verify Frida is installed and accessible.

### Hook Categories

Frida tools support intercepting these runtime operations:

| Category | What's captured |
| --- | --- |
| `network` | NSURLSession/NSURLConnection requests, URLs, methods, headers, body size |
| `request_building` | NSMutableURLRequest construction (setHTTPMethod, setValue:forHTTPHeaderField, setHTTPBody) |
| `keychain` | SecItem* operations (service, account, access group, class) |
| `userdefaults` | NSUserDefaults reads and writes |
| `sqlite` | sqlite3_exec and sqlite3_prepare SQL queries |
| `webview` | WKWebView JS evaluation, navigation decisions, message handlers |
| `deeplinks` | UIApplication openURL calls and app delegate URL handling |
| `ui_actions` | UIControl sendAction, gesture recognizer events |
| `crypto` | CCCrypt, CCHmac, SecKey operations |
| `jailbreak_detection` | File existence checks, canOpenURL, ptrace, sysctl, dlopen |

### Frida Tools

| Tool | What it does | Requires Approval |
| --- | --- | --- |
| `ios_frida_check()` | Detect Frida installation, binary path, iOS version | No |
| `ios_frida_list_processes()` | List all running processes on the device | No |
| `ios_frida_list_apps()` | Fast app listing via Frida (instant, replaces SFTP scan) | No |
| `ios_frida_app_info(bundleId)` | Get app details: entitlements, team ID, plugins, paths | No |
| `ios_frida_start_trace(target, hookTypes, durationSeconds)` | Run hooks on a process for N seconds, return all events | Yes |
| `ios_frida_begin_session(target, hookTypes)` | Start a background trace session, return sessionId | Yes |
| `ios_frida_poll_events(sessionId, clearAfterRead)` | Get accumulated events from a session | No |
| `ios_frida_end_session(sessionId)` | Stop a session and return final events | No |
| `ios_frida_dump_ui(target)` | Get the full UIKit view hierarchy as a JSON tree | Yes |
| `ios_frida_tap_element(target, matcher...)` | Tap a UI element by label, identifier, or className | Yes |
| `ios_frida_run_script(target, script, durationSeconds)` | Execute a custom Frida script string | Yes |

### Example: Capture Network Traffic

```text
ios_frida_start_trace("Safari", ["network"], 10)
```

On your iPhone, open a website in Safari. The tool returns all network events with URLs, methods, and headers.

### Example: Interactive UI Testing

```text
1. ios_frida_begin_session("MyApp", ["ui_actions", "network"])
2. (Let the app run for 30 seconds, tap buttons on the iPhone)
3. ios_frida_poll_events(sessionId, true)  // Get accumulated events
4. (Tap more buttons)
5. ios_frida_poll_events(sessionId, true)
6. ios_frida_end_session(sessionId)        // Stop and get final events
```

---

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
| `ios_download_file(remotePath, localPath, overwrite)` | Copies one file from the iPhone to an allowed local folder on your computer. This is not limited by `maxReadSize`. |
| `ios_zip_download(paths, localPath, overwrite)` | Creates a local ZIP containing one or more iPhone files/folders. Use this for app folders, logs, or grouped exports. |

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

### Writing Files

These tools are disabled unless `readOnly=false` and `allowWrites=true`.

| Tool | What it does |
| --- | --- |
| `ios_write_file(path, content)` | Writes UTF-8 content to a file. Existing files are backed up when `backupBeforeWrite=true`. |
| `ios_append_file(path, content)` | Appends UTF-8 content to a file, or creates it if missing. |
| `ios_delete_file(path)` | Deletes a file or empty directory. |
| `ios_move_file(from, to)` | Moves or renames a file. Existing destinations are backed up when configured. |
| `ios_copy_file(from, to)` | Copies a file on the iPhone. Existing destinations are backed up when configured. |
| `ios_mkdir(path)` | Creates a directory. |

Write-capable tools also accept optional `approvalId`. If `requireWriteApproval=true`, the first call returns an approval request and does not write. Retry the same tool with the returned `approvalId` only after approving the exact operation.

### Diagnostics

| Tool | What it does |
| --- | --- |
| `ios_diagnose_roots()` | Checks whether common iOS app roots are visible over the current SSH/SFTP login and gives notes for empty directories. |

## Notes

- Restart the MCP client after rebuilding.
- If directories are empty as `mobile`, try SSH/SFTP as `root` if your jailbreak supports it.
- `ios_search_files` is recursive and can be slow over SFTP. Use `ios_find_app`, `ios_list_apps`, or `ios_resolve_app_container` for apps.
- `ios_search_files` is capped and cached by default. Repeating the same search should return from memory for `searchCacheTtlMs`.
- Keep recursive searches small first, for example `maxResults=10` and `maxDepth=2`.
- `ios_search_files` returns concise path/type results by default. Set `includeMetadata=true` only when size and modified time are needed.
- `ios_read_file` defaults to a 4 MiB cap through `maxReadSize`.
- Use `ios_read_file_chunk`, `ios_tail_file`, or `ios_read_last_lines` instead of repeated full-file reads.
- Use `ios_download_file` for one large file, or `ios_zip_download` for folders/multiple files you want copied from the iPhone to your PC.
- Use `ios_read_sqlite_schema` and `ios_query_sqlite` for read-only SQLite inspection instead of dumping whole database files into chat.
- Use `ios_inspect_js_bundle` before `ios_decode_js_bundle` when you are not sure whether a React Native bundle is plain JavaScript or Hermes bytecode.
- More app lookup guidance is in `SKILLS.md`.