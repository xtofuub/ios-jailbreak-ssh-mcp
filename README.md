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

Use an SSH key instead of a password if you prefer:

```json
"env": {
  "IOS_FILES_MCP_HOST": "192.168.1.23",
  "IOS_FILES_MCP_USERNAME": "mobile",
  "IOS_FILES_MCP_KEY_PATH": "/path/to/private_key"
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
IOS_FILES_MCP_READ_ONLY
IOS_FILES_MCP_ALLOW_WRITES
IOS_FILES_MCP_REQUIRE_WRITE_APPROVAL
IOS_FILES_MCP_MAX_READ_SIZE
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
  "readOnly": true,
  "allowWrites": false,
  "maxReadSize": 1048576,
  "searchCacheTtlMs": 120000,
  "searchDefaultMaxResults": 25,
  "searchDefaultMaxDepth": 5,
  "searchMaxEntries": 1500,
  "backupBeforeWrite": true,
  "requireWriteApproval": true,
  "writeApprovalTtlMs": 300000
}
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

## Tools

```text
ios_list_dir(path)
ios_read_file(path)
ios_write_file(path, content)
ios_append_file(path, content)
ios_delete_file(path)
ios_move_file(from, to)
ios_copy_file(from, to)
ios_mkdir(path)
ios_stat(path)
ios_search_files(root, pattern)
ios_search_files(root, pattern, maxResults, maxDepth, includeMetadata, useCache)
ios_read_plist(path)
ios_find_app(query)
ios_diagnose_roots()
ios_hash_file(path)
```

Write-capable tools also accept optional `approvalId`.

## Notes

- Restart the MCP client after rebuilding.
- If directories are empty as `mobile`, try SSH/SFTP as `root` if your jailbreak supports it.
- `ios_search_files` is recursive and can be slow over SFTP. Use `ios_find_app` for apps.
- `ios_search_files` is capped and cached by default. Repeating the same search should return from memory for `searchCacheTtlMs`.
- Keep recursive searches small first, for example `maxResults=10` and `maxDepth=2`.
- `ios_search_files` returns concise path/type results by default. Set `includeMetadata=true` only when size and modified time are needed.
- More app lookup guidance is in `SKILLS.md`.
