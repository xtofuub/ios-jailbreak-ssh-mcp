# iOS Files MCP - Quick Setup Guide

## Step 1: Test SSH Connection First

Before configuring this MCP server, make sure you can SSH to your iPhone:

```powershell
ssh mobile@YOUR_IPHONE_IP
```

At the password prompt, enter your iPhone SSH password. If this works, you're ready to proceed.

**Can't connect?**
- Find your iPhone IP: Settings > Wi-Fi > Tap your network > IP Address
- Make sure OpenSSH is installed on the iPhone (via Cydia/Sileo)
- Try pinging the iPhone first: `ping YOUR_IPHONE_IP`

## Step 2: Create Your Config File

```powershell
copy ios-files-mcp.config.example.json ios-files-mcp.config.json
```

## Step 3: Edit the Config File

Open `ios-files-mcp.config.json` and change these values:

| Field | What to Change | Example |
|-------|---|---|
| `host` | Your iPhone's IP address | `192.168.1.23` |
| `password` | Your iPhone SSH password | `(your jailbreak SSH password)` |
| `port` | Usually leave as 22 (unless using USB SSH) | `22` or `2222` |

**All other settings have safe defaults** - you don't need to touch them unless you have a specific need.

## Step 4: Build and Run

```powershell
cd /path/to/ios-jailbreak-ssh-mcp
npm install
npm run build
npm start
```

If you see connection errors:
1. Double-check the `host` and `password` in the config
2. Test SSH again manually: `ssh mobile@YOUR_IP`
3. Check the log file: `ios-files-mcp.log`

## Step 5: Connect Your MCP Client

Configure your MCP client (Claude for VS Code, etc.) to use this server.

For **VS Code with Claude**:

```json
{
  "servers": {
    "ios-files": {
      "command": "node",
      "args": ["/path/to/ios-jailbreak-ssh-mcp/dist/index.js"],
      "env": {
        "IOS_FILES_MCP_CONFIG": "/absolute/path/to/ios-files-mcp.config.json"
      }
    }
  }
}
```

## Advanced: Use SSH Private Key Instead of Password

If you have SSH key-based auth set up:

```json
{
  "privateKeyPath": "C:\\Users\\YourName\\.ssh\\id_rsa",
  "password": null,
  "passphrase": "your-key-passphrase-or-null"
}
```

## Enable Writing (⚠️ Optional & Advanced)

By default, the server is **read-only**. To enable writes:

```json
{
  "readOnly": false,
  "allowWrites": true
}
```

**Warning:** This lets the AI write files to your iPhone. Ensure you understand the security implications.

## Troubleshooting

### "Connection refused"
- Check your iPhone IP is correct
- Make sure OpenSSH is running on iPhone
- Try: `ssh mobile@YOUR_IP` manually first

### "Authentication failed"
- Your password is wrong
- Try: `ssh mobile@YOUR_IP` manually to verify password

### "Timeout"
- iPhone is offline or network is unstable
- Increase `connectTimeoutMs` in config if needed

### "Permission denied"
- The path is outside `allowedRoots` in config
- Or the file doesn't exist

### No logs?
- Check `logPath` value points to a writable directory
- Create the directory if it doesn't exist

## Environment Variables (Alternative to Config File)

You can skip the config file and use environment variables instead:

```powershell
$env:IOS_FILES_MCP_HOST = "192.168.1.23"
$env:IOS_FILES_MCP_USERNAME = "mobile"
$env:IOS_FILES_MCP_PASSWORD = "your-password"
npm start
```

Or in `.env`:
```
IOS_FILES_MCP_HOST=192.168.1.23
IOS_FILES_MCP_USERNAME=mobile
IOS_FILES_MCP_PASSWORD=your-password
```

Then run: `npm start`

---

**Still stuck?** Check the [README.md](README.md) for more details on USB SSH, hotspot connections, and other advanced setups.
