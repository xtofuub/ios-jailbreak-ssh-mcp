# ios-files-mcp App File Lookup Skill

Use this guide when the user asks to inspect files for an App Store app on their own iOS device through `ios-files-mcp`, for example "find YouTube's Info.plist", "look at app directories for YouTube", "where is this app's data container", or "inspect an app bundle".

## Core Rules

- Use MCP tools only inside the configured allowed roots.
- If connection, empty roots, or local setup looks wrong, run `ios_connection_doctor()` first.
- Use `ios_mcp_config_status()` when the MCP package/config install might be wrong.
- Use `ios_snapshot_app(bundleId)` for a first structured pass on a known app bundle id.
- Prefer `ios_resolve_app_container(bundleId)` when the bundle id is known, or `ios_find_app(query)` / `ios_list_apps(query)` for app discovery. Do not use recursive `ios_search_files` to find an app bundle unless the app tools fail.
- If expected app directories appear empty, run `ios_diagnose_roots()` before trying broader searches.
- Do not repeat the same `ios_search_files` call. If a search is needed, start with small limits like `maxResults=10` and `maxDepth=2`.
- Use `includeMetadata=false` unless file size or modified time is needed.
- Prefer `ios_list_dir`, `ios_stat`, `ios_read_plist`, and targeted `ios_read_file` calls before any write operation.
- For large files or file export to the computer, use `ios_download_file(remotePath, localPath, overwrite)` or `ios_zip_download(paths, localPath, overwrite)` instead of `ios_read_file`.
- For logs and large text files, use `ios_tail_file`, `ios_read_last_lines`, or `ios_read_file_chunk`.
- For SQLite databases, use `ios_read_sqlite_schema(path)` first, then `ios_query_sqlite(path, sql, limit)` with read-only SQL. Do not dump whole database files into chat.
- For React Native bundles, use `ios_inspect_js_bundle(path)` first. Use `ios_list_hermes_decoders()` if Hermes decoding fails. Use `ios_decode_js_bundle(path, ...)` for plain `.jsbundle` beautifying or Hermes bytecode decoding through `hbc-decompiler`, `hbc-disassembler`, `hermesc`, `hbctool`, or a custom command such as `jsc2llvm`.
- For write-capable tools, expect a two-step approval flow. The first call returns an `approvalId` and does not write. Only retry with `approvalId` after the user explicitly approves the exact operation.
- Treat app sandbox files as private. Do not hunt for passwords, auth tokens, cookies, session databases, or keychain material unless the user explicitly asks for a specific file on their own device.
- Do not request broader roots for `/var/Keychains`, `/private/var/db`, `/System`, `/usr`, `/bin`, or `/sbin`.
- Use `ios_read_plist(path)` for `Info.plist` and container metadata plists. Avoid dumping binary plist bytes with `ios_read_file`.

## Important iOS App Locations

Do not assume every app-related directory starts under `/var/mobile`.

Use this split:

- App data starts under `/var/mobile` or `/private/var/mobile`.
- App Store `.app` bundles start under `/var/containers/Bundle/Application` or `/private/var/containers/Bundle/Application`.
- `/var` is often effectively the shorter view of `/private/var` on iOS, so both forms may point at the same underlying files.

App Store app bundles:

```text
/private/var/containers/Bundle/Application/<UUID>/<AppName>.app
/var/containers/Bundle/Application/<UUID>/<AppName>.app
```

The bundle is where app code and static metadata usually live. Common targets:

```text
<AppName>.app/Info.plist
<AppName>.app/PkgInfo
<AppName>.app/_CodeSignature/CodeResources
<AppName>.app/Frameworks
<AppName>.app/PlugIns
<AppName>.app/embedded.mobileprovision
```

App data containers:

```text
/private/var/mobile/Containers/Data/Application/<UUID>
/var/mobile/Containers/Data/Application/<UUID>
```

The data container is where app-created user data, settings, caches, and databases usually live. Common targets:

```text
Documents
Library/Preferences
Library/Preferences/<bundle-id>.plist
Library/Application Support
Library/Caches
Library/WebKit
Library/Cookies
tmp
.com.apple.mobile_container_manager.metadata.plist
```

Shared app group containers:

```text
/private/var/mobile/Containers/Shared/AppGroup/<UUID>
/var/mobile/Containers/Shared/AppGroup/<UUID>
```

These may contain shared data used by extensions, widgets, or related apps. Common target:

```text
.com.apple.mobile_container_manager.metadata.plist
```

## Lookup Workflow

1. Identify the app name and likely bundle identifier.

   For YouTube, likely values are:

   ```text
   App name: YouTube
   Bundle id: com.google.ios.youtube
   ```

2. Find the app bundle first.

   Start with:

   ```text
   ios_find_app("YouTube")
   ```

   Do not start by recursively searching `/var/mobile` for `YouTube.app`; that usually searches app data containers and may miss the actual installed app bundle.

   You can also use the bundle id directly:

   ```text
   ios_find_app("com.google.ios.youtube")
   ios_resolve_app_container("com.google.ios.youtube")
   ```

   Only if `ios_find_app` fails, use targeted shallow listing before any recursive search:

   ```text
   ios_list_dir("/private/var/containers/Bundle/Application")
   ```

3. Inspect the bundle directory.

   After finding a path like:

   ```text
   /private/var/containers/Bundle/Application/<UUID>/YouTube.app
   ```

   Use:

   ```text
   ios_list_dir("/private/var/containers/Bundle/Application/<UUID>/YouTube.app")
   ios_stat("/private/var/containers/Bundle/Application/<UUID>/YouTube.app/Info.plist")
   ios_read_plist("/private/var/containers/Bundle/Application/<UUID>/YouTube.app/Info.plist")
   ```

4. Find the matching data container.

   `ios_find_app` and `ios_resolve_app_container` already check data container metadata and report matches when they can. App data containers use UUID directory names, so the directory name usually does not say "YouTube". The metadata file inside each data container maps it back to the bundle id:

   ```text
   /private/var/mobile/Containers/Data/Application/<UUID>/.com.apple.mobile_container_manager.metadata.plist
   ```

   If manual follow-up is needed, list from:

   ```text
   ios_list_dir("/private/var/mobile/Containers/Data/Application")
   ```

   Then inspect candidate metadata files with `ios_read_plist` until one identifies `com.google.ios.youtube`.

5. Inspect the matched data container cautiously.

   Once the matching container is known, start with:

   ```text
   ios_list_dir("/private/var/mobile/Containers/Data/Application/<UUID>")
   ios_list_dir("/private/var/mobile/Containers/Data/Application/<UUID>/Library")
   ios_list_dir("/private/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences")
   ios_list_preferences("com.google.ios.youtube")
   ios_stat("/private/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.google.ios.youtube.plist")
   ```

   Read exact files only after explaining what they likely contain.

6. Check shared app groups only if needed.

   Start with:

   ```text
   ios_list_dir("/private/var/mobile/Containers/Shared/AppGroup")
   ```

   `ios_find_app` already checks app group metadata and reports matches when it can. If manual follow-up is needed, inspect each app group metadata plist with `ios_read_plist` for identifiers related to the app or vendor, such as `google` or `youtube`.

## Sensitive App Files

These files can be useful for debugging but may contain private data. Ask before reading them, summarize file names first, and avoid bulk dumping content:

```text
Library/Preferences/*.plist
Library/Application Support/**/*.db
Library/Application Support/**/*.sqlite
Library/Caches/**/*.db
Library/Caches/**/*.sqlite
Library/Cookies
Library/WebKit
Documents
*.jsbundle
*.hbc
```

Keychain secrets are not stored in the app bundle or ordinary data container in a simple readable form. `ios-files-mcp` blocks keychain roots by default; keep that behavior.

## Example: YouTube

Use this sequence for a normal YouTube inspection:

```text
ios_find_app("YouTube")
ios_resolve_app_container("com.google.ios.youtube")
ios_list_dir("/private/var/containers/Bundle/Application/<UUID>/YouTube.app")
ios_stat("/private/var/containers/Bundle/Application/<UUID>/YouTube.app/Info.plist")
ios_read_plist("/private/var/containers/Bundle/Application/<UUID>/YouTube.app/Info.plist")
```

Use the `dataContainerMatches` result from `ios_find_app`. If it is empty, manually locate the data container whose metadata identifies:

```text
com.google.ios.youtube
```

After the data container is identified, inspect:

```text
Library/Preferences
Library/Application Support
Library/Caches
Documents
tmp
```

Keep the first pass read-only and path-focused. Only read content from specific files the user has approved or clearly requested.
