import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { publicError } from "./logger.js";
import type { OperationLogger } from "./logger.js";
import { ALL_HOOK_TYPES, FridaService } from "./fridaService.js";
import type { HookType, UiMatcher } from "./fridaService.js";

type ToolResult = CallToolResult;

function ok(value: unknown): ToolResult {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: "text", text }], isError: false };
}

function fail(value: unknown): ToolResult {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: "text", text }], isError: true };
}

function wrap(name: string, logger: OperationLogger, fn: () => Promise<unknown>): Promise<ToolResult> {
  const start = Date.now();
  return fn()
    .then((result) => {
      void logger.log({ operation: name, ok: true, durationMs: Date.now() - start });
      return ok(result);
    })
    .catch((error: unknown) => {
      const message = publicError(error);
      void logger.log({ operation: name, ok: false, error: message, durationMs: Date.now() - start });
      return fail({ error: message });
    });
}

const RO: ToolAnnotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true };
const INJECT: ToolAnnotations = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true };
const DANGEROUS: ToolAnnotations = { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true };
const HOOK_TYPE_ENUM = z.enum(ALL_HOOK_TYPES as [HookType, ...HookType[]]);

export function registerFridaTools(
  server: McpServer,
  logger: OperationLogger,
  fridaService: FridaService
): void {

  // ── ios_frida_check ──────────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_check",
    {
      description: "Detect Frida installation on the connected iOS device. Returns binary path, iOS version (16 rootful vs 17 rootless), and frida version string.",
      inputSchema: {},
      annotations: RO
    },
    () => wrap("ios_frida_check", logger, () => fridaService.detectFrida())
  );

  // ── ios_frida_list_processes ─────────────────────────────────────────────
  server.registerTool(
    "ios_frida_list_processes",
    {
      description: "List all running processes on the iOS device via frida-ps. Returns pid and name for each process.",
      inputSchema: {},
      annotations: RO
    },
    () => wrap("ios_frida_list_processes", logger, () => fridaService.listProcesses())
  );

  // ── ios_frida_list_apps ──────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_list_apps",
    {
      description: [
        "List all installed apps on the device via Frida + LSApplicationWorkspace (fast, no SFTP scan).",
        "Returns bundleId, name, bundlePath, dataPath, version, and shortVersion for each app.",
        "Prefer this over ios_list_apps / ios_find_app when Frida is available — it's instant."
      ].join("\n"),
      inputSchema: {},
      annotations: RO
    },
    () => wrap("ios_frida_list_apps", logger, () => fridaService.listApps())
  );

  // ── ios_frida_app_info ───────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_app_info",
    {
      description: [
        "Get detailed info about a specific installed app via Frida + LSApplicationProxy.",
        "Returns: bundleId, name, paths, signerIdentity, teamID, applicationType, entitlements,",
        "app group container URLs, and plugin list. Much faster than reading Info.plist over SFTP."
      ].join("\n"),
      inputSchema: {
        bundleId: z.string().min(1).describe("The app's bundle identifier (e.g. com.example.MyApp)")
      },
      annotations: RO
    },
    (args) => wrap("ios_frida_app_info", logger, () => fridaService.getAppInfo(args.bundleId))
  );

  // ── ios_frida_start_trace ────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_start_trace",
    {
      description: [
        "Attach Frida to a process and collect dynamic analysis events for a fixed duration.",
        "Returns structured events from the selected hook categories.",
        "",
        "target: process name (e.g. 'SpringBoard'), bundle ID (e.g. 'com.example.App'), or PID string.",
        "",
        "Hook categories:",
        "  network           - NSURLSession/NSURLConnection requests (URL, method, headers, body size)",
        "  request_building  - NSMutableURLRequest construction (set method/header/body)",
        "  keychain          - SecItem* operations (service, account, access group, class)",
        "  userdefaults      - NSUserDefaults reads and writes",
        "  sqlite            - sqlite3_exec / sqlite3_prepare SQL queries",
        "  webview           - WKWebView JS evaluation, navigation decisions, message handler calls",
        "  deeplinks         - UIApplication openURL / app delegate URL handling",
        "  ui_actions        - UIControl sendAction, gesture recognizer events",
        "  crypto            - CCCrypt, CCHmac, SecKey operations",
        "  jailbreak_detection - File existence checks, canOpenURL jailbreak schemes, ptrace, sysctl, dlopen"
      ].join("\n"),
      inputSchema: {
        target: z.string().min(1).describe("Process name, bundle ID, or PID"),
        hookTypes: z
          .array(HOOK_TYPE_ENUM)
          .min(1)
          .describe("One or more hook categories to enable"),
        durationSeconds: z
          .number()
          .int()
          .min(1)
          .max(120)
          .default(10)
          .describe("How long to collect events (1–120 seconds, default 10)")
      },
      annotations: INJECT
    },
    (args) =>
      wrap("ios_frida_start_trace", logger, () =>
        fridaService.startTrace(
          args.target,
          args.hookTypes as HookType[],
          (args.durationSeconds ?? 10) * 1000
        )
      )
  );

  // ── ios_frida_begin_session ──────────────────────────────────────────────
  server.registerTool(
    "ios_frida_begin_session",
    {
      description: [
        "Start a long-running Frida trace session in the background.",
        "Returns a sessionId. Use ios_frida_poll_events to retrieve accumulated events and ios_frida_end_session to stop.",
        "Useful when you want to perform actions on the device (e.g. tap buttons, navigate) while trace runs."
      ].join("\n"),
      inputSchema: {
        target: z.string().min(1).describe("Process name, bundle ID, or PID"),
        hookTypes: z
          .array(HOOK_TYPE_ENUM)
          .min(1)
          .describe("Hook categories to enable")
      },
      annotations: INJECT
    },
    (args) =>
      wrap("ios_frida_begin_session", logger, async () => {
        const sessionId = await fridaService.beginSession(
          args.target,
          args.hookTypes as HookType[]
        );
        return { sessionId, started: true };
      })
  );

  // ── ios_frida_poll_events ────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_poll_events",
    {
      description: "Retrieve events buffered in a background Frida session. Set clearAfterRead=true to drain the buffer (avoids duplicate events on repeated polls).",
      inputSchema: {
        sessionId: z.string().min(1).describe("Session ID from ios_frida_begin_session"),
        clearAfterRead: z
          .boolean()
          .default(false)
          .describe("Clear the buffer after returning events")
      },
      annotations: RO
    },
    (args) =>
      wrap("ios_frida_poll_events", logger, async () => {
        const events = fridaService.pollSession(args.sessionId, args.clearAfterRead ?? false);
        return { sessionId: args.sessionId, count: events.length, events };
      })
  );

  // ── ios_frida_end_session ────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_end_session",
    {
      description: "Stop a background Frida session and return all remaining events.",
      inputSchema: {
        sessionId: z.string().min(1).describe("Session ID from ios_frida_begin_session")
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }
    },
    (args) =>
      wrap("ios_frida_end_session", logger, async () => {
        const events = await fridaService.endSession(args.sessionId);
        return { sessionId: args.sessionId, count: events.length, events };
      })
  );

  // ── ios_frida_dump_ui ────────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_dump_ui",
    {
      description: [
        "Dump the full UIKit view hierarchy of a running app as a JSON tree.",
        "Each node includes: cls (class name), frame (x/y/w/h), label (accessibilityLabel),",
        "id (accessibilityIdentifier), title (UIButton currentTitle), text (UILabel/UITextField text),",
        "hidden, enabled, and children array.",
        "Use this to discover element labels/identifiers before calling ios_frida_tap_element."
      ].join("\n"),
      inputSchema: {
        target: z.string().min(1).describe("Process name, bundle ID, or PID")
      },
      annotations: RO
    },
    (args) =>
      wrap("ios_frida_dump_ui", logger, () => fridaService.dumpUi(args.target))
  );

  // ── ios_frida_tap_element ────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_tap_element",
    {
      description: [
        "Tap a UI element in a running app by matching its accessibility properties.",
        "Provide at least one matcher field. If multiple elements match, use index to select (0-based).",
        "Returns a 'tapped' event on success, 'not_found' if no match, or 'tap_failed' if element found but not tappable.",
        "",
        "Tip: Run ios_frida_dump_ui first to discover element labels and identifiers."
      ].join("\n"),
      inputSchema: {
        target: z.string().min(1).describe("Process name, bundle ID, or PID"),
        accessibilityLabel: z
          .string()
          .optional()
          .describe("Match by accessibilityLabel (case-insensitive)"),
        accessibilityIdentifier: z
          .string()
          .optional()
          .describe("Match by accessibilityIdentifier (exact)"),
        className: z
          .string()
          .optional()
          .describe("Match by UIKit class name (e.g. UIButton)"),
        title: z.string().optional().describe("Match UIButton by currentTitle (case-insensitive)"),
        text: z.string().optional().describe("Match UILabel/UITextField by text (case-insensitive)"),
        index: z
          .number()
          .int()
          .nonnegative()
          .default(0)
          .describe("0-based index when multiple elements match")
      },
      annotations: INJECT
    },
    (args) => {
      const matcher: UiMatcher = {
        accessibilityLabel: args.accessibilityLabel,
        accessibilityIdentifier: args.accessibilityIdentifier,
        className: args.className,
        title: args.title,
        text: args.text,
        index: args.index ?? 0
      };
      if (!matcher.accessibilityLabel && !matcher.accessibilityIdentifier && !matcher.className && !matcher.title && !matcher.text) {
        return Promise.resolve(fail({ error: "Provide at least one matcher: accessibilityLabel, accessibilityIdentifier, className, title, or text" }));
      }
      return wrap("ios_frida_tap_element", logger, () =>
        fridaService.tapElement(args.target, matcher)
      );
    }
  );

  // ── ios_frida_run_script ─────────────────────────────────────────────────
  server.registerTool(
    "ios_frida_run_script",
    {
      description: [
        "Execute a custom Frida JavaScript script in a target process and return all emitted events.",
        "The script runs with full Frida API access: Interceptor, ObjC, Memory, Module, send(), etc.",
        "Use send({type: '...', ...}) to emit structured events. Events are collected until durationSeconds elapses.",
        "",
        "Example script:",
        "  ObjC.schedule(ObjC.mainQueue, function() {",
        "    var vc = ObjC.classes.UIApplication.sharedApplication().keyWindow().rootViewController();",
        "    send({ type: 'info', class: vc.$className });",
        "  });"
      ].join("\n"),
      inputSchema: {
        target: z.string().min(1).describe("Process name, bundle ID, or PID"),
        script: z.string().min(1).describe("Frida JavaScript to execute in the target process"),
        durationSeconds: z
          .number()
          .int()
          .min(1)
          .max(120)
          .default(10)
          .describe("How long to wait for events (1–120 seconds)")
      },
      annotations: DANGEROUS
    },
    (args) =>
      wrap("ios_frida_run_script", logger, () =>
        fridaService.runScript(
          args.target,
          args.script,
          (args.durationSeconds ?? 10) * 1000
        )
      )
  );

  // ── ios_dynamic_analyze_app ───────────────────────────────────────────────
  server.registerTool(
    "ios_dynamic_analyze_app",
    {
      description: [
        "Business-friendly dynamic analysis workflow for an app:",
        "- launch the app",
        "- run a single trace session",
        "- optionally auto-tap common consent dialogs (Allow/OK/Continue)",
        "- return captured events",
        "",
        "Use follow-up questions on the returned events (URLs, headers, keychain, jailbreak checks, etc.)."
      ].join("\n"),
      inputSchema: {
        bundleId: z.string().min(1).describe("App bundle identifier (e.g. com.example.App)"),
        hookTypes: z
          .array(HOOK_TYPE_ENUM)
          .min(1)
          .default(["network", "request_building", "ui_actions"])
          .describe("Hook categories to enable"),
        durationSeconds: z
          .number()
          .int()
          .min(5)
          .max(60)
          .default(20)
          .describe("How long to observe after launch (5–60 seconds)"),
        tapCommonPrompts: z
          .boolean()
          .default(false)
          .describe("Try to tap common consent dialogs during the observation window")
      },
      annotations: INJECT
    },
    (args) =>
      wrap("ios_dynamic_analyze_app", logger, () =>
        fridaService.dynamicAnalyzeApp({
          bundleId: args.bundleId,
          hookTypes: args.hookTypes as HookType[],
          durationMs: (args.durationSeconds ?? 20) * 1000,
          tapCommonPrompts: args.tapCommonPrompts ?? false
        })
      )
  );

  // ── ios_dynamic_guided_start ──────────────────────────────────────────────
  server.registerTool(
    "ios_dynamic_guided_start",
    {
      description: [
        "Start a guided dynamic analysis session for an app.",
        "This launches/attaches hooks and immediately returns a sessionId so the user can manually interact",
        "(tap buttons, login, navigate screens) before collecting events."
      ].join("\n"),
      inputSchema: {
        bundleId: z.string().min(1).describe("App bundle identifier (e.g. com.example.App)"),
        hookTypes: z
          .array(HOOK_TYPE_ENUM)
          .min(1)
          .default(["network", "request_building", "keychain", "userdefaults", "sqlite", "webview", "deeplinks"])
          .describe("Hook categories to enable during manual interaction")
      },
      annotations: INJECT
    },
    (args) =>
      wrap("ios_dynamic_guided_start", logger, async () => {
        const launch = await fridaService.launchApp(args.bundleId);
        const sessionId = await fridaService.beginSession(args.bundleId, args.hookTypes as HookType[]);
        return {
          started: true,
          sessionId,
          launched: launch.launched,
          launchMethod: launch.method,
          nextStep:
            "Now interact with the app manually (press buttons, login, navigate), then call ios_dynamic_guided_collect with this sessionId."
        };
      })
  );

  // ── ios_dynamic_guided_collect ────────────────────────────────────────────
  server.registerTool(
    "ios_dynamic_guided_collect",
    {
      description: [
        "Collect events from a guided dynamic session after manual app interaction.",
        "Use stop=true when done to end the session and return final events."
      ].join("\n"),
      inputSchema: {
        sessionId: z.string().min(1).describe("Session ID returned by ios_dynamic_guided_start"),
        clearAfterRead: z
          .boolean()
          .default(true)
          .describe("Clear buffered events after reading (recommended for incremental collection)"),
        stop: z
          .boolean()
          .default(false)
          .describe("Stop/end the session after collecting")
      },
      annotations: RO
    },
    (args) =>
      wrap("ios_dynamic_guided_collect", logger, async () => {
        const events = fridaService.pollSession(args.sessionId, args.clearAfterRead ?? true);
        if (args.stop) {
          const tail = await fridaService.endSession(args.sessionId);
          const merged = [...events, ...tail];
          return {
            sessionId: args.sessionId,
            stopped: true,
            count: merged.length,
            events: merged
          };
        }
        return {
          sessionId: args.sessionId,
          stopped: false,
          count: events.length,
          events
        };
      })
  );
}
