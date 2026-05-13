import { describe, expect, it } from "vitest";
import { buildRemoteCommand, shQuote } from "./r2Runner.js";

describe("shQuote", () => {
  it("wraps a plain string in single quotes", () => {
    expect(shQuote("hello")).toBe("'hello'");
  });

  it("handles strings with spaces", () => {
    expect(shQuote("hello world")).toBe("'hello world'");
  });

  it("escapes embedded single quotes via POSIX form", () => {
    expect(shQuote("it's")).toBe("'it'\\''s'");
  });

  it("leaves double quotes untouched inside single-quoted runs", () => {
    expect(shQuote('say "hi"')).toBe(`'say "hi"'`);
  });

  it("escapes characters that would otherwise be expanded", () => {
    expect(shQuote("$PATH `cmd` $(x)")).toBe("'$PATH `cmd` $(x)'");
  });

  it("handles an empty string", () => {
    expect(shQuote("")).toBe("''");
  });

  it("handles a string of only single quotes", () => {
    expect(shQuote("'''")).toBe("''\\'''\\'''\\'''");
  });
});

describe("buildRemoteCommand", () => {
  it("joins quoted argv pieces with spaces", () => {
    expect(buildRemoteCommand("r2", ["-v"])).toBe("'r2' '-v'");
  });

  it("quotes paths with spaces", () => {
    expect(buildRemoteCommand("/usr/bin/r2", ["/var/My App.app/My App"])).toBe(
      "'/usr/bin/r2' '/var/My App.app/My App'"
    );
  });

  it("quotes paths with single quotes correctly", () => {
    expect(buildRemoteCommand("rabin2", ["/tmp/it's a file"])).toBe(
      "'rabin2' '/tmp/it'\\''s a file'"
    );
  });
});
