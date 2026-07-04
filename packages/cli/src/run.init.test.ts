/**
 * `knotrust init` dispatch wiring, exercised through the REAL `runCli` argv
 * path (P0-E7-T1) — `command.test.ts` covers `runInit` itself exhaustively
 * with injected candidates; this file proves `run.ts`'s dispatcher actually
 * routes `"init"` there with the REAL (non-injected) default path resolver.
 *
 * `init claude`'s default candidate order checks `<cwd>/.mcp.json` FIRST
 * (`client-config.ts`'s `defaultClientConfigCandidates`) — pointing `io.cwd`
 * at a throwaway temp dir with its own `.mcp.json` means this test's `init`
 * run resolves entirely inside that temp dir and never reaches (or even
 * stats) the real global Claude Desktop config path (R106).
 */

import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { runCli } from "./run.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

describe("knotrust CLI — `init` dispatch (P0-E7-T1)", () => {
  it("routes a bad `init` invocation to a usage error, exit 2 — never reaches runInit", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["init"], {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr,
      installSignalHandlers: false,
    });
    expect(code).toBe(2);
    expect(getErr()).toContain("missing client");
  });

  it("routes an unknown client name to a usage error, exit 2", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["init", "bogus-client"], {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr,
      installSignalHandlers: false,
    });
    expect(code).toBe(2);
    expect(getErr()).toContain('unknown client "bogus-client"');
  });

  it("`init claude --dry-run` resolves the REAL default `.mcp.json` candidate under a temp cwd and prints a diff, writing nothing", async () => {
    const tmp = mkdtempSync(path.join(tmpdir(), "knotrust-run-init-e2e-"));
    const mcpJsonPath = path.join(tmp, ".mcp.json");
    const before = `${JSON.stringify(
      { mcpServers: { echo: { command: "node", args: ["echo.js"] } } },
      null,
      2,
    )}\n`;
    writeFileSync(mcpJsonPath, before);

    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const getOut = collect(stdout);

    try {
      const code = await runCli(["init", "claude", "--yes", "--dry-run"], {
        stdin: new PassThrough(),
        stdout,
        stderr,
        installSignalHandlers: false,
        cwd: tmp,
      });
      expect(code).toBe(0);
      expect(getOut()).toContain("claude-code config");
      expect(getOut()).toContain(mcpJsonPath);
      expect(getOut()).toContain("dry run — no changes written");
      // Genuinely nothing written.
      expect(readFileSync(mcpJsonPath, "utf8")).toBe(before);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }, 15_000);

  it("runCli's top-level guard (fix round 1) catches a genuinely unexpected error from `init` cleanly — no raw stack trace, exit 1", async () => {
    const tmp = mkdtempSync(path.join(tmpdir(), "knotrust-run-init-guard-"));
    // A DIRECTORY sitting where `.mcp.json` is expected: `existsSync` still
    // resolves it as "found", so `readClientConfig` proceeds to
    // `readFileSync` it and throws a raw `EISDIR` — an error type neither
    // `ClientConfigNotFoundError` nor `ClientConfigParseError`, so
    // `init/command.ts`'s own narrow catch re-throws it. Before this fix's
    // top-level guard in `runCli`, this would propagate uncaught all the way
    // to `bin.ts` as a raw stack trace.
    mkdirSync(path.join(tmp, ".mcp.json"));

    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const getErr = collect(stderr);

    try {
      const code = await runCli(["init", "claude", "--yes"], {
        stdin: new PassThrough(),
        stdout,
        stderr,
        installSignalHandlers: false,
        cwd: tmp,
      });
      expect(code).toBe(1);
      const err = getErr();
      expect(err).toContain("knotrust:");
      expect(err).toContain("EISDIR");
      // A single clean line — no raw multi-frame Node stack trace.
      expect(err.trim().split("\n").length).toBe(1);
      expect(err).not.toMatch(/\n\s*at .+:\d+:\d+/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
