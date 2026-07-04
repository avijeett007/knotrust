/**
 * `knotrust init` argv parsing tests (P0-E7-T1).
 */

import { describe, expect, it } from "vitest";
import { parseInitArgs } from "./argv.js";

describe("parseInitArgs", () => {
  it("parses the bare client with all defaults", () => {
    const result = parseInitArgs(["claude"]);
    expect(result).toEqual({
      ok: true,
      args: {
        client: "claude",
        yes: false,
        dryRun: false,
        configFormat: "yaml",
      },
    });
  });

  it("parses codex", () => {
    const result = parseInitArgs(["codex"]);
    expect(result.ok).toBe(true);
    expect(result.ok && result.args.client).toBe("codex");
  });

  it("rejects a missing client", () => {
    const result = parseInitArgs([]);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toContain("missing client");
  });

  it("rejects an unknown client", () => {
    const result = parseInitArgs(["cursor"]);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toContain('unknown client "cursor"');
  });

  it("parses --yes and -y as the same flag", () => {
    expect(parseInitArgs(["claude", "--yes"])).toEqual({
      ok: true,
      args: {
        client: "claude",
        yes: true,
        dryRun: false,
        configFormat: "yaml",
      },
    });
    expect(parseInitArgs(["claude", "-y"])).toEqual({
      ok: true,
      args: {
        client: "claude",
        yes: true,
        dryRun: false,
        configFormat: "yaml",
      },
    });
  });

  it("parses --dry-run and its --diff alias", () => {
    expect(parseInitArgs(["claude", "--dry-run"]).ok && true).toBe(true);
    const a = parseInitArgs(["claude", "--dry-run"]);
    const b = parseInitArgs(["claude", "--diff"]);
    expect(a.ok && a.args.dryRun).toBe(true);
    expect(b.ok && b.args.dryRun).toBe(true);
  });

  it("parses --server <name>", () => {
    const result = parseInitArgs(["claude", "--server", "github"]);
    expect(result.ok && result.args.server).toBe("github");
  });

  it("rejects --server with no value", () => {
    const result = parseInitArgs(["claude", "--server"]);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toContain("--server requires a value");
  });

  it("parses --config-format json/yaml/ts", () => {
    for (const fmt of ["json", "yaml", "ts"] as const) {
      const result = parseInitArgs(["claude", "--config-format", fmt]);
      expect(result.ok && result.args.configFormat).toBe(fmt);
    }
  });

  it("rejects an unknown --config-format value", () => {
    const result = parseInitArgs(["claude", "--config-format", "toml"]);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toContain(
      'unknown --config-format "toml"',
    );
  });

  it("rejects --config-format with no value", () => {
    const result = parseInitArgs(["claude", "--config-format"]);
    expect(result.ok).toBe(false);
  });

  it("rejects an unrecognized flag", () => {
    const result = parseInitArgs(["claude", "--bogus"]);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toContain('unknown flag "--bogus"');
  });

  it("combines multiple flags together", () => {
    const result = parseInitArgs([
      "codex",
      "--server",
      "fs",
      "--config-format",
      "json",
      "--yes",
    ]);
    expect(result).toEqual({
      ok: true,
      args: {
        client: "codex",
        yes: true,
        dryRun: false,
        server: "fs",
        configFormat: "json",
      },
    });
  });
});
