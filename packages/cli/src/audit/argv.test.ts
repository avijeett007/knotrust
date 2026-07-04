/**
 * `audit/argv.ts` unit tests (P0-E4-T4, R122) — pure argv parsing for
 * `knotrust audit list|tail|query|verify`.
 */

import { describe, expect, it } from "vitest";
import { parseAuditArgs } from "./argv.js";

describe("parseAuditArgs() — subcommand dispatch", () => {
  it("requires a subcommand", () => {
    const result = parseAuditArgs([]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("requires a subcommand");
  });

  it("rejects an unknown subcommand", () => {
    const result = parseAuditArgs(["bogus"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown subcommand");
  });
});

describe("parseAuditArgs(['list'|'tail', ...]) — R122 aliases", () => {
  it.each([
    "list",
    "tail",
  ] as const)("%s defaults to limit 50, json false", (sub) => {
    const result = parseAuditArgs([sub]);
    expect(result).toEqual({
      ok: true,
      command: { kind: sub, args: { limit: 50, json: false } },
    });
  });

  it.each(["list", "tail"] as const)("%s -n <count> sets the limit", (sub) => {
    const result = parseAuditArgs([sub, "-n", "10"]);
    expect(result).toEqual({
      ok: true,
      command: { kind: sub, args: { limit: 10, json: false } },
    });
  });

  it.each([
    "list",
    "tail",
  ] as const)("%s --limit <count> is a synonym for -n", (sub) => {
    const result = parseAuditArgs([sub, "--limit", "5"]);
    expect(result).toEqual({
      ok: true,
      command: { kind: sub, args: { limit: 5, json: false } },
    });
  });

  it.each(["list", "tail"] as const)("%s --json sets json true", (sub) => {
    const result = parseAuditArgs([sub, "--json"]);
    expect(result).toEqual({
      ok: true,
      command: { kind: sub, args: { limit: 50, json: true } },
    });
  });

  it("rejects a non-positive-integer -n", () => {
    for (const bad of ["0", "-1", "abc", "1.5"]) {
      const result = parseAuditArgs(["tail", "-n", bad]);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toContain("invalid count");
    }
  });

  it("rejects -n with no value", () => {
    const result = parseAuditArgs(["list", "-n"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("requires a value");
  });

  it("rejects an unknown flag", () => {
    const result = parseAuditArgs(["tail", "--bogus"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown flag");
  });
});

describe("parseAuditArgs(['query', ...])", () => {
  it("defaults to no filters, json false", () => {
    const result = parseAuditArgs(["query"]);
    expect(result).toEqual({
      ok: true,
      command: { kind: "query", args: { json: false } },
    });
  });

  it("parses --tool --outcome --tier --agent --server --json together", () => {
    const result = parseAuditArgs([
      "query",
      "--tool",
      "github.*",
      "--outcome",
      "deny",
      "--tier",
      "critical",
      "--agent",
      "codex-cli",
      "--server",
      "github",
      "--json",
    ]);
    expect(result).toEqual({
      ok: true,
      command: {
        kind: "query",
        args: {
          tool: "github.*",
          outcome: "deny",
          tier: "critical",
          agent: "codex-cli",
          server: "github",
          json: true,
        },
      },
    });
  });

  it("parses --since as a duration into a ParsedSince", () => {
    const result = parseAuditArgs(["query", "--since", "1h"]);
    expect(result).toEqual({
      ok: true,
      command: {
        kind: "query",
        args: { since: { kind: "duration", seconds: 3_600 }, json: false },
      },
    });
  });

  it("parses --since as an ISO timestamp into a ParsedSince", () => {
    const result = parseAuditArgs([
      "query",
      "--since",
      "2026-07-01T00:00:00.000Z",
    ]);
    expect(result).toEqual({
      ok: true,
      command: {
        kind: "query",
        args: {
          since: {
            kind: "timestamp",
            epochMs: Date.parse("2026-07-01T00:00:00.000Z"),
          },
          json: false,
        },
      },
    });
  });

  it("rejects an invalid --outcome", () => {
    const result = parseAuditArgs(["query", "--outcome", "bogus"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown --outcome");
  });

  it("rejects an invalid --tier", () => {
    const result = parseAuditArgs(["query", "--tier", "bogus"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown --tier");
  });

  it("rejects an invalid --since", () => {
    const result = parseAuditArgs(["query", "--since", "not-a-duration"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("invalid --since value");
  });

  it("rejects a value-taking flag with no value", () => {
    for (const flag of [
      "--tool",
      "--outcome",
      "--tier",
      "--since",
      "--agent",
      "--server",
    ]) {
      const result = parseAuditArgs(["query", flag]);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toContain("requires a value");
    }
  });

  it("rejects an unknown flag", () => {
    const result = parseAuditArgs(["query", "--bogus"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown flag");
  });
});

describe("parseAuditArgs(['verify', ...])", () => {
  it("takes no flags", () => {
    expect(parseAuditArgs(["verify"])).toEqual({
      ok: true,
      command: { kind: "verify" },
    });
  });

  it("rejects any extra token", () => {
    const result = parseAuditArgs(["verify", "--json"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("unknown flag");
  });
});
