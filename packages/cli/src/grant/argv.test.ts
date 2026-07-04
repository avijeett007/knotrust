/**
 * P0-E7-T2 — `grant`/`grant list`/`revoke` argv parsing acceptance
 * (R111/R113/R114), including the named acceptance: `--tier-cap critical`
 * is refused without `--i-understand-critical`.
 */

import { describe, expect, it } from "vitest";
import {
  parseGrantListArgs,
  parseGrantMintArgs,
  parseRevokeArgs,
} from "./argv.js";

describe("parseGrantMintArgs (R111)", () => {
  it("parses required flags with documented defaults", () => {
    const result = parseGrantMintArgs([
      "--tool",
      "github.*",
      "--server",
      "github-mcp",
    ]);
    expect(result).toEqual({
      ok: true,
      args: {
        tool: "github.*",
        server: "github-mcp",
        agent: "*",
        tierCap: "sensitive",
        ttlSeconds: 2_592_000,
        yes: false,
      },
    });
  });

  it("parses every flag when supplied", () => {
    const result = parseGrantMintArgs([
      "--tool",
      "stripe.create_refund",
      "--server",
      "stripe-mcp",
      "--agent",
      "codex-cli",
      "--tier-cap",
      "routine",
      "--expires",
      "12h",
      "--resource",
      "stripe_charge:ch_*",
      "--yes",
    ]);
    expect(result).toEqual({
      ok: true,
      args: {
        tool: "stripe.create_refund",
        server: "stripe-mcp",
        agent: "codex-cli",
        tierCap: "routine",
        ttlSeconds: 43_200,
        resource: "stripe_charge:ch_*",
        yes: true,
      },
    });
  });

  it("requires --tool", () => {
    const result = parseGrantMintArgs(["--server", "github-mcp"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("--tool is required");
  });

  it("requires --server", () => {
    const result = parseGrantMintArgs(["--tool", "github.*"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("--server is required");
  });

  it("rejects an unknown --tier-cap value", () => {
    const result = parseGrantMintArgs([
      "--tool",
      "github.*",
      "--server",
      "github-mcp",
      "--tier-cap",
      "extreme",
    ]);
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error).toContain('unknown --tier-cap "extreme"');
  });

  it("rejects a malformed --expires with a clean error", () => {
    const result = parseGrantMintArgs([
      "--tool",
      "github.*",
      "--server",
      "github-mcp",
      "--expires",
      "not-a-duration",
    ]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("invalid duration");
  });

  it("rejects an unknown flag", () => {
    const result = parseGrantMintArgs([
      "--tool",
      "github.*",
      "--server",
      "s",
      "--bogus",
    ]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('unknown flag "--bogus"');
  });

  // --- the named acceptance: --tier-cap critical refused without the flag ---
  it("REFUSES --tier-cap critical without --i-understand-critical", () => {
    const result = parseGrantMintArgs([
      "--tool",
      "stripe.refund_all",
      "--server",
      "stripe-mcp",
      "--tier-cap",
      "critical",
    ]);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("--i-understand-critical");
      expect(result.error).toContain("critical");
    }
  });

  it("ACCEPTS --tier-cap critical when --i-understand-critical is given", () => {
    const result = parseGrantMintArgs([
      "--tool",
      "stripe.refund_all",
      "--server",
      "stripe-mcp",
      "--tier-cap",
      "critical",
      "--i-understand-critical",
    ]);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.args.tierCap).toBe("critical");
  });
});

describe("parseGrantListArgs (R113)", () => {
  it("defaults --json to false", () => {
    expect(parseGrantListArgs([])).toEqual({ ok: true, args: { json: false } });
  });
  it("parses --json", () => {
    expect(parseGrantListArgs(["--json"])).toEqual({
      ok: true,
      args: { json: true },
    });
  });
  it("rejects an unknown flag", () => {
    const result = parseGrantListArgs(["--bogus"]);
    expect(result.ok).toBe(false);
  });
});

describe("parseRevokeArgs (R114)", () => {
  it("parses a bare jti positional", () => {
    expect(parseRevokeArgs(["01JZTHEJTI"])).toEqual({
      ok: true,
      args: { selector: { jti: "01JZTHEJTI" }, yes: false },
    });
  });
  it("parses --tool", () => {
    expect(parseRevokeArgs(["--tool", "github.*", "--yes"])).toEqual({
      ok: true,
      args: { selector: { tool: "github.*" }, yes: true },
    });
  });
  it("parses --all", () => {
    expect(parseRevokeArgs(["--all"])).toEqual({
      ok: true,
      args: { selector: { all: true }, yes: false },
    });
  });
  it("rejects no selector at all", () => {
    const result = parseRevokeArgs([]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("requires a jti");
  });
  it("rejects more than one selector", () => {
    const result = parseRevokeArgs(["01JZTHEJTI", "--all"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("exactly one of");
  });
  it("rejects an unsafe jti", () => {
    const result = parseRevokeArgs(["../etc/passwd"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("invalid jti");
  });
  it("rejects more than one jti positional", () => {
    const result = parseRevokeArgs(["01JZONE", "01JZTWO"]);
    expect(result.ok).toBe(false);
  });
});
