/**
 * P0-E7-T2 — formatting/matching helper unit tests (R111/R113/R116). The
 * "destructive-word-in-confirmation" acceptance is proven here at the pure
 * `buildGrantConfirmationText` level (fast, no store/keystore needed); the
 * headline e2e also re-proves it through the real CLI command.
 */

import type { ToolInventory } from "@knotrust/proxy-stdio";
import { describe, expect, it } from "vitest";
import {
  buildGrantConfirmationText,
  buildRevokeConfirmationText,
  deriveServerLabel,
  describeResourceScope,
  formatAbsolute,
  formatDurationShort,
  formatRelativeShort,
  isKnownDestructive,
  parseResourceScope,
  shortJti,
  toolPatternMatches,
  UNSCOPED_SERVER_LABEL,
} from "./format.js";

describe("toolPatternMatches", () => {
  it("matches the lone wildcard against anything", () => {
    expect(toolPatternMatches("*", "github.create_issue")).toBe(true);
  });
  it("matches a trailing-glob namespace pattern", () => {
    expect(toolPatternMatches("github.*", "github.create_issue")).toBe(true);
    expect(toolPatternMatches("github.*", "stripe.create_refund")).toBe(false);
  });
  it("matches exact literal only, otherwise", () => {
    expect(
      toolPatternMatches("stripe.create_refund", "stripe.create_refund"),
    ).toBe(true);
    expect(
      toolPatternMatches("stripe.create_refund", "stripe.create_refund_v2"),
    ).toBe(false);
  });
});

describe("isKnownDestructive (R111)", () => {
  const inventory: ToolInventory = {
    "github.delete_repo": {
      annotations: {
        trusted: false,
        source: "server_advertised",
        destructiveHint: true,
      },
      inputSchemaHash: "sha256:x",
    },
    "github.create_issue": {
      annotations: {
        trusted: false,
        source: "server_advertised",
        destructiveHint: false,
      },
      inputSchemaHash: "sha256:y",
    },
  };

  it("is false when no inventory has ever been captured", () => {
    expect(isKnownDestructive(undefined, "github.*")).toBe(false);
  });

  it("is true when the exact tool is known destructive", () => {
    expect(isKnownDestructive(inventory, "github.delete_repo")).toBe(true);
  });

  it("is true when a glob pattern covers a known-destructive tool", () => {
    expect(isKnownDestructive(inventory, "github.*")).toBe(true);
  });

  it("is false when every covered tool is known non-destructive", () => {
    expect(isKnownDestructive(inventory, "github.create_issue")).toBe(false);
  });
});

describe("parseResourceScope / describeResourceScope (R111)", () => {
  it("parses a colon-separated type:idPattern", () => {
    expect(parseResourceScope("github_repo:kno2gether/*")).toEqual({
      resourceType: "github_repo",
      idPattern: "kno2gether/*",
    });
  });
  it("parses a bare idPattern with no colon", () => {
    expect(parseResourceScope("ch_*")).toEqual({ idPattern: "ch_*" });
  });
  it("describes an unscoped grant in plain words", () => {
    expect(describeResourceScope({})).toBe(
      "any resource (no scope restriction)",
    );
  });
  it("describes a scoped grant in plain words", () => {
    expect(
      describeResourceScope({
        resourceType: "github_repo",
        idPattern: "kno2gether/*",
      }),
    ).toBe('type=github_repo, id matches "kno2gether/*"');
  });
});

describe("deriveServerLabel", () => {
  it("derives the leading dot-namespace segment", () => {
    expect(deriveServerLabel("github.create_issue")).toBe("github");
    expect(deriveServerLabel("github.*")).toBe("github");
  });
  it("is the wildcard itself for a bare *", () => {
    expect(deriveServerLabel("*")).toBe("*");
  });
  it("falls back to the unscoped label for a flat (non-namespaced) tool name", () => {
    expect(deriveServerLabel("routine_tool")).toBe(UNSCOPED_SERVER_LABEL);
  });
});

describe("formatDurationShort / formatRelativeShort / formatAbsolute (R113)", () => {
  it("floors to the largest whole unit", () => {
    expect(formatDurationShort(29 * 86_400)).toBe("29d");
    expect(formatDurationShort(5 * 3_600)).toBe("5h");
    expect(formatDurationShort(10 * 60)).toBe("10m");
    expect(formatDurationShort(30)).toBe("30s");
    expect(formatDurationShort(0)).toBe("0s");
  });

  it("formats a relative expiry as 'in <duration>'", () => {
    expect(formatRelativeShort(1_000, 1_000 + 29 * 86_400)).toBe("in 29d");
  });

  it("reports 'expired' at and after exp", () => {
    expect(formatRelativeShort(1_000, 1_000)).toBe("expired");
    expect(formatRelativeShort(2_000, 1_000)).toBe("expired");
  });

  it("renders exact RFC 3339 for a known epoch", () => {
    expect(formatAbsolute(0)).toBe("1970-01-01T00:00:00.000Z");
  });
});

describe("shortJti", () => {
  it("passes short values through unchanged", () => {
    expect(shortJti("short")).toBe("short");
  });
  it("truncates long ULIDs with an ellipsis", () => {
    expect(shortJti("01JZ8QGRANT0000000000000A")).toBe("01JZ8QGRAN…");
  });
});

describe("buildGrantConfirmationText (R111, R116)", () => {
  const base = {
    tool: "github.create_issue",
    server: "github-mcp",
    agentPattern: "*",
    tierCap: "sensitive" as const,
    ttlSeconds: 2_592_000,
    expEpochSeconds: 1_000_000 + 2_592_000,
    scope: {},
    destructive: false,
  };

  it("shows tool/server/agent/tier-cap/expiry in plain words", () => {
    const text = buildGrantConfirmationText(base);
    expect(text).toContain("github.create_issue");
    expect(text).toContain("github-mcp");
    expect(text).toContain("any agent (*)");
    expect(text).toContain("sensitive");
    expect(text).toContain("30d from now");
    expect(text).toContain("any resource (no scope restriction)");
  });

  it("includes the word 'destructive' when the tool is known destructive", () => {
    const text = buildGrantConfirmationText({ ...base, destructive: true });
    expect(text.toLowerCase()).toContain("destructive");
  });

  it("never mentions 'destructive' when the tool is not known destructive", () => {
    const text = buildGrantConfirmationText(base);
    expect(text.toLowerCase()).not.toContain("destructive");
  });
});

describe("buildRevokeConfirmationText (R114, R116)", () => {
  it("names the jti selector and lists the one candidate", () => {
    const text = buildRevokeConfirmationText({ jti: "01JZTHEJTI" }, [
      {
        jti: "01JZTHEJTI",
        tool: "github.create_issue",
        tierCap: "sensitive",
        agentPattern: "*",
      },
    ]);
    expect(text).toContain("01JZTHEJTI");
    expect(text).toContain("github.create_issue");
  });

  it("names the --tool selector and lists every candidate", () => {
    const text = buildRevokeConfirmationText({ tool: "github.*" }, [
      { jti: "a", tool: "github.*", tierCap: "sensitive", agentPattern: "*" },
      {
        jti: "b",
        tool: "github.*",
        tierCap: "sensitive",
        agentPattern: "codex-cli",
      },
    ]);
    expect(text).toContain('exactly "github.*"');
    expect(text).toContain("2 grant(s)");
    expect(text).toContain("codex-cli");
  });

  it("names the --all selector", () => {
    const text = buildRevokeConfirmationText({ all: true }, []);
    expect(text).toContain("ALL active grants");
  });
});
