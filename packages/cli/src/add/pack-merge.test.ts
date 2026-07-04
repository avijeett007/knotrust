/**
 * `add pack` — the precedence-respecting merge (P0-E7-T3, R118/R120). Pure
 * unit tests over `mergePackIntoTools`; no filesystem, no config loading —
 * see `pack-command.test.ts`/`precedence.test.ts` for the end-to-end
 * (fixture-pack + temp-config + real decider) proof.
 */

import type { ToolEntry } from "@knotrust/store";
import { describe, expect, it } from "vitest";
import { mergePackIntoTools } from "./pack-merge.js";
import type { PackToolEntry } from "./pack-schema.js";

function pack(tools: Record<string, PackToolEntry>) {
  return tools;
}

describe("mergePackIntoTools — NEW (R118/R119)", () => {
  it("adds a tool absent from the existing config as source: pack, with a NEW diff line", () => {
    const result = mergePackIntoTools(
      undefined,
      pack({
        "github.delete_repo": { tier: "critical" },
      }),
    );

    expect(result.tools["github.delete_repo"]).toEqual({
      tier: "critical",
      source: "pack",
    });
    expect(result.changed).toBe(true);
    expect(result.diff).toEqual([
      {
        kind: "new",
        tool: "github.delete_repo",
        text: "NEW: github.delete_repo → critical (from pack)",
      },
    ]);
  });

  it("carries mapping through onto the stamped ToolEntry (never explicitAllow/explicitDeny — PackToolEntrySchema rejects both, fix round 1 FIX 1)", () => {
    const result = mergePackIntoTools(
      undefined,
      pack({
        "stripe.create_refund": {
          tier: "sensitive",
          mapping: {
            resourceType: "charge",
            resourceId: "arguments.charge_id",
          },
        },
      }),
    );
    expect(result.tools["stripe.create_refund"]).toEqual({
      tier: "sensitive",
      source: "pack",
      mapping: { resourceType: "charge", resourceId: "arguments.charge_id" },
    });
  });
});

describe("mergePackIntoTools — CHANGE: pack overrides an annotation-seeded entry (R118)", () => {
  it("overrides a source: annotation entry, emitting a CHANGE line with old -> new tier", () => {
    const existing: Record<string, ToolEntry> = {
      "github.create_issue": { tier: "sensitive", source: "annotation" },
    };
    const result = mergePackIntoTools(
      existing,
      pack({
        "github.create_issue": { tier: "routine" },
      }),
    );

    expect(result.tools["github.create_issue"]).toEqual({
      tier: "routine",
      source: "pack",
    });
    expect(result.changed).toBe(true);
    expect(result.diff).toEqual([
      {
        kind: "change",
        tool: "github.create_issue",
        text: "CHANGE: github.create_issue sensitive → routine (pack)",
      },
    ]);
  });

  it("overrides a STALE source: pack entry when the pack file's tier has since changed (re-applying an updated pack)", () => {
    const existing: Record<string, ToolEntry> = {
      "github.create_issue": { tier: "sensitive", source: "pack" },
    };
    const result = mergePackIntoTools(
      existing,
      pack({
        "github.create_issue": { tier: "critical" },
      }),
    );
    expect(result.tools["github.create_issue"]).toEqual({
      tier: "critical",
      source: "pack",
    });
    expect(result.changed).toBe(true);
    expect(result.diff[0]?.kind).toBe("change");
  });
});

describe("mergePackIntoTools — KEPT: pack NEVER overrides a user entry (R118, the precedence acceptance)", () => {
  it("skips a source: user entry entirely, unchanged in the output, with a KEPT diff line naming both tiers", () => {
    const existing: Record<string, ToolEntry> = {
      "github.push": { tier: "sensitive", source: "user", explicitAllow: true },
    };
    const result = mergePackIntoTools(
      existing,
      pack({
        "github.push": { tier: "routine" },
      }),
    );

    // Untouched — same object values as the original user entry.
    expect(result.tools["github.push"]).toEqual({
      tier: "sensitive",
      source: "user",
      explicitAllow: true,
    });
    expect(result.changed).toBe(false);
    expect(result.diff).toEqual([
      {
        kind: "kept",
        tool: "github.push",
        text: "KEPT: github.push → your user setting sensitive (pack suggested routine)",
      },
    ]);
  });

  it("KEPT fires even when the user's tier happens to equal the pack's suggested tier (still the user's decision, not the pack's)", () => {
    const existing: Record<string, ToolEntry> = {
      "github.push": { tier: "critical", source: "user", explicitDeny: true },
    };
    const result = mergePackIntoTools(
      existing,
      pack({
        "github.push": { tier: "critical" },
      }),
    );
    expect(result.tools["github.push"]).toEqual({
      tier: "critical",
      source: "user",
      explicitDeny: true,
    });
    expect(result.changed).toBe(false);
    expect(result.diff[0]?.kind).toBe("kept");
  });
});

describe("mergePackIntoTools — idempotent re-apply (R118/R120)", () => {
  it("a tool already present as source: pack with the IDENTICAL entry produces no diff line and no change", () => {
    const existing: Record<string, ToolEntry> = {
      "github.delete_repo": { tier: "critical", source: "pack" },
    };
    const result = mergePackIntoTools(
      existing,
      pack({
        "github.delete_repo": { tier: "critical" },
      }),
    );
    expect(result.tools).toEqual(existing);
    expect(result.changed).toBe(false);
    expect(result.diff).toEqual([]);
  });

  it("re-applying a full pack (NEW + CHANGE + KEPT mix) a second time is a total no-op", () => {
    const packTools = pack({
      "github.delete_repo": { tier: "critical" },
      "github.create_issue": { tier: "routine" },
      "github.push": { tier: "routine" },
    });
    const firstExisting: Record<string, ToolEntry> = {
      "github.create_issue": { tier: "sensitive", source: "annotation" },
      "github.push": { tier: "sensitive", source: "user" },
    };
    const first = mergePackIntoTools(firstExisting, packTools);
    expect(first.changed).toBe(true);

    const second = mergePackIntoTools(first.tools, packTools);
    expect(second.changed).toBe(false);
    expect(second.diff.filter((l) => l.kind !== "kept")).toEqual([]);
    expect(second.tools).toEqual(first.tools);
  });
});

describe("mergePackIntoTools — untouched tools are preserved verbatim", () => {
  it("never touches an existing tool the pack does not mention", () => {
    const existing: Record<string, ToolEntry> = {
      "github.list_issues": { tier: "routine", source: "annotation" },
    };
    const result = mergePackIntoTools(
      existing,
      pack({
        "github.delete_repo": { tier: "critical" },
      }),
    );
    expect(result.tools["github.list_issues"]).toEqual({
      tier: "routine",
      source: "annotation",
    });
  });
});

describe("mergePackIntoTools — deterministic ordering", () => {
  it("diff lines are sorted by tool name, independent of the pack's own key order", () => {
    const result = mergePackIntoTools(
      undefined,
      pack({
        "z.tool": { tier: "routine" },
        "a.tool": { tier: "critical" },
      }),
    );
    expect(result.diff.map((l) => l.tool)).toEqual(["a.tool", "z.tool"]);
  });
});
