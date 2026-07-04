/**
 * knotrust CLI `add pack` — the precedence-respecting merge (P0-E7-T3,
 * rulings R118/R119/R120). This is the headline logic the task's acceptance
 * hangs on: folding a pack's tool entries into an existing (or absent)
 * server's `tools` map WITHOUT ever silently clobbering a human's own
 * decision, while still being the authoritative source over an
 * annotation-seeded suggestion.
 *
 * ## Precedence (R118) — mirrors E5-T2's `mergeSeededTiers`, one rank up
 *
 * `@knotrust/proxy-stdio`'s `mergeSeededTiers` (P0-E5-T2, R65) established
 * this exact shape of rule at annotation authority: a fresher seed replaces
 * an existing entry UNLESS that entry already carries higher authority
 * (`"user"`/`"pack"`), in which case it is left completely alone. This module
 * is the same rule one authority level up:
 *
 *   pack   OVERRIDES  source: "annotation"  (pack outranks a seed)
 *   pack   OVERRIDES  source: "pack"        (a re-applied/updated pack
 *                                            refreshes its own prior entry —
 *                                            "pack never outranks pack" would
 *                                            make re-applying an UPDATED pack
 *                                            file permanently stuck on the
 *                                            first tier it ever wrote, which
 *                                            is not idempotent in the sense
 *                                            R120 means; it is idempotent
 *                                            in the sense that mirrors
 *                                            annotation-refreshing-annotation
 *                                            — same source never blocks
 *                                            itself)
 *   pack   NEVER OVERRIDES  source: "user"  (R118's explicit, load-bearing
 *                                            rule — the whole reason this
 *                                            merge exists, not just a
 *                                            generic "newest wins")
 *
 * A tool absent from the existing map entirely is always a plain NEW
 * addition (no existing authority to compare against).
 *
 * ## Idempotence (R120) — a TRUE no-op re-apply
 *
 * Re-applying the identical pack against an already-applied config must
 * produce ZERO diff lines and an unchanged `tools` map (`changed: false`) —
 * not just "no user-visible change" but no `CHANGE` line at all, since a
 * `source: "pack"` entry whose content is byte-for-byte what the pack would
 * produce again is compared for STRUCTURAL equality (`toolEntriesEqual`
 * below) before ever being treated as an override. Only a tool CURRENTLY
 * claimed by `source: "user"` produces a line without a corresponding
 * `tools` change (`kind: "kept"`) — that is the one deliberate exception:
 * transparency about a skipped override is not itself a "change."
 *
 * ## Diff format (R119 — the Homebrew tap-trust preview)
 *
 * Lines are pre-formatted human-readable strings, sorted by tool name for
 * deterministic output (never dependent on the pack file's own key
 * insertion order): `NEW: <tool> → <tier> (from pack)`, `CHANGE: <tool>
 * <oldTier> → <newTier> (pack)`, `KEPT: <tool> → your user setting <tier>
 * (pack suggested <tier>)` — the exact three shapes R119 names.
 */

import type { Tier } from "@knotrust/core";
import type { ToolEntry } from "@knotrust/store";
import type { PackToolEntry } from "./pack-schema.js";

export type PackDiffKind = "new" | "change" | "kept";

export interface PackDiffLine {
  kind: PackDiffKind;
  tool: string;
  /** The exact human-readable line this tool contributes to the printed preview (R119). */
  text: string;
}

export interface PackMergeResult {
  /** The full merged `tools` map for the target server — every untouched existing entry carried over verbatim, plus every NEW/CHANGE stamped `source: "pack"`, plus every KEPT entry unchanged. */
  tools: Record<string, ToolEntry>;
  /** `NEW`/`CHANGE`/`KEPT` lines, sorted by tool name. A tool whose pack-derived entry is STRUCTURALLY IDENTICAL to what already exists (the true idempotent-re-apply case) contributes no line at all. */
  diff: PackDiffLine[];
  /** True iff `tools` differs from the input `existing` map — i.e. at least one NEW or CHANGE happened. A KEPT-only (or empty) merge is `false`: nothing was written, only explained. */
  changed: boolean;
}

/**
 * Stamps a pack tool entry with `source: "pack"` (R118) — the ONE place in
 * this codebase a `ToolEntry` is ever minted with that source. Never carries
 * `explicitAllow`/`explicitDeny` (fix round 1, P0-E7-T3 review, FIX 1):
 * `PackToolEntrySchema` already rejects those two fields outright, so
 * `entry` can never actually carry one in practice — this function simply
 * never reads or writes them, a second, code-level guarantee alongside the
 * schema's own that a pack-sourced `ToolEntry` is never minted with an
 * explicit-authority flag, even if some future caller ever bypassed the
 * schema (e.g. constructing a `PackToolEntry` by hand rather than through
 * `loadPackFile`).
 */
function toPackToolEntry(entry: PackToolEntry): ToolEntry {
  return {
    tier: entry.tier,
    source: "pack",
    ...(entry.mapping !== undefined ? { mapping: entry.mapping } : {}),
  };
}

/** Structural equality over every field a `ToolEntry` can carry — the idempotence check (R120): a `source: "pack"` entry equal to what re-applying the pack would produce again is a true no-op, not a `CHANGE`. */
function toolEntriesEqual(a: ToolEntry, b: ToolEntry): boolean {
  return (
    a.tier === b.tier &&
    a.source === b.source &&
    (a.explicitAllow ?? false) === (b.explicitAllow ?? false) &&
    (a.explicitDeny ?? false) === (b.explicitDeny ?? false) &&
    JSON.stringify(a.mapping ?? null) === JSON.stringify(b.mapping ?? null)
  );
}

function newLine(tool: string, tier: Tier): PackDiffLine {
  return { kind: "new", tool, text: `NEW: ${tool} → ${tier} (from pack)` };
}

function changeLine(tool: string, fromTier: Tier, toTier: Tier): PackDiffLine {
  return {
    kind: "change",
    tool,
    text: `CHANGE: ${tool} ${fromTier} → ${toTier} (pack)`,
  };
}

function keptLine(tool: string, userTier: Tier, packTier: Tier): PackDiffLine {
  return {
    kind: "kept",
    tool,
    text: `KEPT: ${tool} → your user setting ${userTier} (pack suggested ${packTier})`,
  };
}

/**
 * Merges `packTools` into `existing` (a server's current `tools` map, or
 * `undefined` for a server with no prior entries at all) under the
 * precedence rule documented in this module's header. Pure — no I/O, no
 * clock; returns a brand-new `tools` object (never mutates `existing`),
 * mirroring this repo's established "normalizers return fresh objects"
 * discipline (`packages/store/src/config.ts`'s R20).
 */
export function mergePackIntoTools(
  existing: Record<string, ToolEntry> | undefined,
  packTools: Record<string, PackToolEntry>,
): PackMergeResult {
  const merged: Record<string, ToolEntry> = { ...(existing ?? {}) };
  const diff: PackDiffLine[] = [];
  let changed = false;

  for (const tool of Object.keys(packTools).sort()) {
    const packEntryRaw = packTools[tool];
    if (packEntryRaw === undefined) continue;
    const candidate = toPackToolEntry(packEntryRaw);
    const current = merged[tool];

    if (current === undefined) {
      merged[tool] = candidate;
      diff.push(newLine(tool, candidate.tier));
      changed = true;
      continue;
    }

    if (current.source === "user") {
      // R118's load-bearing rule: NEVER override an explicit user entry.
      // `merged[tool]` is left exactly as `current` — no assignment at all.
      diff.push(keptLine(tool, current.tier, candidate.tier));
      continue;
    }

    // `current.source` is "annotation" or "pack" — both overridable.
    if (toolEntriesEqual(current, candidate)) {
      // True idempotent no-op (R120): already applied, identical content.
      continue;
    }

    merged[tool] = candidate;
    diff.push(changeLine(tool, current.tier, candidate.tier));
    changed = true;
  }

  return { tools: merged, diff, changed };
}
