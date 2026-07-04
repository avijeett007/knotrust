/**
 * knotrust CLI `audit query` — filter predicate (P0-E4-T4, R122).
 *
 * `--tool --outcome --tier --since --agent --server` all AND together (R122:
 * "Filters AND together"): an event must satisfy every filter the caller
 * supplied to match; an omitted filter is a wildcard (always passes).
 *
 * `--tool`/`--agent` reuse `../grant/format.js`'s `toolPatternMatches` (R25's
 * P0 pattern grammar: exact string, a trailing-glob `"ns.*"`, or the lone
 * `"*"`) rather than a second bespoke matcher — the SAME convention this
 * package already uses for tool-pattern matching elsewhere (`grant`'s own
 * mint/list/revoke). `--server` reuses `deriveServerLabel` — the SAME
 * best-effort "leading dot-namespace segment of the tool name" derivation
 * `grant list`'s own NAMESPACE column already uses (R113), since a decision
 * `AuditEvent` has no dedicated `server` field of its own either — see that
 * function's own doc-comment for the full rationale.
 *
 * ## `--tier` (R126 — additive follow-up; supersedes the R125-era gap below)
 *
 * As of R126, `@knotrust/store`'s `AuditEvent` carries an OPTIONAL top-level
 * `tier` field, populated on every ordinary `type: "decision"` event
 * (`@knotrust/grants`' `decider.ts`) and on `fail_open_fired`
 * (`proxy-stdio`'s `enforce.ts`) — so `--tier` now matches the common case,
 * not just the rare fail-open event. `deriveEventTier` below prefers that
 * field whenever present.
 *
 * The paragraph below documents the PRE-R126 state, and the fallback this
 * function still honors for events written before this fix (or by any
 * producer that hasn't been updated): R37's original frozen `AuditEvent`
 * field list had NO `tier` field at all — a `type: "decision"` event's
 * `reason` carries a `reasonCode` (e.g. `"no_grant_critical"`,
 * `"tier_exceeded"`), not the resolved tier itself, and most other event
 * types carry no tier-shaped data whatsoever. The ONE place a tier was
 * recoverable from a PRE-R126 persisted event is `fail_open_fired` (R84,
 * `enforce.ts`'s `tryAppendFailOpenFired`), whose `reason` is
 * `JSON.stringify({ tier, cause })` by construction — `deriveEventTier`
 * below still reads exactly that as a fallback, and nothing else (never a
 * guessed/heuristic match against `reasonCode` text, which is not a
 * documented contract and would silently miss or mismatch as reason codes
 * evolve). For any OTHER legacy event type with no top-level `tier`,
 * `--tier` truthfully matches nothing, same as before.
 */

import type { Tier } from "@knotrust/core";
import type { AuditEvent } from "@knotrust/store";
import { deriveServerLabel, toolPatternMatches } from "../grant/format.js";

const TIERS: readonly Tier[] = ["routine", "sensitive", "critical"];

function isTier(value: unknown): value is Tier {
  return (
    typeof value === "string" && (TIERS as readonly string[]).includes(value)
  );
}

/**
 * Tier derivation from a persisted event — see this module's own header
 * for the full R126/pre-R126 rationale. Prefers the first-class `tier`
 * field (R126) whenever present, on ANY event type; falls back to the
 * legacy `fail_open_fired` structured-`reason` parse for events written
 * before this fix. Returns `undefined` (never a guess) when neither source
 * yields a valid `Tier`.
 */
export function deriveEventTier(event: AuditEvent): Tier | undefined {
  if (isTier(event.tier)) {
    return event.tier;
  }
  if (event.type !== "fail_open_fired" || event.reason === undefined) {
    return undefined;
  }
  try {
    const parsed: unknown = JSON.parse(event.reason);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      "tier" in parsed &&
      isTier((parsed as { tier: unknown }).tier)
    ) {
      return (parsed as { tier: Tier }).tier;
    }
  } catch {
    // Not JSON — no tier derivable, not an error.
  }
  return undefined;
}

/** `knotrust audit query`'s filter set (R122) — every field optional (a wildcard when absent). */
export interface AuditQueryFilters {
  tool?: string;
  outcome?: string;
  tier?: Tier;
  /** Already resolved to an absolute epoch-ms cutoff — see `since.ts`'s `resolveSinceEpochMs`. */
  sinceEpochMs?: number;
  agent?: string;
  server?: string;
}

/** `true` iff `event` satisfies EVERY filter present in `filters` (AND semantics, R122). */
export function matchesFilters(
  event: AuditEvent,
  filters: AuditQueryFilters,
): boolean {
  if (
    filters.tool !== undefined &&
    !toolPatternMatches(filters.tool, event.tool)
  ) {
    return false;
  }
  if (filters.outcome !== undefined && event.outcome !== filters.outcome) {
    return false;
  }
  if (filters.tier !== undefined && deriveEventTier(event) !== filters.tier) {
    return false;
  }
  if (filters.sinceEpochMs !== undefined) {
    const eventMs = Date.parse(event.ts);
    if (Number.isNaN(eventMs) || eventMs < filters.sinceEpochMs) return false;
  }
  if (
    filters.agent !== undefined &&
    !toolPatternMatches(filters.agent, event.agent)
  ) {
    return false;
  }
  if (
    filters.server !== undefined &&
    deriveServerLabel(event.tool) !== filters.server
  ) {
    return false;
  }
  return true;
}
