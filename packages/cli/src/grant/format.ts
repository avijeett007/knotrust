/**
 * knotrust CLI `grant`/`revoke` — shared formatting + pattern-matching
 * helpers (P0-E7-T2, R111/R113/R116).
 *
 * Pure functions only (no I/O, no clock reads beyond what callers inject) so
 * every piece of "what will the human see" text is unit-testable in
 * isolation from the real store/keystore/audit composition the commands
 * themselves wire up.
 */

import type { Tier } from "@knotrust/core";
import type { ToolInventory } from "@knotrust/proxy-stdio";

// ---------------------------------------------------------------------------
// Tool-pattern matching (local, documented duplicate of
// `@knotrust/grants`'s `verify.ts` `toolMatches` — R25's conservative P0
// set: exact string, a trailing-glob `"ns.*"`, or the lone `"*"`). Kept as a
// small local copy rather than a new cross-package export for one boolean
// check, mirroring this codebase's established convention for tiny
// cross-package helpers (e.g. `resolveKnotrustHome`'s duplication between
// `@knotrust/store` and `@knotrust/grants`).
// ---------------------------------------------------------------------------

export function toolPatternMatches(pattern: string, toolName: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) return toolName.startsWith(pattern.slice(0, -1));
  return pattern === toolName;
}

/**
 * Whether ANY tool the given pattern could cover is known (from the E5-T2
 * tool-inventory baseline for `server`) to carry `destructiveHint: true`
 * (R111). Conservative: a glob pattern that covers even one destructive
 * tool trips this, so the mint-time confirmation warns before the human
 * pre-authorizes the whole namespace. `inventory` is `undefined` when no
 * capture has ever run for this server (e.g. `knotrust init` was never run
 * against it, or this is a fresh `$KNOTRUST_HOME`) — that is NOT evidence
 * of safety, just absence of information, so it resolves to `false` (no
 * warning) rather than failing the mint outright; the confirmation text
 * always shows the raw tool pattern regardless, so the human still sees
 * what they are authorizing.
 */
export function isKnownDestructive(
  inventory: ToolInventory | undefined,
  toolPattern: string,
): boolean {
  if (inventory === undefined) return false;
  for (const [name, entry] of Object.entries(inventory)) {
    if (
      toolPatternMatches(toolPattern, name) &&
      entry.annotations.destructiveHint === true
    ) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// --resource <scope> parsing (R111)
// ---------------------------------------------------------------------------

export interface ParsedResourceScope {
  resourceType?: string;
  idPattern?: string;
}

/**
 * Parses `--resource <scope>` into `GrantClaims["scope"]`'s two fields.
 * Format: `<resourceType>:<idPattern>` (colon-separated), or a bare
 * `<idPattern>` with no colon (resourceType left unconstrained). Documented,
 * simple convention — matches this codebase's own dot/colon-separated
 * pattern conventions elsewhere (e.g. `claims.ts`'s `tool` pattern doc); NOT
 * a general escaping scheme, so an idPattern that itself needs a literal
 * colon is out of scope for this flag.
 */
export function parseResourceScope(raw: string): ParsedResourceScope {
  const idx = raw.indexOf(":");
  if (idx === -1) {
    return raw.length > 0 ? { idPattern: raw } : {};
  }
  const resourceType = raw.slice(0, idx);
  const idPattern = raw.slice(idx + 1);
  return {
    ...(resourceType.length > 0 ? { resourceType } : {}),
    ...(idPattern.length > 0 ? { idPattern } : {}),
  };
}

/** Plain-words rendering of a scope for the confirmation text / table (R111). */
export function describeResourceScope(scope: ParsedResourceScope): string {
  if (scope.resourceType === undefined && scope.idPattern === undefined) {
    return "any resource (no scope restriction)";
  }
  const parts: string[] = [];
  if (scope.resourceType !== undefined)
    parts.push(`type=${scope.resourceType}`);
  if (scope.idPattern !== undefined)
    parts.push(`id matches "${scope.idPattern}"`);
  return parts.join(", ");
}

// ---------------------------------------------------------------------------
// Server label (R113's "server" column) — GrantClaims (architecture §5.2,
// frozen) carries no per-grant server field: a grant matches by TOOL NAME
// pattern only, independent of which server originally advertised it (the
// same server-agnostic matching `collectCoveringGrants` already performs).
// `knotrust grant --server <name>` is real input (used for the tool-
// inventory destructiveHint lookup and the mint-time confirmation text,
// R111) but is NOT persisted onto the minted grant — there is nowhere in
// the schema to put it without a schema change this task is explicitly not
// chartered to make (R111-R116 are ledger-logged, "no new ADR").
//
// So `grant list`'s "server" column is a BEST-EFFORT label derived from the
// tool PATTERN's own leading dot-namespace segment — the convention this
// codebase's docs and fixtures already use throughout (`"github.*"`,
// `"stripe.create_refund"`; `claims.ts`'s own `tool` field doc-comment:
// "pattern: exact 'stripe.create_refund' or glob 'github.*'"). A tool
// pattern with no dot (a flat name, as the test-harness fixtures use) has no
// namespace to infer from, so it renders as `"(unscoped)"` — an honest
// "cannot be determined from the grant alone", never a guess dressed up as
// a fact.
// ---------------------------------------------------------------------------

export const UNSCOPED_SERVER_LABEL = "(unscoped)";

export function deriveServerLabel(toolPattern: string): string {
  if (toolPattern === "*") return "*";
  const dot = toolPattern.indexOf(".");
  if (dot <= 0) return UNSCOPED_SERVER_LABEL;
  return toolPattern.slice(0, dot);
}

// ---------------------------------------------------------------------------
// Relative + absolute expiry formatting (R113)
// ---------------------------------------------------------------------------

/** The largest whole unit that fits a non-negative second count, floored: `"29d"` / `"5h"` / `"10m"` / `"30s"`. */
export function formatDurationShort(seconds: number): string {
  const abs = Math.max(0, seconds);
  const days = Math.floor(abs / 86_400);
  if (days >= 1) return `${days}d`;
  const hours = Math.floor(abs / 3_600);
  if (hours >= 1) return `${hours}h`;
  const minutes = Math.floor(abs / 60);
  if (minutes >= 1) return `${minutes}m`;
  return `${abs}s`;
}

/** `"in 29d"` / `"in 5h"` / `"in 10m"` / `"in 30s"` / `"expired"` — the largest whole unit that fits, floored. */
export function formatRelativeShort(
  nowEpochSeconds: number,
  expEpochSeconds: number,
): string {
  const diff = expEpochSeconds - nowEpochSeconds;
  if (diff <= 0) return "expired";
  return `in ${formatDurationShort(diff)}`;
}

/** RFC 3339 (ADR-0017, this codebase's one timestamp profile) rendering of an epoch-seconds instant. */
export function formatAbsolute(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString();
}

/** Short display form of a jti (ULID) for the table — the full value is always available via `--json`. */
export function shortJti(jti: string): string {
  return jti.length <= 10 ? jti : `${jti.slice(0, 10)}…`;
}

// ---------------------------------------------------------------------------
// Mint-time confirmation text (R111, R116) — plain words, shown BEFORE the
// grant is minted, regardless of `--yes` (transparency is unconditional;
// only the interactive y/n GATE is skippable).
// ---------------------------------------------------------------------------

export interface GrantConfirmationInput {
  tool: string;
  server: string;
  agentPattern: string;
  tierCap: Tier;
  ttlSeconds: number;
  expEpochSeconds: number;
  scope: ParsedResourceScope;
  destructive: boolean;
}

export function buildGrantConfirmationText(
  input: GrantConfirmationInput,
): string {
  const lines: string[] = [
    "This will pre-authorize the following, as a DURABLE grant (multi-use, until it expires or is revoked):",
    `  Tool:      ${input.tool}`,
    `  Server:    ${input.server}`,
    `  Agent:     ${input.agentPattern === "*" ? "any agent (*)" : input.agentPattern}`,
    `  Tier cap:  ${input.tierCap}`,
    `  Resource:  ${describeResourceScope(input.scope)}`,
    `  Expires:   ${formatAbsolute(input.expEpochSeconds)} (${formatDurationShort(input.ttlSeconds)} from now)`,
  ];
  if (input.destructive) {
    lines.push(
      "",
      `WARNING: "${input.server}" advertises at least one matching tool as destructive ` +
        "(destructiveHint) — every call this grant covers will be pre-authorized without " +
        "further confirmation until it expires or is revoked.",
    );
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Revoke-time confirmation text (R114, R116)
// ---------------------------------------------------------------------------

export interface RevokeCandidateSummary {
  jti: string;
  tool: string;
  tierCap: Tier;
  agentPattern: string;
}

export function describeRevokeSelector(
  selector: { jti: string } | { tool: string } | { all: true },
): string {
  if ("all" in selector) return "ALL active grants";
  if ("tool" in selector)
    return `every active grant whose stored tool pattern is exactly "${selector.tool}"`;
  return `the grant ${selector.jti}`;
}

export function buildRevokeConfirmationText(
  selector: { jti: string } | { tool: string } | { all: true },
  candidates: readonly RevokeCandidateSummary[],
): string {
  const lines: string[] = [
    `This will REVOKE ${describeRevokeSelector(selector)} (${candidates.length} grant(s)):`,
  ];
  for (const c of candidates) {
    const agent = c.agentPattern === "*" ? "any agent (*)" : c.agentPattern;
    lines.push(
      `  - ${c.jti}  tool=${c.tool}  tier-cap=${c.tierCap}  agent=${agent}`,
    );
  }
  return lines.join("\n");
}
