/**
 * @knotrust/core — L0 tier evaluator (P0-E2-T2).
 *
 * The dependency-free built-in evaluator (brief §B1) — the true default
 * every `npx knotrust` run uses with zero config. It is **pure**: no I/O,
 * no `Date.now()`/`Math.random()`, no ID generation. The clock is always an
 * injected input (`nowEpochSeconds`); the same input always produces the
 * same output.
 *
 * Scope boundaries (deliberate, brief §I2.2 / ruling 8):
 * - No precedence engine here. The admin/org envelope (architecture §5.5,
 *   layer 1) and the "no self-escalation" tier-cap-violation reasoning sit
 *   above this evaluator — that composition is P0-E2-T3's job. This module
 *   only answers "does the L0 default, on its own, allow/deny/escalate this
 *   one request" — E2-T3 wraps it under the envelope.
 * - No grant *verification* (signature, revocation ledger). Grant evidence
 *   is injected via `coveringGrants` as already-matched candidates (E3's
 *   verification and tool/principal/scope/condition matching happened
 *   upstream); this evaluator does ONLY temporal validity + tier-cap
 *   reasoning over what it's handed (ruling 3).
 * - No `DecisionResponse` envelope minting. `decisionId`, `latencyMs`, and
 *   `cache` are pipeline concerns (E2-T4 cache, E2-T5 PdpAdapter). This
 *   module returns the internal `L0Decision` shape only.
 */

import type { DecisionRequest, DecisionResponse, Outcome } from "./contract.js";
import type {
  Tier,
  TierPolicy,
  TierSource,
  ToolTierEntry,
} from "./tier-policy.js";

// ---------------------------------------------------------------------------
// Grant evidence (ruling 3) — pre-matched by an upstream layer (E3);
// verification (signature, revocation) is NOT this module's job.
// ---------------------------------------------------------------------------

export interface CoveringGrant {
  /**
   * Durable vs ephemeral (architecture §5.3) — carried through for
   * precedence/audit use (e.g. distinguishing an approval-minted single-use
   * grant from a standing pre-authorization in `reasonAdmin`/audit trails).
   * **Intentionally NOT consulted by `evaluateTierDefault`**: this
   * evaluator's grant coverage logic is temporal validity (`nbf`/`exp`) +
   * tier-cap comparison ONLY (ruling 3/4) — `kind` never gates allow/deny
   * here. In particular, an `ephemeral` grant covers exactly like a
   * `durable` one of the same `tierCap` as far as this module is concerned;
   * `kind`-specific behavior (e.g. `callHash` binding, single-use
   * consumption) is verified upstream (E3) before a grant ever reaches
   * `coveringGrants`.
   */
  kind: "durable" | "ephemeral";
  /** The grant's claim `r` (architecture §5.2) — the tier this grant satisfies. */
  tierCap: Tier;
  /** Epoch seconds. Expiry is exclusive: a grant with `exp === nowEpochSeconds` is expired. */
  exp: number;
  /** Epoch seconds. "Not before" is inclusive: a grant with `nbf === nowEpochSeconds` is valid. */
  nbf?: number;
  jti: string;
}

// ---------------------------------------------------------------------------
// Reason codes — machine-stable snake_case (ruling 5). This starts the
// stable vocabulary later tasks (audit, envelopes, golden vectors) build on.
//
// NOTE: `tier_cap_violation` (a covering-grant-tier-cap-below-critical
// self-escalation *rejection*, as opposed to this evaluator's "the grant
// simply doesn't cover, try the default path" treatment) is E2-T3's
// precedence-engine concern, not emitted here — see the seam note on
// `evaluateTierDefault`'s critical branch below.
// ---------------------------------------------------------------------------

export const L0ReasonCode = {
  /** `routine` tier is always allowed, audited (brief §B1 L0 default semantics). */
  RoutineDefaultAllow: "routine_default_allow",
  /** A valid covering grant (temporal + tier-cap check passed) decided the outcome. */
  GrantAllow: "grant_allow",
  /** `sensitive` tier, no covering grant, but a `source: "user"` config entry sets `explicitAllow: true`. */
  ExplicitConfigAllow: "explicit_config_allow",
  /** `sensitive` tier, no covering grant, no explicit config allow — Requestable Denial (no human block). */
  NoGrantSensitive: "no_grant_sensitive",
  /** `critical` tier, no covering grant — escalates to the approval orchestrator (architecture §3 exemplar). */
  NoGrantCritical: "no_grant_critical",
} as const;

export type L0ReasonCode = (typeof L0ReasonCode)[keyof typeof L0ReasonCode];

/** L0 never produces `deferred_not_eligible` — that's a channel-eligibility concern resolved above this evaluator. */
export type L0Outcome = Extract<Outcome, "allow" | "deny" | "pending_approval">;

/**
 * Pure internal result. NOT a `DecisionResponse` envelope — no `decisionId`,
 * `latencyMs`, or `cache` (those are pipeline concerns, E2-T4/E2-T5).
 */
export interface L0Decision {
  outcome: L0Outcome;
  tier: Tier;
  reasonCode: L0ReasonCode;
  /** Present iff outcome === "deny" and the denial is requestable (sensitive tier, no covering grant). */
  requestable?: DecisionResponse["requestable"];
  /** The `jti` of the covering grant that decided this outcome, when a grant decided it. */
  grantRef?: string;
  /** True iff `critical` tier with no covering grant — E2-T3/E6 route this to the approval orchestrator.
   *  On stdio, the surface later resolves this terminally via block-and-wait (brief §I1); this flag
   *  only means "L0 alone could not resolve it," not "surface a pending_approval envelope verbatim." */
  wantsApproval?: true;
}

// ---------------------------------------------------------------------------
// resolveTier — config precedence + conservative annotation seeding
// (brief §C5, ruling 4)
// ---------------------------------------------------------------------------

/**
 * Resolves a tool's risk tier: explicit config/pack entry > annotation-
 * seeded suggestion already recorded in generated config > default.
 *
 * `toolAnnotations` are SEEDS ONLY (brief §C5, "never trust"): they can
 * inform the *suggested* tier only when `tierPolicy.tools` has no entry for
 * `actionName` at all — an existing entry (of any `source`, including a
 * previously-recorded `"annotation"` seed) always wins outright and
 * `toolAnnotations` is not even consulted. When there is no entry, the
 * baseline is `tierPolicy.unknownToolTier`; a destructive-looking
 * annotation (`destructiveHint: true`) may only RAISE that baseline
 * (sensitive → critical), never lower it — an unlisted tool can never
 * resolve to `routine` this way (brief §C5's "unannotated destructive-
 * looking tools default sensitive or higher", generalized to "any
 * unlisted tool never gets a free routine pass").
 *
 * This seeding path is kept deliberately minimal and conservative:
 * generated-config seeding (E5-T2, which writes a recorded `"annotation"`
 * entry into policy after a human-reviewable step) is the primary
 * annotation path. This live, in-request seed is a same-decision fallback
 * for tools no config generation step has ever seen.
 */
export function resolveTier(
  actionName: string,
  tierPolicy: TierPolicy,
  toolAnnotations?: DecisionRequest["toolAnnotations"],
): { tier: Tier; source: TierSource | "default" } {
  const entry = tierPolicy.tools[actionName];
  if (entry) {
    return { tier: entry.tier, source: entry.source };
  }

  const baseline = tierPolicy.unknownToolTier;
  if (baseline === "sensitive" && toolAnnotations?.destructiveHint === true) {
    return { tier: "critical", source: "annotation" };
  }
  return { tier: baseline, source: "default" };
}

// ---------------------------------------------------------------------------
// Tier-cap ordering + grant temporal validity (ruling 3/4)
// ---------------------------------------------------------------------------

/**
 * Exported (not just an internal constant) because P0-E2-T3's precedence
 * engine (`precedence.ts`) needs the exact same ordering to reason about
 * envelope `grantCeiling` clamping and tier floors — re-deriving a parallel
 * ranking there would risk drift from this module's own tier-cap logic.
 */
export const TIER_RANK: Record<Tier, number> = {
  routine: 0,
  sensitive: 1,
  critical: 2,
};

/**
 * A grant's `tierCap` covers a required tier iff its rank is >= the required
 * tier's rank. Exported for `precedence.ts` (P0-E2-T3) — see `TIER_RANK`'s
 * doc-comment for why sharing this one implementation matters.
 */
export function tierCapCovers(tierCap: Tier, required: Tier): boolean {
  return TIER_RANK[tierCap] >= TIER_RANK[required];
}

/**
 * Temporal validity only — signature/revocation verification already
 * happened upstream (ruling 3). Window is `[nbf, exp)`: `nbf` inclusive,
 * `exp` exclusive (standard JWT convention, RFC 7519 §4.1.4). A grant
 * failing this check is treated as absent, never surfaced as a deny reason
 * (architecture §5.4: fail-closed, not model-visible).
 *
 * Exported for `precedence.ts` (P0-E2-T3): the precedence engine's grant
 * layer re-scans `coveringGrants` itself (to reason about tier-cap
 * violations and envelope-ceiling clamping per-grant, not just find the
 * first covering one), so it needs this exact temporal check rather than a
 * re-implementation that could drift from this one.
 */
export function isGrantTemporallyValid(
  grant: CoveringGrant,
  nowEpochSeconds: number,
): boolean {
  if (grant.nbf !== undefined && nowEpochSeconds < grant.nbf) {
    return false;
  }
  return nowEpochSeconds < grant.exp;
}

/** First temporally-valid grant (in input order) whose `tierCap` covers `required`, if any. */
function findCoveringGrant(
  coveringGrants: readonly CoveringGrant[],
  required: Tier,
  nowEpochSeconds: number,
): CoveringGrant | undefined {
  return coveringGrants.find(
    (grant) =>
      isGrantTemporallyValid(grant, nowEpochSeconds) &&
      tierCapCovers(grant.tierCap, required),
  );
}

function buildRequestableHow(
  request: DecisionRequest,
): DecisionResponse["requestable"] {
  const server = request.surface.server ?? "<server>";
  return {
    how: `knotrust grant --tool ${request.action.name} --server ${server}`,
  };
}

// ---------------------------------------------------------------------------
// evaluateTierDefault — the L0 default semantics table (brief §B1, ruling 4/5)
// ---------------------------------------------------------------------------

export interface EvaluateTierDefaultInput {
  request: DecisionRequest;
  tierPolicy: TierPolicy;
  coveringGrants: readonly CoveringGrant[];
  /** Epoch seconds — the injected clock. Never read from `Date.now()` internally. */
  nowEpochSeconds: number;
}

/**
 * Semantics (exact, ruling 5):
 * - `routine` → `allow` (`routine_default_allow`). Grants are not consulted.
 * - `sensitive` + a valid covering grant (`tierCap` >= sensitive, in its
 *   time window) → `allow` (`grant_allow`, `grantRef` set).
 * - `sensitive`, no covering grant, `source: "user"` entry with
 *   `explicitAllow: true` → `allow` (`explicit_config_allow`).
 * - `sensitive` otherwise → `deny` (`no_grant_sensitive`) with
 *   `requestable.how` guidance. No human block — this is what distinguishes
 *   `sensitive` from `critical` (Requestable Denial, brief §B1).
 * - `critical` + a valid covering grant with `tierCap === "critical"` →
 *   `allow` (`grant_allow`, `grantRef` set).
 * - `critical` + a covering grant whose `tierCap` is below critical → the
 *   grant is treated as non-covering (falls through to the branch below).
 *   The self-escalation *rejection* itself — flagging that a sub-critical
 *   grant was offered for a critical action, reason code
 *   `tier_cap_violation` — is E2-T3's precedence-engine concern; this
 *   evaluator only knows "grant doesn't cover," not "grant was rejected."
 * - `critical` otherwise → `pending_approval` (`no_grant_critical`,
 *   `wantsApproval: true`) — E2-T3/E6 route this to the approval
 *   orchestrator; on stdio the surface later resolves it terminally via
 *   block-and-wait rather than a literal `pending_approval` envelope
 *   (brief §I1).
 *
 * Tier-cap ordering: `routine < sensitive < critical`.
 */
export function evaluateTierDefault(
  input: EvaluateTierDefaultInput,
): L0Decision {
  const { request, tierPolicy, coveringGrants, nowEpochSeconds } = input;
  const actionName = request.action.name;
  const { tier } = resolveTier(actionName, tierPolicy, request.toolAnnotations);

  if (tier === "routine") {
    return {
      outcome: "allow",
      tier,
      reasonCode: L0ReasonCode.RoutineDefaultAllow,
    };
  }

  if (tier === "sensitive") {
    const covering = findCoveringGrant(
      coveringGrants,
      "sensitive",
      nowEpochSeconds,
    );
    if (covering) {
      return {
        outcome: "allow",
        tier,
        reasonCode: L0ReasonCode.GrantAllow,
        grantRef: covering.jti,
      };
    }

    const entry: ToolTierEntry | undefined = tierPolicy.tools[actionName];
    if (entry?.source === "user" && entry.explicitAllow === true) {
      return {
        outcome: "allow",
        tier,
        reasonCode: L0ReasonCode.ExplicitConfigAllow,
      };
    }

    return {
      outcome: "deny",
      tier,
      reasonCode: L0ReasonCode.NoGrantSensitive,
      requestable: buildRequestableHow(request),
    };
  }

  // tier === "critical"
  const covering = findCoveringGrant(
    coveringGrants,
    "critical",
    nowEpochSeconds,
  );
  if (covering) {
    return {
      outcome: "allow",
      tier,
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: covering.jti,
    };
  }

  return {
    outcome: "pending_approval",
    tier,
    reasonCode: L0ReasonCode.NoGrantCritical,
    wantsApproval: true,
  };
}
