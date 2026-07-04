/**
 * @knotrust/core — precedence engine (P0-E2-T3).
 *
 * The authoritative composition over P0-E2-T2's L0 tier evaluator
 * (`l0-evaluator.ts`). Encodes PRD §7's power structure / architecture §5.5:
 * **admin policy is the outer envelope; user grants operate only within it;
 * no self-escalation.** This is the most security-critical logic in the
 * codebase so far — every branch below traces to an explicit orchestrator
 * ruling (R12/R13/R14) or the architecture doc, not ad hoc judgment.
 *
 * Pure function; the clock (`nowEpochSeconds`) is always an injected input,
 * never `Date.now()`. No I/O, no ID generation — `decisionId`/`latencyMs`/
 * `cache` remain pipeline concerns owned by E2-T4/E2-T5, exactly as for
 * `L0Decision` (see l0-evaluator.ts's own header note).
 *
 * Strict top-down ordering, first decisive layer wins (architecture §5.5,
 * task-plan 4-layer expansion — the binding task detail):
 *   (1) admin envelope deny/force-approval
 *   (2) explicit config deny
 *   (3) valid user grant within envelope
 *   (4) tier default behavior (delegates to E2-T2's `evaluateTierDefault`)
 *
 * Tier RESOLUTION (which tier a tool sits at, including the pack-clamp
 * floor, R14) happens once, up front, and is used by every layer — see
 * `resolveTierWithEnvelope` below.
 */

import type { DecisionRequest } from "./contract.js";
import type { CoveringGrant, L0Decision } from "./l0-evaluator.js";
import {
  evaluateTierDefault,
  isGrantTemporallyValid,
  L0ReasonCode,
  resolveTier,
  TIER_RANK,
  tierCapCovers,
} from "./l0-evaluator.js";
import type { Tier, TierPolicy, ToolTierEntry } from "./tier-policy.js";

// ---------------------------------------------------------------------------
// AdminEnvelope (R12) — the minimal P0 form. The corpus (architecture §5.5)
// names the "admin/org envelope" concept but never pins its shape; this is
// that shape, ratified by the orchestrator for this task. It is
// deliberately minimal: exact action-name matching only (`denyTools`,
// `forceApprovalTools`, `tierFloors` are all keyed by the exact
// `DecisionRequest["action"]["name"]` string) — glob/pattern matching over
// tool names arrives with E4-T2 (config loading) / E3 (grant tool patterns),
// not here.
// ---------------------------------------------------------------------------

export interface AdminEnvelope {
  /**
   * §E7 schema-forward: only "personal" is ever produced in P0 (single-user
   * — the user IS the admin). "org" is accepted at the type level now so
   * Phase 2 org-scope bundles need no shape change, but this engine assigns
   * it no special behavior yet.
   */
  scope: "personal" | "org";
  /** Exact action names. A match is a decisive layer-1 deny, no exceptions. */
  denyTools?: readonly string[];
  /** e.g. `["critical"]`: force approval on every tool resolved to this tier, regardless of any grant. */
  forceApprovalTiers?: readonly Tier[];
  /** Exact action names forced to approval, independent of the tool's resolved tier. */
  forceApprovalTools?: readonly string[];
  /**
   * Per-tool tier FLOOR (a minimum, never a maximum) — the pack-clamp input
   * (R14, brief §I2.5). Keyed by exact action name.
   */
  tierFloors?: Readonly<Record<string, Tier>>;
  /**
   * The maximum tier a user grant may authorize under this envelope
   * (architecture §5.5's "ceiling"). A grant whose own `tierCap` exceeds
   * this is outside the envelope for allow purposes — see
   * `evaluateGrantLayer`'s doc-comment for the exact (asymmetric) handling
   * versus a genuine self-escalation attempt.
   */
  grantCeiling?: Tier;
}

// ---------------------------------------------------------------------------
// Reason codes (ruling 4) — extends L0ReasonCode's stable snake_case
// vocabulary with the precedence-layer-specific codes.
// ---------------------------------------------------------------------------

export const PrecedenceReasonCode = {
  /** Layer 1: `action.name` matched `envelope.denyTools` exactly. */
  EnvelopeDeny: "envelope_deny",
  /** Layer 1: the envelope forces approval on this tool/tier regardless of any grant (admin wins over grants, PRD §7). */
  EnvelopeForceApproval: "envelope_force_approval",
  /** Layer 2: a `source: "user"` config entry set `explicitDeny: true`. */
  ExplicitConfigDeny: "explicit_config_deny",
  /**
   * Layer 3: a temporally-valid covering grant's `tierCap` is below the
   * resolved tier — an ACTIVE SELF-ESCALATION ATTEMPT. Always a decisive,
   * loud deny (R13) — never a silent fall-through to the tier default,
   * unlike L0's own "non-covering grant" treatment (see
   * `evaluateGrantLayer`'s doc-comment for the contrast).
   */
  TierCapViolation: "tier_cap_violation",
  /**
   * Layer 3: a grant's native `tierCap` DOES cover the resolved tier, but
   * `envelope.grantCeiling` clamps it below that — "the envelope working as
   * designed," not an attack. See `evaluateGrantLayer`'s doc-comment for
   * exactly when this is surfaced as a decisive deny versus silently
   * yielding to a layer-4 explicit config allow (R13's documented
   * asymmetry with `TierCapViolation`).
   */
  GrantExceedsEnvelope: "grant_exceeds_envelope",
} as const;

export type PrecedenceReasonCode =
  (typeof PrecedenceReasonCode)[keyof typeof PrecedenceReasonCode];

/**
 * `PrecedenceDecision` extends the `L0Decision` shape (ruling 4) with the
 * layer that decided and, when tier resolution clamped a floor in (R14),
 * the audit trail for that clamp. `reasonCode` widens from `L0ReasonCode`
 * alone to also admit the five precedence-layer codes above — expressed via
 * `Omit` rather than a literal `interface ... extends L0Decision` because
 * TS interface extension requires an overridden member to be a SUBTYPE of
 * the base member, and a wider reasonCode union is not a subtype of the
 * narrower `L0ReasonCode` alone.
 */
export interface PrecedenceDecision extends Omit<L0Decision, "reasonCode"> {
  reasonCode: L0ReasonCode | PrecedenceReasonCode;
  precedenceLayer: 1 | 2 | 3 | 4;
  /** Present iff tier resolution (R14) raised the tool's tier to an envelope floor. */
  clamped?: { from: Tier; to: Tier };
}

export interface EvaluatePrecedenceInput {
  request: DecisionRequest;
  tierPolicy: TierPolicy;
  /**
   * Optional rather than a required `AdminEnvelope | undefined` key
   * (this repo's tsconfig sets `exactOptionalPropertyTypes`, under which
   * those are NOT interchangeable at call sites) — absent = empty envelope,
   * every layer below still runs, they simply never match.
   */
  envelope?: AdminEnvelope;
  coveringGrants: readonly CoveringGrant[];
  /** Epoch seconds — the injected clock. Never read from `Date.now()` internally. */
  nowEpochSeconds: number;
}

// ---------------------------------------------------------------------------
// Tier resolution + pack clamp (R14)
// ---------------------------------------------------------------------------

/**
 * Wraps E2-T2's `resolveTier` with the admin-envelope tier FLOOR (R14, brief
 * §I2.5): when the winning entry's source is NOT `"user"` (i.e. `"pack"`,
 * `"annotation"`, or the unlisted-tool `"default"` fallback) and
 * `envelope.tierFloors[actionName]` outranks the resolved tier, the floor
 * wins and the raise is recorded for audit.
 *
 * - **User-source entries are never clamped in P0.** Single-user: the user
 *   IS the admin, so there is no meaningful "envelope beneath the user."
 *   Org scope (Phase 2) revisits this once admin and user are genuinely
 *   different principals.
 * - **The floor is a minimum, never a maximum** — a floor lower than (or
 *   equal to) the resolved tier is a no-op. This is a clamp on packs/
 *   defaults raising an insufficiently-tiered tool, never a way to lower
 *   one — lowering a tier is not this mechanism's job at all.
 * - Annotation-seeded suggestions (E2-T2) are already floored via
 *   `unknownToolTier`; if an annotation-raised suggestion still conflicts
 *   with an envelope floor, the floor wins on top of that (same "not user"
 *   branch handles it — annotation-seeded resolutions carry `source:
 *   "annotation"` or `"default"`, both non-"user").
 *
 * Exported (P0-E2-T5, ruling R19) so `pipeline.ts`'s composed decision
 * pipeline can resolve the SAME envelope-aware, floor-clamped tier this
 * engine uses internally — once, up front — and key both the cache lookup
 * and the cache write off that one resolution (the pinned cache-key-tier
 * rule: `cache.get`/`cache.set` must never be keyed off two independently
 * re-derived tiers, nor off an adapter's own reported tier). Re-exported,
 * not re-implemented, so the pipeline can never drift from this function's
 * exact clamping semantics.
 */
export function resolveTierWithEnvelope(
  actionName: string,
  tierPolicy: TierPolicy,
  envelope: AdminEnvelope | undefined,
  toolAnnotations: DecisionRequest["toolAnnotations"],
): { tier: Tier; clamped?: { from: Tier; to: Tier } } {
  const base = resolveTier(actionName, tierPolicy, toolAnnotations);
  const floor = envelope?.tierFloors?.[actionName];

  if (
    base.source !== "user" &&
    floor !== undefined &&
    TIER_RANK[floor] > TIER_RANK[base.tier]
  ) {
    return { tier: floor, clamped: { from: base.tier, to: floor } };
  }
  return { tier: base.tier };
}

/**
 * Builds a `TierPolicy` whose `tools[actionName].tier` is overridden to the
 * (possibly floor-clamped) resolved tier, for delegating to layer 4
 * (`evaluateTierDefault`) without that function re-deriving tier via its own
 * unclamped `resolveTier` call. Only invoked when the tier was actually
 * clamped — otherwise the original `tierPolicy` reference is reused as-is
 * (no unnecessary allocation, and `evaluateTierDefault`'s own `resolveTier`
 * call reproduces the identical unclamped result).
 *
 * The synthetic entry for a previously-unlisted tool (no prior
 * `tools[actionName]`) uses `source: "pack"` as an inert placeholder: it
 * carries no `explicitAllow`, so layer 4's `source === "user"` gate for
 * explicit config allow is correctly never satisfied by a floor-only
 * synthetic entry. When an entry already existed, its `source` and
 * `explicitAllow` are preserved verbatim — clamping only ever changes
 * `tier`, per `resolveTierWithEnvelope`'s doc-comment (floor never applies
 * to `source: "user"` entries, so this preservation never accidentally
 * re-enables an explicit allow that clamping shouldn't touch).
 */
function withResolvedTierOverride(
  tierPolicy: TierPolicy,
  actionName: string,
  tier: Tier,
): TierPolicy {
  const existing = tierPolicy.tools[actionName];
  const overridden: ToolTierEntry = existing
    ? { ...existing, tier }
    : { tier, source: "pack" };
  return {
    ...tierPolicy,
    tools: { ...tierPolicy.tools, [actionName]: overridden },
  };
}

// ---------------------------------------------------------------------------
// Layer 3 — grant evaluation (R13)
// ---------------------------------------------------------------------------

type GrantLayerVerdict =
  | { kind: "allow"; grantRef: string }
  | { kind: "tier_cap_violation" }
  | { kind: "grant_exceeds_envelope_candidate" }
  | { kind: "none" };

/**
 * Scans every temporally-valid grant in `coveringGrants` against the
 * resolved `tier`, under the envelope's `grantCeiling`. Unlike E2-T2's
 * `findCoveringGrant` (which just finds the first grant whose native
 * `tierCap` covers), this evaluates ALL valid candidates because a
 * non-covering candidate is itself meaningful here — the precedence engine
 * must distinguish two structurally different reasons a grant fails to
 * cover, per R13's documented asymmetry:
 *
 * - **`tier_cap_violation`** — the grant's OWN `tierCap` is below the
 *   resolved tier, independent of any envelope. This is an ACTIVE
 *   SELF-ESCALATION ATTEMPT (someone/something offered a grant that claims
 *   less authority than the action requires) and is always surfaced loudly,
 *   at this layer, rather than falling through — contrast E2-T2's
 *   `evaluateTierDefault`, which (used standalone, with no precedence layer
 *   above it) treats a non-covering grant as simply absent and proceeds to
 *   its own tier-default branch. The precedence engine checks caps BEFORE
 *   ever delegating to the tier default specifically so this attempt never
 *   silently resolves as `pending_approval`/`deny` under a generic reason.
 *
 * - **`grant_exceeds_envelope` candidate** — the grant's OWN `tierCap`
 *   covers the resolved tier just fine; only `envelope.grantCeiling`
 *   (imposed from outside the grant) knocks it down. This is "the envelope
 *   working as designed," not an attack — the caller (`evaluatePrecedence`)
 *   decides whether to surface this as a decisive deny or let it yield to a
 *   layer-4 explicit config allow (see the caller for the exact rule).
 *
 * When BOTH kinds of failing grant are present in the same request, a
 * `tier_cap_violation` always wins over a `grant_exceeds_envelope`
 * candidate — an active self-escalation attempt is the louder signal.
 * A grant that DOES effectively cover (post-ceiling-clamp) short-circuits
 * the scan immediately with `allow`, regardless of what else is in the list.
 */
function evaluateGrantLayer(
  coveringGrants: readonly CoveringGrant[],
  tier: Tier,
  grantCeiling: Tier | undefined,
  nowEpochSeconds: number,
): GrantLayerVerdict {
  let sawCapViolation = false;
  let sawCeilingExceeded = false;

  for (const grant of coveringGrants) {
    if (!isGrantTemporallyValid(grant, nowEpochSeconds)) {
      continue;
    }

    const nativeCovers = tierCapCovers(grant.tierCap, tier);
    const effectiveCap =
      grantCeiling !== undefined &&
      TIER_RANK[grantCeiling] < TIER_RANK[grant.tierCap]
        ? grantCeiling
        : grant.tierCap;

    if (tierCapCovers(effectiveCap, tier)) {
      return { kind: "allow", grantRef: grant.jti };
    }

    if (nativeCovers) {
      sawCeilingExceeded = true;
    } else {
      sawCapViolation = true;
    }
  }

  if (sawCapViolation) {
    return { kind: "tier_cap_violation" };
  }
  if (sawCeilingExceeded) {
    return { kind: "grant_exceeds_envelope_candidate" };
  }
  return { kind: "none" };
}

// ---------------------------------------------------------------------------
// evaluatePrecedence — the composed engine
// ---------------------------------------------------------------------------

export function evaluatePrecedence(
  input: EvaluatePrecedenceInput,
): PrecedenceDecision {
  const { request, tierPolicy, envelope, coveringGrants, nowEpochSeconds } =
    input;
  const actionName = request.action.name;

  // --- Tier resolution (R14 pack/floor clamp happens once, up front) ---
  const { tier, clamped } = resolveTierWithEnvelope(
    actionName,
    tierPolicy,
    envelope,
    request.toolAnnotations,
  );

  // --- Layer 1: admin envelope (deny / force approval) ---
  if (envelope?.denyTools?.includes(actionName)) {
    return withClamp(
      {
        outcome: "deny",
        tier,
        reasonCode: PrecedenceReasonCode.EnvelopeDeny,
        precedenceLayer: 1,
      },
      clamped,
    );
  }
  if (
    envelope?.forceApprovalTools?.includes(actionName) ||
    envelope?.forceApprovalTiers?.includes(tier)
  ) {
    return withClamp(
      {
        outcome: "pending_approval",
        tier,
        reasonCode: PrecedenceReasonCode.EnvelopeForceApproval,
        precedenceLayer: 1,
        wantsApproval: true,
      },
      clamped,
    );
  }

  // --- Layer 2: explicit config deny ---
  // Looks up the ORIGINAL (unclamped) tierPolicy entry deliberately: R14's
  // floor never applies to `source: "user"` entries, and `explicitDeny` is
  // only ever honored on `source: "user"` entries — so the clamp can never
  // have touched the entry this check cares about.
  const rawEntry = tierPolicy.tools[actionName];
  if (rawEntry?.source === "user" && rawEntry.explicitDeny === true) {
    return withClamp(
      {
        outcome: "deny",
        tier,
        reasonCode: PrecedenceReasonCode.ExplicitConfigDeny,
        precedenceLayer: 2,
      },
      clamped,
    );
  }

  // --- Layer 3: valid user grant within envelope ---
  // Routine tier never consults grants at all (mirrors E2-T2: "routine"
  // always allows unconditionally; a routine-tier grant scenario, including
  // a would-be self-escalation-shaped one, is simply moot).
  if (tier !== "routine") {
    const verdict = evaluateGrantLayer(
      coveringGrants,
      tier,
      envelope?.grantCeiling,
      nowEpochSeconds,
    );

    if (verdict.kind === "allow") {
      return withClamp(
        {
          outcome: "allow",
          tier,
          reasonCode: L0ReasonCode.GrantAllow,
          precedenceLayer: 3,
          grantRef: verdict.grantRef,
        },
        clamped,
      );
    }

    if (verdict.kind === "tier_cap_violation") {
      return withClamp(
        {
          outcome: "deny",
          tier,
          reasonCode: PrecedenceReasonCode.TierCapViolation,
          precedenceLayer: 3,
        },
        clamped,
      );
    }

    if (verdict.kind === "grant_exceeds_envelope_candidate") {
      // R13's exact asymmetry: emit the decisive deny ONLY if this grant
      // was the sole basis for what would have been an allow — i.e. only
      // if layer 4 has no OTHER independent path to allow. The only such
      // path in E2-T2's tier-default table is `explicit_config_allow`,
      // which exists only at `sensitive` tier on a `source: "user"` entry
      // with `explicitAllow: true`. If that path exists, this ceiling-
      // exceeded grant was NOT the sole basis — fall through silently and
      // let layer 4 allow via that other path (the envelope worked exactly
      // as designed: it blocked the over-ceiling grant, but something else
      // legitimately authorizes the action anyway). If no such path exists,
      // this genuinely was the sole basis, and the more diagnostic
      // `grant_exceeds_envelope` reason is surfaced here rather than
      // letting it collapse into a generic `no_grant_sensitive`/
      // `no_grant_critical` at layer 4.
      const explicitAllowAvailable =
        tier === "sensitive" &&
        rawEntry?.source === "user" &&
        rawEntry.explicitAllow === true;

      if (!explicitAllowAvailable) {
        return withClamp(
          {
            outcome: "deny",
            tier,
            reasonCode: PrecedenceReasonCode.GrantExceedsEnvelope,
            precedenceLayer: 3,
          },
          clamped,
        );
      }
      // else: fall through to layer 4 below.
    }
    // verdict.kind === "none": no relevant grant at all — fall through.
  }

  // --- Layer 4: tier default (delegates to E2-T2) ---
  // `coveringGrants` is intentionally passed as `[]`: layer 3 above has
  // already made the authoritative, envelope-aware grant decision (either
  // it allowed, decisively denied, or determined no grant helps at all).
  // Re-passing the original grants here would let `evaluateTierDefault`
  // independently re-discover a NATIVELY-covering grant using its own
  // envelope-unaware logic — silently bypassing a `grantCeiling` clamp.
  // The (possibly floor-overridden) `effectiveTierPolicy` ensures
  // `evaluateTierDefault`'s own internal `resolveTier` call reproduces the
  // SAME (clamped) tier this function already resolved, rather than
  // re-deriving the unclamped one from the raw `tierPolicy`.
  const effectiveTierPolicy = clamped
    ? withResolvedTierOverride(tierPolicy, actionName, tier)
    : tierPolicy;

  const l0 = evaluateTierDefault({
    request,
    tierPolicy: effectiveTierPolicy,
    coveringGrants: [],
    nowEpochSeconds,
  });

  return withClamp({ ...l0, precedenceLayer: 4 }, clamped);
}

/**
 * Attaches `clamped` only when defined. `exactOptionalPropertyTypes` (this
 * repo's tsconfig) forbids explicitly assigning `undefined` to an optional
 * property — omitting the key entirely (rather than setting it to
 * `undefined`) is required, hence the conditional spread instead of a
 * plain `{ ...decision, clamped }`.
 */
function withClamp(
  decision: Omit<PrecedenceDecision, "clamped">,
  clamped: { from: Tier; to: Tier } | undefined,
): PrecedenceDecision {
  return clamped ? { ...decision, clamped } : decision;
}
