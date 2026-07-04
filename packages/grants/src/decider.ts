/**
 * @knotrust/grants — the ONE canonical decider (P0-E5-T3; ruling R68, seam
 * obligation E5-I1). Plus the cacheability predicate R69/E5-I2 pins.
 *
 * ## Why this exists — unifying two disjoint decision entry points (E5-I1)
 *
 * Before this task there were TWO entry points into a decision, and neither
 * was complete:
 *
 *   - `@knotrust/core`'s `createDecisionPipeline().decide()` — cache + a
 *     `PdpAdapter`, but NO grant collection, NO single-use consume, NO audit.
 *   - `@knotrust/grants`' `decideWithGrants()` — grant collection + consume +
 *     audit, but NO cache.
 *
 * The proxy (P0-E5-T3, the product's heart) needs BOTH in one path. This
 * module is that single path: the ONE function the proxy calls. It composes
 * the REAL primitives, in the exact order R68 pins:
 *
 *   1. Resolve the tier ONCE via `resolveTierWithEnvelope` (the exported,
 *      envelope-aware, floor-clamped resolution — never re-derived).
 *   2. `cache.get`, keyed with the EFFECTIVE policy version (the caller's
 *      config-epoch `policyVersion` fused with a content fingerprint of
 *      `tierPolicy`/`envelope` — the R20 rule, computed ONCE at construction
 *      here because these are fixed per decider instance, unlike the pipeline
 *      which takes them per request and must memoize by object identity).
 *      - HIT → audit ONE `decision` event with `cacheHit:true` (E5 pinned)
 *        and return, with ZERO grant-store reads.
 *   3. MISS → `decideCore` (the shared collect → precedence → single-use
 *      consume/replay algorithm `decideWithGrants` also uses — same body,
 *      one source of truth).
 *   4. Audit the decision FAIL-CLOSED: an `AuditUnavailableError` from
 *      `append()` converts the decision to `deny`/`audit_unavailable`, which
 *      is then re-audited best-effort (R40 doctrine — an ungoverned-but-
 *      unaudited allow is the worst outcome for a "fully audited" product).
 *   5. `cache.set`, GATED by `isCacheableDecision` (E5-I2 — see below).
 *
 * ## The PdpAdapter boundary (P1 seam — preserved, not broken)
 *
 * Today step 3 evaluates precedence DIRECTLY (via `decideCore` →
 * `evaluatePrecedence`), the L0 default — exactly as `decideWithGrants`
 * already did, so no new dependency edge is introduced (grants has always
 * imported `evaluatePrecedence` from core). The `PdpAdapter` boundary
 * (`@knotrust/core`'s `pdp-port.ts` + `createDecisionPipeline`) is UNCHANGED
 * and intact: P1-E2-T1 threads an injected `PdpAdapter` here by turning
 * `decideCore`'s `evaluatePrecedence(...)` call into `adapter.decide(request,
 * ctx)` and giving this decider an `adapter` dep — a P1 injection, needing
 * ZERO core change. This unification therefore does NOT break the adapter
 * seam (the STOP/NEEDS_CONTEXT condition R68 guards against does not arise).
 *
 * ## Relationship to `createDecisionPipeline` (core)
 *
 * `createDecisionPipeline` remains the cache+adapter PRIMITIVE for pure-PDP
 * composition. This decider does NOT wrap its `decide()` because the
 * grants + consume + audit + cacheability-gating seam sits EXACTLY between
 * `cache.get` and `cache.set`, which the pinned pipeline flow does not expose
 * (its `cache.set` is unconditional beyond the pinned tier/outcome guard, and
 * cannot express the E5-I2 single-use/replay/audit_unavailable exclusions).
 * What this decider DOES reuse from core, cleanly and without duplication, is
 * the cache PRIMITIVE itself (`createDecisionCache`'s `get`/`set`), the single
 * `resolveTierWithEnvelope` tier resolution, and the R20 policy-fingerprint
 * scheme — so cache-key semantics stay identical to the pipeline's.
 */

import type {
  AdminEnvelope,
  DecisionCache,
  DecisionRequest,
  DecisionResponse,
  TierPolicy,
} from "@knotrust/core";
import {
  computeEffectivePolicyVersion,
  resolveTierWithEnvelope,
} from "@knotrust/core";
import type { AuditSink, GrantStore } from "@knotrust/store";
import {
  AUDIT_UNAVAILABLE,
  AuditEventType,
  AuditUnavailableError,
  computeArgsHash,
} from "@knotrust/store";
import type { Ed25519PublicJwk } from "./keys.js";
import {
  decideCore,
  type GrantedDecision,
  GrantsDecisionReasonCode,
} from "./lifecycle.js";

// ---------------------------------------------------------------------------
// isCacheableDecision (E5-I2, R69) — cache ONLY outcomes that are a pure
// function of (request, policy, NON-single-use grants).
// ---------------------------------------------------------------------------

/**
 * Whether a computed decision may be written to the decision cache.
 *
 * `decision-cache.ts` (PINNED) already refuses non-`allow`/`deny` outcomes and
 * `critical`-tier entries at its own `set()`; this predicate is the SUPERSET
 * the unified decider gates on BEFORE calling `cache.set`, adding the
 * consume-dependent + transient exclusions the pinned cache cannot see (it
 * only inspects `.tier`/`.outcome`). Every excluded case, and WHY:
 *
 * - **not `allow`/`deny`** — `pending_approval` (and, once voice wiring lands,
 *   `deferred_not_eligible`) are transient/context-bound, never cacheable.
 * - **`critical` tier** — approval-bound; ephemeral grants are single-use, so
 *   a cached critical allow is either wrong (approval already consumed) or
 *   pointless (never hit again). (Also enforced by the pinned cache.)
 * - **a single-use `grant_allow`** (`decidingGrantSingleUse === true`) — the
 *   deciding grant was consumed to produce THIS allow; caching it would serve
 *   the same allow forever, defeating single-use entirely. This is the case
 *   the pinned cache cannot detect on its own (`.tier`/`.outcome` look exactly
 *   like a cacheable durable-grant allow) — hence this predicate exists.
 * - **`grant_replayed`** — a deny minted precisely because a single-use grant
 *   was already spent; it is a function of the consumed-ledger STATE, not of
 *   (request, policy), so it must be re-decided every time, never cached.
 * - **`audit_unavailable`** — the fail-closed deny for a transient audit-sink
 *   failure; caching it would deny future calls for a failure that has since
 *   healed.
 */
export function isCacheableDecision(
  decision: GrantedDecision,
  decidingGrantSingleUse: boolean,
): boolean {
  if (decision.outcome !== "allow" && decision.outcome !== "deny") {
    return false;
  }
  if (decision.tier === "critical") {
    return false;
  }
  if (decision.reasonCode === GrantsDecisionReasonCode.GrantReplayed) {
    return false;
  }
  if (decision.reasonCode === AUDIT_UNAVAILABLE) {
    return false;
  }
  if (decision.outcome === "allow" && decidingGrantSingleUse) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// createDecider
// ---------------------------------------------------------------------------

export interface CreateDeciderOptions {
  /** The REAL in-process decision cache (`@knotrust/core`'s `createDecisionCache`). */
  cache: DecisionCache;
  /** Resolved tier policy for the server this decider fronts (fixed per instance). */
  tierPolicy: TierPolicy;
  /** Admin envelope (fixed per instance). Absent = empty envelope. */
  envelope?: AdminEnvelope;
  /** Caller-minted config-epoch content-hash (`@knotrust/store`'s `policyVersion(config)`). */
  policyVersion: string;
  /** The REAL grant store (`@knotrust/store`'s `createGrantStore`). */
  store: GrantStore;
  /**
   * The REAL audit sink (`@knotrust/store`'s `createAuditLog`). MANDATORY in
   * production (the proxy always wires it — this is the seam E5 makes
   * non-optional at the surface); optional here only so unit tests can probe
   * the un-audited path. Fail-closed per R40.
   */
  audit?: AuditSink;
  /** Resolves a trusted local Ed25519 public key by `kid` (fail-closed → null). */
  resolvePublicKey(kid: string): Ed25519PublicJwk | null;
  /** Injected epoch-seconds clock — tier/grant temporal reasoning. Never `Date.now()`. */
  nowEpochSeconds(): number;
  /** Injected millisecond clock for `latencyMs` only — never a decision input. Defaults to `Date.now`. */
  nowMs?(): number;
  /** Mints `decisionId` (a ULID). Called once per `decide()`, hit or miss. */
  generateId(): string;
}

export interface Decider {
  decide(request: DecisionRequest): Promise<DecisionResponse>;
}

export function createDecider(opts: CreateDeciderOptions): Decider {
  const {
    cache,
    tierPolicy,
    envelope,
    store,
    audit,
    resolvePublicKey,
    nowEpochSeconds,
    generateId,
  } = opts;
  const nowMs = opts.nowMs ?? Date.now;

  // R20 effective policy version, computed ONCE: `tierPolicy`/`envelope` are
  // fixed per decider, so this is a per-instance constant — unmemoized,
  // since it only ever runs once. `computeEffectivePolicyVersion` (shared
  // from `@knotrust/core`, P0-E5-T3 fix round 1, Minor 1) is the SAME
  // formula `createDecisionPipeline` calls (there memoized, since it takes
  // `tierPolicy`/`envelope` per request), so cache-key semantics match
  // byte-for-byte.
  const effectivePolicyVersion = computeEffectivePolicyVersion(
    tierPolicy,
    envelope,
    opts.policyVersion,
  );

  /** Builds the full `DecisionResponse` envelope around a resolved decision. */
  function assembleResponse(
    request: DecisionRequest,
    decision: GrantedDecision,
    cacheMeta: DecisionResponse["cache"],
    latencyMs: number,
  ): DecisionResponse {
    return {
      contractVersion: "1.0",
      requestId: request.requestId,
      decisionId: generateId(),
      outcome: decision.outcome,
      tier: decision.tier,
      reasonCode: decision.reasonCode,
      ...(decision.requestable !== undefined
        ? { requestable: decision.requestable }
        : {}),
      cache: cacheMeta,
      // A grant decided the allow ⇒ `grant`; every other path is L0. (P1
      // external adapters report their own `evaluatedBy` through this seam.)
      evaluatedBy: decision.grantRef !== undefined ? "grant" : "L0",
      latencyMs,
    };
  }

  /**
   * Appends the decision's audit trail FAIL-CLOSED (R40). Returns the decision
   * the caller must honor: unchanged on success, or the `audit_unavailable`
   * deny when `append()` throws `AuditUnavailableError`. `consumedJti` (miss
   * path only — cache hits never consume) additionally appends one
   * `grant_consumed` event before the decision event. Critical-tier events are
   * fsynced immediately (R38).
   */
  function auditDecision(
    request: DecisionRequest,
    decision: GrantedDecision,
    consumedJti: string | undefined,
    latencyMs: number,
    cacheHit: boolean,
  ): GrantedDecision {
    if (audit === undefined) {
      return decision;
    }
    const appendOpts =
      decision.tier === "critical"
        ? ({ fsync: "immediate" } as const)
        : undefined;
    const argsHash = computeArgsHash(request.context.arguments);
    try {
      if (consumedJti !== undefined) {
        audit.append(
          {
            type: AuditEventType.GRANT_CONSUMED,
            surface: request.surface.kind,
            subject: request.subject.id,
            agent: request.context.agent.id,
            tool: request.action.name,
            argsHash,
            reason: "single_use_consumed",
            grantRefs: [consumedJti],
          },
          appendOpts,
        );
      }
      audit.append(
        decisionEvent(request, argsHash, decision, latencyMs, cacheHit),
        appendOpts,
      );
      return decision;
    } catch (err) {
      if (!(err instanceof AuditUnavailableError)) throw err;
      // Fail-closed (R40): the trail could not record this decision, so the
      // caller sees a deny — even a would-be allow, and even if a single-use
      // grant was already burned (`consumedJti` stays honest; the wx marker on
      // disk is the truth). The deny is re-audited best-effort.
      const denied = auditUnavailableDeny(decision);
      try {
        audit.append(
          decisionEvent(request, argsHash, denied, latencyMs, cacheHit),
          appendOpts,
        );
      } catch {
        // Best-effort by contract (R40) — the deny stands regardless.
      }
      return denied;
    }
  }

  return {
    async decide(request: DecisionRequest): Promise<DecisionResponse> {
      const startMs = nowMs();
      const nowSec = nowEpochSeconds();

      // Step 1: resolve the tier ONCE (envelope-aware, floor-clamped).
      const { tier } = resolveTierWithEnvelope(
        request.action.name,
        tierPolicy,
        envelope,
        request.toolAnnotations,
      );

      // Step 2: cache lookup, keyed by that one resolved tier + effective
      // policy version. `critical` never hits (the pinned cache's own guard).
      const cached = cache.get(request, tier, effectivePolicyVersion);
      if (cached) {
        const hitDecision = cached.decision as unknown as GrantedDecision;
        const latencyMs = nowMs() - startMs;
        // A cache hit is still its own decision + audit event (E5 pinned:
        // `cacheHit:true`), fail-closed. No consume, no cache.set on a hit.
        const finalDecision = auditDecision(
          request,
          hitDecision,
          undefined,
          latencyMs,
          true,
        );
        return assembleResponse(
          request,
          finalDecision,
          { hit: true, ttlSeconds: cached.cache.ttlSeconds },
          latencyMs,
        );
      }

      // Step 3: miss — the shared collect → precedence → consume/replay
      // algorithm (leaves the PdpAdapter seam for P1 — see module header).
      const result = decideCore(
        request,
        {
          tierPolicy,
          ...(envelope !== undefined ? { envelope } : {}),
          nowEpochSeconds: nowSec,
          resolvePublicKey,
        },
        { store },
      );
      const latencyMs = nowMs() - startMs;

      // Step 4: audit fail-closed (may convert the decision to a deny).
      const finalDecision = auditDecision(
        request,
        result.decision,
        result.consumedJti,
        latencyMs,
        false,
      );

      // Step 5: cache.set, GATED by E5-I2. A single-use deciding grant is
      // signalled by `consumedJti` being set (it was consumed to allow).
      if (
        isCacheableDecision(finalDecision, result.consumedJti !== undefined)
      ) {
        cache.set(
          request,
          finalDecision as unknown as Parameters<DecisionCache["set"]>[1],
          effectivePolicyVersion,
        );
      }

      return assembleResponse(
        request,
        finalDecision,
        { hit: false },
        latencyMs,
      );
    },
  };
}

/** Builds the one `type:"decision"` audit event a decision appends, enriched with `latencyMs` + `cacheHit` (E5 pinned) and `tier` (R126: every allow/deny/pending_approval/deferred decision event carries the resolved tier, so `--tier` and E8 observability can filter/observe on it without digging through `reason`). */
function decisionEvent(
  request: DecisionRequest,
  argsHash: string,
  decision: GrantedDecision,
  latencyMs: number,
  cacheHit: boolean,
): Parameters<AuditSink["append"]>[0] {
  return {
    type: AuditEventType.DECISION,
    surface: request.surface.kind,
    subject: request.subject.id,
    agent: request.context.agent.id,
    tool: request.action.name,
    argsHash,
    outcome: decision.outcome,
    reason: decision.reasonCode,
    latencyMs,
    tier: decision.tier,
    ...(cacheHit ? { cacheHit: true } : {}),
    ...(decision.grantRef !== undefined
      ? { grantRefs: [decision.grantRef] }
      : {}),
  };
}

/**
 * Converts a computed decision into the fail-closed `audit_unavailable` deny
 * (R40) — keeps `tier`/`precedenceLayer`/`clamped` (they describe what WAS
 * decided), drops `grantRef`/`requestable`/`wantsApproval` (an unauditable
 * call is a hard deny, never an allow anchor or a "go request a grant" nudge).
 * A local copy of `lifecycle.ts`'s identical helper — kept here so the decider
 * owns its enriched (`latencyMs`/`cacheHit`) audit path without reaching into
 * that module's private internals.
 */
function auditUnavailableDeny(original: GrantedDecision): GrantedDecision {
  return {
    outcome: "deny",
    tier: original.tier,
    reasonCode: AUDIT_UNAVAILABLE,
    precedenceLayer: original.precedenceLayer,
    ...(original.clamped !== undefined ? { clamped: original.clamped } : {}),
  };
}
