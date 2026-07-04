/**
 * @knotrust/core — the composed decision pipeline (P0-E2-T5, ruling R19).
 *
 * Closes the fall-through seam E2-T4's cache module explicitly left open
 * (`decision-cache.ts`'s own header: "Wiring that fall-through pipeline is
 * E2-T5's `PdpAdapter` job"). Flow, exactly:
 *
 *   1. Resolve tier ONCE, via `resolveTierWithEnvelope` (re-exported from
 *      `precedence.ts` for this — never re-implemented, never re-derived a
 *      second time within one `decide()` call).
 *   2. `cache.get` with that one resolved tier. `critical`-tier requests
 *      never reach the cache with a hit (decision-cache.ts's own
 *      `isCacheableTier` guard) — this pipeline relies on that, it does not
 *      duplicate the check.
 *   3. On a miss: call `adapter.decide()` — the `PdpAdapter` this pipeline
 *      was constructed with, `l0` or any Phase-1 external adapter, uniformly.
 *   4. Assemble the full `DecisionResponse` envelope around whatever the
 *      adapter (or the cache) returned.
 *   5. On a miss, `cache.set` using the SAME resolved tier from step 1 —
 *      never `decision.tier` (the adapter's own reported tier). See "The
 *      pinned cache-key-tier rule" below.
 *
 * ## Relationship to the unified grants decider (P0-E5-T3, R68)
 *
 * This pipeline is the cache + `PdpAdapter` PRIMITIVE for pure-PDP composition.
 * The product's actual enforcement path — the ONE canonical decider the stdio
 * proxy calls — lives in `@knotrust/grants` (`createDecider`, ADR-0020),
 * because it must interleave grant collection, single-use consumption, audit,
 * and the E5-I2 cacheability exclusions EXACTLY between `cache.get` and
 * `cache.set` — a seam this pinned flow deliberately does not expose (its
 * `cache.set` is unconditional beyond the tier/outcome guard). That decider
 * therefore does NOT wrap this `decide()`; it reuses the lower-level cache
 * PRIMITIVE (`createDecisionCache`), the single `resolveTierWithEnvelope`
 * resolution, and — since P0-E5-T3 fix round 1 (Minor 1) extracted the R20
 * formula out of this module's closure into the exported
 * {@link computeEffectivePolicyVersion} — literally the SAME shared function
 * this pipeline calls (there memoized; the decider calls it unmemoized, once
 * at construction), so cache-key semantics stay byte-identical to this
 * pipeline's by construction, not just by convention. This module is unchanged by that
 * task and remains the reference for how a PdpAdapter is composed with the
 * cache — the P1 seam where the grants decider will thread an injected adapter.
 *
 * ## The pinned cache-key-tier rule
 *
 * `decision-cache.ts`'s `get`/`set` both key on a `tier` argument the
 * CALLER supplies — the cache module never derives it itself (by design,
 * per its own header: tier resolution needs only policy/envelope config,
 * never a grant-store read, so it can happen before any cache lookup at
 * all). This pipeline resolves tier exactly ONCE per `decide()` call and
 * passes that one value to BOTH `cache.get` and `cache.set`. It is never
 * keyed off `decision.tier` (the value the adapter itself reports), even
 * though that happens to equal the resolved tier for the L0 adapter (this
 * task) today: an external adapter (Phase 1) could in principle report a
 * tier that diverges from KnoTrust's own envelope-aware resolution (its own
 * policy language reclassifying risk, or simply a bug). Keying `get` off
 * the resolved tier while keying `set` off `decision.tier` would silently
 * split one logical cache line into two, or worse, let a decision resolved
 * at `critical` get cached under whatever laxer tier the adapter reported.
 * Deriving both ends from the SAME single resolution structurally forecloses
 * that bug class rather than relying on the two call sites staying in sync
 * by convention.
 *
 * ## `pending_approval` — the approval-orchestrator seam
 *
 * This pipeline assembles `DecisionResponse` WITHOUT an `approval` handle,
 * even when `outcome === "pending_approval"`. Minting the actual
 * `ApprovalHandleRef` (an id, a lifecycle state, an expiry) is the approval
 * orchestrator's job (E6-T4), which wires in between this pipeline's
 * adapter call and final response delivery to a surface (either inside this
 * pipeline in a future task, or as a post-processing step the caller
 * applies to what `decide()` returns — E6-T4's job to land, not this one's).
 * `PdpDecision.wantsApproval` passes through unchanged (see
 * `assembleResponse`) for that downstream wiring to key off; this pipeline
 * does not interpret it beyond carrying it along.
 *
 * ## Clock/ID injection
 *
 * `nowEpochSeconds` — the injected clock tier/precedence resolution uses
 * everywhere else in this package; called once per `decide()` call and
 * passed to the adapter via `PdpEvaluationContext`. `nowMs` — a SEPARATE,
 * optional, millisecond-precision clock for `latencyMs` measurement only
 * (defaults to `Date.now` — the one acceptable default in this pipeline,
 * since `latencyMs` is observability metadata, not a decision input; tests
 * needing deterministic latency still inject it). `generateId` mints
 * `decisionId` — callers supply a ULID generator (`ulid.ts`), keeping this
 * module free of its own entropy/clock coupling for ID generation, called
 * once per `decide()` call (a cache hit is still its own new decision/audit
 * event, hence its own fresh `decisionId` — see `decision-fixtures`-style
 * fixtures in `contract.test.ts`, where a `cache.hit: true` response still
 * carries a distinct `decisionId`).
 *
 * ## The `DecisionCache` / `PdpDecision` bridge
 *
 * `decision-cache.ts` is PINNED (E2-T4; this task must not modify it) and
 * its `get`/`set` are typed against `PrecedenceDecision` — L0/precedence's
 * own internal decision shape, predating the `PdpAdapter` abstraction, and
 * carrying a `precedenceLayer` field with no equivalent for an external
 * adapter. `toCacheBridgePayload`/`fromCacheBridgePayload` below bridge a
 * `PdpDecision` through that pinned shape: at runtime, `decision-cache.ts`
 * reads only `.tier` and `.outcome` from the value it is given
 * (`isCacheableTier`/`isCacheableOutcome`, its only two structural reads)
 * and otherwise stores and returns the value completely opaquely, so a
 * value carrying every `PdpDecision` field the cache-hit path needs, PLUS
 * an inert `precedenceLayer` placeholder solely to satisfy the pinned
 * type, is sound — decision-cache.ts's actual behavior never inspects that
 * placeholder. `reasonUser`/`reasonAdmin` are deliberately NOT threaded
 * through this bridge (`PrecedenceDecision`/`L0Decision` have no slot for
 * them), so they do not survive a cache hit — a cache-hit `DecisionResponse`
 * omits them even if the original miss-path response carried them.
 *
 * ## Policy fingerprint — discriminating cache entries on `tierPolicy` /
 * `envelope` CONTENT, not just the resolved tier (P0-E2-T5 fix round 1, R20)
 *
 * `decision-cache.ts`'s key (see its own `computeCacheKey`) is derived from
 * `(request, tier, policyVersion, grantSetVersion)` — it has no slot for
 * `tierPolicy`/`envelope` themselves, only the single `tier` this pipeline
 * resolves from them. That is fine for the tier VALUE (the pinned
 * cache-key-tier rule above), but it means two calls whose `tierPolicy`/
 * `envelope` differ in ways that do NOT change the resolved tier — e.g. the
 * same `sensitive` tier, but one call's `envelope.denyTools` covers the
 * action and the other's does not — collide on the exact same cache key
 * under one `policyVersion`. A pipeline instance reused across such calls
 * (a real deployment shape: one pipeline, per-request `tierPolicy`/
 * `envelope`, a `policyVersion` that only bumps on a genuine config-epoch
 * change) could then serve a decision computed under a DIFFERENT policy
 * input than the one that just arrived — proven concretely by a reviewer
 * probe: call 1 (no `envelope`, a covering grant) allow, cached; call 2
 * (same request, same `policyVersion`, `envelope.denyTools` now covering the
 * action) served call 1's stale cached allow instead of the layer-1
 * `envelope_deny` the new envelope demands.
 *
 * The fix folds a `policyFingerprint` — the SHA-256 hex of
 * `canonicalStringify({ tierPolicy, envelope: envelope ?? null })` — into
 * the value actually passed to `cache.get`/`cache.set` as `policyVersion`:
 * `${policyVersion}:${policyFingerprint}`. The CALLER-supplied
 * `policyVersion` remains the config-epoch signal (unchanged meaning,
 * unchanged type); the fingerprint is a second, pipeline-internal dimension
 * folded into the same string so `decision-cache.ts` (pinned, not modified
 * by this fix) needs no shape change at all — from its perspective this is
 * still just "a policyVersion string," which is exactly what its own
 * versioned-invalidation design already treats as an opaque, caller-owned
 * value.
 *
 * Hashing `tierPolicy`/`envelope` on every `decide()` call would defeat the
 * "sub-ms common case" this pipeline exists to preserve, so
 * `computePolicyFingerprint` below memoizes by OBJECT IDENTITY (a nested
 * `WeakMap<tierPolicy, WeakMap<envelopeKey, fingerprint>>`, scoped to this
 * pipeline instance — mirroring `decision-cache.ts`'s own closure-scoped
 * state rather than module-level globals): the same `tierPolicy`/`envelope`
 * object references across N `decide()` calls hash once, not N times. See
 * `DecidePipelineInput.tierPolicy`'s doc-comment for the immutability
 * contract this memoization depends on.
 */

import { createHash } from "node:crypto";
import { canonicalStringify } from "./canonical-json.js";
import type { DecisionRequest, DecisionResponse } from "./contract.js";
import type { DecisionCache } from "./decision-cache.js";
import type { CoveringGrant } from "./l0-evaluator.js";
import type {
  PdpAdapter,
  PdpDecision,
  PdpEvaluationContext,
} from "./pdp-port.js";
import type { AdminEnvelope, PrecedenceDecision } from "./precedence.js";
import { resolveTierWithEnvelope } from "./precedence.js";
import type { TierPolicy } from "./tier-policy.js";

/**
 * The R20 "effective policy version" formula (module header "Policy
 * fingerprint" above): folds a content fingerprint of `tierPolicy`/
 * `envelope` into the caller-supplied, config-epoch `policyVersion` so a
 * plain-string cache key (`decision-cache.ts`'s only key shape) can never
 * conflate two decisions whose POLICY CONTENT differs even when they
 * resolve to the same tier under the same `policyVersion`.
 *
 * THE ONE PLACE this formula is computed (P0-E5-T3 fix round 1, Minor 1 —
 * R20 cache-key duplication): before this extraction, `@knotrust/grants`'s
 * unified decider (`createDecider`, ADR-0020) carried a byte-for-byte copy
 * of this exact `sha256(canonicalStringify(...))` +
 * `${policyVersion}:${fingerprint}` expression. Both callers now call this
 * export directly so the formula can never drift between them — cache-key
 * semantics MUST stay identical across the pipeline and the decider (see
 * this module's "Relationship to the unified grants decider" section
 * above).
 *
 * Deliberately UNMEMOIZED here: this pipeline wraps every call to this
 * function in its own per-instance `WeakMap` memo (below —
 * `computeMemoizedEffectivePolicyVersion` — hashing on every `decide()`
 * call would defeat the "sub-ms common case" this pipeline exists to
 * preserve); `@knotrust/grants`'s `createDecider` calls this directly,
 * UNMEMOIZED, exactly ONCE at construction, because its `tierPolicy`/
 * `envelope`/`policyVersion` are fixed for the decider's whole lifetime —
 * there is nothing to memoize there. A shared helper has no way to know
 * which callers want memoization, so memoization stays a call-site concern.
 */
export function computeEffectivePolicyVersion(
  tierPolicy: TierPolicy,
  envelope: AdminEnvelope | undefined,
  policyVersion: string,
): string {
  const fingerprint = createHash("sha256")
    .update(
      canonicalStringify({ tierPolicy, envelope: envelope ?? null }),
      "utf8",
    )
    .digest("hex");
  return `${policyVersion}:${fingerprint}`;
}

export interface CreateDecisionPipelineOptions {
  adapter: PdpAdapter;
  cache: DecisionCache;
  /**
   * Opaque, caller-minted content-hash of the active policy/pack bundle —
   * the config-epoch signal. NOT passed straight through to `cache.get`/
   * `cache.set` anymore as of R20: `decide()` appends a per-call
   * `policyFingerprint` (derived from `tierPolicy`/`envelope` — see module
   * header "Policy fingerprint") to build the actual value handed to
   * `decision-cache.ts`, so this field's own meaning/type is unchanged —
   * still just the config-epoch string this caller owns and bumps.
   */
  policyVersion: string;
  /** Epoch seconds. Never `Date.now()` internally — always this injected function, called once per `decide()` call. */
  nowEpochSeconds: () => number;
  /** Mints `decisionId` (a ULID — see `ulid.ts`). Called once per `decide()` call, hit or miss. */
  generateId: () => string;
  /** Millisecond-precision clock for `latencyMs` only — never a decision input. Defaults to `Date.now`. */
  nowMs?: () => number;
}

export interface DecidePipelineInput {
  request: DecisionRequest;
  /**
   * Folded into the cache key via a memoized `policyFingerprint` (module
   * header "Policy fingerprint", R20) so a `decide()` call under a
   * different `tierPolicy`/`envelope` — even at the SAME resolved tier and
   * `policyVersion` — never reads a decision cached for a different one.
   *
   * CONTRACT: this object (and `envelope` below) must be treated as
   * IMMUTABLE once passed in. The fingerprint memo is keyed by object
   * IDENTITY (`WeakMap`), not by deep value — mutating an already-memoized
   * `tierPolicy` in place (rather than passing a new object for the new
   * policy) leaves the stale fingerprint attached to that same identity,
   * silently defeating this whole protection and reintroducing exactly the
   * stale-decision bug this fix closes. Always construct/replace a new
   * `tierPolicy`/`envelope` object when policy content changes; never
   * mutate one that a pipeline has already seen.
   */
  tierPolicy: TierPolicy;
  /** See `tierPolicy`'s doc-comment — the same identity-keyed memoization and immutability contract applies here. Absent (`undefined`) is itself memoized correctly, keyed off `tierPolicy`'s own entry. */
  envelope?: AdminEnvelope;
  coveringGrants: readonly CoveringGrant[];
}

export interface DecisionPipeline {
  decide(input: DecidePipelineInput): Promise<DecisionResponse>;
}

// ---------------------------------------------------------------------------
// DecisionCache / PdpDecision bridge (see module header)
// ---------------------------------------------------------------------------

/** Inert — `decision-cache.ts` never reads this field; present only to satisfy `PrecedenceDecision`'s pinned type shape. */
const CACHE_BRIDGE_PRECEDENCE_LAYER_PLACEHOLDER = 4 as const;

/**
 * The real runtime shape stored via `cache.set` — every field the
 * cache-hit assembly path in `decide()` needs. `tier` here is DELIBERATELY
 * the pipeline's own resolved tier (see `toCacheBridgeDecision`), never
 * `PdpDecision["tier"]` — `decision-cache.ts`'s `set()` has no separate
 * tier parameter (unlike `get()`); it derives its cache key AND its
 * cacheability/TTL decision from this object's own `.tier` field
 * internally. Storing the adapter-reported tier here instead would be
 * exactly the "keyed off `decision.tier`" bug the pinned cache-key-tier
 * rule (module header) exists to foreclose — including a real security
 * gap, not just a keying inconsistency: a misreporting adapter could make
 * a `critical`-resolved decision cacheable by claiming a laxer tier.
 *
 * TODO(P0-E4-T3/P0-E5): a cache-hit audit event currently has only
 * `reasonCode` to explain itself — `reasonUser`/`reasonAdmin` do not
 * survive the bridge (module header) and there is no `origin decisionId`
 * pointing back at the miss that originally populated this entry. Before
 * audit logging (P0-E4-T3) or the audit trail's consumers (P0-E5) land,
 * either (a) additively thread `reasonAdmin` + an origin `decisionId`
 * through this payload so a cache-hit audit event carries the same
 * rationale a miss would, or (b) get an explicit ratification that
 * `reasonCode` alone suffices for cache-hit audit rationale. Decide there,
 * not here.
 */
interface CacheBridgePayload {
  outcome: PdpDecision["outcome"];
  tier: DecisionResponse["tier"];
  reasonCode: PdpDecision["reasonCode"];
  requestable?: PdpDecision["requestable"];
  evaluatedBy: PdpDecision["evaluatedBy"];
}

function toCacheBridgeDecision(
  decision: PdpDecision,
  resolvedTier: DecisionResponse["tier"],
): PrecedenceDecision {
  const payload: CacheBridgePayload = {
    outcome: decision.outcome,
    tier: resolvedTier,
    reasonCode: decision.reasonCode,
    evaluatedBy: decision.evaluatedBy,
    ...(decision.requestable !== undefined
      ? { requestable: decision.requestable }
      : {}),
  };
  // See module header "The DecisionCache / PdpDecision bridge" for why this
  // cast is sound: decision-cache.ts never reads `precedenceLayer`, and its
  // `reasonCode`/`outcome` unions are strictly narrower than an external
  // adapter's own vocabulary — `unknown` is the honest intermediate given
  // TypeScript's structural typing cannot express "wider at this call site,
  // narrower at that one" any other way.
  return {
    ...payload,
    precedenceLayer: CACHE_BRIDGE_PRECEDENCE_LAYER_PLACEHOLDER,
  } as unknown as PrecedenceDecision;
}

function fromCacheBridgeDecision(
  decision: PrecedenceDecision,
): CacheBridgePayload {
  return decision as unknown as CacheBridgePayload;
}

// ---------------------------------------------------------------------------
// DecisionResponse assembly
// ---------------------------------------------------------------------------

interface AssembleResponseInput {
  request: DecisionRequest;
  decisionId: string;
  outcome: DecisionResponse["outcome"];
  tier: DecisionResponse["tier"];
  reasonCode: string;
  reasonUser?: string;
  reasonAdmin?: string;
  requestable?: DecisionResponse["requestable"];
  evaluatedBy: DecisionResponse["evaluatedBy"];
  cache: DecisionResponse["cache"];
  latencyMs: number;
}

/** `approval` is intentionally never set here — see module header, "the approval-orchestrator seam". */
function assembleResponse(input: AssembleResponseInput): DecisionResponse {
  return {
    contractVersion: "1.0",
    requestId: input.request.requestId,
    decisionId: input.decisionId,
    outcome: input.outcome,
    tier: input.tier,
    reasonCode: input.reasonCode,
    ...(input.reasonUser !== undefined ? { reasonUser: input.reasonUser } : {}),
    ...(input.reasonAdmin !== undefined
      ? { reasonAdmin: input.reasonAdmin }
      : {}),
    ...(input.requestable !== undefined
      ? { requestable: input.requestable }
      : {}),
    cache: input.cache,
    evaluatedBy: input.evaluatedBy,
    latencyMs: input.latencyMs,
  };
}

// ---------------------------------------------------------------------------
// createDecisionPipeline
// ---------------------------------------------------------------------------

export function createDecisionPipeline(
  opts: CreateDecisionPipelineOptions,
): DecisionPipeline {
  const { adapter, cache, policyVersion, nowEpochSeconds, generateId } = opts;
  const nowMs = opts.nowMs ?? Date.now;

  // -------------------------------------------------------------------------
  // Policy fingerprint memoization (R20 fix — see module header "Policy
  // fingerprint"). Scoped to THIS pipeline instance's closure, mirroring
  // `decision-cache.ts`'s own closure-scoped state rather than a module-level
  // global.
  // -------------------------------------------------------------------------

  /**
   * `WeakMap` keys must be objects; `undefined` (the "no envelope" case)
   * cannot be one. This singleton stands in for it so the inner `WeakMap`
   * below can memoize the undefined-envelope case uniformly, keyed off the
   * SAME `tierPolicy`-scoped entry every other envelope identity uses,
   * rather than a separate special-cased branch.
   */
  const UNDEFINED_ENVELOPE_KEY: object = {};

  /**
   * Outer key: the `tierPolicy` object identity. Inner key: the `envelope`
   * object identity (or `UNDEFINED_ENVELOPE_KEY`). Both levels are
   * `WeakMap`s, so entries are garbage-collectable once their `tierPolicy`/
   * `envelope` objects are no longer referenced anywhere else — no manual
   * eviction needed, unlike `decision-cache.ts`'s own LRU (which must evict
   * manually because its keys are hashes, not the live objects themselves).
   */
  const effectivePolicyVersionCache = new WeakMap<
    object,
    WeakMap<object, string>
  >();

  /**
   * Test-only instrumentation (P0-E2-T5 fix round 1 regression suite):
   * counts actual `computeEffectivePolicyVersion` calls (memo misses), never
   * memo hits. Not part of `DecisionPipeline`/`CreateDecisionPipelineOptions`/
   * `DecidePipelineInput` — those stay exactly as documented — this is
   * exposed only as a non-enumerable property on the returned pipeline
   * instance (see `Object.defineProperty` below) so `pipeline.test.ts` can
   * assert "same policy objects across N calls hash once" without a public
   * spy seam.
   */
  let policyFingerprintComputeCount = 0;

  /**
   * Memoizing wrapper around the shared, exported
   * {@link computeEffectivePolicyVersion} (module header "Policy
   * fingerprint"; P0-E5-T3 fix round 1 extracted the formula itself out of
   * this closure so `@knotrust/grants`'s decider can call the exact same
   * code — this function now only owns the per-instance `WeakMap` memo on
   * top of it). Memoizing the FULL effective-policy-version string (not
   * just the fingerprint half) is sound because `policyVersion` is this
   * pipeline instance's own closure-constant `opts.policyVersion` — it never
   * varies call to call, so keying the memo on `tierPolicy`/`envelope`
   * object identity alone is exactly as precise as keying on all three would
   * be.
   */
  function computeMemoizedEffectivePolicyVersion(
    tierPolicy: TierPolicy,
    envelope: AdminEnvelope | undefined,
  ): string {
    const envelopeKey: object = envelope ?? UNDEFINED_ENVELOPE_KEY;
    let inner = effectivePolicyVersionCache.get(tierPolicy);
    if (inner === undefined) {
      inner = new WeakMap<object, string>();
      effectivePolicyVersionCache.set(tierPolicy, inner);
    }
    const memoized = inner.get(envelopeKey);
    if (memoized !== undefined) {
      return memoized;
    }
    policyFingerprintComputeCount++;
    const computed = computeEffectivePolicyVersion(
      tierPolicy,
      envelope,
      policyVersion,
    );
    inner.set(envelopeKey, computed);
    return computed;
  }

  const pipeline: DecisionPipeline = {
    async decide(input: DecidePipelineInput): Promise<DecisionResponse> {
      const { request, tierPolicy, envelope, coveringGrants } = input;
      const startMs = nowMs();

      // Step 1: resolve tier ONCE (the pinned cache-key-tier rule).
      const { tier } = resolveTierWithEnvelope(
        request.action.name,
        tierPolicy,
        envelope,
        request.toolAnnotations,
      );

      // R20: the shared, memoized effective-policy-version (module header
      // "Policy fingerprint"; `computeEffectivePolicyVersion` is the ONE
      // formula this pipeline and `@knotrust/grants`'s decider both call —
      // P0-E5-T3 fix round 1, Minor 1) so a cache entry can never be reused
      // across differing policy inputs that happen to resolve to the same
      // tier under the same caller-supplied policyVersion.
      const effectivePolicyVersion = computeMemoizedEffectivePolicyVersion(
        tierPolicy,
        envelope,
      );

      // Step 2: cache lookup, keyed by the SAME resolved tier.
      const cached = cache.get(request, tier, effectivePolicyVersion);
      if (cached) {
        const payload = fromCacheBridgeDecision(cached.decision);
        return assembleResponse({
          request,
          decisionId: generateId(),
          outcome: payload.outcome,
          // The pipeline's own resolved `tier`, not `payload.tier` (which
          // is the same value by construction — see `toCacheBridgeDecision`
          // — but reading the local resolution directly, rather than
          // round-tripping it through the cache bridge, keeps `tier`'s
          // single source of truth textually obvious at both call sites).
          tier,
          reasonCode: payload.reasonCode,
          ...(payload.requestable !== undefined
            ? { requestable: payload.requestable }
            : {}),
          evaluatedBy: payload.evaluatedBy,
          cache: { hit: true, ttlSeconds: cached.cache.ttlSeconds },
          latencyMs: nowMs() - startMs,
        });
      }

      // Step 3: miss — delegate to the adapter, uniformly (L0 or any
      // Phase-1 external adapter; this pipeline never branches on which).
      const ctx: PdpEvaluationContext = {
        tierPolicy,
        ...(envelope !== undefined ? { envelope } : {}),
        coveringGrants,
        nowEpochSeconds: nowEpochSeconds(),
      };
      const decision = await adapter.decide(request, ctx);

      // Step 5: cache.set using the SAME resolved tier from step 1 — never
      // `decision.tier`. decision-cache.ts's own `set()` has no separate
      // tier parameter; it derives its key AND its cacheability/TTL
      // decision from the object's own `.tier` field, which is exactly why
      // `toCacheBridgeDecision` is handed `tier` (the resolved value)
      // explicitly rather than reading it off `decision`. `set()` silently
      // no-ops for a non-cacheable tier/outcome (critical, pending_approval,
      // deferred_not_eligible) — relied on here, not duplicated.
      cache.set(
        request,
        toCacheBridgeDecision(decision, tier),
        effectivePolicyVersion,
      );

      // Step 4: assemble the response envelope. `tier` here is likewise the
      // pipeline's resolved value, not `decision.tier` — see module header.
      return assembleResponse({
        request,
        decisionId: generateId(),
        outcome: decision.outcome,
        tier,
        reasonCode: decision.reasonCode,
        // `exactOptionalPropertyTypes` (this repo's tsconfig) forbids
        // explicitly assigning `undefined` to an optional property —
        // conditional spread omits the key entirely when absent, mirroring
        // `precedence.ts`'s `withClamp` convention.
        ...(decision.reasonUser !== undefined
          ? { reasonUser: decision.reasonUser }
          : {}),
        ...(decision.reasonAdmin !== undefined
          ? { reasonAdmin: decision.reasonAdmin }
          : {}),
        ...(decision.requestable !== undefined
          ? { requestable: decision.requestable }
          : {}),
        evaluatedBy: decision.evaluatedBy,
        cache: { hit: false },
        latencyMs: nowMs() - startMs,
      });
    },
  };

  // Test-only seam (see `policyFingerprintComputeCount`'s doc-comment above):
  // a non-enumerable property on the instance, not a module/type export, so
  // `DecisionPipeline`'s public shape and `@knotrust/core`'s package exports
  // (`index.ts`'s `export * from "./pipeline.js"`) are both untouched by it.
  Object.defineProperty(pipeline, "__policyFingerprintComputeCountForTests", {
    enumerable: false,
    configurable: false,
    get: () => policyFingerprintComputeCount,
  });

  return pipeline;
}
