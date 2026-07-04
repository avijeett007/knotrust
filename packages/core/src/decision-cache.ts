/**
 * @knotrust/core — in-process decision cache with tiered TTLs and versioned
 * invalidation (P0-E2-T4, R16).
 *
 * This is what makes the "sub-ms common case" true (architecture §7: the
 * fast path is the cache, never header-only evaluation). It sits in front of
 * `evaluatePrecedence` (P0-E2-T3): a cache HIT resolves a decision with zero
 * grant-store reads; a MISS falls through to the full precedence evaluation
 * (grant-store read + `evaluatePrecedence`) and, if the result is cacheable,
 * populates the cache for next time. Wiring that fall-through pipeline is
 * E2-T5's `PdpAdapter` job (explicit scope exclusion here) — this module
 * only owns the cache itself: key derivation, TTL policy, and invalidation.
 *
 * **Invalidation correctness is the security point of this task**: a stale
 * `allow` surviving a grant revocation is a hole (brief §B2 — local-mode
 * revocation must take effect on the *next decision*). Two-field versioned
 * invalidation delivers that:
 *
 * - `policyVersion` — an opaque, caller-supplied content-hash of the active
 *   policy/pack bundle (E4-T2 mints it; for now it's just an input this
 *   module trusts). A policy/pack change ⇒ new `policyVersion` ⇒ every prior
 *   key is unreachable.
 * - `grantSetVersion` — a monotonic counter this module owns, bumped by
 *   `bumpGrantSetVersion()` on any grant add/revoke. Together these two
 *   fields ARE the implementation plan's single `configEpoch`: stale entries
 *   become *unreachable* (a new key never collides with an old one) rather
 *   than being mutated in place and risking a race where a stale value is
 *   read mid-update.
 *
 * `bumpGrantSetVersion()` ALSO fully clears the store (not just increments
 * the counter). The architecture doc (§7.3) additionally calls for "active
 * purge [of] affected entries on revoke for prompt reclamation" — a full
 * clear trivially satisfies that (every entry keyed on the old
 * `grantSetVersion` is both unreachable AND physically freed) and is
 * documented here as the accepted P0-scale simplification versus a
 * selective purge keyed by affected principal/tool/resource (brief §5 /
 * architecture §7.3's stated aspiration for a future, more surgical purge).
 *
 * Only `allow`/`deny` outcomes are ever cacheable, and `critical`-tier
 * decisions are NEVER cached regardless of outcome — critical outcomes are
 * approval-bound and ephemeral grants are single-use, so caching a critical
 * `allow` would either be wrong (approval already consumed) or pointless
 * (never hit again). Both guards are enforced at runtime in `set()`, not
 * just via the type system, precisely because this is the module where a
 * type-level gap would be a live security hole (`PrecedenceDecision`'s
 * `outcome` type already excludes `deferred_not_eligible` structurally, but
 * this module does not rely on that alone — see `isCacheable`'s doc-comment).
 *
 * `node:crypto`'s `createHash` is used for the key hash (permitted per this
 * task's ruling: no fs/network in this module, but the evaluators' I/O-free
 * purity rule doesn't extend to this deliberately stateful cache). The clock
 * STAYS injected (`nowEpochSeconds`) — never `Date.now()` — so TTL/expiry
 * behavior is fully deterministic under test.
 */

import { createHash } from "node:crypto";
import { canonicalStringify } from "./canonical-json.js";
import type { DecisionRequest } from "./contract.js";
import type { PrecedenceDecision } from "./precedence.js";
import type { Tier } from "./tier-policy.js";

// ---------------------------------------------------------------------------
// Cache key (R16 ruling 1) — architecture §7.1's shape, plus `srv` (the
// plan's per-server tuple field; architecture omitted it, both bind, and
// combining is strictly safer: cache-per-server).
// ---------------------------------------------------------------------------

/**
 * Builds the SHA-256 cache key over the canonical JSON of the SARC-derived,
 * volatile-field-free key material.
 *
 * Field-by-field provenance (all binding, R16 ruling 1):
 * - `s`/`a`/`rt`/`ri`/`ag`/`tier`/`policyVersion`/`grantSetVersion` — verbatim
 *   architecture §7.1.
 * - `rp` — P0 rule: ALL of `resource.properties`, not just a per-tool
 *   "conditions-relevant" subset (that filtering config arrives with E4-T2's
 *   mapping layer — this is the seam). "Deep-sorted" falls out of
 *   `canonicalStringify`'s own recursive key sort, so `rp` need only pass the
 *   raw object through.
 * - `srv` — the plan's tuple explicitly keys per server; architecture's key
 *   shape omitted it. Both source documents bind, so it's included.
 *
 * Excluded fields fall into two DIFFERENT categories — conflating them was a
 * prior bug in this comment, so the distinction is spelled out here:
 * - Truly volatile (`requestId`, `timestamp`): per-request identifiers with
 *   no bearing on the authorization outcome under any current or foreseeable
 *   decision logic. Excluding them is what makes repeat requests cache-able
 *   at all.
 * - Decision-relevant but UNCONSUMED TODAY (`subject.type`,
 *   `subject.properties` incl. `tenant`, `action.properties`,
 *   `context.env.surfaceLocal`, `context.env.voiceSession`): per contract.ts
 *   these are NOT inert. `env.voiceSession` explicitly drives
 *   `deferred_not_eligible` eligibility (that outcome sits above this
 *   module's input boundary today, per the module header, but the field
 *   itself is live). `subject.properties.tenant` is schema-forward for P2
 *   org scope. `env.surfaceLocal` and `action.properties` are likewise only
 *   unused because no decision logic reads them YET. They are excluded from
 *   the key purely because nothing currently keys on them, not because they
 *   are inherently non-authorization-relevant.
 *
 * DANGER: if any of these becomes a decision input (voice outcomes,
 * org/tenant scope, surface-locality rules), it MUST be added to the cache
 * key or folded into `policyVersion` — otherwise the cache serves wrong
 * decisions across that dimension (e.g. a cross-tenant leak in P2 if
 * `subject.id` is not globally unique across tenants).
 *
 * `toolAnnotations` is absent from `keyMaterial` too, but that exclusion IS
 * sound (unlike the fields above): annotations influence decisions only via
 * `resolveTier` → `tier`, which IS already in the key, and an
 * annotation-raised `critical` tier is never cached at all (`isCacheableTier`)
 * — so there is no decision path where the raw annotation payload matters
 * but the key's `tier` field doesn't already capture it.
 *
 * Exported (not just an internal helper) so key-stability properties
 * (volatile-field exclusion, property-insertion-order independence) can be
 * asserted directly, in addition to through the cache's public `get`/`set`
 * behavior.
 */
export function computeCacheKey(
  request: DecisionRequest,
  tier: Tier,
  policyVersion: string,
  grantSetVersion: number,
): string {
  const keyMaterial = {
    s: request.subject.id,
    a: request.action.name,
    rt: request.resource.type,
    ri: request.resource.id,
    rp: request.resource.properties ?? {},
    ag: request.context.agent.id,
    srv: request.surface.server ?? null,
    tier,
    policyVersion,
    grantSetVersion,
  };
  return createHash("sha256")
    .update(canonicalStringify(keyMaterial), "utf8")
    .digest("hex");
}

// ---------------------------------------------------------------------------
// Cacheability guards — the security-critical no-ops (brief §"a stale allow
// after revocation is a hole").
// ---------------------------------------------------------------------------

/**
 * `critical` is NEVER cached, independent of outcome (brief §B2: critical
 * outcomes are approval-bound and ephemeral grants are single-use, so
 * caching is both unsafe and useless).
 */
function isCacheableTier(tier: Tier): boolean {
  return tier !== "critical";
}

/**
 * Only `allow`/`deny` are cacheable. `pending_approval` is excluded here at
 * runtime; `deferred_not_eligible` is excluded at the TYPE level already
 * (`PrecedenceDecision["outcome"]` is `L0Outcome`, which has no
 * `"deferred_not_eligible"` member — that outcome is decided above this
 * module's input boundary, by a layer this task's scope excludes). This
 * function still checks by exact positive match (`=== "allow" || === "deny"`)
 * rather than a negative match against the excluded set, so that ANY future
 * widening of `PrecedenceDecision["outcome"]` — including a
 * `deferred_not_eligible` value arriving via an unsafe cast, exactly as one
 * of this module's own tests exercises — fails closed (not cacheable) rather
 * than silently becoming cacheable by omission.
 */
function isCacheableOutcome(outcome: PrecedenceDecision["outcome"]): boolean {
  return outcome === "allow" || outcome === "deny";
}

// ---------------------------------------------------------------------------
// TTL policy (brief §B2 caps, enforced here regardless of ttlOverrides)
// ---------------------------------------------------------------------------

const DEFAULT_ROUTINE_TTL_SECONDS = 300;
const DEFAULT_SENSITIVE_TTL_SECONDS = 60;
const MAX_ROUTINE_TTL_SECONDS = 300;
const MAX_SENSITIVE_TTL_SECONDS = 60;
const DEFAULT_MAX_ENTRIES = 5000;

/** Clamps to `[0, max]` — a config-supplied override can lower but never raise past the cap, and can never go negative. */
function clampTtl(value: number, max: number): number {
  return Math.min(Math.max(value, 0), max);
}

// ---------------------------------------------------------------------------
// Public API (R16 ruling 3)
// ---------------------------------------------------------------------------

/**
 * A cache hit: the stored decision plus the hit metadata shape
 * `DecisionResponse.cache` eventually wants (`{ hit: boolean; ttlSeconds?:
 * number }}`). E2-T5's `PdpAdapter` wires this into the full envelope; this
 * module only ever returns the `hit: true` shape (a miss is `undefined`, not
 * a `{ hit: false }` value) since `get`'s return type already distinguishes
 * hit/miss via presence.
 */
export interface CachedDecision {
  decision: PrecedenceDecision;
  cache: { hit: true; ttlSeconds: number };
}

export interface DecisionCacheStats {
  hits: number;
  misses: number;
  size: number;
}

export interface DecisionCache {
  /**
   * `tier` is supplied by the caller (resolved upstream, pure — tier
   * resolution needs only policy/envelope config, never a grant-store read)
   * rather than derived here, so a `critical`-tier lookup can be rejected
   * before any key computation at all.
   */
  get(
    req: DecisionRequest,
    tier: Tier,
    policyVersion: string,
  ): CachedDecision | undefined;
  /** Silently refuses (no-op) any non-cacheable tier or outcome — see `isCacheableTier`/`isCacheableOutcome`. */
  set(
    req: DecisionRequest,
    decision: PrecedenceDecision,
    policyVersion: string,
  ): void;
  /**
   * Bumps the monotonic grant-set version AND fully clears the store (see
   * module header). Simulates grant add/revoke/config change.
   *
   * Contrast with a `policyVersion` change (the caller-supplied field, not a
   * method on this interface): that path relies on key-unreachability ALONE
   * — old entries are never actively cleared, they just linger under the
   * stale `policyVersion` until LRU eviction or TTL expiry reclaims them.
   * `bumpGrantSetVersion` instead clears eagerly. Both are R16-compliant
   * (unreachability alone already satisfies "no stale allow survives"); the
   * eager clear here is a deliberate extra (see `bumpGrantSetVersion`'s
   * implementation comment), not something `policyVersion` is required to
   * match.
   */
  bumpGrantSetVersion(): void;
  clear(): void;
  readonly stats: DecisionCacheStats;
}

export interface CreateDecisionCacheOptions {
  /** Epoch seconds. Never `Date.now()` internally — always this injected function. */
  nowEpochSeconds: () => number;
  /**
   * Config (E4-T2) may LOWER the routine/sensitive TTLs but never raise them
   * past brief §B2's caps (300s / 60s) — enforced via `clampTtl`, not just
   * documented.
   */
  ttlOverrides?: Partial<Record<"routine" | "sensitive", number>>;
  /** Simple max-entries LRU bound. Default 5000. */
  maxEntries?: number;
}

interface CacheEntry {
  decision: PrecedenceDecision;
  ttlSeconds: number;
  expiresAtEpochSeconds: number;
}

export function createDecisionCache(
  opts: CreateDecisionCacheOptions,
): DecisionCache {
  const { nowEpochSeconds, maxEntries = DEFAULT_MAX_ENTRIES } = opts;

  const ttlSecondsByTier: Record<"routine" | "sensitive", number> = {
    routine: clampTtl(
      opts.ttlOverrides?.routine ?? DEFAULT_ROUTINE_TTL_SECONDS,
      MAX_ROUTINE_TTL_SECONDS,
    ),
    sensitive: clampTtl(
      opts.ttlOverrides?.sensitive ?? DEFAULT_SENSITIVE_TTL_SECONDS,
      MAX_SENSITIVE_TTL_SECONDS,
    ),
  };

  let grantSetVersion = 0;
  // Map iteration order === insertion order in JS; combined with the
  // delete-then-reinsert dance below on every access, the map's key order
  // doubles as an LRU recency list with no extra bookkeeping structure.
  const store = new Map<string, CacheEntry>();
  let hits = 0;
  let misses = 0;

  function touch(key: string, entry: CacheEntry): void {
    store.delete(key);
    store.set(key, entry);
  }

  function evictOverflow(): void {
    while (store.size > maxEntries) {
      const oldestKey: string | undefined = store.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      store.delete(oldestKey);
    }
  }

  return {
    get(req, tier, policyVersion) {
      if (!isCacheableTier(tier)) {
        misses++;
        return undefined;
      }

      const key = computeCacheKey(req, tier, policyVersion, grantSetVersion);
      const entry = store.get(key);
      if (!entry) {
        misses++;
        return undefined;
      }

      if (nowEpochSeconds() >= entry.expiresAtEpochSeconds) {
        store.delete(key);
        misses++;
        return undefined;
      }

      touch(key, entry); // refresh LRU recency on hit
      hits++;
      return {
        decision: entry.decision,
        cache: { hit: true, ttlSeconds: entry.ttlSeconds },
      };
    },

    set(req, decision, policyVersion) {
      if (
        !isCacheableTier(decision.tier) ||
        !isCacheableOutcome(decision.outcome)
      ) {
        return; // silent no-op — see module header on why this guard is defense in depth
      }

      // Cast is safe only because the `isCacheableTier` guard above already
      // eliminated "critical" — `decision.tier` is narrowed to exactly
      // "routine" | "sensitive" at runtime, just not by TypeScript's control
      // flow analysis. If a 4th tier is ever added, both `isCacheableTier`
      // and `ttlSecondsByTier`'s key type must be extended together, or this
      // cast silently lies again.
      const ttlSeconds =
        ttlSecondsByTier[decision.tier as "routine" | "sensitive"];
      const key = computeCacheKey(
        req,
        decision.tier,
        policyVersion,
        grantSetVersion,
      );
      const entry: CacheEntry = {
        decision,
        ttlSeconds,
        expiresAtEpochSeconds: nowEpochSeconds() + ttlSeconds,
      };
      touch(key, entry);
      evictOverflow();
    },

    bumpGrantSetVersion() {
      grantSetVersion++;
      // Full clear on bump (documented P0-scale simplification — see module
      // header). Every entry keyed under the prior grantSetVersion is both
      // unreachable (versioned invalidation) and now physically freed
      // (active purge), satisfying architecture §7.3's "purge on revoke"
      // without needing per-principal/tool/resource selective invalidation.
      store.clear();
    },

    clear() {
      store.clear();
    },

    get stats(): DecisionCacheStats {
      return { hits, misses, size: store.size };
    },
  };
}
