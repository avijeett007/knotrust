import { describe, expect, it } from "vitest";
import type { DecisionRequest } from "./contract.js";
import type { CachedDecision, DecisionCache } from "./decision-cache.js";
import { computeCacheKey, createDecisionCache } from "./decision-cache.js";
import type { CoveringGrant } from "./l0-evaluator.js";
import { L0ReasonCode, resolveTier } from "./l0-evaluator.js";
import type { PrecedenceDecision } from "./precedence.js";
import { evaluatePrecedence } from "./precedence.js";
import type { TierPolicy, ToolTierEntry } from "./tier-policy.js";

// ---------------------------------------------------------------------------
// Fixture builders — mirrors precedence.test.ts's style/conventions.
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000;
const ROUTINE_ACTION = "github.list_issues";
const SENSITIVE_ACTION = "github.create_issue";
const CRITICAL_ACTION = "stripe.create_refund";
const POLICY_VERSION = "policy_v1";

function makeRequest(
  overrides: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01TEST00000000000000000000",
    timestamp: "2026-07-03T00:00:00.000Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: SENSITIVE_ACTION },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: "claude-desktop", type: "ai_agent" },
      env: { time: "2026-07-03T00:00:00Z", surfaceLocal: true },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px_test",
      server: "github-mcp",
    },
    ...overrides,
  };
}

function makeGrant(overrides: Partial<CoveringGrant> = {}): CoveringGrant {
  return {
    kind: "durable",
    tierCap: "sensitive",
    exp: NOW + 10_000,
    jti: "01GRANT0000000000000000000",
    ...overrides,
  };
}

function makePolicy(
  tools: Record<string, ToolTierEntry>,
  unknownToolTier: TierPolicy["unknownToolTier"] = "sensitive",
): TierPolicy {
  return { tools, unknownToolTier };
}

const TIER_POLICY = makePolicy({
  [ROUTINE_ACTION]: { tier: "routine", source: "user" },
  [SENSITIVE_ACTION]: { tier: "sensitive", source: "user" },
  [CRITICAL_ACTION]: { tier: "critical", source: "user" },
});

function makeDecision(
  overrides: Partial<PrecedenceDecision> = {},
): PrecedenceDecision {
  return {
    outcome: "allow",
    tier: "sensitive",
    reasonCode: L0ReasonCode.GrantAllow,
    precedenceLayer: 3,
    grantRef: "01GRANT0000000000000000000",
    ...overrides,
  };
}

/**
 * A grant-source spy: tracks read-call count so tests can assert "zero
 * grant-store reads" on a cache hit. Deliberately NOT a real store package
 * import (scope exclusion: "no store packages" — brief §5) — this is the
 * minimal shape the composition pipeline below needs.
 */
function makeGrantSourceSpy(grants: readonly CoveringGrant[]) {
  let calls = 0;
  let current = grants;
  return {
    read(): readonly CoveringGrant[] {
      calls++;
      return current;
    },
    setGrants(next: readonly CoveringGrant[]): void {
      current = next;
    },
    get calls(): number {
      return calls;
    },
  };
}

/**
 * The plan's acceptance composition (brief §"the plan's acceptance
 * composition test"): cache→precedence, cache-first. Tier resolution here
 * deliberately uses the plain (envelope-unaware) `resolveTier` — no envelope
 * is exercised in this task's composition test, so the pre-evaluation tier
 * used for the cache lookup always equals `evaluatePrecedence`'s own
 * (unclamped) resolved tier, keeping `get`'s and `set`'s cache keys
 * consistent. Envelope-clamp interaction with cache keying is out of this
 * task's scope (P0-E2-T3 already covers envelope clamping in isolation).
 *
 * This function lives ONLY in the test file — it is not exported production
 * code. The real pipeline composition is E2-T5's PdpAdapter (explicit scope
 * exclusion, brief §5).
 */
function decide(
  cache: DecisionCache,
  grantSource: { read: () => readonly CoveringGrant[] },
  request: DecisionRequest,
  tierPolicy: TierPolicy,
  nowEpochSeconds: number,
): PrecedenceDecision {
  const { tier } = resolveTier(
    request.action.name,
    tierPolicy,
    request.toolAnnotations,
  );

  const cached = cache.get(request, tier, POLICY_VERSION);
  if (cached) {
    return cached.decision;
  }

  const coveringGrants = grantSource.read();
  const decision = evaluatePrecedence({
    request,
    tierPolicy,
    coveringGrants,
    nowEpochSeconds,
  });

  cache.set(request, decision, POLICY_VERSION);
  return decision;
}

// ---------------------------------------------------------------------------
// Acceptance case 1/4: zero-store-read cache hit
// ---------------------------------------------------------------------------

describe("acceptance: zero-store-read cache hit", () => {
  it("first call misses and reads the grant store; identical second call hits with zero grant-store reads", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const grantSource = makeGrantSourceSpy([makeGrant()]);
    const request = makeRequest();

    const first = decide(cache, grantSource, request, TIER_POLICY, now);
    expect(first.outcome).toBe("allow");
    expect(grantSource.calls).toBe(1);
    expect(cache.stats.misses).toBe(1);
    expect(cache.stats.hits).toBe(0);

    const second = decide(cache, grantSource, request, TIER_POLICY, now);
    expect(second).toEqual(first);
    expect(grantSource.calls).toBe(1); // unchanged — zero additional grant-store reads
    expect(cache.stats.hits).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Acceptance case 2/4: revoke bumps grantSetVersion -> miss -> re-evaluate
// ---------------------------------------------------------------------------

describe("acceptance: revoke bumps grantSetVersion -> miss -> re-evaluate", () => {
  it("revoking a grant (bumpGrantSetVersion) then re-deciding the same call misses the cache and re-evaluates", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const grantSource = makeGrantSourceSpy([makeGrant()]);
    const request = makeRequest();

    const first = decide(cache, grantSource, request, TIER_POLICY, now);
    expect(first.outcome).toBe("allow");
    expect(grantSource.calls).toBe(1);

    // Cache hit: no re-read.
    decide(cache, grantSource, request, TIER_POLICY, now);
    expect(grantSource.calls).toBe(1);

    // Simulate revoke: the grant is gone from the store AND the cache is told to invalidate.
    grantSource.setGrants([]);
    cache.bumpGrantSetVersion();

    const third = decide(cache, grantSource, request, TIER_POLICY, now);
    expect(grantSource.calls).toBe(2); // re-invoked the grant store
    expect(third.outcome).toBe("deny"); // stale allow does NOT survive revocation
    expect(third.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });

  it("bumpGrantSetVersion purges unrelated cached entries too (documented full-clear-on-bump, P0 scale)", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const grantSourceA = makeGrantSourceSpy([makeGrant()]);
    const requestA = makeRequest({
      resource: { type: "github_repo", id: "repo-a" },
    });

    decide(cache, grantSourceA, requestA, TIER_POLICY, now);
    expect(cache.stats.size).toBe(1);

    cache.bumpGrantSetVersion();
    expect(cache.stats.size).toBe(0);

    // Re-deciding the SAME unrelated request now misses (proves an actual purge, not a no-op).
    decide(cache, grantSourceA, requestA, TIER_POLICY, now);
    expect(grantSourceA.calls).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Acceptance case 3/4: TTL expiry under fake clock
// ---------------------------------------------------------------------------

describe("acceptance: TTL expiry under fake clock", () => {
  it("a cached sensitive decision expires after 60s and re-invokes the grant store", () => {
    let now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const grantSource = makeGrantSourceSpy([makeGrant()]);
    const request = makeRequest();

    decide(cache, grantSource, request, TIER_POLICY, now);
    expect(grantSource.calls).toBe(1);

    now += 59; // still within TTL
    decide(cache, grantSource, request, TIER_POLICY, now);
    expect(grantSource.calls).toBe(1); // still a hit

    now += 1; // now exactly 60s elapsed — TTL boundary is exclusive (expired)
    const afterExpiry = decide(cache, grantSource, request, TIER_POLICY, now);
    expect(grantSource.calls).toBe(2); // re-invoked
    expect(afterExpiry.outcome).toBe("allow");
  });

  it("a cached routine decision expires after 300s, not 60s", () => {
    let now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const grantSource = makeGrantSourceSpy([]);
    const request = makeRequest({ action: { name: ROUTINE_ACTION } });

    decide(cache, grantSource, request, TIER_POLICY, now);
    expect(grantSource.calls).toBe(1);

    now += 299;
    decide(cache, grantSource, request, TIER_POLICY, now);
    expect(grantSource.calls).toBe(1); // still cached at 299s

    now += 1; // 300s elapsed
    decide(cache, grantSource, request, TIER_POLICY, now);
    expect(grantSource.calls).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Acceptance case 4/4: critical decision is never inserted
// ---------------------------------------------------------------------------

describe("acceptance: critical decision is never inserted", () => {
  it("set() with tier critical is a no-op even for an outcome that would otherwise be cacheable (allow)", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const criticalAllow = makeDecision({
      tier: "critical",
      outcome: "allow",
      precedenceLayer: 3,
    });

    cache.set(request, criticalAllow, POLICY_VERSION);

    expect(cache.stats.size).toBe(0);
    expect(cache.get(request, "critical", POLICY_VERSION)).toBeUndefined();
  });

  it("get() with tier critical always misses, never touching the store even after an attempted set()", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    cache.set(
      request,
      makeDecision({ tier: "critical", outcome: "deny" }),
      POLICY_VERSION,
    );

    expect(cache.get(request, "critical", POLICY_VERSION)).toBeUndefined();
    expect(cache.stats.misses).toBeGreaterThan(0);
  });

  it("full pipeline: two identical critical decisions both re-invoke the grant store (never a cache hit)", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const grantSource = makeGrantSourceSpy([
      makeGrant({ tierCap: "critical" }),
    ]);
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });

    const first = decide(cache, grantSource, request, TIER_POLICY, now);
    const second = decide(cache, grantSource, request, TIER_POLICY, now);

    expect(first.outcome).toBe("allow");
    expect(second.outcome).toBe("allow");
    expect(grantSource.calls).toBe(2); // never cached, always re-evaluated
    expect(cache.stats.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Only allow/deny outcomes are cacheable
// ---------------------------------------------------------------------------

describe("only allow/deny outcomes are cacheable", () => {
  it("set() with outcome pending_approval is a no-op", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const pending = makeDecision({
      tier: "critical",
      outcome: "pending_approval",
      reasonCode: L0ReasonCode.NoGrantCritical,
      precedenceLayer: 4,
      wantsApproval: true,
    });

    cache.set(request, pending, POLICY_VERSION);

    expect(cache.stats.size).toBe(0);
  });

  it("set() with outcome pending_approval at a cacheable tier (sensitive) is STILL a no-op", () => {
    // PrecedenceDecision.outcome is typed as L0Outcome (allow|deny|pending_approval) —
    // deliberately exercised here at sensitive tier (not critical) to prove the
    // outcome-cacheability guard is independent of the tier guard.
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const request = makeRequest();
    const pendingAtSensitive: PrecedenceDecision = {
      outcome: "pending_approval",
      tier: "sensitive",
      reasonCode: "envelope_force_approval",
      precedenceLayer: 1,
      wantsApproval: true,
    };

    cache.set(request, pendingAtSensitive, POLICY_VERSION);

    expect(cache.stats.size).toBe(0);
    expect(cache.get(request, "sensitive", POLICY_VERSION)).toBeUndefined();
  });

  it("`deferred_not_eligible` can never reach set() by construction (PrecedenceDecision.outcome excludes it) — the runtime guard is defense in depth, verified via a type cast", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const request = makeRequest();
    const deferred = {
      ...makeDecision({ tier: "sensitive" }),
      outcome: "deferred_not_eligible",
    } as unknown as PrecedenceDecision;

    cache.set(request, deferred, POLICY_VERSION);

    expect(cache.stats.size).toBe(0);
  });

  it("set() with outcome allow or deny at a cacheable tier IS inserted", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const request = makeRequest();

    cache.set(
      request,
      makeDecision({ outcome: "deny", tier: "sensitive" }),
      POLICY_VERSION,
    );

    expect(cache.stats.size).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Cache key stability — volatile-field exclusion, property-order independence
// ---------------------------------------------------------------------------

describe("cache key stability", () => {
  it("two requests differing only in requestId/timestamp/env share a cache key", () => {
    const a = makeRequest({
      requestId: "01AAAA00000000000000000000",
      timestamp: "2026-07-03T00:00:00.000Z",
      context: {
        agent: { id: "claude-desktop", type: "ai_agent" },
        env: { time: "2026-07-03T00:00:00Z", surfaceLocal: true },
      },
    });
    const b = makeRequest({
      requestId: "01BBBB00000000000000000000",
      timestamp: "2026-07-03T12:34:56.000Z",
      context: {
        agent: { id: "claude-desktop", type: "ai_agent" },
        env: { time: "2026-07-03T12:34:56Z", surfaceLocal: false, extra: "x" },
      },
    });

    expect(computeCacheKey(a, "sensitive", POLICY_VERSION, 0)).toBe(
      computeCacheKey(b, "sensitive", POLICY_VERSION, 0),
    );
  });

  it("a set() under request A is retrievable via get() under request B when they differ only in volatile fields", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const a = makeRequest({ requestId: "01AAAA00000000000000000000" });
    const b = makeRequest({ requestId: "01BBBB00000000000000000000" });

    cache.set(a, makeDecision(), POLICY_VERSION);
    const hit = cache.get(b, "sensitive", POLICY_VERSION);

    expect(hit).toBeDefined();
  });

  it("cache key is stable under resource.properties insertion-order variation", () => {
    const a = makeRequest({
      resource: {
        type: "stripe_charge",
        id: "ch_1",
        properties: { amount: 100, currency: "usd" },
      },
    });
    const b = makeRequest({
      resource: {
        type: "stripe_charge",
        id: "ch_1",
        properties: { currency: "usd", amount: 100 },
      },
    });

    expect(computeCacheKey(a, "sensitive", POLICY_VERSION, 0)).toBe(
      computeCacheKey(b, "sensitive", POLICY_VERSION, 0),
    );
  });

  it("cache key differs when subject.id differs", () => {
    const a = makeRequest({ subject: { type: "user", id: "user-a" } });
    const b = makeRequest({ subject: { type: "user", id: "user-b" } });

    expect(computeCacheKey(a, "sensitive", POLICY_VERSION, 0)).not.toBe(
      computeCacheKey(b, "sensitive", POLICY_VERSION, 0),
    );
  });

  it("cache key differs when resource.properties differ", () => {
    const a = makeRequest({
      resource: {
        type: "stripe_charge",
        id: "ch_1",
        properties: { amount: 100 },
      },
    });
    const b = makeRequest({
      resource: {
        type: "stripe_charge",
        id: "ch_1",
        properties: { amount: 200 },
      },
    });

    expect(computeCacheKey(a, "sensitive", POLICY_VERSION, 0)).not.toBe(
      computeCacheKey(b, "sensitive", POLICY_VERSION, 0),
    );
  });

  it("cache key differs when policyVersion differs", () => {
    const req = makeRequest();
    expect(computeCacheKey(req, "sensitive", "v1", 0)).not.toBe(
      computeCacheKey(req, "sensitive", "v2", 0),
    );
  });

  it("cache key differs when grantSetVersion differs", () => {
    const req = makeRequest();
    expect(computeCacheKey(req, "sensitive", POLICY_VERSION, 0)).not.toBe(
      computeCacheKey(req, "sensitive", POLICY_VERSION, 1),
    );
  });

  it("cache key differs when surface.server differs (per-server caching)", () => {
    const a = makeRequest({
      surface: { kind: "stdio_proxy", instanceId: "px", server: "server-a" },
    });
    const b = makeRequest({
      surface: { kind: "stdio_proxy", instanceId: "px", server: "server-b" },
    });

    expect(computeCacheKey(a, "sensitive", POLICY_VERSION, 0)).not.toBe(
      computeCacheKey(b, "sensitive", POLICY_VERSION, 0),
    );
  });

  it("cache key differs when context.agent.id differs", () => {
    const a = makeRequest({
      context: {
        agent: { id: "agent-a", type: "ai_agent" },
        env: { time: "t", surfaceLocal: true },
      },
    });
    const b = makeRequest({
      context: {
        agent: { id: "agent-b", type: "ai_agent" },
        env: { time: "t", surfaceLocal: true },
      },
    });

    expect(computeCacheKey(a, "sensitive", POLICY_VERSION, 0)).not.toBe(
      computeCacheKey(b, "sensitive", POLICY_VERSION, 0),
    );
  });
});

// ---------------------------------------------------------------------------
// TTL defaults + ttlOverrides clamp (never above brief §B2's caps)
// ---------------------------------------------------------------------------

describe("TTL defaults and ttlOverrides clamp", () => {
  it("defaults: routine 300s, sensitive 60s (reported via CachedDecision.cache.ttlSeconds)", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const routineReq = makeRequest({ action: { name: ROUTINE_ACTION } });
    const sensitiveReq = makeRequest();

    cache.set(
      routineReq,
      makeDecision({
        tier: "routine",
        reasonCode: L0ReasonCode.RoutineDefaultAllow,
        precedenceLayer: 4,
      }),
      POLICY_VERSION,
    );
    cache.set(
      sensitiveReq,
      makeDecision({ tier: "sensitive" }),
      POLICY_VERSION,
    );

    const routineHit = cache.get(
      routineReq,
      "routine",
      POLICY_VERSION,
    ) as CachedDecision;
    const sensitiveHit = cache.get(
      sensitiveReq,
      "sensitive",
      POLICY_VERSION,
    ) as CachedDecision;

    expect(routineHit.cache.ttlSeconds).toBe(300);
    expect(sensitiveHit.cache.ttlSeconds).toBe(60);
    expect(routineHit.cache.hit).toBe(true);
  });

  it("ttlOverrides may LOWER sensitive below 60s and it is honored as-is", () => {
    const now = NOW;
    const cache = createDecisionCache({
      nowEpochSeconds: () => now,
      ttlOverrides: { sensitive: 10 },
    });
    const req = makeRequest();
    cache.set(req, makeDecision({ tier: "sensitive" }), POLICY_VERSION);

    const hit = cache.get(req, "sensitive", POLICY_VERSION) as CachedDecision;
    expect(hit.cache.ttlSeconds).toBe(10);
  });

  it("ttlOverrides can never RAISE sensitive above 60s — clamped at createDecisionCache", () => {
    const now = NOW;
    const cache = createDecisionCache({
      nowEpochSeconds: () => now,
      ttlOverrides: { sensitive: 3600 },
    });
    const req = makeRequest();
    cache.set(req, makeDecision({ tier: "sensitive" }), POLICY_VERSION);

    const hit = cache.get(req, "sensitive", POLICY_VERSION) as CachedDecision;
    expect(hit.cache.ttlSeconds).toBe(60);
  });

  it("ttlOverrides can never RAISE routine above 300s — clamped at createDecisionCache", () => {
    const now = NOW;
    const cache = createDecisionCache({
      nowEpochSeconds: () => now,
      ttlOverrides: { routine: 999_999 },
    });
    const req = makeRequest({ action: { name: ROUTINE_ACTION } });
    cache.set(
      req,
      makeDecision({
        tier: "routine",
        reasonCode: L0ReasonCode.RoutineDefaultAllow,
        precedenceLayer: 4,
      }),
      POLICY_VERSION,
    );

    const hit = cache.get(req, "routine", POLICY_VERSION) as CachedDecision;
    expect(hit.cache.ttlSeconds).toBe(300);
  });
});

// ---------------------------------------------------------------------------
// Bounded memory: max-entries LRU eviction
// ---------------------------------------------------------------------------

describe("bounded memory: max-entries LRU eviction", () => {
  it("evicts the oldest-accessed entry first when maxEntries is exceeded", () => {
    const now = NOW;
    const cache = createDecisionCache({
      nowEpochSeconds: () => now,
      maxEntries: 2,
    });

    const reqA = makeRequest({ resource: { type: "r", id: "a" } });
    const reqB = makeRequest({ resource: { type: "r", id: "b" } });
    const reqC = makeRequest({ resource: { type: "r", id: "c" } });

    cache.set(reqA, makeDecision(), POLICY_VERSION);
    cache.set(reqB, makeDecision(), POLICY_VERSION);
    expect(cache.stats.size).toBe(2);

    // Access A so it becomes most-recently-used; B is now the oldest-accessed.
    cache.get(reqA, "sensitive", POLICY_VERSION);

    // Inserting C should evict B (the oldest-accessed), not A.
    cache.set(reqC, makeDecision(), POLICY_VERSION);

    expect(cache.stats.size).toBe(2);
    expect(cache.get(reqA, "sensitive", POLICY_VERSION)).toBeDefined();
    expect(cache.get(reqB, "sensitive", POLICY_VERSION)).toBeUndefined();
    expect(cache.get(reqC, "sensitive", POLICY_VERSION)).toBeDefined();
  });

  it("defaults maxEntries to 5000", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    for (let i = 0; i < 5001; i++) {
      const req = makeRequest({ resource: { type: "r", id: `id-${i}` } });
      cache.set(req, makeDecision(), POLICY_VERSION);
    }
    expect(cache.stats.size).toBe(5000);
  });
});

// ---------------------------------------------------------------------------
// clear()
// ---------------------------------------------------------------------------

describe("clear()", () => {
  it("empties the store", () => {
    const now = NOW;
    const cache = createDecisionCache({ nowEpochSeconds: () => now });
    const req = makeRequest();
    cache.set(req, makeDecision(), POLICY_VERSION);
    expect(cache.stats.size).toBe(1);

    cache.clear();

    expect(cache.stats.size).toBe(0);
    expect(cache.get(req, "sensitive", POLICY_VERSION)).toBeUndefined();
  });
});
