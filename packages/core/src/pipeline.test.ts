import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { FormatsPlugin } from "ajv-formats";
import { describe, expect, it, vi } from "vitest";
import { canonicalStringify } from "./canonical-json.js";
import type { DecisionRequest, DecisionResponse } from "./contract.js";
import type { DecisionCache } from "./decision-cache.js";
import { createDecisionCache } from "./decision-cache.js";
import type {
  PdpAdapter,
  PdpDecision,
  PdpEvaluationContext,
} from "./pdp-port.js";
import {
  computeEffectivePolicyVersion,
  createDecisionPipeline,
} from "./pipeline.js";
import type { AdminEnvelope } from "./precedence.js";
import type { TierPolicy, ToolTierEntry } from "./tier-policy.js";

// ---------------------------------------------------------------------------
// Schema loading (mirrors contract.test.ts's ajv setup — validates pipeline
// outputs against the SAME shared decision.v1.schema.json, not a parallel
// copy).
// ---------------------------------------------------------------------------

const require = createRequire(import.meta.url);
const addFormats: FormatsPlugin = require("ajv-formats");

const here = path.dirname(fileURLToPath(import.meta.url));
const schemasDir = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "schemas",
);

function loadSchema(fileName: string): object {
  return JSON.parse(
    readFileSync(path.join(schemasDir, fileName), "utf8"),
  ) as object;
}

const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);
const validateDecisionResponse = ajv.compile(
  loadSchema("decision.v1.schema.json"),
);

function expectValidDecisionResponse(response: DecisionResponse): void {
  const serialized = JSON.parse(JSON.stringify(response)) as unknown;
  const valid = validateDecisionResponse(serialized);
  expect(validateDecisionResponse.errors).toBeNull();
  expect(valid).toBe(true);
}

// ---------------------------------------------------------------------------
// Fixture builders (mirrors precedence.test.ts / decision-cache.test.ts's
// style/conventions).
// ---------------------------------------------------------------------------

const NOW_EPOCH_SECONDS = 1_800_000_000;
const ACTION = "github.create_issue";
const POLICY_VERSION = "policy_v1";

function makeRequest(
  overrides: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01TEST00000000000000000000",
    timestamp: "2026-07-03T00:00:00.000Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: ACTION },
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

function makePolicy(
  tools: Record<string, ToolTierEntry>,
  unknownToolTier: TierPolicy["unknownToolTier"] = "sensitive",
): TierPolicy {
  return { tools, unknownToolTier };
}

/** A stub `PdpAdapter` whose `decide()` always returns whatever `nextDecision` currently holds, and counts calls (the acceptance test's "spy"). */
function makeStubAdapter(initial: PdpDecision) {
  let nextDecision = initial;
  const decide = vi.fn(async (): Promise<PdpDecision> => nextDecision);
  return {
    adapter: {
      capabilities: { name: "stub", latencyClass: "in_process" as const },
      decide,
    } satisfies PdpAdapter,
    setNextDecision(d: PdpDecision): void {
      nextDecision = d;
    },
    get calls(): number {
      return decide.mock.calls.length;
    },
  };
}

function makeIdGenerator(prefix = "01ID"): () => string {
  let n = 0;
  return () => `${prefix}${String(n++).padStart(22, "0")}`;
}

function makeCache(): DecisionCache {
  return createDecisionCache({ nowEpochSeconds: () => NOW_EPOCH_SECONDS });
}

// ---------------------------------------------------------------------------
// Acceptance: a stub adapter returning each of the four outcomes; the
// pipeline handles all four with correct DecisionResponse assembly and
// cacheability honored (allow/deny cached, pending_approval/deferred_not_eligible
// + critical never).
// ---------------------------------------------------------------------------

describe("createDecisionPipeline — four-outcome stub adapter acceptance", () => {
  const tierPolicy = makePolicy({
    [ACTION]: { tier: "sensitive", source: "user" },
  });

  it("outcome: allow (sensitive, cacheable) — assembles response and populates the cache", async () => {
    const cache = makeCache();
    const stub = makeStubAdapter({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: "stub_allow",
      evaluatedBy: "cedar",
      grantRef: "01GRANT0000000000000000000",
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    const response = await pipeline.decide({
      request,
      tierPolicy,
      coveringGrants: [],
    });

    expect(response.outcome).toBe("allow");
    expect(response.tier).toBe("sensitive");
    expect(response.reasonCode).toBe("stub_allow");
    expect(response.evaluatedBy).toBe("cedar");
    expect(response.cache).toEqual({ hit: false });
    expect(response.approval).toBeUndefined();
    expect(stub.calls).toBe(1);
    expectValidDecisionResponse(response);

    expect(cache.stats.size).toBe(1); // allow was cached
  });

  it("outcome: deny (sensitive, cacheable, requestable) — assembles response and populates the cache", async () => {
    const cache = makeCache();
    const stub = makeStubAdapter({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: "no_grant_sensitive",
      evaluatedBy: "opa",
      requestable: {
        how: "knotrust grant --tool github.create_issue --server github-mcp",
      },
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    const response = await pipeline.decide({
      request,
      tierPolicy,
      coveringGrants: [],
    });

    expect(response.outcome).toBe("deny");
    expect(response.requestable).toEqual({
      how: "knotrust grant --tool github.create_issue --server github-mcp",
    });
    expect(response.cache).toEqual({ hit: false });
    expectValidDecisionResponse(response);

    expect(cache.stats.size).toBe(1); // deny was cached
  });

  it("outcome: pending_approval (critical) — no approval handle attached, NOT cached", async () => {
    const cache = makeCache();
    const criticalPolicy = makePolicy({
      [ACTION]: { tier: "critical", source: "user" },
    });
    const stub = makeStubAdapter({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: "no_grant_critical",
      evaluatedBy: "L0",
      wantsApproval: true,
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    const response = await pipeline.decide({
      request,
      tierPolicy: criticalPolicy,
      coveringGrants: [],
    });

    expect(response.outcome).toBe("pending_approval");
    expect(response.tier).toBe("critical");
    // The approval-orchestrator seam: pipeline never mints a handle itself.
    expect(response.approval).toBeUndefined();
    expect(response.cache).toEqual({ hit: false });
    expectValidDecisionResponse(response);

    expect(cache.stats.size).toBe(0); // critical is never cached

    // A second identical call re-invokes the adapter — proves nothing was cached.
    await pipeline.decide({
      request,
      tierPolicy: criticalPolicy,
      coveringGrants: [],
    });
    expect(stub.calls).toBe(2);
  });

  it("outcome: deferred_not_eligible — assembles response, NOT cached", async () => {
    const cache = makeCache();
    const criticalPolicy = makePolicy({
      [ACTION]: { tier: "critical", source: "user" },
    });
    const stub = makeStubAdapter({
      outcome: "deferred_not_eligible",
      tier: "critical",
      reasonCode: "channel_not_eligible",
      evaluatedBy: "L0",
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    const response = await pipeline.decide({
      request,
      tierPolicy: criticalPolicy,
      coveringGrants: [],
    });

    expect(response.outcome).toBe("deferred_not_eligible");
    expect(response.approval).toBeUndefined();
    expect(response.cache).toEqual({ hit: false });
    expectValidDecisionResponse(response);

    expect(cache.stats.size).toBe(0); // deferred_not_eligible is never cached

    await pipeline.decide({
      request,
      tierPolicy: criticalPolicy,
      coveringGrants: [],
    });
    expect(stub.calls).toBe(2); // re-invoked — nothing was cached
  });
});

// ---------------------------------------------------------------------------
// Acceptance: cache-hit path never calls adapter.decide (spy).
// ---------------------------------------------------------------------------

describe("createDecisionPipeline — cache-hit path never calls adapter.decide", () => {
  const tierPolicy = makePolicy({
    [ACTION]: { tier: "sensitive", source: "user" },
  });

  it("second identical decide() call is served from cache without invoking the adapter", async () => {
    const cache = makeCache();
    const stub = makeStubAdapter({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: "stub_allow",
      evaluatedBy: "L0",
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    const first = await pipeline.decide({
      request,
      tierPolicy,
      coveringGrants: [],
    });
    expect(first.cache).toEqual({ hit: false });
    expect(stub.calls).toBe(1);

    const second = await pipeline.decide({
      request,
      tierPolicy,
      coveringGrants: [],
    });
    expect(second.cache.hit).toBe(true);
    expect(second.cache.ttlSeconds).toBeGreaterThan(0);
    expect(stub.calls).toBe(1); // NOT re-invoked — served from cache

    // Cache hit still assembles a full, valid, correctly-populated response,
    // and mints its own fresh decisionId (a cache hit is still a new
    // decision/audit event).
    expect(second.outcome).toBe("allow");
    expect(second.tier).toBe("sensitive");
    expect(second.reasonCode).toBe("stub_allow");
    expect(second.evaluatedBy).toBe("L0");
    expect(second.decisionId).not.toBe(first.decisionId);
    expectValidDecisionResponse(second);
  });

  it("changing the stub's next decision after a cache hit has no effect — the adapter is genuinely never called again", async () => {
    const cache = makeCache();
    const stub = makeStubAdapter({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: "stub_allow",
      evaluatedBy: "L0",
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    await pipeline.decide({ request, tierPolicy, coveringGrants: [] });
    stub.setNextDecision({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: "should_never_be_seen",
      evaluatedBy: "L0",
    });

    const second = await pipeline.decide({
      request,
      tierPolicy,
      coveringGrants: [],
    });
    expect(second.outcome).toBe("allow"); // still the original cached decision
    expect(stub.calls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Injected clock/id plumbing.
// ---------------------------------------------------------------------------

describe("createDecisionPipeline — injected nowMs / generateId", () => {
  it("uses the injected nowMs clock for latencyMs, not a real wall clock", async () => {
    const cache = makeCache();
    const stub = makeStubAdapter({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: "stub_allow",
      evaluatedBy: "L0",
    });
    let clock = 1000;
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
      nowMs: () => {
        const t = clock;
        clock += 7;
        return t;
      },
    });

    const response = await pipeline.decide({
      request: makeRequest(),
      tierPolicy: makePolicy({
        [ACTION]: { tier: "sensitive", source: "user" },
      }),
      coveringGrants: [],
    });

    expect(response.latencyMs).toBe(7);
  });

  it("calls generateId() to mint decisionId, never fabricating one itself", async () => {
    const cache = makeCache();
    const stub = makeStubAdapter({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: "stub_allow",
      evaluatedBy: "L0",
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: () => "01FIXEDDECISIONID000000001",
    });

    const response = await pipeline.decide({
      request: makeRequest(),
      tierPolicy: makePolicy({
        [ACTION]: { tier: "sensitive", source: "user" },
      }),
      coveringGrants: [],
    });

    expect(response.decisionId).toBe("01FIXEDDECISIONID000000001");
  });
});

// ---------------------------------------------------------------------------
// The pinned cache-key-tier rule: cache.set is keyed off the pipeline's OWN
// resolved tier, never off a divergent `decision.tier` the adapter reports.
// ---------------------------------------------------------------------------

describe("createDecisionPipeline — pinned cache-key-tier rule", () => {
  it("a decision resolved at critical tier is never cached even if the adapter mis-reports a laxer tier", async () => {
    const cache = makeCache();
    const criticalPolicy = makePolicy({
      [ACTION]: { tier: "critical", source: "user" },
    });
    const stub = makeStubAdapter({
      outcome: "allow",
      tier: "routine", // adapter mis-reports a laxer tier than KnoTrust's own resolution
      reasonCode: "stub_allow",
      evaluatedBy: "cedar",
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    const response = await pipeline.decide({
      request,
      tierPolicy: criticalPolicy,
      coveringGrants: [],
    });

    // The pipeline's OWN resolution wins for the response's tier field...
    expect(response.tier).toBe("critical");
    // ...and, because that resolution says critical, nothing is cached —
    // even though the adapter reported "routine" (which would have been
    // cacheable on its own).
    expect(cache.stats.size).toBe(0);

    await pipeline.decide({
      request,
      tierPolicy: criticalPolicy,
      coveringGrants: [],
    });
    expect(stub.calls).toBe(2); // re-invoked — proves it was never cached
  });
});

// ---------------------------------------------------------------------------
// R20 fix round 1: the policy fingerprint must discriminate the cache key on
// `tierPolicy`/`envelope` CONTENT, not just the resolved tier — this is the
// reviewer's exact locked reproduction (finding 1 on P0-E2-T5).
// ---------------------------------------------------------------------------

/**
 * Casts a `DecisionPipeline` to read the test-only, non-enumerable
 * `__policyFingerprintComputeCountForTests` property `pipeline.ts` attaches
 * to each instance (see that file's `createDecisionPipeline` for why this is
 * a property on the instance rather than a module export: it keeps
 * `@knotrust/core`'s public package surface — `index.ts`'s
 * `export * from "./pipeline.js"` — untouched).
 */
function getPolicyFingerprintComputeCount(pipeline: unknown): number {
  return (
    pipeline as { readonly __policyFingerprintComputeCountForTests: number }
  ).__policyFingerprintComputeCountForTests;
}

describe("createDecisionPipeline — policy fingerprint discriminates the cache key (R20)", () => {
  const tierPolicy = makePolicy({
    [ACTION]: { tier: "sensitive", source: "user" },
  });

  /**
   * Envelope-aware stub: mirrors exactly what a real `PdpAdapter` (e.g. the
   * L0 adapter, via `evaluatePrecedence`'s layer 1) does with
   * `envelope.denyTools` — a decisive deny, independent of any covering
   * grant. This is NOT re-implementing precedence logic for its own sake;
   * it exists solely so this test can observe, at the PIPELINE boundary,
   * whether a `decide()` call reached the adapter at all (a cache MISS) or
   * was served a stale cached value (a cache HIT) — the exact distinction
   * the reviewer's probe turns on.
   */
  function makeEnvelopeAwareAdapter(): {
    adapter: PdpAdapter;
    decide: ReturnType<typeof vi.fn>;
  } {
    const decide = vi.fn(
      async (
        _req: DecisionRequest,
        ctx: PdpEvaluationContext,
      ): Promise<PdpDecision> => {
        if (ctx.envelope?.denyTools?.includes(ACTION)) {
          return {
            outcome: "deny",
            tier: "sensitive",
            reasonCode: "envelope_deny",
            evaluatedBy: "L0",
          };
        }
        return {
          outcome: "allow",
          tier: "sensitive",
          reasonCode: "stub_allow",
          evaluatedBy: "L0",
          grantRef: "01GRANT0000000000000000000",
        };
      },
    );
    return {
      decide,
      adapter: {
        capabilities: {
          name: "envelope-aware-stub",
          latencyClass: "in_process",
        },
        decide,
      },
    };
  }

  it("locked reproduction: call 2 (same request/policyVersion, envelope.denyTools added) MISSES and returns envelope_deny; call 3 (repeat of call 1) HITS call 1's original allow", async () => {
    const cache = makeCache();
    const { adapter, decide } = makeEnvelopeAwareAdapter();
    const pipeline = createDecisionPipeline({
      adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    // Call 1: no envelope (a covering grant is present in the reviewer's
    // exact reproduction shape; the stub's own `allow` branch stands in for
    // "a covering grant made this an allow") — MISS, allow, cached.
    const call1 = await pipeline.decide({
      request,
      tierPolicy,
      coveringGrants: [],
    });
    expect(call1.outcome).toBe("allow");
    expect(call1.cache).toEqual({ hit: false });
    expect(decide).toHaveBeenCalledTimes(1);

    // Call 2: SAME request, SAME tierPolicy object, SAME policyVersion —
    // but `envelope.denyTools` now covers the action. Pre-fix, this
    // incorrectly HIT call 1's stale `allow` entry (same resolved tier
    // "sensitive", same policyVersion — nothing else was in the cache key).
    // Post-fix, the policy fingerprint differs, so this MUST miss and
    // re-invoke the adapter, which correctly returns `envelope_deny`.
    const envelope: AdminEnvelope = { scope: "personal", denyTools: [ACTION] };
    const call2 = await pipeline.decide({
      request,
      tierPolicy,
      envelope,
      coveringGrants: [],
    });
    expect(call2.cache).toEqual({ hit: false }); // MUST MISS — proves the fix
    expect(call2.outcome).toBe("deny");
    expect(call2.reasonCode).toBe("envelope_deny");
    expect(decide).toHaveBeenCalledTimes(2);

    // Call 3: repeat of call 1's exact input (no envelope) — served from
    // call 1's cache entry (hit), proving the fingerprint DISCRIMINATES
    // rather than disabling caching outright.
    const call3 = await pipeline.decide({
      request,
      tierPolicy,
      coveringGrants: [],
    });
    expect(call3.cache.hit).toBe(true);
    expect(call3.outcome).toBe("allow");
    expect(decide).toHaveBeenCalledTimes(2); // NOT re-invoked — served from cache
  });

  it("memoizes the policy fingerprint per (tierPolicy, envelope) object identity — repeated calls with the SAME objects hash once", async () => {
    const cache = makeCache();
    const stub = makeStubAdapter({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: "stub_allow",
      evaluatedBy: "L0",
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const memoTierPolicy = makePolicy({
      [ACTION]: { tier: "sensitive", source: "user" },
    });
    const request = makeRequest();

    for (let i = 0; i < 5; i++) {
      await pipeline.decide({
        request,
        tierPolicy: memoTierPolicy,
        coveringGrants: [],
      });
    }

    // 5 calls, same `memoTierPolicy` object and the same (absent) envelope
    // every time — the SHA-256 hash must have run exactly once, not 5 times.
    expect(getPolicyFingerprintComputeCount(pipeline)).toBe(1);
  });

  it("a DIFFERENT tierPolicy/envelope object with equal-by-value content still hashes again (identity-keyed, not value-keyed, by design)", async () => {
    const cache = makeCache();
    const stub = makeStubAdapter({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: "stub_allow",
      evaluatedBy: "L0",
    });
    const pipeline = createDecisionPipeline({
      adapter: stub.adapter,
      cache,
      policyVersion: POLICY_VERSION,
      nowEpochSeconds: () => NOW_EPOCH_SECONDS,
      generateId: makeIdGenerator(),
    });
    const request = makeRequest();

    await pipeline.decide({
      request,
      tierPolicy: makePolicy({
        [ACTION]: { tier: "sensitive", source: "user" },
      }),
      coveringGrants: [],
    });
    await pipeline.decide({
      request,
      // A structurally-identical but distinct object reference.
      tierPolicy: makePolicy({
        [ACTION]: { tier: "sensitive", source: "user" },
      }),
      coveringGrants: [],
    });

    expect(getPolicyFingerprintComputeCount(pipeline)).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// P0-E5-T3 fix round 1, Minor 1 — `computeEffectivePolicyVersion` extraction.
//
// Before this fix, `@knotrust/grants`'s `createDecider` (ADR-0020) carried a
// byte-for-byte COPY of this exact formula rather than calling shared code.
// This locks the extracted export's output against a hand-rolled
// reproduction of the ORIGINAL (pre-extraction) inline expression, for both
// the "envelope present" and "envelope absent" branches — proving the
// extraction changed nothing observable, and that `@knotrust/grants`'s
// decider (which imports and calls this same export — see
// `packages/grants/src/decider.ts` and its own
// "computeEffectivePolicyVersion parity" test) can never drift from the
// pipeline's cache-key semantics again.
// ---------------------------------------------------------------------------

describe("computeEffectivePolicyVersion (P0-E5-T3 fix round 1, Minor 1 — shared R20 formula)", () => {
  const tierPolicy = makePolicy({
    [ACTION]: { tier: "sensitive", source: "user" },
  });
  const policyVersion = "policy-v42";

  it("reproduces the original inline sha256(canonicalStringify({tierPolicy, envelope})) + policyVersion-colon-fingerprint string, envelope present", () => {
    const envelope: AdminEnvelope = { scope: "personal", denyTools: [ACTION] };
    const expectedFingerprint = createHash("sha256")
      .update(canonicalStringify({ tierPolicy, envelope }), "utf8")
      .digest("hex");
    const expected = `${policyVersion}:${expectedFingerprint}`;

    expect(
      computeEffectivePolicyVersion(tierPolicy, envelope, policyVersion),
    ).toBe(expected);
  });

  it("reproduces the original inline formula for the envelope-ABSENT branch (hashed against `null`, per the original expression)", () => {
    const expectedFingerprint = createHash("sha256")
      .update(canonicalStringify({ tierPolicy, envelope: null }), "utf8")
      .digest("hex");
    const expected = `${policyVersion}:${expectedFingerprint}`;

    expect(
      computeEffectivePolicyVersion(tierPolicy, undefined, policyVersion),
    ).toBe(expected);
  });

  it("is a pure function of its three arguments — same inputs, same output, called repeatedly", () => {
    const first = computeEffectivePolicyVersion(
      tierPolicy,
      undefined,
      policyVersion,
    );
    const second = computeEffectivePolicyVersion(
      tierPolicy,
      undefined,
      policyVersion,
    );
    expect(second).toBe(first);
  });
});
