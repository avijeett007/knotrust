/**
 * @knotrust/grants — the unified canonical decider (P0-E5-T3; rulings
 * R68/R69, seam obligations E5-I1/E5-I2).
 *
 * This is E5-I1's PROOF: ONE decider composed over the REAL cache
 * (`@knotrust/core`), REAL grant store + REAL hash-chained audit log
 * (`@knotrust/store`), and the REAL precedence/consume algorithm
 * (`decideCore`) — never mocks — exercising:
 *
 *   - miss → allow (cached), hit → allow (cache) with ZERO grant-store reads,
 *   - a covering-grant allow,
 *   - a single-use grant consumed EXACTLY once (second identical call misses
 *     the cache AND is denied `grant_replayed`, never served the cached allow),
 *   - revoke + bump → next decide misses and denies,
 *   - every decision (incl. cache hits) appends EXACTLY one decision event.
 *
 * Plus E5-I2 (R69): the `isCacheableDecision` predicate and the
 * single-use-`grant_allow`-is-never-cached proof.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type {
  AdminEnvelope,
  DecisionRequest,
  TierPolicy,
} from "@knotrust/core";
import {
  computeEffectivePolicyVersion,
  createDecisionCache,
} from "@knotrust/core";
import {
  type AuditEvent,
  type AuditSink,
  createAuditLog,
  createGrantStore,
  type GrantStore,
} from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createDecider, isCacheableDecision } from "./decider.js";
import { makeTestKeyStore, resolverFor } from "./grant-test-kit.js";
import type { GrantedDecision } from "./lifecycle.js";
import {
  decodeGrantIndexEntry,
  mintDurableGrant,
  mintEphemeralGrant,
} from "./lifecycle.js";
import { revokeGrants } from "./revoke.js";

// ---------------------------------------------------------------------------
// Shared fixtures — mirrors revocation.integration.test.ts's composition
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000;
const keyStore = makeTestKeyStore();
const resolvePublicKey = resolverFor(
  keyStore.identity.kid,
  keyStore.publicKeyJwk,
);

function makeIdGen(prefix = "TESTDEC"): () => string {
  let n = 0;
  return () => `${prefix}${String(n++).padStart(4, "0")}`;
}

let tempHome: string;
let store: GrantStore;
let audit: AuditSink;

beforeEach(() => {
  tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-decider-"));
  store = createGrantStore({
    home: tempHome,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  audit = createAuditLog({ home: tempHome, nowEpochMs: () => NOW * 1000 });
});

afterEach(() => {
  try {
    audit.close();
  } catch {
    // best-effort — release the audit writer lock
  }
  rmSync(tempHome, { recursive: true, force: true });
});

function readAuditEvents(): AuditEvent[] {
  audit.flush();
  const auditDir = path.join(tempHome, "audit");
  const files = readdirSync(auditDir)
    .filter((name) => /^\d{6}\.jsonl$/.test(name))
    .sort();
  const events: AuditEvent[] = [];
  for (const file of files) {
    const raw = readFileSync(path.join(auditDir, file), "utf8");
    for (const line of raw.split("\n")) {
      if (line.length > 0) events.push(JSON.parse(line) as AuditEvent);
    }
  }
  return events;
}

function decisionEvents(): AuditEvent[] {
  return readAuditEvents().filter((e) => e.type === "decision");
}

// The one combined policy every scenario decides under.
const POLICY: TierPolicy = {
  tools: {
    "echo.ping": { tier: "routine", source: "pack" },
    "github.create_issue": { tier: "sensitive", source: "pack" },
    "stripe.create_refund": { tier: "sensitive", source: "pack" },
  },
  unknownToolTier: "sensitive",
};

function routineRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01DECIDERROUTINE0000000001",
    timestamp: "2027-01-15T08:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "echo.ping" },
    resource: { type: "tool", id: "echo.ping" },
    context: {
      agent: { id: "claude-desktop", type: "ai_agent" },
      env: { time: "2027-01-15T08:00:00Z", surfaceLocal: true },
      arguments: { msg: "hi" },
    },
    surface: { kind: "stdio_proxy", instanceId: "px1", server: "echo" },
  };
}

function sensitiveRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01DECIDERSENSITIVE00000001",
    timestamp: "2027-01-15T08:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "github.create_issue" },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: "claude-desktop", type: "ai_agent" },
      env: { time: "2027-01-15T08:00:00Z", surfaceLocal: true },
      arguments: { repo: "kno2gether/openclaw", title: "hi" },
    },
    surface: { kind: "stdio_proxy", instanceId: "px1", server: "github" },
  };
}

/** A sensitive refund call satisfied only by a single-use ephemeral grant. */
function singleUseRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01DECIDERSINGLEUSE00000001",
    timestamp: "2027-01-15T08:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2027-01-15T08:00:00Z", surfaceLocal: true },
      arguments: { amount: 4200, reason: "requested_by_customer" },
    },
    surface: { kind: "stdio_proxy", instanceId: "px2", server: "stripe" },
  };
}

const DURABLE_GITHUB_INPUT = {
  principal: { type: "user", id: "avijeett007@gmail.com" },
  agent: "*",
  tool: "github.*",
  scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
  tier: "sensitive",
  envelopeScope: "personal",
  ttlSeconds: 2_592_000,
} as const;

function newDecider(over: { envelope?: AdminEnvelope } = {}) {
  return createDecider({
    cache: cacheRef,
    tierPolicy: POLICY,
    ...(over.envelope !== undefined ? { envelope: over.envelope } : {}),
    policyVersion: "policy-v1",
    store,
    audit,
    resolvePublicKey,
    nowEpochSeconds: () => NOW,
    nowMs: () => NOW * 1000,
    generateId: makeIdGen(),
  });
}

let cacheRef: ReturnType<typeof createDecisionCache>;
beforeEach(() => {
  cacheRef = createDecisionCache({ nowEpochSeconds: () => NOW });
});

// ---------------------------------------------------------------------------
// P0-E5-T3 fix round 1, Minor 1 — shared `computeEffectivePolicyVersion`
// parity. Before this fix, this decider carried its OWN byte-for-byte copy
// of the R20 `sha256(canonicalStringify(...))` + `${policyVersion}:
// ${fingerprint}` formula, duplicated from `@knotrust/core`'s
// `createDecisionPipeline`. Both now call the ONE exported
// `computeEffectivePolicyVersion` (see `pipeline.ts`'s own parity test for
// the formula-level lock); this test proves the decider's REAL cache key —
// observed on the wire via a spy on the real `createDecisionCache` instance,
// not a re-derivation — is byte-identical to calling that shared function
// directly with this decider's own `tierPolicy`/`envelope`/`policyVersion`.
// ---------------------------------------------------------------------------

describe("computeEffectivePolicyVersion parity (P0-E5-T3 fix round 1, Minor 1)", () => {
  it("the decider's real cache.get key equals computeEffectivePolicyVersion(tierPolicy, envelope, policyVersion) computed independently", async () => {
    const getSpy = vi.spyOn(cacheRef, "get");
    const decider = newDecider();

    await decider.decide(routineRequest());

    expect(getSpy).toHaveBeenCalledTimes(1);
    const [, , effectivePolicyVersionArg] = getSpy.mock.calls[0] ?? [];
    expect(effectivePolicyVersionArg).toBe(
      computeEffectivePolicyVersion(POLICY, undefined, "policy-v1"),
    );
  });

  it("an envelope changes the decider's cache key exactly as computeEffectivePolicyVersion predicts", async () => {
    const envelope: AdminEnvelope = { scope: "personal", denyTools: [] };
    const getSpy = vi.spyOn(cacheRef, "get");
    const decider = newDecider({ envelope });

    await decider.decide(routineRequest());

    const [, , effectivePolicyVersionArg] = getSpy.mock.calls[0] ?? [];
    expect(effectivePolicyVersionArg).toBe(
      computeEffectivePolicyVersion(POLICY, envelope, "policy-v1"),
    );
    // And it must differ from the no-envelope key (proves the fingerprint is
    // actually load-bearing here, not coincidentally equal).
    expect(effectivePolicyVersionArg).not.toBe(
      computeEffectivePolicyVersion(POLICY, undefined, "policy-v1"),
    );
  });
});

// ---------------------------------------------------------------------------
// R68 (E5-I1) — the spanning integration
// ---------------------------------------------------------------------------

describe("R68 (E5-I1) — unified decider spanning integration (real cache+store+audit)", () => {
  it("routine: miss→allow (cached), hit→allow (cache) with ZERO grant-store reads, each decide audits exactly one decision event", async () => {
    const decider = newDecider();
    const listSpy = vi.spyOn(store, "list");
    const request = routineRequest();

    const miss = await decider.decide(request);
    expect(miss.outcome).toBe("allow");
    expect(miss.reasonCode).toBe("routine_default_allow");
    expect(miss.cache.hit).toBe(false);
    // A miss runs the full path, which collects covering grants (one store read).
    const readsAfterMiss = listSpy.mock.calls.length;
    expect(readsAfterMiss).toBeGreaterThanOrEqual(1);

    const hit = await decider.decide(request);
    expect(hit.outcome).toBe("allow");
    expect(hit.cache.hit).toBe(true);
    // The hit served from cache: ZERO additional grant-store reads.
    expect(listSpy.mock.calls.length).toBe(readsAfterMiss);

    // Each decide (miss AND hit) appended exactly one decision event.
    const events = decisionEvents();
    expect(events).toHaveLength(2);
    expect(events.every((e) => e.outcome === "allow")).toBe(true);
    // The hit's decision event is marked cacheHit:true (E5 pinned obligation).
    expect(events[0]?.cacheHit).toBeUndefined();
    expect(events[1]?.cacheHit).toBe(true);
    // Both carry a latencyMs (bracketed by the injected clock).
    expect(typeof events[0]?.latencyMs).toBe("number");
    // R126: both the miss AND the cache-hit decision event carry the
    // resolved tier — `echo.ping` is configured `routine` in POLICY.
    expect(events[0]?.tier).toBe("routine");
    expect(events[1]?.tier).toBe("routine");
    expect(audit.verify().ok).toBe(true);
  });

  it('R126: a sensitive-tier decision event carries tier:"sensitive" (so `knotrust audit query --tier` matches ordinary decisions, not just fail_open_fired)', async () => {
    const decider = newDecider();
    await decider.decide(sensitiveRequest());

    const events = decisionEvents();
    expect(events).toHaveLength(1);
    expect(events[0]?.tier).toBe("sensitive");
    expect(events[0]?.outcome).toBe("deny");
  });

  it("a covering durable grant yields a cached grant_allow (fast path)", async () => {
    await mintDurableGrant(DURABLE_GITHUB_INPUT, {
      store,
      keyStore,
      nowEpochSeconds: NOW,
      generateId: makeIdGen("DURGRANT"),
      audit,
    });
    const decider = newDecider();
    const request = sensitiveRequest();

    const first = await decider.decide(request);
    expect(first.outcome).toBe("allow");
    expect(first.reasonCode).toBe("grant_allow");
    expect(first.evaluatedBy).toBe("grant");
    expect(first.cache.hit).toBe(false);

    // A durable (non-single-use) grant allow IS cacheable — second decide hits.
    const listSpy = vi.spyOn(store, "list");
    const second = await decider.decide(request);
    expect(second.outcome).toBe("allow");
    expect(second.cache.hit).toBe(true);
    expect(listSpy.mock.calls.length).toBe(0);
  });

  it("a single-use grant is consumed EXACTLY once: second identical call misses cache AND is denied grant_replayed (never served the cached allow)", async () => {
    const request = singleUseRequest();
    const { jti } = await mintEphemeralGrant(
      { request, tier: "sensitive" },
      { store, keyStore, nowEpochSeconds: NOW, generateId: makeIdGen("EPH") },
    );
    const decider = newDecider();

    const first = await decider.decide(request);
    expect(first.outcome).toBe("allow");
    expect(first.reasonCode).toBe("grant_allow");
    expect(first.cache.hit).toBe(false);
    expect(store.isConsumed(jti)).toBe(true);

    // Second identical call: NOT served from cache (single-use allow excluded),
    // a fresh miss that re-decides and denies grant_replayed.
    const second = await decider.decide(request);
    expect(second.cache.hit).toBe(false);
    expect(second.outcome).toBe("deny");
    expect(second.reasonCode).toBe("grant_replayed");

    // Exactly two decision events (both misses), plus one grant_consumed.
    const all = readAuditEvents();
    expect(all.filter((e) => e.type === "decision")).toHaveLength(2);
    expect(all.filter((e) => e.type === "grant_consumed")).toHaveLength(1);
    expect(audit.verify().ok).toBe(true);
  });

  it("revoke + bump → next decide misses and denies (no stale allow survives)", async () => {
    const { jti } = await mintDurableGrant(DURABLE_GITHUB_INPUT, {
      store,
      keyStore,
      nowEpochSeconds: NOW,
      generateId: makeIdGen("DUR2"),
      audit,
    });
    const decider = newDecider();
    const request = sensitiveRequest();

    const allowed = await decider.decide(request);
    expect(allowed.outcome).toBe("allow");
    const hit = await decider.decide(request);
    expect(hit.cache.hit).toBe(true);

    // Revoke, wiring onInvalidate to the cache bump (the composed configEpoch).
    revokeGrants(
      { jti },
      { store, audit, onInvalidate: () => cacheRef.bumpGrantSetVersion() },
    );

    const fresh = await decider.decide(request);
    expect(fresh.cache.hit).toBe(false);
    expect(fresh.outcome).toBe("deny");
    expect(fresh.reasonCode).toBe("no_grant_sensitive");
  });
});

// ---------------------------------------------------------------------------
// R69 (E5-I2) — cacheability exclusions
// ---------------------------------------------------------------------------

describe("R69 (E5-I2) — isCacheableDecision excludes consume-dependent + transient outcomes", () => {
  const base = (over: Partial<GrantedDecision>): GrantedDecision => ({
    outcome: "allow",
    tier: "sensitive",
    reasonCode: "grant_allow",
    precedenceLayer: 3,
    ...over,
  });

  it("caches a pure allow/deny (routine/sensitive, non-single-use)", () => {
    expect(
      isCacheableDecision(
        base({
          outcome: "allow",
          tier: "routine",
          reasonCode: "routine_default_allow",
        }),
        false,
      ),
    ).toBe(true);
    expect(
      isCacheableDecision(
        base({ outcome: "deny", reasonCode: "no_grant_sensitive" }),
        false,
      ),
    ).toBe(true);
    expect(
      isCacheableDecision(base({ reasonCode: "grant_allow" }), false),
    ).toBe(true);
  });

  it("excludes critical tier", () => {
    expect(isCacheableDecision(base({ tier: "critical" }), false)).toBe(false);
  });

  it("excludes pending_approval / non-allow-deny outcomes", () => {
    expect(
      isCacheableDecision(
        base({ outcome: "pending_approval", reasonCode: "no_grant_critical" }),
        false,
      ),
    ).toBe(false);
  });

  it("excludes a single-use grant_allow (would cache and replay forever)", () => {
    expect(isCacheableDecision(base({ reasonCode: "grant_allow" }), true)).toBe(
      false,
    );
  });

  it("excludes grant_replayed and audit_unavailable", () => {
    expect(
      isCacheableDecision(
        base({ outcome: "deny", reasonCode: "grant_replayed" }),
        false,
      ),
    ).toBe(false);
    expect(
      isCacheableDecision(
        base({ outcome: "deny", reasonCode: "audit_unavailable" }),
        false,
      ),
    ).toBe(false);
  });

  it("PROOF: a single-use sensitive grant_allow is NOT cached — decide twice, second is a fresh miss that denies grant_replayed, never a cache hit", async () => {
    const request = singleUseRequest();
    await mintEphemeralGrant(
      { request, tier: "sensitive" },
      { store, keyStore, nowEpochSeconds: NOW, generateId: makeIdGen("EPH2") },
    );
    const decider = newDecider();

    const first = await decider.decide(request);
    expect(first.outcome).toBe("allow");
    expect(first.cache.hit).toBe(false);

    // If the single-use allow had been cached, this would be a hit→allow —
    // a replay. It must be a fresh miss that denies instead.
    const second = await decider.decide(request);
    expect(second.cache.hit).toBe(false);
    expect(second.outcome).toBe("deny");
    expect(second.reasonCode).toBe("grant_replayed");
  });
});
