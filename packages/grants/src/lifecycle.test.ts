/**
 * @knotrust/grants — durable + ephemeral grant lifecycle acceptance suite
 * (P0-E3-T3, ruling R34).
 *
 * Locks the four plan-acceptance behaviors of call-hash-bound, single-use
 * ephemeral grants over the real E4-T1 file store:
 *   1. replay: one ephemeral grant authorizes exactly one decision; the
 *      second attempt with the same jti → deny `grant_replayed`
 *      (P0-E11-T3's hook).
 *   2. call-hash mismatch: a grant minted for call X denies a call Y that
 *      differs in ANY hashed field (tool, one argument byte, resource.id,
 *      agent.id) with `grant_call_mismatch`; an identical Y′ allows
 *      (P0-E11-T6's hook).
 *   3. durable grants survive process restart (a fresh store over the same
 *      home).
 *   4. expiry honored under a fake clock.
 *
 * Every test gets a fresh temp `home` and injects the clock/ids/public-key
 * resolver — no `Date.now()`, no real keychain, no `~/.knotrust`.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { DecisionRequest, TierPolicy } from "@knotrust/core";
import { createGrantStore, type GrantStore } from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { computeCallHash } from "./callhash.js";
import { makeTestKeyStore, resolverFor } from "./grant-test-kit.js";
import {
  collectCoveringGrants,
  decideWithGrants,
  decodeGrantIndexEntry,
  mintDurableGrant,
  mintEphemeralGrant,
} from "./lifecycle.js";
import { mintGrant } from "./mint.js";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000;
const keyStore = makeTestKeyStore();
const resolvePublicKey = resolverFor(
  keyStore.identity.kid,
  keyStore.publicKeyJwk,
);

/** Deterministic, store-safe (`/^[A-Za-z0-9_-]+$/`) unique jti generator. */
function makeIdGen(): () => string {
  let n = 0;
  return () => `TESTGRANT${String(n++).padStart(4, "0")}`;
}

let tempHome: string;
let store: GrantStore;

beforeEach(() => {
  tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-lifecycle-test-"));
  store = createGrantStore({
    home: tempHome,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
});

afterEach(() => {
  rmSync(tempHome, { recursive: true, force: true });
});

/** A critical-tier stripe refund call (the approval-orchestrator ephemeral path). */
function criticalRequest(over: Partial<DecisionRequest> = {}): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01REPLAYX0000000000000001",
    timestamp: "2026-07-03T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-03T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 42000, reason: "requested_by_customer" },
    },
    surface: { kind: "stdio_proxy", instanceId: "px1", server: "stripe" },
    ...over,
  };
}

/** A sensitive-tier github call, covered by a durable github.* grant. */
function sensitiveRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01DURABLE00000000000000001",
    timestamp: "2026-07-03T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "github.create_issue" },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: "claude-desktop", type: "ai_agent" },
      env: { time: "2026-07-03T12:00:00Z", surfaceLocal: true },
    },
    surface: { kind: "stdio_proxy", instanceId: "px2", server: "github" },
  };
}

const CRITICAL_POLICY: TierPolicy = {
  tools: { "stripe.create_refund": { tier: "critical", source: "pack" } },
  unknownToolTier: "critical",
};

const SENSITIVE_POLICY: TierPolicy = {
  tools: { "github.create_issue": { tier: "sensitive", source: "pack" } },
  unknownToolTier: "sensitive",
};

// ---------------------------------------------------------------------------
// 1. Replay — grant_replayed (P0-E11-T3 hook)
// ---------------------------------------------------------------------------

describe("ephemeral single-use grant — replay (P0-E11-T3 hook)", () => {
  it("authorizes exactly one decision; the second attempt with the same jti → deny grant_replayed", async () => {
    const request = criticalRequest();
    await mintEphemeralGrant(
      { request, tier: "critical" },
      { store, keyStore, nowEpochSeconds: NOW, generateId: makeIdGen() },
    );

    const ctx = {
      tierPolicy: CRITICAL_POLICY,
      nowEpochSeconds: NOW,
      resolvePublicKey,
    };

    // First evaluation: allowed by the ephemeral grant, consumed atomically.
    const first = decideWithGrants(request, ctx, { store });
    expect(first.decision.outcome).toBe("allow");
    expect(first.decision.reasonCode).toBe("grant_allow");
    expect(first.consumedJti).toBeDefined();

    // Second evaluation with the SAME call/jti: the consumed-ledger gate wins,
    // the re-run (grant excluded) cannot re-allow → deny grant_replayed.
    const second = decideWithGrants(request, ctx, { store });
    expect(second.decision.outcome).toBe("deny");
    expect(second.decision.reasonCode).toBe("grant_replayed");
    expect(second.consumedJti).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 2. Call-hash mismatch matrix — grant_call_mismatch (P0-E11-T6 hook)
// ---------------------------------------------------------------------------

describe("ephemeral grant call-hash binding — mismatch matrix (P0-E11-T6 hook)", () => {
  // The grant is minted DELIBERATELY BROAD (agent "*", tool "stripe.*", empty
  // scope) so that the coarse pattern matchers (agent/tool/scope) all still
  // MATCH each Y variant — isolating the call-hash gate as the SOLE
  // discriminator. This proves the call-hash closes approve-X-execute-Y even
  // when the grant's own patterns are permissive: every hashed-field change
  // (tool name, one argument byte, resource.id, agent.id) is caught as
  // grant_call_mismatch, not as a tool/scope/agent mismatch.
  const approvedX = criticalRequest();

  async function seedBroadGrant(): Promise<void> {
    const minted = await mintGrant(
      {
        kind: "ephemeral",
        principal: {
          type: approvedX.subject.type,
          id: approvedX.subject.id,
        },
        agent: "*",
        tool: "stripe.*",
        scope: {},
        tier: "critical",
        envelopeScope: "personal",
        ttlSeconds: 120,
        callHash: computeCallHash(approvedX),
      },
      { keyStore, nowEpochSeconds: NOW, generateId: makeIdGen() },
    );
    const put = store.put(minted.token);
    expect(put.ok).toBe(true);
  }

  function collect(request: DecisionRequest) {
    return collectCoveringGrants(request, {
      store,
      resolvedTier: "critical" as const,
      nowEpochSeconds: NOW,
      resolvePublicKey,
    });
  }

  const mismatchCases: Array<[string, () => DecisionRequest]> = [
    [
      "differs in tool name",
      () => criticalRequest({ action: { name: "stripe.create_charge" } }),
    ],
    [
      "differs in ONE argument byte",
      () =>
        criticalRequest({
          context: {
            agent: { id: "codex-cli", type: "ai_agent" },
            env: { time: "2026-07-03T12:00:00Z", surfaceLocal: true },
            arguments: { amount: 42001, reason: "requested_by_customer" },
          },
        }),
    ],
    [
      "differs in resource.id",
      () =>
        criticalRequest({
          resource: { type: "stripe_charge", id: "ch_DIFFERENT" },
        }),
    ],
    [
      "differs in agent.id",
      () =>
        criticalRequest({
          context: {
            agent: { id: "other-agent", type: "ai_agent" },
            env: { time: "2026-07-03T12:00:00Z", surfaceLocal: true },
            arguments: { amount: 42000, reason: "requested_by_customer" },
          },
        }),
    ],
  ];

  it.each(
    mismatchCases,
  )("denies a call Y that %s → grant_call_mismatch (no covering grant)", async (_label, buildY) => {
    await seedBroadGrant();
    const result = collect(buildY());
    expect(result.coveringGrants).toHaveLength(0);
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0]?.reason).toBe("grant_call_mismatch");
  });

  it("allows an identical call Y′ === X (call-hash matches → covering)", async () => {
    await seedBroadGrant();
    const result = collect(criticalRequest());
    expect(result.coveringGrants).toHaveLength(1);
    expect(result.rejected).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 3. Durable grant survives process restart
// ---------------------------------------------------------------------------

describe("durable grant — survives process restart", () => {
  it("a fresh store instance over the same home still authorizes the call", async () => {
    const request = sensitiveRequest();
    await mintDurableGrant(
      {
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      { store, keyStore, nowEpochSeconds: NOW, generateId: makeIdGen() },
    );

    // Simulate a process restart: brand-new store object, same on-disk home.
    const restarted = createGrantStore({
      home: tempHome,
      decodeIndexEntry: decodeGrantIndexEntry,
    });

    const result = decideWithGrants(
      request,
      {
        tierPolicy: SENSITIVE_POLICY,
        nowEpochSeconds: NOW,
        resolvePublicKey,
      },
      { store: restarted },
    );

    expect(result.decision.outcome).toBe("allow");
    expect(result.decision.reasonCode).toBe("grant_allow");
    // Durable grants are multi-use — never consumed.
    expect(result.consumedJti).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 4. Expiry honored under a fake clock
// ---------------------------------------------------------------------------

describe("grant expiry — honored under a fake clock", () => {
  it("allows before exp and denies once the fake clock reaches exp (exclusive)", async () => {
    const request = sensitiveRequest();
    const ttl = 3600;
    await mintDurableGrant(
      {
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: ttl,
      },
      { store, keyStore, nowEpochSeconds: NOW, generateId: makeIdGen() },
    );

    const before = decideWithGrants(
      request,
      { tierPolicy: SENSITIVE_POLICY, nowEpochSeconds: NOW, resolvePublicKey },
      { store },
    );
    expect(before.decision.outcome).toBe("allow");
    expect(before.decision.reasonCode).toBe("grant_allow");

    // exp === NOW + ttl; expiry is exclusive, so at exactly exp the grant is
    // absent and the sensitive-tier default (no covering grant) denies.
    const after = decideWithGrants(
      request,
      {
        tierPolicy: SENSITIVE_POLICY,
        nowEpochSeconds: NOW + ttl,
        resolvePublicKey,
      },
      { store },
    );
    expect(after.decision.outcome).toBe("deny");
    expect(after.decision.reasonCode).toBe("no_grant_sensitive");
    expect(after.consumedJti).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 5. R35 — precedence is the single tier-cap authority in composition.
//
// Before R35, collectCoveringGrants ran verifyGrant with the resolved tier and
// treated a `tier_cap_violation` rejection as ABSENT, so precedence's ratified
// loud tier_cap_violation deny (R15, fixture-locked) was dead code in the wired
// path: the tier-cap-violation-over-explicit-allow scenario flipped from deny
// (ratified) to allow (wired). R35 passes such a rejection THROUGH as a
// CoveringGrant so precedence fires the loud deny, and reorders verify so the
// call-hash gate runs before the tier-cap gate (a passed-through grant is thus
// always bound to THIS exact call).
// ---------------------------------------------------------------------------

describe("R35 — precedence is the single tier-cap authority (wired composition)", () => {
  const SENSITIVE_EXPLICIT_ALLOW_POLICY: TierPolicy = {
    tools: {
      "github.create_issue": {
        tier: "sensitive",
        source: "user",
        explicitAllow: true,
      },
    },
    unknownToolTier: "sensitive",
  };

  it("(a) wired mirror of tier-cap-violation-over-explicit-allow → deny/tier_cap_violation at layer 3, even though the config alone would allow", async () => {
    // A durable grant whose own tierCap is "routine" — below the resolved
    // sensitive tier — is a live self-escalation attempt. It matches the call
    // in every pattern (agent "*", tool github.*, scope), so it reaches and
    // fails ONLY the tier-cap gate → passed through to precedence. The config
    // alone (source: "user", explicitAllow) would allow at layer 4, but the
    // loud tier_cap_violation at layer 3 wins outright (R15).
    const request = sensitiveRequest();
    await mintDurableGrant(
      {
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "routine",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      { store, keyStore, nowEpochSeconds: NOW, generateId: makeIdGen() },
    );

    const result = decideWithGrants(
      request,
      {
        tierPolicy: SENSITIVE_EXPLICIT_ALLOW_POLICY,
        nowEpochSeconds: NOW,
        resolvePublicKey,
      },
      { store },
    );

    expect(result.decision.outcome).toBe("deny");
    expect(result.decision.reasonCode).toBe("tier_cap_violation");
    expect(result.decision.precedenceLayer).toBe(3);
    expect(result.consumedJti).toBeUndefined();
    // The self-escalating grant is passed THROUGH, not folded into rejected.
    expect(result.rejected).toHaveLength(0);
  });

  it("(b) a sub-cap grant alone at a critical tool → deny/tier_cap_violation, NOT pending_approval", async () => {
    // Durable grant tierCap "sensitive" for a critical tool: pre-R35 this was
    // rejected+absent, so the decision fell to the critical tier default
    // (pending_approval). R35 passes it through → the loud deny fires.
    const request = criticalRequest();
    await mintDurableGrant(
      {
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "stripe.*",
        scope: { resourceType: "stripe_charge", idPattern: "ch_*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      { store, keyStore, nowEpochSeconds: NOW, generateId: makeIdGen() },
    );

    const result = decideWithGrants(
      request,
      { tierPolicy: CRITICAL_POLICY, nowEpochSeconds: NOW, resolvePublicKey },
      { store },
    );

    expect(result.decision.outcome).toBe("deny");
    expect(result.decision.reasonCode).toBe("tier_cap_violation");
    expect(result.decision.precedenceLayer).toBe(3);
    expect(result.decision.outcome).not.toBe("pending_approval");
    expect(result.consumedJti).toBeUndefined();
  });

  it("(c) an ephemeral sub-cap grant whose call-hash MISMATCHES is treated absent (grant_call_mismatch), NOT tier_cap_violation — decision falls to the tier default", async () => {
    // The grant is minted for approved call X (tier "sensitive") but the LIVE
    // call Y differs in one hashed field. R35's check order (call-hash before
    // tier-cap) makes the mismatch — not the sub-cap — the reported reason, so
    // the grant is absent and the critical tier default (no covering grant)
    // resolves pending_approval. Proves the pass-through never leaks a grant
    // that does not bind to THIS exact call.
    const approvedX = criticalRequest();
    const minted = await mintGrant(
      {
        kind: "ephemeral",
        principal: { type: approvedX.subject.type, id: approvedX.subject.id },
        agent: "*",
        tool: "stripe.*",
        scope: {},
        tier: "sensitive", // sub-cap for the critical tool
        envelopeScope: "personal",
        ttlSeconds: 120,
        callHash: computeCallHash(approvedX),
      },
      { keyStore, nowEpochSeconds: NOW, generateId: makeIdGen() },
    );
    expect(store.put(minted.token).ok).toBe(true);

    // Call Y differs from X in one argument byte → call-hash mismatch.
    const callY = criticalRequest({
      context: {
        agent: { id: "codex-cli", type: "ai_agent" },
        env: { time: "2026-07-03T12:00:00Z", surfaceLocal: true },
        arguments: { amount: 42001, reason: "requested_by_customer" },
      },
    });

    const result = decideWithGrants(
      callY,
      { tierPolicy: CRITICAL_POLICY, nowEpochSeconds: NOW, resolvePublicKey },
      { store },
    );

    expect(result.decision.reasonCode).not.toBe("tier_cap_violation");
    expect(result.decision.outcome).toBe("pending_approval");
    expect(result.decision.reasonCode).toBe("no_grant_critical");
    expect(result.rejected).toHaveLength(1);
    expect(result.rejected[0]?.reason).toBe("grant_call_mismatch");
  });

  it("(R35 minor) a non-canonicalizable request does not throw; call-hash unavailable → ephemeral fails closed (grant_call_mismatch), durable unaffected", async () => {
    const approvedX = criticalRequest();
    // ONE shared id generator across BOTH mints so the two grants get distinct
    // jtis (a fresh generator per mint would collide on "TESTGRANT0000" and the
    // second would overwrite the first in the store).
    const idGen = makeIdGen();
    // A broad ephemeral grant (ch present) AND a broad durable grant (no ch),
    // both covering the critical call by pattern + tier.
    const ephem = await mintGrant(
      {
        kind: "ephemeral",
        principal: { type: approvedX.subject.type, id: approvedX.subject.id },
        agent: "*",
        tool: "stripe.*",
        scope: {},
        tier: "critical",
        envelopeScope: "personal",
        ttlSeconds: 120,
        callHash: computeCallHash(approvedX),
      },
      { keyStore, nowEpochSeconds: NOW, generateId: idGen },
    );
    expect(store.put(ephem.token).ok).toBe(true);

    await mintDurableGrant(
      {
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "stripe.*",
        scope: {},
        tier: "critical",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      { store, keyStore, nowEpochSeconds: NOW, generateId: idGen },
    );

    // Poison the request: a bigint in arguments makes canonicalizeJcs throw.
    // collectCoveringGrants must catch it once and treat call-hash unavailable.
    const poisoned = criticalRequest({
      context: {
        agent: { id: "codex-cli", type: "ai_agent" },
        env: { time: "2026-07-03T12:00:00Z", surfaceLocal: true },
        arguments: { amount: 42_000n },
      },
    });

    let result: ReturnType<typeof collectCoveringGrants> | undefined;
    expect(() => {
      result = collectCoveringGrants(poisoned, {
        store,
        resolvedTier: "critical",
        nowEpochSeconds: NOW,
        resolvePublicKey,
      });
    }).not.toThrow();

    // Durable grant (no ch) is unaffected → covering. Ephemeral (ch present)
    // fails closed because the call-hash is unavailable → grant_call_mismatch.
    expect(result?.coveringGrants).toHaveLength(1);
    expect(result?.rejected.map((r) => r.reason)).toContain(
      "grant_call_mismatch",
    );
  });
});
