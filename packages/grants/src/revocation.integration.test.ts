/**
 * @knotrust/grants — revocation + audit-wiring integration suite
 * (P0-E3-T4, rulings R40/R41).
 *
 * Composes the REAL pieces in one temp home — E4-T1 grant store
 * (`<home>/grants`), E4-T3 hash-chained audit log (`<home>/audit`), E2-T3/
 * E3-T3 decision path (`decideWithGrants`), and for the cache angle the
 * E2-T4 decision cache under the E2-T5 pipeline — and locks the plan
 * acceptance:
 *
 *   grant → allow → revoke → same call now denied, with ZERO process
 *   restarts; audit shows grant_created → decision(allow) → grant_revoked →
 *   decision(deny) in hash-chain order.
 *
 * Plus the R40 wiring this task ships: `grant_created` on mint,
 * `grant_consumed` on the consume path, one `decision` event per audited
 * decision (critical tier ⇒ `{ fsync: "immediate" }`, R38), and the
 * fail-closed deny/`audit_unavailable` conversion — the exact composition
 * P0-E5-T5 makes mandatory at the proxy.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { DecisionRequest, PdpAdapter, TierPolicy } from "@knotrust/core";
import { createDecisionCache, createDecisionPipeline } from "@knotrust/core";
import {
  AUDIT_UNAVAILABLE,
  type AuditEvent,
  type AuditSink,
  AuditUnavailableError,
  createAuditLog,
  createGrantStore,
  type GrantStore,
} from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeTestKeyStore, resolverFor } from "./grant-test-kit.js";
import {
  decideWithGrants,
  decodeGrantIndexEntry,
  mintDurableGrant,
  mintEphemeralGrant,
} from "./lifecycle.js";
import { revokeGrants } from "./revoke.js";

// ---------------------------------------------------------------------------
// Shared fixtures (mirrors lifecycle.test.ts)
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000;
const keyStore = makeTestKeyStore();
const resolvePublicKey = resolverFor(
  keyStore.identity.kid,
  keyStore.publicKeyJwk,
);

function makeIdGen(prefix = "TESTCHAIN"): () => string {
  let n = 0;
  return () => `${prefix}${String(n++).padStart(4, "0")}`;
}

let tempHome: string;
let store: GrantStore;
let sink: AuditSink | undefined;

beforeEach(() => {
  tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-revocation-int-"));
  store = createGrantStore({
    home: tempHome,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  sink = undefined;
});

afterEach(() => {
  try {
    sink?.close();
  } catch {
    // best-effort — release the audit writer lock
  }
  rmSync(tempHome, { recursive: true, force: true });
});

function makeAudit(): AuditSink {
  sink = createAuditLog({ home: tempHome, nowEpochMs: () => NOW * 1000 });
  return sink;
}

function readAuditEvents(): AuditEvent[] {
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

/** A sensitive-tier github call, covered by a durable github.* grant. */
function sensitiveRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01REVOKECHAIN000000000001",
    timestamp: "2027-01-15T08:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "github.create_issue" },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: "claude-desktop", type: "ai_agent" },
      env: { time: "2027-01-15T08:00:00Z", surfaceLocal: true },
      arguments: { repo: "kno2gether/openclaw", title: "test issue" },
    },
    surface: { kind: "stdio_proxy", instanceId: "px1", server: "github" },
  };
}

/** A critical-tier stripe refund call (the approval-orchestrator ephemeral path). */
function criticalRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01REVOKECHAIN000000000002",
    timestamp: "2027-01-15T08:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2027-01-15T08:00:00Z", surfaceLocal: true },
      arguments: { amount: 42000, reason: "requested_by_customer" },
    },
    surface: { kind: "stdio_proxy", instanceId: "px2", server: "stripe" },
  };
}

const SENSITIVE_POLICY: TierPolicy = {
  tools: { "github.create_issue": { tier: "sensitive", source: "pack" } },
  unknownToolTier: "sensitive",
};

const CRITICAL_POLICY: TierPolicy = {
  tools: { "stripe.create_refund": { tier: "critical", source: "pack" } },
  unknownToolTier: "critical",
};

const DURABLE_GITHUB_INPUT = {
  principal: { type: "user", id: "avijeett007@gmail.com" },
  agent: "*",
  tool: "github.*",
  scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
  tier: "sensitive",
  envelopeScope: "personal",
  ttlSeconds: 2_592_000,
} as const;

// ---------------------------------------------------------------------------
// R41 — the acceptance four-event chain
// ---------------------------------------------------------------------------

describe("R41 — grant → allow → revoke → deny, four-event hash chain, zero restarts", () => {
  it("audits grant_created → decision(allow) → grant_revoked → decision(deny) in exact seq order over the same live objects", async () => {
    const audit = makeAudit();
    const request = sensitiveRequest();
    const ctx = {
      tierPolicy: SENSITIVE_POLICY,
      nowEpochSeconds: NOW,
      resolvePublicKey,
    };

    // ZERO process restarts: `store` and `audit` are constructed ONCE above
    // and the SAME object references flow through mint → decide → revoke →
    // re-decide (asserted at the end against these captured identities —
    // no `createGrantStore`/`createAuditLog` call happens again below).
    const storeRef = store;
    const auditRef = audit;

    // 1. Mint (audited).
    const { jti } = await mintDurableGrant(DURABLE_GITHUB_INPUT, {
      store,
      keyStore,
      nowEpochSeconds: NOW,
      generateId: makeIdGen(),
      audit,
    });

    // 2. Decide → allow (audited).
    const first = decideWithGrants(request, ctx, { store, audit });
    expect(first.decision.outcome).toBe("allow");
    expect(first.decision.reasonCode).toBe("grant_allow");
    expect(first.decision.grantRef).toBe(jti);

    // 3. Revoke (audited; onInvalidate spy fired exactly once).
    const onInvalidate = vi.fn();
    const revoked = revokeGrants({ jti }, { store, audit, onInvalidate });
    expect(revoked).toEqual({ revoked: [jti], notFound: false });
    expect(onInvalidate).toHaveBeenCalledTimes(1);

    // 4. Same request, re-decided over the SAME objects → the tier default
    //    deny (no covering grant at sensitive), NOT a model-visible
    //    "revoked" reason (architecture §5.4: revoked = absent).
    const second = decideWithGrants(request, ctx, { store, audit });
    expect(second.decision.outcome).toBe("deny");
    expect(second.decision.reasonCode).toBe("no_grant_sensitive");

    // Zero restarts, asserted: identical live objects end-to-end.
    expect(store).toBe(storeRef);
    expect(audit).toBe(auditRef);

    // The chain: exactly four events, verify() green, exact seq order.
    expect(audit.verify()).toEqual({ ok: true, events: 4 });
    audit.flush();
    const events = readAuditEvents();
    expect(events.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    expect(events.map((e) => e.type)).toEqual([
      "grant_created",
      "decision",
      "grant_revoked",
      "decision",
    ]);
    expect(events[1]?.outcome).toBe("allow");
    expect(events[1]?.reason).toBe("grant_allow");
    expect(events[1]?.grantRefs).toEqual([jti]);
    expect(events[2]?.grantRefs).toEqual([jti]);
    expect(events[3]?.outcome).toBe("deny");
    expect(events[3]?.reason).toBe("no_grant_sensitive");
  });
});

// ---------------------------------------------------------------------------
// R41 — the cache angle: revoke makes the previously-cached allow unreachable
// ---------------------------------------------------------------------------

describe("R41 — pipeline + cache composed: revoke + bump makes the cached allow unreachable", () => {
  it("decide → cached allow; revoke + bumpGrantSetVersion (via onInvalidate); decide → fresh deny", async () => {
    const audit = makeAudit();
    const request = sensitiveRequest();
    const cache = createDecisionCache({ nowEpochSeconds: () => NOW });

    // The composed adapter: decides against the REAL store via
    // decideWithGrants (the pipeline's coveringGrants input is unused — the
    // grants layer collects its own candidates from the store).
    const adapter: PdpAdapter = {
      capabilities: { name: "grants-composed", latencyClass: "in_process" },
      async decide(req, pdpCtx) {
        const result = decideWithGrants(
          req,
          {
            tierPolicy: pdpCtx.tierPolicy,
            nowEpochSeconds: pdpCtx.nowEpochSeconds,
            resolvePublicKey,
          },
          { store, audit },
        );
        return {
          outcome: result.decision.outcome,
          tier: result.decision.tier,
          reasonCode: result.decision.reasonCode,
          evaluatedBy: "grant",
          ...(result.decision.grantRef !== undefined
            ? { grantRef: result.decision.grantRef }
            : {}),
        };
      },
    };

    let idCounter = 0;
    const pipeline = createDecisionPipeline({
      adapter,
      cache,
      policyVersion: "policy-v1",
      nowEpochSeconds: () => NOW,
      generateId: () => `01PIPELINEDEC${String(idCounter++).padStart(3, "0")}`,
      nowMs: () => NOW * 1000,
    });

    const { jti } = await mintDurableGrant(DURABLE_GITHUB_INPUT, {
      store,
      keyStore,
      nowEpochSeconds: NOW,
      generateId: makeIdGen(),
      audit,
    });

    // Miss → adapter → allow, populated into the cache.
    const miss = await pipeline.decide({
      request,
      tierPolicy: SENSITIVE_POLICY,
      coveringGrants: [],
    });
    expect(miss.outcome).toBe("allow");
    expect(miss.cache.hit).toBe(false);

    // Hit → the CACHED allow, no adapter/store involvement.
    const hit = await pipeline.decide({
      request,
      tierPolicy: SENSITIVE_POLICY,
      coveringGrants: [],
    });
    expect(hit.outcome).toBe("allow");
    expect(hit.cache.hit).toBe(true);

    // Revoke, wiring onInvalidate to the cache's own bump — the composed
    // system's realization of the plan's `configEpoch` bump (R16/R20).
    const onInvalidate = vi.fn(() => cache.bumpGrantSetVersion());
    revokeGrants({ jti }, { store, audit, onInvalidate });
    expect(onInvalidate).toHaveBeenCalledTimes(1);

    // The previously-cached allow is unreachable: fresh evaluation → deny.
    const fresh = await pipeline.decide({
      request,
      tierPolicy: SENSITIVE_POLICY,
      coveringGrants: [],
    });
    expect(fresh.cache.hit).toBe(false);
    expect(fresh.outcome).toBe("deny");
    expect(fresh.reasonCode).toBe("no_grant_sensitive");

    expect(audit.verify().ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// R40 — grant_created / grant_consumed wiring
// ---------------------------------------------------------------------------

describe("R40 — mint + consume audit wiring", () => {
  it("mintDurableGrant(audited) appends grant_created with kind=durable, subject=principal.id, agent '*', grantRefs=[jti]", async () => {
    const audit = makeAudit();
    const { jti } = await mintDurableGrant(DURABLE_GITHUB_INPUT, {
      store,
      keyStore,
      nowEpochSeconds: NOW,
      generateId: makeIdGen(),
      audit,
    });
    audit.flush();

    const events = readAuditEvents();
    expect(events).toHaveLength(1);
    const event = events[0];
    expect(event?.type).toBe("grant_created");
    expect(event?.subject).toBe("avijeett007@gmail.com");
    expect(event?.agent).toBe("*");
    expect(event?.tool).toBe("github.*");
    expect(event?.reason).toBe("kind=durable");
    expect(event?.grantRefs).toEqual([jti]);
  });

  it("the consume path chains grant_created → grant_consumed → decision(allow) for a single-use ephemeral grant", async () => {
    const audit = makeAudit();
    const request = criticalRequest();
    const { jti } = await mintEphemeralGrant(
      { request, tier: "critical" },
      {
        store,
        keyStore,
        nowEpochSeconds: NOW,
        generateId: makeIdGen(),
        audit,
      },
    );

    const result = decideWithGrants(
      request,
      { tierPolicy: CRITICAL_POLICY, nowEpochSeconds: NOW, resolvePublicKey },
      { store, audit },
    );
    expect(result.decision.outcome).toBe("allow");
    expect(result.consumedJti).toBe(jti);

    expect(audit.verify()).toEqual({ ok: true, events: 3 });
    audit.flush();
    const events = readAuditEvents();
    expect(events.map((e) => e.type)).toEqual([
      "grant_created",
      "grant_consumed",
      "decision",
    ]);
    expect(events[0]?.reason).toBe("kind=ephemeral");
    expect(events[0]?.agent).toBe("codex-cli");
    expect(events[1]?.grantRefs).toEqual([jti]);
    expect(events[1]?.reason).toBe("single_use_consumed");
    expect(events[2]?.outcome).toBe("allow");
    expect(events[2]?.grantRefs).toEqual([jti]);
  });

  it("critical-tier decision events (and the consume event of the same decision) pass { fsync: 'immediate' } (R38); sensitive-tier events do not", async () => {
    const real = makeAudit();
    const calls: Array<{ type: string; opts: unknown }> = [];
    const recording: AuditSink = {
      append(event, opts) {
        calls.push({ type: event.type, opts });
        return real.append(event, opts);
      },
      flush: () => real.flush(),
      close: () => real.close(),
      verify: () => real.verify(),
      onAppend: (listener) => real.onAppend(listener),
    };

    // Critical: ephemeral grant, consumed → grant_consumed + decision, both immediate.
    const critReq = criticalRequest();
    await mintEphemeralGrant(
      { request: critReq, tier: "critical" },
      {
        store,
        keyStore,
        nowEpochSeconds: NOW,
        generateId: makeIdGen("TESTFSYNCA"),
      },
    );
    decideWithGrants(
      critReq,
      { tierPolicy: CRITICAL_POLICY, nowEpochSeconds: NOW, resolvePublicKey },
      { store, audit: recording },
    );

    // Sensitive: no grant → tier-default deny, still exactly one decision event, deferred fsync.
    decideWithGrants(
      sensitiveRequest(),
      { tierPolicy: SENSITIVE_POLICY, nowEpochSeconds: NOW, resolvePublicKey },
      { store, audit: recording },
    );

    expect(calls).toEqual([
      { type: "grant_consumed", opts: { fsync: "immediate" } },
      { type: "decision", opts: { fsync: "immediate" } },
      { type: "decision", opts: undefined },
    ]);
  });
});

// ---------------------------------------------------------------------------
// R40 — fail closed on audit failure (the P0-E5-T5 proxy composition hook)
// ---------------------------------------------------------------------------

describe("R40 — fail-closed audit composition (the P0-E5-T5 mandatory-wiring hook)", () => {
  function failingSink(attempts: string[]): AuditSink {
    return {
      append(event) {
        attempts.push(event.type);
        throw new AuditUnavailableError(
          "injected: audit disk unavailable (P0-E5-T5 hook test)",
        );
      },
      flush() {
        // no-op — this stub never buffers
      },
      close() {
        // no-op
      },
      verify() {
        return { ok: true, events: 0 };
      },
      onAppend() {
        // no-op — this stub has no listener bus; nothing in this suite subscribes.
        return () => {};
      },
    };
  }

  it("a would-be allow resolves deny/audit_unavailable when the decision append throws; the deny itself is re-audited best-effort and the second failure is swallowed", async () => {
    const request = sensitiveRequest();
    await mintDurableGrant(DURABLE_GITHUB_INPUT, {
      store,
      keyStore,
      nowEpochSeconds: NOW,
      generateId: makeIdGen(),
    });

    const attempts: string[] = [];
    const audit = failingSink(attempts);

    let result: ReturnType<typeof decideWithGrants> | undefined;
    expect(() => {
      result = decideWithGrants(
        request,
        {
          tierPolicy: SENSITIVE_POLICY,
          nowEpochSeconds: NOW,
          resolvePublicKey,
        },
        { store, audit },
      );
    }).not.toThrow();

    expect(result?.decision.outcome).toBe("deny");
    expect(result?.decision.reasonCode).toBe(AUDIT_UNAVAILABLE);
    expect(result?.decision.reasonCode).toBe("audit_unavailable");
    // Two attempts: the original decision event, then the best-effort
    // re-audit of the converted deny (also failed, swallowed).
    expect(attempts).toEqual(["decision", "decision"]);
  });

  it("a consumed single-use grant stays honestly reported as consumed even when the audit failure converts the allow to the deny", async () => {
    const request = criticalRequest();
    const { jti } = await mintEphemeralGrant(
      { request, tier: "critical" },
      { store, keyStore, nowEpochSeconds: NOW, generateId: makeIdGen() },
    );

    const attempts: string[] = [];
    const result = decideWithGrants(
      request,
      { tierPolicy: CRITICAL_POLICY, nowEpochSeconds: NOW, resolvePublicKey },
      { store, audit: failingSink(attempts) },
    );

    // The wx marker landed before the audit failure — the grant IS burned.
    expect(result.decision.outcome).toBe("deny");
    expect(result.decision.reasonCode).toBe(AUDIT_UNAVAILABLE);
    expect(result.consumedJti).toBe(jti);
    expect(store.isConsumed(jti)).toBe(true);
    // grant_consumed threw first; the decision-allow event was never
    // attempted; the converted deny was re-attempted best-effort.
    expect(attempts).toEqual(["grant_consumed", "decision"]);
  });

  it("with NO audit sink wired, behavior is unchanged (the seam stays optional until P0-E5-T3/T5 makes it mandatory at the proxy)", async () => {
    const request = sensitiveRequest();
    await mintDurableGrant(DURABLE_GITHUB_INPUT, {
      store,
      keyStore,
      nowEpochSeconds: NOW,
      generateId: makeIdGen(),
    });

    const result = decideWithGrants(
      request,
      { tierPolicy: SENSITIVE_POLICY, nowEpochSeconds: NOW, resolvePublicKey },
      { store },
    );

    expect(result.decision.outcome).toBe("allow");
    expect(result.decision.reasonCode).toBe("grant_allow");
  });
});
