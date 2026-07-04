/**
 * @knotrust/approval — the approval lifecycle state machine's acceptance
 * suite (P0-E6-T1, rulings R86–R90).
 *
 * Two tiers of test double:
 *
 *  - The illegal-transition matrix and the plain deny/cancel/expire/
 *    fail-closed-audit paths use a lightweight in-memory `AuditSink` double
 *    and manually-controlled `mintEphemeralGrant`/`decide` stubs — they are
 *    testing THIS module's own state machine, not the grants/precedence
 *    stack underneath it.
 *  - The two security-heart acceptance items — approve → mint → re-evaluate
 *    → allow, and the mid-flight admin force-deny — compose the REAL
 *    `@knotrust/grants` (`mintEphemeralGrant`, `createDecider`,
 *    `computeCallHash`) and REAL `@knotrust/store` (`createGrantStore`,
 *    `createAuditLog`) over a throwaway temp `$KNOTRUST_HOME`, proving the
 *    orchestrator's injected-deps design actually composes with the real
 *    stack end-to-end, exactly as the proxy (E6-T4) will wire it.
 */

import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type {
  AdminEnvelope,
  DecisionRequest,
  DecisionResponse,
  TierPolicy,
} from "@knotrust/core";
import { createDecisionCache } from "@knotrust/core";
import type {
  Ed25519PublicJwk,
  KeyStore,
  KnotrustIdentity,
} from "@knotrust/grants";
import {
  computeCallHash,
  createDecider,
  decodeGrantIndexEntry,
  decodeGrantPayload,
  type MintResult,
  parseWireClaims,
  mintEphemeralGrant as realMintEphemeralGrant,
  revokeGrants,
} from "@knotrust/grants";
import {
  type AuditEvent,
  type AuditSink,
  createAuditLog,
  createGrantStore,
  type GrantStore,
} from "@knotrust/store";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ApprovalNotFoundError,
  type ApprovalRequest,
  createApprovalOrchestrator,
  IllegalApprovalTransitionError,
} from "./lifecycle.js";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000; // fixed epoch seconds — no real clock anywhere in this suite

/** The complete §6.1 `ApprovalState` union — the ONLY values `status()`/the handle may ever expose (R90). */
const VALID_APPROVAL_STATES: ReadonlyArray<string> = [
  "requested",
  "pending",
  "approved",
  "denied",
  "expired",
  "cancelled",
];

function makeDecisionRequest(
  over: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01APPROVALREQ0000000000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 42_000, reason: "requested_by_customer" },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px-approval-1",
      server: "stripe",
    },
    ...over,
  };
}

function makeApprovalRequest(
  decisionRequest: DecisionRequest,
  over: Partial<ApprovalRequest> = {},
): ApprovalRequest {
  return {
    decisionId: "01DECISION000000000000001",
    requestId: decisionRequest.requestId,
    subject: decisionRequest.subject,
    agent: decisionRequest.context.agent,
    action: decisionRequest.action,
    resource: decisionRequest.resource,
    tier: "critical",
    eligibleChannels: ["block_and_wait"],
    decisionRequest,
    ...over,
  };
}

function makeIdGen(prefix = "TEST"): () => string {
  let n = 0;
  return () => `${prefix}${String(n++).padStart(4, "0")}`;
}

/** A minimal `allow` `DecisionResponse` for the fake-deps latch tests — the orchestrator only ever reads `.outcome`/`.reasonCode`. */
function fakeAllowResponse(): DecisionResponse {
  return {
    contractVersion: "1.0",
    requestId: "01APPROVALREQ0000000000001",
    decisionId: "01DECISION000000000000001",
    outcome: "allow",
    tier: "critical",
    reasonCode: "grant_allow",
    cache: { hit: false },
    evaluatedBy: "grant",
    latencyMs: 0,
  };
}

// ---------------------------------------------------------------------------
// Fake in-memory AuditSink — for the state-machine-only test tier.
// ---------------------------------------------------------------------------

type RecordedAuditEvent = Omit<AuditEvent, "seq" | "prevHash" | "hash" | "ts">;

function makeFakeAuditSink(): {
  sink: AuditSink;
  events: RecordedAuditEvent[];
} {
  const events: RecordedAuditEvent[] = [];
  let seq = 0;
  const sink: AuditSink = {
    append(event) {
      seq += 1;
      events.push(event);
      const full: AuditEvent = {
        seq,
        ts: new Date(NOW * 1000).toISOString(),
        prevHash: "0".repeat(64),
        hash: "0".repeat(64),
        ...event,
      };
      return full;
    },
    flush() {},
    close() {},
    verify() {
      return { ok: true, events: events.length };
    },
    onAppend() {
      // no-op — no test in this file subscribes; @knotrust/otel's subscriber
      // contract is covered in that package's own suite, not here.
      return () => {};
    },
  };
  return { sink, events };
}

/** An `AuditSink` whose `append` throws for any event whose `type` is in `failOn`. */
function makeThrowingAuditSink(failOn: ReadonlySet<string>): {
  sink: AuditSink;
  events: RecordedAuditEvent[];
} {
  const events: RecordedAuditEvent[] = [];
  let seq = 0;
  const sink: AuditSink = {
    append(event) {
      if (failOn.has(event.type)) {
        throw new Error(`knotrust: simulated audit failure for ${event.type}`);
      }
      seq += 1;
      events.push(event);
      const full: AuditEvent = {
        seq,
        ts: new Date(NOW * 1000).toISOString(),
        prevHash: "0".repeat(64),
        hash: "0".repeat(64),
        ...event,
      };
      return full;
    },
    flush() {},
    close() {},
    verify() {
      return { ok: true, events: events.length };
    },
    onAppend() {
      // no-op — no test in this file subscribes; @knotrust/otel's subscriber
      // contract is covered in that package's own suite, not here.
      return () => {};
    },
  };
  return { sink, events };
}

/** Narrows away `undefined` with a real runtime check (never `!`) — biome forbids non-null assertions. */
function assertDefined<T>(
  value: T | undefined,
  message: string,
): asserts value is T {
  if (value === undefined) throw new Error(message);
}

/** Narrows away `null` with a real runtime check (never `!`) — biome forbids non-null assertions. */
function assertNotNull<T>(
  value: T | null,
  message: string,
): asserts value is T {
  if (value === null) throw new Error(message);
}

/**
 * Captures `process.stderr.write` by direct reassignment — the pattern this
 * repo already uses for stderr-notice assertions (see `@knotrust/store`'s
 * `audit-log.test.ts`); `vi.spyOn(process.stderr, "write")` does not intercept
 * reliably under this Vitest setup.
 */
function captureStderr(): { writes: string[]; restore: () => void } {
  const writes: string[] = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array): boolean => {
    writes.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  return {
    writes,
    restore: () => {
      process.stderr.write = original;
    },
  };
}

/** Deps that must never be invoked (deny/cancel/expire paths mint nothing, per R89). */
function unreachableMint(): never {
  throw new Error("mintEphemeralGrant must not be called on this path");
}
function unreachableDecide(): never {
  throw new Error("decide must not be called on this path");
}

// =============================================================================
// 1. State-machine-only suite (fake audit, stub mint/decide)
// =============================================================================

describe("createApprovalOrchestrator — state machine (fake deps)", () => {
  it("request() transitions requested → pending and returns {id, state} only", async () => {
    const { sink, events } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: unreachableMint,
      decide: unreachableDecide,
      audit: sink,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen(),
    });

    const handle = await orchestrator.request(
      makeApprovalRequest(makeDecisionRequest()),
    );

    expect(handle).toEqual({
      id: expect.stringMatching(/^apr_TEST\d{4}$/),
      state: "pending",
    });
    expect(Object.keys(handle).sort()).toEqual(["id", "state"]);
    expect(events.map((e) => e.type)).toEqual([
      "approval_requested",
      "approval_pending",
    ]);
  });

  it("status() returns the current handle and never mutates a non-expired pending record", async () => {
    const { sink } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: unreachableMint,
      decide: unreachableDecide,
      audit: sink,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen(),
    });
    const handle = await orchestrator.request(
      makeApprovalRequest(makeDecisionRequest()),
    );
    expect(await orchestrator.status(handle.id)).toEqual({
      id: handle.id,
      state: "pending",
    });
  });

  it("resolve(id, 'denied') → terminal denied, onResolved() settles 'denied', audited", async () => {
    const { sink, events } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: unreachableMint,
      decide: unreachableDecide,
      audit: sink,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen(),
    });
    const handle = await orchestrator.request(
      makeApprovalRequest(makeDecisionRequest()),
    );

    await orchestrator.resolve(handle.id, "denied");

    expect(await orchestrator.onResolved(handle.id)).toBe("denied");
    expect(await orchestrator.status(handle.id)).toEqual({
      id: handle.id,
      state: "denied",
    });
    expect(events.map((e) => e.type)).toEqual([
      "approval_requested",
      "approval_pending",
      "approval_denied",
    ]);
    expect(events.at(-1)?.reason).toBe("approval_denied");
  });

  it("cancel() → terminal cancelled, onResolved() settles 'cancelled', audited", async () => {
    const { sink, events } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: unreachableMint,
      decide: unreachableDecide,
      audit: sink,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen(),
    });
    const handle = await orchestrator.request(
      makeApprovalRequest(makeDecisionRequest()),
    );

    await orchestrator.cancel(handle.id);

    expect(await orchestrator.onResolved(handle.id)).toBe("cancelled");
    expect(events.at(-1)).toMatchObject({
      type: "approval_cancelled",
      reason: "approval_cancelled",
    });
  });

  describe("expiry — no real timers (lazy check + sweepExpired)", () => {
    it("sweepExpired(now) expires a past-deadline pending approval and returns its id", async () => {
      const { sink, events } = makeFakeAuditSink();
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest(), { timeoutSeconds: 300 }),
      );

      const expiredBeforeDeadline = orchestrator.sweepExpired(NOW + 299);
      expect(expiredBeforeDeadline).toEqual([]);
      expect(await orchestrator.status(handle.id)).toEqual({
        id: handle.id,
        state: "pending",
      });

      const expiredAtDeadline = orchestrator.sweepExpired(NOW + 300);
      expect(expiredAtDeadline).toEqual([handle.id]);
      expect(await orchestrator.onResolved(handle.id)).toBe("expired");
      expect(events.at(-1)).toMatchObject({
        type: "approval_expired",
        reason: "approval_timeout",
      });

      // Idempotent: sweeping again does not re-expire/re-audit an already-terminal record.
      const eventCountAfterFirstExpiry = events.length;
      expect(orchestrator.sweepExpired(NOW + 1000)).toEqual([]);
      expect(events.length).toBe(eventCountAfterFirstExpiry);
    });

    it("status()/onResolved() lazily expire a past-deadline approval with no sweepExpired call at all", async () => {
      // request() reads nowEpochSeconds() once for requestedAt, so the clock
      // must start before the deadline and only advance afterwards.
      let clock = NOW;
      const { sink, events } = makeFakeAuditSink();
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => clock,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest(), { timeoutSeconds: 300 }),
      );
      clock = NOW + 301; // deadline has now passed, but nobody called sweepExpired

      expect(await orchestrator.status(handle.id)).toEqual({
        id: handle.id,
        state: "expired",
      });
      expect(events.at(-1)).toMatchObject({
        type: "approval_expired",
        reason: "approval_timeout",
      });
    });
  });

  describe("illegal-transition matrix", () => {
    async function pendingHandle(): Promise<{
      orchestrator: ReturnType<typeof createApprovalOrchestrator>;
      id: string;
    }> {
      const { sink } = makeFakeAuditSink();
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );
      return { orchestrator, id: handle.id };
    }

    it("unknown id → status()/resolve()/cancel()/onResolved() all throw ApprovalNotFoundError", async () => {
      const { orchestrator } = await pendingHandle();
      await expect(orchestrator.status("apr_nope")).rejects.toThrow(
        ApprovalNotFoundError,
      );
      await expect(
        orchestrator.resolve("apr_nope", "approved"),
      ).rejects.toThrow(ApprovalNotFoundError);
      await expect(orchestrator.cancel("apr_nope")).rejects.toThrow(
        ApprovalNotFoundError,
      );
      await expect(orchestrator.onResolved("apr_nope")).rejects.toThrow(
        ApprovalNotFoundError,
      );
    });

    it("double-deny: resolve(id,'denied') twice → second throws IllegalApprovalTransitionError", async () => {
      const { orchestrator, id } = await pendingHandle();
      await orchestrator.resolve(id, "denied");
      await expect(orchestrator.resolve(id, "denied")).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
    });

    it("resolve(id,'approved') after already denied → throws", async () => {
      const { orchestrator, id } = await pendingHandle();
      await orchestrator.resolve(id, "denied");
      await expect(orchestrator.resolve(id, "approved")).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
    });

    it("cancel() after resolve(id,'denied') → throws", async () => {
      const { orchestrator, id } = await pendingHandle();
      await orchestrator.resolve(id, "denied");
      await expect(orchestrator.cancel(id)).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
    });

    it("double-cancel → second throws", async () => {
      const { orchestrator, id } = await pendingHandle();
      await orchestrator.cancel(id);
      await expect(orchestrator.cancel(id)).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
    });

    it("resolve(id,'denied') after cancel() → throws", async () => {
      const { orchestrator, id } = await pendingHandle();
      await orchestrator.cancel(id);
      await expect(orchestrator.resolve(id, "denied")).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
    });

    it("approve after expiry (deadline already passed) → throws, never mints/decides", async () => {
      let clock = NOW;
      const { sink } = makeFakeAuditSink();
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => clock,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest(), { timeoutSeconds: 60 }),
      );
      clock = NOW + 61; // past the deadline

      await expect(orchestrator.resolve(handle.id, "approved")).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
      expect(await orchestrator.status(handle.id)).toEqual({
        id: handle.id,
        state: "expired",
      });
    });

    it("deny after expiry → throws; cancel after expiry → throws", async () => {
      let clock = NOW;
      const { sink } = makeFakeAuditSink();
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => clock,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest(), { timeoutSeconds: 60 }),
      );
      clock = NOW + 61;

      await expect(orchestrator.resolve(handle.id, "denied")).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
      await expect(orchestrator.cancel(handle.id)).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
    });
  });

  describe("fail-closed on audit failure (R86)", () => {
    it("request() whose 'approval_pending' audit throws returns state 'denied' immediately", async () => {
      const { sink, events } = makeThrowingAuditSink(
        new Set(["approval_pending"]),
      );
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });

      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      expect(handle.state).toBe("denied");
      expect(await orchestrator.onResolved(handle.id)).toBe("denied");
      expect(events.map((e) => e.type)).toEqual([
        "approval_requested",
        "approval_denied",
      ]);
      expect(events.at(-1)?.reason).toBe("audit_unavailable");
    });

    it("request() whose very first 'approval_requested' audit throws never reaches 'pending'", async () => {
      const { sink, events } = makeThrowingAuditSink(
        new Set(["approval_requested"]),
      );
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });

      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      expect(handle.state).toBe("denied");
      // The failed "approval_requested" line never made it into the log; only
      // the fail-closed corrective "approval_denied" line did.
      expect(events.map((e) => e.type)).toEqual(["approval_denied"]);
    });

    it("resolve(id,'approved') whose 'approval_approved' audit throws denies fail-closed and never mints", async () => {
      const { sink } = makeThrowingAuditSink(new Set(["approval_approved"]));
      let mintCalled = false;
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: async () => {
          mintCalled = true;
          throw new Error("must not be reached");
        },
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      await orchestrator.resolve(handle.id, "approved");

      expect(mintCalled).toBe(false);
      expect(await orchestrator.onResolved(handle.id)).toBe("denied");
    });
  });

  // FIX 1 — the in-flight latch, exercised with fake deps. (The double-approve
  // "exactly one grant minted + consumed" probe lives in the real-composition
  // suite below, where `store.isConsumed` is real.)
  describe("in-flight latch — resolve/cancel are single-winner (FIX 1)", () => {
    it("concurrent resolve('approved') + resolve('approved'): exactly one mint, one approval_approved, one winner", async () => {
      const { sink, events } = makeFakeAuditSink();
      let mintCount = 0;
      let decideCount = 0;
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: async () => {
          mintCount += 1;
          return { token: `tok_${mintCount}`, jti: `01GRANT${mintCount}` };
        },
        decide: async () => {
          decideCount += 1;
          return fakeAllowResponse();
        },
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      const results = await Promise.allSettled([
        orchestrator.resolve(handle.id, "approved"),
        orchestrator.resolve(handle.id, "approved"),
      ]);

      const fulfilled = results.filter((r) => r.status === "fulfilled");
      const rejected = results.filter((r) => r.status === "rejected");
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(
        IllegalApprovalTransitionError,
      );
      // The latch let exactly ONE caller through mint + re-eval.
      expect(mintCount).toBe(1);
      expect(decideCount).toBe(1);
      expect(events.filter((e) => e.type === "approval_approved")).toHaveLength(
        1,
      );
      expect(await orchestrator.status(handle.id)).toEqual({
        id: handle.id,
        state: "approved",
      });
      expect(await orchestrator.onResolved(handle.id)).toBe("approved");
    });

    it("status()/the handle NEVER expose the internal 'resolving' latch mid-flight (R90 — no leak)", async () => {
      const { sink } = makeFakeAuditSink();
      let releaseMint: () => void = () => {};
      const mintGate = new Promise<void>((res) => {
        releaseMint = res;
      });
      let signalMintStarted: () => void = () => {};
      const mintStarted = new Promise<void>((res) => {
        signalMintStarted = res;
      });
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: async () => {
          signalMintStarted();
          await mintGate; // park the resolve() winner mid-flight (latched)
          return { token: "tok", jti: "01GRANT1" };
        },
        decide: async () => fakeAllowResponse(),
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      const inflight = orchestrator.resolve(handle.id, "approved");
      await mintStarted; // the record is now latched (resolving), mid-flight

      // The public handle still exposes ONLY the §6.1 ApprovalState "pending" —
      // never the internal "resolving" latch.
      const midStatus = await orchestrator.status(handle.id);
      expect(midStatus).toEqual({ id: handle.id, state: "pending" });
      expect(Object.keys(midStatus).sort()).toEqual(["id", "state"]);
      expect(VALID_APPROVAL_STATES).toContain(midStatus.state);
      expect(midStatus.state).not.toBe("resolving");

      releaseMint();
      await inflight;
      expect((await orchestrator.status(handle.id)).state).toBe("approved");
    });

    it("concurrent resolve('approved') + cancel(): resolve wins, cancel rejected, terminal state never overwritten", async () => {
      const { sink } = makeFakeAuditSink();
      let mintCount = 0;
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: async () => {
          mintCount += 1;
          return { token: `tok_${mintCount}`, jti: `01GRANT${mintCount}` };
        },
        decide: async () => fakeAllowResponse(),
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      // resolve() is issued first: it latches synchronously and parks at its
      // mint await, so the cancel() that follows sees the latch and is rejected.
      const results = await Promise.allSettled([
        orchestrator.resolve(handle.id, "approved"),
        orchestrator.cancel(handle.id),
      ]);

      expect(results[0].status).toBe("fulfilled");
      expect(results[1].status).toBe("rejected");
      expect((results[1] as PromiseRejectedResult).reason).toBeInstanceOf(
        IllegalApprovalTransitionError,
      );
      expect(mintCount).toBe(1);
      // status() and onResolved() AGREE, and the terminal state is "approved" —
      // the cancel() never wrote "cancelled" for the resolve to overwrite.
      const status = await orchestrator.status(handle.id);
      const settled = await orchestrator.onResolved(handle.id);
      expect(status.state).toBe("approved");
      expect(settled).toBe("approved");
    });

    it("concurrent cancel() + resolve('approved'): cancel wins, NO grant minted, resolve rejected", async () => {
      const { sink } = makeFakeAuditSink();
      let mintCount = 0;
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: async () => {
          mintCount += 1;
          return { token: `tok_${mintCount}`, jti: `01GRANT${mintCount}` };
        },
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      // cancel() is issued first: it is fully synchronous through its terminal
      // write, so the resolve() that follows sees a "cancelled" terminal record.
      const results = await Promise.allSettled([
        orchestrator.cancel(handle.id),
        orchestrator.resolve(handle.id, "approved"),
      ]);

      expect(results[0].status).toBe("fulfilled");
      expect(results[1].status).toBe("rejected");
      expect((results[1] as PromiseRejectedResult).reason).toBeInstanceOf(
        IllegalApprovalTransitionError,
      );
      // Cancel won ⇒ NO grant minted/consumed.
      expect(mintCount).toBe(0);
      const status = await orchestrator.status(handle.id);
      const settled = await orchestrator.onResolved(handle.id);
      expect(status.state).toBe("cancelled");
      expect(settled).toBe("cancelled");
    });
  });

  // FIX 2 — on deny/cancel/expire the terminal state is written BEFORE the
  // audit append, so a throwing sink used to silently lose the forensic line
  // (forceFailClosedDeny no-ops on an already-terminal record). The failure
  // must now be surfaced to stderr while the correct terminal outcome stands.
  describe("audit failure on an already-terminal transition surfaces to stderr (FIX 2)", () => {
    it("resolve('denied') whose 'approval_denied' audit throws: terminal deny stands, failure hits stderr", async () => {
      const { sink } = makeThrowingAuditSink(new Set(["approval_denied"]));
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );
      const stderr = captureStderr();
      try {
        await orchestrator.resolve(handle.id, "denied");
      } finally {
        stderr.restore();
      }

      expect(await orchestrator.status(handle.id)).toEqual({
        id: handle.id,
        state: "denied",
      });
      expect(await orchestrator.onResolved(handle.id)).toBe("denied");
      expect(stderr.writes).toHaveLength(1);
      expect(stderr.writes[0]).toContain("approval_denied");
    });

    it("cancel() whose 'approval_cancelled' audit throws: terminal cancelled stands, failure hits stderr", async () => {
      const { sink } = makeThrowingAuditSink(new Set(["approval_cancelled"]));
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );
      const stderr = captureStderr();
      try {
        await orchestrator.cancel(handle.id);
      } finally {
        stderr.restore();
      }

      expect(await orchestrator.onResolved(handle.id)).toBe("cancelled");
      expect(stderr.writes).toHaveLength(1);
      expect(stderr.writes[0]).toContain("approval_cancelled");
    });

    it("expiry whose 'approval_expired' audit throws: terminal expired stands, failure hits stderr", async () => {
      let clock = NOW;
      const { sink } = makeThrowingAuditSink(new Set(["approval_expired"]));
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: unreachableMint,
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => clock,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest(), { timeoutSeconds: 60 }),
      );
      clock = NOW + 61;

      const stderr = captureStderr();
      let state: string;
      try {
        state = (await orchestrator.status(handle.id)).state;
      } finally {
        stderr.restore();
      }

      expect(state).toBe("expired");
      expect(stderr.writes).toHaveLength(1);
      expect(stderr.writes[0]).toContain("approval_expired");
    });
  });

  // FIX 4 — mint/re-evaluation THROWING (rather than resolving to a non-
  // "allow" outcome) must not leave the record latched forever: see module
  // header, "Fail-closed when mint/re-evaluation THROWS." Pre-fix, an
  // uncaught throw from either `await` left `state` stuck at `"pending"` with
  // `resolving` latched, so `checkExpiry` (which exempts latched records)
  // could never reclaim it and `onResolved()` never settled.
  describe("fail-closed when mint/re-evaluation THROWS (FIX 4)", () => {
    it("mintEphemeralGrant() throws → resolves terminal 'denied' (not stuck pending/resolving); onResolved() settles", async () => {
      const { sink, events } = makeFakeAuditSink();
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: async () => {
          throw new Error("simulated store.put failure");
        },
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      await orchestrator.resolve(handle.id, "approved");

      // A true §6.1 terminal state — never stuck "pending", never leaking the
      // internal "resolving" latch (R90).
      const status = await orchestrator.status(handle.id);
      expect(status.state).toBe("denied");
      expect(VALID_APPROVAL_STATES).toContain(status.state);
      expect(Object.keys(status).sort()).toEqual(["id", "state"]);
      // onResolved() settles instead of hanging the awaiting caller
      // (block-and-wait, E6-T2) forever.
      expect(await orchestrator.onResolved(handle.id)).toBe("denied");
      expect(events.at(-1)).toMatchObject({
        type: "approval_denied",
        reason: "approval_internal_error",
      });

      // Expiry is no longer needed to reclaim it (already terminal), and a
      // rescue resolve() correctly reports the terminal state — never a
      // lingering "resolving".
      expect(orchestrator.sweepExpired(NOW + 100_000)).toEqual([]);
      await expect(orchestrator.resolve(handle.id, "denied")).rejects.toThrow(
        IllegalApprovalTransitionError,
      );
    });

    it("decide() throws AFTER a successful mint → resolves terminal 'denied' AND the minted grant is best-effort revoked", async () => {
      const { sink, events } = makeFakeAuditSink();
      let revokedJti: string | undefined;
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: async () => ({ token: "tok_1", jti: "01GRANT1" }),
        decide: async () => {
          throw new Error("simulated re-evaluation failure");
        },
        revokeGrant: (jti) => {
          revokedJti = jti;
        },
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      await orchestrator.resolve(handle.id, "approved");

      expect(await orchestrator.status(handle.id)).toEqual({
        id: handle.id,
        state: "denied",
      });
      expect(await orchestrator.onResolved(handle.id)).toBe("denied");
      // The grant minted before `decide` threw is not left active/consumable
      // — it is best-effort revoked, the same posture as the non-allow
      // re-eval path (FIX 3).
      expect(revokedJti).toBe("01GRANT1");
      expect(events.at(-1)).toMatchObject({
        type: "approval_denied",
        reason: "approval_internal_error",
      });
    });

    it("audit-sink throwing during the fail-closed-on-throw path is surfaced to stderr; still terminal, onResolved() settles", async () => {
      const { sink } = makeThrowingAuditSink(new Set(["approval_denied"]));
      const orchestrator = createApprovalOrchestrator({
        mintEphemeralGrant: async () => {
          throw new Error("simulated mint failure");
        },
        decide: unreachableDecide,
        audit: sink,
        nowEpochSeconds: () => NOW,
        generateId: makeIdGen(),
      });
      const handle = await orchestrator.request(
        makeApprovalRequest(makeDecisionRequest()),
      );

      const stderr = captureStderr();
      try {
        await orchestrator.resolve(handle.id, "approved");
      } finally {
        stderr.restore();
      }

      // Still terminal — the audit failure while HANDLING the mint throw must
      // never re-brick the record back into a latched limbo.
      expect(await orchestrator.status(handle.id)).toEqual({
        id: handle.id,
        state: "denied",
      });
      expect(await orchestrator.onResolved(handle.id)).toBe("denied");
      // Two distinct stderr lines: the mint-throw notice, and the
      // fail-closed-deny's own audit-append-failure notice.
      expect(stderr.writes).toHaveLength(2);
      expect(
        stderr.writes.some((w) => w.includes("simulated mint failure")),
      ).toBe(true);
      expect(stderr.writes.some((w) => w.includes(handle.id))).toBe(true);
    });
  });
});

// =============================================================================
// 2. Real end-to-end suite — real grants + store composition
// =============================================================================

/**
 * A minimal in-memory `KeyStore` test double over a fresh, randomly-generated
 * seed (determinism across runs is unnecessary here — nothing in this suite
 * compares against golden vectors, only against values derived from the SAME
 * seed within a single test run). `sign()` goes through the exact same
 * `@noble/curves` primitive `@knotrust/grants`' real `keys.ts` uses.
 */
function makeTestKeyStore(): KeyStore & {
  identity: KnotrustIdentity;
  publicKeyJwk: Ed25519PublicJwk;
} {
  const seed = new Uint8Array(randomBytes(32));
  const publicKey = ed25519.getPublicKey(seed);
  const kid = Buffer.from(createHash("sha256").update(publicKey).digest())
    .toString("base64url")
    .slice(0, 16);
  const identity: KnotrustIdentity = {
    kid,
    publicKeyJwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(publicKey).toString("base64url"),
    },
  };
  return {
    identity,
    publicKeyJwk: identity.publicKeyJwk,
    backendKind: () => "file",
    ensureIdentity: async () => identity,
    getIdentity: async () => identity,
    sign: async (data: Uint8Array) => ed25519.sign(data, seed),
  };
}

const CRITICAL_POLICY: TierPolicy = {
  tools: { "stripe.create_refund": { tier: "critical", source: "pack" } },
  unknownToolTier: "critical",
};

describe("createApprovalOrchestrator — real end-to-end (grants + store)", () => {
  let tempHome: string;
  let store: GrantStore;
  let audit: AuditSink;
  const keyStore = makeTestKeyStore();
  const resolvePublicKey = (kid: string): Ed25519PublicJwk | null =>
    kid === keyStore.identity.kid ? keyStore.publicKeyJwk : null;

  beforeEach(() => {
    tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-approval-e2e-"));
    store = createGrantStore({
      home: tempHome,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    audit = createAuditLog({ home: tempHome, nowEpochMs: () => NOW * 1000 });
  });

  afterEach(() => {
    audit.close();
    rmSync(tempHome, { recursive: true, force: true });
  });

  /** Reads every audit event across every `<yyyymm>.jsonl` file, in seq order. */
  function readAllAuditEvents(): AuditEvent[] {
    const auditDir = path.join(tempHome, "audit");
    const files = readdirSync(auditDir)
      .filter((f) => /^\d{6}\.jsonl$/.test(f))
      .sort();
    const events: AuditEvent[] = [];
    for (const file of files) {
      const text = readFileSync(path.join(auditDir, file), "utf8");
      for (const line of text.split("\n")) {
        if (line.trim().length === 0) continue;
        events.push(JSON.parse(line) as AuditEvent);
      }
    }
    events.sort((a, b) => a.seq - b.seq);
    return events;
  }

  it("approve → mint ephemeral grant → re-evaluate → allow, end-to-end; ch === callHash(frozen snapshot); every transition audited", async () => {
    const originalRequest = makeDecisionRequest();
    const expectedCallHash = computeCallHash(originalRequest);

    const cache = createDecisionCache({ nowEpochSeconds: () => NOW });
    const decider = createDecider({
      cache,
      tierPolicy: CRITICAL_POLICY,
      policyVersion: "v1",
      store,
      audit,
      resolvePublicKey,
      nowEpochSeconds: () => NOW,
      nowMs: () => NOW * 1000,
      generateId: makeIdGen("DECID"),
    });

    let captured: MintResult | undefined;
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async (input) => {
        const result = await realMintEphemeralGrant(input, {
          store,
          keyStore,
          nowEpochSeconds: NOW,
          generateId: makeIdGen("GRANT"),
          audit,
        });
        captured = result;
        return result;
      },
      decide: (req) => decider.decide(req),
      audit,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen("APR"),
    });

    const handle = await orchestrator.request(
      makeApprovalRequest(originalRequest),
    );
    expect(handle.state).toBe("pending");

    // Mutate the CALLER's own object after request() — proves the orchestrator
    // captured a frozen, independent clone, not a live reference (R86).
    (originalRequest.context.arguments as Record<string, unknown>).amount =
      999_999_999;
    originalRequest.action.name = "mutated.should_never_be_used";

    await orchestrator.resolve(handle.id, "approved");
    const finalState = await orchestrator.onResolved(handle.id);

    expect(finalState).toBe("approved");
    assertDefined(captured, "mintEphemeralGrant was not invoked");

    // ch === computeCallHash(frozen snapshot) — asserted directly against the
    // minted token's own claims, and against the PRE-mutation expected hash.
    const claims = parseWireClaims(decodeGrantPayload(captured.token));
    assertNotNull(claims, "minted token failed to decode");
    expect(claims.callHash).toBe(expectedCallHash);

    // The ephemeral grant was the deciding, single-use grant — consumed exactly once.
    expect(store.isConsumed(captured.jti)).toBe(true);

    // Every transition (and the mint + consume + decision it triggered) is in
    // the audit chain, in order (R87d's illustrative order — `...approved →
    // grant_created(ephemeral) → decision(allow)` — plus the `grant_consumed`
    // event the real single-use-consume-is-atomic-with-the-decision algorithm
    // (grants' `decideCore`) also appends, immediately before `decision`).
    const events = readAllAuditEvents();
    expect(events.map((e) => e.type)).toEqual([
      "approval_requested",
      "approval_pending",
      "approval_approved",
      "grant_created",
      "grant_consumed",
      "decision",
    ]);
    const decisionEvent = events.at(-1);
    expect(decisionEvent).toMatchObject({
      outcome: "allow",
      reason: "grant_allow",
      grantRefs: [captured.jti],
    });

    expect(audit.verify()).toEqual({ ok: true, events: events.length });
  });

  it("mid-flight admin force-deny turns an approved-by-human approval into a final deny (approval satisfies a prerequisite, never bypasses policy)", async () => {
    const originalRequest = makeDecisionRequest();

    const forceDenyEnvelope: AdminEnvelope = {
      scope: "personal",
      denyTools: ["stripe.create_refund"],
    };

    // No `envelope` key at all — `exactOptionalPropertyTypes` treats an
    // explicit `envelope: undefined` as distinct from an absent key.
    const deciderAllow = createDecider({
      cache: createDecisionCache({ nowEpochSeconds: () => NOW }),
      tierPolicy: CRITICAL_POLICY,
      policyVersion: "v1",
      store,
      audit,
      resolvePublicKey,
      nowEpochSeconds: () => NOW,
      nowMs: () => NOW * 1000,
      generateId: makeIdGen("DECIDA"),
    });
    const deciderForceDeny = createDecider({
      cache: createDecisionCache({ nowEpochSeconds: () => NOW }),
      tierPolicy: CRITICAL_POLICY,
      envelope: forceDenyEnvelope,
      policyVersion: "v1",
      store,
      audit,
      resolvePublicKey,
      nowEpochSeconds: () => NOW,
      nowMs: () => NOW * 1000,
      generateId: makeIdGen("DECIDF"),
    });

    // A mutable reference standing in for "the admin envelope currently in
    // effect" — flipped mid-flight, between request() and resolve(), to
    // simulate an admin force-deny landing while the human is still looking
    // at the approval prompt.
    let activeDecider = deciderAllow;

    let captured: MintResult | undefined;
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async (input) => {
        const result = await realMintEphemeralGrant(input, {
          store,
          keyStore,
          nowEpochSeconds: NOW,
          generateId: makeIdGen("GRANT2"),
          audit,
        });
        captured = result;
        return result;
      },
      decide: (req) => activeDecider.decide(req),
      audit,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen("APR2"),
    });

    const handle = await orchestrator.request(
      makeApprovalRequest(originalRequest),
    );
    expect(handle.state).toBe("pending");

    // The admin adds a force-deny WHILE the approval is in flight.
    activeDecider = deciderForceDeny;

    await orchestrator.resolve(handle.id, "approved");
    const finalState = await orchestrator.onResolved(handle.id);

    // The human approved — but the envelope still governs (PRD §7).
    expect(finalState).toBe("denied");
    assertDefined(captured, "mintEphemeralGrant was not invoked");

    // The ephemeral grant WAS minted (mint happens before re-evaluation runs)
    // but was never the deciding factor — envelope deny is layer 1, decided
    // before any grant is even considered — so it was never consumed.
    expect(store.isConsumed(captured.jti)).toBe(false);
    expect(store.get(captured.jti).status).toBe("active");

    const events = readAllAuditEvents();
    expect(events.map((e) => e.type)).toEqual([
      "approval_requested",
      "approval_pending",
      "approval_approved",
      "grant_created",
      "decision",
      "approval_denied",
    ]);
    const decisionEvent = events[4];
    expect(decisionEvent).toMatchObject({
      outcome: "deny",
      reason: "envelope_deny",
    });
    const correctiveEvent = events.at(-1);
    expect(correctiveEvent).toMatchObject({
      reason: "envelope_deny",
      grantRefs: [captured.jti],
    });

    expect(audit.verify()).toEqual({ ok: true, events: events.length });

    // Terminal, immutable: a further resolve() throws.
    await expect(orchestrator.resolve(handle.id, "denied")).rejects.toThrow(
      IllegalApprovalTransitionError,
    );
  });

  it("concurrent resolve('approved') twice (real grants): EXACTLY one grant minted + consumed, one approval_approved, one winner (FIX 1)", async () => {
    const originalRequest = makeDecisionRequest();

    const cache = createDecisionCache({ nowEpochSeconds: () => NOW });
    const decider = createDecider({
      cache,
      tierPolicy: CRITICAL_POLICY,
      policyVersion: "v1",
      store,
      audit,
      resolvePublicKey,
      nowEpochSeconds: () => NOW,
      nowMs: () => NOW * 1000,
      generateId: makeIdGen("DECIDL"),
    });

    let mintCount = 0;
    const mintedJtis: string[] = [];
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async (input) => {
        const result = await realMintEphemeralGrant(input, {
          store,
          keyStore,
          nowEpochSeconds: NOW,
          generateId: makeIdGen("GRANTL"),
          audit,
        });
        mintCount += 1;
        mintedJtis.push(result.jti);
        return result;
      },
      decide: (req) => decider.decide(req),
      audit,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen("APRL"),
    });

    const handle = await orchestrator.request(
      makeApprovalRequest(originalRequest),
    );

    // Two concurrent resolve('approved') on the SAME id. Without the
    // synchronous in-flight latch both would pass the `state === "pending"`
    // guard and each mint + consume its own grant and emit its own
    // approval_approved event for one human click.
    const results = await Promise.allSettled([
      orchestrator.resolve(handle.id, "approved"),
      orchestrator.resolve(handle.id, "approved"),
    ]);

    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const rejected = results.filter((r) => r.status === "rejected");
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(
      IllegalApprovalTransitionError,
    );

    // Exactly one grant minted, and it was consumed exactly once.
    expect(mintCount).toBe(1);
    expect(mintedJtis).toHaveLength(1);
    const jti = mintedJtis[0];
    assertDefined(jti, "no grant minted");
    expect(store.isConsumed(jti)).toBe(true);

    const events = readAllAuditEvents();
    expect(events.filter((e) => e.type === "approval_approved")).toHaveLength(
      1,
    );
    expect(events.filter((e) => e.type === "grant_created")).toHaveLength(1);
    expect(events.filter((e) => e.type === "grant_consumed")).toHaveLength(1);
    expect(await orchestrator.onResolved(handle.id)).toBe("approved");
    expect(audit.verify()).toEqual({ ok: true, events: events.length });
  });

  it("mid-flight envelope-deny revokes the orphaned ephemeral grant, closing the replay window (FIX 3)", async () => {
    const originalRequest = makeDecisionRequest();

    const forceDenyEnvelope: AdminEnvelope = {
      scope: "personal",
      denyTools: ["stripe.create_refund"],
    };
    const deciderAllow = createDecider({
      cache: createDecisionCache({ nowEpochSeconds: () => NOW }),
      tierPolicy: CRITICAL_POLICY,
      policyVersion: "v1",
      store,
      audit,
      resolvePublicKey,
      nowEpochSeconds: () => NOW,
      nowMs: () => NOW * 1000,
      generateId: makeIdGen("DEC3A"),
    });
    const deciderForceDeny = createDecider({
      cache: createDecisionCache({ nowEpochSeconds: () => NOW }),
      tierPolicy: CRITICAL_POLICY,
      envelope: forceDenyEnvelope,
      policyVersion: "v1",
      store,
      audit,
      resolvePublicKey,
      nowEpochSeconds: () => NOW,
      nowMs: () => NOW * 1000,
      generateId: makeIdGen("DEC3F"),
    });
    let activeDecider = deciderAllow;

    let captured: MintResult | undefined;
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async (input) => {
        const result = await realMintEphemeralGrant(input, {
          store,
          keyStore,
          nowEpochSeconds: NOW,
          generateId: makeIdGen("GRANT3"),
          audit,
        });
        captured = result;
        return result;
      },
      decide: (req) => activeDecider.decide(req),
      // The real revoke path, wired exactly as E6-T4 will wire it.
      revokeGrant: (jti) => {
        revokeGrants({ jti }, { store, audit });
      },
      audit,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen("APR3"),
    });

    const handle = await orchestrator.request(
      makeApprovalRequest(originalRequest),
    );

    // Admin force-deny lands while the approval is in flight.
    activeDecider = deciderForceDeny;

    await orchestrator.resolve(handle.id, "approved");
    expect(await orchestrator.onResolved(handle.id)).toBe("denied");
    assertDefined(captured, "mintEphemeralGrant was not invoked");

    // FIX 3: the orphaned, single-use, ch-bound grant is REVOKED (not left
    // ACTIVE for its full TTL), and it was never consumed.
    expect(store.get(captured.jti).status).toBe("revoked");
    expect(store.isConsumed(captured.jti)).toBe(false);

    // The replay window is closed: even with the deny lifted (deciderAllow), an
    // EXACT-call decide can no longer authorize off the now-revoked stale grant.
    const replay = await deciderAllow.decide(originalRequest);
    expect(replay.outcome).not.toBe("allow");

    // The grant_revoked line joined the (still-valid) audit chain.
    const events = readAllAuditEvents();
    expect(events.map((e) => e.type)).toContain("grant_revoked");
    expect(audit.verify()).toEqual({ ok: true, events: events.length });
  });
});
