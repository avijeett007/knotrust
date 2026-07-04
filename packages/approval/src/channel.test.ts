/**
 * @knotrust/approval — `ApprovalChannel`/`MultiChannelDispatcher`/
 * `DispatchingApprovalOrchestrator` acceptance (P0-E6-T4; rulings R101,
 * R102, R104, R105).
 *
 * Three tiers:
 *
 *  - `createMultiChannelDispatcher` in isolation, against small fake
 *    `ApprovalChannel` stubs — the "notify-all, filter-by-available,
 *    tolerate-a-failure" contract (R101), fast and deterministic.
 *  - `createDispatchingApprovalOrchestrator` against a REAL lifecycle
 *    orchestrator (`createApprovalOrchestrator`, E6-T1) with fake
 *    `mintEphemeralGrant`/`decide` — the R102 `request → present →
 *    onResolved → map` sequence, plus the R105 cancel-by-`jsonRpcRequestId`
 *    bridge.
 *  - R104's own acceptance, verbatim: register the REAL block-and-wait
 *    channel (E6-T2) alongside a no-op recorder stub — BOTH channels'
 *    `notify` fire with the identical `(ApprovalRequest, ApprovalHandle)`,
 *    block-and-wait still holds and resolves, proving a second channel
 *    drops in without touching the lifecycle.
 */

import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type {
  DecisionRequest,
  DecisionResponse,
  SurfaceMetadata,
} from "@knotrust/core";
import type { AuditEvent, AuditSink } from "@knotrust/store";
import { afterEach, describe, expect, it } from "vitest";
import {
  type ApprovalChannel,
  createDispatchingApprovalOrchestrator,
  createMultiChannelDispatcher,
  type DispatchingApprovalRequestInput,
} from "./channel.js";
import {
  createBlockAndWaitChannel,
  type HeartbeatScheduler,
} from "./channels/block-and-wait.js";
import {
  type ApprovalHandle,
  type ApprovalRequest,
  createApprovalOrchestrator,
} from "./lifecycle.js";

const NOW = 1_800_000_000;
const SURFACE: SurfaceMetadata = { kind: "stdio_proxy", instanceId: "px-1" };

function makeDecisionRequest(
  over: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01CHANNELREQ00000000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_channel1" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 1000 },
    },
    surface: SURFACE,
    ...over,
  };
}

function makeDecisionResponse(
  over: Partial<DecisionResponse> = {},
): DecisionResponse {
  return {
    contractVersion: "1.0",
    requestId: "01CHANNELREQ00000000001",
    decisionId: "01CHANNELDEC00000000001",
    outcome: "pending_approval",
    tier: "critical",
    reasonCode: "no_grant_critical",
    cache: { hit: false },
    evaluatedBy: "L0",
    latencyMs: 0,
    ...over,
  };
}

function fakeAllowResponse(): DecisionResponse {
  return {
    contractVersion: "1.0",
    requestId: "01CHANNELREQ00000000001",
    decisionId: "01CHANNELDEC00000000001",
    outcome: "allow",
    tier: "critical",
    reasonCode: "grant_allow",
    cache: { hit: false },
    evaluatedBy: "grant",
    latencyMs: 0,
  };
}

function makeFakeAuditSink(): { sink: AuditSink; events: AuditEvent[] } {
  const events: AuditEvent[] = [];
  let seq = 0;
  const sink: AuditSink = {
    append(event) {
      seq += 1;
      const full: AuditEvent = {
        seq,
        ts: new Date(NOW * 1000).toISOString(),
        prevHash: "0".repeat(64),
        hash: "0".repeat(64),
        ...event,
      };
      events.push(full);
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

function unreachableMint(): never {
  throw new Error("mintEphemeralGrant must not be called on this path");
}
function unreachableDecide(): never {
  throw new Error("decide must not be called on this path");
}

async function flushMicrotasks(times = 5): Promise<void> {
  for (let i = 0; i < times; i++) {
    await Promise.resolve();
  }
}

const dirsToClean: string[] = [];
afterEach(() => {
  while (dirsToClean.length > 0) {
    const dir = dirsToClean.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});
function makeTempHome(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "knotrust-channel-test-"));
  dirsToClean.push(dir);
  return dir;
}

// ---------------------------------------------------------------------------
// A minimal recording stub `ApprovalChannel` — a P1/P2-style channel that
// merely records the notification it received (no real presentation
// surface). Used both for the isolated dispatcher tests and R104's
// multi-channel proof.
// ---------------------------------------------------------------------------

function createRecordingStubChannel(
  kind: ApprovalChannel["kind"] = "web_push",
  opts: { available?: boolean; failNotify?: boolean } = {},
): ApprovalChannel & {
  notifications: Array<{ req: ApprovalRequest; handle: ApprovalHandle }>;
} {
  const notifications: Array<{
    req: ApprovalRequest;
    handle: ApprovalHandle;
  }> = [];
  return {
    kind,
    notifications,
    available: () => opts.available ?? true,
    async notify(req, handle) {
      if (opts.failNotify) throw new Error("simulated notify failure");
      notifications.push({ req, handle });
    },
  };
}

function makeApprovalHandle(id: string): ApprovalHandle {
  return { id, state: "pending" };
}

function makeApprovalRequest(): ApprovalRequest {
  const decisionRequest = makeDecisionRequest();
  return {
    decisionId: "01CHANNELDEC00000000001",
    requestId: decisionRequest.requestId,
    subject: decisionRequest.subject,
    agent: decisionRequest.context.agent,
    action: decisionRequest.action,
    resource: decisionRequest.resource,
    tier: "critical",
    eligibleChannels: ["block_and_wait", "web_push"],
    decisionRequest,
  };
}

// ---------------------------------------------------------------------------
// createMultiChannelDispatcher — R101's "notify-all, filter-by-available,
// tolerate-a-failure" contract, in isolation.
// ---------------------------------------------------------------------------

describe("createMultiChannelDispatcher (R101)", () => {
  it("invokes notify() on EVERY available channel with the SAME (req, handle) — not just the first", async () => {
    const a = createRecordingStubChannel("block_and_wait");
    const b = createRecordingStubChannel("web_push");
    const dispatcher = createMultiChannelDispatcher([a, b]);
    const req = makeApprovalRequest();
    const handle = makeApprovalHandle("apr_MULTI0001");

    await dispatcher.present(req, SURFACE, handle);

    expect(a.notifications).toEqual([{ req, handle }]);
    expect(b.notifications).toEqual([{ req, handle }]);
  });

  it("filters out a channel whose available() returns false — it is never notified", async () => {
    const available = createRecordingStubChannel("block_and_wait", {
      available: true,
    });
    const unavailable = createRecordingStubChannel("sms", {
      available: false,
    });
    const dispatcher = createMultiChannelDispatcher([available, unavailable]);
    const req = makeApprovalRequest();
    const handle = makeApprovalHandle("apr_MULTI0002");

    await dispatcher.present(req, SURFACE, handle);

    expect(available.notifications).toHaveLength(1);
    expect(unavailable.notifications).toHaveLength(0);
  });

  it("treats a throwing available() as unavailable — logged, never crashes present()", async () => {
    const throwingAvailable: ApprovalChannel = {
      kind: "sms",
      available: () => {
        throw new Error("simulated availability check failure");
      },
      notify: async () => {
        throw new Error("must not be called — available() said no");
      },
    };
    const recorder = createRecordingStubChannel("block_and_wait");
    const logs: string[] = [];
    const dispatcher = createMultiChannelDispatcher(
      [throwingAvailable, recorder],
      { logger: (line) => logs.push(line) },
    );
    const req = makeApprovalRequest();
    const handle = makeApprovalHandle("apr_MULTI0003");

    await expect(
      dispatcher.present(req, SURFACE, handle),
    ).resolves.toBeUndefined();
    expect(recorder.notifications).toHaveLength(1);
    expect(logs.some((l) => l.includes("available() threw"))).toBe(true);
  });

  it("a rejecting notify() on one channel never prevents another channel from being notified, nor rejects present()", async () => {
    const failing = createRecordingStubChannel("web_push", {
      failNotify: true,
    });
    const ok = createRecordingStubChannel("block_and_wait");
    const logs: string[] = [];
    const dispatcher = createMultiChannelDispatcher([failing, ok], {
      logger: (line) => logs.push(line),
    });
    const req = makeApprovalRequest();
    const handle = makeApprovalHandle("apr_MULTI0004");

    await expect(
      dispatcher.present(req, SURFACE, handle),
    ).resolves.toBeUndefined();
    expect(ok.notifications).toHaveLength(1);
    expect(logs.some((l) => l.includes("notify() failed"))).toBe(true);
  });

  it("an empty channel list is a safe no-op", async () => {
    const dispatcher = createMultiChannelDispatcher([]);
    await expect(
      dispatcher.present(
        makeApprovalRequest(),
        SURFACE,
        makeApprovalHandle("apr_MULTI0005"),
      ),
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// createDispatchingApprovalOrchestrator — R102's request → present →
// onResolved → map sequence, plus R105's cancel-by-jsonRpcRequestId bridge.
// ---------------------------------------------------------------------------

describe("createDispatchingApprovalOrchestrator (R102/R105)", () => {
  function setup(opts: { allowApprove?: boolean } = {}) {
    const { sink: audit } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: opts.allowApprove
        ? async () => ({ token: "tok_dispatch", jti: "01DISPATCHGRANT" })
        : unreachableMint,
      decide: opts.allowApprove
        ? async () => fakeAllowResponse()
        : unreachableDecide,
      audit,
      nowEpochSeconds: () => NOW,
      generateId: (() => {
        let n = 0;
        return () => `DISP${String(n++).padStart(4, "0")}`;
      })(),
    });
    return { orchestrator };
  }

  function makeInput(
    jsonRpcRequestId: string | number = 42,
  ): DispatchingApprovalRequestInput {
    return {
      request: makeDecisionRequest(),
      decision: makeDecisionResponse(),
      jsonRpcRequestId,
    };
  }

  it("approve path: request -> present (notifies channels) -> onResolved -> {outcome:'allow'}", async () => {
    const { orchestrator } = setup({ allowApprove: true });
    // A channel that resolves the approval itself as soon as it is notified
    // (standing in for a human clicking "approve" on a presentation
    // surface) — this proves the FULL request->present->onResolved->map
    // sequence deterministically, with no scheduler/timing involved.
    const autoApprove: ApprovalChannel = {
      kind: "block_and_wait",
      available: () => true,
      notify: async (_req, handle) => {
        await orchestrator.resolve(handle.id, "approved");
      },
    };
    const dispatcher = createMultiChannelDispatcher([autoApprove]);
    const adapter = createDispatchingApprovalOrchestrator({
      orchestrator,
      dispatcher,
    });

    const resolution = await adapter.requestApproval(makeInput());
    expect(resolution).toEqual({ outcome: "allow" });
  });

  it("deny path: {outcome:'deny', reasonCode:'approval_denied'}", async () => {
    const { orchestrator } = setup();
    const autoDeny: ApprovalChannel = {
      kind: "block_and_wait",
      available: () => true,
      notify: async (_req, handle) => {
        await orchestrator.resolve(handle.id, "denied");
      },
    };
    const adapter = createDispatchingApprovalOrchestrator({
      orchestrator,
      dispatcher: createMultiChannelDispatcher([autoDeny]),
    });

    const resolution = await adapter.requestApproval(makeInput());
    expect(resolution).toEqual({
      outcome: "deny",
      reasonCode: "approval_denied",
    });
  });

  it("timeout path (no channel ever resolves it): {outcome:'deny', reasonCode:'approval_timeout'}", async () => {
    const { sink: audit } = makeFakeAuditSink();
    let clock = NOW;
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: unreachableMint,
      decide: unreachableDecide,
      audit,
      nowEpochSeconds: () => clock,
      generateId: () => "DISPTIMEOUT",
      defaultTimeoutSeconds: 300,
    });
    const inert: ApprovalChannel = {
      kind: "block_and_wait",
      available: () => true,
      notify: async () => {},
    };
    const adapter = createDispatchingApprovalOrchestrator({
      orchestrator,
      dispatcher: createMultiChannelDispatcher([inert]),
    });

    const resolutionPromise = adapter.requestApproval(makeInput());
    // Nothing but the injected clock + a status() probe ever advances
    // expiry (R86) — simulate a host's periodic sweep.
    clock += 301;
    orchestrator.sweepExpired(clock);

    expect(await resolutionPromise).toEqual({
      outcome: "deny",
      reasonCode: "approval_timeout",
    });
  });

  it("cancel(jsonRpcRequestId): cancels the pending approval created for that id — resolves {outcome:'deny', reasonCode:'approval_cancelled'}", async () => {
    const { orchestrator } = setup();
    const inert: ApprovalChannel = {
      kind: "block_and_wait",
      available: () => true,
      notify: async () => {},
    };
    const adapter = createDispatchingApprovalOrchestrator({
      orchestrator,
      dispatcher: createMultiChannelDispatcher([inert]),
    });

    const resolutionPromise = adapter.requestApproval(makeInput("call-77"));
    await flushMicrotasks();
    await adapter.cancel("call-77");

    expect(await resolutionPromise).toEqual({
      outcome: "deny",
      reasonCode: "approval_cancelled",
    });
  });

  it("cancel() for an unknown jsonRpcRequestId is a safe no-op (never throws)", async () => {
    const { orchestrator } = setup();
    const adapter = createDispatchingApprovalOrchestrator({
      orchestrator,
      dispatcher: createMultiChannelDispatcher([]),
    });
    await expect(adapter.cancel("never-requested")).resolves.toBeUndefined();
  });

  it("cancel() racing an already-resolved approval is a safe no-op (never throws, never overwrites the terminal state)", async () => {
    const { orchestrator } = setup({ allowApprove: true });
    const autoApprove: ApprovalChannel = {
      kind: "block_and_wait",
      available: () => true,
      notify: async (_req, handle) => {
        await orchestrator.resolve(handle.id, "approved");
      },
    };
    const adapter = createDispatchingApprovalOrchestrator({
      orchestrator,
      dispatcher: createMultiChannelDispatcher([autoApprove]),
    });

    const resolution = await adapter.requestApproval(makeInput("call-88"));
    expect(resolution).toEqual({ outcome: "allow" });
    // The approval already settled (and its jsonRpcRequestId mapping was
    // cleaned up) BEFORE this call — still a safe no-op.
    await expect(adapter.cancel("call-88")).resolves.toBeUndefined();
  });

  it("two concurrent approvals never cross-cancel each other (mapping is per-jsonRpcRequestId)", async () => {
    const { sink: audit } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: unreachableMint,
      decide: unreachableDecide,
      audit,
      nowEpochSeconds: () => NOW,
      generateId: (() => {
        let n = 0;
        return () => `DISPCONC${String(n++)}`;
      })(),
    });
    const inert: ApprovalChannel = {
      kind: "block_and_wait",
      available: () => true,
      notify: async () => {},
    };
    const adapter = createDispatchingApprovalOrchestrator({
      orchestrator,
      dispatcher: createMultiChannelDispatcher([inert]),
    });

    const firstPromise = adapter.requestApproval(makeInput("call-A"));
    const secondPromise = adapter.requestApproval(makeInput("call-B"));
    await flushMicrotasks();

    await adapter.cancel("call-A");
    expect(await firstPromise).toEqual({
      outcome: "deny",
      reasonCode: "approval_cancelled",
    });

    // "call-B"'s approval is untouched — still pending. Deny it explicitly
    // to finish the test rather than leaving a dangling promise.
    await adapter.cancel("call-B");
    expect(await secondPromise).toEqual({
      outcome: "deny",
      reasonCode: "approval_cancelled",
    });
  });
});

// ---------------------------------------------------------------------------
// R104 — the multi-channel proof, verbatim: block-and-wait (real) + a
// no-op recorder stub, registered simultaneously — BOTH channels' `notify`
// fire with the SAME ApprovalRequest/handle; the stub records it;
// block-and-wait still holds+resolves.
// ---------------------------------------------------------------------------

describe("R104 — multi-channel proof (block-and-wait + a stub channel, both notified)", () => {
  /** A manually-driven fake scheduler (mirrors block-and-wait.test.ts's own). */
  function makeFakeScheduler(): {
    scheduler: HeartbeatScheduler;
    fireTick: () => void;
  } {
    let tickFn: (() => void) | undefined;
    return {
      scheduler: {
        start(_intervalMs, tick) {
          tickFn = tick;
          return () => {
            tickFn = undefined;
          };
        },
      },
      fireTick: () => tickFn?.(),
    };
  }

  it("registers block-and-wait as the always-available floor + a second stub channel; a critical call notifies BOTH with the identical request/handle; the stub records it; block-and-wait still holds and resolves to allow", async () => {
    const { sink: audit } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async () => ({
        token: "tok_r104",
        jti: "01R104GRANT",
      }),
      decide: async () => fakeAllowResponse(),
      audit,
      nowEpochSeconds: () => NOW,
      generateId: () => "R104ONE",
    });

    const home = makeTempHome();
    const { scheduler, fireTick } = makeFakeScheduler();
    const stderrWrites: string[] = [];
    const blockAndWait = createBlockAndWaitChannel({
      orchestrator,
      sendNotification: () => {},
      nowEpochSeconds: () => NOW,
      scheduler,
      home,
      stderrWrite: (chunk) => stderrWrites.push(chunk),
    });
    const stub = createRecordingStubChannel("web_push");

    const dispatcher = createMultiChannelDispatcher([blockAndWait, stub]);
    const adapter = createDispatchingApprovalOrchestrator({
      orchestrator,
      dispatcher,
    });

    const resolutionPromise = adapter.requestApproval({
      request: makeDecisionRequest(),
      decision: makeDecisionResponse(),
      jsonRpcRequestId: "r104-call-1",
    });
    await flushMicrotasks();

    // BOTH channels were notified with the identical (req, handle) — the
    // ruling's own words: "ALL registered channels' notify is invoked."
    expect(stub.notifications).toHaveLength(1);
    const { req: notifiedReq, handle: notifiedHandle } =
      stub.notifications[0] ?? {};
    expect(notifiedReq?.decisionRequest.action.name).toBe(
      "stripe.create_refund",
    );
    expect(notifiedHandle?.id).toMatch(/^apr_/);

    // block-and-wait genuinely presented (stderr prompt + pending record) —
    // its OWN hold+heartbeat properties are unaffected by a second channel
    // sharing the same notification.
    expect(stderrWrites.join("")).toContain("approval required");
    const pendingDir = path.join(home, "pending");
    const pendingFiles = readdirSync(pendingDir);
    expect(pendingFiles).toHaveLength(1);
    expect((pendingFiles[0] ?? "").replace(/\.json$/, "")).toBe(
      notifiedHandle?.id,
    );

    // Advance one heartbeat — proves block-and-wait's own hold logic is
    // still running in the background, unaffected by the stub sharing the
    // notification.
    fireTick();
    await flushMicrotasks();

    // Resolve via the SAME lifecycle orchestrator both channels share —
    // block-and-wait's background watcher settles the adapter's own await.
    await orchestrator.resolve(notifiedHandle?.id ?? "", "approved");
    expect(await resolutionPromise).toEqual({ outcome: "allow" });

    // The pending record is gone once terminal (block-and-wait's own
    // cleanup still ran, proving its hold logic wasn't disturbed).
    await flushMicrotasks();
    expect(readdirSync(pendingDir)).toEqual([]);
  });
});
