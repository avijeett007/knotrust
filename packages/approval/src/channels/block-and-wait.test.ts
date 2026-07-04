/**
 * @knotrust/approval — block-and-wait terminal channel acceptance (P0-E6-T2;
 * rulings R91–R95; reshaped to the `ApprovalChannel` interface in P0-E6-T4,
 * ruling R101 — `notify(req, handle)` replaces the old monolithic
 * `requestApproval(input)`; see `block-and-wait.ts`'s own module header for
 * the full before/after).
 *
 * These are UNIT-level tests: a REAL `createApprovalOrchestrator` (E6-T1) —
 * with fake `mintEphemeralGrant`/`decide`/`audit` stubs so approval/deny
 * paths are deterministic and fast — plus a FAKE, manually-driven
 * `HeartbeatScheduler` and an injected, mutable epoch-seconds clock shared
 * with the orchestrator. This proves a ≥60s hold with heartbeats WITHOUT any
 * real sleep (R91/R95: "do NOT sleep 60s in tests; advance the clock and
 * assert heartbeats fire"), and lets the timeout path be reached by
 * advancing that same clock, exactly as `lifecycle.test.ts`'s own
 * expiry suite does.
 *
 * Since `request()` now happens OUTSIDE this channel (P0-E6-T4 — see
 * `channel.ts`'s `createDispatchingApprovalOrchestrator`), every test here
 * calls the REAL lifecycle orchestrator's `request()` itself to mint the
 * `(ApprovalRequest, ApprovalHandle)` pair, hands both to
 * `channel.notify(...)`, and separately awaits `orchestrator.onResolved(id)`
 * to observe the terminal outcome — exactly what the real adapter does.
 *
 * The FULL harness-driven acceptance (a real fake-client, a real spawned
 * fake server, the real proxy relay, and `assertNoLeakedSecrets` scanning
 * literal wire frames) lives in
 * `packages/proxy-stdio/src/block-and-wait.integration.test.ts` — this
 * suite exercises the channel's own contract in isolation first.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { DecisionRequest, DecisionResponse } from "@knotrust/core";
import type { AuditEvent, AuditSink } from "@knotrust/store";
import { assertNoLeakedSecrets, type Frame } from "@knotrust/test-harness";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApprovalHandle, ApprovalRequest } from "../lifecycle.js";
import { createApprovalOrchestrator } from "../lifecycle.js";
import {
  type BlockAndWaitProgressNotification,
  createBlockAndWaitChannel,
  DEFAULT_HEARTBEAT_INTERVAL_MS,
  type HeartbeatScheduler,
  presentApprovalToHuman,
} from "./block-and-wait.js";

// ---------------------------------------------------------------------------
// node:fs interception seam (fix round 1, Minor 2) — proves the pending
// record is written temp-file-then-rename, not a direct `writeFileSync` onto
// the final path (which a concurrent `knotrust approvals` (E7) reader could
// observe mid-write, torn/truncated). Mirrors
// `@knotrust/store`'s `grant-store.test.ts` interception pattern: a
// passthrough wrapper around the real `node:fs` that records every
// `writeFileSync`/`renameSync` call so a test can assert on the SEQUENCE of
// calls without faking the actual filesystem.
// ---------------------------------------------------------------------------

const fsSpy = vi.hoisted(() => ({
  writeFileSyncPaths: [] as string[],
  renameSyncCalls: [] as Array<{ from: string; to: string }>,
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    writeFileSync: (...args: unknown[]) => {
      fsSpy.writeFileSyncPaths.push(String(args[0]));
      // biome-ignore lint/suspicious/noExplicitAny: passthrough to the real overload set
      return (actual.writeFileSync as any)(...args);
    },
    renameSync: (...args: unknown[]) => {
      fsSpy.renameSyncCalls.push({
        from: String(args[0]),
        to: String(args[1]),
      });
      // biome-ignore lint/suspicious/noExplicitAny: passthrough to the real overload set
      return (actual.renameSync as any)(...args);
    },
  };
});

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000; // fixed epoch seconds baseline

function makeDecisionRequest(
  over: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01BLOCKANDWAIT00000000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 42_000 },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px-block-and-wait-1",
      server: "stripe",
    },
    ...over,
  };
}

function makeDecisionResponse(
  over: Partial<DecisionResponse> = {},
): DecisionResponse {
  return {
    contractVersion: "1.0",
    requestId: "01BLOCKANDWAIT00000000001",
    decisionId: "01DECISION0000000000000BW",
    outcome: "pending_approval",
    tier: "critical",
    reasonCode: "no_grant_critical",
    cache: { hit: false },
    evaluatedBy: "L0",
    latencyMs: 0,
    ...over,
  };
}

/** Builds the `ApprovalRequest` a real `createDispatchingApprovalOrchestrator` would build from wire-shaped input — duplicated here (this suite is testing the CHANNEL, not the adapter) rather than importing `channel.ts`'s private helper. */
function makeApprovalRequest(
  over: {
    decisionRequest?: DecisionRequest;
    decisionResponse?: DecisionResponse;
    progressToken?: string | number;
  } = {},
): ApprovalRequest {
  const request = over.decisionRequest ?? makeDecisionRequest();
  const decision = over.decisionResponse ?? makeDecisionResponse();
  return {
    decisionId: decision.decisionId,
    requestId: request.requestId,
    subject: request.subject,
    agent: request.context.agent,
    action: request.action,
    resource: request.resource,
    tier: decision.tier === "sensitive" ? "sensitive" : "critical",
    eligibleChannels: ["block_and_wait"],
    decisionRequest: request,
    ...(over.progressToken !== undefined
      ? { progressToken: over.progressToken }
      : {}),
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

/** A manually-driven fake scheduler: `fireTick()` synchronously invokes whatever `tick` the channel most recently started. */
function makeFakeScheduler(): {
  scheduler: HeartbeatScheduler;
  fireTick: () => void;
  stopped: () => boolean;
  lastIntervalMs: () => number | undefined;
} {
  let tickFn: (() => void) | undefined;
  let stopped = true;
  let lastIntervalMs: number | undefined;
  const scheduler: HeartbeatScheduler = {
    start(intervalMs, tick) {
      tickFn = tick;
      stopped = false;
      lastIntervalMs = intervalMs;
      return () => {
        stopped = true;
        tickFn = undefined;
      };
    },
  };
  return {
    scheduler,
    fireTick: () => tickFn?.(),
    stopped: () => stopped,
    lastIntervalMs: () => lastIntervalMs,
  };
}

/** Flushes the microtask queue a few times — the channel's fire-and-forget `sendNotification`/`status()`/background-watcher calls need this to actually land before assertions. */
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
  const dir = mkdtempSync(path.join(tmpdir(), "knotrust-block-and-wait-"));
  dirsToClean.push(dir);
  return dir;
}

// ---------------------------------------------------------------------------
// presentApprovalToHuman — stderr + pending-file side effects, in isolation.
// (Unchanged by P0-E6-T4 — still a standalone export.)
// ---------------------------------------------------------------------------

describe("presentApprovalToHuman (R91a)", () => {
  it("writes a fixed-template stderr prompt with tool, server, tier, code, and the tokened URL — and a pending/<id>.json record carrying the SAME token", () => {
    const home = makeTempHome();
    const writes: string[] = [];
    const decisionRequest = makeDecisionRequest();

    const minted = presentApprovalToHuman(
      {
        decisionId: "01DECISION0000000000000BW",
        requestId: decisionRequest.requestId,
        subject: decisionRequest.subject,
        agent: decisionRequest.context.agent,
        action: decisionRequest.action,
        resource: decisionRequest.resource,
        tier: "critical",
        eligibleChannels: ["block_and_wait"],
        decisionRequest,
      },
      { id: "apr_TESTID0001", state: "pending" },
      {
        home,
        stderrWrite: (chunk) => writes.push(chunk),
        nowEpochSeconds: () => NOW,
      },
    );

    // Token format contract (R92 / the E5-T4 binding contract): tok_ + >=22 base64url chars.
    expect(minted.token).toMatch(/^tok_[A-Za-z0-9_-]{22,}$/);
    expect(minted.code).toMatch(/^[A-Z0-9]{6}$/);
    expect(minted.url).toContain(minted.token);
    expect(minted.url).toContain("apr_TESTID0001");

    const prompt = writes.join("");
    expect(prompt).toContain("stripe.create_refund");
    expect(prompt).toContain("stripe");
    expect(prompt).toContain("critical");
    expect(prompt).toContain(minted.code);
    expect(prompt).toContain(minted.url);

    const recordPath = path.join(home, "pending", "apr_TESTID0001.json");
    const record = JSON.parse(readFileSync(recordPath, "utf8")) as Record<
      string,
      unknown
    >;
    expect(record).toMatchObject({
      approvalId: "apr_TESTID0001",
      tool: "stripe.create_refund",
      server: "stripe",
      tier: "critical",
      subject: "avijeett007@gmail.com",
      agent: "codex-cli",
      token: minted.token,
      url: minted.url,
      code: minted.code,
      createdAtEpochSeconds: NOW,
    });
  });

  it("mints a DIFFERENT token/code on every call (real randomness, no reuse)", () => {
    const home = makeTempHome();
    const decisionRequest = makeDecisionRequest();
    const approvalRequest = {
      decisionId: "01DECISION0000000000000BW",
      requestId: decisionRequest.requestId,
      subject: decisionRequest.subject,
      agent: decisionRequest.context.agent,
      action: decisionRequest.action,
      resource: decisionRequest.resource,
      tier: "critical" as const,
      eligibleChannels: ["block_and_wait" as const],
      decisionRequest,
    };
    const a = presentApprovalToHuman(
      approvalRequest,
      { id: "apr_A", state: "pending" },
      { home, stderrWrite: () => {}, nowEpochSeconds: () => NOW },
    );
    const b = presentApprovalToHuman(
      approvalRequest,
      { id: "apr_B", state: "pending" },
      { home, stderrWrite: () => {}, nowEpochSeconds: () => NOW },
    );
    expect(a.token).not.toBe(b.token);
    expect(a.code).not.toBe(b.code);
  });

  it("sanitizes a hostile tool/server name for the terminal (strips control/escape chars) before printing", () => {
    const home = makeTempHome();
    const writes: string[] = [];
    const decisionRequest = makeDecisionRequest({
      action: { name: "evil\x1b[31mtool\ntwo-line" },
      surface: { kind: "stdio_proxy", instanceId: "px-1", server: "srv\r\nX" },
    });
    presentApprovalToHuman(
      {
        decisionId: "d1",
        requestId: decisionRequest.requestId,
        subject: decisionRequest.subject,
        agent: decisionRequest.context.agent,
        action: decisionRequest.action,
        resource: decisionRequest.resource,
        tier: "critical",
        eligibleChannels: ["block_and_wait"],
        decisionRequest,
      },
      { id: "apr_HOSTILE", state: "pending" },
      {
        home,
        stderrWrite: (chunk) => writes.push(chunk),
        nowEpochSeconds: () => NOW,
      },
    );
    const prompt = writes.join("");
    expect(prompt).not.toContain("\x1b[31m");
    expect(prompt).not.toContain("\r\n");
    // Every line of the prompt is still exactly one line each (no injected newline broke the template).
    expect(
      prompt
        .split("\n")
        .some((line) => line.includes("evil") && line.includes("tool")),
    ).toBe(true);
  });

  it("writes the pending record atomically — temp file + rename, never a direct write onto the final path (fix round 1, Minor 2: no torn-read window for a concurrent `knotrust approvals` reader)", () => {
    fsSpy.writeFileSyncPaths.length = 0;
    fsSpy.renameSyncCalls.length = 0;

    const home = makeTempHome();
    const decisionRequest = makeDecisionRequest();
    presentApprovalToHuman(
      {
        decisionId: "01DECISION0000000000000BW",
        requestId: decisionRequest.requestId,
        subject: decisionRequest.subject,
        agent: decisionRequest.context.agent,
        action: decisionRequest.action,
        resource: decisionRequest.resource,
        tier: "critical",
        eligibleChannels: ["block_and_wait"],
        decisionRequest,
      },
      { id: "apr_ATOMIC0001", state: "pending" },
      { home, stderrWrite: () => {}, nowEpochSeconds: () => NOW },
    );

    const finalPath = path.join(home, "pending", "apr_ATOMIC0001.json");

    // Exactly one writeFileSync, and it targets a TEMP path in the SAME
    // directory as the final record — never the final path directly.
    expect(fsSpy.writeFileSyncPaths).toHaveLength(1);
    const tmpPath = fsSpy.writeFileSyncPaths[0] as string;
    expect(tmpPath).not.toBe(finalPath);
    expect(path.dirname(tmpPath)).toBe(path.dirname(finalPath));
    expect(path.basename(tmpPath)).toMatch(
      /^apr_ATOMIC0001\.json\.[0-9a-f]+\.tmp$/,
    );

    // Exactly one atomic rename, from that same temp path onto the final path.
    expect(fsSpy.renameSyncCalls).toEqual([{ from: tmpPath, to: finalPath }]);

    // The final file holds the complete, valid record — never a partial
    // write a reader could observe mid-write (there is no window where
    // `finalPath` exists with anything other than its complete contents,
    // since it only ever comes into being via the atomic rename above).
    const record = JSON.parse(readFileSync(finalPath, "utf8")) as {
      approvalId: string;
    };
    expect(record.approvalId).toBe("apr_ATOMIC0001");
  });
});

// ---------------------------------------------------------------------------
// createBlockAndWaitChannel — the notify → (background) hold → resolve
// sequence (P0-E6-T4 reshape).
// ---------------------------------------------------------------------------

/** A minimal `allow` `DecisionResponse` for the approve-path fixtures — the orchestrator only ever reads `.outcome`/`.reasonCode` (mirrors `lifecycle.test.ts`'s own `fakeAllowResponse`). */
function fakeAllowResponse(): DecisionResponse {
  return {
    contractVersion: "1.0",
    requestId: "01BLOCKANDWAIT00000000001",
    decisionId: "01DECISION0000000000000BW",
    outcome: "allow",
    tier: "critical",
    reasonCode: "grant_allow",
    cache: { hit: false },
    evaluatedBy: "grant",
    latencyMs: 0,
  };
}

describe("createBlockAndWaitChannel — the ApprovalChannel contract (kind/available/notify, R91–R95/R101)", () => {
  function setup(
    opts: {
      defaultTimeoutSeconds?: number;
      /** Default `unreachableMint`/`unreachableDecide` (proves mint/decide are NEVER called on deny/cancel/timeout paths, per R89). Pass real-ish resolving fakes for a test that approves. */
      allowApprove?: boolean;
    } = {},
  ) {
    let clock = NOW;
    const { sink: audit, events } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: opts.allowApprove
        ? async () => ({ token: "tok_grantfixture", jti: "01GRANTFIXTURE" })
        : unreachableMint,
      decide: opts.allowApprove
        ? async () => fakeAllowResponse()
        : unreachableDecide,
      audit,
      nowEpochSeconds: () => clock,
      generateId: (() => {
        let n = 0;
        return () => `BW${String(n++).padStart(4, "0")}`;
      })(),
      ...(opts.defaultTimeoutSeconds !== undefined
        ? { defaultTimeoutSeconds: opts.defaultTimeoutSeconds }
        : {}),
    });

    const home = makeTempHome();
    const { scheduler, fireTick, stopped, lastIntervalMs } =
      makeFakeScheduler();
    const sent: BlockAndWaitProgressNotification[] = [];
    const stderrWrites: string[] = [];

    const channel = createBlockAndWaitChannel({
      orchestrator,
      sendNotification: (message) => {
        sent.push(message);
      },
      nowEpochSeconds: () => clock,
      scheduler,
      home,
      stderrWrite: (chunk) => stderrWrites.push(chunk),
    });

    /** Drives the full `request()` → `notify()` sequence a real adapter runs, returning the handle plus `onResolved()`'s own promise. */
    async function present(
      over: {
        decisionRequest?: DecisionRequest;
        decisionResponse?: DecisionResponse;
        progressToken?: string | number;
      } = {},
    ): Promise<{
      handle: ApprovalHandle;
      req: ApprovalRequest;
      resolvedPromise: ReturnType<typeof orchestrator.onResolved>;
    }> {
      const req = makeApprovalRequest(over);
      const handle = await orchestrator.request(req);
      const resolvedPromise = orchestrator.onResolved(handle.id);
      await channel.notify(req, handle);
      return { handle, req, resolvedPromise };
    }

    return {
      channel,
      orchestrator,
      events,
      present,
      advanceClock: (deltaSeconds: number) => {
        clock += deltaSeconds;
      },
      fireTick,
      stopped,
      lastIntervalMs,
      sent,
      stderrWrites,
      home,
    };
  }

  it("kind is 'block_and_wait' and available() is unconditionally true (the always-available floor, architecture §6.2)", () => {
    const h = setup();
    expect(h.channel.kind).toBe("block_and_wait");
    expect(
      h.channel.available(makeApprovalRequest(), {
        kind: "stdio_proxy",
        instanceId: "px-1",
      }),
    ).toBe(true);
  });

  it("holds ≥60s with heartbeats observed via an injected clock/scheduler (no real sleep), then approving flows to a terminal 'approved' state", async () => {
    const h = setup({ allowApprove: true });
    const { resolvedPromise } = await h.present({ progressToken: "tok-1" });
    await flushMicrotasks();

    // 7 ticks * 10s = 70s >= 60s — all synchronous, zero real wall-clock wait.
    for (let i = 0; i < 7; i++) {
      h.advanceClock(10);
      h.fireTick();
      await flushMicrotasks();
    }

    expect(h.sent.length).toBe(7);
    for (const notification of h.sent) {
      expect(notification).toMatchObject({
        jsonrpc: "2.0",
        method: "notifications/progress",
        params: { progressToken: "tok-1" },
      });
      expect(notification.params.progress).toBeGreaterThan(0);
    }
    // Strictly increasing progress across heartbeats.
    const progressValues = h.sent.map((n) => n.params.progress);
    expect(progressValues).toEqual([...progressValues].sort((a, b) => a - b));
    expect(new Set(progressValues).size).toBe(progressValues.length);

    // Still pending — nothing has resolved it yet.
    let settled = false;
    void resolvedPromise.then(() => {
      settled = true;
    });
    await flushMicrotasks();
    expect(settled).toBe(false);

    // Approve — standing in for the real page POST calling resolve().
    const pendingDir = path.join(h.home, "pending");
    const [file] = readdirSync(pendingDir);
    expect(file).toBeDefined();
    const approvalId = (file ?? "").replace(/\.json$/, "");

    await h.orchestrator.resolve(approvalId, "approved");
    expect(await resolvedPromise).toBe("approved");

    // The background watcher has stopped the scheduler and removed the
    // pending record (may take one more microtask turn to observe).
    await flushMicrotasks();
    expect(h.stopped()).toBe(true);
    expect(readdirSync(pendingDir)).toEqual([]);
  });

  it("denying settles onResolved() to 'denied'", async () => {
    const h = setup();
    const { resolvedPromise } = await h.present();
    await flushMicrotasks();
    const pendingDir = path.join(h.home, "pending");
    const [file] = readdirSync(pendingDir);
    const approvalId = (file ?? "").replace(/\.json$/, "");

    await h.orchestrator.resolve(approvalId, "denied");
    expect(await resolvedPromise).toBe("denied");
  });

  it("cancelling settles onResolved() to 'cancelled'", async () => {
    const h = setup();
    const { resolvedPromise } = await h.present();
    await flushMicrotasks();
    const pendingDir = path.join(h.home, "pending");
    const [file] = readdirSync(pendingDir);
    const approvalId = (file ?? "").replace(/\.json$/, "");

    await h.orchestrator.cancel(approvalId);
    expect(await resolvedPromise).toBe("cancelled");
  });

  it("letting it time out (no human ever resolves it) settles onResolved() to 'expired' — driven purely by advancing the injected clock + periodic ticks, even with NO progressToken", async () => {
    const h = setup({ defaultTimeoutSeconds: 300 });
    // No progressToken this time — the doc-comment's "no heartbeat, but the
    // internal expiry probe still runs" path.
    const { resolvedPromise } = await h.present();

    // Advance well past the 300s default timeout, 10s per tick.
    for (let i = 0; i < 31; i++) {
      h.advanceClock(10);
      h.fireTick();
      await flushMicrotasks();
    }

    expect(h.sent).toEqual([]); // no progressToken ⇒ no notification ever sent.
    expect(await resolvedPromise).toBe("expired");
    await flushMicrotasks();
    expect(h.stopped()).toBe(true);
  });

  it("a sendNotification that throws/rejects never aborts the hold (best-effort heartbeat delivery)", async () => {
    let clock = NOW;
    const { sink: audit } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async () => ({
        token: "tok_grantfixture2",
        jti: "01GRANTFIXTURE2",
      }),
      decide: async () => fakeAllowResponse(),
      audit,
      nowEpochSeconds: () => clock,
      generateId: (() => {
        let n = 0;
        return () => `THROW${String(n++)}`;
      })(),
    });
    const home = makeTempHome();
    const { scheduler, fireTick } = makeFakeScheduler();
    const channel = createBlockAndWaitChannel({
      orchestrator,
      sendNotification: () => {
        throw new Error("simulated transport failure");
      },
      nowEpochSeconds: () => clock,
      scheduler,
      home,
      stderrWrite: () => {},
    });

    const req = makeApprovalRequest({ progressToken: "tok-x" });
    const handle = await orchestrator.request(req);
    const resolvedPromise = orchestrator.onResolved(handle.id);
    await channel.notify(req, handle);
    await flushMicrotasks();
    clock += 10;
    fireTick();
    await flushMicrotasks();

    const pendingDir = path.join(home, "pending");
    const [file] = readdirSync(pendingDir);
    const approvalId = (file ?? "").replace(/\.json$/, "");
    await orchestrator.resolve(approvalId, "approved");
    expect(await resolvedPromise).toBe("approved");
  });

  it("uses the default 10s heartbeat interval unless overridden", async () => {
    expect(DEFAULT_HEARTBEAT_INTERVAL_MS).toBe(10_000);
    const h = setup();
    const { resolvedPromise } = await h.present({ progressToken: "tok-y" });
    await flushMicrotasks();
    expect(h.lastIntervalMs()).toBe(DEFAULT_HEARTBEAT_INTERVAL_MS);

    // Tidy up: resolve it so the test doesn't leave a dangling promise.
    const pendingDir = path.join(h.home, "pending");
    const [file] = readdirSync(pendingDir);
    const approvalId = (file ?? "").replace(/\.json$/, "");
    await h.orchestrator.resolve(approvalId, "denied");
    await resolvedPromise;
  });

  it("reads req.progressToken straight off the ApprovalRequest object (P0-E6-T4 — no separate wire-input type)", async () => {
    const h = setup();
    const req = makeApprovalRequest({ progressToken: 777 });
    const handle = await h.orchestrator.request(req);
    await h.channel.notify(req, handle);
    await flushMicrotasks();
    h.advanceClock(10);
    h.fireTick();
    await flushMicrotasks();

    expect(h.sent).toHaveLength(1);
    expect(h.sent[0]?.params.progressToken).toBe(777);

    const pendingDir = path.join(h.home, "pending");
    const [file] = readdirSync(pendingDir);
    const approvalId = (file ?? "").replace(/\.json$/, "");
    await h.orchestrator.resolve(approvalId, "denied");
  });
});

// ---------------------------------------------------------------------------
// R92/R93 — the security-heart properties, proven with the harness's OWN
// frame-scan primitive against synthetic "frames" built from exactly what
// this module hands `sendNotification` — the SAME assertion the full
// harness integration test runs against real wire traffic. (Terminal
// resolution is no longer THIS module's own return value as of P0-E6-T4 —
// the adapter's `toResolution` mapping is scanned in `channel.test.ts`
// instead — so this suite scans only the heartbeat stream, plus proves the
// pending file is the ONLY place the token appears.)
// ---------------------------------------------------------------------------

describe("R92/R93 — no token leak in the heartbeat stream", () => {
  it("assertNoLeakedSecrets finds nothing in the heartbeat notifications, even though the pending-file record (a DIFFERENT, human-only channel) DOES carry the token", async () => {
    let clock = NOW;
    const { sink: audit } = makeFakeAuditSink();
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async () => ({
        token: "tok_grantfixture3",
        jti: "01GRANTFIXTURE3",
      }),
      decide: async () => fakeAllowResponse(),
      audit,
      nowEpochSeconds: () => clock,
      generateId: () => "LEAKSCAN0001",
    });
    const home = makeTempHome();
    const { scheduler, fireTick } = makeFakeScheduler();
    const sent: BlockAndWaitProgressNotification[] = [];
    const channel = createBlockAndWaitChannel({
      orchestrator,
      sendNotification: (message) => {
        sent.push(message);
      },
      nowEpochSeconds: () => clock,
      scheduler,
      home,
      stderrWrite: () => {},
    });

    const req = makeApprovalRequest({ progressToken: "tok-scan" });
    const handle = await orchestrator.request(req);
    const resolvedPromise = orchestrator.onResolved(handle.id);
    await channel.notify(req, handle);
    await flushMicrotasks();
    for (let i = 0; i < 3; i++) {
      clock += 10;
      fireTick();
      await flushMicrotasks();
    }

    const pendingDir = path.join(home, "pending");
    const [file] = readdirSync(pendingDir);
    const approvalId = (file ?? "").replace(/\.json$/, "");
    const pendingRecordText = readFileSync(
      path.join(pendingDir, file ?? ""),
      "utf8",
    );

    await orchestrator.resolve(approvalId, "approved");
    expect(await resolvedPromise).toBe("approved");

    // Model-visible "frames": every heartbeat notification — exactly what
    // the wire would carry from this channel (the terminal resolution
    // itself is the ADAPTER's concern, scanned in channel.test.ts).
    const modelVisibleFrames: Frame[] = sent.map((message, i) => ({
      seq: i,
      direction: "recv",
      atMs: i,
      message,
    }));

    expect(() => assertNoLeakedSecrets(modelVisibleFrames)).not.toThrow();
    // No frame ever carries a literal `pending_approval` outcome (R93).
    for (const frame of modelVisibleFrames) {
      expect(JSON.stringify(frame.message)).not.toContain("pending_approval");
    }

    // Contrast: the token DOES exist — but only in the pending-record file
    // (a human channel), proving the scan's cleanliness above isn't just
    // "there was no token to find."
    expect(pendingRecordText).toMatch(/"token":\s*"tok_[A-Za-z0-9_-]{22,}"/);
  });
});
