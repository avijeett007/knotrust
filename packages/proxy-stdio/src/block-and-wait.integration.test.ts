/**
 * @knotrust/proxy-stdio — block-and-wait channel wired into the REAL
 * enforcement path, end to end (P0-E6-T2; rulings R91–R95; the plan's own
 * acceptance bar; wiring reshaped in P0-E6-T4, R102, to route through
 * `@knotrust/approval`'s `createDispatchingApprovalOrchestrator` +
 * `createMultiChannelDispatcher` rather than handing the channel directly to
 * `createEnforcer` — see that module's own header for the full sequence).
 *
 * This is the harness-driven acceptance the task brief names verbatim: a
 * fake client (with a real `progressToken`) drives a `critical` tool call
 * through the REAL relay (`createStdioProxy`) → the REAL enforcer
 * (`createEnforcer`) → the REAL unified decider (`@knotrust/grants`
 * `createDecider`, over a real decision cache + grant store + hash-chained
 * audit log + Ed25519 file keystore) → the REAL `@knotrust/approval`
 * lifecycle orchestrator + dispatching adapter, driven by the REAL
 * `createBlockAndWaitChannel` (P0-E6-T2's own deliverable, now registered as
 * the dispatcher's one floor channel, P0-E6-T4) — against a REAL spawned
 * fake MCP server child process. Only the channel's heartbeat/expiry-probe
 * SCHEDULER and its shared epoch-seconds CLOCK are fakes (injected, manually
 * advanced) — exactly what R91/R95 ask for: prove a ≥60s hold with real
 * heartbeats without ever actually sleeping 60 real seconds.
 *
 * Acceptance, by name (this file's `it()` titles below map 1:1 to the
 * plan's bullets):
 *  - critical held ≥60s w/ heartbeats via injected clock;
 *  - approve → the REAL child's result flows back on the original id;
 *  - timeout → deny with reasonCode approval_timeout (proven via the real
 *    audit log's `approval_expired`/`approval_timeout` event, since the
 *    model-visible wire envelope only ever carries the SAFE R75 code);
 *  - deny path likewise;
 *  - frame-scan (`assertNoLeakedSecrets`) finds zero leaks across every
 *    frame emitted during the ENTIRE hold (heartbeats + final result);
 *  - no frame — during or after the hold — carries `outcome:
 *    "pending_approval"` (R93: this channel never produces it);
 *  - `pending/<id>.json` carries the token; no model-visible frame does;
 *  - other traffic (a routine call) flows normally while the critical call
 *    is held (the R70 async-relay property, still true with the real
 *    channel wired in place of the E5-T3 placeholder).
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  createApprovalOrchestrator,
  createBlockAndWaitChannel,
  createDispatchingApprovalOrchestrator,
  createMultiChannelDispatcher,
  type HeartbeatScheduler,
  type ApprovalOrchestrator as LifecycleOrchestrator,
} from "@knotrust/approval";
import type { TierPolicy } from "@knotrust/core";
import { createDecisionCache, createUlidGenerator } from "@knotrust/core";
import {
  createDecider,
  createDiskPublicKeyResolver,
  createKeyStore,
  decodeGrantIndexEntry,
  mintEphemeralGrant,
  revokeGrants,
} from "@knotrust/grants";
import {
  type AuditEvent,
  createAuditLog,
  createGrantStore,
} from "@knotrust/store";
import {
  assertNoLeakedSecrets,
  FakeClient,
  type FakeServerConfig,
  type FakeToolDef,
  parseCallLogFromStderr,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";
import { createEnforcer } from "./enforce.js";
import { createStdioProxy, type StdioProxy } from "./proxy.js";

const SERVER = "srv";

const POLICY: TierPolicy = {
  tools: {
    routine_tool: { tier: "routine", source: "pack" },
    critical_tool: { tier: "critical", source: "pack" },
  },
  unknownToolTier: "sensitive",
};

function tool(name: string): FakeToolDef {
  return { name, inputSchema: { type: "object", properties: {} } };
}

const CONFIG: FakeServerConfig = {
  serverInfo: { name: "knotrust-fake-block-and-wait", version: "1.0.0" },
  tools: [tool("routine_tool"), tool("critical_tool")],
};

async function waitUntil(
  predicate: () => boolean,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) {
    if (performance.now() > deadline) return predicate();
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
  return true;
}

/** A manually-driven fake scheduler — `fireTick()` synchronously invokes whatever `tick` the channel most recently started (R91: "expose a tick()"). */
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

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) await Promise.resolve(fn()).catch(() => {});
  }
});

interface Harness {
  client: FakeClient;
  clientTransport: Transport;
  proxy: StdioProxy;
  orchestrator: LifecycleOrchestrator;
  advanceClock: (deltaSeconds: number) => void;
  fireTick: () => void;
  home: string;
  pendingDir: string;
  readApprovalEvents: () => AuditEvent[];
  getStderr: () => string;
}

async function setupBlockAndWait(
  opts: { defaultTimeoutSeconds?: number } = {},
): Promise<Harness> {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-baw-int-"));
  const priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;

  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  let clock = 1_800_000_000;
  const audit = createAuditLog({ home, nowEpochMs: () => clock * 1000 });
  const cache = createDecisionCache({ nowEpochSeconds: () => clock });
  const keyStore = await createKeyStore({ backend: "file" });
  await keyStore.ensureIdentity();
  const resolvePublicKey = createDiskPublicKeyResolver(home);
  const idGen = createUlidGenerator(() => clock * 1000);

  const decider = createDecider({
    cache,
    tierPolicy: POLICY,
    policyVersion: "pv1",
    store,
    audit,
    resolvePublicKey,
    nowEpochSeconds: () => clock,
    nowMs: () => clock * 1000,
    generateId: idGen,
  });

  const orchestrator = createApprovalOrchestrator({
    // `mintEphemeralGrant`'s own deps take `nowEpochSeconds` as a SNAPSHOT
    // NUMBER (`@knotrust/grants`' `MintGrantDeps`/`LifecycleMintDeps` shape),
    // unlike this orchestrator's OWN `nowEpochSeconds` (a function) — read
    // the shared mutable `clock` fresh on every call via this closure.
    mintEphemeralGrant: (input) =>
      mintEphemeralGrant(input, {
        store,
        keyStore,
        nowEpochSeconds: clock,
        generateId: idGen,
        audit,
      }),
    decide: (request) => decider.decide(request),
    revokeGrant: (jti) => {
      revokeGrants(
        { jti },
        { store, audit, onInvalidate: () => cache.bumpGrantSetVersion() },
      );
    },
    audit,
    nowEpochSeconds: () => clock,
    generateId: idGen,
    ...(opts.defaultTimeoutSeconds !== undefined
      ? { defaultTimeoutSeconds: opts.defaultTimeoutSeconds }
      : {}),
  });

  const { scheduler, fireTick } = makeFakeScheduler();

  // Chicken/egg: the channel needs to reach the PROXY's client-facing send
  // to emit heartbeats, but the proxy is only constructed once `enforce` (in
  // turn built from the channel) already exists. A mutable box (bound right
  // after the proxy is constructed, below) breaks the cycle cleanly.
  let proxyRef: StdioProxy | undefined;
  const channel = createBlockAndWaitChannel({
    orchestrator,
    sendNotification: (message) =>
      proxyRef?.sendToClient(message as never) ?? Promise.resolve(),
    nowEpochSeconds: () => clock,
    scheduler,
    home,
    stderrWrite: () => {}, // keep the test's own stderr clean; presence is unit-tested in @knotrust/approval
  });

  // P0-E6-T4 (R102): the enforcer's `orchestrator` seam is now satisfied by
  // `createDispatchingApprovalOrchestrator`, which runs `request → present →
  // onResolved → map` over a `createMultiChannelDispatcher` registering
  // block-and-wait as its one floor channel — replacing the old direct
  // `orchestrator: channel` wiring one-for-one.
  const dispatcher = createMultiChannelDispatcher([channel]);
  const approvalAdapter = createDispatchingApprovalOrchestrator({
    orchestrator,
    dispatcher,
  });

  const enforcer = createEnforcer({
    decider,
    requestContext: {
      identity: { subjectType: "user", subjectId: "avijeett007@gmail.com" },
      agent: { id: "codex-cli" },
      surface: { instanceId: "px-baw-int", server: SERVER },
      nowMs: () => clock * 1000,
      generateId: idGen,
    },
    orchestrator: approvalAdapter,
  });

  const started = await startFakeServer(CONFIG, { prepareChildCommand: true });
  const childCommand = started.childCommand;
  if (childCommand === undefined) throw new Error("no childCommand");

  const clientToProxy = new PassThrough();
  const proxyToClient = new PassThrough();
  const stderrSink = new PassThrough();
  let stderrText = "";
  stderrSink.on("data", (chunk: Buffer) => {
    stderrText += chunk.toString("utf8");
  });

  const proxy = createStdioProxy({
    serverCommand: childCommand,
    stdin: clientToProxy,
    stdout: proxyToClient,
    stderr: stderrSink,
    enforce: (message) => enforcer.handle(message),
  });
  proxyRef = proxy;
  await proxy.start();

  const clientTransport = new StdioServerTransport(
    proxyToClient,
    clientToProxy,
  );
  const client = new FakeClient(clientTransport);

  cleanups.push(async () => {
    await proxy.stop().catch(() => {});
    await client.close().catch(() => {});
    await started.close().catch(() => {});
    try {
      audit.close();
    } catch {
      /* release the writer lock */
    }
    if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
    else process.env.KNOTRUST_HOME = priorHome;
    rmSync(home, { recursive: true, force: true });
  });

  return {
    client,
    clientTransport,
    proxy,
    orchestrator,
    advanceClock: (deltaSeconds) => {
      clock += deltaSeconds;
    },
    fireTick,
    home,
    pendingDir: path.join(home, "pending"),
    getStderr: () => stderrText,
    readApprovalEvents: () => {
      audit.flush();
      const dir = path.join(home, "audit");
      const events: AuditEvent[] = [];
      for (const f of readdirSync(dir)
        .filter((n) => /^\d{6}\.jsonl$/.test(n))
        .sort()) {
        for (const line of readFileSync(path.join(dir, f), "utf8").split(
          "\n",
        )) {
          if (line.length > 0) events.push(JSON.parse(line) as AuditEvent);
        }
      }
      return events.filter((e) => e.type.startsWith("approval_"));
    },
  };
}

function knotrustMeta(result: CallToolResult): Record<string, unknown> {
  const sc = (
    result as { structuredContent?: { knotrust?: Record<string, unknown> } }
  ).structuredContent;
  return sc?.knotrust ?? {};
}

function readOnePendingRecord(pendingDir: string): {
  approvalId: string;
  token: string;
  raw: string;
} {
  const [file] = readdirSync(pendingDir);
  if (file === undefined) throw new Error("no pending record found");
  const raw = readFileSync(path.join(pendingDir, file), "utf8");
  const parsed = JSON.parse(raw) as { approvalId: string; token: string };
  return { approvalId: parsed.approvalId, token: parsed.token, raw };
}

describe("P0-E6-T2 — block-and-wait wired into the real enforcement path (replaces the E5-T3 placeholder)", () => {
  it("critical tool held ≥60s with real notifications/progress heartbeats (injected clock/scheduler, zero real sleep); approving releases the call and the REAL child result flows back on the original id; frame-scan finds zero leaks; no frame ever carries pending_approval", async () => {
    const h = await setupBlockAndWait();
    await h.client.connect();

    const progressSeen: Array<{ progress: number; total?: number }> = [];
    const criticalPromise = h.client.callTool(
      "critical_tool",
      { amount: 9000 },
      {
        progressToken: "prog-critical-1",
        onProgress: (p) => progressSeen.push(p),
      },
    );

    // The hold has genuinely started: a pending-record file exists (R91a).
    await waitUntil(() => {
      try {
        return readdirSync(h.pendingDir).length > 0;
      } catch {
        return false;
      }
    }, 5_000);
    const pending = readOnePendingRecord(h.pendingDir);
    expect(pending.token).toMatch(/^tok_[A-Za-z0-9_-]{22,}$/);

    // 7 heartbeats * 10s = 70s >= 60s of virtual hold time — via the
    // injected clock/scheduler, never a real sleep.
    for (let i = 0; i < 7; i++) {
      h.advanceClock(10);
      h.fireTick();
      await waitUntil(() => progressSeen.length >= i + 1, 3_000);
    }
    expect(progressSeen.length).toBe(7);
    for (const p of progressSeen) expect(p.progress).toBeGreaterThan(0);

    // While still held, the REAL child must NOT have received the call yet.
    expect(
      parseCallLogFromStderr(h.getStderr()).some(
        (e) => e.toolName === "critical_tool",
      ),
    ).toBe(false);

    // Approve — standing in for E6-T3's future localhost-page POST calling
    // the SAME lifecycle orchestrator's resolve().
    await h.orchestrator.resolve(pending.approvalId, "approved");

    const result = await criticalPromise;
    expect(result.isError).toBeFalsy();
    // The REAL child answered (an echo), not a synthesized envelope.
    expect(result.content).toEqual([
      { type: "text", text: JSON.stringify({ amount: 9000 }) },
    ]);

    // The REAL child's callLog now shows it — the call was actually
    // forwarded post-approval, not synthesized.
    await waitUntil(
      () =>
        parseCallLogFromStderr(h.getStderr()).some(
          (e) => e.toolName === "critical_tool",
        ),
      3_000,
    );

    // The pending record is gone once terminal.
    expect(readdirSync(h.pendingDir)).toEqual([]);

    // R92/R93 — the security heart: scan EVERY frame the fake client ever
    // received during the ENTIRE hold (every heartbeat + the final result)
    // for a leaked token/policy-internal, and confirm none carries a
    // literal pending_approval outcome.
    assertNoLeakedSecrets(h.client.frames);
    for (const frame of h.client.frames) {
      if (frame.direction !== "recv") continue;
      const text = JSON.stringify(frame.message);
      expect(text).not.toContain(pending.token);
      expect(text).not.toContain('"pending_approval"');
    }
  }, 40_000);

  it("denying via the orchestrator yields a deny envelope on the original id (never a fabricated allow, never pending_approval)", async () => {
    const h = await setupBlockAndWait();
    await h.client.connect();

    const criticalPromise = h.client.callTool("critical_tool", { amount: 1 });
    await waitUntil(() => {
      try {
        return readdirSync(h.pendingDir).length > 0;
      } catch {
        return false;
      }
    }, 5_000);
    const pending = readOnePendingRecord(h.pendingDir);

    await h.orchestrator.resolve(pending.approvalId, "denied");
    const result = await criticalPromise;
    expect(result.isError).toBe(true);
    expect(knotrustMeta(result)).toMatchObject({ outcome: "deny" });
    expect(knotrustMeta(result).outcome).not.toBe("pending_approval");
    assertNoLeakedSecrets(h.client.frames);
  }, 40_000);

  it("letting it time out (no human ever resolves it) yields a deny — proven by the real audit log's approval_expired/approval_timeout event — driven purely by advancing the injected clock, never a real 300s wait", async () => {
    const h = await setupBlockAndWait({ defaultTimeoutSeconds: 300 });
    await h.client.connect();

    const criticalPromise = h.client.callTool("critical_tool", { amount: 1 });
    await waitUntil(() => {
      try {
        return readdirSync(h.pendingDir).length > 0;
      } catch {
        return false;
      }
    }, 5_000);

    // Advance well past the 300s default timeout — 31 ticks * 10s = 310s.
    for (let i = 0; i < 31; i++) {
      h.advanceClock(10);
      h.fireTick();
    }

    const result = await criticalPromise;
    expect(result.isError).toBe(true);
    expect(knotrustMeta(result)).toMatchObject({ outcome: "deny" });

    const approvalEvents = h.readApprovalEvents();
    const expired = approvalEvents.find((e) => e.type === "approval_expired");
    expect(expired).toBeDefined();
    expect(expired?.reason).toBe("approval_timeout");

    assertNoLeakedSecrets(h.client.frames);
  }, 40_000);

  it("other traffic (a routine call) flows normally while the critical call is HELD — the async-relay property holds with the real channel wired in", async () => {
    const h = await setupBlockAndWait();
    await h.client.connect();

    const criticalPromise = h.client.callTool("critical_tool", {});
    await waitUntil(() => {
      try {
        return readdirSync(h.pendingDir).length > 0;
      } catch {
        return false;
      }
    }, 5_000);

    // Routine traffic fired WHILE the critical call is still held.
    const routine = await h.client.callTool("routine_tool", { fast: true });
    expect(routine.content).toEqual([
      { type: "text", text: JSON.stringify({ fast: true }) },
    ]);

    // The routine response arrived before the (still-pending) critical one.
    const responseIds = h.client.frames
      .filter(
        (f) =>
          f.direction === "recv" &&
          "id" in (f.message as object) &&
          !("method" in (f.message as object)),
      )
      .map((f) => (f.message as { id: unknown }).id);
    // FakeClient assigns ids sequentially: initialize=0, critical=1, routine=2.
    expect(responseIds).toContain(2);
    expect(responseIds).not.toContain(1); // critical's response has not arrived yet.

    // Clean up: deny the still-held critical call so the test doesn't hang.
    const pending = readOnePendingRecord(h.pendingDir);
    await h.orchestrator.resolve(pending.approvalId, "denied");
    await criticalPromise;
  }, 40_000);
});
