/**
 * @knotrust/proxy-stdio — enforcement END-TO-END acceptance (P0-E5-T3).
 *
 * The plan's fake-server integration acceptance, plus the R70 async-relay
 * ordering proof — driven through the REAL pieces, no mocks:
 *
 *   real spawned fake MCP server (child process, its own callLog sideband)
 *     ← proxy (async enforcement relay, R70)
 *     ← the UNIFIED decider (`@knotrust/grants` `createDecider`) over a REAL
 *       decision cache + REAL grant store + REAL hash-chained audit log + REAL
 *       Ed25519 file keystore/disk resolver.
 *
 * Acceptance (by name):
 *  - routine tool → forwarded + result relayed;
 *  - sensitive tool WITHOUT a grant → denied WITHOUT the child ever receiving
 *    it (asserted on the child's callLog);
 *  - sensitive tool WITH a valid grant → forwarded;
 *  - critical tool → reaches the approval orchestrator (stub invoked);
 *  - every case → EXACTLY one decision audit event;
 *  - malformed `tools/call` → protocol-error passthrough, no crash.
 *  - R70: a HELD (slow-orchestrator) enforced call does not block a later
 *    routine call's response.
 *
 * P0-E5-T5 (rulings R81/R84) adds the fail-closed/fail-open crash & error
 * battery at the bottom of this file — a REAL spawned child + REAL
 * hash-chained audit log (`audit.verify()` proves the chain), but a
 * deliberately-THROWING stub `Decider` (exactly R81's own prescribed test
 * technique: "inject a throw into the evaluator — a decider/precedence stub
 * that throws"), so the internal-error/fail-open paths are exercised
 * reliably without needing to corrupt the real `@knotrust/grants` decider's
 * internals.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import type { TierPolicy } from "@knotrust/core";
import { createDecisionCache, createUlidGenerator } from "@knotrust/core";
import {
  createDecider,
  createDiskPublicKeyResolver,
  createKeyStore,
  decodeGrantIndexEntry,
  mintDurableGrant,
} from "@knotrust/grants";
import {
  type AuditEvent,
  createAuditLog,
  createGrantStore,
} from "@knotrust/store";
import {
  FakeClient,
  type FakeServerConfig,
  type FakeToolDef,
  parseCallLogFromStderr,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type ApprovalOrchestrator,
  type ApprovalResolution,
  createEnforcer,
  type Decider,
} from "./enforce.js";
import { createStdioProxy } from "./proxy.js";

const NOW = 1_800_000_000;
const SERVER = "srv";

const POLICY: TierPolicy = {
  tools: {
    routine_tool: { tier: "routine", source: "pack" },
    blocked_tool: { tier: "sensitive", source: "pack" },
    granted_tool: { tier: "sensitive", source: "pack" },
    critical_tool: { tier: "critical", source: "pack" },
  },
  unknownToolTier: "sensitive",
};

function tool(name: string): FakeToolDef {
  return { name, inputSchema: { type: "object", properties: {} } };
}

const CONFIG: FakeServerConfig = {
  serverInfo: { name: "knotrust-fake-enforce", version: "1.0.0" },
  tools: [
    tool("routine_tool"),
    tool("blocked_tool"),
    tool("granted_tool"),
    tool("critical_tool"),
  ],
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
  getStderr: () => string;
  readDecisionEvents: () => AuditEvent[];
  orchestratorSpy: ReturnType<typeof vi.fn>;
}

async function setupEnforced(
  opts: {
    mintGrant?: boolean;
    approvalDelayMs?: number;
    approvalResolution?: ApprovalResolution;
  } = {},
): Promise<Harness> {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-enforce-int-"));
  const priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;

  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const audit = createAuditLog({ home, nowEpochMs: () => NOW * 1000 });
  const cache = createDecisionCache({ nowEpochSeconds: () => NOW });
  const keyStore = await createKeyStore({ backend: "file" });
  await keyStore.ensureIdentity();
  const resolvePublicKey = createDiskPublicKeyResolver(home);
  const idGen = createUlidGenerator(() => NOW * 1000);

  if (opts.mintGrant) {
    await mintDurableGrant(
      {
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "granted_tool",
        scope: { resourceType: SERVER, idPattern: "granted_tool" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      { store, keyStore, nowEpochSeconds: NOW, generateId: idGen, audit },
    );
  }

  const decider = createDecider({
    cache,
    tierPolicy: POLICY,
    policyVersion: "pv1",
    store,
    audit,
    resolvePublicKey,
    nowEpochSeconds: () => NOW,
    nowMs: () => NOW * 1000,
    generateId: idGen,
  });

  const orchestratorSpy = vi.fn(async (): Promise<ApprovalResolution> => {
    if (opts.approvalDelayMs !== undefined) {
      await new Promise((r) => setTimeout(r, opts.approvalDelayMs));
    }
    return opts.approvalResolution ?? { outcome: "pending" };
  });
  const orchestrator: ApprovalOrchestrator = {
    requestApproval: orchestratorSpy,
  };

  const enforcer = createEnforcer({
    decider,
    requestContext: {
      identity: { subjectType: "user", subjectId: "avijeett007@gmail.com" },
      agent: { id: "codex-cli" },
      surface: { instanceId: "px-int", server: SERVER },
      nowMs: () => NOW * 1000,
      generateId: idGen,
    },
    orchestrator,
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
    getStderr: () => stderrText,
    readDecisionEvents: () => {
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
      return events.filter((e) => e.type === "decision");
    },
    orchestratorSpy,
  };
}

function knotrustMeta(result: CallToolResult): Record<string, unknown> {
  const sc = (
    result as { structuredContent?: { knotrust?: Record<string, unknown> } }
  ).structuredContent;
  return sc?.knotrust ?? {};
}

describe("P0-E5-T3 — tools/call enforcement end-to-end (fake server + real decider)", () => {
  it("routine forwards+relays; sensitive-no-grant denies WITHOUT child receipt; sensitive-with-grant forwards; critical reaches the orchestrator; one decision event each; malformed passes through", async () => {
    const h = await setupEnforced({ mintGrant: true });
    await h.client.connect();

    // routine → forwarded, echoed back.
    const routine = await h.client.callTool("routine_tool", { ping: "pong" });
    expect(routine.isError).toBeFalsy();
    expect(routine.content).toEqual([
      { type: "text", text: JSON.stringify({ ping: "pong" }) },
    ]);

    // sensitive, no grant → deny; the child NEVER receives it. reasonCode is
    // the R75 SAFE code (P0-E5-T4) — never the internal "no_grant_sensitive".
    const blocked = await h.client.callTool("blocked_tool", { x: 1 });
    expect(blocked.isError).toBe(true);
    expect(knotrustMeta(blocked)).toMatchObject({
      outcome: "deny",
      reasonCode: "blocked_needs_grant",
      retryable: false,
    });

    // sensitive, WITH grant → forwarded, echoed back.
    const granted = await h.client.callTool("granted_tool", { y: 2 });
    expect(granted.isError).toBeFalsy();
    expect(granted.content).toEqual([
      { type: "text", text: JSON.stringify({ y: 2 }) },
    ]);

    // critical → pending_approval → orchestrator invoked, resolves "pending"
    // (non-terminal, the default stub) → the honest cannot-hold envelope
    // (P0-E5-T4, architecture §3.1/§I1): outcome stays "pending_approval",
    // never a fabricated "deny".
    const critical = await h.client.callTool("critical_tool", { z: 3 });
    expect(h.orchestratorSpy).toHaveBeenCalledTimes(1);
    expect(critical.isError).toBe(true);
    expect(knotrustMeta(critical)).toMatchObject({
      outcome: "pending_approval",
      reasonCode: "blocked_needs_approval",
    });

    // malformed tools/call (no params.name) → passthrough → child protocol
    // error, no crash. Sent raw over the same transport.
    await h.clientTransport.send({
      jsonrpc: "2.0",
      id: "malformed-1",
      method: "tools/call",
      params: {},
    } as never);
    await waitUntil(
      () =>
        h.client.frames.some(
          (f) =>
            f.direction === "recv" &&
            (f.message as { id?: unknown }).id === "malformed-1",
        ),
      3000,
    );
    const malformedFrame = h.client.frames.find(
      (f) =>
        f.direction === "recv" &&
        (f.message as { id?: unknown }).id === "malformed-1",
    );
    expect(malformedFrame).toBeDefined();
    // The child answered it (a protocol error) — passthrough worked, no crash.
    expect(
      (malformedFrame?.message as { error?: unknown }).error,
    ).toBeDefined();

    // The relay is still fully functional after the malformed message.
    const afterMalformed = await h.client.callTool("routine_tool", {
      again: true,
    });
    expect(afterMalformed.content).toEqual([
      { type: "text", text: JSON.stringify({ again: true }) },
    ]);

    // The child's callLog: it received ONLY the allowed calls, never the
    // denied/critical ones.
    await waitUntil(
      () => parseCallLogFromStderr(h.getStderr()).length >= 3,
      3000,
    );
    const received = parseCallLogFromStderr(h.getStderr()).map(
      (e) => e.toolName,
    );
    expect(received).toContain("routine_tool");
    expect(received).toContain("granted_tool");
    expect(received).not.toContain("blocked_tool");
    expect(received).not.toContain("critical_tool");

    // EXACTLY one decision audit event per decided call (malformed → no
    // decision; it never reached the decider).
    const decisions = h.readDecisionEvents();
    const byTool = new Map<string, number>();
    for (const e of decisions)
      byTool.set(e.tool, (byTool.get(e.tool) ?? 0) + 1);
    expect(byTool.get("routine_tool")).toBe(2); // called twice (before + after malformed)
    expect(byTool.get("blocked_tool")).toBe(1);
    expect(byTool.get("granted_tool")).toBe(1);
    expect(byTool.get("critical_tool")).toBe(1);
    // No decision event was minted for the malformed call.
    expect(decisions.every((e) => e.tool !== "")).toBe(true);
  }, 40_000);

  it("R70 ordering: a HELD (slow-orchestrator) critical call does not block a later routine call's response", async () => {
    const h = await setupEnforced({ approvalDelayMs: 200 });
    await h.client.connect();

    // Fire the critical call (held ~200ms by the slow orchestrator), then a
    // routine call right behind it — WITHOUT awaiting the critical first.
    const criticalPromise = h.client.callTool("critical_tool", {});
    const routinePromise = h.client.callTool("routine_tool", { fast: true });
    const [critical, routine] = await Promise.all([
      criticalPromise,
      routinePromise,
    ]);

    // The routine call completed (its echo), the critical resolved to the deny.
    expect(routine.content).toEqual([
      { type: "text", text: JSON.stringify({ fast: true }) },
    ]);
    expect(critical.isError).toBe(true);

    // And on the wire the routine RESPONSE arrived BEFORE the critical one —
    // the held critical call did not block later traffic (per-request async).
    const responseIds = h.client.frames
      .filter(
        (f) =>
          f.direction === "recv" &&
          "id" in (f.message as object) &&
          !("method" in (f.message as object)),
      )
      .map((f) => (f.message as { id: unknown }).id);
    // FakeClient assigns ids sequentially: initialize=0, critical=1, routine=2.
    // The routine (id 2) response arrived BEFORE the held critical (id 1) one.
    expect(responseIds.indexOf(2)).toBeLessThan(responseIds.indexOf(1));
  }, 40_000);
});

// ---------------------------------------------------------------------------
// P0-E5-T5 — R81/R84: fail-closed internal errors + the narrow fail-open
// recovery, against a REAL spawned fake-server child + REAL hash-chained
// audit log (`audit.verify()` proves the chain is intact end to end), with a
// deliberately-THROWING stub `Decider` — R81's own prescribed test technique.
// ---------------------------------------------------------------------------

describe("P0-E5-T5 — R81 internal_error deny (real audit chain) + R84 fail-open recovery (real spawned child)", () => {
  function throwingDecider(message: string): Decider {
    return {
      decide: async () => {
        throw new Error(message);
      },
    };
  }

  interface FailOpenSetup {
    client: FakeClient;
    getStderr: () => string;
    readAllAuditEvents: () => AuditEvent[];
    verifyChain: () => { ok: boolean };
  }

  async function setupFailOpenScenario(
    opts: {
      failOpenRoutine?: boolean;
      /** When set, the audit sink throws for exactly this event `type` — models a broken audit sink for ONE event kind, real for everything else. */
      brokenAuditEventType?: string;
    } = {},
  ): Promise<FailOpenSetup> {
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-failopen-int-"));
    const priorHome = process.env.KNOTRUST_HOME;
    process.env.KNOTRUST_HOME = home;

    const realAudit = createAuditLog({ home, nowEpochMs: () => NOW * 1000 });
    const audit = {
      append: (
        event: Parameters<typeof realAudit.append>[0],
        appendOpts?: Parameters<typeof realAudit.append>[1],
      ) => {
        if (
          opts.brokenAuditEventType !== undefined &&
          event.type === opts.brokenAuditEventType
        ) {
          throw new Error(`simulated broken audit sink for "${event.type}"`);
        }
        return realAudit.append(event, appendOpts);
      },
    };

    const idGen = createUlidGenerator(() => NOW * 1000);
    const enforcer = createEnforcer({
      decider: throwingDecider("evaluator exploded"),
      requestContext: {
        identity: { subjectType: "user", subjectId: "avijeett007@gmail.com" },
        agent: { id: "codex-cli" },
        surface: { instanceId: "px-failopen", server: SERVER },
        nowMs: () => NOW * 1000,
        generateId: idGen,
      },
      audit,
      failOpen: {
        ...(opts.failOpenRoutine !== undefined
          ? { routine: opts.failOpenRoutine }
          : {}),
        tierPolicy: POLICY,
      },
    });

    const started = await startFakeServer(CONFIG, {
      prepareChildCommand: true,
    });
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
        realAudit.close();
      } catch {
        /* release the writer lock */
      }
      if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = priorHome;
      rmSync(home, { recursive: true, force: true });
    });

    return {
      client,
      getStderr: () => stderrText,
      readAllAuditEvents: () => {
        realAudit.flush();
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
        return events;
      },
      verifyChain: () => realAudit.verify(),
    };
  }

  it("R84: routine tool + failOpen.routine:true + evaluator throw → ALLOWED — the REAL child actually receives the call, exactly one fail_open_fired event, and the real hash chain verifies", async () => {
    const h = await setupFailOpenScenario({ failOpenRoutine: true });
    await h.client.connect();

    const result = await h.client.callTool("routine_tool", { ping: "pong" });
    expect(result.isError).toBeFalsy();
    // Forwarded to the REAL child — echoed back, not synthesized.
    expect(result.content).toEqual([
      { type: "text", text: JSON.stringify({ ping: "pong" }) },
    ]);

    await waitUntil(
      () => parseCallLogFromStderr(h.getStderr()).length >= 1,
      3_000,
    );
    const received = parseCallLogFromStderr(h.getStderr()).map(
      (e) => e.toolName,
    );
    expect(received).toContain("routine_tool");

    const events = h.readAllAuditEvents();
    const failOpenEvents = events.filter((e) => e.type === "fail_open_fired");
    expect(failOpenEvents).toHaveLength(1);
    expect(failOpenEvents[0]).toMatchObject({
      tool: "routine_tool",
      agent: "codex-cli",
    });
    expect(JSON.parse(failOpenEvents[0]?.reason ?? "{}")).toMatchObject({
      tier: "routine",
    });
    // No internal_error decision-deny event ALSO minted — this was an allow.
    expect(
      events.filter((e) => e.type === "decision" && e.outcome === "deny"),
    ).toHaveLength(0);

    const verify = h.verifyChain();
    expect(verify.ok).toBe(true);
  }, 40_000);

  it("R84: sensitive tool NEVER fails open regardless of config — evaluator throw still denies internal_error, and the real child never receives the call", async () => {
    const h = await setupFailOpenScenario({ failOpenRoutine: true });
    await h.client.connect();

    const result = await h.client.callTool("blocked_tool", { x: 1 });
    expect(result.isError).toBe(true);

    // Give the (non-)delivery a moment, then confirm the child's REAL
    // callLog never saw it — the strongest proof a sensitive tool cannot
    // fail open no matter what `failOpen.routine` says.
    await new Promise((resolve) => setTimeout(resolve, 300));
    const received = parseCallLogFromStderr(h.getStderr()).map(
      (e) => e.toolName,
    );
    expect(received).not.toContain("blocked_tool");

    const events = h.readAllAuditEvents();
    expect(events.filter((e) => e.type === "fail_open_fired")).toHaveLength(0);
    expect(
      events.filter(
        (e) =>
          e.type === "decision" &&
          e.outcome === "deny" &&
          e.reason === "internal_error",
      ),
    ).toHaveLength(1);
    expect(h.verifyChain().ok).toBe(true);
  }, 40_000);

  it("R84: routine tool eligible for fail-open, but the fail_open_fired audit append itself fails → DENIES (audit-of-fail-open is mandatory) — the real child never receives the call", async () => {
    const h = await setupFailOpenScenario({
      failOpenRoutine: true,
      brokenAuditEventType: "fail_open_fired",
    });
    await h.client.connect();

    const result = await h.client.callTool("routine_tool", { ping: "pong" });
    expect(result.isError).toBe(true);

    await new Promise((resolve) => setTimeout(resolve, 300));
    const received = parseCallLogFromStderr(h.getStderr()).map(
      (e) => e.toolName,
    );
    expect(received).not.toContain("routine_tool");

    // The broken sink means fail_open_fired never actually lands — but the
    // deny itself is STILL best-effort audited as an internal_error decision
    // event (the broken sink only throws for "fail_open_fired", not
    // "decision" — realistic partial failure).
    const events = h.readAllAuditEvents();
    expect(events.filter((e) => e.type === "fail_open_fired")).toHaveLength(0);
    expect(
      events.filter(
        (e) =>
          e.type === "decision" &&
          e.outcome === "deny" &&
          e.reason === "internal_error",
      ),
    ).toHaveLength(1);
    expect(h.verifyChain().ok).toBe(true);
  }, 40_000);
});
