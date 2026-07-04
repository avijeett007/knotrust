/**
 * P0-E11-T5 — the approval-page CSRF & DNS-rebinding adversarial battery.
 *
 * The load-bearing test for threat-model **T1.1e (Loopback auto-approve)**
 * (`docs/02-architecture/security-threat-model.md` §3 "T1", narrative 1e):
 * "The agent (or a malicious web page open in the human's browser, via
 * DNS-rebinding/CSRF) issues an HTTP POST to the localhost approval endpoint
 * to approve its own call" — and its mitigation in §4.3 ("Approval requires
 * an authenticated human on a separate channel"), the brief's ratified
 * requirement **§I2.2**: "unguessable single-use tokens delivered to the
 * human only, never in model-visible content; loopback bind, Origin/Host
 * validation, CSRF protection, POST-only mutations."
 *
 * P0-E6-T3's own suite (`packages/approval/src/channels/local-page/
 * server.test.ts`) already proves every one of these properties at the
 * UNIT level, against a FAKE orchestrator, driven directly at the server. And
 * P0-E11-T2's `self-approval.test.ts` attack (c) already proves a REDUCED
 * three-forge version of this against the real stack (explicitly noting
 * "Full CSRF/rebind/wrong-Origin web battery is E11-T5"). THIS suite is
 * that promised, durable, CI-wired adversarial suite: it composes the REAL
 * end-to-end stack — spawned fake MCP server child ← real `createStdioProxy`
 * relay ← real `createEnforcer` → real unified `createDecider` → real
 * `createDispatchingApprovalOrchestrator` → real `createMultiChannelDispatcher`
 * → real `createBlockAndWaitChannel` driving the real `createApprovalOrchestrator`
 * lifecycle state machine, plus the REAL localhost `createApprovalPageServer`
 * — and mounts five named attacks against a REAL pending approval on the
 * REAL running loopback page, each proven to fail CLOSED, leave the approval
 * UNCHANGED, mint NO grant, and get AUDITED `approval_channel_violation`.
 *
 * The five attacks (R143):
 *
 *   (a) **model-driven approval attempt** — the fake client, playing the
 *       agent, harvests EVERYTHING model-visible during a pending hold
 *       (denial envelopes, progress heartbeats, tool results) and attempts
 *       to construct/POST an approval from that material. This is the CORE
 *       §I2.2 property: the global frame-scan (P0-E5-T4's own
 *       `assertNoLeakedSecrets`, the real function, not a bespoke
 *       substring check) finds ZERO tokens across every model-visible
 *       frame — the agent has nothing to forge with — and a POST built
 *       from whatever it harvested (nothing) is rejected regardless.
 *   (b) **CSRF** — a page on ANOTHER local origin auto-submits a POST
 *       carrying the approval's REAL token (worst case: assume the
 *       attacker somehow has it) but a cross-site/missing `Origin` and/or
 *       a missing CSRF nonce → rejected 403, audited `bad_origin`/`bad_csrf`.
 *   (c) **DNS-rebinding** — a request on the SAME loopback socket carries an
 *       attacker-controlled `Host` header → rejected 403, audited `bad_host`.
 *   (d) **GET-mutation** — a GET to the one mutating route
 *       (`/approve/action`), for every action value (`approve`,
 *       `always_allow`, `deny`) → 405, mutates NOTHING.
 *   (e) **token/approvalId mismatch** — a valid URL token for approval A
 *       replayed against approval B's id (and vice versa) → rejected,
 *       audited; plus the single-use replay-after-terminal case → 410.
 *
 * R144: every rejection above is audited `approval_channel_violation` with
 * the reason ONLY, never the token value; the global frame-scan runs over
 * every model-visible frame this suite captures; `audit.verify()` stays
 * green throughout.
 *
 * R145 (R136 applies): TEST-AUTHORING only, no product-code change. Every
 * attack here is expected to PASS by the already-built system failing
 * closed. If any attack ever SUCCEEDED (an approval resolved / a grant
 * minted via a forged/cross-origin/rebind/GET request, or a token appeared
 * in a model-visible frame), that is a Critical product bug to escalate
 * BLOCKED with the exact code path — never a test to weaken.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  type ApprovalPageServer,
  createApprovalOrchestrator,
  createApprovalPageServer,
  createBlockAndWaitChannel,
  createDispatchingApprovalOrchestrator,
  createMultiChannelDispatcher,
  generateApprovalCode,
  generateApprovalToken,
  type HeartbeatScheduler,
  type ApprovalOrchestrator as LifecycleOrchestrator,
  withApprovalRequestRegistry,
} from "@knotrust/approval";
import type { TierPolicy } from "@knotrust/core";
import { createDecisionCache, createUlidGenerator } from "@knotrust/core";
import {
  createDecider,
  createDiskPublicKeyResolver,
  createKeyStore,
  decodeGrantIndexEntry,
  type KeyStore,
  mintDurableGrant,
  mintEphemeralGrant,
  revokeGrants,
} from "@knotrust/grants";
import {
  createEnforcer,
  createStdioProxy,
  type StdioProxy,
} from "@knotrust/proxy-stdio";
import {
  type AuditEvent,
  type ChainVerifyResult,
  createAuditLog,
  createGrantStore,
  type GrantStore,
} from "@knotrust/store";
import {
  APPROVAL_TOKEN_PREFIXED_PATTERN,
  assertNoLeakedSecrets,
  FakeClient,
  type FakeServerConfig,
  type FakeToolDef,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";

const SERVER = "srv";
const SUBJECT_ID = "avijeett007@gmail.com";
const AGENT_ID = "codex-cli";
const INITIAL_CLOCK = 1_800_000_000;

/**
 * One shared tier policy: two independent `critical` tools (so attack (e)
 * can hold TWO concurrent approvals distinguishable by tool name alone,
 * with no reliance on ULID/filesystem ordering), a `routine` tool (a
 * legitimate tool RESULT to harvest in attack (a)), and a `sensitive` tool
 * with no grant (a genuine DENIAL ENVELOPE to harvest in attack (a)).
 */
const POLICY: TierPolicy = {
  tools: {
    critical_tool_a: { tier: "critical", source: "pack" },
    critical_tool_b: { tier: "critical", source: "pack" },
    routine_tool: { tier: "routine", source: "pack" },
    blocked_tool: { tier: "sensitive", source: "pack" },
  },
  unknownToolTier: "sensitive",
};

function tool(name: string): FakeToolDef {
  return { name, inputSchema: { type: "object", properties: {} } };
}

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

/**
 * A manually-driven fake heartbeat/expiry scheduler — `fireTick()` runs
 * EVERY still-registered `tick`, not just the most recent one. Attack (e)
 * holds TWO concurrent approvals, each with its OWN `block-and-wait`
 * `notify()` call registering its own tick via `scheduler.start(...)`; a
 * scheduler that tracked only a single `tickFn` (as P0-E11-T2's own
 * `self-approval.test.ts` helper does — sufficient there because that suite
 * never holds more than one approval at once) would silently starve every
 * hold but the last-registered one. A `Set` keyed by disposal keeps every
 * concurrent hold's heartbeat/expiry-probe alive across the whole test.
 */
function makeFakeScheduler(): {
  scheduler: HeartbeatScheduler;
  fireTick: () => void;
} {
  const ticks = new Set<() => void>();
  return {
    scheduler: {
      start(_intervalMs, tick) {
        ticks.add(tick);
        return () => {
          ticks.delete(tick);
        };
      },
    },
    fireTick: () => {
      for (const tick of ticks) tick();
    },
  };
}

function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

interface PendingRecord {
  approvalId: string;
  token: string;
  tool: string;
}

/** Reads every `$KNOTRUST_HOME/pending/*.json` record and returns the one whose `tool` field matches — lets attack (e) hold TWO concurrent approvals and address each unambiguously by which tool it's for, with no dependency on filename/ULID ordering. */
function readPendingRecordFor(
  pendingDir: string,
  toolName: string,
): PendingRecord {
  for (const file of readdirSync(pendingDir)) {
    const parsed = JSON.parse(
      readFileSync(path.join(pendingDir, file), "utf8"),
    ) as PendingRecord;
    if (parsed.tool === toolName) return parsed;
  }
  throw new Error(`no pending record found for tool "${toolName}"`);
}

function readAllAuditEvents(home: string): AuditEvent[] {
  const dir = path.join(home, "audit");
  const events: AuditEvent[] = [];
  for (const f of safeReaddir(dir)
    .filter((n) => /^\d{6}\.jsonl$/.test(n))
    .sort()) {
    for (const line of readFileSync(path.join(dir, f), "utf8").split("\n")) {
      if (line.length > 0) events.push(JSON.parse(line) as AuditEvent);
    }
  }
  return events;
}

function knotrustMeta(result: CallToolResult): Record<string, unknown> {
  const sc = (
    result as { structuredContent?: { knotrust?: Record<string, unknown> } }
  ).structuredContent;
  return sc?.knotrust ?? {};
}

interface RawResponse {
  status: number;
  body: string;
}

/**
 * A raw HTTP request to the localhost approval page — deliberately NOT
 * `fetch()`: the Fetch spec forbids a caller from setting `Host`/`Origin` at
 * all (the "forbidden header names" list), which is exactly what the
 * DNS-rebinding and CSRF/Origin batteries below need to control.
 * `node:http`'s `request()` has no such restriction (mirrors E6-T3's own
 * `server.test.ts` and P0-E11-T2's `self-approval.test.ts`).
 */
function rawRequest(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: options.port,
        method: options.method,
        path: options.path,
        ...(options.headers !== undefined ? { headers: options.headers } : {}),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => {
          body += chunk.toString("utf8");
        });
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, body });
        });
      },
    );
    req.on("error", reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

function extractCsrf(html: string): string {
  const m = /name="csrf" value="([^"]*)"/.exec(html);
  if (m?.[1] === undefined)
    throw new Error("csrf token not found in rendered page");
  return m[1];
}

interface ResolveCall {
  id: string;
  outcome: "approved" | "denied";
  channel?: string;
}

interface Stack {
  client: FakeClient;
  clientTransport: Transport;
  proxy: StdioProxy;
  orchestrator: LifecycleOrchestrator;
  pageServer: ApprovalPageServer;
  store: GrantStore;
  keyStore: KeyStore;
  resolveCalls: ResolveCall[];
  advanceClock: (deltaSeconds: number) => void;
  currentClock: () => number;
  fireTick: () => void;
  home: string;
  pendingDir: string;
  readAuditEvents: () => AuditEvent[];
  verifyAudit: () => ChainVerifyResult;
}

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) await Promise.resolve(fn()).catch(() => {});
  }
});

/**
 * Builds the FULL real enforcement + approval stack against a spawned fake
 * MCP server — the exact composition `packages/cli`'s `enforcement.ts` wires
 * in production, minus the CLI process around it. Mirrors P0-E11-T2's
 * `self-approval.test.ts` `setupStack` verbatim in shape (same substrate,
 * same rationale for every dependency).
 */
async function setupStack(
  config: FakeServerConfig,
  opts: { defaultTimeoutSeconds?: number } = {},
): Promise<Stack> {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-adv-page-"));
  const priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;

  let clock = INITIAL_CLOCK;
  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
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

  const resolveCalls: ResolveCall[] = [];
  const baseLifecycle = createApprovalOrchestrator({
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
  const lifecycle: LifecycleOrchestrator = {
    ...baseLifecycle,
    resolve: (id, r, channel) => {
      resolveCalls.push({
        id,
        outcome: r,
        ...(channel !== undefined ? { channel } : {}),
      });
      return baseLifecycle.resolve(id, r, channel);
    },
  };
  const registry = withApprovalRequestRegistry(lifecycle);

  const pageServer = createApprovalPageServer({
    orchestrator: registry.orchestrator,
    getApprovalRequest: registry.getApprovalRequest,
    mintDurableGrant: (input) =>
      mintDurableGrant(input, {
        store,
        keyStore,
        nowEpochSeconds: clock,
        generateId: idGen,
        audit,
      }),
    audit,
    nowEpochSeconds: () => clock,
  });
  await pageServer.start();

  const { scheduler, fireTick } = makeFakeScheduler();

  let proxyRef: StdioProxy | undefined;
  const channel = createBlockAndWaitChannel({
    orchestrator: registry.orchestrator,
    sendNotification: (message) =>
      proxyRef?.sendToClient(message as never) ?? Promise.resolve(),
    nowEpochSeconds: () => clock,
    scheduler,
    home,
    stderrWrite: () => {},
    // The presented URL points at THIS real page, registering the real
    // single-use token with the page (human channel only — never
    // model-visible; see attack (a)'s frame-scan below).
    mintApproval: (approvalId) => {
      const token = generateApprovalToken();
      const code = generateApprovalCode();
      const url = pageServer.url(approvalId, token);
      return { token, url, code };
    },
  });

  const dispatcher = createMultiChannelDispatcher([channel]);
  const approvalAdapter = createDispatchingApprovalOrchestrator({
    orchestrator: registry.orchestrator,
    dispatcher,
  });

  const enforcer = createEnforcer({
    decider,
    requestContext: {
      identity: { subjectType: "user", subjectId: SUBJECT_ID },
      agent: { id: AGENT_ID },
      surface: { instanceId: "px-adv-page", server: SERVER },
      nowMs: () => clock * 1000,
      generateId: idGen,
    },
    audit,
    orchestrator: approvalAdapter,
  });

  const started = await startFakeServer(config, { prepareChildCommand: true });
  const childCommand = started.childCommand;
  if (childCommand === undefined) throw new Error("no childCommand");

  const clientToProxy = new PassThrough();
  const proxyToClient = new PassThrough();
  const stderrSink = new PassThrough();
  stderrSink.on("data", () => {
    // Discarded — this suite does not inspect stderr call logs.
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
    await pageServer.stop().catch(() => {});
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
    orchestrator: registry.orchestrator,
    pageServer,
    store,
    keyStore,
    resolveCalls,
    advanceClock: (deltaSeconds) => {
      clock += deltaSeconds;
    },
    currentClock: () => clock,
    fireTick,
    home,
    pendingDir: path.join(home, "pending"),
    readAuditEvents: () => {
      audit.flush();
      return readAllAuditEvents(home);
    },
    verifyAudit: () => audit.verify(),
  };
}

// ===========================================================================
// (a) The model-driven approval attempt — the core §I2.2 property.
// ===========================================================================

describe("(a) the model cannot construct a valid approval POST from anything model-visible — the core §I2.2 property (T1.1e)", () => {
  it("harvests every model-visible frame during a pending hold (a genuine denial envelope, a real progress heartbeat, a legitimate tool result) — the E5-T4 frame-scan finds ZERO tokens across all of it, and a POST built from whatever was harvested is rejected without touching the approval", async () => {
    const stack = await setupStack(
      {
        serverInfo: { name: "knotrust-adv-page-a", version: "1.0.0" },
        tools: [
          tool("critical_tool_a"),
          tool("routine_tool"),
          tool("blocked_tool"),
        ],
      },
      { defaultTimeoutSeconds: 60 },
    );
    await stack.client.connect();

    // A REAL critical call, held by the REAL block-and-wait channel.
    const criticalPromise = stack.client.callTool(
      "critical_tool_a",
      { amount: 500 },
      { progressToken: "prog-harvest" },
    );
    await waitUntil(() => safeReaddir(stack.pendingDir).length > 0, 5_000);

    // One heartbeat tick — a real `notifications/progress` frame to harvest.
    stack.advanceClock(10);
    stack.fireTick();
    await waitUntil(
      () =>
        stack.client.receivedNotificationsOf("notifications/progress").length >
        0,
      3_000,
    );

    // The agent drives OTHER traffic while the critical call is held: a
    // legitimate tool RESULT, and a genuine DENIAL ENVELOPE (blocked_tool —
    // sensitive tier, no grant, denied by policy before it ever reaches the
    // child) — exactly the "denial envelopes, progress frames, tool
    // results" the brief names as harvestable material.
    const routineResult = await stack.client.callTool("routine_tool", {
      ok: true,
    });
    expect(routineResult.isError).toBeFalsy();
    const deniedResult = await stack.client.callTool("blocked_tool", {});
    expect(deniedResult.isError).toBe(true);
    expect(knotrustMeta(deniedResult)).toMatchObject({ outcome: "deny" });

    const pending = readPendingRecordFor(stack.pendingDir, "critical_tool_a");

    // PROPERTY 1 — the global reusable substrate (P0-E5-T4), not a bespoke
    // check: zero leaks across EVERY frame this suite captured.
    assertNoLeakedSecrets(stack.client.frames);

    // Belt-and-suspenders: explicitly confirm the two most specific
    // secrets — the real token and the real (internal) approval id — never
    // appear in ANY received frame, and actually attempt to HARVEST a
    // token-shaped string using the exact pattern the scanner itself uses.
    const allRecvText = stack.client.frames
      .filter((f) => f.direction === "recv")
      .map((f) => JSON.stringify(f.message))
      .join("\n");
    expect(allRecvText).not.toContain(pending.token);
    expect(allRecvText).not.toContain(pending.approvalId);
    APPROVAL_TOKEN_PREFIXED_PATTERN.lastIndex = 0;
    const harvestedTokens =
      allRecvText.match(APPROVAL_TOKEN_PREFIXED_PATTERN) ?? [];
    expect(harvestedTokens).toEqual([]);

    // PROPERTY 2: even granting the attacker the BEST case — it somehow
    // knows WHICH approval id to target (read here via the test harness's
    // OWN filesystem introspection, never from a model-visible frame) — a
    // POST built from whatever it harvested (nothing) is rejected. Two
    // "best-effort forgeries" from the harvested material: a plausible
    // `tok_`-shaped guess (the only thing "constructing a token" from
    // public knowledge of the format contract could produce, since nothing
    // was actually harvestable), and the literal empty case (no token
    // field at all).
    const port = stack.pageServer.port;
    const origin = `http://127.0.0.1:${port}`;
    const harvestedOrGuessed = harvestedTokens[0] ?? `tok_${"A".repeat(32)}`;

    const attemptWithGuess = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: origin,
      },
      body: new URLSearchParams({
        id: pending.approvalId,
        token: harvestedOrGuessed,
        csrf: "whatever-the-agent-could-guess",
        action: "approve",
      }).toString(),
    });
    expect(attemptWithGuess.status).toBe(404);

    const attemptEmpty = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: origin,
      },
      body: new URLSearchParams({
        id: pending.approvalId,
        action: "approve",
      }).toString(),
    });
    expect(attemptEmpty.status).toBe(400);

    // NOTHING resolved / minted.
    expect(stack.resolveCalls).toEqual([]);
    expect((await stack.orchestrator.status(pending.approvalId)).state).toBe(
      "pending",
    );
    expect(stack.store.stats().active).toBe(0);

    const events = stack.readAuditEvents();
    const violations = events.filter(
      (e) => e.type === "approval_channel_violation",
    );
    expect(violations.some((v) => v.reason === "bad_token")).toBe(true);
    for (const v of violations) {
      expect(v.surface).toBe("local_page");
      expect(JSON.stringify(v)).not.toContain(pending.token);
    }
    expect(events.some((e) => e.type === "approval_approved")).toBe(false);
    expect(events.some((e) => e.type === "grant_created")).toBe(false);

    // Clean up: the legitimate timeout is the only resolution.
    stack.advanceClock(120);
    stack.fireTick();
    expect(knotrustMeta(await criticalPromise)).toMatchObject({
      outcome: "deny",
    });
    expect(stack.resolveCalls).toEqual([]);

    assertNoLeakedSecrets(stack.client.frames);
    expect(stack.verifyAudit().ok).toBe(true);
  }, 40_000);
});

// ===========================================================================
// (b) CSRF — a cross-site auto-submitting page, even holding the real token.
// ===========================================================================

describe("(b) CSRF — a page on another local origin cannot auto-submit an approval, even holding the real token (T1.1e)", () => {
  it("a cross-site Origin, a missing Origin, and a missing CSRF nonce are each independently rejected 403 and audited approval_channel_violation; the approval is unchanged throughout", async () => {
    const stack = await setupStack(
      {
        serverInfo: { name: "knotrust-adv-page-b", version: "1.0.0" },
        tools: [tool("critical_tool_a")],
      },
      { defaultTimeoutSeconds: 60 },
    );
    await stack.client.connect();

    const criticalPromise = stack.client.callTool(
      "critical_tool_a",
      { amount: 1 },
      { progressToken: "prog-csrf" },
    );
    await waitUntil(() => safeReaddir(stack.pendingDir).length > 0, 5_000);
    const pending = readPendingRecordFor(stack.pendingDir, "critical_tool_a");
    const port = stack.pageServer.port;

    // The REAL, single-use token — worst case for this battery: assume the
    // attacker page somehow already has it (a phished link, clipboard
    // leak, browser history). CSRF/Origin must hold REGARDLESS of token
    // secrecy — this is deliberately independent of attack (a)'s "the
    // model never sees the token at all" property.
    const body = new URLSearchParams({
      id: pending.approvalId,
      token: pending.token,
      action: "approve",
    }).toString();

    // (b1) A page on ANOTHER local origin auto-submits a <form> POST — the
    // browser sends the TRUE cross-site Origin, and a blind auto-submit
    // form has no way to read this page's own per-render CSRF nonce
    // (doing so would require reading the legitimate GET response
    // cross-origin, which the same-origin policy forbids).
    const crossSite = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: "http://evil.example",
      },
      body,
    });
    expect(crossSite.status).toBe(403);

    // (b2) The brief's "(or missing Origin)" case — some auto-submit
    // vectors carry no Origin header at all. Policy: missing is REJECTED,
    // never treated as same-origin.
    const missingOrigin = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    expect(missingOrigin.status).toBe(403);

    // (b3) The CSRF nonce's OWN defense, isolated from Origin: even with a
    // matching Origin, a POST missing the per-render CSRF nonce is
    // rejected — belt-and-suspenders in case Origin were ever satisfied by
    // some other means.
    const missingCsrf = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: `http://127.0.0.1:${port}`,
      },
      body,
    });
    expect(missingCsrf.status).toBe(403);

    // NOTHING resolved / minted — three genuine forgery attempts, zero effect.
    expect(stack.resolveCalls).toEqual([]);
    expect((await stack.orchestrator.status(pending.approvalId)).state).toBe(
      "pending",
    );
    expect(stack.store.stats().active).toBe(0);

    const events = stack.readAuditEvents();
    const violations = events.filter(
      (e) => e.type === "approval_channel_violation",
    );
    expect(violations.filter((v) => v.reason === "bad_origin")).toHaveLength(2);
    expect(violations.some((v) => v.reason === "bad_csrf")).toBe(true);
    for (const v of violations) {
      expect(v.surface).toBe("local_page");
      expect(JSON.stringify(v)).not.toContain(pending.token);
    }
    expect(events.some((e) => e.type === "approval_approved")).toBe(false);
    expect(events.some((e) => e.type === "grant_created")).toBe(false);

    stack.advanceClock(120);
    stack.fireTick();
    expect(knotrustMeta(await criticalPromise)).toMatchObject({
      outcome: "deny",
    });
    expect(stack.resolveCalls).toEqual([]);

    assertNoLeakedSecrets(stack.client.frames);
    expect(stack.verifyAudit().ok).toBe(true);
  }, 40_000);
});

// ===========================================================================
// (c) DNS-rebinding — an attacker-controlled Host header on the loopback
//     socket.
// ===========================================================================

describe("(c) DNS-rebinding — an attacker-controlled Host header on the SAME loopback socket is rejected (T1.1e)", () => {
  it("both the GET render and the POST action, carrying the real id/token/Origin but a rebound Host, → 403 bad_host, audited, approval unchanged; the legitimate Host still works", async () => {
    const stack = await setupStack(
      {
        serverInfo: { name: "knotrust-adv-page-c", version: "1.0.0" },
        tools: [tool("critical_tool_a")],
      },
      { defaultTimeoutSeconds: 60 },
    );
    await stack.client.connect();

    const criticalPromise = stack.client.callTool(
      "critical_tool_a",
      { amount: 1 },
      { progressToken: "prog-rebind" },
    );
    await waitUntil(() => safeReaddir(stack.pendingDir).length > 0, 5_000);
    const pending = readPendingRecordFor(stack.pendingDir, "critical_tool_a");
    const port = stack.pageServer.port;

    // Rebind vector 1: GET render with a rebound Host — a browser DNS-bound
    // to `evil.example`, then rebound to resolve to 127.0.0.1, still
    // presents `Host: evil.example` on the wire; this is exactly what
    // catches it.
    const rebindGet = await rawRequest({
      port,
      method: "GET",
      path: `/approve?id=${encodeURIComponent(pending.approvalId)}&token=${encodeURIComponent(pending.token)}`,
      headers: { Host: "evil.example:1337" },
    });
    expect(rebindGet.status).toBe(403);

    // Rebind vector 2: POST action with a rebound Host — carrying the real
    // token/id and an otherwise-valid Origin. Host validation runs FIRST
    // for every request, path-independent (`route()`'s own ordering) —
    // before Origin/CSRF are ever inspected.
    const rebindBody = new URLSearchParams({
      id: pending.approvalId,
      token: pending.token,
      csrf: "n/a-host-check-fires-first",
      action: "approve",
    }).toString();
    const rebindPost = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: `http://127.0.0.1:${port}`,
        Host: "evil.example:1337",
      },
      body: rebindBody,
    });
    expect(rebindPost.status).toBe(403);

    // NOTHING resolved / minted.
    expect(stack.resolveCalls).toEqual([]);
    expect((await stack.orchestrator.status(pending.approvalId)).state).toBe(
      "pending",
    );
    expect(stack.store.stats().active).toBe(0);

    const events = stack.readAuditEvents();
    const violations = events.filter(
      (e) => e.type === "approval_channel_violation" && e.reason === "bad_host",
    );
    expect(violations.length).toBeGreaterThanOrEqual(2);
    for (const v of violations) {
      expect(v.surface).toBe("local_page");
      expect(JSON.stringify(v)).not.toContain(pending.token);
    }

    // The legitimate Host still works — proves this isn't a blanket outage,
    // just the rebind vector.
    const legit = await rawRequest({
      port,
      method: "GET",
      path: `/approve?id=${encodeURIComponent(pending.approvalId)}&token=${encodeURIComponent(pending.token)}`,
      headers: { Host: `127.0.0.1:${port}` },
    });
    expect(legit.status).toBe(200);

    stack.advanceClock(120);
    stack.fireTick();
    expect(knotrustMeta(await criticalPromise)).toMatchObject({
      outcome: "deny",
    });
    expect(stack.resolveCalls).toEqual([]);

    assertNoLeakedSecrets(stack.client.frames);
    expect(stack.verifyAudit().ok).toBe(true);
  }, 40_000);
});

// ===========================================================================
// (d) GET-mutation attempts against every mutating route.
// ===========================================================================

describe("(d) GET-mutation attempts against the mutating route — 405, mutates NOTHING, for every action (T1.1e)", () => {
  it("GET /approve/action for approve, always_allow, and deny each → 405, never calls resolve(), never mints a grant, approval stays pending throughout", async () => {
    const stack = await setupStack(
      {
        serverInfo: { name: "knotrust-adv-page-d", version: "1.0.0" },
        tools: [tool("critical_tool_a")],
      },
      { defaultTimeoutSeconds: 60 },
    );
    await stack.client.connect();

    const criticalPromise = stack.client.callTool(
      "critical_tool_a",
      { amount: 1 },
      { progressToken: "prog-getmut" },
    );
    await waitUntil(() => safeReaddir(stack.pendingDir).length > 0, 5_000);
    const pending = readPendingRecordFor(stack.pendingDir, "critical_tool_a");
    const port = stack.pageServer.port;

    // The ONE mutating route this server exposes is `/approve/action`
    // (the page's own GET render, `/approve`, never mutates by design —
    // see server.ts's own module header, "Two distinct paths"). Every
    // action value it accepts is attempted via GET here.
    for (const action of ["approve", "always_allow", "deny"] as const) {
      const res = await rawRequest({
        port,
        method: "GET",
        path: `/approve/action?id=${encodeURIComponent(pending.approvalId)}&token=${encodeURIComponent(pending.token)}&action=${action}`,
      });
      expect(res.status).toBe(405);
      expect((await stack.orchestrator.status(pending.approvalId)).state).toBe(
        "pending",
      );
    }

    // NOTHING resolved / minted across all three GET attempts.
    expect(stack.resolveCalls).toEqual([]);
    expect(stack.store.stats().active).toBe(0);

    const events = stack.readAuditEvents();
    const violations = events.filter(
      (e) =>
        e.type === "approval_channel_violation" && e.reason === "wrong_method",
    );
    expect(violations).toHaveLength(3);
    for (const v of violations) {
      expect(v.surface).toBe("local_page");
      expect(JSON.stringify(v)).not.toContain(pending.token);
    }
    expect(events.some((e) => e.type === "approval_approved")).toBe(false);
    expect(events.some((e) => e.type === "grant_created")).toBe(false);

    // The real approval is STILL usable afterward — a real POST with the
    // still-untouched token completes normally, proving the GET attempts
    // left the single-use token intact (never consumed it).
    const render = await rawRequest({
      port,
      method: "GET",
      path: `/approve?id=${encodeURIComponent(pending.approvalId)}&token=${encodeURIComponent(pending.token)}`,
    });
    expect(render.status).toBe(200);
    const csrf = extractCsrf(render.body);
    const denyRes = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: `http://127.0.0.1:${port}`,
      },
      body: new URLSearchParams({
        id: pending.approvalId,
        token: pending.token,
        csrf,
        action: "deny",
      }).toString(),
    });
    expect(denyRes.status).toBe(200);
    expect(stack.resolveCalls).toEqual([
      { id: pending.approvalId, outcome: "denied", channel: "elicitation_url" },
    ]);

    expect(knotrustMeta(await criticalPromise)).toMatchObject({
      outcome: "deny",
    });

    assertNoLeakedSecrets(stack.client.frames);
    expect(stack.verifyAudit().ok).toBe(true);
  }, 40_000);
});

// ===========================================================================
// (e) token/approvalId mismatch, plus single-use replay after terminal.
// ===========================================================================

describe("(e) a valid token replayed against a DIFFERENT approvalId is rejected; single-use replay after terminal → 410 (T1.1e)", () => {
  it("two concurrent held approvals: approval A's token against approval B's id (and vice versa) is rejected bad_token, both approvals unaffected; A is then legitimately resolved, and replaying the IDENTICAL correct pair afterward → 410 replayed_token, B still untouched", async () => {
    const stack = await setupStack(
      {
        serverInfo: { name: "knotrust-adv-page-e", version: "1.0.0" },
        tools: [tool("critical_tool_a"), tool("critical_tool_b")],
      },
      { defaultTimeoutSeconds: 60 },
    );
    await stack.client.connect();

    const promiseA = stack.client.callTool(
      "critical_tool_a",
      { amount: 1 },
      { progressToken: "prog-e-a" },
    );
    const promiseB = stack.client.callTool(
      "critical_tool_b",
      { amount: 2 },
      { progressToken: "prog-e-b" },
    );
    await waitUntil(() => safeReaddir(stack.pendingDir).length >= 2, 5_000);

    const pendingA = readPendingRecordFor(stack.pendingDir, "critical_tool_a");
    const pendingB = readPendingRecordFor(stack.pendingDir, "critical_tool_b");
    expect(pendingA.approvalId).not.toBe(pendingB.approvalId);
    expect(pendingA.token).not.toBe(pendingB.token);

    const port = stack.pageServer.port;
    const origin = `http://127.0.0.1:${port}`;

    // A's token against B's id — the page's own per-id token map means A's
    // token is simply the WRONG value for B's entry.
    const crossAB = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: origin,
      },
      body: new URLSearchParams({
        id: pendingB.approvalId,
        token: pendingA.token,
        csrf: "n/a",
        action: "approve",
      }).toString(),
    });
    expect(crossAB.status).toBe(404);

    // ...and the reverse pairing.
    const crossBA = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: origin,
      },
      body: new URLSearchParams({
        id: pendingA.approvalId,
        token: pendingB.token,
        csrf: "n/a",
        action: "approve",
      }).toString(),
    });
    expect(crossBA.status).toBe(404);

    // BOTH approvals unaffected by either mismatched pairing.
    expect(stack.resolveCalls).toEqual([]);
    expect((await stack.orchestrator.status(pendingA.approvalId)).state).toBe(
      "pending",
    );
    expect((await stack.orchestrator.status(pendingB.approvalId)).state).toBe(
      "pending",
    );
    expect(stack.store.stats().active).toBe(0);

    let events = stack.readAuditEvents();
    let violations = events.filter(
      (e) => e.type === "approval_channel_violation",
    );
    expect(
      violations.filter((v) => v.reason === "bad_token").length,
    ).toBeGreaterThanOrEqual(2);
    for (const v of violations) {
      expect(JSON.stringify(v)).not.toContain(pendingA.token);
      expect(JSON.stringify(v)).not.toContain(pendingB.token);
    }

    // Single-use replay after terminal (R143e's parenthetical): resolve A
    // LEGITIMATELY via its own correct id+token+real render-issued CSRF,
    // then replay the IDENTICAL request — 410 Gone, audited
    // replayed_token, and it resolves exactly once.
    const renderA = await rawRequest({
      port,
      method: "GET",
      path: `/approve?id=${encodeURIComponent(pendingA.approvalId)}&token=${encodeURIComponent(pendingA.token)}`,
    });
    expect(renderA.status).toBe(200);
    const csrfA = extractCsrf(renderA.body);
    const denyBodyA = new URLSearchParams({
      id: pendingA.approvalId,
      token: pendingA.token,
      csrf: csrfA,
      action: "deny",
    }).toString();

    const firstDeny = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: origin,
      },
      body: denyBodyA,
    });
    expect(firstDeny.status).toBe(200);
    expect(stack.resolveCalls).toEqual([
      {
        id: pendingA.approvalId,
        outcome: "denied",
        channel: "elicitation_url",
      },
    ]);

    const replay = await rawRequest({
      port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: origin,
      },
      body: denyBodyA,
    });
    expect(replay.status).toBe(410);

    // A is now terminally denied; B is still pending — the replay attempt
    // against A's already-resolved pair touched nothing, and never
    // affected B (proving the mismatch/replay checks are per-id, not a
    // global toggle).
    expect((await stack.orchestrator.status(pendingA.approvalId)).state).toBe(
      "denied",
    );
    expect((await stack.orchestrator.status(pendingB.approvalId)).state).toBe(
      "pending",
    );
    expect(stack.resolveCalls).toHaveLength(1);

    events = stack.readAuditEvents();
    violations = events.filter((e) => e.type === "approval_channel_violation");
    expect(violations.some((v) => v.reason === "replayed_token")).toBe(true);
    expect(events.some((e) => e.type === "grant_created")).toBe(false);
    for (const v of violations) {
      expect(JSON.stringify(v)).not.toContain(pendingA.token);
      expect(JSON.stringify(v)).not.toContain(pendingB.token);
    }

    // Clean up B via the legitimate timeout.
    stack.advanceClock(120);
    stack.fireTick();
    expect(knotrustMeta(await promiseA)).toMatchObject({ outcome: "deny" });
    expect(knotrustMeta(await promiseB)).toMatchObject({ outcome: "deny" });
    expect(stack.resolveCalls).toHaveLength(1);

    assertNoLeakedSecrets(stack.client.frames);
    expect(stack.verifyAudit().ok).toBe(true);
  }, 40_000);
});
