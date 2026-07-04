/**
 * P0-E9-T1 / P0-E9-T2 — the harness-based dogfood proof (R156–R160).
 *
 * **Read `examples/dogfood/README.md` first.** OpenClaw's real MCP server(s)
 * and the real Knotie MCP path are NOT present in this repo/environment —
 * they are separate KnoTrust-org systems. This suite does NOT claim any real
 * OpenClaw or Knotie session ran. What it DOES do is compose the FULLY BUILT
 * system — the real grant store, real hash-chained audit log, real unified
 * decider, real approval lifecycle orchestrator + block-and-wait channel,
 * the real localhost approval page, and the real `createEnforcer`/
 * `createStdioProxy` proxy pair (the exact composition
 * `packages/cli/src/enforcement.ts`'s `buildEnforcement` wires in
 * production, assembled here directly rather than through the outer CLI
 * process — mirroring this file's own sibling suites,
 * `approval-page.test.ts` and `self-approval.test.ts`, both of which use the
 * identical `setupStack` shape for the identical reason) — and drives it,
 * through the P0-E11-T1 test harness's fake MCP server/client (a faithful
 * MCP 2025-11-25 stand-in for OpenClaw/Knotie's wire protocol, not OpenClaw
 * or Knotie themselves), against the TWO REAL, COMMITTED config files this
 * task ships (`examples/dogfood/openclaw/knotrust.config.yaml` and
 * `examples/dogfood/knotie/knotrust.config.yaml` — loaded here via the real
 * `loadKnotrustConfig`, which is also how this suite proves "the example
 * configs load, valid against the config schema": there is no separate
 * copy to validate, this IS the validation, by using them for real).
 *
 * Three tiers, one shared walkthrough (`runThreeTierWalkthrough` below),
 * run once per adopter:
 *
 *   - **routine** — a real call runs uninterrupted on the fast path (allow,
 *     forwarded, result relayed on the original id, never held).
 *   - **sensitive, un-granted** — the Requestable Denial envelope: `deny` +
 *     `requestable.how` naming an actionable `knotrust grant --tool …
 *     --server …` command (what an agent would conversationally relay to
 *     the human) — and the whole session's model-visible frames are swept
 *     with the REAL `assertNoLeakedSecrets` (P0-E5-T4's own substrate, not a
 *     bespoke check) to prove zero policy internals ever reached the model.
 *   - **critical** — the call BLOCKS (block-and-wait), is approved via a
 *     REAL HTTP GET (fetch CSRF) + POST to the REAL running localhost
 *     approval page (not a direct `resolve()` call), and COMPLETES — the
 *     child's real result flows back on the original JSON-RPC id. The audit
 *     chain for that call is asserted in the canonical order
 *     (`decision(pending_approval) -> approval_requested ->
 *     approval_pending -> approval_approved -> grant_created ->
 *     grant_consumed -> decision(allow)`, the same chain
 *     `run.approval-chain.test.ts`'s R103 acceptance proves for the CLI
 *     path this mirrors).
 *   - **`verifyAuditChain`** (the exact function `knotrust audit verify`
 *     calls, `packages/cli/src/audit/verify-command.ts`) is asserted green
 *     over the WHOLE session's hash-chained log, afterward.
 *
 * A third `describe` block (`E9-I1`) demonstrates — for real, not just by
 * citation — the one cross-cutting issue R159 asks this task to surface:
 * wrapping OpenClaw's config AND Knotie's config as two concurrent proxies
 * against the SAME `$KNOTRUST_HOME` fails the second one CLOSED (an
 * "audit log already locked" error), never open, hung, or silently
 * corrupting the chain — and that a fresh writer against the same home
 * succeeds again once the first is torn down (proving this is specifically
 * the concurrent-lock condition, not general breakage). See
 * `examples/dogfood/FINDINGS.md`, finding 1, for the full writeup.
 *
 * R160: no product-code change was needed — every assertion below passed
 * against the already-built system on the first real run of this suite.
 */

import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
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
  withApprovalRequestRegistry,
} from "@knotrust/approval";
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
  policyVersion as computePolicyVersion,
  createAuditLog,
  createGrantStore,
  type GrantStore,
  loadKnotrustConfig,
  toAdminEnvelope,
  toTierPolicy,
  verifyAuditChain,
} from "@knotrust/store";
import {
  assertNoLeakedSecrets,
  FakeClient,
  type FakeServerConfig,
  type FakeToolDef,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
// test/adversarial/src -> test/adversarial -> test -> repo root.
const repoRoot = path.resolve(here, "..", "..", "..");
const OPENCLAW_DIR = path.join(repoRoot, "examples", "dogfood", "openclaw");
const KNOTIE_DIR = path.join(repoRoot, "examples", "dogfood", "knotie");

const SUBJECT_ID = "avijeett007@gmail.com";
const AGENT_ID = "dogfood-harness-client";
const INITIAL_CLOCK = 1_800_000_000;

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
  url: string;
}

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
  return events.sort((a, b) => a.seq - b.seq);
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

/** Deliberately `node:http`, not `fetch()` — mirrors every other real-page suite in this directory (Fetch forbids setting some headers this harness never needs here, but the convention is kept identical for consistency). */
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

/** Mirrors `approval-page.test.ts`'s own fake scheduler — tracks EVERY registered tick (a `Set`), not just the latest, so this suite is safe even if a future test in this file ever held two approvals concurrently. */
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

// ---------------------------------------------------------------------------
// Adopter fixtures — one per dogfood config, naming the exact tool this
// suite calls per tier. Tool names/tiers mirror the COMMITTED config files
// exactly (see each `exampleDir`) — this suite exercises those real files,
// not a hand-typed stand-in policy.
// ---------------------------------------------------------------------------

interface DogfoodAdopter {
  label: string;
  exampleDir: string;
  serverKey: string;
  routine: { tool: string; args: Record<string, unknown> };
  sensitive: { tool: string; args: Record<string, unknown> };
  critical: { tool: string; args: Record<string, unknown> };
}

const OPENCLAW_ADOPTER: DogfoodAdopter = {
  label: "openclaw",
  exampleDir: OPENCLAW_DIR,
  serverKey: "openclaw",
  routine: { tool: "openclaw.read_file", args: { path: "README.md" } },
  sensitive: {
    tool: "openclaw.write_file",
    args: { path: "notes.md", content: "hello" },
  },
  critical: { tool: "openclaw.run_shell", args: { command: "echo hi" } },
};

const KNOTIE_ADOPTER: DogfoodAdopter = {
  label: "knotie",
  exampleDir: KNOTIE_DIR,
  serverKey: "knotie",
  routine: {
    tool: "knotie.get_calendar",
    args: { date: "2026-07-04" },
  },
  sensitive: {
    tool: "knotie.send_message",
    args: { to: "alice", body: "running late" },
  },
  critical: {
    tool: "knotie.transfer_funds",
    args: { amount: 50, to: "roommate" },
  },
};

// ---------------------------------------------------------------------------
// The stack — the exact composition `packages/cli/src/enforcement.ts`'s
// `buildEnforcement` wires in production (real store, real audit, real
// decider fed the REAL loaded+validated config's tier policy/envelope, real
// approval lifecycle + block-and-wait + localhost page, real proxy),
// assembled directly rather than through the outer CLI process — mirroring
// this directory's `approval-page.test.ts`/`self-approval.test.ts`
// `setupStack` shape verbatim.
// ---------------------------------------------------------------------------

interface Stack {
  client: FakeClient;
  proxy: StdioProxy;
  pageServer: ApprovalPageServer;
  store: GrantStore;
  keyStore: KeyStore;
  home: string;
  sourceFile: string;
  pendingDir: string;
  advanceClock: (deltaSeconds: number) => void;
  fireTick: () => void;
  readAuditEvents: () => AuditEvent[];
  teardown: () => Promise<void>;
}

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) await Promise.resolve(fn()).catch(() => {});
  }
});

async function setupDogfoodStack(
  adopter: DogfoodAdopter,
  opts: { home?: string } = {},
): Promise<Stack> {
  const home =
    opts.home ?? mkdtempSync(path.join(tmpdir(), "knotrust-dogfood-home-"));
  const priorHome = process.env.KNOTRUST_HOME;
  const priorKeyBackend = process.env.KNOTRUST_KEY_BACKEND;
  process.env.KNOTRUST_HOME = home;
  // Never risk a real OS keychain prompt in CI (mirrors every sibling suite).
  process.env.KNOTRUST_KEY_BACKEND = "file";

  // The REAL, committed example config — loaded + validated for real. This
  // IS "the example configs load (valid against the config schema)" — there
  // is no separate copy asserted elsewhere; using it for real enforcement
  // below is the strongest possible proof it loads correctly.
  const loaded = await loadKnotrustConfig({ cwd: adopter.exampleDir });
  if (loaded.sourceFile === undefined) {
    throw new Error(
      `no knotrust.config.* found under ${adopter.exampleDir} — the ` +
        "committed dogfood example is missing or unreadable",
    );
  }

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

  // The REAL normalizers `buildEnforcement` calls, fed the REAL loaded config.
  const tierPolicy = toTierPolicy(loaded.config, adopter.serverKey);
  const envelope = toAdminEnvelope(loaded.config);
  const pv = computePolicyVersion(loaded.config);

  const decider = createDecider({
    cache,
    tierPolicy,
    envelope,
    policyVersion: pv,
    store,
    audit,
    resolvePublicKey,
    nowEpochSeconds: () => clock,
    nowMs: () => clock * 1000,
    generateId: idGen,
  });

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
  });
  const registry = withApprovalRequestRegistry(baseLifecycle);

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
      surface: {
        instanceId: `px-${adopter.serverKey}`,
        server: adopter.serverKey,
      },
      nowMs: () => clock * 1000,
      generateId: idGen,
    },
    audit,
    orchestrator: approvalAdapter,
  });

  const serverConfig: FakeServerConfig = {
    serverInfo: {
      name: `knotrust-fake-${adopter.serverKey}`,
      version: "1.0.0",
    },
    tools: [
      tool(adopter.routine.tool),
      tool(adopter.sensitive.tool),
      tool(adopter.critical.tool),
    ],
  };
  const started = await startFakeServer(serverConfig, {
    prepareChildCommand: true,
  });
  const childCommand = started.childCommand;
  if (childCommand === undefined) throw new Error("no childCommand");

  const clientToProxy = new PassThrough();
  const proxyToClient = new PassThrough();
  const stderrSink = new PassThrough();
  stderrSink.on("data", () => {
    // Discarded — this suite reads audit events and the page, not stderr.
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

  let torn = false;
  const teardown = async (): Promise<void> => {
    if (torn) return;
    torn = true;
    await proxy.stop().catch(() => {});
    await client.close().catch(() => {});
    await pageServer.stop().catch(() => {});
    await started.close().catch(() => {});
    try {
      audit.close();
    } catch {
      // release the writer lock — best-effort on teardown.
    }
    if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
    else process.env.KNOTRUST_HOME = priorHome;
    if (priorKeyBackend === undefined) delete process.env.KNOTRUST_KEY_BACKEND;
    else process.env.KNOTRUST_KEY_BACKEND = priorKeyBackend;
    if (opts.home === undefined) rmSync(home, { recursive: true, force: true });
  };

  return {
    client,
    proxy,
    pageServer,
    store,
    keyStore,
    home,
    sourceFile: loaded.sourceFile,
    pendingDir: path.join(home, "pending"),
    advanceClock: (deltaSeconds) => {
      clock += deltaSeconds;
    },
    fireTick,
    readAuditEvents: () => {
      audit.flush();
      return readAllAuditEvents(home);
    },
    teardown,
  };
}

// ---------------------------------------------------------------------------
// The shared three-tier walkthrough — run once per adopter below.
// ---------------------------------------------------------------------------

async function runThreeTierWalkthrough(adopter: DogfoodAdopter): Promise<void> {
  const stack = await setupDogfoodStack(adopter);
  cleanups.push(stack.teardown);
  await stack.client.connect();

  // --- 1. routine: fast path, uninterrupted, forwarded, result relayed ---
  const routineResult = await stack.client.callTool(
    adopter.routine.tool,
    adopter.routine.args,
  );
  expect(routineResult.isError).toBeFalsy();
  expect(routineResult.content).toEqual([
    { type: "text", text: JSON.stringify(adopter.routine.args) },
  ]);
  // Never held — no pending record was ever created for the routine call.
  expect(safeReaddir(stack.pendingDir)).toEqual([]);

  // --- 2. sensitive, un-granted: the Requestable Denial ---
  const sensitiveResult = await stack.client.callTool(
    adopter.sensitive.tool,
    adopter.sensitive.args,
  );
  expect(sensitiveResult.isError).toBe(true);
  const sMeta = knotrustMeta(sensitiveResult);
  expect(sMeta).toMatchObject({
    outcome: "deny",
    tierClass: "sensitive",
    retryable: false,
    humanApproval: { possible: true },
  });
  const requestable = sMeta.requestable as { how: string } | undefined;
  const expectedHow = `knotrust grant --tool ${adopter.sensitive.tool} --server ${adopter.serverKey}`;
  expect(requestable?.how).toBe(expectedHow);
  // The model-visible TEXT (what an agent would read and relay
  // conversationally) also carries the same actionable command and says
  // a human can approve it — never a rule id, threshold, or internal
  // reason code.
  const sensitiveText =
    (sensitiveResult.content as Array<{ type: string; text?: string }>)[0]
      ?.text ?? "";
  expect(sensitiveText).toContain(expectedHow);
  expect(sensitiveText.toLowerCase()).toContain("human");
  expect(safeReaddir(stack.pendingDir)).toEqual([]); // sensitive never holds.

  // --- 3. critical: block -> real HTTP approve on the local page -> complete ---
  const criticalPromise = stack.client.callTool(
    adopter.critical.tool,
    adopter.critical.args,
    { progressToken: `prog-${adopter.serverKey}` },
  );
  await waitUntil(() => safeReaddir(stack.pendingDir).length > 0, 5_000);
  const pending = readPendingRecordFor(stack.pendingDir, adopter.critical.tool);
  expect(pending.tool).toBe(adopter.critical.tool);

  const parsedUrl = new URL(pending.url);
  const port = Number(parsedUrl.port);
  const rendered = await rawRequest({
    port,
    method: "GET",
    path: `${parsedUrl.pathname}${parsedUrl.search}`,
  });
  expect(rendered.status).toBe(200);
  expect(rendered.body).toContain(adopter.critical.tool);
  const csrf = extractCsrf(rendered.body);

  const params = new URLSearchParams(parsedUrl.search);
  const id = params.get("id");
  const token = params.get("token");
  if (id === null || token === null) {
    throw new Error("missing id/token in the pending record's URL");
  }
  const postBody = new URLSearchParams({
    id,
    token,
    csrf,
    action: "approve",
  }).toString();
  const postRes = await rawRequest({
    port,
    method: "POST",
    path: "/approve/action",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Origin: `http://127.0.0.1:${port}`,
    },
    body: postBody,
  });
  expect(postRes.status).toBe(200);

  const criticalResult = await criticalPromise;
  expect(criticalResult.isError).toBeFalsy();
  expect(criticalResult.content).toEqual([
    { type: "text", text: JSON.stringify(adopter.critical.args) },
  ]);
  // Terminal — the pending record is gone.
  expect(safeReaddir(stack.pendingDir)).toEqual([]);

  // --- the E5-T4 property: zero policy internals across EVERY frame ---
  assertNoLeakedSecrets(stack.client.frames);

  // --- the canonical audit chain for the critical call, in EXACT order ---
  const events = stack.readAuditEvents();
  const criticalEvents = events.filter((e) => e.tool === adopter.critical.tool);
  expect(criticalEvents.map((e) => e.type)).toEqual([
    "decision",
    "approval_requested",
    "approval_pending",
    "approval_approved",
    "grant_created",
    "grant_consumed",
    "decision",
  ]);
  expect(criticalEvents[0]).toMatchObject({
    type: "decision",
    outcome: "pending_approval",
    tier: "critical",
  });
  expect(criticalEvents.at(-1)).toMatchObject({
    type: "decision",
    outcome: "allow",
  });

  const routineEvents = events.filter((e) => e.tool === adopter.routine.tool);
  expect(routineEvents.map((e) => e.type)).toEqual(["decision"]);
  expect(routineEvents[0]).toMatchObject({ outcome: "allow", tier: "routine" });

  const sensitiveEvents = events.filter(
    (e) => e.tool === adopter.sensitive.tool,
  );
  expect(sensitiveEvents.map((e) => e.type)).toEqual(["decision"]);
  expect(sensitiveEvents[0]).toMatchObject({
    outcome: "deny",
    tier: "sensitive",
  });

  // --- audit verify GREEN afterward — the exact function `knotrust audit
  // verify` calls (packages/cli/src/audit/verify-command.ts), run
  // lock-free (no need to stop the proxy first — that is itself the
  // documented "a forensic read must never contend with a live writer"
  // property, packages/store/src/audit-log.ts's own header) ---
  const verified = verifyAuditChain(stack.home);
  if (!verified.ok) {
    throw new Error(
      `audit chain broken for ${adopter.label}: ${JSON.stringify(verified.breakAt)}`,
    );
  }
  expect(verified.ok).toBe(true);
  expect(verified.events).toBeGreaterThanOrEqual(9); // 1 + 1 + 7, at minimum.

  await stack.client.close();
  await stack.proxy.stop().catch(() => {});
}

// ---------------------------------------------------------------------------
// P0-E9-T1 — OpenClaw.
// ---------------------------------------------------------------------------

describe("P0-E9-T1 — OpenClaw dogfood, harness-based proof (R157)", () => {
  it("examples/dogfood/openclaw/knotrust.config.yaml loads (valid against the config schema) and drives a real three-tier session: routine fast-path allow, sensitive Requestable Denial, critical block->page-approve->complete, audit verify green", async () => {
    await runThreeTierWalkthrough(OPENCLAW_ADOPTER);
  }, 40_000);
});

// ---------------------------------------------------------------------------
// P0-E9-T2 — Knotie.
// ---------------------------------------------------------------------------

describe("P0-E9-T2 — Knotie dogfood, harness-based proof (R157)", () => {
  it("examples/dogfood/knotie/knotrust.config.yaml loads (valid against the config schema) and drives the SAME three-tier session evidence as OpenClaw", async () => {
    await runThreeTierWalkthrough(KNOTIE_ADOPTER);
  }, 40_000);

  it("the voice-outcome findings note names a concrete deferred_not_eligible trigger case tied to this config's own critical tool (R156)", () => {
    const notePath = path.join(KNOTIE_DIR, "VOICE-FINDINGS.md");
    expect(existsSync(notePath)).toBe(true);
    const note = readFileSync(notePath, "utf8");
    expect(note).toContain("deferred_not_eligible");
    // The concrete trigger case must name the SAME critical tool this
    // suite's own walkthrough just drove through block-and-wait above —
    // the finding and the config are the same artifact, not a hypothetical.
    expect(note).toContain(KNOTIE_ADOPTER.critical.tool);
  });
});

// ---------------------------------------------------------------------------
// E9-I1 — the multi-server audit single-writer lock, demonstrated for real
// (R159): wrapping OpenClaw AND Knotie simultaneously against ONE
// $KNOTRUST_HOME is exactly the real dogfood scenario this pin describes.
// ---------------------------------------------------------------------------

describe("E9-I1 — OpenClaw + Knotie wrapped simultaneously against ONE $KNOTRUST_HOME hits the known multi-server audit single-writer lock (R159)", () => {
  it("the second proxy's createAuditLog() fails CLOSED with 'already locked' (never hangs, never silently corrupts) while the first is still running; a fresh writer against the SAME home succeeds again once the first is torn down", async () => {
    const sharedHome = mkdtempSync(
      path.join(tmpdir(), "knotrust-dogfood-shared-home-"),
    );

    const stack1 = await setupDogfoodStack(OPENCLAW_ADOPTER, {
      home: sharedHome,
    });
    try {
      await expect(
        setupDogfoodStack(KNOTIE_ADOPTER, { home: sharedHome }),
      ).rejects.toThrow(/audit log already locked/);
    } finally {
      await stack1.teardown();
    }

    // The lock is released — a fresh writer against the SAME home now
    // succeeds, proving this was specifically the concurrent-lock
    // condition, not general breakage of that $KNOTRUST_HOME.
    const stack2 = await setupDogfoodStack(KNOTIE_ADOPTER, {
      home: sharedHome,
    });
    await stack2.teardown();

    rmSync(sharedHome, { recursive: true, force: true });
  }, 40_000);
});
