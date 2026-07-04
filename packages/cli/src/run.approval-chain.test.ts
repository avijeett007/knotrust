/**
 * knotrust CLI — the R103 canonical audit-chain acceptance (P0-E6-T4, the
 * approval epic's headline): end-to-end on a REAL spawned fake-server child
 * + a REAL fake client, through the REAL `knotrust -- <server>` enforcement
 * stack (real decider, real grant store, real hash-chained audit log, the
 * REAL block-and-wait channel + the REAL localhost approval page, now
 * consolidated behind `@knotrust/approval`'s `ApprovalChannel`/
 * `MultiChannelDispatcher`/`createDispatchingApprovalOrchestrator`, P0-E6-T4):
 *
 *   `critical` tool call -> HELD by block-and-wait -> approved via a REAL
 *   HTTP POST to the localhost page (not a direct `resolve()` call, proving
 *   the full surface) -> the audit chain shows, IN ORDER:
 *
 *     decision(pending_approval) -> approval_requested -> approval_pending
 *       -> approval_approved -> grant_created(ephemeral) -> decision(allow)
 *
 *   -> `audit.verify()` is green over the WHOLE chain -> the REAL child's
 *   result flows back on the ORIGINAL JSON-RPC id.
 *
 * This also proves the E6-T1 `revokeGrant` obligation and the E6-T4
 * dispatcher consolidation stay wired for a real run — the chain could not
 * show `grant_created` immediately after `approval_approved` (mint-before-
 * reevaluate, R87) without the real `createApprovalOrchestrator` +
 * `createDispatchingApprovalOrchestrator` composition actually being live.
 *
 * R105 (client-cancellation) is proven in the second `describe` below, using
 * the harness's own `FakeClient.callToolWithCancel` (built for exactly this,
 * R55) against a held critical call: the client's `notifications/cancelled`
 * cancels the pending approval, the audit log shows `approval_cancelled`,
 * and the child NEVER receives the call.
 */

import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import type { AuditEvent } from "@knotrust/store";
import { createAuditLog } from "@knotrust/store";
import {
  FakeClient,
  type FakeServerConfig,
  parseCallLogFromStderr,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "./run.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

const SERVER_CONFIG: FakeServerConfig = {
  serverInfo: { name: "knotrust-fake-cli-chain", version: "1.0.0" },
  tools: [
    { name: "critical_tool", inputSchema: { type: "object", properties: {} } },
  ],
};

interface RawResponse {
  status: number;
  body: string;
}

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
        headers: options.headers,
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
  if (m?.[1] === undefined) throw new Error("csrf token not found");
  return m[1];
}

interface PendingRecord {
  approvalId: string;
  tool: string;
  token: string;
  url: string;
}

async function waitUntil(
  predicate: () => boolean,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) {
    if (performance.now() > deadline) return predicate();
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return true;
}

function readOnePendingRecord(pendingDir: string): PendingRecord {
  const [file] = readdirSync(pendingDir);
  if (file === undefined) throw new Error("no pending record found");
  return JSON.parse(
    readFileSync(path.join(pendingDir, file), "utf8"),
  ) as PendingRecord;
}

/** Reads every audit event persisted under `$KNOTRUST_HOME/audit`, in `seq` order. */
function readAllAuditEvents(home: string): AuditEvent[] {
  const dir = path.join(home, "audit");
  const events: AuditEvent[] = [];
  for (const f of readdirSync(dir)
    .filter((n) => /^\d{6}\.jsonl$/.test(n))
    .sort()) {
    for (const line of readFileSync(path.join(dir, f), "utf8").split("\n")) {
      if (line.length > 0) events.push(JSON.parse(line) as AuditEvent);
    }
  }
  return events.sort((a, b) => a.seq - b.seq);
}

interface Harness {
  configDir: string;
  home: string;
  client: FakeClient;
  cliDone: Promise<number>;
  clientToProxy: PassThrough;
  getStderr: () => string;
  /** Ends the client, awaits the CLI's own teardown (releasing the audit writer's lock file) — WITHOUT removing any temp directory. Idempotent. */
  stopCli(): Promise<void>;
  /** `stopCli()` + removes every temp directory this harness created. */
  cleanup(): Promise<void>;
}

async function setup(): Promise<Harness> {
  const configDir = mkdtempSync(path.join(tmpdir(), "knotrust-chain-cfg-"));
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-chain-home-"));
  const priorHome = process.env.KNOTRUST_HOME;
  const priorKeyBackend = process.env.KNOTRUST_KEY_BACKEND;
  process.env.KNOTRUST_HOME = home;
  // Never risk a real OS keychain prompt in CI (mirrors run.enforce.test.ts's
  // own discipline).
  process.env.KNOTRUST_KEY_BACKEND = "file";
  writeFileSync(
    path.join(configDir, "knotrust.config.json"),
    JSON.stringify({
      version: 1,
      identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
      servers: {
        testsrv: {
          tools: {
            critical_tool: { tier: "critical", source: "user" },
          },
        },
      },
    }),
  );

  const started = await startFakeServer(SERVER_CONFIG, {
    prepareChildCommand: true,
  });
  const childCommand = started.childCommand;
  if (childCommand === undefined) throw new Error("no childCommand");

  const clientToProxy = new PassThrough();
  const proxyToClient = new PassThrough();
  const stderr = new PassThrough();
  const getErr = collect(stderr);

  const cliDone = runCli(["--", ...childCommand], {
    stdin: clientToProxy,
    stdout: proxyToClient,
    stderr,
    installSignalHandlers: false,
    cwd: configDir,
  });

  const client = new FakeClient(
    new StdioServerTransport(proxyToClient, clientToProxy),
  );

  let stopped = false;
  const stopCli = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    clientToProxy.end();
    await client.close().catch(() => {});
    await cliDone.catch(() => {});
    await started.close().catch(() => {});
  };

  return {
    configDir,
    home,
    client,
    cliDone,
    clientToProxy,
    getStderr: getErr,
    stopCli,
    cleanup: async () => {
      await stopCli();
      if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = priorHome;
      if (priorKeyBackend === undefined) {
        delete process.env.KNOTRUST_KEY_BACKEND;
      } else {
        process.env.KNOTRUST_KEY_BACKEND = priorKeyBackend;
      }
      rmSync(configDir, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    },
  };
}

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) await Promise.resolve(fn()).catch(() => {});
  }
});

describe("R103 — the canonical audit-chain acceptance (approve via the REAL page HTTP POST)", () => {
  it("decision(pending_approval) -> approval_requested -> approval_pending -> approval_approved -> grant_created(ephemeral) -> decision(allow), in order, audit.verify() green, REAL child result on the original id", async () => {
    const h = await setup();
    cleanups.push(h.cleanup);
    await h.client.connect();

    const callPromise = h.client.callTool("critical_tool", { amount: 4200 });

    // The hold has genuinely started — a pending-record file exists (R91a).
    const pendingDir = path.join(h.home, "pending");
    await waitUntil(() => {
      try {
        return readdirSync(pendingDir).length > 0;
      } catch {
        return false;
      }
    }, 5_000);
    const pending = readOnePendingRecord(pendingDir);
    expect(pending.tool).toBe("critical_tool");

    // Approve via a REAL HTTP GET (fetch CSRF) + POST to the localhost page
    // — NOT a direct resolve() call — proving the full surface (R103).
    const { pathname, search } = new URL(pending.url);
    const rendered = await rawRequest({
      port: Number(new URL(pending.url).port),
      method: "GET",
      path: `${pathname}${search}`,
    });
    expect(rendered.status).toBe(200);
    expect(rendered.body).toContain("critical_tool");
    const csrf = extractCsrf(rendered.body);

    const params = new URLSearchParams(search);
    const id = params.get("id");
    const token = params.get("token");
    if (id === null || token === null) {
      throw new Error("missing id/token in the pending record's URL");
    }
    const port = Number(new URL(pending.url).port);
    const body = new URLSearchParams({
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
        "Content-Length": String(Buffer.byteLength(body)),
        Origin: `http://127.0.0.1:${port}`,
      },
      body,
    });
    expect(postRes.status).toBe(200);

    // The REAL child eventually answers, on the ORIGINAL JSON-RPC id — the
    // fake client's own request/response correlation already guarantees the
    // "original id" property; a wrong id would simply never resolve this
    // promise.
    const result = await callPromise;
    expect(result.isError).toBeFalsy();
    expect(result.content).toEqual([
      { type: "text", text: JSON.stringify({ amount: 4200 }) },
    ]);
    await waitUntil(
      () =>
        parseCallLogFromStderr(h.getStderr()).some(
          (e) => e.toolName === "critical_tool",
        ),
      3_000,
    );

    // The pending record is gone once terminal.
    expect(readdirSync(pendingDir)).toEqual([]);

    // --- the canonical audit chain, in EXACT order (R103) ---
    //
    // The plan's shorthand (`decision(pending_approval) -> approval_requested
    // -> approval_pending -> approval_approved -> grant_created(ephemeral) ->
    // decision(allow)`) reconciles to the REAL emitted vocabulary with ONE
    // extra event the shorthand doesn't name: `grant_consumed`, between
    // `grant_created` and the final `decision`. This is the re-evaluation
    // (R87) ACTUALLY consuming the fresh single-use ephemeral grant to
    // produce the `allow` — the grant genuinely mattering, not a vestigial
    // mint — so it belongs in the canonical chain as much as the shorthand's
    // five named events do.
    const events = readAllAuditEvents(h.home).filter(
      (e) => e.tool === "critical_tool",
    );
    expect(events.map((e) => e.type)).toEqual([
      "decision",
      "approval_requested",
      "approval_pending",
      "approval_approved",
      "grant_created",
      "grant_consumed",
      "decision",
    ]);
    expect(events[0]).toMatchObject({
      type: "decision",
      outcome: "pending_approval",
    });
    expect(events[1]).toMatchObject({ type: "approval_requested" });
    expect(events[2]).toMatchObject({ type: "approval_pending" });
    expect(events[3]).toMatchObject({ type: "approval_approved" });
    expect(events[4]).toMatchObject({
      type: "grant_created",
      reason: "kind=ephemeral",
    });
    expect(events[5]).toMatchObject({
      type: "grant_consumed",
      reason: "single_use_consumed",
    });
    expect(events[6]).toMatchObject({ type: "decision", outcome: "allow" });
    // The consumed grant IS the just-minted ephemeral one (same jti).
    expect(events[5]?.grantRefs).toEqual(events[4]?.grantRefs);
    // Every approval_* event shares the SAME approvalId as the pending record.
    for (const e of events.slice(1, 4)) {
      expect(e.approvalId).toBe(pending.approvalId);
    }

    // --- audit.verify() is green over the WHOLE hash-chained log ---
    // The CLI's own audit writer holds an exclusive lock on
    // `$KNOTRUST_HOME/audit` (single-writer-process discipline) — stop the
    // CLI first (releasing it) before opening a fresh reader instance.
    await h.stopCli();
    const reader = createAuditLog({
      home: h.home,
      nowEpochMs: () => Date.now(),
    });
    try {
      const verified = reader.verify();
      expect(verified.ok).toBe(true);
    } finally {
      reader.close();
    }
  }, 40_000);
});

describe("R105 — client-cancellation of a held critical call", () => {
  it("notifications/cancelled for a held critical call cancels the pending approval (audited approval_cancelled); the child NEVER receives the call", async () => {
    const h = await setup();
    cleanups.push(h.cleanup);
    await h.client.connect();

    const pendingDir = path.join(h.home, "pending");

    // A short client-side cancel delay: long enough for the hold to
    // genuinely start (well under it in practice — request()/present() run
    // synchronously through their first await), short enough to keep the
    // test fast.
    const cancelResult = await h.client.callToolWithCancel(
      "critical_tool",
      { amount: 1 },
      { cancelAfterMs: 300, reason: "user_cancelled" },
    );
    expect(cancelResult.status).toBe("cancelled");

    // The audit log shows the cancellation — best-effort proof the
    // notifications/cancelled -> orchestrator.cancel() bridge actually fired
    // (R105), not just a client-side local give-up.
    await waitUntil(() => {
      const events = readAllAuditEvents(h.home).filter(
        (e) => e.tool === "critical_tool",
      );
      return events.some((e) => e.type === "approval_cancelled");
    }, 5_000);
    const events = readAllAuditEvents(h.home).filter(
      (e) => e.tool === "critical_tool",
    );
    const cancelled = events.find((e) => e.type === "approval_cancelled");
    expect(cancelled?.reason).toBe("approval_cancelled");

    // The pending record is gone (terminal) and the child never received
    // the call — cancellation denied it, it was never forwarded.
    await waitUntil(() => {
      try {
        return readdirSync(pendingDir).length === 0;
      } catch {
        return true;
      }
    }, 5_000);
    expect(
      parseCallLogFromStderr(h.getStderr()).some(
        (e) => e.toolName === "critical_tool",
      ),
    ).toBe(false);
  }, 40_000);
});
