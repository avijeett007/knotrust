/**
 * @knotrust/approval — approve-via-real-HTTP-POST releases a held
 * block-and-wait call (P0-E6-T3, R100). Mirrors E6-T2's own R95 acceptance
 * ("approve resolves the hold") but resolves through a REAL HTTP POST to the
 * localhost approval page instead of a direct `orchestrator.resolve()` call
 * — proving the page is genuinely wired to the SAME lifecycle orchestrator
 * instance the block-and-wait channel is awaiting.
 *
 * Composition: a REAL `createApprovalOrchestrator` (E6-T1) + a REAL
 * `createBlockAndWaitChannel` (E6-T2), both driven through the SAME
 * `withApprovalRequestRegistry`-wrapped orchestrator a REAL
 * `createApprovalPageServer` (this task) also holds — exactly the
 * production wiring shape (`packages/cli`'s `enforcement.ts`), just without
 * the full CLI/proxy process around it.
 */

import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import type { DecisionRequest, DecisionResponse } from "@knotrust/core";
import type { AuditEvent, AuditSink } from "@knotrust/store";
import { afterEach, describe, expect, it } from "vitest";
import type { ApprovalRequest } from "../../lifecycle.js";
import { createApprovalOrchestrator } from "../../lifecycle.js";
import {
  createBlockAndWaitChannel,
  generateApprovalCode,
  generateApprovalToken,
} from "../block-and-wait.js";
import { withApprovalRequestRegistry } from "./registry.js";
import { createApprovalPageServer } from "./server.js";

const NOW = 1_800_000_000;

function makeDecisionRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01PAGEHOLDREQ0000000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_pagehold1" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 4200 },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px-pagehold-1",
      server: "stripe",
    },
  };
}

function makeDecisionResponse(): DecisionResponse {
  return {
    contractVersion: "1.0",
    requestId: "01PAGEHOLDREQ0000000001",
    decisionId: "01PAGEHOLDDEC000000000B",
    outcome: "pending_approval",
    tier: "critical",
    reasonCode: "no_grant_critical",
    cache: { hit: false },
    evaluatedBy: "L0",
    latencyMs: 0,
  };
}

function makeFakeAudit(): { sink: AuditSink; events: AuditEvent[] } {
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

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) await fn();
  }
});

describe("approve-via-real-HTTP-POST releases a held block-and-wait call (R100)", () => {
  it("a real HTTP POST approve to the page resolves the SAME hold the block-and-wait channel is awaiting", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-page-hold-"));
    cleanups.push(() => rmSync(home, { recursive: true, force: true }));

    const lifecycleOrchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async () => ({
        token: "tok_ephemeral",
        jti: "jti-eph-1",
      }),
      decide: async () => ({
        contractVersion: "1.0",
        requestId: "01PAGEHOLDREQ0000000001",
        decisionId: "01PAGEHOLDREEVAL0000001",
        outcome: "allow",
        tier: "critical",
        reasonCode: "grant_allow",
        cache: { hit: false },
        evaluatedBy: "grant",
        latencyMs: 0,
      }),
      audit: makeFakeAudit().sink,
      nowEpochSeconds: () => NOW,
      generateId: () => "PAGEHOLD01",
    });
    const registry = withApprovalRequestRegistry(lifecycleOrchestrator);

    const { sink: pageAudit } = makeFakeAudit();
    const pageServer = createApprovalPageServer({
      orchestrator: registry.orchestrator,
      getApprovalRequest: registry.getApprovalRequest,
      mintDurableGrant: async () => {
        throw new Error("must not be called on the approve-once path");
      },
      audit: pageAudit,
      nowEpochSeconds: () => NOW,
    });
    await pageServer.start();
    cleanups.push(() => pageServer.stop());

    let capturedUrl: string | undefined;
    const channel = createBlockAndWaitChannel({
      orchestrator: registry.orchestrator,
      sendNotification: () => {},
      nowEpochSeconds: () => NOW,
      home,
      stderrWrite: () => {},
      mintApproval: (approvalId: string) => {
        const token = generateApprovalToken();
        const code = generateApprovalCode();
        const url = pageServer.url(approvalId, token);
        capturedUrl = url;
        return { token, url, code };
      },
    });

    const decisionRequest = makeDecisionRequest();
    const decisionResponse = makeDecisionResponse();
    const approvalRequest: ApprovalRequest = {
      decisionId: decisionResponse.decisionId,
      requestId: decisionRequest.requestId,
      subject: decisionRequest.subject,
      agent: decisionRequest.context.agent,
      action: decisionRequest.action,
      resource: decisionRequest.resource,
      tier: "critical",
      eligibleChannels: ["block_and_wait"],
      decisionRequest,
    };
    // P0-E6-T4: `request()` now happens OUTSIDE the channel (the real
    // adapter — `channel.ts`'s `createDispatchingApprovalOrchestrator` — owns
    // it); this test drives the same two-step sequence directly.
    const handle = await registry.orchestrator.request(approvalRequest);
    const resolutionPromise = registry.orchestrator.onResolved(handle.id);
    await channel.notify(approvalRequest, handle);

    // Let `notify()` (real, but promise-based) settle and
    // `presentApprovalToHuman` run — both happen before the FIRST scheduler
    // tick, with no external timer to wait on.
    await new Promise((r) => setImmediate(r));
    expect(capturedUrl).toBeDefined();
    const { pathname, search } = new URL(capturedUrl as string);

    const rendered = await rawRequest({
      port: pageServer.port,
      method: "GET",
      path: `${pathname}${search}`,
    });
    expect(rendered.status).toBe(200);
    expect(rendered.body).toContain("stripe.create_refund");
    const csrf = extractCsrf(rendered.body);

    const params = new URLSearchParams(search);
    const id = params.get("id");
    const token = params.get("token");
    if (id === null || token === null)
      throw new Error("missing id/token in captured URL");

    const body = new URLSearchParams({
      id,
      token,
      csrf,
      action: "approve",
    }).toString();
    const postRes = await rawRequest({
      port: pageServer.port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
        Origin: `http://127.0.0.1:${pageServer.port}`,
      },
      body,
    });
    expect(postRes.status).toBe(200);

    const resolution = await resolutionPromise;
    expect(resolution).toBe("approved");
  }, 15_000);
});
