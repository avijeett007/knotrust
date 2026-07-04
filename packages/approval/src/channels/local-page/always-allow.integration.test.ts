/**
 * @knotrust/approval — "Always allow" produces a durable grant a REAL
 * `@knotrust/grants` decider honors on the next identical call (P0-E6-T3,
 * R99). Spanning integration: REAL `GrantStore` (`@knotrust/store`), REAL
 * `KeyStore` (test seed, same primitives as production), REAL
 * `createDecider` (`@knotrust/grants`) — never mocks for the pieces this
 * acceptance is actually about.
 *
 * Acceptance (verbatim from the task spec): "'Always allow' produces a
 * durable grant visible in `knotrust grant list` and the NEXT identical call
 * allows without approval." The `knotrust grant list` CLI subcommand itself
 * is P0-E7 (not yet built) — its future implementation is a thin
 * `store.list()` read (see `@knotrust/store`'s `grant-store.ts`), so this
 * test proves the exact substrate that command will read from: the durable
 * grant is `active` in `store.list()`, AND a fresh `decider.decide()` call
 * against the identical `DecisionRequest` now allows via that grant with
 * ZERO human approval in the loop.
 */
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import type { DecisionRequest, TierPolicy } from "@knotrust/core";
import { createDecisionCache } from "@knotrust/core";
import {
  createDecider,
  createDiskPublicKeyResolver,
  createKeyStore,
  decodeGrantIndexEntry,
  type KeyStore,
  mintDurableGrant,
  mintEphemeralGrant,
} from "@knotrust/grants";
import {
  type AuditEvent,
  type AuditSink,
  createAuditLog,
  createGrantStore,
  type GrantStore,
} from "@knotrust/store";
import { afterEach, describe, expect, it } from "vitest";
import { createApprovalOrchestrator } from "../../lifecycle.js";
import { withApprovalRequestRegistry } from "./registry.js";
import { createApprovalPageServer } from "./server.js";

const NOW = 1_800_000_000;

function makeIdGen(prefix: string): () => string {
  let n = 0;
  return () => `${prefix}${String(n++).padStart(4, "0")}`;
}

function makeRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01ALWAYSALLOWREQ00000001",
    timestamp: "2027-01-15T08:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_alwaysallow1" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2027-01-15T08:00:00Z", surfaceLocal: true },
      arguments: { amount: 4200, reason: "requested_by_customer" },
    },
    surface: { kind: "stdio_proxy", instanceId: "px-aa-1", server: "stripe" },
  };
}

const POLICY: TierPolicy = {
  tools: {
    "stripe.create_refund": { tier: "critical", source: "pack" },
  },
  unknownToolTier: "sensitive",
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
        let respBody = "";
        res.on("data", (chunk: Buffer) => {
          respBody += chunk.toString("utf8");
        });
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, body: respBody }),
        );
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

let tempHome: string;
let store: GrantStore;
let audit: AuditSink;
let priorHome: string | undefined;
let priorKeyBackend: string | undefined;

afterEach(() => {
  try {
    audit.close();
  } catch {
    // best-effort — release the writer lock
  }
  rmSync(tempHome, { recursive: true, force: true });
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;
  if (priorKeyBackend === undefined) delete process.env.KNOTRUST_KEY_BACKEND;
  else process.env.KNOTRUST_KEY_BACKEND = priorKeyBackend;
});

function readAuditEvents(): AuditEvent[] {
  audit.flush();
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

describe('"Always allow" → durable grant → next identical call allows (R99)', () => {
  it("mints a durable grant visible in store.list(), and the NEXT decide() on the identical request allows without approval", async () => {
    tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-always-allow-"));
    priorHome = process.env.KNOTRUST_HOME;
    priorKeyBackend = process.env.KNOTRUST_KEY_BACKEND;
    process.env.KNOTRUST_HOME = tempHome;
    // Force the file backend (fix round 1, Minor 3 discipline elsewhere in
    // this repo): never touch the developer's real OS keychain from a test.
    process.env.KNOTRUST_KEY_BACKEND = "file";

    store = createGrantStore({
      home: tempHome,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    audit = createAuditLog({ home: tempHome, nowEpochMs: () => NOW * 1000 });
    const cache = createDecisionCache({ nowEpochSeconds: () => NOW });
    const keyStore: KeyStore = await createKeyStore({ backend: "file" });
    const resolvePublicKey = createDiskPublicKeyResolver(tempHome);
    // The disk resolver reads whatever `keys.ts` already wrote — force one
    // real identity write now so the FIRST `mintEphemeralGrant` isn't the
    // moment `ensureIdentity()` first runs (harmless either way, just
    // deterministic ordering for this test's own clarity).
    await keyStore.ensureIdentity();

    const decider = createDecider({
      cache,
      tierPolicy: POLICY,
      policyVersion: "policy-v1",
      store,
      audit,
      resolvePublicKey,
      nowEpochSeconds: () => NOW,
      nowMs: () => NOW * 1000,
      generateId: makeIdGen("DEC"),
    });

    const request = makeRequest();
    const firstDecision = await decider.decide(request);
    expect(firstDecision.outcome).toBe("pending_approval");
    expect(firstDecision.tier).toBe("critical");

    const lifecycleOrchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: (input) =>
        mintEphemeralGrant(input, {
          store,
          keyStore,
          nowEpochSeconds: NOW,
          generateId: makeIdGen("EPH"),
          audit,
        }),
      decide: (req) => decider.decide(req),
      audit,
      nowEpochSeconds: () => NOW,
      generateId: makeIdGen("APR"),
    });
    const registry = withApprovalRequestRegistry(lifecycleOrchestrator);

    const pageServer = createApprovalPageServer({
      orchestrator: registry.orchestrator,
      getApprovalRequest: registry.getApprovalRequest,
      mintDurableGrant: (input) =>
        mintDurableGrant(input, {
          store,
          keyStore,
          nowEpochSeconds: NOW,
          generateId: makeIdGen("DUR"),
          audit,
        }),
      audit,
      nowEpochSeconds: () => NOW,
    });
    await pageServer.start();

    try {
      const handle = await registry.orchestrator.request({
        decisionId: firstDecision.decisionId,
        requestId: request.requestId,
        subject: request.subject,
        agent: request.context.agent,
        action: request.action,
        resource: request.resource,
        tier: "critical",
        eligibleChannels: ["elicitation_url"],
        decisionRequest: request,
      });
      expect(handle.state).toBe("pending");

      const token = "tok_ALWAYSALLOWTESTTOKEN0001";
      const url = pageServer.url(handle.id, token);
      const { pathname, search } = new URL(url);

      const rendered = await rawRequest({
        port: pageServer.port,
        method: "GET",
        path: `${pathname}${search}`,
      });
      expect(rendered.status).toBe(200);
      // The human sees the scope + expiry BEFORE confirming (PRD §7).
      expect(rendered.body).toContain("Always allow");
      expect(rendered.body).toContain("stripe.create_refund");
      expect(rendered.body).toContain("expires in 30 days");
      const csrf = extractCsrf(rendered.body);

      const body = new URLSearchParams({
        id: handle.id,
        token,
        csrf,
        action: "always_allow",
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

      // The CURRENT call passed too (approve-once semantics still apply).
      const resolvedState = await registry.orchestrator.onResolved(handle.id);
      expect(resolvedState).toBe("approved");

      // Visible in the store's list() — the exact substrate `knotrust grant
      // list` (P0-E7) will read from.
      const listed = store.list();
      expect(listed.active.length).toBeGreaterThanOrEqual(1);
      const durableJtis = listed.active.map((r) => r.jti);
      const grantCreatedEvents = readAuditEvents().filter(
        (e) => e.type === "grant_created" && e.reason === "kind=durable",
      );
      expect(grantCreatedEvents.length).toBe(1);
      const durableJti = grantCreatedEvents[0]?.grantRefs?.[0];
      expect(durableJti).toBeDefined();
      expect(durableJtis).toContain(durableJti);

      // THE ACCEPTANCE: the next identical call allows, with ZERO approval.
      const secondDecision = await decider.decide(makeRequest());
      expect(secondDecision.outcome).toBe("allow");
      expect(secondDecision.reasonCode).not.toBe("no_grant_critical");
      expect(secondDecision.evaluatedBy).toBe("grant");
    } finally {
      await pageServer.stop();
    }
  }, 15_000);
});
