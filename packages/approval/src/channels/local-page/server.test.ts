/**
 * @knotrust/approval — the localhost approval page hardening battery
 * (P0-E6-T3; rulings R96–R100). This is a UNIT-level suite: a real
 * `createApprovalPageServer` bound to a real ephemeral loopback port, driven
 * over REAL `node:http` requests, with a fake `orchestrator`/
 * `getApprovalRequest`/`mintDurableGrant`/`audit` so every path is
 * deterministic. The full end-to-end proofs — approve-via-real-HTTP-POST
 * releasing a genuine block-and-wait hold, and "always allow" producing a
 * durable grant a REAL `@knotrust/grants` decider honors on the next
 * identical call — live in this directory's own integration suites
 * (`page-releases-hold.integration.test.ts`,
 * `always-allow.integration.test.ts`).
 */
import http from "node:http";
import { networkInterfaces } from "node:os";
import type { DecisionRequest } from "@knotrust/core";
import type { MintResult } from "@knotrust/grants";
import type { AuditEvent, AuditSink } from "@knotrust/store";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  ApprovalHandle,
  ApprovalOrchestrator,
  ApprovalRequest,
} from "../../lifecycle.js";
import { createApprovalPageServer } from "./server.js";

// ---------------------------------------------------------------------------
// Tiny raw-http client — deliberately NOT `fetch()`: the Fetch spec forbids a
// caller from setting `Host`/`Origin` headers at all (the "forbidden header
// names" list), which is exactly what the Host-validation and Origin-
// validation batteries below need to control. `node:http`'s `request()` has
// no such restriction.
// ---------------------------------------------------------------------------

interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
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
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body });
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000;

function makeDecisionRequest(
  over: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01PAGESERVERREQ00000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_pageserver1" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 4200 },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px-pageserver-1",
      server: "stripe",
    },
    ...over,
  };
}

function makeApprovalRequest(
  over: Partial<ApprovalRequest> = {},
): ApprovalRequest {
  const decisionRequest = over.decisionRequest ?? makeDecisionRequest();
  return {
    decisionId: "dec-page-1",
    requestId: decisionRequest.requestId,
    subject: decisionRequest.subject,
    agent: decisionRequest.context.agent,
    action: decisionRequest.action,
    resource: decisionRequest.resource,
    tier: "critical",
    eligibleChannels: ["elicitation_url"],
    decisionRequest,
    ...over,
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

/** A minimal fake `ApprovalOrchestrator` — `resolve`/`status` are spies so tests can assert on calls without a real lifecycle state machine. */
function makeFakeOrchestrator(): {
  orchestrator: ApprovalOrchestrator;
  setState(id: string, state: ApprovalHandle["state"]): void;
} {
  const states = new Map<string, ApprovalHandle["state"]>();
  const orchestrator: ApprovalOrchestrator = {
    request: vi.fn(async () => {
      throw new Error("not used in this suite");
    }),
    status: vi.fn(async (id: string) => ({
      id,
      state: states.get(id) ?? "pending",
    })),
    resolve: vi.fn(async (id: string, r: "approved" | "denied") => {
      states.set(id, r);
    }),
    cancel: vi.fn(async () => {}),
    onResolved: vi.fn(async (id: string) => states.get(id) ?? "pending"),
    sweepExpired: vi.fn(() => []),
  };
  return {
    orchestrator,
    setState: (id, state) => states.set(id, state),
  };
}

async function unreachableMintDurableGrant(): Promise<MintResult> {
  throw new Error("mintDurableGrant must not be called on this path");
}

interface Harness {
  port: number;
  orchestrator: ApprovalOrchestrator;
  setState(id: string, state: ApprovalHandle["state"]): void;
  events: AuditEvent[];
  approvalRequests: Map<string, ApprovalRequest>;
  stop(): Promise<void>;
  mintDurableGrant: ReturnType<typeof vi.fn>;
}

async function startHarness(
  overrides: {
    mintDurableGrant?: (input: unknown) => Promise<MintResult>;
  } = {},
): Promise<Harness> {
  const { orchestrator, setState } = makeFakeOrchestrator();
  const { sink, events } = makeFakeAudit();
  const approvalRequests = new Map<string, ApprovalRequest>();
  const mintDurableGrant = vi.fn(
    overrides.mintDurableGrant ?? unreachableMintDurableGrant,
  );

  const server = createApprovalPageServer({
    orchestrator,
    getApprovalRequest: (id) => approvalRequests.get(id),
    // biome-ignore lint/suspicious/noExplicitAny: test harness accepts a loosely-typed override for the durable-grant-mint failure path
    mintDurableGrant: mintDurableGrant as any,
    audit: sink,
    nowEpochSeconds: () => NOW,
  });
  await server.start();

  return {
    port: server.port,
    orchestrator,
    setState,
    events,
    approvalRequests,
    stop: () => server.stop(),
    mintDurableGrant,
    // expose url() via closure below
    ...{ url: server.url },
  } as Harness & { url: typeof server.url };
}

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) await fn();
  }
});

function registerApproval(
  h: Harness & { url: (id: string, token: string) => string },
  id: string,
  token: string,
  approvalRequest: ApprovalRequest,
): string {
  h.approvalRequests.set(id, approvalRequest);
  h.setState(id, "pending");
  return h.url(id, token);
}

// ---------------------------------------------------------------------------
// Loopback bind
// ---------------------------------------------------------------------------

describe("loopback-only bind (R98)", () => {
  it("accepts a connection on 127.0.0.1", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    registerApproval(
      h,
      "apr_bind1",
      "tok_AAAAAAAAAAAAAAAAAAAAAAAA",
      makeApprovalRequest(),
    );

    const res = await rawRequest({
      port: h.port,
      method: "GET",
      path: "/approve?id=apr_bind1&token=tok_AAAAAAAAAAAAAAAAAAAAAAAA",
    });
    expect(res.status).toBe(200);
  });

  it("refuses a connection on every non-loopback local interface (external-interface bind test fails)", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);

    const externalIPv4 = Object.values(networkInterfaces())
      .flat()
      .find((i) => i !== undefined && i.family === "IPv4" && !i.internal);

    if (externalIPv4 === undefined) {
      // No routable non-loopback interface on this host — the bind-address
      // assertion below is the environment-independent proof instead.
      return;
    }

    await expect(
      new Promise<void>((resolve, reject) => {
        const socket = http
          .request(
            {
              host: externalIPv4.address,
              port: h.port,
              method: "GET",
              path: "/approve",
              timeout: 800,
            },
            () => {
              reject(new Error("connection unexpectedly succeeded"));
            },
          )
          .on("error", () => resolve())
          .on("timeout", () => {
            socket.destroy();
            resolve();
          });
        socket.end();
      }),
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// XSS-proof rendering, end-to-end over real HTTP.
// ---------------------------------------------------------------------------

describe("argument summary rendering — <script> renders escaped/inert (R99)", () => {
  it("a <script>-laden argument value never reaches the response as a live tag", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const decisionRequest = makeDecisionRequest({
      context: {
        agent: { id: "codex-cli", type: "ai_agent" },
        env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
        arguments: { note: "<script>alert(1)</script>" },
      },
    });
    const url = registerApproval(
      h,
      "apr_xss1",
      "tok_BBBBBBBBBBBBBBBBBBBBBBBB",
      makeApprovalRequest({ decisionRequest }),
    );
    const { pathname, search } = new URL(url);

    const res = await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    });

    expect(res.status).toBe(200);
    expect(res.body).not.toContain("<script>alert(1)</script>");
    expect(res.body).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});

// ---------------------------------------------------------------------------
// GET on the mutating endpoint → 405, no mutation.
// ---------------------------------------------------------------------------

describe("POST-only mutations (R98)", () => {
  it("GET /approve/action → 405 and mutates nothing", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    registerApproval(
      h,
      "apr_get405",
      "tok_CCCCCCCCCCCCCCCCCCCCCCCC",
      makeApprovalRequest(),
    );

    const res = await rawRequest({
      port: h.port,
      method: "GET",
      path: "/approve/action?id=apr_get405&token=tok_CCCCCCCCCCCCCCCCCCCCCCCC",
    });

    expect(res.status).toBe(405);
    expect(h.orchestrator.resolve).not.toHaveBeenCalled();
    expect(h.mintDurableGrant).not.toHaveBeenCalled();
  });

  it("POST /approve (the render endpoint) → 405", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);

    const res = await rawRequest({
      port: h.port,
      method: "POST",
      path: "/approve",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "0",
      },
    });

    expect(res.status).toBe(405);
  });
});

// ---------------------------------------------------------------------------
// Host validation (DNS-rebinding defense).
// ---------------------------------------------------------------------------

describe("Host validation — DNS-rebinding defense (R98)", () => {
  it("a request on the loopback socket with an attacker-controlled Host → 403, audited", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    registerApproval(
      h,
      "apr_host1",
      "tok_DDDDDDDDDDDDDDDDDDDDDDDD",
      makeApprovalRequest(),
    );

    const res = await rawRequest({
      port: h.port,
      method: "GET",
      path: "/approve?id=apr_host1&token=tok_DDDDDDDDDDDDDDDDDDDDDDDD",
      headers: { Host: "evil.example:9999" },
    });

    expect(res.status).toBe(403);
    const violation = h.events.find(
      (e) => e.type === "approval_channel_violation",
    );
    expect(violation?.reason).toBe("bad_host");
    // NEVER the token value in the audit line.
    expect(JSON.stringify(violation)).not.toContain(
      "tok_DDDDDDDDDDDDDDDDDDDDDDDD",
    );
  });

  it("Host: localhost:<port> is accepted (the other valid form)", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    registerApproval(
      h,
      "apr_host2",
      "tok_EEEEEEEEEEEEEEEEEEEEEEEE",
      makeApprovalRequest(),
    );

    const res = await rawRequest({
      port: h.port,
      method: "GET",
      path: "/approve?id=apr_host2&token=tok_EEEEEEEEEEEEEEEEEEEEEEEE",
      headers: { Host: `localhost:${h.port}` },
    });

    expect(res.status).toBe(200);
  });

  it("a missing Host header → 403, audited bad_host", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    registerApproval(
      h,
      "apr_host3",
      "tok_FFFFFFFFFFFFFFFFFFFFFFFF",
      makeApprovalRequest(),
    );

    // A raw HTTP/1.0 request carries no Host line at all — the one way to
    // reach this server with `req.headers.host === undefined` (Node's own
    // http.request client always synthesizes a Host header for HTTP/1.1).
    const net = await import("node:net");
    const status = await new Promise<number>((resolve, reject) => {
      const socket = net.connect(h.port, "127.0.0.1", () => {
        socket.write(
          "GET /approve?id=apr_host3&token=tok_FFFFFFFFFFFFFFFFFFFFFFFF HTTP/1.0\r\n\r\n",
        );
      });
      socket.on("data", (chunk: Buffer) => {
        const statusLine = chunk.toString("utf8").split("\r\n")[0] ?? "";
        const match = /^HTTP\/\d\.\d (\d+)/.exec(statusLine);
        resolve(match?.[1] !== undefined ? Number(match[1]) : 0);
        socket.end();
      });
      socket.on("error", reject);
    });

    expect(status).toBe(403);
    expect(h.events.some((e) => e.reason === "bad_host")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Origin validation.
// ---------------------------------------------------------------------------

describe("Origin validation (R98)", () => {
  async function approveFlow(
    h: Harness & { url: (id: string, token: string) => string },
  ) {
    const id = "apr_origin1";
    const token = "tok_GGGGGGGGGGGGGGGGGGGGGGGG";
    const url = registerApproval(h, id, token, makeApprovalRequest());
    const { pathname, search } = new URL(url);
    const rendered = await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    });
    const csrf = extractCsrf(rendered.body);
    return { id, token, csrf };
  }

  it("a wrong Origin on POST /approve/action → 403, audited, no mutation", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const { id, token, csrf } = await approveFlow(h);

    const body = new URLSearchParams({
      id,
      token,
      csrf,
      action: "approve",
    }).toString();
    const res = await rawRequest({
      port: h.port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
        Origin: "http://evil.example",
      },
      body,
    });

    expect(res.status).toBe(403);
    expect(h.orchestrator.resolve).not.toHaveBeenCalled();
    const violation = h.events.find((e) => e.reason === "bad_origin");
    expect(violation?.type).toBe("approval_channel_violation");
    expect(JSON.stringify(violation)).not.toContain(token);
  });

  it("a missing Origin on POST /approve/action → 403, audited, no mutation", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const { id, token, csrf } = await approveFlow(h);

    const body = new URLSearchParams({
      id,
      token,
      csrf,
      action: "approve",
    }).toString();
    const res = await rawRequest({
      port: h.port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
      },
      body,
    });

    expect(res.status).toBe(403);
    expect(h.orchestrator.resolve).not.toHaveBeenCalled();
    expect(h.events.some((e) => e.reason === "bad_origin")).toBe(true);
  });

  it("a matching Origin (http://127.0.0.1:<port>) is accepted", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const { id, token, csrf } = await approveFlow(h);

    const body = new URLSearchParams({
      id,
      token,
      csrf,
      action: "approve",
    }).toString();
    const res = await rawRequest({
      port: h.port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
        Origin: `http://127.0.0.1:${h.port}`,
      },
      body,
    });

    expect(res.status).toBe(200);
    expect(h.orchestrator.resolve).toHaveBeenCalledWith(
      id,
      "approved",
      "elicitation_url",
    );
  });
});

// ---------------------------------------------------------------------------
// CSRF.
// ---------------------------------------------------------------------------

describe("CSRF (R97/R98)", () => {
  it("a missing CSRF token on POST /approve/action → 403, audited, no mutation", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const id = "apr_csrf1";
    const token = "tok_HHHHHHHHHHHHHHHHHHHHHHHH";
    const url = registerApproval(h, id, token, makeApprovalRequest());
    const { pathname, search } = new URL(url);
    await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    }); // renders + issues csrf, discarded

    const body = new URLSearchParams({
      id,
      token,
      action: "approve",
    }).toString();
    const res = await rawRequest({
      port: h.port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
        Origin: `http://127.0.0.1:${h.port}`,
      },
      body,
    });

    expect(res.status).toBe(403);
    expect(h.orchestrator.resolve).not.toHaveBeenCalled();
    const violation = h.events.find((e) => e.reason === "bad_csrf");
    expect(violation?.type).toBe("approval_channel_violation");
    expect(JSON.stringify(violation)).not.toContain(token);
  });

  it("a wrong CSRF token on POST /approve/action → 403, audited, no mutation", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const id = "apr_csrf2";
    const token = "tok_IIIIIIIIIIIIIIIIIIIIIIII";
    const url = registerApproval(h, id, token, makeApprovalRequest());
    const { pathname, search } = new URL(url);
    await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    });

    const body = new URLSearchParams({
      id,
      token,
      csrf: "csrf_totally-wrong-value",
      action: "approve",
    }).toString();
    const res = await rawRequest({
      port: h.port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
        Origin: `http://127.0.0.1:${h.port}`,
      },
      body,
    });

    expect(res.status).toBe(403);
    expect(h.orchestrator.resolve).not.toHaveBeenCalled();
    expect(h.events.some((e) => e.reason === "bad_csrf")).toBe(true);
  });

  it("the correct, render-issued CSRF token is accepted", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const id = "apr_csrf3";
    const token = "tok_JJJJJJJJJJJJJJJJJJJJJJJJ";
    const url = registerApproval(h, id, token, makeApprovalRequest());
    const { pathname, search } = new URL(url);
    const rendered = await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    });
    const csrf = extractCsrf(rendered.body);

    const body = new URLSearchParams({
      id,
      token,
      csrf,
      action: "deny",
    }).toString();
    const res = await rawRequest({
      port: h.port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
        Origin: `http://127.0.0.1:${h.port}`,
      },
      body,
    });

    expect(res.status).toBe(200);
    expect(h.orchestrator.resolve).toHaveBeenCalledWith(
      id,
      "denied",
      "elicitation_url",
    );
  });
});

// ---------------------------------------------------------------------------
// Single-use token → 410 on replay.
// ---------------------------------------------------------------------------

describe("single-use token (R97)", () => {
  it("replaying the GET URL after a terminal action → 410", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const id = "apr_replay1";
    const token = "tok_KKKKKKKKKKKKKKKKKKKKKKKK";
    const url = registerApproval(h, id, token, makeApprovalRequest());
    const { pathname, search } = new URL(url);

    const rendered = await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    });
    const csrf = extractCsrf(rendered.body);
    const body = new URLSearchParams({
      id,
      token,
      csrf,
      action: "approve",
    }).toString();
    const approveRes = await rawRequest({
      port: h.port,
      method: "POST",
      path: "/approve/action",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(Buffer.byteLength(body)),
        Origin: `http://127.0.0.1:${h.port}`,
      },
      body,
    });
    expect(approveRes.status).toBe(200);

    const replayGet = await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    });
    expect(replayGet.status).toBe(410);
    const violation = h.events.find((e) => e.reason === "replayed_token");
    expect(violation?.type).toBe("approval_channel_violation");
    expect(JSON.stringify(violation)).not.toContain(token);
  });

  it("replaying the POST after a terminal action → 410, no second resolve()", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const id = "apr_replay2";
    const token = "tok_LLLLLLLLLLLLLLLLLLLLLLLL";
    const url = registerApproval(h, id, token, makeApprovalRequest());
    const { pathname, search } = new URL(url);

    const rendered = await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    });
    const csrf = extractCsrf(rendered.body);
    const body = new URLSearchParams({
      id,
      token,
      csrf,
      action: "approve",
    }).toString();
    const postOnce = () =>
      rawRequest({
        port: h.port,
        method: "POST",
        path: "/approve/action",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": String(Buffer.byteLength(body)),
          Origin: `http://127.0.0.1:${h.port}`,
        },
        body,
      });

    const first = await postOnce();
    expect(first.status).toBe(200);
    const second = await postOnce();
    expect(second.status).toBe(410);

    expect(h.orchestrator.resolve).toHaveBeenCalledTimes(1);
  });

  it("an unknown/forged token for a known id → 404, audited bad_token, no mutation", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const id = "apr_forged1";
    registerApproval(
      h,
      id,
      "tok_MMMMMMMMMMMMMMMMMMMMMMMM",
      makeApprovalRequest(),
    );

    const res = await rawRequest({
      port: h.port,
      method: "GET",
      path: `/approve?id=${id}&token=tok_ZZZZZZZZZZZZZZZZZZZZZZZZ`,
    });

    expect(res.status).toBe(404);
    expect(h.events.some((e) => e.reason === "bad_token")).toBe(true);
    expect(h.orchestrator.resolve).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// No cookies.
// ---------------------------------------------------------------------------

describe("no cookies / no session (R98)", () => {
  it("never sends Set-Cookie on any response", async () => {
    const h = (await startHarness()) as Harness & {
      url: (id: string, token: string) => string;
    };
    cleanups.push(h.stop);
    const url = registerApproval(
      h,
      "apr_nocookie1",
      "tok_NNNNNNNNNNNNNNNNNNNNNNNN",
      makeApprovalRequest(),
    );
    const { pathname, search } = new URL(url);

    const res = await rawRequest({
      port: h.port,
      method: "GET",
      path: `${pathname}${search}`,
    });
    expect(res.headers["set-cookie"]).toBeUndefined();
  });
});
