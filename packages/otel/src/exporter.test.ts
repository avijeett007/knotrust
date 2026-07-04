/**
 * @knotrust/otel — attachOtelExporter() integration tests against the REAL
 * OTel SDK (P0-E8-T1; rulings R127/R130/R131). No `vi.mock` of any
 * `@opentelemetry/*` package in this file — that's deliberately confined to
 * the sibling `exporter.zero-construction.test.ts`. This file proves two
 * things end to end:
 *
 *   1. With `telemetryExport` unset, the REAL SDK is never even asked to
 *      open a socket — proven with a real `node:net`/`node:http` spy, not a
 *      mock (R131a's "spy on net/http" phrasing, taken literally).
 *   2. With a real local HTTP server standing in for an OTLP collector
 *      (R131b's "local OTLP collector fixture"), one span per decision
 *      arrives with the correct attribute set for a routine allow, a
 *      sensitive deny, and a critical pending_approval.
 */

import http from "node:http";
import net from "node:net";
import type { AuditEvent, AuditSink } from "@knotrust/store";
import { AuditEventType } from "@knotrust/store";
import { afterEach, describe, expect, it, vi } from "vitest";
import { attachOtelExporter } from "./exporter.js";

// ---------------------------------------------------------------------------
// Fake audit bus — mirrors AuditSink.onAppend's real contract exactly (a
// listener `Set`, synchronous notify) without needing a real, file-backed
// `createAuditLog()` for what is a subscriber-wiring test, not a full
// proxy/audit-log integration test (that level is covered separately at the
// CLI wiring layer).
// ---------------------------------------------------------------------------

function createFakeAuditBus(): Pick<AuditSink, "onAppend"> & {
  emit(event: AuditEvent): void;
} {
  const listeners = new Set<(event: AuditEvent) => void>();
  return {
    onAppend(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    emit(event) {
      for (const listener of listeners) listener(event);
    },
  };
}

let seqCounter = 0;

function decisionEvent(over: Partial<AuditEvent> = {}): AuditEvent {
  seqCounter += 1;
  return {
    seq: seqCounter,
    ts: new Date().toISOString(),
    prevHash: "0".repeat(64),
    hash: "1".repeat(64),
    type: AuditEventType.DECISION,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "claude-desktop",
    tool: "github.create_issue",
    argsHash: "sha256:deadbeef",
    outcome: "allow",
    ...over,
  };
}

// ---------------------------------------------------------------------------
// A tiny local HTTP server standing in for an OTLP collector (R131b).
// `@opentelemetry/exporter-trace-otlp-http` sends OTLP/HTTP as JSON by
// default (its own README: "This module provides a trace-exporter for OTLP
// (http/json)") — no protobuf decoding needed to assert on the payload.
// ---------------------------------------------------------------------------

interface CapturedRequest {
  headers: http.IncomingHttpHeaders;
  body: unknown;
}

interface CollectorFixture {
  port: number;
  requests: CapturedRequest[];
  close(): Promise<void>;
}

function startCollectorFixture(): Promise<CollectorFixture> {
  return new Promise((resolve, reject) => {
    const requests: CapturedRequest[] = [];
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        let body: unknown;
        try {
          body = JSON.parse(raw);
        } catch {
          body = raw;
        }
        requests.push({ headers: req.headers, body });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({}));
      });
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("collector fixture: failed to bind a port"));
        return;
      }
      resolve({
        port: address.port,
        requests,
        close: () =>
          new Promise((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

interface DecodedSpan {
  name: string;
  attributes: Record<string, string | number | boolean>;
  statusCode: number | undefined;
}

interface OtlpAttributeValue {
  stringValue?: string;
  intValue?: string | number;
  doubleValue?: number;
  boolValue?: boolean;
}

interface OtlpSpanJson {
  name: string;
  attributes?: Array<{ key: string; value: OtlpAttributeValue }>;
  status?: { code?: number };
}

interface OtlpExportBody {
  resourceSpans?: Array<{
    resource?: {
      attributes?: Array<{ key: string; value: OtlpAttributeValue }>;
    };
    scopeSpans?: Array<{ spans?: OtlpSpanJson[] }>;
  }>;
}

function decodeSpans(body: unknown): DecodedSpan[] {
  const parsed = body as OtlpExportBody;
  const spans: DecodedSpan[] = [];
  for (const resourceSpan of parsed.resourceSpans ?? []) {
    for (const scopeSpan of resourceSpan.scopeSpans ?? []) {
      for (const span of scopeSpan.spans ?? []) {
        const attributes: Record<string, string | number | boolean> = {};
        for (const kv of span.attributes ?? []) {
          const v = kv.value;
          if (v.stringValue !== undefined) attributes[kv.key] = v.stringValue;
          else if (v.intValue !== undefined)
            attributes[kv.key] = Number(v.intValue);
          else if (v.doubleValue !== undefined)
            attributes[kv.key] = v.doubleValue;
          else if (v.boolValue !== undefined) attributes[kv.key] = v.boolValue;
        }
        spans.push({
          name: span.name,
          attributes,
          statusCode: span.status?.code,
        });
      }
    }
  }
  return spans;
}

function serviceNameOf(body: unknown): string | undefined {
  const parsed = body as OtlpExportBody;
  for (const kv of parsed.resourceSpans?.[0]?.resource?.attributes ?? []) {
    if (kv.key === "service.name") return kv.value.stringValue;
  }
  return undefined;
}

const openHandles: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  vi.restoreAllMocks();
  while (openHandles.length > 0) {
    const handle = openHandles.pop();
    await handle?.close();
  }
});

describe("attachOtelExporter — real SDK, telemetryExport unset (R131a, no mocks)", () => {
  it("never opens a socket — real node:net/node:http spies see zero calls", async () => {
    const netConnectSpy = vi.spyOn(net, "connect");
    const httpRequestSpy = vi.spyOn(http, "request");

    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: undefined,
      audit: bus,
      serverName: "github-mcp",
    });

    // Even feeding events through — nothing is subscribed, so nothing runs.
    bus.emit(decisionEvent());

    expect(handle).toBeUndefined();
    expect(netConnectSpy).not.toHaveBeenCalled();
    expect(httpRequestSpy).not.toHaveBeenCalled();
  });
});

describe("attachOtelExporter — local OTLP collector fixture (R131b)", () => {
  it("delivers one span per decision, with the correct attribute set, for a routine allow / sensitive deny / critical pending", async () => {
    const fixture = await startCollectorFixture();
    openHandles.push(fixture);

    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: {
        enabled: true,
        endpoint: `http://127.0.0.1:${fixture.port}/v1/traces`,
        serviceName: "otel-fixture-test",
      },
      audit: bus,
      serverName: "github-mcp",
    });
    expect(handle).toBeDefined();
    openHandles.push({ close: () => handle?.close() ?? Promise.resolve() });

    bus.emit(
      decisionEvent({
        tool: "github.create_issue",
        tier: "routine",
        outcome: "allow",
        reason: "routine_default_allow",
        latencyMs: 2,
        cacheHit: true,
      }),
    );
    bus.emit(
      decisionEvent({
        tool: "stripe.create_refund",
        tier: "sensitive",
        outcome: "deny",
        reason: "no_grant_sensitive",
        latencyMs: 4,
      }),
    );
    bus.emit(
      decisionEvent({
        tool: "github.delete_repo",
        tier: "critical",
        outcome: "pending_approval",
        reason: "no_grant_critical",
        latencyMs: 1,
      }),
    );

    await handle?.flush();

    const allSpans = fixture.requests.flatMap((r) => decodeSpans(r.body));
    expect(allSpans).toHaveLength(3);

    const routine = allSpans.find(
      (s) => s.attributes["knotrust.tool"] === "github.create_issue",
    );
    expect(routine?.name).toBe("knotrust.decision");
    expect(routine?.attributes).toMatchObject({
      "knotrust.tool": "github.create_issue",
      "knotrust.server": "github-mcp",
      "knotrust.tier": "routine",
      "knotrust.outcome": "allow",
      "knotrust.reason": "routine_default_allow",
      "knotrust.cache_hit": true,
      "knotrust.latency_ms": 2,
    });
    expect(routine?.statusCode).toBe(1); // OTLP SpanStatusCode.OK = 1

    const sensitive = allSpans.find(
      (s) => s.attributes["knotrust.tool"] === "stripe.create_refund",
    );
    expect(sensitive?.attributes).toMatchObject({
      "knotrust.tier": "sensitive",
      "knotrust.outcome": "deny",
      "knotrust.reason": "no_grant_sensitive",
      "knotrust.cache_hit": false,
      "knotrust.latency_ms": 4,
    });
    expect(sensitive?.statusCode).toBe(2); // OTLP SpanStatusCode.ERROR = 2

    const critical = allSpans.find(
      (s) => s.attributes["knotrust.tool"] === "github.delete_repo",
    );
    expect(critical?.attributes).toMatchObject({
      "knotrust.tier": "critical",
      "knotrust.outcome": "pending_approval",
      "knotrust.reason": "no_grant_critical",
    });
    // pending_approval maps to UNSET (0) — neither an OK nor an ERROR verdict.
    expect(critical?.statusCode ?? 0).toBe(0);

    // The configured serviceName resource attribute is present on the export.
    expect(
      fixture.requests.some(
        (r) => serviceNameOf(r.body) === "otel-fixture-test",
      ),
    ).toBe(true);

    // Secrets hygiene: no argsHash value ever crosses the wire.
    const rawBodies = JSON.stringify(fixture.requests.map((r) => r.body));
    expect(rawBodies).not.toContain("deadbeef");
  });

  it("also delivers approval-lifecycle spans (standalone, R130)", async () => {
    const fixture = await startCollectorFixture();
    openHandles.push(fixture);

    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: {
        enabled: true,
        endpoint: `http://127.0.0.1:${fixture.port}/v1/traces`,
        serviceName: "knotrust",
      },
      audit: bus,
      serverName: "github-mcp",
    });
    openHandles.push({ close: () => handle?.close() ?? Promise.resolve() });

    bus.emit(
      decisionEvent({
        type: AuditEventType.APPROVAL_REQUESTED,
        tool: "github.delete_repo",
        approvalId: "appr_abc",
      }),
    );

    await handle?.flush();

    const spans = fixture.requests.flatMap((r) => decodeSpans(r.body));
    expect(spans).toHaveLength(1);
    expect(spans[0]?.name).toBe("knotrust.approval.requested");
    expect(spans[0]?.attributes["knotrust.approval_id"]).toBe("appr_abc");
  });

  it("also delivers security-anomaly spans end to end (R132) — fail_open_fired carries tier/tool and NEVER the raw cause text", async () => {
    const fixture = await startCollectorFixture();
    openHandles.push(fixture);

    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: {
        enabled: true,
        endpoint: `http://127.0.0.1:${fixture.port}/v1/traces`,
        serviceName: "knotrust",
      },
      audit: bus,
      serverName: "github-mcp",
    });
    openHandles.push({ close: () => handle?.close() ?? Promise.resolve() });

    bus.emit(
      decisionEvent({
        type: AuditEventType.FAIL_OPEN_FIRED,
        tool: "github.create_issue",
        tier: "routine",
        reason: JSON.stringify({
          tier: "routine",
          cause: "Error: leaked sk-live-topsecrettoken while resolving grant",
        }),
      }),
    );
    bus.emit(
      decisionEvent({
        type: AuditEventType.DENIAL_PROBING_SUSPECTED,
        tool: "stripe.create_refund",
        reason:
          '5 denials for "stripe.create_refund" by agent "claude-desktop" within 60000ms',
      }),
    );
    bus.emit(
      decisionEvent({
        type: AuditEventType.TOOL_DEFINITION_CHANGED,
        tool: "github.delete_repo",
        reason: JSON.stringify({
          server: "github-mcp",
          changeKind: "changed",
          schemaHashChanged: true,
        }),
      }),
    );

    await handle?.flush();

    const spans = fixture.requests.flatMap((r) => decodeSpans(r.body));
    expect(spans).toHaveLength(3);

    const failOpen = spans.find(
      (s) => s.name === "knotrust.security.fail_open_fired",
    );
    expect(failOpen).toBeDefined();
    expect(failOpen?.attributes).toMatchObject({
      "knotrust.tool": "github.create_issue",
      "knotrust.server": "github-mcp",
      "knotrust.tier": "routine",
      "knotrust.reason": "fail_open_recovery",
    });
    expect(failOpen?.statusCode).toBe(2); // OTLP SpanStatusCode.ERROR = 2

    const probing = spans.find(
      (s) => s.name === "knotrust.security.denial_probing_suspected",
    );
    expect(probing?.attributes["knotrust.tool"]).toBe("stripe.create_refund");

    const drift = spans.find(
      (s) => s.name === "knotrust.security.tool_definition_changed",
    );
    expect(drift?.attributes["knotrust.tool"]).toBe("github.delete_repo");

    // Secrets hygiene: fail_open_fired's raw cause text (and any token-like
    // substring it might have carried) never crosses the wire.
    const rawBodies = JSON.stringify(fixture.requests.map((r) => r.body));
    expect(rawBodies).not.toContain("sk-live-topsecrettoken");
    expect(rawBodies).not.toContain("leaked");
  });

  it("close() unsubscribes from the audit bus — events after close() produce no further spans", async () => {
    const fixture = await startCollectorFixture();
    openHandles.push(fixture);

    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: {
        enabled: true,
        endpoint: `http://127.0.0.1:${fixture.port}/v1/traces`,
        serviceName: "knotrust",
      },
      audit: bus,
      serverName: "github-mcp",
    });

    await handle?.close();
    bus.emit(decisionEvent());

    // Give any (unwanted) async export a moment to have arrived, if it were
    // going to — then assert it did not.
    await new Promise((r) => setTimeout(r, 50));
    expect(fixture.requests).toHaveLength(0);
  });
});
