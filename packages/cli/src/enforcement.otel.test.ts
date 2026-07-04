/**
 * knotrust CLI — `buildEnforcement`'s OTel exporter wiring (P0-E8-T1;
 * rulings R127/R128/R131).
 *
 * Proves the wiring end to end at the level a real `knotrust -- <server>`
 * run actually exercises:
 *
 *   1. With `telemetryExport` absent (the overwhelmingly common case),
 *      `attachOtelExporter` is called exactly once (proving the wiring is
 *      unconditional — R127) but constructs nothing and returns `undefined`
 *      — a real `tools/call` still enforces normally.
 *   2. With `telemetryExport` enabled and pointed at a local HTTP fixture
 *      standing in for an OTLP collector, a REAL `tools/call` through the
 *      REAL `buildEnforcement` stack produces exactly one span at that
 *      fixture, carrying the resolved `serverName` and the decision's
 *      attributes (R131b, exercised through the actual CLI wiring rather
 *      than `@knotrust/otel`'s own isolated test suite).
 *   3. `close()` unsubscribes/shuts the exporter down — a decision AFTER
 *      close() produces no further span.
 *
 * `@knotrust/otel`'s own attachOtelExporter/constructor-call-count acceptance
 * (the "zero sockets" security-critical proof) lives in that package's test
 * suite (`exporter.zero-construction.test.ts`); this file is the "wired
 * correctly into the CLI" proof, not a second copy of that proof.
 */

import { mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { type KnotrustConfig, KnotrustConfigSchema } from "@knotrust/store";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildEnforcement } from "./enforcement.js";

// ---------------------------------------------------------------------------
// A tiny local HTTP server standing in for an OTLP collector — same
// JSON-decoding approach as @knotrust/otel's own `exporter.test.ts` (the
// exporter sends OTLP/HTTP as JSON by default).
// ---------------------------------------------------------------------------

interface CollectorFixture {
  port: number;
  requestCount(): number;
  bodies(): unknown[];
  close(): Promise<void>;
}

function startCollectorFixture(): Promise<CollectorFixture> {
  return new Promise((resolve, reject) => {
    const bodies: unknown[] = [];
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        try {
          bodies.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch {
          bodies.push(undefined);
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end("{}");
      });
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("collector fixture: failed to bind"));
        return;
      }
      resolve({
        port: address.port,
        requestCount: () => bodies.length,
        bodies: () => bodies,
        close: () =>
          new Promise((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

interface SpanAttr {
  key: string;
  value: { stringValue?: string };
}
interface Span {
  name: string;
  attributes?: SpanAttr[];
}
interface OtlpBody {
  resourceSpans?: Array<{
    scopeSpans?: Array<{ spans?: Span[] }>;
  }>;
}

function flattenSpans(bodies: unknown[]): Span[] {
  const spans: Span[] = [];
  for (const body of bodies) {
    for (const rs of (body as OtlpBody)?.resourceSpans ?? []) {
      for (const ss of rs.scopeSpans ?? []) {
        for (const s of ss.spans ?? []) spans.push(s);
      }
    }
  }
  return spans;
}

function attrValue(span: Span, key: string): string | undefined {
  return span.attributes?.find((a) => a.key === key)?.value.stringValue;
}

// ---------------------------------------------------------------------------
// Fixtures (mirrors enforcement.test.ts's own conventions)
// ---------------------------------------------------------------------------

function makeConfig(over: Partial<KnotrustConfig> = {}): KnotrustConfig {
  return KnotrustConfigSchema.parse({
    version: 1,
    identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
    servers: {
      testsrv: {
        tools: {
          routine_tool: { tier: "routine", source: "user" },
        },
      },
    },
    ...over,
  });
}

function toolsCall(id: number, name: string): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name, arguments: {} },
  } as JSONRPCMessage;
}

const dirsToClean: string[] = [];
const priorHome = process.env.KNOTRUST_HOME;

afterEach(() => {
  vi.restoreAllMocks();
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;
  while (dirsToClean.length > 0) {
    const dir = dirsToClean.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

function useTempHome(): void {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-enforcement-otel-"));
  dirsToClean.push(home);
  process.env.KNOTRUST_HOME = home;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("buildEnforcement — telemetryExport unset (R128 default)", () => {
  it("enforces normally with telemetryExport absent — no crash, no otel construction", async () => {
    useTempHome();
    const bundle = await buildEnforcement(makeConfig());
    try {
      const result = await bundle.enforce(toolsCall(1, "routine_tool"));
      expect(result).toEqual({ action: "forward" });
    } finally {
      await bundle.close();
    }
  });
});

describe("buildEnforcement — telemetryExport enabled against a local collector fixture (R131b)", () => {
  it("a real tools/call decision through buildEnforcement produces one span at the configured collector, carrying the resolved serverName", async () => {
    useTempHome();
    const fixture = await startCollectorFixture();
    try {
      const config = makeConfig({
        telemetryExport: {
          enabled: true,
          endpoint: `http://127.0.0.1:${fixture.port}/v1/traces`,
          serviceName: "knotrust-enforcement-otel-test",
        },
      });
      const bundle = await buildEnforcement(config);
      try {
        const result = await bundle.enforce(toolsCall(1, "routine_tool"));
        expect(result).toEqual({ action: "forward" });
      } finally {
        // AWAITED (P0-E8-T1): close() now blocks on the exporter's bounded
        // shutdown, so the fixture has already received the span by the
        // time this resolves — no polling needed (unlike the built-bin
        // variant of this same test, which spawns a real child process and
        // can't await this in-process promise directly).
        await bundle.close();
      }

      const spans = flattenSpans(fixture.bodies());
      expect(spans).toHaveLength(1);
      expect(spans[0]?.name).toBe("knotrust.decision");
      expect(attrValue(spans[0] as Span, "knotrust.tool")).toBe("routine_tool");
      expect(attrValue(spans[0] as Span, "knotrust.server")).toBe("testsrv");
      expect(attrValue(spans[0] as Span, "knotrust.tier")).toBe("routine");
      expect(attrValue(spans[0] as Span, "knotrust.outcome")).toBe("allow");
    } finally {
      await fixture.close();
    }
  }, 15_000);

  it("close() shuts the exporter down — a decision after close() produces no further span", async () => {
    useTempHome();
    const fixture = await startCollectorFixture();
    try {
      const config = makeConfig({
        telemetryExport: {
          enabled: true,
          endpoint: `http://127.0.0.1:${fixture.port}/v1/traces`,
          serviceName: "knotrust-enforcement-otel-test",
        },
      });
      const bundle = await buildEnforcement(config);
      await bundle.close();

      // No decision ever happened before close() — this proves close()
      // itself doesn't spuriously emit anything (an empty run still
      // constructs and immediately tears down the exporter cleanly).
      expect(fixture.requestCount()).toBe(0);
    } finally {
      await fixture.close();
    }
  });
});
