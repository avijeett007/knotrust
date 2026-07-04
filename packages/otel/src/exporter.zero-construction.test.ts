/**
 * @knotrust/otel — attachOtelExporter() "off by default" acceptance
 * (P0-E8-T1; rulings R127/R128/R131a — the SECURITY-CRITICAL acceptance).
 *
 * Mocks `@opentelemetry/exporter-trace-otlp-http` and
 * `@opentelemetry/sdk-trace-node` (same `vi.mock` technique as
 * `audit-log.fault-injection.test.ts`'s `node:fs` mock) so this file can
 * assert, by CONSTRUCTOR CALL COUNT, that with `telemetryExport`
 * unset/disabled, `attachOtelExporter` builds NOTHING: no `OTLPTraceExporter`,
 * no `NodeTracerProvider`, no `BatchSpanProcessor` — which is exactly what
 * "zero telemetry sockets opened" reduces to, since none of those classes are
 * ever instantiated to open one. The REAL (unmocked) SDK's own
 * network-touching behavior — and a real-network local-collector fixture
 * proving spans DO arrive when configured — lives in the sibling
 * `exporter.test.ts`, which never mocks these modules; this file is the one
 * negative-space acceptance, kept in its own file so mocking doesn't leak
 * into (or accidentally weaken) that positive-path suite.
 *
 * Fix round 1 (Minor — perf/privacy-story): `attachOtelExporter` now
 * `import()`s all four `@opentelemetry/*` packages lazily, INSIDE its
 * `enabled === true` branch, rather than as static top-level imports — see
 * `exporter.ts`'s module header. The four `vi.mock` factories below each
 * increment a `*ModuleLoadCount` counter on first evaluation — since a
 * `vi.mock`ed (or real) ES module's factory/body runs exactly once, the
 * FIRST time anything (static or dynamic) imports that specifier, these
 * counts are a direct proxy for "was this module ever loaded at all,"
 * strictly stronger than the constructor-call-count assertions above them
 * (a module can be loaded/evaluated without any of its classes ever being
 * `new`'d). The "ZERO construction" describe block below now also asserts
 * ZERO module loads; the final "contrast case" test asserts loads DO happen
 * once `enabled: true` is reached, proving the counters themselves are live.
 */

import type { AuditEvent, AuditSink } from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const otelMocks = vi.hoisted(() => ({
  otlpCtorCalls: [] as unknown[][],
  providerCtorCalls: [] as unknown[][],
  batchCtorCalls: [] as unknown[][],
  apiModuleLoadCount: 0,
  otlpModuleLoadCount: 0,
  resourcesModuleLoadCount: 0,
  sdkTraceNodeModuleLoadCount: 0,
}));

// Real pass-through (via `importOriginal`) for the two packages this file
// doesn't otherwise need to fake — `SpanKind`/`SpanStatusCode`/
// `resourceFromAttributes` stay fully functional; only the load itself is
// counted, proving these are lazy too, not just the two SDK classes below.
vi.mock("@opentelemetry/api", async (importOriginal) => {
  otelMocks.apiModuleLoadCount += 1;
  return importOriginal();
});

vi.mock("@opentelemetry/resources", async (importOriginal) => {
  otelMocks.resourcesModuleLoadCount += 1;
  return importOriginal();
});

vi.mock("@opentelemetry/exporter-trace-otlp-http", () => {
  otelMocks.otlpModuleLoadCount += 1;
  return {
    OTLPTraceExporter: class {
      constructor(...args: unknown[]) {
        otelMocks.otlpCtorCalls.push(args);
      }
    },
  };
});

vi.mock("@opentelemetry/sdk-trace-node", () => {
  otelMocks.sdkTraceNodeModuleLoadCount += 1;
  return {
    NodeTracerProvider: class {
      constructor(...args: unknown[]) {
        otelMocks.providerCtorCalls.push(args);
      }
      getTracer(): unknown {
        return { startSpan: vi.fn() };
      }
      forceFlush(): Promise<void> {
        return Promise.resolve();
      }
      shutdown(): Promise<void> {
        return Promise.resolve();
      }
    },
    BatchSpanProcessor: class {
      constructor(...args: unknown[]) {
        otelMocks.batchCtorCalls.push(args);
      }
    },
  };
});

// Imported AFTER the mocks above so `exporter.ts`'s own static imports of
// these two packages resolve to the mocked classes (vitest hoists `vi.mock`
// calls above imports at transform time regardless of source order, but the
// dynamic `import()` below makes the ordering explicit and unambiguous too).
const { attachOtelExporter } = await import("./exporter.js");

function createFakeAuditBus(): Pick<AuditSink, "onAppend"> & {
  subscriberCount(): number;
} {
  const listeners = new Set<(event: AuditEvent) => void>();
  return {
    onAppend(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    subscriberCount: () => listeners.size,
  };
}

beforeEach(() => {
  otelMocks.otlpCtorCalls.length = 0;
  otelMocks.providerCtorCalls.length = 0;
  otelMocks.batchCtorCalls.length = 0;
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("attachOtelExporter — telemetryExport unset/disabled ⇒ ZERO construction (R128)", () => {
  it("config: undefined ⇒ returns undefined, constructs nothing, subscribes to nothing, LOADS NOTHING", async () => {
    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: undefined,
      audit: bus,
      serverName: "github-mcp",
    });

    expect(handle).toBeUndefined();
    expect(otelMocks.otlpCtorCalls).toHaveLength(0);
    expect(otelMocks.providerCtorCalls).toHaveLength(0);
    expect(otelMocks.batchCtorCalls).toHaveLength(0);
    expect(bus.subscriberCount()).toBe(0);
    // Fix round 1 (Minor): not merely unconstructed — never even `import()`ed.
    expect(otelMocks.apiModuleLoadCount).toBe(0);
    expect(otelMocks.otlpModuleLoadCount).toBe(0);
    expect(otelMocks.resourcesModuleLoadCount).toBe(0);
    expect(otelMocks.sdkTraceNodeModuleLoadCount).toBe(0);
  });

  it("config: {enabled: false} (the schema default) ⇒ constructs nothing, loads nothing", async () => {
    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: { enabled: false, serviceName: "knotrust" },
      audit: bus,
      serverName: "github-mcp",
    });

    expect(handle).toBeUndefined();
    expect(otelMocks.otlpCtorCalls).toHaveLength(0);
    expect(otelMocks.providerCtorCalls).toHaveLength(0);
    expect(otelMocks.batchCtorCalls).toHaveLength(0);
    expect(bus.subscriberCount()).toBe(0);
    expect(otelMocks.apiModuleLoadCount).toBe(0);
    expect(otelMocks.otlpModuleLoadCount).toBe(0);
    expect(otelMocks.resourcesModuleLoadCount).toBe(0);
    expect(otelMocks.sdkTraceNodeModuleLoadCount).toBe(0);
  });

  it("config: {enabled: false, endpoint: <set>} ⇒ STILL constructs nothing and loads nothing — enabled is the sole gate, a stray endpoint is inert", async () => {
    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: {
        enabled: false,
        endpoint: "https://a-real-looking-collector.example.com/v1/traces",
        serviceName: "knotrust",
      },
      audit: bus,
      serverName: "github-mcp",
    });

    expect(handle).toBeUndefined();
    expect(otelMocks.otlpCtorCalls).toHaveLength(0);
    expect(otelMocks.providerCtorCalls).toHaveLength(0);
    expect(otelMocks.batchCtorCalls).toHaveLength(0);
    expect(bus.subscriberCount()).toBe(0);
    expect(otelMocks.apiModuleLoadCount).toBe(0);
    expect(otelMocks.otlpModuleLoadCount).toBe(0);
    expect(otelMocks.resourcesModuleLoadCount).toBe(0);
    expect(otelMocks.sdkTraceNodeModuleLoadCount).toBe(0);
  });

  it("the four @opentelemetry/* modules are STILL never loaded after repeated disabled calls — not a one-shot fluke of the tests above", async () => {
    const bus = createFakeAuditBus();
    await attachOtelExporter({
      config: undefined,
      audit: bus,
      serverName: "s",
    });
    await attachOtelExporter({
      config: { enabled: false, serviceName: "knotrust" },
      audit: bus,
      serverName: "s",
    });

    expect(otelMocks.apiModuleLoadCount).toBe(0);
    expect(otelMocks.otlpModuleLoadCount).toBe(0);
    expect(otelMocks.resourcesModuleLoadCount).toBe(0);
    expect(otelMocks.sdkTraceNodeModuleLoadCount).toBe(0);
  });

  it("config: {enabled: true, endpoint: ...} ⇒ (contrast case) DOES construct AND load — proving the mock/counter setup itself is live, not just silently no-op", async () => {
    const bus = createFakeAuditBus();
    const handle = await attachOtelExporter({
      config: {
        enabled: true,
        endpoint: "https://collector.example.com/v1/traces",
        serviceName: "knotrust",
      },
      audit: bus,
      serverName: "github-mcp",
    });

    expect(handle).toBeDefined();
    expect(otelMocks.otlpCtorCalls).toHaveLength(1);
    expect(otelMocks.providerCtorCalls).toHaveLength(1);
    expect(otelMocks.batchCtorCalls).toHaveLength(1);
    expect(bus.subscriberCount()).toBe(1);
    // Only now — once `enabled: true` is actually reached — do the four
    // `@opentelemetry/*` modules get `import()`ed at all (ESM caches each
    // module's factory to run exactly once, so this is `1`, not merely
    // `>= 1`, even though the mocked two are also independently proven
    // constructed above).
    expect(otelMocks.apiModuleLoadCount).toBe(1);
    expect(otelMocks.otlpModuleLoadCount).toBe(1);
    expect(otelMocks.resourcesModuleLoadCount).toBe(1);
    expect(otelMocks.sdkTraceNodeModuleLoadCount).toBe(1);
  });
});
