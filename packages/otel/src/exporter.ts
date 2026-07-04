/**
 * @knotrust/otel — attachOtelExporter() (P0-E8-T1; rulings R127/R128/R130/R131).
 *
 * The one function this package exists to provide: a SUBSCRIBER on the audit
 * event stream (R127) that maps `AuditEvent`s to OTel spans and ships them via
 * OTLP/HTTP. See `../src/index.ts`'s module header for the full "this is
 * telemetry-EXPORT, not product telemetry" doctrine (the verbatim R128
 * statement lives there, not duplicated here).
 *
 * ## The off-by-default gate (R128) — read this before touching this function
 *
 * `attachOtelExporter` returns `undefined` — constructing and subscribing
 * NOTHING — unless `config !== undefined && config.enabled === true`. That
 * one `if` at the top is the ENTIRE mechanism behind "with export unset, zero
 * telemetry sockets/constructors" (R131a): no `OTLPTraceExporter`, no
 * `NodeTracerProvider`, no `BatchSpanProcessor` is ever `new`'d, and
 * `audit.onAppend` is never called, so the audit sink's listener set stays
 * empty and this module's mapping/export code never runs for a single event.
 * `exporter.zero-construction.test.ts` proves this by constructor call count
 * (mocked); `exporter.test.ts` proves it again against the REAL SDK with a
 * `node:net`/`node:http` spy.
 *
 * ## Lazy-loaded, not just lazily-constructed (fix round 1, Minor — perf/
 * privacy-story)
 *
 * All four `@opentelemetry/*` packages are imported with a dynamic
 * `await import()` INSIDE the `enabled === true` branch below, not as static
 * top-level imports. `@knotrust/otel` is inlined into the published CLI bundle
 * (tsup `noExternal`, `tsup.config.ts`), so a static top-level import of these
 * (external, but still eagerly-`import`ed) packages would resolve and
 * evaluate all four from disk on EVERY `knotrust` invocation — including
 * `--help` and every subcommand that never touches enforcement — regardless
 * of `telemetryExport`. That is a real startup-latency tax on the ~99% of
 * invocations that never export, and it is strictly MORE than R131a's
 * "zero constructors" promises: those packages would be loaded and evaluated
 * (module-level side effects included) even though nothing is ever
 * constructed. Gating the `import()` itself behind the exact same `if` that
 * already gates construction means the disabled path now loads NOTHING
 * either — the strongest form of "zero cost when off." See
 * `exporter.zero-construction.test.ts`'s module-load-count assertions for the
 * test proving this (as distinct from the pre-existing constructor-call-count
 * proof, which only showed nothing was BUILT, not that nothing was LOADED).
 *
 * ## Subscriber pattern, not a core hook (R127)
 *
 * This function takes `audit: Pick<AuditSink, "onAppend">` — the READ-ONLY
 * subscribe capability, not the full sink — and never touches
 * `@knotrust/core`, `@knotrust/grants`, or `@knotrust/proxy-stdio` at all.
 * Enabling/disabling this exporter is therefore, BY CONSTRUCTION, a change
 * with zero code-path impact on the decision/enforcement pipeline: it
 * consumes events the decider/enforcer ALREADY write to the audit log for
 * their own reasons, on a side channel that either has zero listeners (off)
 * or one (on) — the decider and enforcer cannot tell the difference either
 * way (R131c).
 *
 * ## Span construction: retroactive, not live (batched, real-time export)
 *
 * Every audit event has ALREADY happened by the time this subscriber sees it
 * — there is no "in-flight decision" to attach a live span to. So this
 * builds each span with an explicit `startTime`/`endTime` reconstructed from
 * the event's own `ts` (+ `latencyMs` for decisions — see `span-mapper.ts`),
 * then `.end()`s it immediately. The SPAN PROCESSOR (a `BatchSpanProcessor`)
 * still batches the resulting ALREADY-ENDED spans for efficient export, the
 * same as it would for live spans — "retroactive" describes how the span's
 * own timestamps are derived, not how/when it reaches the collector.
 *
 * ## Bounded shutdown (why `close()` can't use the SDK's own defaults)
 *
 * A `knotrust -- <server>` proxy process is normally SESSION-SCOPED — it
 * exits shortly after the client disconnects (`enforcement.ts`'s `close()`
 * runs from that exact teardown path, and `bin.ts` calls `process.exit`
 * right after). If this exporter's shutdown used the OTel SDK's own
 * defaults (`OTLPExporterConfigBase.timeoutMillis`: 10000ms;
 * `TracerProviderOptions.forceFlushTimeoutMillis`: 30000ms), an unreachable
 * or slow collector would make EVERY proxy exit hang for up to 30 SECONDS —
 * turning a broken `telemetryExport.endpoint` into a availability bug for
 * the whole product, not just a missing nice-to-have. `SHUTDOWN_TIMEOUT_MS`
 * below caps both knobs at a much shorter, still generous-for-a-healthy-
 * collector bound, so a bad endpoint costs at most a few seconds of extra
 * shutdown latency — bounded and documented, never indefinite.
 */

import type {
  AuditEvent,
  AuditSink,
  TelemetryExportConfig,
} from "@knotrust/store";
// `import type` only — erased entirely at compile time (no runtime import,
// no module load), unlike the four `@opentelemetry/*` VALUE imports below,
// which are deliberately NOT imported here at all — see the module header,
// "Lazy-loaded, not just lazily-constructed," and `attachOtelExporter`'s own
// `await import()` calls inside its `enabled === true` branch.
import type { Tracer } from "@opentelemetry/api";
import {
  type MapContext,
  type MappedSpan,
  mapAuditEventToSpan,
} from "./span-mapper.js";

export interface AttachOtelExporterOptions {
  /**
   * `config.telemetryExport` exactly as `@knotrust/store`'s
   * `KnotrustConfigSchema` parsed it — `undefined` when the config file
   * never declared the key at all (the overwhelmingly common case: R128's
   * "off by default"). By the time this function sees `enabled: true`, the
   * schema has ALREADY guaranteed `endpoint` is a non-empty string (R129's
   * `.superRefine()`) — the runtime check below is defense in depth only.
   */
  config: TelemetryExportConfig | undefined;
  /** The subscribe-only capability — never the full `AuditSink` (R127: this is a subscriber, not a co-owner of the log). */
  audit: Pick<AuditSink, "onAppend">;
  /**
   * The ONE MCP server this proxy instance fronts for its entire lifetime
   * (`buildEnforcement`'s already-resolved `serverName`) — supplied here,
   * NOT read off each `AuditEvent` (which carries no server field; see
   * `span-mapper.ts`'s module header, "Deviations" section).
   */
  serverName: string;
}

/** See module header, "Bounded shutdown" — caps both the OTLP HTTP request timeout and the tracer provider's forceFlush timeout, so a slow/unreachable collector can never hang a proxy exit for the SDK's own (10s/30s) defaults. */
const SHUTDOWN_TIMEOUT_MS = 5000;

export interface OtelExporterHandle {
  /** Forces any buffered spans to export now. Mostly for tests / graceful shutdown; production callers rarely need this. */
  flush(): Promise<void>;
  /** Unsubscribes from the audit stream and shuts the tracer provider (and its exporter) down, flushing any pending spans first. */
  close(): Promise<void>;
}

/**
 * Constructs (ONLY when configured — see module header) an OTel
 * `NodeTracerProvider` + `OTLPTraceExporter`, subscribes it to `audit`'s
 * append stream, and maps every `AuditEvent` the mapper recognizes
 * (`span-mapper.ts`) into a span. Returns `undefined` when
 * `telemetryExport` is absent or `enabled` is not `true` — see the module
 * header for why that single branch is the whole R128 contract.
 *
 * **`async`** (fix round 1, Minor — perf/privacy-story): the four
 * `@opentelemetry/*` packages are loaded with a dynamic `await import()`
 * INSIDE the `enabled === true` branch below, not as static top-level
 * imports — see the module header, "Lazy-loaded, not just
 * lazily-constructed." The disabled path (the overwhelmingly common case)
 * still returns/resolves immediately having loaded, constructed, and
 * subscribed NOTHING. Callers (`@knotrust/cli`'s `buildEnforcement`, already
 * an `async` function) must `await` this call.
 */
export async function attachOtelExporter(
  options: AttachOtelExporterOptions,
): Promise<OtelExporterHandle | undefined> {
  const { config, audit, serverName } = options;

  if (config === undefined || config.enabled !== true) {
    return undefined;
  }

  const endpoint = config.endpoint;
  if (endpoint === undefined || endpoint.trim() === "") {
    // Unreachable from any real `knotrust.config.*` (R129's `.superRefine()`
    // rejects `enabled: true` with no endpoint at load time) — defense in
    // depth so this function stays total/safe if ever called with a
    // hand-built config rather than one that passed through
    // `@knotrust/store`'s validated loader.
    throw new Error(
      "knotrust: telemetryExport.enabled is true but telemetryExport.endpoint is missing " +
        "(this should have been caught by config validation — see @knotrust/store's KnotrustConfigSchema)",
    );
  }

  // Lazy-loaded HERE, not at module top level (fix round 1, Minor — see
  // module header): only reached once `enabled === true` is already known,
  // so the disabled path (the ~99% default) never resolves or evaluates any
  // of these four packages at all — strictly stronger than R131a's
  // "zero constructors," now also "zero module loads."
  const [otelApi, otlpHttp, otelResources, sdkTraceNode] = await Promise.all([
    import("@opentelemetry/api"),
    import("@opentelemetry/exporter-trace-otlp-http"),
    import("@opentelemetry/resources"),
    import("@opentelemetry/sdk-trace-node"),
  ]);
  const { SpanKind, SpanStatusCode } = otelApi;
  const { OTLPTraceExporter } = otlpHttp;
  const { resourceFromAttributes } = otelResources;
  const { BatchSpanProcessor, NodeTracerProvider } = sdkTraceNode;

  const serviceName = config.serviceName ?? "knotrust";
  const resource = resourceFromAttributes({ "service.name": serviceName });
  const otlpExporter = new OTLPTraceExporter({
    url: endpoint,
    timeoutMillis: SHUTDOWN_TIMEOUT_MS,
    ...(config.headers !== undefined ? { headers: config.headers } : {}),
  });
  const spanProcessor = new BatchSpanProcessor(otlpExporter);
  const provider = new NodeTracerProvider({
    resource,
    spanProcessors: [spanProcessor],
    forceFlushTimeoutMillis: SHUTDOWN_TIMEOUT_MS,
  });
  const tracer: Tracer = provider.getTracer("@knotrust/otel");

  const mapContext: MapContext = { serverName };

  function handleAppend(event: AuditEvent): void {
    const mapped = mapAuditEventToSpan(event, mapContext);
    if (mapped === undefined) return;
    applyMappedSpan(tracer, mapped, SpanKind, SpanStatusCode);
  }

  const unsubscribe = audit.onAppend(handleAppend);

  return {
    async flush(): Promise<void> {
      await raceAgainstTimeout(provider.forceFlush());
    },
    async close(): Promise<void> {
      unsubscribe();
      await raceAgainstTimeout(provider.shutdown());
    },
  };
}

/**
 * Defense in depth on top of `OTLPExporterConfigBase.timeoutMillis` /
 * `TracerProviderOptions.forceFlushTimeoutMillis` (both already set to
 * `SHUTDOWN_TIMEOUT_MS` above): races the given promise against an
 * independent timer of the SAME bound, so a proxy exit is guaranteed to
 * proceed after `SHUTDOWN_TIMEOUT_MS` even in an edge case neither SDK knob
 * fully covers (e.g. TCP connection establishment hanging before the
 * request-level timeout would even start counting). A timeout here means
 * "give up waiting," not "cancel the underlying operation" — the SDK's own
 * shutdown/flush continues in the background; this function's caller
 * (`close()`) simply stops blocking process exit on it.
 */
function raceAgainstTimeout(promise: Promise<void>): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, SHUTDOWN_TIMEOUT_MS);
    timer.unref?.();
    promise.then(
      () => {
        clearTimeout(timer);
        resolve();
      },
      () => {
        clearTimeout(timer);
        resolve();
      },
    );
  });
}

/**
 * Turns a pure `MappedSpan` descriptor into a real, already-ended OTel span.
 *
 * `spanKind`/`spanStatusCode` are the live `SpanKind`/`SpanStatusCode` enum
 * objects from the dynamically-`import()`ed `@opentelemetry/api` (see
 * `attachOtelExporter` above) — passed in rather than imported at this
 * module's top level, so this helper carries no static `@opentelemetry/*`
 * value import of its own (only the type-only `Tracer` import survives,
 * which the module header explains is compile-time-only and therefore
 * free). The type-only `typeof import(...)` queries below are likewise
 * erased at compile time — no runtime import.
 */
function applyMappedSpan(
  tracer: Tracer,
  mapped: MappedSpan,
  spanKind: typeof import("@opentelemetry/api").SpanKind,
  spanStatusCode: typeof import("@opentelemetry/api").SpanStatusCode,
): void {
  const span = tracer.startSpan(mapped.name, {
    kind: spanKind.INTERNAL,
    startTime: mapped.startTimeMs,
    attributes: mapped.attributes,
  });
  if (mapped.status !== "unset") {
    span.setStatus({
      code:
        mapped.status === "error" ? spanStatusCode.ERROR : spanStatusCode.OK,
    });
  }
  span.end(mapped.endTimeMs);
}
