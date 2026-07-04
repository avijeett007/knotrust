/**
 * @knotrust/otel — OpenTelemetry OTLP/HTTP exporter for decision spans and
 * audit events (P0-E8-T1; rulings R127–R131).
 *
 * ## This is telemetry-EXPORT, categorically NOT product telemetry (R128)
 *
 * **KnoTrust has NO product telemetry / phone-home / usage analytics — ever
 * (PRD §11). `telemetryExport` is a user-controlled export of the USER'S OWN
 * audit stream to the USER'S OWN OTLP collector; it is off by default and
 * makes no external call unless the user configures an endpoint.**
 *
 * (That paragraph is stated verbatim in three places — this module header,
 * `@knotrust/store`'s `TelemetryExportConfigSchema` doc-comment, and
 * `docs/02-architecture/system-architecture.md` §9.2 — by design: R128
 * requires the distinction be documented verbatim, and a single canonical
 * sentence repeated exactly, rather than paraphrased three different ways,
 * is what makes "verbatim" a checkable property instead of a vibe.)
 *
 * Concretely: this package never opens a network connection, never
 * constructs an OTel exporter, and never subscribes to anything, unless the
 * user's own `knotrust.config.*` sets `telemetryExport.enabled: true` AND a
 * concrete `telemetryExport.endpoint` — see `attachOtelExporter`'s own
 * doc-comment for exactly which one `if` enforces that, and
 * `exporter.zero-construction.test.ts` / `exporter.test.ts` for the tests
 * that prove it (by constructor call count, and by a real `node:net`/
 * `node:http` spy, respectively).
 *
 * ## Architecture: a SUBSCRIBER on the audit stream, not a core hook (R127)
 *
 * This package is wired in as an OPTIONAL, PURELY-ADDITIVE listener on
 * `@knotrust/store`'s `AuditSink.onAppend` — it consumes the exact same
 * `AuditEvent`s the sink already writes to `~/.knotrust/audit/*.jsonl` for
 * every decision/approval-lifecycle event, and maps them to OTel spans
 * (`span-mapper.ts`). It does NOT hook into `@knotrust/core`,
 * `@knotrust/grants`, or `@knotrust/proxy-stdio` — enabling or disabling
 * this exporter changes no code path in any of those packages (R131c: "the
 * decider/enforce code is byte-identical"). The CLI (`packages/cli/src/
 * enforcement.ts`) is the only wiring point: it calls `attachOtelExporter`
 * unconditionally, and that function itself decides — from `config.
 * telemetryExport` alone — whether to construct anything at all.
 *
 * ## Secrets hygiene: never raw arguments or tokens
 *
 * `AuditEvent` already only ever carries `argsHash` (a one-way SHA-256 hash,
 * or the literal `"unavailable"`), never raw call arguments, by
 * construction — this package inherits that safety for free (see
 * `@knotrust/store`'s `audit-log.ts` for the "raw args never appear in the
 * log by default" contract). `span-mapper.ts`'s attribute set does not
 * include `argsHash` (or anything derived from it) at all — see its own
 * "never leaks raw arguments" test.
 *
 * ## Span mapping (R130, extended by R132)
 *
 * Every `type: "decision"` audit event → one `knotrust.decision` span, with
 * attributes `knotrust.tool`/`server`/`tier`/`outcome`/`reason`/`cache_hit`/
 * `latency_ms`/`seq`/`subject`/`agent`. The six approval-lifecycle event
 * types → their own standalone `knotrust.approval.<phase>` span each. Five
 * SECURITY-ANOMALY event types (`fail_open_fired`, `denial_probing_suspected`,
 * `tool_definition_changed`, `approval_channel_violation`, `probe_flagged`,
 * R132) → their own standalone `knotrust.security.<type>` span each — see
 * this package's dogfood dashboard's "Fail-open firings" panel, the
 * motivating consumer. See `span-mapper.ts`'s module header for the full
 * mapping contract and its documented P0 scope limits/deviations.
 */
export const PKG = "@knotrust/otel";

export type {
  AttachOtelExporterOptions,
  OtelExporterHandle,
} from "./exporter.js";
export { attachOtelExporter } from "./exporter.js";
export type {
  MapContext,
  MappedSpan,
  MappedSpanAttributeValue,
  MappedSpanStatus,
} from "./span-mapper.js";
export {
  APPROVAL_SPAN_NAME_PREFIX,
  DECISION_SPAN_NAME,
  mapAuditEventToSpan,
  SECURITY_SPAN_NAME_PREFIX,
} from "./span-mapper.js";
