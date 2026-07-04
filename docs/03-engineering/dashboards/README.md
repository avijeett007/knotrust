# KnoTrust dashboards

## `knotrust-dogfood.dashboard.json`

The P0-E8-T2 SigNoz dogfood dashboard. Built against the spans and attributes
the P0-E8-T1 OTLP/HTTP audit-stream exporter (`packages/otel`) actually
emits — every panel below names the exact source it queries, so this file
stays independently verifiable (see "Verifying this file" below).

### Importing it

1. Point the exporter at your reference SigNoz instance: set
   `telemetryExport.enabled: true` and `telemetryExport.endpoint` in your
   `knotrust.config.*` (see `packages/store/src/config.ts`'s
   `TelemetryExportConfigSchema`, and `docs/02-architecture/system-architecture.md`
   §9.2 — this is telemetry-**export** of your own audit stream to your own
   collector, never product telemetry; it is off by default).
2. In the SigNoz UI: **Dashboards → New Dashboard → Import JSON**, and paste
   the contents of `knotrust-dogfood.dashboard.json`.
3. This file mirrors the request body shape of SigNoz's own
   `POST /api/v1/dashboards` (title/description/tags/layout/widgets/variables
   at the top level) — the same shape this repo's SigNoz MCP integration's
   `signoz_create_dashboard` tool accepts, and the shape a dashboard's own
   `data` field holds once created. **SigNoz-version assumption**: authored
   against SigNoz's "Query Builder v5" query envelope (`schemaVersion: v1`
   composite queries, `attributes_string`/`attributes_number`/
   `attributes_bool` maps on `signoz_index_v3`), as documented by this
   repo's own reference SigNoz MCP server at the time this file was written
   (2026-07). If your SigNoz instance is on an older query-builder version,
   the "Import JSON" step may need the payload wrapped differently, or the
   ClickHouse SQL panel (see below) may need column-name touch-ups — the
   in-app dashboard editor will tell you immediately if a widget fails to
   hydrate.
4. A `service_name` dashboard variable is included, defaulting to **ALL**
   services (no filter) — narrow it once you've confirmed your deployment's
   configured `telemetryExport.serviceName` (default `"knotrust"`).

### Panels, and exactly what they query

All six panels query only span names and attribute keys that
`packages/otel/src/span-mapper.ts`'s `mapAuditEventToSpan` actually emits.
Three span families exist:

- **`knotrust.decision`** (`DECISION_SPAN_NAME`) — one per audited
  `AuditEventType.DECISION` event. Attributes: `knotrust.tool`,
  `knotrust.server`, `knotrust.tier`, `knotrust.outcome`, `knotrust.reason`,
  `knotrust.cache_hit`, `knotrust.latency_ms`, `knotrust.seq`,
  `knotrust.subject`, `knotrust.agent`.
- **`knotrust.approval.<phase>`** (`APPROVAL_SPAN_NAME_PREFIX` +
  `.requested`/`.pending`/`.approved`/`.denied`/`.expired`/`.cancelled`) —
  one standalone, **zero-duration** span per approval-lifecycle audit event
  (`startTimeMs === endTimeMs === event.ts`; there is no `latency_ms` on
  these). Attributes: `knotrust.tool`, `knotrust.server`, `knotrust.seq`,
  `knotrust.subject`, `knotrust.agent`, `knotrust.approval_id`,
  `knotrust.reason`.
- **`knotrust.security.<type>`** (`SECURITY_SPAN_NAME_PREFIX` — R132) — one
  standalone, **zero-duration** span per SECURITY-ANOMALY audit event:
  `fail_open_fired`, `denial_probing_suspected`, `tool_definition_changed`,
  `approval_channel_violation`, `probe_flagged`. Attributes:
  `knotrust.tool`, `knotrust.server`, `knotrust.seq`, `knotrust.subject`,
  `knotrust.agent`, `knotrust.reason`, plus `knotrust.tier` and
  `knotrust.approval_id` when the underlying event actually carries them
  (today: `knotrust.tier` only on `fail_open_fired`; `knotrust.approval_id`
  only on `approval_channel_violation`). `fail_open_fired`'s
  `knotrust.reason` is always the fixed safe label `"fail_open_recovery"` —
  never the event's own free-text cause (see `span-mapper.ts`'s
  `FAIL_OPEN_SAFE_REASON` doc comment).

| # | Panel | Widget id | Queries |
|---|-------|-----------|---------|
| a | Decisions per minute, by outcome | `decisions-per-minute-by-outcome` | `count()` of `knotrust.decision` spans, grouped by `knotrust.outcome` |
| b | Added latency by path (ms), p50/p95/p99 | `latency-by-path-table` + `latency-p95-trend-by-cache-hit` | `p50/p95/p99(knotrust.latency_ms)` on `knotrust.decision` spans, grouped by `knotrust.cache_hit` × `knotrust.outcome` |
| c | Denial reasons | `denial-reasons` | `count()` of `knotrust.decision` spans where `knotrust.outcome = 'deny'`, grouped by `knotrust.reason` |
| d | Fail-open firings | `fail-open-firings` | `count()` of `knotrust.security.fail_open_fired` spans (R132), grouped by `knotrust.tier` |
| e | Approval resolution times | `approval-resolution-time` | ClickHouse SQL cross-span join on `knotrust.approval_id`, terminal-phase timestamp minus requested/pending-phase timestamp |

#### (b) — how "path" is derived (there is no native `path` attribute)

The decision span carries no single attribute that says "this call was
served from cache / evaluated fresh / went to approval." `evaluatedBy`
(`"L0" | "cedar" | "authzen_http" | "opa" | "grant"`, `@knotrust/core`'s
`DecisionResponse`) is **never persisted to the audit log and never exported
as a span attribute** — checked directly against
`packages/store/src/audit-log.ts`'s `AuditEvent` interface and
`span-mapper.ts`'s `commonAttributes`/`mapDecisionEvent`. So panel (b) derives
three path buckets from the two attributes that *do* exist:

- **cache-hit**: `knotrust.cache_hit = true`.
- **fresh evaluation**: `knotrust.cache_hit = false AND knotrust.outcome != 'pending_approval'`.
  This conflates L0 with any deeper PDP layer (cedar/OPA/AuthZen/grant) —
  they are not distinguishable with today's exported attributes. If that
  distinction becomes important, it requires exporting `evaluatedBy` as a
  new span attribute first (an additive `span-mapper.ts` change, out of this
  task's scope — this task does not touch the exporter).
- **approval (synchronous portion only)**: `knotrust.outcome = 'pending_approval'`.
  This is the latency to *decide* a call needs approval, not the end-to-end
  wait — that is panel (e).

#### (d) — fail-open firings (R132: no longer a known gap)

Originally, `span-mapper.ts`'s `mapAuditEventToSpan` mapped exactly two
families to spans (`type: "decision"` and the six approval-lifecycle types),
so `AuditEventType.FAIL_OPEN_FIRED` (`"fail_open_fired"`, appended by
`packages/proxy-stdio/src/enforce.ts`'s `tryAppendFailOpenFired`) produced no
span at all and this panel read `0` forever regardless of real fail-open
activity. R132 closed that gap: `span-mapper.ts`'s `mapSecurityAnomalyEvent`
now maps `fail_open_fired` (and four other security-anomaly event types) to
its own standalone span, `knotrust.security.fail_open_fired` — see this
file's "Two/Three span families" section above.

The panel now queries `count()` of real `knotrust.security.fail_open_fired`
spans, grouped by `knotrust.tier` (R84's fail-open is structurally
routine-only, so a non-routine value here is itself notable). The event's own
free-text `reason` (a JSON `{tier, cause}` blob whose `cause` comes from an
arbitrary thrown error) is deliberately **never** exported — the span's
`knotrust.reason` is always the fixed label `"fail_open_recovery"`; see
`span-mapper.ts`'s `FAIL_OPEN_SAFE_REASON` doc comment for the secrets-hygiene
rationale.

**Alert-threshold note**: alert if this panel's value is `> 0` — a threshold
annotation to that effect (`thresholdOperator: ">"`, `thresholdValue: 0`) is
set on the widget so the "unexpected fail-open" framing is visible
immediately, even though no SigNoz alert rule has been created from it
(creating a live alert rule requires an owner decision on notification
channels — see "Owner-run validation" below).

#### (e) — approval resolution time is a cross-span ClickHouse query

Approval spans are point-in-time markers (zero duration each), so "how long
did approval take" cannot be read off a single span — it is the wall-clock
gap between the `requested`/`pending` phase and the terminal phase
(`approved`/`denied`/`expired`/`cancelled`) of the **same**
`knotrust.approval_id`. The Query Builder can't express a cross-row,
cross-group time diff, so this panel uses ClickHouse SQL directly against
`signoz_traces.distributed_signoz_index_v3`, following the same
`minIf`/`maxIf`-grouped-by-correlation-key pattern SigNoz's own documented
"Latency Between Spans in Trace" example uses. **This SQL has not been run
against a live SigNoz + real data in this environment** — see "Owner-run
validation."

### Owner-run validation (this is not done yet — be honest about it)

This dashboard was authored and schema-checked in an environment with no
live SigNoz instance and no dogfood traffic (the reference SigNoz MCP server
that ships with this repo returned `401 unauthenticated` when queried during
this task — there was nothing to render against, and this task does not
create or modify anything on a live server). The following parts of
P0-E8-T2's acceptance criteria are **owner-run steps that have not been
executed**, and this dashboard's existence does not imply they have been:

1. **"A day of dogfood traffic renders on the dashboard."** Not observed.
   Import the file, point a real (or test) `telemetryExport` at your SigNoz
   instance, generate real traffic, and confirm each panel populates.
2. **"Latency panels match the harness numbers from P0-E9-T3 within
   noise."** Not checked — P0-E9-T3 (the latency validation harness) has not
   run yet as of this task. Once it has, compare its budget-table numbers
   against panel (b)'s p50/p95/p99 for the matching path.
3. **"A deliberate fail-open test event appears on the panel."** The
   structural gap that previously blocked this (panel (d) had no underlying
   span data source) was closed by R132 — `fail_open_fired` now maps to a
   real `knotrust.security.fail_open_fired` span (proven by
   `packages/otel/src/span-mapper.test.ts` and the local-collector fixture in
   `packages/otel/src/exporter.test.ts`). **Still not verified against a
   live SigNoz instance** in this environment — trigger a real fail-open
   (`failOpen.routine: true` configured, a genuine internal-error path hit)
   and confirm the panel's count increments.
4. **The ClickHouse SQL query in panel (e)** has been checked against the
   documented schema and example patterns, but not executed against live
   ClickHouse data — verify it returns sensible results on import, and
   adjust column/table names if your SigNoz version's schema has moved on.

### Verifying this file (what IS automated)

`packages/otel/src/dashboard-consistency.test.ts` (part of the normal
`pnpm turbo test` run) checks, without any network access or live SigNoz
instance:

1. The JSON parses, and has the shape a SigNoz dashboard export needs
   (`title`/`widgets`/`layout`, exactly one layout entry per widget id).
2. Every `knotrust.*` token any panel's query references — span names via
   `filter.expression` / ClickHouse `name = '...'` predicates, attribute
   keys via `groupBy`/`aggregations`/`legend`/ClickHouse map access — is a
   **real, currently-emitted** span name or attribute key, computed by
   calling the actual `mapAuditEventToSpan` (not a hand-maintained duplicate
   list that could itself drift from the exporter). `title`/`description`
   text is deliberately excluded from this scan — free-text prose can
   reference an attribute by name for narrative purposes without that
   creating a false pass/fail signal either way; only the actual
   `query`/`selectedTracesFields`/`selectedLogFields` subtrees a panel
   executes are checked.

This is what catches the dashboard silently rotting relative to the
exporter (a renamed/removed attribute breaking a panel). It is **not**, and
cannot be, a substitute for the owner-run validation above.
