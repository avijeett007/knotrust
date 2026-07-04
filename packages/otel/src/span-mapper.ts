/**
 * @knotrust/otel — audit-event → OTel-span pure mapper (P0-E8-T1; ruling R130).
 *
 * Deliberately OTel-SDK-free: this module imports nothing from
 * `@opentelemetry/*`, only `@knotrust/store`'s `AuditEvent` type/constants.
 * It returns a plain, serializable `MappedSpan` descriptor — a real
 * `@opentelemetry/api` `Tracer` turns that into an actual span
 * (`exporter.ts`'s `applyMappedSpan`). Keeping the mapping PURE means the
 * attribute-set acceptance (R131b: "assert the attribute set for a routine
 * allow, a sensitive deny, a critical pending") is a fast, network-free,
 * OTel-SDK-free unit test (`span-mapper.test.ts`) — the real end-to-end
 * OTLP/HTTP wiring is a SEPARATE concern, proven once in `exporter.test.ts`'s
 * local-collector fixture.
 *
 * ## What gets a span, and what doesn't (P0 scope, R130)
 *
 * - `type: "decision"` → one span, `DECISION_SPAN_NAME` (a single fixed name;
 *   the tool/tier/outcome/etc. vary in ATTRIBUTES, not the span name — this
 *   groups every decision under one operation for a backend like SigNoz to
 *   aggregate on, rather than fragmenting into one "span name" per tool).
 * - The six approval-lifecycle types (`approval_requested/pending/approved/
 *   denied/expired/cancelled`) → their OWN standalone span each, named
 *   `knotrust.approval.<phase>`. R130 offered a choice between
 *   "span events on the related decision span if correlatable by
 *   approvalId" and "standalone spans... simpler... acceptable for P0" —
 *   this module takes the standalone-span option: correlating an approval
 *   event back to the ORIGINAL decision span that returned
 *   `pending_approval` would need that span to still be open (it isn't —
 *   `decisionEvent()`'s span already ended when the decision event was
 *   audited, before the approval lifecycle even begins) or a span-linking
 *   scheme this task does not attempt. A standalone span still lets a
 *   collector's trace/log view join approval spans back to their decision by
 *   `knotrust.tool`/`knotrust.approval_id` — good enough for P0.
 * - The five SECURITY-ANOMALY types (`fail_open_fired`,
 *   `denial_probing_suspected`, `tool_definition_changed`,
 *   `approval_channel_violation`, `probe_flagged`) → their OWN standalone
 *   span each, named `${SECURITY_SPAN_NAME_PREFIX}.<event.type>` (e.g.
 *   `knotrust.security.fail_open_fired`) — R132, a P0-E8-T2 follow-up. R130
 *   originally scoped this mapper to decision + approval only and left every
 *   other event type unmapped as "a clean, additive follow-up"; R132 is that
 *   follow-up, ruled on after the E8-T2 dashboard's "fail-open firings, alert
 *   if > 0" panel surfaced that an invisible fail-open defeats the whole
 *   point of a security-monitoring exporter. See `mapSecurityAnomalyEvent`
 *   below for the per-type attribute mapping and, especially, why
 *   `fail_open_fired`'s own `reason` field is NEVER exported verbatim.
 * - EVERY OTHER audit event type (`grant_created`, `grant_revoked`,
 *   `grant_consumed`, `audit_recovered`) → still `undefined`, no span at
 *   all. `grant_*` are lifecycle/inventory bookkeeping, not anomalies — out
 *   of R130's original scope and untouched by R132. `audit_recovered` is an
 *   internally-generated sink-recovery marker (`@knotrust/store`'s
 *   `audit-log.ts`), not an externally-observable security signal, and R132's
 *   fix list is explicit (`fail_open_fired`/`denial_probing_suspected`/
 *   `tool_definition_changed`/`approval_channel_violation`/`probe_flagged`)
 *   — `audit_recovered` deliberately stays out of scope for this task, kept
 *   with the `grant_*` family. Extending to more event types remains a clean,
 *   additive follow-up (add to `SECURITY_ANOMALY_TYPES` or a new case below),
 *   never a breaking change to this module's shape.
 *
 * ## Deviations from R130's literal attribute list, documented
 *
 * - **`server`**: `AuditEvent` carries NO server-name field at all (only
 *   `surface` (kind) — see `@knotrust/store`'s `audit-log.ts`, and
 *   `@knotrust/grants`' `decider.ts`'s `decisionEvent()`, which never writes
 *   one). Rather than extend the audit log schema (out of this task's scope
 *   — it would touch `packages/grants/src/decider.ts`, the exact "core"
 *   surface R127/R131c requires stay byte-identical) or the store's schema,
 *   `knotrust.server` is supplied by the CALLER (`MapContext.serverName`) —
 *   the one MCP server a given proxy instance fronts for its ENTIRE
 *   lifetime (`buildEnforcement`'s already-resolved `serverName`, CLI
 *   `enforcement.ts`), so every span this mapper builds in one process run
 *   carries the same, correct `knotrust.server` value with zero per-event
 *   lookup.
 * - **`decision_id`**: `AuditEvent` also carries no `decisionId` (that field
 *   lives on the ephemeral `DecisionResponse`, never persisted to the audit
 *   log). R130 itself allows this substitution ("`knotrust.decision_id`/
 *   `seq`") — this module uses `seq`, the stable, already-persisted
 *   per-event identifier every `AuditEvent` carries, as `knotrust.seq`.
 */

import { type AuditEvent, AuditEventType } from "@knotrust/store";

export type MappedSpanStatus = "unset" | "ok" | "error";

export type MappedSpanAttributeValue = string | number | boolean;

export interface MappedSpan {
  name: string;
  /** Epoch milliseconds. */
  startTimeMs: number;
  /** Epoch milliseconds. */
  endTimeMs: number;
  status: MappedSpanStatus;
  attributes: Record<string, MappedSpanAttributeValue>;
}

/** The one fixed span name every `type: "decision"` audit event maps to (see module header). */
export const DECISION_SPAN_NAME = "knotrust.decision";

/** Prefix for the six approval-lifecycle standalone spans: `${APPROVAL_SPAN_NAME_PREFIX}.<phase>`. */
export const APPROVAL_SPAN_NAME_PREFIX = "knotrust.approval";

/** Prefix for the five security-anomaly standalone spans (R132): `${SECURITY_SPAN_NAME_PREFIX}.<event.type>`. */
export const SECURITY_SPAN_NAME_PREFIX = "knotrust.security";

export interface MapContext {
  /**
   * The one MCP server this proxy instance fronts (`buildEnforcement`'s
   * resolved `serverName`) — NOT read from the audit event, which carries no
   * server field at all. See this module's header, "Deviations" section.
   */
  serverName: string;
}

const APPROVAL_EVENT_PHASES: ReadonlyMap<string, string> = new Map([
  [AuditEventType.APPROVAL_REQUESTED, "requested"],
  [AuditEventType.APPROVAL_PENDING, "pending"],
  [AuditEventType.APPROVAL_APPROVED, "approved"],
  [AuditEventType.APPROVAL_DENIED, "denied"],
  [AuditEventType.APPROVAL_EXPIRED, "expired"],
  [AuditEventType.APPROVAL_CANCELLED, "cancelled"],
]);

/** The five security-anomaly types this mapper gives a standalone span to (R132; see module header). */
const SECURITY_ANOMALY_TYPES: ReadonlySet<string> = new Set([
  AuditEventType.FAIL_OPEN_FIRED,
  AuditEventType.DENIAL_PROBING_SUSPECTED,
  AuditEventType.TOOL_DEFINITION_CHANGED,
  AuditEventType.APPROVAL_CHANNEL_VIOLATION,
  AuditEventType.PROBE_FLAGGED,
]);

/**
 * Fixed, safe stand-in for `fail_open_fired`'s own `reason` field (R132).
 *
 * `enforce.ts`'s `tryAppendFailOpenFired` writes `reason` as
 * `JSON.stringify({ tier, cause: describeError(err) })`, where `cause` is
 * `${err.name}: ${err.message}` off of WHATEVER internal error tripped the
 * fail-open path (tier resolution, grant collection, precedence, cache, or
 * `DecisionRequest` mapping — R81's whole covered surface). That message is
 * fine for the LOCAL, file-permission-protected audit log (its own doc
 * comment calls it "local-audit-only diagnostic text"), but this module
 * exports to a THIRD-PARTY OTel collector over the network — a strictly
 * wider trust boundary. Nothing guarantees an arbitrary thrown `Error`'s
 * `.message` is free of anything sensitive (a future error path could, for
 * instance, echo a fragment of malformed config or input), so this mapper
 * never forwards it: every `fail_open_fired` span reports this FIXED label
 * instead. The operationally useful signal — that a fail-open fired at all,
 * for which tool, at which tier — is already carried by
 * `knotrust.tool`/`knotrust.tier`/`knotrust.seq`, none of which come from the
 * free-text `cause`.
 */
const FAIL_OPEN_SAFE_REASON = "fail_open_recovery";

/** Attributes every mapped span (decision or approval) shares — never includes `argsHash`/`rawArgs` (see module header + the secrets-hygiene test). */
function commonAttributes(
  event: AuditEvent,
  context: MapContext,
): Record<string, MappedSpanAttributeValue> {
  return {
    "knotrust.tool": event.tool,
    "knotrust.server": context.serverName,
    "knotrust.seq": event.seq,
    "knotrust.subject": event.subject,
    "knotrust.agent": event.agent,
  };
}

function mapDecisionEvent(event: AuditEvent, context: MapContext): MappedSpan {
  const endTimeMs = Date.parse(event.ts);
  const latencyMs = event.latencyMs ?? 0;
  const startTimeMs = endTimeMs - latencyMs;
  const status: MappedSpanStatus =
    event.outcome === "deny"
      ? "error"
      : event.outcome === "allow"
        ? "ok"
        : "unset"; // pending_approval / deferred_not_eligible — neither succeeded nor failed yet.

  return {
    name: DECISION_SPAN_NAME,
    startTimeMs,
    endTimeMs,
    status,
    attributes: {
      ...commonAttributes(event, context),
      "knotrust.tier": event.tier ?? "unknown",
      "knotrust.outcome": event.outcome ?? "unknown",
      "knotrust.reason": event.reason ?? "",
      "knotrust.cache_hit": event.cacheHit ?? false,
      "knotrust.latency_ms": latencyMs,
    },
  };
}

function mapApprovalEvent(
  event: AuditEvent,
  context: MapContext,
  phase: string,
): MappedSpan {
  const tMs = Date.parse(event.ts);
  const status: MappedSpanStatus =
    event.type === AuditEventType.APPROVAL_APPROVED
      ? "ok"
      : event.type === AuditEventType.APPROVAL_DENIED
        ? "error"
        : "unset"; // requested/pending/expired/cancelled — no success/failure verdict of their own.

  return {
    name: `${APPROVAL_SPAN_NAME_PREFIX}.${phase}`,
    startTimeMs: tMs,
    endTimeMs: tMs,
    status,
    attributes: {
      ...commonAttributes(event, context),
      "knotrust.approval_id": event.approvalId ?? "",
      "knotrust.reason": event.reason ?? "",
    },
  };
}

/**
 * Maps one of the five SECURITY-ANOMALY event types (R132; see module
 * header) to its own standalone, zero-duration span — mirroring
 * `mapApprovalEvent`'s "point-in-time marker" shape (`startTimeMs ===
 * endTimeMs === event.ts`; none of these five carry a `latencyMs`). Status is
 * always `"error"`: every one of these five IS the anomaly signal itself
 * (an unexpected fail-open, a suspected probing burst, a detected tool
 * definition rug-pull, a rejected approval-channel forgery attempt), never a
 * routine outcome — which is exactly what makes `count() > 0` a sane
 * "alert if any fired" panel query (see the dashboard's `fail-open-firings`
 * panel).
 *
 * Attribute mapping, safe-by-construction for every one of the five (see
 * this function's callers in `span-mapper.test.ts` for the "no raw
 * args/tokens" proof against each real construction site):
 * - `knotrust.tier` — included ONLY when `event.tier` is actually present
 *   (unlike `mapDecisionEvent`, this does NOT default to `"unknown"`: most
 *   of these five event types never carry a tier at all — see
 *   `enforce.ts`/`tool-inventory.ts`/`local-page/server.ts` — so defaulting
 *   would falsely imply every anomaly is tier-scoped). Today only
 *   `fail_open_fired` sets it (R126, `enforce.ts`'s `tryAppendFailOpenFired`).
 * - `knotrust.approval_id` — included only when present (only
 *   `approval_channel_violation` ever carries one, and only when the
 *   rejected request could be correlated back to a pending approval —
 *   `local-page/server.ts`'s `auditViolation`).
 * - `knotrust.reason` — `fail_open_fired` NEVER exports its own `reason`
 *   verbatim; see `FAIL_OPEN_SAFE_REASON`'s doc comment for why. Every other
 *   type here passes `event.reason` straight through, exactly like
 *   `mapDecisionEvent`/`mapApprovalEvent` — verified safe by reading each
 *   real construction site: `denial_probing_suspected`'s reason is a
 *   template of numbers/tool/agent (`enforce.ts`'s `noteRejection`, no raw
 *   args); `tool_definition_changed`'s reason is JSON of
 *   `{server, changeKind, annotationChanges?, schemaHashChanged?}` — enum
 *   values and booleans only, "never carries the raw schema" by the source
 *   module's own contract (`tool-inventory.ts`); `approval_channel_violation`'s
 *   reason is one of a fixed, closed vocabulary
 *   (`bad_host`/`bad_origin`/`bad_csrf`/`bad_token`/`replayed_token`/
 *   `wrong_method`) that is by construction "NEVER the token value itself"
 *   (`local-page/server.ts`); `probe_flagged` has no real construction site
 *   in this codebase yet (the constant exists in `AuditEventType`'s open
 *   vocabulary but nothing appends it today) — passed through defensively,
 *   matching this function's own pattern for the other four.
 */
function mapSecurityAnomalyEvent(
  event: AuditEvent,
  context: MapContext,
): MappedSpan {
  const tMs = Date.parse(event.ts);
  const reason =
    event.type === AuditEventType.FAIL_OPEN_FIRED
      ? FAIL_OPEN_SAFE_REASON
      : (event.reason ?? "");

  return {
    name: `${SECURITY_SPAN_NAME_PREFIX}.${event.type}`,
    startTimeMs: tMs,
    endTimeMs: tMs,
    status: "error",
    attributes: {
      ...commonAttributes(event, context),
      ...(event.tier !== undefined ? { "knotrust.tier": event.tier } : {}),
      ...(event.approvalId !== undefined
        ? { "knotrust.approval_id": event.approvalId }
        : {}),
      "knotrust.reason": reason,
    },
  };
}

/**
 * Maps one `AuditEvent` to a `MappedSpan`, or `undefined` if this event type
 * is out of P0 scope (see module header). Pure: no I/O, no OTel SDK, no
 * clock reads beyond parsing the event's own `ts`.
 */
export function mapAuditEventToSpan(
  event: AuditEvent,
  context: MapContext,
): MappedSpan | undefined {
  if (event.type === AuditEventType.DECISION) {
    return mapDecisionEvent(event, context);
  }
  const phase = APPROVAL_EVENT_PHASES.get(event.type);
  if (phase !== undefined) {
    return mapApprovalEvent(event, context, phase);
  }
  if (SECURITY_ANOMALY_TYPES.has(event.type)) {
    return mapSecurityAnomalyEvent(event, context);
  }
  return undefined;
}
