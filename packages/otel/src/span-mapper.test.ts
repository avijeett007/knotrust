/**
 * @knotrust/otel — span-mapper.ts unit tests (P0-E8-T1; ruling R130).
 *
 * Pure-function coverage only: no OTel SDK, no network, no audit sink — just
 * `AuditEvent` in, `MappedSpan | undefined` out. This is the primary
 * acceptance vehicle for "assert the attribute set for a routine allow, a
 * sensitive deny, a critical pending" (R131b) — the real-network local-
 * collector fixture in `exporter.test.ts` proves the WIRING (subscribe →
 * span → real OTLP/HTTP POST), not the attribute contents a second time.
 */

import type { AuditEvent } from "@knotrust/store";
import { AuditEventType } from "@knotrust/store";
import { describe, expect, it } from "vitest";
import {
  APPROVAL_SPAN_NAME_PREFIX,
  DECISION_SPAN_NAME,
  mapAuditEventToSpan,
  SECURITY_SPAN_NAME_PREFIX,
} from "./span-mapper.js";

const CTX = { serverName: "github-mcp" };

function decisionEvent(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    seq: 42,
    ts: "2026-07-04T12:00:00.000Z",
    prevHash: "a".repeat(64),
    hash: "b".repeat(64),
    type: AuditEventType.DECISION,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "claude-desktop",
    tool: "github.create_issue",
    argsHash: "sha256:deadbeef",
    outcome: "allow",
    reason: "routine_default_allow",
    tier: "routine",
    latencyMs: 3,
    ...over,
  };
}

function approvalEvent(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    seq: 7,
    ts: "2026-07-04T12:00:05.000Z",
    prevHash: "a".repeat(64),
    hash: "c".repeat(64),
    type: AuditEventType.APPROVAL_REQUESTED,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "claude-desktop",
    tool: "stripe.create_refund",
    argsHash: "sha256:deadbeef",
    approvalId: "appr_123",
    ...over,
  };
}

/** Mirrors `enforce.ts`'s `tryAppendFailOpenFired` real construction site exactly (R84/R126). */
function failOpenEvent(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    seq: 99,
    ts: "2026-07-04T12:00:10.000Z",
    prevHash: "a".repeat(64),
    hash: "d".repeat(64),
    type: AuditEventType.FAIL_OPEN_FIRED,
    surface: "stdio_proxy",
    subject: "local-user",
    agent: "unknown-agent",
    tool: "github.create_issue",
    argsHash: "sha256:deadbeef",
    tier: "routine",
    reason: JSON.stringify({
      tier: "routine",
      cause: "Error: config lookup failed for token sk-live-supersecrettoken",
    }),
    ...over,
  };
}

/** Mirrors `enforce.ts`'s `noteRejection` real construction site (R78). */
function denialProbingEvent(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    seq: 100,
    ts: "2026-07-04T12:00:15.000Z",
    prevHash: "a".repeat(64),
    hash: "e".repeat(64),
    type: AuditEventType.DENIAL_PROBING_SUSPECTED,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "claude-desktop",
    tool: "stripe.create_refund",
    argsHash: "sha256:deadbeef",
    reason:
      '5 denials for "stripe.create_refund" by agent "claude-desktop" within 60000ms',
    ...over,
  };
}

/** Mirrors `tool-inventory.ts`'s `emitToolDefinitionChangeEvent` real construction site (R66). */
function toolDefinitionChangedEvent(
  over: Partial<AuditEvent> = {},
): AuditEvent {
  return {
    seq: 101,
    ts: "2026-07-04T12:00:20.000Z",
    prevHash: "a".repeat(64),
    hash: "f".repeat(64),
    type: AuditEventType.TOOL_DEFINITION_CHANGED,
    surface: "stdio_proxy",
    subject: "system",
    agent: "system",
    tool: "github.delete_repo",
    argsHash: "sha256:deadbeef",
    reason: JSON.stringify({
      server: "github-mcp",
      changeKind: "changed",
      schemaHashChanged: true,
    }),
    ...over,
  };
}

/** Mirrors `local-page/server.ts`'s `auditViolation` real construction site (R98). */
function approvalChannelViolationEvent(
  over: Partial<AuditEvent> = {},
): AuditEvent {
  return {
    seq: 102,
    ts: "2026-07-04T12:00:25.000Z",
    prevHash: "a".repeat(64),
    hash: "0".repeat(64),
    type: AuditEventType.APPROVAL_CHANNEL_VIOLATION,
    surface: "local_page",
    subject: "unknown",
    agent: "unknown",
    tool: "github.delete_repo",
    argsHash: "sha256:deadbeef",
    approvalId: "appr_456",
    reason: "bad_csrf",
    ...over,
  };
}

describe("mapAuditEventToSpan — decision events (R130)", () => {
  it("maps a routine allow with the full attribute set, status OK", () => {
    const event = decisionEvent({
      tier: "routine",
      outcome: "allow",
      reason: "routine_default_allow",
      latencyMs: 2,
      cacheHit: true,
    });
    const span = mapAuditEventToSpan(event, CTX);
    expect(span).toBeDefined();
    expect(span?.name).toBe(DECISION_SPAN_NAME);
    expect(span?.status).toBe("ok");
    expect(span?.attributes).toEqual({
      "knotrust.tool": "github.create_issue",
      "knotrust.server": "github-mcp",
      "knotrust.tier": "routine",
      "knotrust.outcome": "allow",
      "knotrust.reason": "routine_default_allow",
      "knotrust.cache_hit": true,
      "knotrust.latency_ms": 2,
      "knotrust.seq": 42,
      "knotrust.subject": "user:local",
      "knotrust.agent": "claude-desktop",
    });
  });

  it("maps a sensitive deny with status ERROR and cache_hit defaulting to false when absent", () => {
    const event = decisionEvent({
      tier: "sensitive",
      outcome: "deny",
      reason: "no_grant_sensitive",
      latencyMs: 5,
      tool: "stripe.create_refund",
    });
    const span = mapAuditEventToSpan(event, CTX);
    expect(span?.status).toBe("error");
    expect(span?.attributes).toMatchObject({
      "knotrust.tool": "stripe.create_refund",
      "knotrust.tier": "sensitive",
      "knotrust.outcome": "deny",
      "knotrust.reason": "no_grant_sensitive",
      "knotrust.cache_hit": false,
      "knotrust.latency_ms": 5,
    });
  });

  it("maps a critical pending_approval with status UNSET (neither allow nor deny)", () => {
    const event = decisionEvent({
      tier: "critical",
      outcome: "pending_approval",
      reason: "no_grant_critical",
      latencyMs: 1,
      tool: "github.delete_repo",
    });
    const span = mapAuditEventToSpan(event, CTX);
    expect(span?.status).toBe("unset");
    expect(span?.attributes).toMatchObject({
      "knotrust.tool": "github.delete_repo",
      "knotrust.tier": "critical",
      "knotrust.outcome": "pending_approval",
      "knotrust.reason": "no_grant_critical",
    });
  });

  it("derives startTimeMs from ts minus latencyMs, endTimeMs from ts", () => {
    const event = decisionEvent({
      ts: "2026-07-04T12:00:00.500Z",
      latencyMs: 500,
    });
    const span = mapAuditEventToSpan(event, CTX);
    expect(span).toBeDefined();
    const endTimeMs = Date.parse("2026-07-04T12:00:00.500Z");
    expect(span?.endTimeMs).toBe(endTimeMs);
    expect(span?.startTimeMs).toBe(endTimeMs - 500);
  });

  it("falls back reason to '' and tier to 'unknown' when absent (defensive — every real decision event carries both)", () => {
    const { reason, tier, ...rest } = decisionEvent();
    void reason;
    void tier;
    const span = mapAuditEventToSpan(rest as AuditEvent, CTX);
    expect(span?.attributes["knotrust.reason"]).toBe("");
    expect(span?.attributes["knotrust.tier"]).toBe("unknown");
  });

  it("injects the caller-provided serverName — never reads a 'server' field off the event (the audit event carries none, see this module's header)", () => {
    const span = mapAuditEventToSpan(decisionEvent(), {
      serverName: "some-other-server",
    });
    expect(span?.attributes["knotrust.server"]).toBe("some-other-server");
  });
});

describe("mapAuditEventToSpan — approval lifecycle events (R130, standalone-span choice)", () => {
  it("maps approval_requested to its own span, named with the phase, status UNSET", () => {
    const span = mapAuditEventToSpan(
      approvalEvent({ type: AuditEventType.APPROVAL_REQUESTED }),
      CTX,
    );
    expect(span?.name).toBe(`${APPROVAL_SPAN_NAME_PREFIX}.requested`);
    expect(span?.status).toBe("unset");
    expect(span?.attributes).toEqual({
      "knotrust.tool": "stripe.create_refund",
      "knotrust.server": "github-mcp",
      "knotrust.approval_id": "appr_123",
      "knotrust.reason": "",
      "knotrust.seq": 7,
      "knotrust.subject": "user:local",
      "knotrust.agent": "claude-desktop",
    });
  });

  it("maps approval_approved with status OK", () => {
    const span = mapAuditEventToSpan(
      approvalEvent({ type: AuditEventType.APPROVAL_APPROVED }),
      CTX,
    );
    expect(span?.name).toBe(`${APPROVAL_SPAN_NAME_PREFIX}.approved`);
    expect(span?.status).toBe("ok");
  });

  it("maps approval_denied with status ERROR, carrying the reason", () => {
    const span = mapAuditEventToSpan(
      approvalEvent({
        type: AuditEventType.APPROVAL_DENIED,
        reason: "user_denied",
      }),
      CTX,
    );
    expect(span?.name).toBe(`${APPROVAL_SPAN_NAME_PREFIX}.denied`);
    expect(span?.status).toBe("error");
    expect(span?.attributes["knotrust.reason"]).toBe("user_denied");
  });

  it("maps approval_expired and approval_cancelled too", () => {
    expect(
      mapAuditEventToSpan(
        approvalEvent({ type: AuditEventType.APPROVAL_EXPIRED }),
        CTX,
      )?.name,
    ).toBe(`${APPROVAL_SPAN_NAME_PREFIX}.expired`);
    expect(
      mapAuditEventToSpan(
        approvalEvent({ type: AuditEventType.APPROVAL_CANCELLED }),
        CTX,
      )?.name,
    ).toBe(`${APPROVAL_SPAN_NAME_PREFIX}.cancelled`);
  });

  it("approval spans are instantaneous (startTimeMs === endTimeMs === ts) — no latency figure on these events", () => {
    const span = mapAuditEventToSpan(approvalEvent(), CTX);
    const expected = Date.parse("2026-07-04T12:00:05.000Z");
    expect(span?.startTimeMs).toBe(expected);
    expect(span?.endTimeMs).toBe(expected);
  });
});

describe("mapAuditEventToSpan — out-of-scope event types (P0 scope limit, documented; R132 narrowed this list)", () => {
  it.each([
    AuditEventType.GRANT_CREATED,
    AuditEventType.GRANT_REVOKED,
    AuditEventType.GRANT_CONSUMED,
    AuditEventType.AUDIT_RECOVERED,
  ])("returns undefined (no span) for %s", (type) => {
    const span = mapAuditEventToSpan(decisionEvent({ type }), CTX);
    expect(span).toBeUndefined();
  });
});

describe("mapAuditEventToSpan — security-anomaly events (R132: fail-open, probing, drift, channel violations)", () => {
  it("maps fail_open_fired to its own span, status ERROR, carrying tool/tier — NEVER the raw reason/cause text", () => {
    const event = failOpenEvent({ tier: "routine" });
    const span = mapAuditEventToSpan(event, CTX);
    expect(span).toBeDefined();
    expect(span?.name).toBe(`${SECURITY_SPAN_NAME_PREFIX}.fail_open_fired`);
    expect(span?.status).toBe("error");
    expect(span?.attributes).toEqual({
      "knotrust.tool": "github.create_issue",
      "knotrust.server": "github-mcp",
      "knotrust.seq": 99,
      "knotrust.subject": "local-user",
      "knotrust.agent": "unknown-agent",
      "knotrust.tier": "routine",
      "knotrust.reason": "fail_open_recovery",
    });
  });

  it("fail_open_fired spans are instantaneous (startTimeMs === endTimeMs === ts, like approval spans)", () => {
    const span = mapAuditEventToSpan(failOpenEvent(), CTX);
    const expected = Date.parse("2026-07-04T12:00:10.000Z");
    expect(span?.startTimeMs).toBe(expected);
    expect(span?.endTimeMs).toBe(expected);
  });

  it("maps denial_probing_suspected to its own span, status ERROR, with the real (safe) reason text and no tier attribute (none present on the event)", () => {
    const span = mapAuditEventToSpan(denialProbingEvent(), CTX);
    expect(span?.name).toBe(
      `${SECURITY_SPAN_NAME_PREFIX}.denial_probing_suspected`,
    );
    expect(span?.status).toBe("error");
    expect(span?.attributes).toEqual({
      "knotrust.tool": "stripe.create_refund",
      "knotrust.server": "github-mcp",
      "knotrust.seq": 100,
      "knotrust.subject": "user:local",
      "knotrust.agent": "claude-desktop",
      "knotrust.reason":
        '5 denials for "stripe.create_refund" by agent "claude-desktop" within 60000ms',
    });
    expect(span?.attributes).not.toHaveProperty("knotrust.tier");
  });

  it("maps tool_definition_changed to its own span, status ERROR, carrying the safe JSON reason (changeKind/schemaHashChanged, never the raw schema)", () => {
    const span = mapAuditEventToSpan(toolDefinitionChangedEvent(), CTX);
    expect(span?.name).toBe(
      `${SECURITY_SPAN_NAME_PREFIX}.tool_definition_changed`,
    );
    expect(span?.status).toBe("error");
    expect(span?.attributes["knotrust.tool"]).toBe("github.delete_repo");
    expect(span?.attributes["knotrust.reason"]).toBe(
      JSON.stringify({
        server: "github-mcp",
        changeKind: "changed",
        schemaHashChanged: true,
      }),
    );
  });

  it("maps approval_channel_violation to its own span, status ERROR, carrying the approval_id and the closed-vocabulary reason code", () => {
    const span = mapAuditEventToSpan(approvalChannelViolationEvent(), CTX);
    expect(span?.name).toBe(
      `${SECURITY_SPAN_NAME_PREFIX}.approval_channel_violation`,
    );
    expect(span?.status).toBe("error");
    expect(span?.attributes["knotrust.approval_id"]).toBe("appr_456");
    expect(span?.attributes["knotrust.reason"]).toBe("bad_csrf");
  });

  it("maps probe_flagged to its own span even though no production call site emits it today (defensive, open-vocabulary coverage)", () => {
    const span = mapAuditEventToSpan(
      denialProbingEvent({
        type: AuditEventType.PROBE_FLAGGED,
        reason: "probe_flagged_reason",
      }),
      CTX,
    );
    expect(span?.name).toBe(`${SECURITY_SPAN_NAME_PREFIX}.probe_flagged`);
    expect(span?.status).toBe("error");
    expect(span?.attributes["knotrust.reason"]).toBe("probe_flagged_reason");
  });
});

describe("never leaks raw arguments or the argsHash into span attributes", () => {
  it("the decision span's attribute set contains no argsHash-derived or raw-argument key", () => {
    const event = decisionEvent({ argsHash: "sha256:supersecrethashvalue" });
    const span = mapAuditEventToSpan(event, CTX);
    const values = Object.values(span?.attributes ?? {}).map(String);
    expect(values.some((v) => v.includes("supersecrethashvalue"))).toBe(false);
    expect(Object.keys(span?.attributes ?? {})).not.toContain(
      "knotrust.argsHash",
    );
  });

  it("fail_open_fired's span NEVER exports the event's own reason/cause text, even though that text is present on the audit event (R132's one non-passthrough case)", () => {
    const event = failOpenEvent({
      reason: JSON.stringify({
        tier: "routine",
        cause: "Error: leaked sk-live-topsecrettoken in message",
      }),
    });
    const span = mapAuditEventToSpan(event, CTX);
    const values = Object.values(span?.attributes ?? {}).map(String);
    expect(values.some((v) => v.includes("sk-live-topsecrettoken"))).toBe(
      false,
    );
    expect(span?.attributes["knotrust.reason"]).toBe("fail_open_recovery");
  });

  it("none of the five security-anomaly span types ever carry an argsHash-derived key", () => {
    const events = [
      failOpenEvent({ argsHash: "sha256:supersecrethashvalue" }),
      denialProbingEvent({ argsHash: "sha256:supersecrethashvalue" }),
      toolDefinitionChangedEvent({ argsHash: "sha256:supersecrethashvalue" }),
      approvalChannelViolationEvent({
        argsHash: "sha256:supersecrethashvalue",
      }),
    ];
    for (const event of events) {
      const span = mapAuditEventToSpan(event, CTX);
      const values = Object.values(span?.attributes ?? {}).map(String);
      expect(values.some((v) => v.includes("supersecrethashvalue"))).toBe(
        false,
      );
      expect(Object.keys(span?.attributes ?? {})).not.toContain(
        "knotrust.argsHash",
      );
    }
  });
});
