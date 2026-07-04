/**
 * @knotrust/otel — dashboard/exporter drift check (P0-E8-T2; ruling R3).
 *
 * `docs/03-engineering/dashboards/knotrust-dogfood.dashboard.json` is a
 * SigNoz dashboard export, hand-authored against the span names and
 * attribute keys `span-mapper.ts`'s `mapAuditEventToSpan` emits. Nothing
 * enforces that the dashboard stays in sync with the mapper as the mapper
 * evolves — a renamed or removed attribute would silently leave a dashboard
 * panel dead (or, worse, silently matching nothing while looking fine).
 *
 * This file makes that a CI-enforced property instead of a hope:
 *
 * 1. The dashboard JSON parses, and has the shape a SigNoz dashboard export
 *    needs (title/widgets/layout, one layout entry per widget id).
 * 2. Every `knotrust.*` token any panel's query references (span names via
 *    `filter.expression`/ClickHouse `name = '...'` predicates, attribute
 *    keys via `groupBy`/`aggregations`/`legend`/ClickHouse column access) is
 *    computed as REAL by calling the actual, real `mapAuditEventToSpan` on
 *    representative fixture events — not a hand-copied duplicate list that
 *    could itself drift. Free-text `title`/`description` fields are
 *    deliberately NOT scanned — only the `query`/`selectedTracesFields`/
 *    `selectedLogFields` subtrees a panel actually executes are checked (see
 *    `dashboards/README.md`).
 *
 * This test does NOT and CANNOT prove the dashboard renders correctly
 * against live SigNoz + real traffic — see `dashboards/README.md`'s
 * "owner-run validation" section for that (out of scope for an automated,
 * network-free check).
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AuditEvent } from "@knotrust/store";
import { AuditEventType } from "@knotrust/store";
import { describe, expect, it } from "vitest";
import {
  APPROVAL_SPAN_NAME_PREFIX,
  DECISION_SPAN_NAME,
  mapAuditEventToSpan,
} from "./span-mapper.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const dashboardPath = path.join(
  repoRoot,
  "docs",
  "03-engineering",
  "dashboards",
  "knotrust-dogfood.dashboard.json",
);
const rawDashboard = readFileSync(dashboardPath, "utf8");

interface DashboardWidget {
  id: string;
  query: unknown;
  selectedTracesFields: unknown;
  selectedLogFields: unknown;
}

interface Dashboard {
  title: string;
  widgets: DashboardWidget[];
  layout: Array<{ i: string }>;
}

function parseDashboard(): Dashboard {
  return JSON.parse(rawDashboard) as Dashboard;
}

// ---------------------------------------------------------------------------
// Building the REAL emitted shape — by calling the real mapper, not by
// hand-copying its attribute list a second time (that copy could itself
// silently drift from the source of truth).
// ---------------------------------------------------------------------------

const CTX = { serverName: "dashboard-consistency-test" };

function decisionEvent(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    seq: 1,
    ts: "2026-01-01T00:00:00.000Z",
    prevHash: "a".repeat(64),
    hash: "b".repeat(64),
    type: AuditEventType.DECISION,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "test-agent",
    tool: "test.tool",
    argsHash: "sha256:test",
    outcome: "allow",
    reason: "test_reason",
    tier: "routine",
    latencyMs: 1,
    cacheHit: false,
    ...over,
  };
}

function approvalEvent(
  type: string,
  over: Partial<AuditEvent> = {},
): AuditEvent {
  return {
    seq: 2,
    ts: "2026-01-01T00:00:05.000Z",
    prevHash: "a".repeat(64),
    hash: "c".repeat(64),
    type,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "test-agent",
    tool: "test.tool",
    argsHash: "sha256:test",
    approvalId: "appr_test",
    reason: "test_reason",
    ...over,
  };
}

const APPROVAL_TYPES: string[] = [
  AuditEventType.APPROVAL_REQUESTED,
  AuditEventType.APPROVAL_PENDING,
  AuditEventType.APPROVAL_APPROVED,
  AuditEventType.APPROVAL_DENIED,
  AuditEventType.APPROVAL_EXPIRED,
  AuditEventType.APPROVAL_CANCELLED,
];

/** The five security-anomaly types R132 added spans for — see span-mapper.ts. */
const SECURITY_ANOMALY_TYPES: string[] = [
  AuditEventType.FAIL_OPEN_FIRED,
  AuditEventType.DENIAL_PROBING_SUSPECTED,
  AuditEventType.TOOL_DEFINITION_CHANGED,
  AuditEventType.APPROVAL_CHANNEL_VIOLATION,
  AuditEventType.PROBE_FLAGGED,
];

function securityAnomalyEvent(
  type: string,
  over: Partial<AuditEvent> = {},
): AuditEvent {
  return {
    seq: 3,
    ts: "2026-01-01T00:00:10.000Z",
    prevHash: "a".repeat(64),
    hash: "d".repeat(64),
    type,
    surface: "stdio_proxy",
    subject: "user:local",
    agent: "test-agent",
    tool: "test.tool",
    argsHash: "sha256:test",
    tier: "routine",
    approvalId: "appr_test",
    reason: "test_reason",
    ...over,
  };
}

interface EmittedShape {
  spanNames: Set<string>;
  attributeKeys: Set<string>;
}

/** Exercises the REAL `mapAuditEventToSpan` (span-mapper.ts) across every span-producing audit event type, and collects the real span names + attribute keys it actually emits. */
function computeRealEmittedShape(): EmittedShape {
  const spanNames = new Set<string>();
  const attributeKeys = new Set<string>();

  const decisionSpan = mapAuditEventToSpan(decisionEvent(), CTX);
  if (decisionSpan !== undefined) {
    spanNames.add(decisionSpan.name);
    for (const key of Object.keys(decisionSpan.attributes)) {
      attributeKeys.add(key);
    }
  }

  for (const type of APPROVAL_TYPES) {
    const span = mapAuditEventToSpan(approvalEvent(type), CTX);
    if (span !== undefined) {
      spanNames.add(span.name);
      for (const key of Object.keys(span.attributes)) {
        attributeKeys.add(key);
      }
    }
  }

  for (const type of SECURITY_ANOMALY_TYPES) {
    const span = mapAuditEventToSpan(securityAnomalyEvent(type), CTX);
    if (span !== undefined) {
      spanNames.add(span.name);
      for (const key of Object.keys(span.attributes)) {
        attributeKeys.add(key);
      }
    }
  }

  return { spanNames, attributeKeys };
}

// ---------------------------------------------------------------------------
// Scanning the dashboard JSON for every knotrust.* token its queries
// reference (deliberately excludes `title`/`description`, by only ever
// walking `query`/`selectedTracesFields`/`selectedLogFields` subtrees).
// ---------------------------------------------------------------------------

const KNOTRUST_TOKEN_RE = /knotrust\.[A-Za-z0-9_.]*[A-Za-z0-9_]/g;

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const v of Object.values(value)) collectStrings(v, out);
  }
}

function knotrustTokensReferencedBy(widget: DashboardWidget): Set<string> {
  const strings: string[] = [];
  collectStrings(widget.query, strings);
  collectStrings(widget.selectedTracesFields, strings);
  collectStrings(widget.selectedLogFields, strings);

  const tokens = new Set<string>();
  for (const s of strings) {
    const matches = s.match(KNOTRUST_TOKEN_RE) ?? [];
    for (const token of matches) tokens.add(token);
  }
  return tokens;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("knotrust-dogfood.dashboard.json — well-formed SigNoz export (P0-E8-T2)", () => {
  it("parses as valid JSON with the expected top-level shape", () => {
    const dashboard = parseDashboard();
    expect(typeof dashboard.title).toBe("string");
    expect(Array.isArray(dashboard.widgets)).toBe(true);
    expect(Array.isArray(dashboard.layout)).toBe(true);
    expect(dashboard.widgets.length).toBeGreaterThan(0);
  });

  it("every layout entry's 'i' matches exactly one widget id, and vice versa (no orphaned/duplicate layout or widget entries)", () => {
    const dashboard = parseDashboard();
    const widgetIds = dashboard.widgets.map((w) => w.id);
    const layoutIds = dashboard.layout.map((l) => l.i);
    expect(new Set(widgetIds).size).toBe(widgetIds.length);
    expect(new Set(layoutIds).size).toBe(layoutIds.length);
    expect([...widgetIds].sort()).toEqual([...layoutIds].sort());
  });

  it("covers all five required panel families (decisions/outcome, latency, denial reasons, fail-open, approval resolution)", () => {
    const dashboard = parseDashboard();
    const titles = dashboard.widgets.map((w) => w.id).join(" | ");
    expect(titles).toMatch(/decisions-per-minute-by-outcome/);
    expect(titles).toMatch(/latency/);
    expect(titles).toMatch(/denial-reasons/);
    expect(titles).toMatch(/fail-open-firings/);
    expect(titles).toMatch(/approval-resolution-time/);
  });
});

describe("attribute-consistency: every knotrust.* token a panel queries is real (P0-E8-T2, ruling R3b)", () => {
  it("sanity: the real emitted shape is non-empty (guards against a fixture bug making the check below vacuous)", () => {
    const { spanNames, attributeKeys } = computeRealEmittedShape();
    // 1 decision span name + 6 approval-phase span names + 5 security-anomaly span names (R132).
    expect(spanNames.size).toBe(12);
    // knotrust.tool/server/seq/subject/agent (common) + tier/outcome/reason/cache_hit/latency_ms (decision) + approval_id (approval).
    // The five R132 security-anomaly spans reuse this same attribute vocabulary (tier/approval_id/reason), adding no NEW keys.
    expect(attributeKeys.size).toBeGreaterThanOrEqual(10);
  });

  it("the token scanner itself actually flags drift (not a vacuous pass — self-check)", () => {
    const { spanNames, attributeKeys } = computeRealEmittedShape();
    const validTokens = new Set<string>([...spanNames, ...attributeKeys]);
    const strings: string[] = [];
    collectStrings(
      { filter: { expression: "knotrust.totally_made_up_attribute = 'x'" } },
      strings,
    );
    const found = new Set(strings.join(" ").match(KNOTRUST_TOKEN_RE) ?? []);
    expect(found.has("knotrust.totally_made_up_attribute")).toBe(true);
    expect(validTokens.has("knotrust.totally_made_up_attribute")).toBe(false);
  });

  it("every knotrust.* token referenced by every panel's query/fields is a real, currently-emitted span name or attribute key", () => {
    const { spanNames, attributeKeys } = computeRealEmittedShape();
    const validTokens = new Set<string>([
      ...spanNames,
      ...attributeKeys,
      // The wildcard span-name filter for the approval-resolution panel
      // (`name LIKE 'knotrust.approval.%'`) resolves, after stripping the
      // trailing `%`, to exactly this real, exported constant.
      APPROVAL_SPAN_NAME_PREFIX,
      DECISION_SPAN_NAME,
    ]);

    const dashboard = parseDashboard();
    const offenders: string[] = [];

    for (const widget of dashboard.widgets) {
      const tokens = knotrustTokensReferencedBy(widget);
      for (const token of tokens) {
        if (!validTokens.has(token)) {
          offenders.push(
            `widget "${widget.id}" references unknown token "${token}"`,
          );
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
