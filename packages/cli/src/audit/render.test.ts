/**
 * `render.ts` unit tests (P0-E4-T4, R122/R125).
 */

import type { AuditEvent } from "@knotrust/store";
import { AuditEventType, computeArgsHash } from "@knotrust/store";
import { describe, expect, it } from "vitest";
import {
  formatEventJsonLine,
  formatEventLine,
  renderEventLines,
} from "./render.js";

/** See `filters.test.ts`'s identical helper for why this isn't just `Partial<AuditEvent>` under `exactOptionalPropertyTypes`. */
type EventOverrides = { [K in keyof AuditEvent]?: AuditEvent[K] | undefined };

function stripUndefined<T extends object>(obj: T): T {
  const out = {} as T;
  for (const key of Object.keys(obj) as (keyof T)[]) {
    if (obj[key] !== undefined) out[key] = obj[key];
  }
  return out;
}

function event(over: EventOverrides = {}): AuditEvent {
  const merged = {
    seq: 7,
    ts: "2026-07-04T10:00:00.000Z",
    prevHash: "0".repeat(64),
    hash: "a".repeat(64),
    type: AuditEventType.DECISION,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "claude-desktop",
    tool: "github.create_issue",
    argsHash: computeArgsHash(null),
    outcome: "deny",
    ...over,
  };
  return stripUndefined(merged) as AuditEvent;
}

describe("formatEventJsonLine() — NDJSON, the raw stored event (R125)", () => {
  it("is exactly JSON.stringify(event) — no derived/lossy shape, no secrets added", () => {
    const e = event();
    expect(formatEventJsonLine(e)).toBe(JSON.stringify(e));
  });

  it("round-trips back to an equivalent object", () => {
    const e = event({ reason: "tier_exceeded", grantRefs: ["01JZ"] });
    expect(JSON.parse(formatEventJsonLine(e))).toEqual(e);
  });
});

describe("formatEventLine() — compact single-line human format", () => {
  it("includes ts/seq/type/outcome/tool/agent always", () => {
    const line = formatEventLine(event());
    expect(line).toContain("2026-07-04T10:00:00.000Z");
    expect(line).toContain("seq=7");
    expect(line).toContain("type=decision");
    expect(line).toContain("outcome=deny");
    expect(line).toContain("tool=github.create_issue");
    expect(line).toContain("agent=claude-desktop");
  });

  it("includes argsHash (M3, R125 follow-up) — a hash, never raw arguments — for forensic completeness in the human line too", () => {
    const e = event({ argsHash: computeArgsHash({ repo: "knotrust" }) });
    const line = formatEventLine(e);
    expect(line).toContain(`argsHash=${e.argsHash}`);
    expect(e.argsHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("renders outcome=- when outcome is absent (never the literal 'undefined')", () => {
    const line = formatEventLine(
      event({ type: AuditEventType.GRANT_CREATED, outcome: undefined }),
    );
    expect(line).toContain("outcome=-");
    expect(line).not.toContain("undefined");
  });

  it("appends reason= only when present", () => {
    expect(formatEventLine(event({ reason: undefined }))).not.toContain(
      "reason=",
    );
    expect(formatEventLine(event({ reason: "no_grant_critical" }))).toContain(
      "reason=no_grant_critical",
    );
  });

  it("appends grants=<jti,jti> only when grantRefs is non-empty", () => {
    expect(formatEventLine(event({ grantRefs: undefined }))).not.toContain(
      "grants=",
    );
    expect(formatEventLine(event({ grantRefs: [] }))).not.toContain("grants=");
    expect(formatEventLine(event({ grantRefs: ["01JZA", "01JZB"] }))).toContain(
      "grants=01JZA,01JZB",
    );
  });
});

describe("renderEventLines() — preserves the given array order", () => {
  it("joins one formatted line per event, in order, newline-separated", () => {
    const events = [event({ seq: 1 }), event({ seq: 2 }), event({ seq: 3 })];
    const rendered = renderEventLines(events);
    const lines = rendered.split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[0]).toContain("seq=1");
    expect(lines[1]).toContain("seq=2");
    expect(lines[2]).toContain("seq=3");
  });

  it("renders an empty array as an empty string", () => {
    expect(renderEventLines([])).toBe("");
  });
});
