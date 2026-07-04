/**
 * `filters.ts` unit tests (P0-E4-T4, R122) — the AND-composed filter set,
 * plus the documented `--tier` derivation gap.
 */

import type { AuditEvent } from "@knotrust/store";
import { AuditEventType, computeArgsHash } from "@knotrust/store";
import { describe, expect, it } from "vitest";
import { deriveEventTier, matchesFilters } from "./filters.js";

/**
 * Allows an override to explicitly UNSET a default (e.g. `{ outcome:
 * undefined }` to build a fixture with no outcome at all) — `Partial<T>`
 * alone can't express that under this repo's `exactOptionalPropertyTypes`.
 * `event()` below strips any resulting `undefined`-valued keys before
 * returning, so the final fixture matches real events' "omitted entirely,
 * never present as `undefined`" invariant (R37).
 */
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
    seq: 1,
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

describe("matchesFilters() — AND composition (R122)", () => {
  it("no filters at all always matches", () => {
    expect(matchesFilters(event(), {})).toBe(true);
  });

  it("--tool: exact / trailing-glob / wildcard (reuses toolPatternMatches)", () => {
    const e = event({ tool: "github.create_issue" });
    expect(matchesFilters(e, { tool: "github.create_issue" })).toBe(true);
    expect(matchesFilters(e, { tool: "github.*" })).toBe(true);
    expect(matchesFilters(e, { tool: "*" })).toBe(true);
    expect(matchesFilters(e, { tool: "stripe.*" })).toBe(false);
    expect(matchesFilters(e, { tool: "github.create_issue_v2" })).toBe(false);
  });

  it("--outcome: exact equality", () => {
    const e = event({ outcome: "deny" });
    expect(matchesFilters(e, { outcome: "deny" })).toBe(true);
    expect(matchesFilters(e, { outcome: "allow" })).toBe(false);
  });

  it("--outcome: an event with no outcome at all never matches a non-empty --outcome filter", () => {
    const e = event({ outcome: undefined, type: AuditEventType.GRANT_CREATED });
    expect(matchesFilters(e, { outcome: "allow" })).toBe(false);
  });

  it("--agent: exact / trailing-glob / wildcard", () => {
    const e = event({ agent: "claude-desktop" });
    expect(matchesFilters(e, { agent: "claude-desktop" })).toBe(true);
    expect(matchesFilters(e, { agent: "*" })).toBe(true);
    expect(matchesFilters(e, { agent: "codex-cli" })).toBe(false);
  });

  it("--server: derived from the tool's leading dot-namespace segment", () => {
    expect(
      matchesFilters(event({ tool: "github.create_issue" }), {
        server: "github",
      }),
    ).toBe(true);
    expect(
      matchesFilters(event({ tool: "stripe.create_refund" }), {
        server: "github",
      }),
    ).toBe(false);
  });

  it("--since: matches events at/after the resolved cutoff, excludes strictly-before", () => {
    const cutoffMs = Date.parse("2026-07-04T09:00:00.000Z");
    expect(
      matchesFilters(event({ ts: "2026-07-04T09:00:00.000Z" }), {
        sinceEpochMs: cutoffMs,
      }),
    ).toBe(true);
    expect(
      matchesFilters(event({ ts: "2026-07-04T10:00:00.000Z" }), {
        sinceEpochMs: cutoffMs,
      }),
    ).toBe(true);
    expect(
      matchesFilters(event({ ts: "2026-07-04T08:59:59.999Z" }), {
        sinceEpochMs: cutoffMs,
      }),
    ).toBe(false);
  });

  it("combines every filter with AND — all must pass", () => {
    const e = event({
      tool: "github.create_issue",
      agent: "claude-desktop",
      outcome: "deny",
      ts: "2026-07-04T10:00:00.000Z",
    });
    expect(
      matchesFilters(e, {
        tool: "github.*",
        agent: "claude-desktop",
        outcome: "deny",
        server: "github",
        sinceEpochMs: Date.parse("2026-07-04T09:00:00.000Z"),
      }),
    ).toBe(true);
    // Flip ONE filter to a non-match — the whole predicate must fail.
    expect(
      matchesFilters(e, {
        tool: "github.*",
        agent: "claude-desktop",
        outcome: "allow", // mismatch
        server: "github",
        sinceEpochMs: Date.parse("2026-07-04T09:00:00.000Z"),
      }),
    ).toBe(false);
  });
});

describe("deriveEventTier() — R126: first-class tier field, with a legacy fail_open_fired fallback", () => {
  it("prefers the first-class event.tier field when present, on ANY event type", () => {
    const decision = event({
      type: AuditEventType.DECISION,
      outcome: "deny",
      tier: "critical",
    });
    expect(deriveEventTier(decision)).toBe("critical");
  });

  it("--tier filter now matches an ordinary decision event carrying a first-class tier (not just fail_open_fired)", () => {
    const critical = event({
      type: AuditEventType.DECISION,
      outcome: "deny",
      tier: "critical",
    });
    expect(matchesFilters(critical, { tier: "critical" })).toBe(true);
    expect(matchesFilters(critical, { tier: "sensitive" })).toBe(false);
  });

  it("falls back to the legacy fail_open_fired reason-JSON parse for a pre-R126 event with no top-level tier", () => {
    const legacyFailOpen = event({
      type: AuditEventType.FAIL_OPEN_FIRED,
      reason: JSON.stringify({ tier: "routine", cause: "x" }),
      outcome: undefined,
      tier: undefined,
    });
    expect(deriveEventTier(legacyFailOpen)).toBe("routine");
  });

  it("derives tier from a fail_open_fired event's structured reason", () => {
    const e = event({
      type: AuditEventType.FAIL_OPEN_FIRED,
      reason: JSON.stringify({ tier: "critical", cause: "decider_threw" }),
      outcome: undefined,
    });
    expect(deriveEventTier(e)).toBe("critical");
  });

  it("returns undefined for a plain decision event — tier is NOT recoverable from reasonCode text", () => {
    const e = event({
      type: AuditEventType.DECISION,
      outcome: "deny",
      reason: "no_grant_critical",
    });
    expect(deriveEventTier(e)).toBeUndefined();
  });

  it("returns undefined for a fail_open_fired event with an unparseable/missing reason", () => {
    expect(
      deriveEventTier(
        event({ type: AuditEventType.FAIL_OPEN_FIRED, reason: undefined }),
      ),
    ).toBeUndefined();
    expect(
      deriveEventTier(
        event({ type: AuditEventType.FAIL_OPEN_FIRED, reason: "not json" }),
      ),
    ).toBeUndefined();
  });

  it("--tier filter: for a LEGACY event with no first-class tier field, only fail_open_fired's structured reason is recoverable", () => {
    const failOpen = event({
      type: AuditEventType.FAIL_OPEN_FIRED,
      reason: JSON.stringify({ tier: "sensitive", cause: "x" }),
      outcome: undefined,
    });
    expect(matchesFilters(failOpen, { tier: "sensitive" })).toBe(true);
    expect(matchesFilters(failOpen, { tier: "critical" })).toBe(false);

    const decision = event({ type: AuditEventType.DECISION, outcome: "deny" });
    expect(matchesFilters(decision, { tier: "sensitive" })).toBe(false);
  });
});
