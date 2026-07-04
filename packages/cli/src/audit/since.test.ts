/**
 * `since.ts` unit tests (P0-E4-T4, R122) — `--since` accepts EITHER a
 * duration (reusing R112's parser) OR an ISO timestamp.
 */

import { describe, expect, it } from "vitest";
import { type ParsedSince, parseSince, resolveSinceEpochMs } from "./since.js";

describe("parseSince()", () => {
  it("parses a duration like the grant --expires grammar (R112)", () => {
    const result = parseSince("1h");
    expect(result).toEqual({
      ok: true,
      parsed: { kind: "duration", seconds: 3_600 },
    });
  });

  it("parses combined duration tokens", () => {
    expect(parseSince("1d12h")).toEqual({
      ok: true,
      parsed: { kind: "duration", seconds: 129_600 },
    });
  });

  it("parses an ISO 8601 timestamp", () => {
    const result = parseSince("2026-07-01T00:00:00.000Z");
    expect(result).toEqual({
      ok: true,
      parsed: {
        kind: "timestamp",
        epochMs: Date.parse("2026-07-01T00:00:00.000Z"),
      },
    });
  });

  it("parses a date-only ISO string", () => {
    const result = parseSince("2026-07-01");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.parsed.kind).toBe("timestamp");
  });

  it("rejects garbage with a clean, combined-form error — never throws", () => {
    expect(() => parseSince("not-a-duration-or-date")).not.toThrow();
    const result = parseSince("not-a-duration-or-date");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("invalid --since value");
      expect(result.error).toContain("duration");
      expect(result.error).toContain("ISO 8601");
    }
  });

  it("rejects the empty string", () => {
    expect(parseSince("").ok).toBe(false);
  });
});

describe("resolveSinceEpochMs()", () => {
  const NOW = Date.UTC(2026, 6, 4, 12, 0, 0); // 2026-07-04T12:00:00Z

  it("a duration resolves to now minus the duration", () => {
    const parsed: ParsedSince = { kind: "duration", seconds: 3_600 };
    expect(resolveSinceEpochMs(parsed, NOW)).toBe(NOW - 3_600_000);
  });

  it("a timestamp resolves to itself, ignoring now", () => {
    const epochMs = Date.UTC(2026, 5, 1, 0, 0, 0);
    const parsed: ParsedSince = { kind: "timestamp", epochMs };
    expect(resolveSinceEpochMs(parsed, NOW)).toBe(epochMs);
  });
});
