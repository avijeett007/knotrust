/**
 * P0-E7-T2, R112 — duration parsing. Exact-value acceptance: `"30d"` must
 * land on exactly `2_592_000` seconds (the same 30-day constant
 * `@knotrust/grants`' `grant-test-kit.ts` uses for its own durable fixture).
 */

import { describe, expect, it } from "vitest";
import { parseDuration } from "./duration.js";

describe("parseDuration (R112)", () => {
  it.each([
    ["30d", 2_592_000],
    ["12h", 43_200],
    ["90m", 5_400],
    ["1w", 604_800],
    ["1s", 1],
    ["1d12h", 129_600],
    ["1w1d", 691_200],
    ["2h30m", 9_000],
    ["  1d  ", 86_400], // surrounding whitespace is tolerated (trimmed)
  ])("parses %s to exactly %d seconds", (input, expected) => {
    const result = parseDuration(input);
    expect(result).toEqual({ ok: true, seconds: expected });
  });

  it.each([
    [""],
    ["   "],
    ["abc"],
    ["30"],
    ["30x"],
    ["-5d"],
    ["0d"],
    ["0s"],
    ["1D"],
    ["d30"],
  ])("rejects %j with a clean error, never throwing", (input) => {
    expect(() => parseDuration(input)).not.toThrow();
    const result = parseDuration(input);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("invalid duration");
    }
  });
});
