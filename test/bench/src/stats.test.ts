import { describe, expect, it } from "vitest";
import { percentileOfSorted, subtractPercentiles, summarize } from "./stats.js";

describe("percentileOfSorted", () => {
  it("nearest-rank: p50 of [1..10] is the 5th value (rank = ceil(0.5*10) = 5)", () => {
    const sorted = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    expect(percentileOfSorted(sorted, 50)).toBe(5);
    expect(percentileOfSorted(sorted, 95)).toBe(10);
    expect(percentileOfSorted(sorted, 100)).toBe(10);
    expect(percentileOfSorted(sorted, 1)).toBe(1);
  });

  it("a single-sample array returns that sample for every percentile", () => {
    expect(percentileOfSorted([42], 50)).toBe(42);
    expect(percentileOfSorted([42], 99)).toBe(42);
  });

  it("throws on an empty array rather than returning NaN", () => {
    expect(() => percentileOfSorted([], 50)).toThrow(/zero samples/);
  });

  it("throws on an out-of-range percentile", () => {
    expect(() => percentileOfSorted([1, 2, 3], 101)).toThrow(/p must be in/);
  });
});

describe("summarize", () => {
  it("computes p50/p95/p99/mean/min/max/count over an unsorted sample", () => {
    const durations = [5, 1, 3, 4, 2];
    const s = summarize(durations);
    expect(s.min).toBe(1);
    expect(s.max).toBe(5);
    expect(s.mean).toBe(3);
    expect(s.count).toBe(5);
    expect(s.p50).toBe(3);
  });

  it("throws on zero samples", () => {
    expect(() => summarize([])).toThrow(/zero samples/);
  });
});

describe("subtractPercentiles", () => {
  it("subtracts each percentile independently (on minus off)", () => {
    const on = summarize([10, 12, 14, 16, 20]);
    const off = summarize([1, 2, 3, 4, 5]);
    const added = subtractPercentiles(on, off);
    expect(added.p50).toBeCloseTo(on.p50 - off.p50);
    expect(added.p95).toBeCloseTo(on.p95 - off.p95);
    expect(added.p99).toBeCloseTo(on.p99 - off.p99);
  });

  it("can be negative when the 'off' run happened to be noisier than 'on' (honest — never clamped to zero)", () => {
    const on = summarize([1, 1, 1]);
    const off = summarize([100, 100, 100]);
    const added = subtractPercentiles(on, off);
    expect(added.p50).toBeLessThan(0);
  });
});
