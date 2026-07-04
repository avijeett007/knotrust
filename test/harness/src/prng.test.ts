import { describe, expect, it } from "vitest";
import { createSeededPrng } from "./prng.js";

describe("createSeededPrng", () => {
  it("produces an identical sequence for the same seed", () => {
    const a = createSeededPrng(42);
    const b = createSeededPrng(42);
    const seqA = Array.from({ length: 20 }, () => a.next());
    const seqB = Array.from({ length: 20 }, () => b.next());
    expect(seqA).toEqual(seqB);
  });

  it("produces a different sequence for a different seed", () => {
    const a = createSeededPrng(1);
    const b = createSeededPrng(2);
    const seqA = Array.from({ length: 20 }, () => a.next());
    const seqB = Array.from({ length: 20 }, () => b.next());
    expect(seqA).not.toEqual(seqB);
  });

  it("never produces Math.random-style values outside [0, 1)", () => {
    const prng = createSeededPrng(7);
    for (let i = 0; i < 1000; i++) {
      const value = prng.next();
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(1);
    }
  });

  it("nextInt stays within [min, max] inclusive, deterministically", () => {
    const a = createSeededPrng(99);
    const b = createSeededPrng(99);
    for (let i = 0; i < 200; i++) {
      const valueA = a.nextInt(10, 20);
      const valueB = b.nextInt(10, 20);
      expect(valueA).toBe(valueB);
      expect(valueA).toBeGreaterThanOrEqual(10);
      expect(valueA).toBeLessThanOrEqual(20);
    }
  });

  it("nextInt rejects max < min", () => {
    const prng = createSeededPrng(1);
    expect(() => prng.nextInt(5, 1)).toThrow(RangeError);
  });

  it("pick always returns an element of the array, deterministically", () => {
    const a = createSeededPrng(5);
    const b = createSeededPrng(5);
    const items = ["x", "y", "z"];
    for (let i = 0; i < 50; i++) {
      const pickA = a.pick(items);
      const pickB = b.pick(items);
      expect(pickA).toBe(pickB);
      expect(items).toContain(pickA);
    }
  });

  it("pick rejects an empty array", () => {
    const prng = createSeededPrng(1);
    expect(() => prng.pick([])).toThrow(RangeError);
  });

  it("exposes the seed it was constructed from", () => {
    expect(createSeededPrng(1234).seed).toBe(1234);
  });
});
