/**
 * `ring-buffer.ts` unit tests (P0-E4-T4, R123) — the bounded-memory "keep
 * last N" primitive `audit list|tail` are built on.
 */

import { describe, expect, it } from "vitest";
import { createRingBuffer } from "./ring-buffer.js";

describe("createRingBuffer()", () => {
  it("keeps everything pushed while under capacity, in order", () => {
    const rb = createRingBuffer<number>(5);
    rb.push(1);
    rb.push(2);
    rb.push(3);
    expect(rb.toArray()).toEqual([1, 2, 3]);
  });

  it("keeps exactly the LAST N items, in original order, once over capacity", () => {
    const rb = createRingBuffer<number>(3);
    for (let i = 1; i <= 10; i++) rb.push(i);
    expect(rb.toArray()).toEqual([8, 9, 10]);
  });

  it("capacity 1 keeps only the most recent item", () => {
    const rb = createRingBuffer<string>(1);
    rb.push("a");
    rb.push("b");
    rb.push("c");
    expect(rb.toArray()).toEqual(["c"]);
  });

  it("an empty buffer's toArray() is an empty array", () => {
    expect(createRingBuffer<number>(5).toArray()).toEqual([]);
  });

  it("handles a large number of pushes over a small capacity without growing memory (bounded array length)", () => {
    const rb = createRingBuffer<number>(50);
    for (let i = 0; i < 1_000_000; i++) rb.push(i);
    const result = rb.toArray();
    expect(result).toHaveLength(50);
    expect(result[0]).toBe(999_950);
    expect(result[49]).toBe(999_999);
  });

  it("rejects a non-positive-integer capacity", () => {
    expect(() => createRingBuffer(0)).toThrow();
    expect(() => createRingBuffer(-1)).toThrow();
    expect(() => createRingBuffer(1.5)).toThrow();
  });
});
