import { describe, expect, it } from "vitest";
import { canonicalStringify } from "./canonical-json.js";

// ---------------------------------------------------------------------------
// canonicalStringify (R16 ruling 2, P0-E2-T4) — recursively key-sorted JSON,
// no whitespace, deliberately JCS (RFC 8785)-compatible for the plain-JSON
// shapes the decision cache feeds it. See canonical-json.ts's header for the
// full seam note (superseded by the frozen SARC normal form at E3-T3).
// ---------------------------------------------------------------------------

describe("canonicalStringify — primitives", () => {
  it("encodes strings, numbers, booleans, and null exactly like JSON.stringify", () => {
    expect(canonicalStringify("hello")).toBe('"hello"');
    expect(canonicalStringify(42)).toBe("42");
    expect(canonicalStringify(0)).toBe("0");
    expect(canonicalStringify(-0)).toBe("0");
    expect(canonicalStringify(true)).toBe("true");
    expect(canonicalStringify(false)).toBe("false");
    expect(canonicalStringify(null)).toBe("null");
  });

  it("rejects non-finite numbers (NaN, Infinity) cleanly", () => {
    expect(() => canonicalStringify(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalStringify(Number.POSITIVE_INFINITY)).toThrow(
      TypeError,
    );
    expect(() => canonicalStringify(Number.NEGATIVE_INFINITY)).toThrow(
      TypeError,
    );
  });
});

describe("canonicalStringify — objects: key sorting, no whitespace", () => {
  it("sorts top-level keys lexicographically", () => {
    expect(canonicalStringify({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("emits no whitespace anywhere", () => {
    const out = canonicalStringify({ z: [1, 2, 3], a: { y: 1, x: 2 } });
    expect(out).not.toMatch(/\s/);
  });

  it("sorts nested object keys recursively (deep-sorted)", () => {
    const out = canonicalStringify({ outer: { z: 1, a: { d: 1, c: 2 } } });
    expect(out).toBe('{"outer":{"a":{"c":2,"d":1},"z":1}}');
  });

  it("produces identical output regardless of property insertion order", () => {
    const a = { rp: { amount: 100, currency: "usd" }, s: "u1" };
    const b = { s: "u1", rp: { currency: "usd", amount: 100 } };
    expect(canonicalStringify(a)).toBe(canonicalStringify(b));
  });
});

describe("canonicalStringify — arrays: order preserved, not sorted", () => {
  it("preserves array element order", () => {
    expect(canonicalStringify([3, 1, 2])).toBe("[3,1,2]");
  });

  it("still deep-sorts object keys nested inside array elements", () => {
    const out = canonicalStringify([
      { b: 1, a: 2 },
      { d: 3, c: 4 },
    ]);
    expect(out).toBe('[{"a":2,"b":1},{"c":4,"d":3}]');
  });
});

describe("canonicalStringify — rejects invalid canonical JSON values", () => {
  it("rejects a bare undefined", () => {
    expect(() => canonicalStringify(undefined)).toThrow(TypeError);
  });

  it("rejects undefined nested in an object value", () => {
    expect(() => canonicalStringify({ a: undefined })).toThrow(TypeError);
  });

  it("rejects undefined nested in an array element", () => {
    expect(() => canonicalStringify([1, undefined, 3])).toThrow(TypeError);
  });

  it("rejects a bare function", () => {
    expect(() => canonicalStringify(() => {})).toThrow(TypeError);
  });

  it("rejects a function nested in an object value", () => {
    expect(() => canonicalStringify({ f: () => {} })).toThrow(TypeError);
  });

  it("rejects a cyclic object cleanly (no stack overflow)", () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic.self = cyclic;
    expect(() => canonicalStringify(cyclic)).toThrow(TypeError);
  });

  it("rejects a cyclic array cleanly", () => {
    const cyclic: unknown[] = [1, 2];
    cyclic.push(cyclic);
    expect(() => canonicalStringify(cyclic)).toThrow(TypeError);
  });

  it("does NOT false-positive on a shared (non-cyclic) reference appearing twice", () => {
    const shared = { x: 1 };
    const value = { left: shared, right: shared };
    expect(() => canonicalStringify(value)).not.toThrow();
    expect(canonicalStringify(value)).toBe('{"left":{"x":1},"right":{"x":1}}');
  });
});
