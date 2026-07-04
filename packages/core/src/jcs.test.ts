/**
 * @knotrust/core — RFC 8785 (JCS) canonicalizer tests (P0-E3-T3, R33).
 *
 * `canonicalizeJcs` is a FROZEN cross-language artifact: the Phase-3 Python
 * port must reproduce its output byte-for-byte. These cases lock the JCS
 * profile that freeze depends on — UTF-16-code-unit key ordering,
 * ECMAScript-shortest-round-trip number formatting (incl. `-0` → `0`), JCS
 * string escaping, and strict rejection of non-JSON values — so a future
 * change to the canonicalizer that silently alters bytes trips a test here.
 */

import { describe, expect, it } from "vitest";
import { canonicalizeJcs } from "./jcs.js";

describe("canonicalizeJcs — primitives", () => {
  it("serializes null / booleans", () => {
    expect(canonicalizeJcs(null)).toBe("null");
    expect(canonicalizeJcs(true)).toBe("true");
    expect(canonicalizeJcs(false)).toBe("false");
  });

  it("serializes plain strings", () => {
    expect(canonicalizeJcs("hello")).toBe('"hello"');
    expect(canonicalizeJcs("")).toBe('""');
  });
});

describe("canonicalizeJcs — number formatting (ECMAScript shortest round-trip)", () => {
  it("formats integers and decimals", () => {
    expect(canonicalizeJcs(1)).toBe("1");
    expect(canonicalizeJcs(-42)).toBe("-42");
    expect(canonicalizeJcs(1.5)).toBe("1.5");
    expect(canonicalizeJcs(100)).toBe("100");
    expect(canonicalizeJcs(0)).toBe("0");
  });

  it("formats exponential forms exactly as JSON.stringify (RFC 8785 = ES Number::toString)", () => {
    expect(canonicalizeJcs(1e21)).toBe("1e+21");
    expect(canonicalizeJcs(0.000001)).toBe("0.000001");
    expect(canonicalizeJcs(1e-7)).toBe("1e-7");
  });

  it("serializes -0 as 0 (RFC 8785 §3.2.2.3 / ES Number::toString)", () => {
    expect(canonicalizeJcs(-0)).toBe("0");
    expect(canonicalizeJcs([-0])).toBe("[0]");
    expect(canonicalizeJcs({ x: -0 })).toBe('{"x":0}');
  });
});

describe("canonicalizeJcs — object key ordering by UTF-16 code unit", () => {
  it("sorts keys ascending by code unit", () => {
    expect(canonicalizeJcs({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("locks the unicode ordering of keys a / é / Z (Z=0x5A < a=0x61 < é=0xE9)", () => {
    expect(canonicalizeJcs({ a: 1, é: 2, Z: 3 })).toBe('{"Z":3,"a":1,"é":2}');
  });

  it("sorts recursively through nested objects, preserving array order", () => {
    expect(canonicalizeJcs({ z: { y: 1, x: 2 }, a: [3, 2, 1] })).toBe(
      '{"a":[3,2,1],"z":{"x":2,"y":1}}',
    );
  });

  it("emits no whitespace", () => {
    expect(canonicalizeJcs({ a: 1, b: [2, 3] })).toBe('{"a":1,"b":[2,3]}');
  });
});

describe("canonicalizeJcs — arrays", () => {
  it("preserves element order (never sorted)", () => {
    expect(canonicalizeJcs([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalizeJcs([])).toBe("[]");
  });

  it("canonicalizes each element", () => {
    expect(canonicalizeJcs([-0, 1e21, 0.000001, null, true])).toBe(
      "[0,1e+21,0.000001,null,true]",
    );
  });
});

describe("canonicalizeJcs — string escaping follows JCS (= JSON.stringify)", () => {
  const cases = [
    'a"b',
    "a\\b",
    "line1\nline2",
    "tab\tend",
    "ctrlchar",
    "unicode-é",
    "emoji-😀",
    "/no slash escape/",
  ];
  for (const s of cases) {
    it(`escapes ${JSON.stringify(s)} identically to JSON.stringify`, () => {
      expect(canonicalizeJcs(s)).toBe(JSON.stringify(s));
    });
  }
});

describe("canonicalizeJcs — strict rejection of non-JSON values", () => {
  it("rejects top-level undefined", () => {
    expect(() => canonicalizeJcs(undefined)).toThrow(TypeError);
  });

  it("rejects undefined as an object property (NOT silently dropped like JSON.stringify)", () => {
    expect(() => canonicalizeJcs({ a: undefined })).toThrow(TypeError);
  });

  it("rejects undefined as an array element (NOT coerced to null like JSON.stringify)", () => {
    expect(() => canonicalizeJcs([1, undefined, 2])).toThrow(TypeError);
  });

  it("rejects functions, symbols, and bigints", () => {
    expect(() => canonicalizeJcs(() => 1)).toThrow(TypeError);
    expect(() => canonicalizeJcs(Symbol("s"))).toThrow(TypeError);
    expect(() => canonicalizeJcs(10n)).toThrow(TypeError);
    expect(() => canonicalizeJcs({ a: 10n })).toThrow(TypeError);
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalizeJcs(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalizeJcs(Number.POSITIVE_INFINITY)).toThrow(TypeError);
    expect(() => canonicalizeJcs(Number.NEGATIVE_INFINITY)).toThrow(TypeError);
  });

  it("rejects cyclic structures instead of overflowing the stack", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalizeJcs(cyclic)).toThrow(TypeError);
  });

  it("does NOT false-positive a shared (diamond) non-cyclic reference as a cycle", () => {
    const shared = { v: 1 };
    expect(canonicalizeJcs({ a: shared, b: shared })).toBe(
      '{"a":{"v":1},"b":{"v":1}}',
    );
  });
});
