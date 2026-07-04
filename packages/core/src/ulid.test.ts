import { describe, expect, it } from "vitest";
import { createUlidGenerator } from "./ulid.js";

// ---------------------------------------------------------------------------
// Local decode helpers (test-only — the production module exposes encode
// only, per the task ruling: "Implement a minimal spec-correct ULID"). These
// mirror the spec's own encoding rules and let the suite assert round-trip
// correctness instead of hand-computing expected base32 strings, which is
// both more thorough (exercises the real 5-bit bit-slicing across byte
// boundaries) and less error-prone than transcribing bit arithmetic by hand.
// ---------------------------------------------------------------------------

const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function decodeCrockford(chars: string): number[] {
  return [...chars].map((c) => {
    const idx = CROCKFORD_ALPHABET.indexOf(c);
    if (idx === -1) {
      throw new Error(`not a Crockford base32 character: ${c}`);
    }
    return idx;
  });
}

/** Decodes the 10-char time component back to a millisecond epoch integer. */
function decodeTime(timePart: string): number {
  return decodeCrockford(timePart).reduce((acc, v) => acc * 32 + v, 0);
}

/** Decodes the 16-char randomness component back to its 10 raw entropy bytes. */
function decodeEntropy(randomPart: string): number[] {
  const digits = decodeCrockford(randomPart);
  const bytes: number[] = [];
  let bitBuffer = 0;
  let bitsInBuffer = 0;
  for (const digit of digits) {
    bitBuffer = (bitBuffer << 5) | digit;
    bitsInBuffer += 5;
    if (bitsInBuffer >= 8) {
      bitsInBuffer -= 8;
      bytes.push((bitBuffer >> bitsInBuffer) & 0xff);
    }
  }
  return bytes;
}

describe("createUlidGenerator", () => {
  it("produces a 26-character string using only the Crockford base32 alphabet", () => {
    const generate = createUlidGenerator(
      () => 1_700_000_000_000,
      () => new Uint8Array(10).fill(0x5a),
    );

    const id = generate();

    expect(id).toHaveLength(26);
    expect([...id].every((c) => CROCKFORD_ALPHABET.includes(c))).toBe(true);
  });

  it("round-trips the injected time through the 10-char time component", () => {
    const times = [0, 1, 1_469_918_176_385, 281_474_976_710_655]; // 0, 1ms, spec example, 2^48-1 (max)

    for (const t of times) {
      const generate = createUlidGenerator(
        () => t,
        () => new Uint8Array(10),
      );
      const id = generate();
      expect(decodeTime(id.slice(0, 10))).toBe(t);
    }
  });

  it("round-trips injected entropy through the 16-char random component (all-zero bytes)", () => {
    const generate = createUlidGenerator(
      () => 0,
      () => new Uint8Array(10).fill(0x00),
    );
    const id = generate();
    expect(id.slice(10)).toBe("0000000000000000");
    expect(decodeEntropy(id.slice(10))).toEqual(new Array(10).fill(0));
  });

  it("round-trips injected entropy through the 16-char random component (all-0xFF bytes)", () => {
    const generate = createUlidGenerator(
      () => 0,
      () => new Uint8Array(10).fill(0xff),
    );
    const id = generate();
    expect(id.slice(10)).toBe("ZZZZZZZZZZZZZZZZ");
    expect(decodeEntropy(id.slice(10))).toEqual(new Array(10).fill(255));
  });

  it("round-trips injected entropy through the 16-char random component (mixed/incrementing bytes)", () => {
    const bytes = new Uint8Array([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0xfe,
    ]);
    const generate = createUlidGenerator(
      () => 0,
      () => bytes,
    );
    const id = generate();
    expect(decodeEntropy(id.slice(10))).toEqual(Array.from(bytes));
  });

  it("is lexicographically sortable by increasing injected time (spec property)", () => {
    const entropy = () => new Uint8Array(10).fill(0x00);
    const earlier = createUlidGenerator(() => 1_700_000_000_000, entropy)();
    const later = createUlidGenerator(() => 1_700_000_000_001, entropy)();

    expect(earlier < later).toBe(true);
    expect(earlier.slice(0, 10) < later.slice(0, 10)).toBe(true);
  });

  it("defaults to node:crypto randomBytes when no entropy source is injected (format still valid, calls differ)", () => {
    const generate = createUlidGenerator(() => 1_700_000_000_000);
    const a = generate();
    const b = generate();

    expect(a).toHaveLength(26);
    expect(b).toHaveLength(26);
    expect(a.slice(0, 10)).toBe(b.slice(0, 10)); // same injected time
    expect(a.slice(10)).not.toBe(b.slice(10)); // independently random entropy per call
  });

  it("re-reads the injected clock on every call (not cached at generator-creation time)", () => {
    let current = 1_700_000_000_000;
    const generate = createUlidGenerator(
      () => current,
      () => new Uint8Array(10).fill(0x00),
    );

    const first = generate();
    current += 5;
    const second = generate();

    expect(decodeTime(first.slice(0, 10))).toBe(1_700_000_000_000);
    expect(decodeTime(second.slice(0, 10))).toBe(1_700_000_000_005);
  });

  it("rejects a time outside the 48-bit unsigned range", () => {
    const generate = createUlidGenerator(
      () => 2 ** 48,
      () => new Uint8Array(10),
    );
    expect(() => generate()).toThrow(RangeError);
  });

  it("rejects entropy of the wrong byte length", () => {
    const generate = createUlidGenerator(
      () => 0,
      () => new Uint8Array(9),
    );
    expect(() => generate()).toThrow(RangeError);
  });
});
