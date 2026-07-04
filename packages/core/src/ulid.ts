/**
 * @knotrust/core — minimal, spec-correct ULID generator (P0-E2-T5, ruling
 * R19).
 *
 * `DecisionResponse.decisionId` (contract.ts) is a ULID — a 26-character,
 * Crockford base32-encoded, lexicographically sortable identifier: 48 bits
 * of millisecond-precision time (10 chars) followed by 80 bits of
 * cryptographic randomness (16 chars). See the ULID spec
 * (github.com/ulid/spec) for the reference encoding.
 *
 * Both the clock and the entropy source are INJECTED, never read from a
 * module-level `Date.now()`/`crypto.randomBytes()` call directly — matching
 * every other pure/testable module in this package (`nowEpochSeconds` in
 * `precedence.ts`/`decision-cache.ts`). `createUlidGenerator(nowMs,
 * randomBytes?)` returns a `() => string` generator function; `nowMs` and
 * `randomBytes` are both re-invoked on EVERY call to that returned function
 * (never cached at generator-creation time), so a single generator instance
 * correctly produces a fresh, time-accurate ULID each call.
 *
 * `randomBytes` defaults to `node:crypto`'s `randomBytes` (cryptographically
 * secure). Tests inject a deterministic byte source instead. No new
 * dependencies — this is a from-scratch implementation, not a wrapper
 * around an `ulid`/`ulidx` package.
 */

import { randomBytes as nodeRandomBytes } from "node:crypto";

/** Crockford's Base32 alphabet — excludes I, L, O, U to avoid transcription ambiguity. */
const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** 48-bit unsigned max — the largest millisecond epoch a 10-char time component can encode. */
const MAX_TIME_MS = 2 ** 48 - 1;

const TIME_CHARS = 10;
const ENTROPY_BYTES = 10; // 80 bits
const ENTROPY_CHARS = 16; // 80 bits / 5 bits-per-char, exact — no padding needed

export type RandomBytesFn = (byteLength: number) => Uint8Array;

/**
 * Encodes a non-negative integer `< 2^48` as a fixed-width, 10-character
 * Crockford base32 string (most-significant digit first). Plain
 * division/modulo by 32 — exact for any integer within `Number`'s safe
 * range (48 bits is well under the 53-bit safe-integer ceiling), so this
 * never needs bitwise operators (which truncate to 32 bits in JS and would
 * silently corrupt a 48-bit timestamp).
 */
function encodeTime(ms: number, len: number): string {
  let value = ms;
  let out = "";
  for (let i = 0; i < len; i++) {
    const digit = value % 32;
    out = CROCKFORD_ALPHABET[digit] + out;
    value = (value - digit) / 32;
  }
  return out;
}

/**
 * Encodes a byte buffer as Crockford base32 via exact 5-bit-group bit
 * slicing (a standard base32 encode, RFC 4648 §6 mechanics with Crockford's
 * alphabet substituted in). `bitBuffer` never holds more than 12 bits at
 * once (at most 4 leftover bits from a prior drain + 8 new bits), so plain
 * `number` bitwise operators (32-bit-safe) are exact — no precision loss.
 * Exact for `ENTROPY_BYTES` (10 bytes = 80 bits = 16 * 5 bits, no
 * remainder), so no trailing-padding branch is needed for this call site.
 */
function encodeBytes(bytes: Uint8Array): string {
  let out = "";
  let bitBuffer = 0;
  let bitsInBuffer = 0;
  for (const byte of bytes) {
    bitBuffer = (bitBuffer << 8) | byte;
    bitsInBuffer += 8;
    while (bitsInBuffer >= 5) {
      bitsInBuffer -= 5;
      out += CROCKFORD_ALPHABET[(bitBuffer >> bitsInBuffer) & 0x1f];
    }
  }
  return out;
}

function defaultRandomBytes(byteLength: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(byteLength));
}

/**
 * Returns a ULID generator function. `nowMs` and `randomBytes` are called
 * fresh on every invocation of the returned function.
 */
export function createUlidGenerator(
  nowMs: () => number,
  randomBytes: RandomBytesFn = defaultRandomBytes,
): () => string {
  return () => {
    const time = nowMs();
    if (!Number.isInteger(time) || time < 0 || time > MAX_TIME_MS) {
      throw new RangeError(
        `ulid: time must be an integer in [0, ${MAX_TIME_MS}] (48-bit unsigned ms epoch), got ${time}`,
      );
    }

    const entropy = randomBytes(ENTROPY_BYTES);
    if (entropy.length !== ENTROPY_BYTES) {
      throw new RangeError(
        `ulid: randomBytes must return exactly ${ENTROPY_BYTES} bytes, got ${entropy.length}`,
      );
    }

    const randomPart = encodeBytes(entropy);
    // Exact by construction (see `encodeBytes`'s doc-comment): 80 bits / 5
    // bits-per-char = 16 chars with zero remainder. Asserted here, not just
    // documented, so a future change to `ENTROPY_BYTES` that breaks the
    // clean division fails loudly instead of silently emitting a
    // wrong-length ULID.
    if (randomPart.length !== ENTROPY_CHARS) {
      throw new RangeError(
        `ulid: internal error — encoded entropy length ${randomPart.length} !== ${ENTROPY_CHARS}`,
      );
    }

    return encodeTime(time, TIME_CHARS) + randomPart;
  };
}
