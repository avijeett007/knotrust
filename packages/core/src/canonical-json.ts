/**
 * @knotrust/core — canonicalStringify (R16 ruling 2, P0-E2-T4).
 *
 * A recursively key-sorted, whitespace-free JSON serializer used by
 * `decision-cache.ts` to build a stable hash input from a `DecisionRequest`
 * subset. It is deliberately **JCS (RFC 8785)-compatible** for the plain
 * JSON shapes the cache feeds it (finite numbers, strings, booleans, null,
 * plain objects, arrays — no dates, maps, sets, or other non-JSON types):
 * object keys are sorted by UTF-16 code unit (matching both JS's default
 * string `<`/`sort()` ordering and JCS §3.2.3, since JS strings are UTF-16
 * internally), arrays keep their original order, and numbers/strings/
 * booleans/null are emitted via `JSON.stringify`'s own encoding (which
 * matches ECMA-262 `Number::toString` for the finite-number range this
 * module accepts).
 *
 * This is NOT a full JCS implementation — it doesn't handle every ES2015
 * numeric edge case JCS pins (e.g. `Number.MAX_SAFE_INTEGER`-adjacent
 * rounding) and has no opinion on non-JSON types. **E3-T3 will freeze the
 * full JCS SARC normal form**; this util may be superseded by that frozen
 * canonicalizer then. Until then it's the one canonicalization path the
 * decision cache (and only the decision cache) depends on.
 *
 * Deliberately REJECTS rather than silently drops or coerces:
 * - `undefined` (unlike `JSON.stringify`, which drops undefined object
 *   properties and turns undefined array elements into `null` — both would
 *   make two semantically different cache-key inputs hash identically).
 * - functions (same silent-drop hazard as `undefined`).
 * - cyclic structures (rather than a stack overflow).
 * - non-finite numbers (`NaN`, `Infinity`, `-Infinity` — not valid JSON).
 *
 * `bigint`/`symbol` are rejected too — neither is a valid canonical JSON
 * value and neither can appear in an unmodified `DecisionRequest`.
 */

/** A no-op alias documenting the plain-JSON shapes this module accepts and returns. */
export type CanonicalJsonValue =
  | string
  | number
  | boolean
  | null
  | CanonicalJsonValue[]
  | { [key: string]: CanonicalJsonValue };

export function canonicalStringify(value: unknown): string {
  return stringify(value, new Set<unknown>());
}

function stringify(value: unknown, seen: Set<unknown>): string {
  if (value === null) {
    return "null";
  }

  const t = typeof value;

  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new TypeError(
        `canonicalStringify: non-finite number (${String(value)}) is not a valid canonical JSON value`,
      );
    }
    return JSON.stringify(value);
  }

  if (t === "boolean" || t === "string") {
    return JSON.stringify(value);
  }

  if (t === "undefined") {
    throw new TypeError(
      "canonicalStringify: undefined is not a valid canonical JSON value",
    );
  }

  if (t === "function") {
    throw new TypeError(
      "canonicalStringify: functions are not valid canonical JSON values",
    );
  }

  if (t === "bigint" || t === "symbol") {
    throw new TypeError(
      `canonicalStringify: ${t} is not a valid canonical JSON value`,
    );
  }

  // t === "object": plain object or array (typeof null already handled above).
  if (seen.has(value)) {
    throw new TypeError(
      "canonicalStringify: cyclic structure cannot be canonicalized",
    );
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const items = value.map((item) => stringify(item, seen));
      return `[${items.join(",")}]`;
    }

    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map(
      (key) => `${JSON.stringify(key)}:${stringify(obj[key], seen)}`,
    );
    return `{${parts.join(",")}}`;
  } finally {
    // Remove on the way back out: a non-cyclic diamond reference (the same
    // object reachable via two sibling branches, not an ancestor chain)
    // must not false-positive as a cycle.
    seen.delete(value);
  }
}
