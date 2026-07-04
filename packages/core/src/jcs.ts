/**
 * @knotrust/core — RFC 8785 (JCS) canonicalizer (P0-E3-T3, ruling R33).
 *
 * ## A FROZEN cross-language artifact
 *
 * `canonicalizeJcs` is the byte-exact canonical-JSON producer the SARC
 * normal-form call-hash is computed over (see `packages/grants/src/callhash.ts`
 * and `golden-vectors/schemas/sarc-normal-form.v1.md`). Its output is FROZEN:
 * the Phase-3 Python port MUST reproduce the same bytes for the same input, or
 * an ephemeral grant minted by the TypeScript enforcement path would fail to
 * verify under a Python one (and vice-versa). Change the profile below only
 * with a version bump + a golden-vector bump (R33 versioning policy).
 *
 * ## Relationship to `canonicalStringify` (canonical-json.ts)
 *
 * `canonical-json.ts`'s `canonicalStringify` is the decision-cache's own
 * key-hashing serializer; it was written to be *JCS-compatible for the plain
 * JSON shapes the cache feeds it* but explicitly disclaimed being a full JCS
 * implementation. THIS module FORMALIZES and supersedes it for frozen
 * artifacts: it commits to the full RFC 8785 profile (below) as the pinned
 * contract, not a best-effort compatibility. Per R33 the cache and
 * `canonicalStringify` are left UNTOUCHED — no refactor here — so the two
 * coexist: the cache keeps its util, frozen artifacts use this one.
 *
 * ## The JCS profile this pins (RFC 8785)
 *
 * - **No insignificant whitespace** — objects/arrays are emitted with no
 *   spaces or newlines (`{"a":1,"b":[2,3]}`).
 * - **Object property names sorted by UTF-16 code unit** (RFC 8785 §3.2.3).
 *   JavaScript strings are UTF-16 internally and `Array.prototype.sort()` with
 *   no comparator orders by UTF-16 code-unit sequence, so the default sort IS
 *   the JCS order — including for supplementary-plane keys (surrogate pairs
 *   compare code-unit by code-unit under both). Sorting is recursive.
 * - **Array element order preserved** — never reordered.
 * - **Numbers via ECMAScript `Number::toString` shortest round-trip** (RFC
 *   8785 §3.2.2.3). `JSON.stringify(n)` for a finite number IS
 *   `! ToString(n)` per ECMA-262 `SerializeJSONProperty`, so it produces the
 *   exact JCS number form (`1e21` → `"1e+21"`, `0.000001` → `"0.000001"`,
 *   `1e-7` → `"1e-7"`). `-0` serializes as `0` (both `JSON.stringify(-0)` and
 *   `String(-0)` yield `"0"`), which JCS requires.
 * - **Strings via JCS §3.2.2.2 escaping**, which is exactly what
 *   `JSON.stringify` emits: minimal escaping (`\"`, `\\`, `\b`, `\f`, `\n`,
 *   `\r`, `\t`), control characters `< U+0020` as lowercase `\u00xx`, and all
 *   other characters (incl. non-ASCII like `é` / `😀`, and the forward slash)
 *   emitted raw as UTF-8. No `\uXXXX` escaping of non-control BMP or
 *   astral characters.
 *
 * ## Strict rejection (fail loud — this is not a lossy serializer)
 *
 * Unlike `JSON.stringify` (which silently DROPS `undefined`/function object
 * properties and COERCES `undefined`/function array elements to `null`), this
 * throws `TypeError` on any value that is not representable losslessly as
 * canonical JSON — because a silent drop/coerce would let two semantically
 * different inputs hash identically, reopening exactly the call-substitution
 * gap the call-hash exists to close:
 *
 * - `undefined`, functions, symbols, bigints — anywhere (top-level, property,
 *   or array element).
 * - non-finite numbers (`NaN`, `Infinity`, `-Infinity`) — not valid JSON.
 * - cyclic structures — rather than a stack overflow.
 *
 * A shared (diamond) reference that is NOT an ancestor of itself is fine — it
 * is serialized once per occurrence and never misreported as a cycle.
 */

/** The plain-JSON value space this canonicalizer accepts (documentation alias). */
export type JcsValue =
  | string
  | number
  | boolean
  | null
  | JcsValue[]
  | { [key: string]: JcsValue };

/**
 * Serializes `value` to its RFC 8785 (JCS) canonical JSON string. See the
 * module header for the exact profile and the frozen-artifact contract.
 * Throws `TypeError` on any non-canonical-JSON value (see header).
 */
export function canonicalizeJcs(value: unknown): string {
  return serialize(value, new Set<object>());
}

function serialize(value: unknown, ancestors: Set<object>): string {
  if (value === null) {
    return "null";
  }

  const t = typeof value;

  if (t === "boolean") {
    return value ? "true" : "false";
  }

  if (t === "string") {
    // JCS §3.2.2.2 string escaping is exactly JSON.stringify's output.
    return JSON.stringify(value);
  }

  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new TypeError(
        `canonicalizeJcs: non-finite number (${String(value)}) is not valid canonical JSON`,
      );
    }
    // JSON.stringify(n) === ! ToString(n) for finite numbers (ECMA-262
    // SerializeJSONProperty), which is RFC 8785's number form. -0 → "0".
    return JSON.stringify(value);
  }

  if (t === "undefined") {
    throw new TypeError(
      "canonicalizeJcs: undefined is not valid canonical JSON (a silent drop/coerce would let distinct inputs collide)",
    );
  }

  if (t === "function") {
    throw new TypeError(
      "canonicalizeJcs: functions are not valid canonical JSON",
    );
  }

  if (t === "bigint" || t === "symbol") {
    throw new TypeError(`canonicalizeJcs: ${t} is not valid canonical JSON`);
  }

  // t === "object": an array or a plain object (typeof null handled above).
  const obj = value as object;
  if (ancestors.has(obj)) {
    throw new TypeError(
      "canonicalizeJcs: cyclic structure cannot be canonicalized",
    );
  }
  ancestors.add(obj);
  try {
    if (Array.isArray(value)) {
      // Array order is preserved (never sorted); each element canonicalized.
      const items = value.map((item) => serialize(item, ancestors));
      return `[${items.join(",")}]`;
    }

    const record = value as Record<string, unknown>;
    // Own enumerable string keys, sorted by UTF-16 code unit (default sort).
    const keys = Object.keys(record).sort();
    const parts = keys.map(
      (key) => `${JSON.stringify(key)}:${serialize(record[key], ancestors)}`,
    );
    return `{${parts.join(",")}}`;
  } finally {
    // Pop on the way back out so a non-cyclic diamond (same object reachable
    // via two sibling branches, not via an ancestor chain) is not
    // false-flagged as a cycle.
    ancestors.delete(obj);
  }
}
