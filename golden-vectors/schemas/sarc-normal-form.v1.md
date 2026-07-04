# SARC Normal Form v1 — FROZEN artifact (call-hash binding)

**Status:** FROZEN. **Version:** `v = 1`. **Introduced:** P0-E3-T3 (rulings R32–R34).

This document specifies the **SARC normal form** and the **`callHash`** computed
over it. It is a **frozen cross-language artifact**: the reference
implementation is TypeScript (`packages/core/src/jcs.ts` +
`packages/grants/src/callhash.ts`), and the Phase-3 Python port **MUST** reproduce
every byte of the canonical string and every hex digit of the hash for the same
input. A mismatch means an ephemeral grant minted by one language's enforcement
path would fail to verify under the other's — silently reopening the TOCTOU gap
this artifact exists to close.

The authoritative vectors live in `golden-vectors/sarc-normal-form/*.json`
(`request` → `canonical` → `hash`). Any conforming implementation must pass them.

---

## 1. Purpose — closing approve-X-execute-Y (TOCTOU)

An **ephemeral** grant (minted by the approval orchestrator the instant a human
approves an escalation; architecture §5.2/§5.3, brief §I2.3) carries
`ch = callHash` of the **exact call that was approved**. At execution the
verifier re-derives the hash from the live `DecisionRequest` and requires an
exact match (`verifyGrant`, `packages/grants/src/verify.ts`, step 8). The human
approves *this call*, not "one free critical call." Without an exact, byte-stable
normal form shared across languages, that guarantee cannot hold across a mixed
TS/Python deployment.

---

## 2. The normal form (v1)

Given a `DecisionRequest` (`golden-vectors/schemas/decision-request.v1.schema.json`),
the SARC normal-form value is **exactly** these six fields — nothing else:

```
{
  "v": 1,
  "subject":   <request.subject.id>,                       // string
  "action":    <request.action.name>,                      // string
  "resource":  {
    "type":       <request.resource.type>,                 // string
    "id":         <request.resource.id>,                   // string
    "properties": <request.resource.properties ?? null>    // object | null
  },
  "agent":     <request.context.agent.id>,                 // string
  "arguments": <request.context.arguments ?? null>         // object | null
}
```

### 2.1 Field list (hashed inputs)

| Normal-form field | Source (`DecisionRequest`) | Type |
|---|---|---|
| `v` | (constant) | integer `1` |
| `subject` | `subject.id` | string |
| `action` | `action.name` | string |
| `resource.type` | `resource.type` | string |
| `resource.id` | `resource.id` | string |
| `resource.properties` | `resource.properties ?? null` | object or `null` |
| `agent` | `context.agent.id` | string |
| `arguments` | `context.arguments ?? null` | object or `null` |

`context.arguments` (added by **R32**, P0-E3-T3) is hashed **verbatim, as the
surface received it**. It is the raw tool-call arguments. It is included so two
calls that differ only in an argument that the per-tool resource-mapping never
projected into `resource.properties` still produce different hashes. Omitting it
would let those two calls collide, reopening approve-X-execute-Y.

### 2.2 Excluded fields

Everything not listed above is **excluded** and never affects the hash:
`contractVersion`, `requestId`, `timestamp`, `context.env` (incl. `time`,
`surfaceLocal`, `voiceSession`), `surface`, `toolAnnotations`, and the
`subject.type` / `subject.properties` / `action.properties` / `context.agent`
sub-fields other than `agent.id`. These are provenance/volatile metadata, not
"which call was approved."

> **Note — this is a distinct artifact from the cache key.** The decision-cache
> key (architecture §7.1) hashes a *different* projection (short field names
> `s/a/rt/ri/rp/ag/tier/policyVersion/grantSetVersion`) via a
> *different* serializer (`canonicalStringify`, `packages/core/src/canonical-json.ts`).
> That is NOT this normal form and the two must not be conflated. This document
> governs the **call-hash** only.

### 2.3 The null-for-absent rule

`resource.properties` and `arguments` are **always present** in the normal form.
When the source field is absent (`undefined`), the normal-form value is the JSON
literal `null`. Consequently an **absent** field and an **explicit `null`** are
indistinguishable in the frozen form — this is intentional and vector-locked
(`arguments-absent-vs-null.json`). No other field is ever omitted; the normal
form has a fixed shape.

---

## 3. Canonicalization — RFC 8785 (JCS)

The normal-form value is serialized with **RFC 8785 (JSON Canonicalization
Scheme)**. Reference implementation: `canonicalizeJcs` in
`packages/core/src/jcs.ts`. The pinned profile:

1. **No insignificant whitespace.** Objects and arrays carry no spaces or
   newlines: `{"a":1,"b":[2,3]}`.
2. **Object property names sorted by UTF-16 code unit** (RFC 8785 §3.2.3),
   applied **recursively** to every object. Sorting is a pure numeric comparison
   of the UTF-16 code-unit sequences of the key strings. Example — keys `"a"`,
   `"é"`, `"Z"` sort to `Z` (U+005A) < `a` (U+0061) < `é` (U+00E9), i.e.
   `{"Z":...,"a":...,"é":...}` (vector `unicode-keys.json`). Supplementary-plane
   keys (surrogate pairs) compare code-unit by code-unit.
3. **Array element order is preserved** — never reordered.
4. **Numbers** use the ECMAScript `Number::toString` shortest round-trip form
   (RFC 8785 §3.2.2.3):
   - `1` → `1`, `1.5` → `1.5`, `100` → `100`, `-42` → `-42`
   - `1e21` → `1e+21`, `0.000001` → `0.000001`, `1e-7` → `1e-7`
   - **`-0` serializes as `0`.**
   In the reference implementation this is exactly `JSON.stringify(n)` for finite
   `n` (ECMA-262 `SerializeJSONProperty` defines it as `! ToString(n)`). Ports
   must match this shortest-round-trip form (e.g. Python cannot use a naive
   `repr`/`str(float)`; it must emit the ECMAScript form — `1e+21`, not
   `1e21` or `1000000000000000000000`).
5. **Strings** use JCS §3.2.2.2 escaping, identical to `JSON.stringify`: minimal
   escapes (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`), control characters below
   U+0020 as lowercase `\u00xx`, and **all** other characters — including
   non-ASCII (`é`, `😀`) and the forward slash `/` — emitted **raw as UTF-8**,
   never `\uXXXX`-escaped.
6. The canonical string is encoded to bytes as **UTF-8** before hashing.

### 3.1 Strict rejection (no lossy inputs)

Unlike `JSON.stringify` (which drops `undefined`/function object properties and
coerces `undefined`/function array elements to `null`), the canonicalizer
**throws** on any value not losslessly representable as canonical JSON, because a
silent drop/coerce would let two distinct calls hash identically:

- `undefined`, functions, symbols, bigints — top-level, as a property value, or
  as an array element.
- non-finite numbers (`NaN`, `Infinity`, `-Infinity`).
- cyclic structures.

A shared (diamond) reference that is not its own ancestor is serialized once per
occurrence and is **not** treated as a cycle.

### 3.2 Lone (unpaired) surrogates — ES2019 escaping (normative)

A string field (`subject`, `action`, `resource.type`/`id`, `agent`, or any value
nested in `resource.properties` / `arguments`) may contain an **unpaired UTF-16
surrogate** — a high surrogate (U+D800–U+DBFF) or a low surrogate
(U+DC00–U+DFFF) with no valid pair. These are ill-formed Unicode but reachable,
because a tool-call argument is untrusted input.

The reference implementation escapes them exactly as **ES2019 "well-formed
`JSON.stringify`"** does: a lone surrogate is emitted as a **lowercase**
`\uXXXX` escape (e.g. the one-character string `"\uD800"` canonicalizes to the
eight bytes `"\ud800"`), never as a raw byte and never dropped. A **properly
paired** astral character (e.g. `"😀"` = U+D83D U+DE00) is NOT a lone surrogate
and is emitted **raw as UTF-8** per §3 rule 5.

This section is **normative** and makes explicit the existing v1 behavior — it
does not change the profile. A conforming port MUST replicate it:

- A Python port using `json.dumps(x, ensure_ascii=False)` — the natural way to
  obtain the raw-UTF-8 emission §3 rule 5 requires — will **RAISE** when it
  UTF-8-encodes a value containing a lone surrogate, rather than produce
  `\ud800`. The port MUST therefore detect unpaired surrogates and emit the
  lowercase `\uXXXX` escape itself, matching the ECMAScript output
  byte-for-byte.

### 3.3 Worked example — astral-plane key ordering (UTF-16 code units)

§3 rule 2 sorts object keys by **UTF-16 code unit**, not by Unicode code point.
The distinction is load-bearing for supplementary-plane (astral) keys, whose
first UTF-16 code unit is a high surrogate in U+D800–U+DBFF — numerically
**below** the BMP range U+E000–U+FFFF. Worked example with keys `"z"`, `"😀"`,
`"￿"`:

| Key | Code point | First UTF-16 code unit |
|---|---|---|
| `"z"`  | U+007A  | `0x007A` |
| `"😀"` | U+1F600 | `0xD83D` (high surrogate; full pair `0xD83D 0xDE00`) |
| `"￿"`  | U+FFFF  | `0xFFFF` |

Since `0x007A < 0xD83D < 0xFFFF`, the canonical key order is
`"z" < "😀" < "￿"`, i.e. the object serializes as `{"z":…,"😀":…,"￿":…}`. A
naive **code-point** sort would instead order `U+007A < U+FFFF < U+1F600` —
placing `"😀"` LAST — which is **wrong**. Ports MUST compare UTF-16 code-unit
sequences (JavaScript's default `Array.prototype.sort()` already does; a Python
port must sort on the string's UTF-16 encoding, e.g. keyed on
`s.encode("utf-16-be")`, not on code points).

---

## 4. The `callHash` string

```
callHash = "sha256:" + lowercase-hex( SHA-256( utf8( canonicalizeJcs(normalForm) ) ) )
```

- Algorithm: **SHA-256**.
- Prefix: the literal `"sha256:"` (an algorithm agility tag; future algorithms
  would use a different prefix under a version bump).
- Digest: **lowercase** hexadecimal, 64 characters.

This matches architecture §5.2's example `"ch":"sha256:9f2c1e...d41b"`. Reference:
`computeCallHash` in `packages/grants/src/callhash.ts`.

---

## 5. Timestamps (ADR-0017) — informational

No timestamp is part of the SARC normal form (all of `timestamp`,
`context.env.time`, `toolAnnotations.capturedAt` are excluded, §2.2), so RFC 3339
formatting never affects the call-hash. This note exists only to record that
where timestamps *do* appear elsewhere in the `DecisionRequest`, they are the
RFC 3339 profiled subset of ISO 8601 (ADR-0017) — and that profile is
deliberately **outside** the hashed surface here.

---

## 6. Versioning policy

- The normal form is **frozen at `v = 1`**. The `v` field is inside the hashed
  value, so a version change necessarily changes every hash.
- Any change to the **field list**, the **null-for-absent rule**, the **JCS
  profile**, or the **hash construction** is a **new version (`v = 2`)** plus a
  **golden-vector bump** (new/updated files under
  `golden-vectors/sarc-normal-form/`), **never an in-place edit** of v1. v1
  vectors remain valid v1 forever.
- Additive-only evolution is preferred: a v2 would define new hashed fields while
  keeping v1 grants verifiable under v1 rules during any migration window.
- The reference implementations (`packages/core/src/jcs.ts`,
  `packages/grants/src/callhash.ts`) and this document and the vectors move
  together; the `packages/grants/src/sarc-vectors.test.ts` suite enforces that
  the TypeScript implementation matches the vectors on every run.
