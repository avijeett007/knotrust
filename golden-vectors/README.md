# golden-vectors

**Status: v1 frozen 2026-07-04 (P0-E3-T5).**

Language-neutral, JSON-only fixtures. These vectors are the cross-language
contract: the Phase-3 Python port (and every future refactor, in any
language) is proven correct by passing them, not by re-reading the
TypeScript source. Nothing under this directory imports or references an
MCP SDK type — every vector exercises `@knotrust/core` + `@knotrust/grants`
concepts only (mechanically enforced —
`packages/grants/src/golden-vectors-mcp-guard.test.ts` walks this entire tree
and fails on any reference to the banned npm scope; see that file's header
for the one deliberate, documented exception: core's own `mcpMethod`
contract field is not an MCP *type* reference — and note that this README
itself is scanned by that guard, which is why it never spells out the
banned scope literally).

## Corpus map

| Directory / file | Contents | Consumed by |
|---|---|---|
| `schemas/` | `decision-request.v1.schema.json`, `decision.v1.schema.json` (JSON Schema draft 2020-12 mirrors of `packages/core/src/contract.ts`); `config.v1.schema.json`; `denial-envelope.v1.schema.json` (the model-visible `structuredContent.knotrust` shape of a synthesized `tools/call` denial, P0-E5-T4 — structure only; the reusable frame-scan assertion, `@knotrust/test-harness`'s `assertNoLeakedSecrets`, is what forbids a token/policy-internal hiding inside its free-text fields); `sarc-normal-form.v1.md` (the SARC normal-form + JCS canonicalization spec, normative) | `packages/core/src/contract.test.ts`, `packages/core/src/schema-validation-fixtures.test.ts`, `packages/proxy-stdio/src/denial-envelope.test.ts` |
| `decisions/` | `DecisionRequest`/policy input → expected `PrecedenceDecision` fixtures, one per precedence rule / tier default / reason code | `packages/core/src/decision-fixtures.test.ts` |
| `grants/` | Real, signed JWS-Compact grant tokens (minted under the frozen test-only keypairs below) + verify context → expected `verifyGrant` result, one per R49-mandated case; `test-keys.json` (the two test keypairs) | `packages/grants/src/golden-vectors.test.ts` |
| `sarc-normal-form/` | `DecisionRequest` → canonical JCS string → `sha256:` call-hash, for the FROZEN SARC normal form (v1) | `packages/grants/src/sarc-vectors.test.ts` |
| `schema-validation/` | `{ name, target, value, valid }` schema-validation fixtures (positive and negative), including the ADR-0017 negative-timestamp regression guard | `packages/core/src/schema-validation-fixtures.test.ts` |

Every directory is enumerated **dynamically** by its runner (`readdirSync` +
`.json` filter) — dropping a new file into an existing directory is picked
up automatically with no runner-file edit required. Adding a *new* directory
still needs a new runner.

## Stability policy — additive-only within v1

**Modifying or deleting ANY existing vector, in any file under this
directory, is a contract break.** This includes: changing a `token`,
`value`, `expected`, `canonical`, `hash`, schema, or description field on an
already-committed vector; renaming a vector file; changing the seeds in
`grants/test-keys.json`. A contract break requires:

1. An explicit **vector-version bump** (a new `v2` directory/field, per the
   affected artifact's own versioning note — e.g. `sarc-normal-form.v1.md`
   §6 for the SARC normal form, or a new `decision-request.v2.schema.json`
   for the contract shape).
2. An **ADR** recording why the break was necessary and what changed.

This is not a style preference — it is the pre-implementation handover's own
working agreement (`docs/04-roadmap/pre-implementation-handover.md` §6):
*"Golden vectors are append-only once frozen; changing one is an ADR-level
event."* **Adding new vectors to an existing directory is always fine** and
is how the corpus grows (e.g. a new precedence edge case, a new
adversarial-suite case that turns out to be contract-shaped) — only
touching a byte of something already committed is the break.

## Test-only keys — `grants/test-keys.json`

`grants/test-keys.json` commits two **obviously-synthetic, deterministic
Ed25519 seeds** in plaintext (`primary`: `"42"` repeated to 32 bytes;
`secondary`: `"1337"` repeated to 32 bytes) plus their derived
`publicKeyJwk`/`kid`. The file's own `warning` field states this
explicitly, and it bears repeating here:

> **TEST-ONLY KEYS — never use outside golden-vector suites.** These are not
> secrets in any meaningful sense (their whole purpose is to be public,
> reproducible, and committed); they must never back a real KnoTrust
> identity, and a real identity's seed must never be constructed this way
> (see `packages/grants/src/keys.ts` for the real key-generation path — real
> entropy, OS keychain or `0600` file, never a repeating hex pattern).

Every grant vector is minted with `primary`. The `wrong-key` vector's
`verifyContext.resolveKid` is `"secondary"` — its resolver deliberately
returns `secondary`'s public key for `primary`'s `kid`, modeling a
misresolved/hostile key mapping (see `grants/wrong-key.json` and
`packages/grants/src/golden-vectors.test.ts`'s `resolverFor` doc-comment).

`packages/grants/src/golden-vectors.test.ts` independently **re-derives**
each `kid`/`publicKeyJwk` from the raw `seed` bytes (via `@noble/curves` +
`node:crypto`'s SHA-256, mirroring `keys.ts`'s exact `deriveIdentity`/
`deriveKid`) and asserts it matches the committed value — this locks the
seed→JWK→kid derivation path cross-language, not just the seeds themselves.
A Python port's own key-loading code carries the identical obligation.

Tokens were minted once via `packages/grants/scripts/generate-golden-grant-vectors.mjs`
(a dev-only generation util — see its header). The runner asserts that the
**committed** token verifies; it never regenerates and diffs (see that
script's header for why).

## The cross-language contract (Phase-3 Python port)

A conforming implementation in any language — the Phase-3 Python port first
— **MUST**:

1. **Pass 100% of every vector in every directory above.** This is the
   Phase-3 exit criterion verbatim (`docs/04-roadmap/implementation-plan.md`:
   *"Python passes 100% of golden vectors v1"*).
2. **Assert `format: date-time`** on every JSON-Schema timestamp field, not
   just `type: "string"` (ADR-0017). `golden-vectors/schema-validation/
   adr-0017-negative-timestamp.json` is the permanent regression guard: a
   validator that skips format assertion wrongly accepts an offset-less
   ISO-8601 timestamp (`"2026-07-03T14:32:10"`, no `Z`/`±hh:mm`) as valid
   RFC 3339. `python-jsonschema` does **not** enable format checking by
   default — a `FormatChecker` must be constructed and passed explicitly.
3. **Reproduce the SARC normal-form canonicalization byte-identically**,
   including the two normative edge-case rules `golden-vectors/schemas/
   sarc-normal-form.v1.md` calls out explicitly:
   - **§3.2 — lone (unpaired) UTF-16 surrogates**: escaped as a lowercase
     `\uXXXX` sequence (ES2019 "well-formed `JSON.stringify`" behavior),
     never dropped, never raw-byte-emitted. A Python port using
     `json.dumps(..., ensure_ascii=False)` will **raise** on an unpaired
     surrogate rather than emit `\ud800` — it must detect and escape these
     itself.
   - **§3.3 — object keys sorted by UTF-16 code unit**, not Unicode code
     point. This is load-bearing for astral (supplementary-plane) keys,
     whose leading UTF-16 code unit is a high surrogate
     (`0xD800`–`0xDBFF`) — numerically *below* the BMP range
     (`0xE000`–`0xFFFF`), so a naive code-point sort orders astral keys
     wrong relative to BMP keys near the top of the range. A Python port
     must sort on each key's UTF-16BE encoding, not on `ord()`/code points.
4. **Never** import or structurally depend on an MCP SDK type to reproduce
   any vector — see the MCP-reference note at the top of this file.

## Freeze changelog

- **v1 frozen 2026-07-04 (P0-E3-T5).** This task materialized the grant
  vectors (`grants/*.json` + `test-keys.json`), the schema-validation
  vectors (`schema-validation/*.json`, including the ADR-0017 negative
  timestamp case), completed the decision-vector corpus (extended
  `expected` assertions, `cacheEligible` flags, machine-checked reason-code
  completeness, and the previously-missing `explicit_config_allow` positive
  — see `decisions/README.md`'s own changelog line for the exact diff),
  wrote this stability policy, and wired the MCP-reference guard. Everything
  listed in the corpus map above existed and was reviewed before this task
  (`schemas/`, `sarc-normal-form/`, and the original 12 `decisions/`
  fixtures landed across P0-E2-T1/T3 and P0-E3-T2/T3); this task's job was
  to complete the corpus and freeze it, not to originate it from scratch.
