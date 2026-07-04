/**
 * @knotrust/core — canonical leak-pattern source (P0-E5-T4 fix round 2;
 * ruling R80; continuity with R75/R76/R77).
 *
 * ONE shared source for every pattern/identifier that makes model-visible
 * content count as a "leak." Two consumers, by design, both REQUIRED to stay
 * on this module (never a local copy):
 *
 *   - `@knotrust/test-harness`'s `leak-scan.ts` (`findLeaks`/
 *     `assertNoLeakedSecrets`) — the scanner every model-visible-content-
 *     emitting suite in this repo calls.
 *   - `@knotrust/proxy-stdio`'s `denial-envelope.ts` `buildSafeRequestableHow`
 *     redactor — which must redact from a hostile tool/server NAME exactly
 *     what the scanner would flag.
 *
 * ## Why this lives in `@knotrust/core`, not `@knotrust/test-harness` (R80)
 *
 * Fix round 1 hosted this module in `@knotrust/test-harness` and, to let
 * the production redactor consume it, made `@knotrust/proxy-stdio` — a
 * PRODUCTION package the published `knotrust` CLI bundles wholesale via
 * tsup's `noExternal: [/^@knotrust\//]` (see `packages/cli/tsup.config.ts`)
 * — take a real runtime `dependencies` entry on `@knotrust/test-harness`, a
 * TEST package. That is the wrong direction: production must never
 * runtime-depend on test code, and for a product whose entire pitch is
 * supply-chain trust, shipping test-harness code inside the CLI tarball
 * (however indirectly) is exactly the class of smell this product exists to
 * catch in OTHER people's dependency trees.
 *
 * `@knotrust/core` is the neutral home instead: `proxy-stdio` already
 * depends on it (for `DecisionResponse` and the `L0ReasonCode`/
 * `PrecedenceReasonCode` unions this very redaction logic is built around),
 * `core` already owns the reason-code identifiers being redacted, and
 * `test-harness` can cleanly add `core` as a dependency without creating a
 * cycle — `core` depends on neither `proxy-stdio` nor `test-harness` (see
 * `packages/core/scripts/check-boundaries.mjs`, which fails the build if
 * that ever stops being true for `@modelcontextprotocol/*`/`proxy-*`
 * imports).
 *
 * This module is pure string/RegExp literals — zero MCP types, zero
 * proxy-specific or test-harness-specific imports — so it sits comfortably
 * inside core's zero-MCP-types boundary (invariant §4.1; brief §E1).
 * Consumers import it from `@knotrust/core`'s public entry (`index.ts`);
 * there is no narrow subpath here the way `@knotrust/test-harness` needed
 * one (that package's barrel also re-exports fake-client/fake-server test
 * doubles a production import graph must avoid — core's barrel carries no
 * such doubles, so it is already the narrow surface).
 *
 * ---------------------------------------------------------------------
 * BINDING TOKEN-FORMAT CONTRACT for E6-T3 (approval-token minting — not yet
 * implemented as of this fix):
 *
 *   Approval tokens issued by this system MUST carry the literal `tok_`
 *   prefix followed by AT LEAST 22 base64url characters (`[A-Za-z0-9_-]`),
 *   matched case-insensitively (>=128 bits of entropy). This is the scan's
 *   PRIMARY detector (`APPROVAL_TOKEN_PREFIXED_PATTERN` below) and the shape
 *   E6-T3 is contractually required to mint against.
 *
 *   `APPROVAL_TOKEN_HEX_PATTERN` (a bare 32+ hex-char run, no prefix) is a
 *   defense-in-depth FALLBACK only — it catches a token that HAPPENS to be
 *   pure hex, but cannot reliably catch every possible bare token shape. In
 *   particular, a bare (non-`tok_`-prefixed) base64url token that mixes case
 *   and uses non-hex letters/`-`/`_` falls OUTSIDE both patterns and is a
 *   KNOWN, ACCEPTED blind spot (`leak-scan.test.ts`'s "bare base64url token"
 *   case documents this directly rather than silently passing).
 *
 *   >>> E6-T3 minting a token WITHOUT the `tok_` prefix is a CONTRACT
 *   >>> VIOLATION this scanner is NOT guaranteed to catch. E6-T3 MUST mint
 *   >>> tokens with the `tok_` prefix. <<<
 * ---------------------------------------------------------------------
 */

// ---------------------------------------------------------------------------
// Token shapes.
// ---------------------------------------------------------------------------

/**
 * Shape 1 (PRIMARY — the binding contract above): an opaque `tok_`-prefixed
 * id, >=22 base64url chars (>=128 bits).
 *
 * Fix round 1 (finding 3): added the `i` flag so `TOK_...`/`Tok_...` (any
 * casing of the literal prefix) are caught too, not only an exact-lowercase
 * `tok_`.
 */
export const APPROVAL_TOKEN_PREFIXED_PATTERN = /\btok_[A-Za-z0-9_-]{22,}\b/gi;

/**
 * Shape 2 (defense-in-depth FALLBACK — see header): a bare run of 32+ hex
 * chars (128+ bits, no prefix).
 *
 * Fix round 1 (finding 3) hardening, over the original pattern:
 *
 *   - Added the `i` flag: the original character class was lowercase-only
 *     (`[0-9a-f]`), so an uppercase or mixed-case hex run (e.g.
 *     `DEADBEEF...`) sailed through uncaught. `i` extends the class to
 *     `[0-9a-fA-F]` without widening it to any other letters.
 *   - Dropped the `\b` word-boundary anchors: `\b` only fires at a
 *     transition between a word char (`\w` = `[A-Za-z0-9_]`) and a
 *     non-word char. Hex digits AND ordinary letters (e.g. the `z` in
 *     `zzz<hex>zzz`) are BOTH word chars, so a hex run immediately flanked
 *     by letters has NO `\b` at either edge — the old pattern silently
 *     missed exactly this shape. The character class itself already
 *     defines each match's boundaries (only `[0-9a-fA-F]` chars extend a
 *     run), so no boundary assertion is needed for correctness; dropping
 *     `\b` closes the blind spot without introducing a new one.
 */
export const APPROVAL_TOKEN_HEX_PATTERN = /[0-9a-f]{32,}/gi;

// ---------------------------------------------------------------------------
// Policy-internal identifiers + generic admin/rule-id-shaped patterns.
// ---------------------------------------------------------------------------

/**
 * The internal reason codes P0-E5-T4's `toSafeReasonCode` (R75) maps away —
 * these must NEVER appear verbatim in model-visible content, because each
 * one reveals policy shape (which layer, which rule, self-escalation
 * detection, replay detection, ...).
 */
export const POLICY_INTERNAL_IDENTIFIERS: readonly string[] = [
  "no_grant_sensitive",
  "no_grant_critical",
  "tier_cap_violation",
  "envelope_deny",
  "envelope_force_approval",
  "explicit_config_deny",
  "grant_exceeds_envelope",
  "grant_replayed",
  "audit_unavailable",
  "internal_error",
  "enforcement_error",
];

/**
 * Generic shapes: an audit-only rationale key, or a rule/policy/pack-id-
 * looking key name.
 *
 * Fix round 1 (finding 2): exported (not module-private) precisely so
 * `denial-envelope.ts`'s redactor can consume the SAME patterns the scanner
 * flags on — a tool NAMED "rule-id", "policy-id", "pack_id", or "ruleid"
 * gets redacted before it ever reaches `requestable.how`, instead of
 * surviving redaction and then tripping `assertNoLeakedSecrets` downstream.
 */
export const POLICY_INTERNAL_PATTERNS: readonly RegExp[] = [
  /"reasonAdmin"/g,
  /\brule[-_]?id\b/gi,
  /\bpolicy[-_]?id\b/gi,
  /\bpack[-_]?id\b/gi,
];
