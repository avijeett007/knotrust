/**
 * @knotrust/grants — offline grant verification (P0-E3-T2, ruling R26).
 *
 * ## Threat posture
 *
 * Every allow this product ever grants flows through `verifyGrant`, and the
 * token is ALWAYS hostile input — it arrives from the wire, from an agent,
 * from a URL. So this module is fail-closed and adversarial by construction:
 *
 * - **No check ever throws.** Every parse/decode/verify step is wrapped so
 *   that truncated tokens, non-JSON payloads, wrong segment counts, huge or
 *   Unicode-laden inputs, and garbage signatures all resolve to a typed
 *   `{ ok: false, reason }` — never an exception. (`@noble/curves` DOES throw
 *   `RangeError` on a wrong-length signature/pubkey; that throw is caught and
 *   mapped to `grant_invalid_signature`.)
 * - **Distinct, machine-stable reason codes**, checked in a FIXED order with
 *   first-failure-wins semantics (`GrantRejectionReason`). The order matters:
 *   structural/shape validity (`grant_malformed`) before key resolution
 *   (`grant_unknown_key`) before the cryptographic check
 *   (`grant_invalid_signature`) before any claim is acted upon. Shape-checking
 *   the payload before verifying the signature is NOT "trusting" it — the
 *   claims are only acted upon (temporal/pattern/conditions/call-hash/tier)
 *   AFTER the signature over those exact bytes has verified.
 *
 *   **R35 amendment (P0-E3-T3):** the call-hash gate (`grant_call_mismatch`,
 *   including the ch-present-but-`opts.callHash`-absent case) now runs BEFORE
 *   the tier-cap gate (`tier_cap_violation`), not after. This makes a
 *   `tier_cap_violation` rejection GUARANTEE the grant already passed
 *   signature/temporal/pattern/conditions AND the call-hash — i.e. it is a
 *   fully-valid grant for THIS exact call that merely claims too little tier.
 *   That guarantee is what makes the precedence pass-through (below) safe: a
 *   grant is only escalated to precedence as a live self-escalation attempt
 *   once it is known to bind to the exact call being authorized.
 *
 * ## What a rejection MEANS to callers (architecture §5.4)
 *
 * A rejected grant is "treated as ABSENT, not a deny reason the model sees."
 * The precedence wiring (E3-T3, `lifecycle.ts` `collectCoveringGrants`) maps
 * every reason here to grant-absence, EXCEPT `tier_cap_violation`: that one
 * rejection is passed THROUGH to precedence as a `CoveringGrant` (rebuilt from
 * the decoded claims) so precedence fires its ratified loud self-escalation
 * deny (R15) — the loud-deny decision is precedence's call (it re-derives it
 * from the covering-grant set), never `verifyGrant`'s. Precedence is thus the
 * single tier-cap authority in composition; this module only reports why THIS
 * token did not satisfy THIS request, and (per the R35 amendment above)
 * guarantees a `tier_cap_violation` grant is call-hash-bound before it is
 * handed on.
 *
 * ## Call-hash (`ch`) binding — fail closed (brief §I2.3)
 *
 * `parseWireClaims` already guarantees `ch` is present iff the grant is
 * ephemeral. When `ch` is present, the executing call's SARC hash
 * (`opts.callHash`) MUST be provided and equal it; an absent `opts.callHash`
 * is `grant_call_mismatch`, never a pass. E3-T3 wires the real SARC
 * canonicalizer — callers compute the hash and pass it here.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import type {
  CoveringGrant,
  DecisionRequest,
  Subject,
  Tier,
} from "@knotrust/core";
import { TIER_RANK } from "@knotrust/core";
import { ed25519 } from "@noble/curves/ed25519.js";
import type { GrantClaims } from "./claims.js";
import { parseJwsHeader, parseWireClaims } from "./claims.js";
import type { Ed25519PublicJwk } from "./keys.js";
import { resolveKnotrustHome } from "./keys.js";

// ---------------------------------------------------------------------------
// Reason codes — machine-stable const-object union (mirrors core's pattern).
// ---------------------------------------------------------------------------

export const GrantRejectionReason = {
  /** parse failure / bad shape / unknown alg or typ / v ≠ 1 / ch-kind invariant. */
  Malformed: "grant_malformed",
  /** header `kid` resolves to no local trusted key. */
  UnknownKey: "grant_unknown_key",
  /** Ed25519 signature does not verify (incl. wrong key resolved for the kid). */
  InvalidSignature: "grant_invalid_signature",
  /** now >= exp (exp exclusive). */
  Expired: "grant_expired",
  /** now < nbf (nbf inclusive). */
  NotYetValid: "grant_not_yet_valid",
  /** principal type/id does not equal request.subject. */
  PrincipalMismatch: "grant_principal_mismatch",
  /** agent pattern does not match request.context.agent. */
  AgentMismatch: "grant_agent_mismatch",
  /** tool pattern does not match request.action.name. */
  ToolMismatch: "grant_tool_mismatch",
  /** scope resourceType/idPattern does not match request.resource. */
  ScopeMismatch: "grant_scope_mismatch",
  /** grant carries a non-empty conditions object — not evaluated in P0, fail closed. */
  ConditionsUnsupported: "conditions_unsupported",
  /** ch present but opts.callHash absent or unequal (TOCTOU binding). Checked
   *  BEFORE the tier cap (R35), so a tier-cap violation is always call-bound. */
  CallMismatch: "grant_call_mismatch",
  /** claims.tier < resolvedTier (self-escalation, via core's TIER_RANK). Passed
   *  THROUGH to precedence by `collectCoveringGrants` (R35), not treated absent. */
  TierCapViolation: "tier_cap_violation",
} as const;

export type GrantRejectionReason =
  (typeof GrantRejectionReason)[keyof typeof GrantRejectionReason];

export interface VerifyGrantOptions {
  /** The call being authorized — the grant is matched against this. */
  request: DecisionRequest;
  /** The tier the tool resolved to (from core's tier resolution). `claims.tier` must cover it. */
  resolvedTier: Tier;
  /** Injected clock (epoch seconds) — never `Date.now()`. */
  nowEpochSeconds: number;
  /** The executing call's SARC-normal-form hash. REQUIRED to satisfy an ephemeral grant's `ch`. */
  callHash?: string;
  /** Resolves a trusted local public key by the header `kid`. Injectable (tests, alt stores). */
  resolvePublicKey(kid: string): Ed25519PublicJwk | null;
}

export type VerifyGrantResult =
  | { ok: true; claims: GrantClaims; coveringGrant: CoveringGrant }
  | { ok: false; reason: GrantRejectionReason };

function reject(reason: GrantRejectionReason): VerifyGrantResult {
  return { ok: false, reason };
}

// ---------------------------------------------------------------------------
// Never-throwing decode helpers
// ---------------------------------------------------------------------------

/**
 * Decodes a base64url segment and JSON-parses it. Returns `undefined` on ANY
 * failure — `undefined` is never a valid JSON parse result, so it is a safe
 * failure sentinel (a payload of literal `null` still parses to `null`, which
 * the shape validators then reject).
 */
function decodeJsonSegment(segment: string): unknown {
  try {
    const json = Buffer.from(segment, "base64url").toString("utf8");
    return JSON.parse(json) as unknown;
  } catch {
    return undefined;
  }
}

/** Ed25519 verify that never throws — noble's `RangeError` on bad lengths → false. */
function verifyEd25519(
  signingInput: string,
  signature: Uint8Array,
  jwk: Ed25519PublicJwk,
): boolean {
  try {
    const publicKey = new Uint8Array(Buffer.from(jwk.x, "base64url"));
    const message = new Uint8Array(Buffer.from(signingInput, "utf8"));
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Matching semantics (R25 — conservative P0 set)
// ---------------------------------------------------------------------------

function principalMatches(
  principal: GrantClaims["principal"],
  subject: Subject,
): boolean {
  return principal.type === subject.type && principal.id === subject.id;
}

function agentMatches(
  agent: GrantClaims["agent"],
  requestAgent: DecisionRequest["context"]["agent"],
): boolean {
  if (agent === "*") return true;
  return agent.id === requestAgent.id && agent.type === requestAgent.type;
}

/**
 * `tool` matching (R25): exact string equality; OR a trailing-glob `"ns.*"`
 * (prefix match on `"ns."`, the dot included); OR the lone `"*"` (matches
 * all). Nothing richer — a bare `"foo*"` (no dot) is treated as an exact
 * literal, never a glob.
 */
function toolMatches(pattern: string, actionName: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) {
    return actionName.startsWith(pattern.slice(0, -1));
  }
  return pattern === actionName;
}

/**
 * `scope` matching (R25): `resourceType` is exact equality when present;
 * `idPattern` is exact OR a trailing-`"*"` prefix match (`"ch_*"`,
 * `"kno2gether/*"`). An absent scope field imposes no constraint.
 */
function scopeMatches(
  scope: GrantClaims["scope"],
  resource: DecisionRequest["resource"],
): boolean {
  if (
    scope.resourceType !== undefined &&
    scope.resourceType !== resource.type
  ) {
    return false;
  }
  if (scope.idPattern !== undefined) {
    if (scope.idPattern.endsWith("*")) {
      if (!resource.id.startsWith(scope.idPattern.slice(0, -1))) return false;
    } else if (scope.idPattern !== resource.id) {
      return false;
    }
  }
  return true;
}

/**
 * Projects verified grant claims onto the core `CoveringGrant` shape precedence
 * consumes. Exported (P0-E5-T3, folded review item M2) so `lifecycle.ts`'s R35
 * `tier_cap_violation` pass-through rebuilds a covering grant through THIS one
 * projection rather than an inline duplicate that could silently drift from it.
 */
export function toCoveringGrant(claims: GrantClaims): CoveringGrant {
  return {
    kind: claims.kind,
    tierCap: claims.tier,
    exp: claims.exp,
    ...(claims.nbf !== undefined ? { nbf: claims.nbf } : {}),
    jti: claims.jti,
  };
}

/**
 * Defense-in-depth cap on incoming token length (UTF-16 code units, i.e.
 * `token.length` — checked BEFORE any base64/JSON decode). The largest
 * legitimate grant measured in `mint.test.ts`'s size ledger is ~700 bytes;
 * 8 KiB leaves ~10x headroom for future claim growth while ensuring
 * `verifyGrant` never spends base64-decode + `JSON.parse` cycles on an
 * attacker-supplied multi-MB blob — an unauthenticated caller can otherwise
 * force that decode work on every request, since this check runs before key
 * resolution or signature verification. Exported for visibility (tests,
 * callers sizing their own request-body limits upstream of this call).
 */
export const MAX_GRANT_TOKEN_LENGTH = 8192;

// ---------------------------------------------------------------------------
// verifyGrant — the offline verifier. Checks run in the FIXED order below;
// first failure wins.
// ---------------------------------------------------------------------------

export function verifyGrant(
  token: string,
  opts: VerifyGrantOptions,
): VerifyGrantResult {
  // --- 0. DoS defense-in-depth: reject oversized tokens before any decode ---
  if (typeof token !== "string") return reject(GrantRejectionReason.Malformed);
  if (token.length > MAX_GRANT_TOKEN_LENGTH) {
    return reject(GrantRejectionReason.Malformed);
  }

  // --- 1. structural + shape validity (grant_malformed) ---
  const segments = token.split(".");
  if (segments.length !== 3) return reject(GrantRejectionReason.Malformed);
  const [headerSeg, payloadSeg, signatureSeg] = segments;
  if (!headerSeg || !payloadSeg || !signatureSeg) {
    return reject(GrantRejectionReason.Malformed);
  }

  const header = parseJwsHeader(decodeJsonSegment(headerSeg));
  if (header === null) return reject(GrantRejectionReason.Malformed);

  const claims = parseWireClaims(decodeJsonSegment(payloadSeg));
  if (claims === null) return reject(GrantRejectionReason.Malformed);

  // --- 2. key resolution (grant_unknown_key) ---
  const jwk = opts.resolvePublicKey(header.kid);
  if (!jwk) return reject(GrantRejectionReason.UnknownKey);

  // --- 3. signature over the EXACT signed bytes (grant_invalid_signature) ---
  // Reconstructed from the RAW segments, not a re-serialization — the
  // signature covers exactly what was transmitted (the point of JWS Compact).
  const signature = new Uint8Array(Buffer.from(signatureSeg, "base64url"));
  const signingInput = `${headerSeg}.${payloadSeg}`;
  if (!verifyEd25519(signingInput, signature, jwk)) {
    return reject(GrantRejectionReason.InvalidSignature);
  }

  // --- 4. temporal window ---
  if (opts.nowEpochSeconds >= claims.exp) {
    return reject(GrantRejectionReason.Expired);
  }
  if (claims.nbf !== undefined && opts.nowEpochSeconds < claims.nbf) {
    return reject(GrantRejectionReason.NotYetValid);
  }

  // --- 5. pattern matching against the DecisionRequest ---
  if (!principalMatches(claims.principal, opts.request.subject)) {
    return reject(GrantRejectionReason.PrincipalMismatch);
  }
  if (!agentMatches(claims.agent, opts.request.context.agent)) {
    return reject(GrantRejectionReason.AgentMismatch);
  }
  if (!toolMatches(claims.tool, opts.request.action.name)) {
    return reject(GrantRejectionReason.ToolMismatch);
  }
  if (!scopeMatches(claims.scope, opts.request.resource)) {
    return reject(GrantRejectionReason.ScopeMismatch);
  }

  // --- 6. conditions — fail closed in P0 (R25) ---
  if (
    claims.conditions !== undefined &&
    Object.keys(claims.conditions).length > 0
  ) {
    return reject(GrantRejectionReason.ConditionsUnsupported);
  }

  // --- 7. call-hash binding (ephemeral; fail closed) — R35: checked BEFORE
  //        the tier-cap gate below. A `ch` present with `opts.callHash` absent
  //        or unequal is `grant_call_mismatch`, never a pass. Ordering it here
  //        means a `tier_cap_violation` (step 8) can only be reached by a grant
  //        that already binds to THIS exact call, which is what lets
  //        `collectCoveringGrants` safely pass such a grant through to
  //        precedence (see the header's R35 note). ---
  if (claims.callHash !== undefined) {
    if (opts.callHash === undefined || opts.callHash !== claims.callHash) {
      return reject(GrantRejectionReason.CallMismatch);
    }
  }

  // --- 8. tier cap (self-escalation; feeds precedence T3) ---
  if (TIER_RANK[claims.tier] < TIER_RANK[opts.resolvedTier]) {
    return reject(GrantRejectionReason.TierCapViolation);
  }

  return { ok: true, claims, coveringGrant: toCoveringGrant(claims) };
}

// ---------------------------------------------------------------------------
// Default resolvePublicKey seam — reads $KNOTRUST_HOME/keys/<kid>.jwk.json
// ---------------------------------------------------------------------------

/**
 * `kid` is base64url derived from a SHA-256 (keys.ts) — 16 chars in practice,
 * always within this charset. Because `kid` arrives from an UNTRUSTED token
 * header and is interpolated into a filesystem path, it is validated against
 * this allowlist BEFORE any `path.join`, so a hostile `"../.."` or `"a/b"`
 * kid can never traverse out of the keys directory (it simply resolves to
 * `null` → `grant_unknown_key`). The upper bound is generous but finite.
 */
const KID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

function isEd25519PublicJwk(v: unknown): v is Ed25519PublicJwk {
  return (
    typeof v === "object" &&
    v !== null &&
    (v as { kty?: unknown }).kty === "OKP" &&
    (v as { crv?: unknown }).crv === "Ed25519" &&
    typeof (v as { x?: unknown }).x === "string" &&
    (v as { x: string }).x.length > 0
  );
}

/**
 * Builds the production `resolvePublicKey` seam. `home` defaults to
 * `resolveKnotrustHome()` read FRESH on every call (so a test that repoints
 * `KNOTRUST_HOME` per case needs no resolver rebuild). Any failure — an
 * invalid kid, a missing file, unreadable bytes, non-JSON, or a JWK of the
 * wrong shape — resolves to `null` (fail closed); it never throws.
 */
export function createDiskPublicKeyResolver(
  home?: string,
): (kid: string) => Ed25519PublicJwk | null {
  return (kid: string): Ed25519PublicJwk | null => {
    if (!KID_PATTERN.test(kid)) return null;
    const base = home ?? resolveKnotrustHome();
    const file = path.join(base, "keys", `${kid}.jwk.json`);
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown;
      return isEd25519PublicJwk(parsed) ? parsed : null;
    } catch {
      return null;
    }
  };
}
