/**
 * @knotrust/grants — canonical grant claim schema + bijective wire codec
 * (P0-E3-T2; architecture §5.1/§5.2; rulings R24–R27).
 *
 * Two shapes for one concept:
 *
 * - `GrantClaims` — the in-memory, human-readable form (copied VERBATIM from
 *   architecture §5.2). This is what `mintGrant` builds and `verifyGrant`
 *   returns; the rest of the codebase never touches the wire form.
 * - `GrantClaimsWire` — the on-the-wire JWS payload. Uses ONLY the short
 *   claim names (§5.2 mapping table) because grant size drives the URL-mode
 *   elicitation / QR-transfer budget (research crypto §7.2). Absent optionals
 *   stay ABSENT on the wire — every dropped key is bytes saved.
 *
 * The two are connected by a bijective codec: `claimsToWire` (mint side) and
 * `parseWireClaims` (verify side). `parseWireClaims` is the ONLY place an
 * untrusted, already-JSON-parsed payload becomes a typed `GrantClaims`, so it
 * is exhaustively fail-closed: every field is type-checked, unknown keys are
 * dropped (v pins the schema, the signature pins the bytes), and any
 * violation returns `null` — it NEVER throws. `parseJwsHeader` applies the
 * same discipline to the JWS header (the alg-confusion defense lives here:
 * only the literal `"EdDSA"` is accepted).
 *
 * There is deliberately NO JSON canonicalization anywhere (R24): mint
 * serializes each object exactly once with `JSON.stringify` and signs those
 * bytes; verify parses whatever bytes were signed. That is the whole point of
 * JWS Compact — the signature covers the exact base64url payload, so no
 * canonical form is needed on either side.
 */

// ---------------------------------------------------------------------------
// JWS header (architecture §5.1)
// ---------------------------------------------------------------------------

export const GRANT_JWS_ALG = "EdDSA" as const;
export const GRANT_JWS_TYP = "knotrust-grant+jws" as const;

export interface GrantJwsHeader {
  alg: typeof GRANT_JWS_ALG;
  typ: typeof GRANT_JWS_TYP;
  kid: string;
}

// ---------------------------------------------------------------------------
// GrantClaims — VERBATIM architecture §5.2 (in-memory, human-readable form)
// ---------------------------------------------------------------------------

export interface GrantClaims {
  v: 1; // grant schema version
  jti: string; // ULID grant id (revocation + single-use ledger key)
  iat: number;
  exp: number;
  nbf?: number;
  iss: string; // granted_by: the minting authority identity
  kind: "durable" | "ephemeral"; // ephemeral = single-use, minted on approval
  singleUse: boolean; // true ⇒ consumed atomically on first match

  principal: { type: "user" | "service"; id: string }; // the HUMAN
  agent: { id: string; type: "ai_agent" | "workload" | "user" } | "*"; // "*" = any agent
  tool: string; // pattern: exact "stripe.create_refund" or glob "github.*"
  scope: {
    resourceType?: string; // e.g. "stripe_charge"
    idPattern?: string; // e.g. "ch_*" or "kno2gether/*"
  };
  conditions?: Record<string, unknown>; // e.g. { maxAmount: 5000, currency: "usd" }
  tier: "routine" | "sensitive" | "critical"; // the tier this grant satisfies (cannot exceed minter's)
  envelopeScope: "personal" | "org"; // which policy scope minted it (schema-forward, brief §E7)
  admin?: boolean; // minted under an admin/org envelope
  /** REQUIRED iff kind === "ephemeral" (brief §I2.3): sha256 of the SARC normal form of the EXACT
   *  call the human approved. Closes approve-X-execute-Y (TOCTOU). */
  callHash?: string;
}

// ---------------------------------------------------------------------------
// GrantClaimsWire — the short-name payload (§5.2 mapping table). ONLY these
// keys ever appear on the wire.
// ---------------------------------------------------------------------------

export interface GrantClaimsWire {
  v: 1;
  jti: string;
  iat: number;
  exp: number;
  nbf?: number;
  iss: string;
  k: GrantClaims["kind"]; // kind
  su: boolean; // singleUse
  p: GrantClaims["principal"]; // principal
  ag: GrantClaims["agent"]; // agent
  t: string; // tool
  s: GrantClaims["scope"]; // scope
  c?: Record<string, unknown>; // conditions
  r: GrantClaims["tier"]; // tier (r = risk-tier cap)
  es: GrantClaims["envelopeScope"]; // envelopeScope
  ad?: boolean; // admin
  ch?: string; // callHash
}

// ---------------------------------------------------------------------------
// mint side: claims → wire (drop absent optionals; size matters)
// ---------------------------------------------------------------------------

/**
 * Maps the in-memory `GrantClaims` to its short-name wire form. Absent
 * optionals are omitted entirely (not set to `undefined`) so they never
 * consume wire bytes. Scope is copied field-by-field so an absent
 * `resourceType`/`idPattern` also stays off the wire.
 *
 * An explicitly-EMPTY `conditions: {}` is dropped from the wire exactly like
 * an absent `conditions` — `verifyGrant`'s conditions check already treats
 * `{}` as "no conditions" (only a non-empty object trips
 * `conditions_unsupported`), so encoding `{}` as `c:{}` would be a codec
 * asymmetry: two distinct in-memory inputs (`conditions` absent vs.
 * `conditions: {}`) that mean the same thing would serialize to two distinct
 * wire forms. Dropping it restores bijectivity between the wire and the
 * meaning verify actually assigns it.
 */
export function claimsToWire(claims: GrantClaims): GrantClaimsWire {
  const scope: GrantClaims["scope"] = {
    ...(claims.scope.resourceType !== undefined
      ? { resourceType: claims.scope.resourceType }
      : {}),
    ...(claims.scope.idPattern !== undefined
      ? { idPattern: claims.scope.idPattern }
      : {}),
  };

  return {
    v: claims.v,
    jti: claims.jti,
    iat: claims.iat,
    exp: claims.exp,
    ...(claims.nbf !== undefined ? { nbf: claims.nbf } : {}),
    iss: claims.iss,
    k: claims.kind,
    su: claims.singleUse,
    p: { type: claims.principal.type, id: claims.principal.id },
    ag:
      claims.agent === "*"
        ? "*"
        : { id: claims.agent.id, type: claims.agent.type },
    t: claims.tool,
    s: scope,
    ...(claims.conditions !== undefined &&
    Object.keys(claims.conditions).length > 0
      ? { c: claims.conditions }
      : {}),
    r: claims.tier,
    es: claims.envelopeScope,
    ...(claims.admin !== undefined ? { ad: claims.admin } : {}),
    ...(claims.callHash !== undefined ? { ch: claims.callHash } : {}),
  };
}

// ---------------------------------------------------------------------------
// verify side: strict, fail-closed decoders. NEVER throw; return null on any
// shape violation.
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

/** Epoch-seconds fields: a non-negative safe integer (mint only ever emits these). */
function isEpochSeconds(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

const KINDS = new Set(["durable", "ephemeral"]);
const AGENT_TYPES = new Set(["ai_agent", "workload", "user"]);
const PRINCIPAL_TYPES = new Set(["user", "service"]);
const TIERS = new Set(["routine", "sensitive", "critical"]);
const ENVELOPE_SCOPES = new Set(["personal", "org"]);

function parsePrincipal(v: unknown): GrantClaims["principal"] | null {
  if (!isObject(v)) return null;
  if (typeof v.type !== "string" || !PRINCIPAL_TYPES.has(v.type)) return null;
  if (!isNonEmptyString(v.id)) return null;
  return { type: v.type as GrantClaims["principal"]["type"], id: v.id };
}

function parseAgent(v: unknown): GrantClaims["agent"] | null {
  if (v === "*") return "*";
  if (!isObject(v)) return null;
  if (!isNonEmptyString(v.id)) return null;
  if (typeof v.type !== "string" || !AGENT_TYPES.has(v.type)) return null;
  return {
    id: v.id,
    type: v.type as Exclude<GrantClaims["agent"], string>["type"],
  };
}

function parseScope(v: unknown): GrantClaims["scope"] | null {
  if (!isObject(v)) return null;
  const scope: GrantClaims["scope"] = {};
  if (v.resourceType !== undefined) {
    if (!isNonEmptyString(v.resourceType)) return null;
    scope.resourceType = v.resourceType;
  }
  if (v.idPattern !== undefined) {
    if (!isNonEmptyString(v.idPattern)) return null;
    scope.idPattern = v.idPattern;
  }
  return scope;
}

/**
 * The load-bearing decoder: an already-JSON-parsed, untrusted payload → a
 * typed `GrantClaims`, or `null` on ANY shape violation. Every field is
 * validated; unknown keys are dropped (only known fields are copied out).
 * The ephemeral/durable `callHash` invariant (§5.2) is enforced HERE as part
 * of schema validity, so a mismatched grant fails as `grant_malformed`, not
 * as a silent success.
 */
export function parseWireClaims(raw: unknown): GrantClaims | null {
  if (!isObject(raw)) return null;

  if (raw.v !== 1) return null;
  if (!isNonEmptyString(raw.jti)) return null;
  if (!isEpochSeconds(raw.iat)) return null;
  if (!isEpochSeconds(raw.exp)) return null;
  if (raw.nbf !== undefined && !isEpochSeconds(raw.nbf)) return null;
  if (!isNonEmptyString(raw.iss)) return null;

  if (typeof raw.k !== "string" || !KINDS.has(raw.k)) return null;
  const kind = raw.k as GrantClaims["kind"];

  if (typeof raw.su !== "boolean") return null;

  const principal = parsePrincipal(raw.p);
  if (principal === null) return null;

  const agent = parseAgent(raw.ag);
  if (agent === null) return null;

  if (!isNonEmptyString(raw.t)) return null;

  const scope = parseScope(raw.s);
  if (scope === null) return null;

  if (raw.c !== undefined && !isObject(raw.c)) return null;

  if (typeof raw.r !== "string" || !TIERS.has(raw.r)) return null;
  const tier = raw.r as GrantClaims["tier"];

  if (typeof raw.es !== "string" || !ENVELOPE_SCOPES.has(raw.es)) return null;
  const envelopeScope = raw.es as GrantClaims["envelopeScope"];

  if (raw.ad !== undefined && typeof raw.ad !== "boolean") return null;

  if (raw.ch !== undefined && !isNonEmptyString(raw.ch)) return null;

  // §5.2 invariant: callHash is REQUIRED on ephemeral, ABSENT on durable.
  if (kind === "ephemeral" && raw.ch === undefined) return null;
  if (kind === "durable" && raw.ch !== undefined) return null;

  return {
    v: 1,
    jti: raw.jti,
    iat: raw.iat,
    exp: raw.exp,
    ...(raw.nbf !== undefined ? { nbf: raw.nbf } : {}),
    iss: raw.iss,
    kind,
    singleUse: raw.su,
    principal,
    agent,
    tool: raw.t,
    scope,
    ...(raw.c !== undefined ? { conditions: raw.c } : {}),
    tier,
    envelopeScope,
    ...(raw.ad !== undefined ? { admin: raw.ad } : {}),
    ...(raw.ch !== undefined ? { callHash: raw.ch } : {}),
  };
}

/**
 * Validates the JWS header. Only the literal `"EdDSA"` alg is accepted — the
 * alg-confusion defense (a token presenting `"none"`, `"HS256"`, etc. is
 * `grant_malformed`, never verified). Extra header params are permitted (they
 * are covered by the signature); the three required fields must match exactly.
 *
 * A header carrying `crit` (RFC 7515 §4.1.11) is rejected outright,
 * REGARDLESS of its value. Per the RFC, any extension named in `crit` MUST be
 * understood and processed by the verifier, or the JWS MUST be rejected; our
 * minter never emits `crit`, so a token that carries it is either forged or
 * from a producer this verifier does not understand — silently ignoring it
 * would defeat the whole point of a "critical" extension marker.
 */
export function parseJwsHeader(raw: unknown): GrantJwsHeader | null {
  if (!isObject(raw)) return null;
  if (raw.alg !== GRANT_JWS_ALG) return null;
  if (raw.typ !== GRANT_JWS_TYP) return null;
  if (!isNonEmptyString(raw.kid)) return null;
  if (raw.crit !== undefined) return null;
  return { alg: GRANT_JWS_ALG, typ: GRANT_JWS_TYP, kid: raw.kid };
}
