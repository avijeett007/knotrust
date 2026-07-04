/**
 * @knotrust/grants — grant minting (JWS Compact, `alg: EdDSA`; P0-E3-T2,
 * ruling R27).
 *
 * Hand-assembles a JWS Compact token (R24 — NO `jose`/JWT dependency):
 *
 *   token = base64url(utf8(headerJSON))
 *         + "." + base64url(utf8(payloadJSON))
 *         + "." + base64url(Ed25519-sig)
 *
 * where the signature is Ed25519 over the ASCII bytes of `header.payload`
 * (RFC 7515 §5.1), produced by `keys.ts`'s `KeyStore.sign()` — the private
 * key never leaves that module. The payload is the short-name wire form
 * (`claims.ts`), serialized ONCE with `JSON.stringify`; those exact bytes are
 * what the signature covers, so there is no canonicalization step.
 *
 * Mint is NOT an adversarial surface — the caller already holds the signing
 * key. So the input validations below are PROGRAMMER-error guards that THROW
 * (contrast `verifyGrant`, which fails closed and never throws): a caller who
 * asks for an ephemeral grant with no `callHash`, or a durable grant that
 * carries one, has a bug, and a loud throw at mint time is the right failure.
 *
 * Out of scope here (E3-T3 / E4-T1): the single-use / `jti` consumed-ledger
 * and any persistence. Mint only produces the token + claims.
 */

import type { Tier } from "@knotrust/core";
import {
  claimsToWire,
  GRANT_JWS_ALG,
  GRANT_JWS_TYP,
  type GrantClaims,
  type GrantJwsHeader,
} from "./claims.js";
import type { KeyStore } from "./keys.js";

/**
 * The grant-relevant fields a caller supplies. `jti`/`iat`/`exp`/`iss`/`v`
 * are DERIVED (see `mintGrant`), never passed in. `singleUse` defaults to
 * `kind === "ephemeral"` unless explicitly overridden.
 */
export interface MintGrantInput {
  kind: "durable" | "ephemeral";
  principal: { type: "user" | "service"; id: string };
  agent: { id: string; type: "ai_agent" | "workload" | "user" } | "*";
  tool: string;
  scope: { resourceType?: string; idPattern?: string };
  conditions?: Record<string, unknown>;
  tier: Tier;
  envelopeScope: "personal" | "org";
  admin?: boolean;
  /** Grant lifetime in seconds; `exp = now + ttlSeconds`. Must be a positive integer. */
  ttlSeconds: number;
  /** Optional "not before" epoch seconds. */
  nbf?: number;
  /** REQUIRED for `kind: "ephemeral"` (TOCTOU binding); MUST be absent for durable. */
  callHash?: string;
  /** Override the `singleUse` default. Ephemeral grants must stay single-use. */
  singleUse?: boolean;
}

export interface MintGrantDeps {
  keyStore: KeyStore;
  /** Injected clock (epoch seconds) — never `Date.now()`. */
  nowEpochSeconds: number;
  /** Injected id source — core's ULID generator in production. */
  generateId(): string;
}

export interface MintGrantResult {
  token: string;
  claims: GrantClaims;
}

function base64urlUtf8(s: string): string {
  return Buffer.from(s, "utf8").toString("base64url");
}

function base64urlBytes(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/**
 * Mints a signed grant. Validates programmer-supplied invariants (throws on
 * violation), derives the standard claims, serializes the short-name wire
 * payload once, and signs `header.payload` via `deps.keyStore`.
 */
export async function mintGrant(
  input: MintGrantInput,
  deps: MintGrantDeps,
): Promise<MintGrantResult> {
  if (!Number.isSafeInteger(input.ttlSeconds) || input.ttlSeconds <= 0) {
    throw new Error(
      `mintGrant: ttlSeconds must be a positive integer, got ${String(input.ttlSeconds)}`,
    );
  }
  if (!Number.isSafeInteger(deps.nowEpochSeconds) || deps.nowEpochSeconds < 0) {
    throw new Error(
      `mintGrant: nowEpochSeconds must be a non-negative integer, got ${String(deps.nowEpochSeconds)}`,
    );
  }
  if (
    input.nbf !== undefined &&
    (!Number.isSafeInteger(input.nbf) || input.nbf < 0)
  ) {
    throw new Error(
      `mintGrant: nbf must be a non-negative integer when provided, got ${String(input.nbf)}`,
    );
  }

  const singleUse = input.singleUse ?? input.kind === "ephemeral";

  if (input.kind === "ephemeral") {
    if (input.callHash === undefined || input.callHash.length === 0) {
      throw new Error(
        "mintGrant: ephemeral grants require a non-empty callHash (TOCTOU binding, brief §I2.3)",
      );
    }
    if (singleUse !== true) {
      throw new Error(
        "mintGrant: ephemeral grants must be singleUse (they are consumed on first match)",
      );
    }
  } else if (input.callHash !== undefined) {
    throw new Error(
      "mintGrant: durable grants must not carry a callHash (architecture §5.2: absent on durable)",
    );
  }

  const claims: GrantClaims = {
    v: 1,
    jti: deps.generateId(),
    iat: deps.nowEpochSeconds,
    exp: deps.nowEpochSeconds + input.ttlSeconds,
    ...(input.nbf !== undefined ? { nbf: input.nbf } : {}),
    iss: `user:${input.principal.id}`,
    kind: input.kind,
    singleUse,
    principal: input.principal,
    agent: input.agent,
    tool: input.tool,
    scope: input.scope,
    ...(input.conditions !== undefined ? { conditions: input.conditions } : {}),
    tier: input.tier,
    envelopeScope: input.envelopeScope,
    ...(input.admin !== undefined ? { admin: input.admin } : {}),
    ...(input.callHash !== undefined ? { callHash: input.callHash } : {}),
  };

  const identity = await deps.keyStore.ensureIdentity();
  const header: GrantJwsHeader = {
    alg: GRANT_JWS_ALG,
    typ: GRANT_JWS_TYP,
    kid: identity.kid,
  };

  const headerSeg = base64urlUtf8(JSON.stringify(header));
  const payloadSeg = base64urlUtf8(JSON.stringify(claimsToWire(claims)));
  const signingInput = `${headerSeg}.${payloadSeg}`;

  const signature = await deps.keyStore.sign(
    new Uint8Array(Buffer.from(signingInput, "utf8")),
  );

  return { token: `${signingInput}.${base64urlBytes(signature)}`, claims };
}
