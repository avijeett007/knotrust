/**
 * @knotrust/grants — shared test kit for the mint/verify suites (P0-E3-T2).
 *
 * NOT a test file (no `describe`/`it`, filename is not `*.test.ts`), so
 * Vitest never collects it; it exists only so `mint.test.ts`,
 * `verify.test.ts`, and `claims.test.ts` share one set of fixtures and one
 * `craftToken` helper for adversarial payloads a real `mintGrant` would
 * refuse to produce.
 *
 * The Ed25519 material below is the SAME golden seed cross-validated against
 * `node:crypto` in `keys.test.ts` (see that file's header), so `WRONG_*` is a
 * genuinely different, independently-derived key — exactly what the
 * wrong-key-vs-unknown-kid distinction (R26) needs.
 */

import { createHash } from "node:crypto";
import type { DecisionRequest } from "@knotrust/core";
import { ed25519 } from "@noble/curves/ed25519.js";
import type { GrantJwsHeader } from "./claims.js";
import type { Ed25519PublicJwk, KeyStore, KnotrustIdentity } from "./keys.js";
import type { MintGrantInput } from "./mint.js";

/** The golden seed (see keys.test.ts) — its kid/pubkey are known-correct. */
export const GOLDEN_SEED_HEX =
  "4c8a67b53eb24b1197b90d0339594e5d2cdd953c2fabc418f1231235c126ee29";
/** A DIFFERENT seed — its key resolved for the golden kid is the wrong-key case. */
export const WRONG_SEED_HEX =
  "1111111111111111111111111111111111111111111111111111111111111111";

/** Mirror of keys.ts `deriveKid`: first 16 chars of base64url(SHA-256(raw pubkey)). */
function deriveKid(publicKey: Uint8Array): string {
  return Buffer.from(createHash("sha256").update(publicKey).digest())
    .toString("base64url")
    .slice(0, 16);
}

function identityFromSeed(seedHex: string): {
  seed: Uint8Array;
  identity: KnotrustIdentity;
} {
  const seed = Uint8Array.from(Buffer.from(seedHex, "hex"));
  const publicKey = ed25519.getPublicKey(seed);
  return {
    seed,
    identity: {
      kid: deriveKid(publicKey),
      publicKeyJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: Buffer.from(publicKey).toString("base64url"),
      },
    },
  };
}

export interface TestKeyStore extends KeyStore {
  identity: KnotrustIdentity;
  publicKeyJwk: Ed25519PublicJwk;
}

/**
 * A minimal in-memory `KeyStore` over a fixed seed — deterministic signatures,
 * no filesystem, no OS keychain. `sign()` goes through the exact same
 * `@noble/curves` primitive as the real `keys.ts` file backend.
 */
export function makeTestKeyStore(
  seedHex: string = GOLDEN_SEED_HEX,
): TestKeyStore {
  const { seed, identity } = identityFromSeed(seedHex);
  return {
    identity,
    publicKeyJwk: identity.publicKeyJwk,
    backendKind: () => "file",
    ensureIdentity: async () => identity,
    getIdentity: async () => identity,
    sign: async (data: Uint8Array) => ed25519.sign(data, seed),
  };
}

/** A `resolvePublicKey` seam that returns `jwk` only for `kid`, else null. */
export function resolverFor(
  kid: string,
  jwk: Ed25519PublicJwk,
): (k: string) => Ed25519PublicJwk | null {
  return (k) => (k === kid ? jwk : null);
}

// ---------------------------------------------------------------------------
// base64url helpers (local to the kit — the production code has its own)
// ---------------------------------------------------------------------------

function utf8ToBase64url(s: string): string {
  return Buffer.from(s, "utf8").toString("base64url");
}

/**
 * Hand-assembles a `header.payload.sig` token from arbitrary objects WITHOUT
 * validating them — the whole point is to craft payloads (bad `v`, ephemeral
 * missing `ch`, durable carrying `ch`, wrong-typed fields) that `mintGrant`
 * would throw on. `signature` defaults to a syntactically-valid-but-bogus
 * segment: adequate for the malformed/unknown-key checks that run BEFORE the
 * signature check and never reach it.
 */
export function craftToken(args: {
  header: unknown;
  payload: unknown;
  signature?: string;
}): string {
  const headerSeg = utf8ToBase64url(JSON.stringify(args.header));
  const payloadSeg = utf8ToBase64url(JSON.stringify(args.payload));
  const sigSeg = args.signature ?? "AAAA";
  return `${headerSeg}.${payloadSeg}.${sigSeg}`;
}

/** A well-formed header for a given kid (valid `alg`/`typ`). */
export function validHeader(kid: string): GrantJwsHeader {
  return { alg: "EdDSA", typ: "knotrust-grant+jws", kid };
}

// ---------------------------------------------------------------------------
// Grant + request fixtures (the architecture §5.2 examples, adapted)
// ---------------------------------------------------------------------------

/** The §5.2 durable example, as `mintGrant` input (github.* typical grant). */
export function durableInput(
  over: Partial<MintGrantInput> = {},
): MintGrantInput {
  return {
    kind: "durable",
    principal: { type: "user", id: "avijeett007@gmail.com" },
    agent: "*",
    tool: "github.*",
    scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
    tier: "sensitive",
    envelopeScope: "personal",
    ttlSeconds: 2_592_000, // 30 days, as in the §5.2 example (iat→exp span)
    ...over,
  };
}

/** The §5.2 ephemeral example, as `mintGrant` input (note callHash). */
export function ephemeralInput(
  over: Partial<MintGrantInput> = {},
): MintGrantInput {
  return {
    kind: "ephemeral",
    principal: { type: "user", id: "avijeett007@gmail.com" },
    agent: { id: "codex-cli", type: "ai_agent" },
    tool: "stripe.create_refund",
    scope: { resourceType: "stripe_charge", idPattern: "ch_3PabcXYZ" },
    tier: "critical",
    envelopeScope: "personal",
    ttlSeconds: 120,
    callHash: "sha256:9f2c1ed41b",
    ...over,
  };
}

/** A `DecisionRequest` that the durable fixture grant covers (matches). */
export function durableRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01JZ8QREQUEST001",
    timestamp: "2026-07-03T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "github.create_issue" },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: "claude-desktop", type: "ai_agent" },
      env: { time: "2026-07-03T12:00:00Z", surfaceLocal: true },
    },
    surface: { kind: "stdio_proxy", instanceId: "inst-1", server: "github" },
  };
}

/** A `DecisionRequest` that the ephemeral fixture grant covers (matches). */
export function ephemeralRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01JZ8QREQUEST002",
    timestamp: "2026-07-03T12:04:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-03T12:04:00Z", surfaceLocal: true },
    },
    surface: { kind: "stdio_proxy", instanceId: "inst-2", server: "stripe" },
  };
}
