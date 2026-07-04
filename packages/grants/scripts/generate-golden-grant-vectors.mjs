#!/usr/bin/env node
/**
 * @knotrust/grants — golden grant-vector generation util (P0-E3-T5, R48/R49).
 *
 * DEV-ONLY. Not part of the package's runtime surface, not exported from
 * `src/index.ts`, and never imported by production code or by the vector
 * RUNNER (`packages/grants/src/golden-vectors.test.ts`) — the runner only
 * ever reads the committed JSON files it produced, and only ever asserts
 * that the COMMITTED token verifies, never that a fresh run of this script
 * reproduces byte-identical output (Ed25519 signing over a fixed payload
 * *is* deterministic, so in practice it does — but the frozen files, not
 * this script's live output, are the contract per the R49 ruling).
 *
 * Mints REAL signed grant tokens (via the package's actual `mintGrant` —
 * never a hand-rolled token — so the vectors exercise the exact production
 * JWS-assembly code path) under the two frozen, obviously-synthetic
 * Ed25519 test seeds (R48), then writes:
 *
 *   - `golden-vectors/grants/test-keys.json`   (the two seeds + derived
 *     kid/publicKeyJwk, independently re-derived here from raw seed bytes
 *     via `@noble/curves/ed25519.js` + `node:crypto` — the SAME derivation
 *     `packages/grants/src/keys.ts`'s `deriveIdentity`/`deriveKid` perform,
 *     duplicated deliberately, same pattern as `grant-test-kit.ts`'s own
 *     `identityFromSeed`, so this script has zero import coupling to
 *     internal `src/` paths)
 *   - `golden-vectors/grants/<name>.json` — one file per R49-mandated case.
 *
 * Regenerate with (from `packages/grants/`, after a monorepo build so
 * `@knotrust/grants`'s barrel — which pulls in `@knotrust/store` via
 * `lifecycle.ts`/`revoke.ts` — resolves against `dist/`):
 *
 *   pnpm turbo build
 *   node scripts/generate-golden-grant-vectors.mjs
 *
 * Running this OVERWRITES the committed vectors. Per the freeze policy
 * (`golden-vectors/README.md`), doing so intentionally — i.e. changing any
 * byte of an already-frozen v1 vector — is a contract break requiring an
 * explicit vector-version bump and an ADR. This script exists to produce
 * the v1 corpus once, not to be re-run casually thereafter.
 */

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { computeCallHash, mintGrant } from "@knotrust/grants";
import { ed25519 } from "@noble/curves/ed25519.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const grantsVectorsDir = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "grants",
);
mkdirSync(grantsVectorsDir, { recursive: true });

// ---------------------------------------------------------------------------
// R48 — TWO deterministic, obviously-synthetic Ed25519 seeds. NEVER use
// outside golden-vector suites; NEVER derive a production identity from
// these. `PRIMARY_SEED_HEX` is "42" repeated to 64 hex chars (32 bytes);
// `SECONDARY_SEED_HEX` is "1337" repeated to 64 hex chars — both instantly
// recognizable as test fixtures, never mistakable for real entropy.
// ---------------------------------------------------------------------------
const PRIMARY_SEED_HEX = "42".repeat(32);
const SECONDARY_SEED_HEX = "1337".repeat(16);

if (PRIMARY_SEED_HEX.length !== 64 || SECONDARY_SEED_HEX.length !== 64) {
  throw new Error(
    "golden-vector seeds must be exactly 64 hex chars (32 bytes)",
  );
}

/** Mirrors `packages/grants/src/keys.ts`'s `deriveKid` exactly (first 16 chars of base64url(SHA-256(pubkey))). */
function deriveKid(publicKey) {
  return Buffer.from(createHash("sha256").update(publicKey).digest())
    .toString("base64url")
    .slice(0, 16);
}

function identityFromSeed(seedHex) {
  const seed = Uint8Array.from(Buffer.from(seedHex, "hex"));
  const publicKey = ed25519.getPublicKey(seed);
  return {
    seed,
    seedHex,
    kid: deriveKid(publicKey),
    publicKeyJwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(publicKey).toString("base64url"),
    },
  };
}

/** A minimal in-memory `KeyStore` over a fixed seed (mirrors `grant-test-kit.ts`'s `makeTestKeyStore`, duplicated here for zero coupling to internal src paths — see module header). */
function makeKeyStore(identity) {
  return {
    backendKind: () => "file",
    ensureIdentity: async () => ({
      kid: identity.kid,
      publicKeyJwk: identity.publicKeyJwk,
    }),
    getIdentity: async () => ({
      kid: identity.kid,
      publicKeyJwk: identity.publicKeyJwk,
    }),
    sign: async (data) => ed25519.sign(data, identity.seed),
  };
}

const primary = identityFromSeed(PRIMARY_SEED_HEX);
const secondary = identityFromSeed(SECONDARY_SEED_HEX);
const primaryKeyStore = makeKeyStore(primary);

writeFileSync(
  path.join(grantsVectorsDir, "test-keys.json"),
  `${JSON.stringify(
    {
      warning:
        "TEST-ONLY KEYS — never use outside golden-vector suites. These seeds are obviously synthetic (repeating hex patterns), committed in plaintext on purpose, and must never back a real identity.",
      primary: {
        seed: primary.seedHex,
        publicKeyJwk: primary.publicKeyJwk,
        kid: primary.kid,
      },
      secondary: {
        seed: secondary.seedHex,
        publicKeyJwk: secondary.publicKeyJwk,
        kid: secondary.kid,
      },
    },
    null,
    2,
  )}\n`,
);
console.log(
  `wrote test-keys.json (primary kid=${primary.kid}, secondary kid=${secondary.kid})`,
);

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------
const NOW = 1_800_000_000; // fixed verify-time constant, matches golden-vectors/decisions' convention

let jtiCounter = 0;
function nextJti() {
  return `01GOLDGRANT${String(jtiCounter++).padStart(4, "0")}`;
}

function writeVector(name, description, token, verifyContext, expected) {
  const vector = { name, description, token, verifyContext, expected };
  writeFileSync(
    path.join(grantsVectorsDir, `${name}.json`),
    `${JSON.stringify(vector, null, 2)}\n`,
  );
  console.log(`wrote ${name}.json`);
}

function githubRequest(overrides = {}) {
  return {
    contractVersion: "1.0",
    requestId: "01GVGRANT0000000GITHUBREQ",
    timestamp: "2026-07-03T00:00:00.000Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "github.create_issue" },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: "claude-desktop", type: "ai_agent" },
      env: { time: "2026-07-03T00:00:00Z", surfaceLocal: true },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px_test",
      server: "github-mcp",
    },
    ...overrides,
  };
}

function stripeRequest(overrides = {}) {
  return {
    contractVersion: "1.0",
    requestId: "01GVGRANT0000000STRIPEREQ",
    timestamp: "2026-07-03T00:00:00.000Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-03T00:00:00Z", surfaceLocal: true },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px_test",
      server: "stripe-mcp",
    },
    ...overrides,
  };
}

/** Flips the last character of a decoded wire payload's `jti` string post-signing, keeping valid JSON shape but invalidating the signature (verify.ts step 3, BEFORE any claim is trusted). Mirrors `verify.test.ts`'s own "payload bytes mutated after signing" precedent. */
function tamperPayloadJti(token) {
  const [h, p, s] = token.split(".");
  const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  const chars = claims.jti.split("");
  const last = chars.at(-1);
  chars[chars.length - 1] = last === "0" ? "1" : "0";
  claims.jti = chars.join("");
  const newPayload = Buffer.from(JSON.stringify(claims), "utf8").toString(
    "base64url",
  );
  return `${h}.${newPayload}.${s}`;
}

// ---------------------------------------------------------------------------
// The 8 R49-mandated cases, in the plan's exact order.
// ---------------------------------------------------------------------------

async function main() {
  // --- 1. valid-durable (ok) ---
  {
    const request = githubRequest();
    const { token, claims } = await mintGrant(
      {
        kind: "durable",
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      {
        keyStore: primaryKeyStore,
        nowEpochSeconds: NOW - 1000,
        generateId: nextJti,
      },
    );
    writeVector(
      "valid-durable",
      "A durable grant, minted with the primary test key, within its temporal window and covering the request's principal/agent/tool/scope/tier — the baseline ok:true case.",
      token,
      {
        request,
        resolvedTier: "sensitive",
        nowEpochSeconds: NOW,
        resolveKid: "primary",
      },
      {
        ok: true,
        claims: { jti: claims.jti, kind: "durable", tier: "sensitive" },
      },
    );
  }

  // --- 2. expired ---
  {
    const request = githubRequest({ requestId: "01GVGRANT0000000EXPIREDRQ" });
    const { token, claims } = await mintGrant(
      {
        kind: "durable",
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 1000,
      },
      {
        keyStore: primaryKeyStore,
        nowEpochSeconds: NOW - 2000, // exp = NOW - 1000, already elapsed by verify time
        generateId: nextJti,
      },
    );
    writeVector(
      "expired",
      "A durable grant whose exp (iat + ttl) is already behind nowEpochSeconds at verify time — exp is exclusive (now >= exp).",
      token,
      {
        request,
        resolvedTier: "sensitive",
        nowEpochSeconds: NOW,
        resolveKid: "primary",
      },
      { ok: false, reasonCode: "grant_expired" },
    );
    void claims;
  }

  // --- 3. tampered-signature (flip one payload byte post-signing) ---
  {
    const request = githubRequest({ requestId: "01GVGRANT0000000TAMPERRQ" });
    const { token } = await mintGrant(
      {
        kind: "durable",
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      {
        keyStore: primaryKeyStore,
        nowEpochSeconds: NOW - 1000,
        generateId: nextJti,
      },
    );
    const tampered = tamperPayloadJti(token);
    writeVector(
      "tampered-signature",
      "A validly-minted durable grant whose payload's `jti` string had its last character flipped AFTER signing (valid JSON, valid shape, different signed bytes) — the original signature no longer covers these bytes, so this is grant_invalid_signature, not grant_malformed.",
      tampered,
      {
        request,
        resolvedTier: "sensitive",
        nowEpochSeconds: NOW,
        resolveKid: "primary",
      },
      { ok: false, reasonCode: "grant_invalid_signature" },
    );
  }

  // --- 4. wrong-key ---
  {
    const request = githubRequest({ requestId: "01GVGRANT0000000WRONGKYRQ" });
    const { token } = await mintGrant(
      {
        kind: "durable",
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      {
        keyStore: primaryKeyStore,
        nowEpochSeconds: NOW - 1000,
        generateId: nextJti,
      },
    );
    writeVector(
      "wrong-key",
      "A validly-minted (primary-signed) durable grant whose verify context resolves the SECONDARY test key's pubkey for the primary's kid (a misresolved/hostile key mapping) — the Ed25519 verify fails against the wrong key material: grant_invalid_signature, distinct from grant_unknown_key (the kid still resolves to SOME key, just the wrong one).",
      token,
      {
        request,
        resolvedTier: "sensitive",
        nowEpochSeconds: NOW,
        resolveKid: "secondary",
      },
      { ok: false, reasonCode: "grant_invalid_signature" },
    );
  }

  // --- 5. single-use-ephemeral-valid (ok; su+ch matching — doubles as "call-hash-bound with matching call") ---
  {
    const request = stripeRequest({ requestId: "01GVGRANT0000000EPHEMEOK1" });
    const callHash = computeCallHash(request);
    const { token, claims } = await mintGrant(
      {
        kind: "ephemeral",
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: { id: "codex-cli", type: "ai_agent" },
        tool: "stripe.create_refund",
        scope: { resourceType: "stripe_charge", idPattern: "ch_3PabcXYZ" },
        tier: "critical",
        envelopeScope: "personal",
        ttlSeconds: 120,
        callHash,
      },
      {
        keyStore: primaryKeyStore,
        nowEpochSeconds: NOW - 10,
        generateId: nextJti,
      },
    );
    writeVector(
      "single-use-ephemeral-valid",
      "An ephemeral, single-use grant whose callHash matches the executing call's SARC-normal-form hash exactly — the TOCTOU-closing positive path (su: true, ch bound and matching).",
      token,
      {
        request,
        resolvedTier: "critical",
        nowEpochSeconds: NOW,
        callHash,
        resolveKid: "primary",
      },
      {
        ok: true,
        claims: { jti: claims.jti, kind: "ephemeral", tier: "critical" },
      },
    );
  }

  // --- 6. scope-mismatch ---
  {
    const mintRequest = githubRequest({
      requestId: "01GVGRANT0000000SCOPEMMRQ",
    });
    const { token } = await mintGrant(
      {
        kind: "durable",
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      {
        keyStore: primaryKeyStore,
        nowEpochSeconds: NOW - 1000,
        generateId: nextJti,
      },
    );
    // The live request's resource id falls outside the grant's idPattern
    // prefix ("kno2gether/*") — same tool, same principal/agent, temporally
    // valid, but the wrong repo owner.
    const liveRequest = githubRequest({
      requestId: "01GVGRANT0000000SCOPEMMRQ",
      resource: { type: "github_repo", id: "someone-else/repo" },
    });
    void mintRequest;
    writeVector(
      "scope-mismatch",
      'A durable grant scoped to idPattern "kno2gether/*" verified against a request whose resource.id is "someone-else/repo" — same tool/principal/agent, temporally valid, but outside the grant\'s resource scope.',
      token,
      {
        request: liveRequest,
        resolvedTier: "sensitive",
        nowEpochSeconds: NOW,
        resolveKid: "primary",
      },
      { ok: false, reasonCode: "grant_scope_mismatch" },
    );
  }

  // --- 7. tier-cap-violation (R35 order: otherwise-valid grant, cap below resolvedTier) ---
  {
    const request = stripeRequest({ requestId: "01GVGRANT0000000TIERCAPRQ" });
    const { token } = await mintGrant(
      {
        kind: "durable",
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: { id: "codex-cli", type: "ai_agent" },
        tool: "stripe.create_refund",
        scope: { resourceType: "stripe_charge", idPattern: "ch_*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      {
        keyStore: primaryKeyStore,
        nowEpochSeconds: NOW - 1000,
        generateId: nextJti,
      },
    );
    // Durable grant carries no callHash, so R35's call-hash gate is a no-op
    // (skipped entirely) and the tier-cap gate is reached directly after an
    // otherwise fully-matching grant — this is the case's whole point:
    // signature/temporal/pattern/conditions all pass, only the tier cap fails.
    writeVector(
      "tier-cap-violation",
      'An otherwise-fully-valid durable grant (signature, temporal window, principal/agent/tool/scope, conditions all pass) whose own tierCap ("sensitive") is below the resolvedTier ("critical") — an active self-escalation attempt. Durable (no callHash), so R35\'s call-hash gate never applies here; this isolates the tier-cap check alone.',
      token,
      {
        request,
        resolvedTier: "critical",
        nowEpochSeconds: NOW,
        resolveKid: "primary",
      },
      { ok: false, reasonCode: "tier_cap_violation" },
    );
  }

  // --- 8. call-hash-mismatch ---
  {
    const approvedRequest = stripeRequest({
      requestId: "01GVGRANT0000000CHMISMRQ",
    });
    const approvedCallHash = computeCallHash(approvedRequest);
    const { token } = await mintGrant(
      {
        kind: "ephemeral",
        principal: { type: "user", id: "avijeett007@gmail.com" },
        agent: { id: "codex-cli", type: "ai_agent" },
        tool: "stripe.create_refund",
        scope: { resourceType: "stripe_charge", idPattern: "ch_3PabcXYZ" },
        tier: "critical",
        envelopeScope: "personal",
        ttlSeconds: 120,
        callHash: approvedCallHash,
      },
      {
        keyStore: primaryKeyStore,
        nowEpochSeconds: NOW - 10,
        generateId: nextJti,
      },
    );
    // The live call hashed for verification is a DIFFERENT call (a different
    // charge id) than the one the grant's `ch` is bound to — principal,
    // agent, tool, and scope.idPattern ("ch_3PabcXYZ" is an exact string, and
    // `approvedRequest`'s own resource.id is what's used for verifyContext
    // matching) all still line up, but the hash itself mismatches.
    const differentRequest = stripeRequest({
      requestId: "01GVGRANT0000000CHMISMRQ",
      resource: { type: "stripe_charge", id: "ch_9ZZZdifferentcharge" },
    });
    const mismatchedCallHash = computeCallHash(differentRequest);
    writeVector(
      "call-hash-mismatch",
      "An ephemeral grant whose `ch` is bound to one approved call; the live verifyContext.callHash is computed from a DIFFERENT call (a different charge id) — the TOCTOU gate rejects it as grant_call_mismatch even though resolvedTier equals the grant's own tierCap (so a tier-cap check, if reached, would have passed — R35 orders call-hash strictly before tier-cap).",
      token,
      {
        request: approvedRequest,
        resolvedTier: "critical",
        nowEpochSeconds: NOW,
        callHash: mismatchedCallHash,
        resolveKid: "primary",
      },
      { ok: false, reasonCode: "grant_call_mismatch" },
    );
  }

  console.log(
    `\ndone — ${jtiCounter} grants minted, 8 vectors + test-keys.json written to ${grantsVectorsDir}`,
  );
}

await main();
