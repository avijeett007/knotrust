/**
 * @knotrust/grants — golden grant-vector runner (P0-E3-T5, R48/R49 — THE FREEZE).
 *
 * Loads EVERY `*.json` fixture in the repo-root `golden-vectors/grants/`
 * directory (dynamic, exactly like `packages/core/src/decision-fixtures.test.ts`
 * and this package's own `sarc-vectors.test.ts`) — EXCEPT `test-keys.json`,
 * which is key material, not a case fixture — and runs `verifyGrant` against
 * each one's `verifyContext`, asserting the frozen `expected` outcome.
 *
 * These vectors anchor the Phase-3 Python port and every future TS refactor
 * (`golden-vectors/README.md`'s freeze policy): after this task, changing any
 * byte of a committed vector is a contract break requiring an explicit
 * vector-version bump. This suite asserts that the COMMITTED token verifies —
 * it deliberately never regenerates a token and diffs it against the fixture
 * (see `scripts/generate-golden-grant-vectors.mjs`'s header for why: Ed25519
 * signing over a fixed payload happens to be deterministic, but the frozen
 * bytes on disk are the contract, not a fresh run of the generator).
 *
 * R48: the seed→JWK→kid derivation path is ALSO reproduced HERE, independently
 * of the generation script, directly from each seed's raw bytes — locking that
 * derivation cross-language too (a Python port's own key-loading code has the
 * exact same obligation: reproduce kid/pubkey from the raw seed, not just trust
 * the committed JWK).
 */

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { DecisionRequest, Tier } from "@knotrust/core";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import type { Ed25519PublicJwk } from "./keys.js";
import { GrantRejectionReason, verifyGrant } from "./verify.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const grantsVectorsDir = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "grants",
);

// ---------------------------------------------------------------------------
// test-keys.json (R48) — TEST-ONLY. Loaded once; every vector resolves one of
// these two identities via its own `verifyContext.resolveKid`.
// ---------------------------------------------------------------------------

interface TestKeyEntry {
  seed: string;
  publicKeyJwk: Ed25519PublicJwk;
  kid: string;
}

interface TestKeysFile {
  warning: string;
  primary: TestKeyEntry;
  secondary: TestKeyEntry;
}

const testKeys = JSON.parse(
  readFileSync(path.join(grantsVectorsDir, "test-keys.json"), "utf8"),
) as TestKeysFile;

/** Mirrors `packages/grants/src/keys.ts`'s `deriveKid` exactly. */
function deriveKid(publicKey: Uint8Array): string {
  return Buffer.from(createHash("sha256").update(publicKey).digest())
    .toString("base64url")
    .slice(0, 16);
}

describe("golden-vectors/grants/test-keys.json — R48 seed→JWK→kid derivation", () => {
  it.each([
    ["primary", testKeys.primary],
    ["secondary", testKeys.secondary],
  ] as const)("%s: the committed publicKeyJwk/kid are reproduced from the raw seed (not just trusted from the file)", (_label, entry) => {
    const seed = Uint8Array.from(Buffer.from(entry.seed, "hex"));
    expect(seed).toHaveLength(32);
    const publicKey = ed25519.getPublicKey(seed);
    const rederivedJwk: Ed25519PublicJwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(publicKey).toString("base64url"),
    };
    expect(rederivedJwk).toEqual(entry.publicKeyJwk);
    expect(deriveKid(publicKey)).toBe(entry.kid);
  });

  it("the warning field marks these as test-only, never for production use", () => {
    expect(testKeys.warning).toMatch(/test-only/i);
    expect(testKeys.warning).toMatch(/never/i);
  });

  it("primary and secondary are genuinely different keys", () => {
    expect(testKeys.primary.kid).not.toBe(testKeys.secondary.kid);
    expect(testKeys.primary.publicKeyJwk.x).not.toBe(
      testKeys.secondary.publicKeyJwk.x,
    );
  });
});

// ---------------------------------------------------------------------------
// Vector loading (dynamic enumeration, `test-keys.json` excluded)
// ---------------------------------------------------------------------------

interface GrantVectorExpected {
  ok: boolean;
  reasonCode?: string;
  claims?: { jti: string; kind: "durable" | "ephemeral"; tier: Tier };
}

interface GrantVector {
  name: string;
  description: string;
  token: string;
  verifyContext: {
    request: DecisionRequest;
    resolvedTier: Tier;
    nowEpochSeconds: number;
    callHash?: string;
    resolveKid: "primary" | "secondary";
  };
  expected: GrantVectorExpected;
}

function loadVectors(): Array<[string, GrantVector]> {
  const files = readdirSync(grantsVectorsDir).filter(
    (f) => f.endsWith(".json") && f !== "test-keys.json",
  );
  return files
    .sort()
    .map((file) => [
      file,
      JSON.parse(
        readFileSync(path.join(grantsVectorsDir, file), "utf8"),
      ) as GrantVector,
    ]);
}

const vectors = loadVectors();

/**
 * Builds the `resolvePublicKey` seam for one vector: ALWAYS keyed on the
 * PRIMARY test key's kid (every vector's token is signed with `primary` —
 * R48: "All grant vectors are minted with primary"), returning whichever
 * identity's pubkey `verifyContext.resolveKid` names. For the `wrong-key`
 * vector this is `"secondary"` — the primary's kid resolves to the WRONG
 * key's material, exactly reproducing R48's "the wrong-key vector's verify
 * context resolves secondary's pubkey for primary's kid".
 */
function resolverFor(
  resolveKid: "primary" | "secondary",
): (kid: string) => Ed25519PublicJwk | null {
  const jwk = testKeys[resolveKid].publicKeyJwk;
  const presentedKid = testKeys.primary.kid;
  return (kid: string) => (kid === presentedKid ? jwk : null);
}

describe("golden grant vectors (golden-vectors/grants) — THE FREEZE", () => {
  it("enumerates the directory dynamically and finds exactly the 8 R49-mandated cases", () => {
    const expectedNames = [
      "call-hash-mismatch",
      "expired",
      "scope-mismatch",
      "single-use-ephemeral-valid",
      "tampered-signature",
      "tier-cap-violation",
      "valid-durable",
      "wrong-key",
    ];
    expect(vectors.map(([file]) => file).sort()).toEqual(
      expectedNames.map((n) => `${n}.json`).sort(),
    );
  });

  it.each(vectors)("%s", (_file, vector) => {
    const { verifyContext, expected } = vector;
    const result = verifyGrant(vector.token, {
      request: verifyContext.request,
      resolvedTier: verifyContext.resolvedTier,
      nowEpochSeconds: verifyContext.nowEpochSeconds,
      ...(verifyContext.callHash !== undefined
        ? { callHash: verifyContext.callHash }
        : {}),
      resolvePublicKey: resolverFor(verifyContext.resolveKid),
    });

    expect(result.ok).toBe(expected.ok);

    if (expected.ok) {
      if (!result.ok) {
        throw new Error(
          `expected ok:true but got ok:false (reason=${result.reason})`,
        );
      }
      if (expected.claims === undefined) {
        throw new Error(
          `fixture ${vector.name}: expected.ok is true but expected.claims is missing`,
        );
      }
      expect(result.claims.jti).toBe(expected.claims.jti);
      expect(result.claims.kind).toBe(expected.claims.kind);
      expect(result.claims.tier).toBe(expected.claims.tier);
      expect(result.coveringGrant.jti).toBe(expected.claims.jti);
      expect(result.coveringGrant.tierCap).toBe(expected.claims.tier);
    } else {
      if (result.ok) {
        throw new Error("expected ok:false but got ok:true");
      }
      expect(result.reason).toBe(expected.reasonCode);
    }
  });

  it("every rejection reasonCode used by a vector is a real GrantRejectionReason (no typos)", () => {
    const known = new Set<string>(Object.values(GrantRejectionReason));
    for (const [file, vector] of vectors) {
      if (!vector.expected.ok) {
        expect(
          known.has(vector.expected.reasonCode as string),
          `${file}: unknown reasonCode ${vector.expected.reasonCode}`,
        ).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// MCP-reference guard (ruling 6): the comprehensive, cross-directory guard —
// walking the ENTIRE golden-vectors/ tree, including this directory — lives
// in ./golden-vectors-mcp-guard.test.ts (see that file's header for why it
// lives in @knotrust/grants rather than @knotrust/core).
// ---------------------------------------------------------------------------
