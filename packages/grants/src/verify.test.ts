/**
 * @knotrust/grants — verify tests (P0-E3-T2, ruling R26).
 *
 * Every allow this product grants flows through `verifyGrant`, so this suite
 * is adversarial by construction:
 *   1. one dedicated rejection test per machine-stable reason code, in the
 *      exact check order (first failure wins);
 *   2. the wrong-key-vs-unknown-kid distinction;
 *   3. no-throw guarantees over a corpus of hostile tokens + a byte-mutation
 *      fuzz over a valid token;
 *   4. mint→verify round-trip (durable + ephemeral-with-callHash);
 *   5. the on-disk `resolvePublicKey` seam, incl. its path-traversal guard.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { Tier } from "@knotrust/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  craftToken,
  durableInput,
  durableRequest,
  ephemeralInput,
  ephemeralRequest,
  makeTestKeyStore,
  resolverFor,
  validHeader,
  WRONG_SEED_HEX,
} from "./grant-test-kit.js";
import { createKeyStore } from "./keys.js";
import { mintGrant } from "./mint.js";
import {
  createDiskPublicKeyResolver,
  GrantRejectionReason,
  MAX_GRANT_TOKEN_LENGTH,
  type VerifyGrantOptions,
  verifyGrant,
} from "./verify.js";

const NOW = 1751553600;
let idc = 0;
const nextId = () => `01JZ8QAGRANT${String(idc++).padStart(3, "0")}`;

const ks = makeTestKeyStore();

async function mintDurable(over = {}) {
  return mintGrant(durableInput(over), {
    keyStore: ks,
    nowEpochSeconds: NOW,
    generateId: nextId,
  });
}
async function mintEphemeral(over = {}) {
  return mintGrant(ephemeralInput(over), {
    keyStore: ks,
    nowEpochSeconds: NOW,
    generateId: nextId,
  });
}

/** Baseline opts under which a freshly-minted durable grant VERIFIES OK. */
function goodOpts(over: Partial<VerifyGrantOptions> = {}): VerifyGrantOptions {
  return {
    request: durableRequest(),
    resolvedTier: "sensitive",
    nowEpochSeconds: NOW + 10,
    resolvePublicKey: resolverFor(ks.identity.kid, ks.publicKeyJwk),
    ...over,
  };
}

// ===========================================================================
// 1. Rejection reasons — one dedicated test per code, in check order.
// ===========================================================================

describe("verifyGrant — grant_malformed (parse/shape/alg/typ/v)", () => {
  it("rejects a token without exactly three segments", () => {
    for (const t of ["", "a", "a.b", "a.b.c.d"]) {
      expect(verifyGrant(t, goodOpts())).toEqual({
        ok: false,
        reason: GrantRejectionReason.Malformed,
      });
    }
  });

  it("rejects a header that is not valid JSON", () => {
    const token = `${Buffer.from("not json", "utf8").toString("base64url")}.x.y`;
    expect(verifyGrant(token, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.Malformed,
    });
  });

  it("rejects a header with alg other than EdDSA (alg-confusion defense)", async () => {
    const { token } = await mintDurable();
    const payloadSeg = token.split(".")[1] ?? "";
    const forged = craftToken({
      header: { alg: "none", typ: "knotrust-grant+jws", kid: ks.identity.kid },
      payload: { placeholder: true },
    });
    // Reuse a real signed payload segment but a "none" header → still malformed.
    const badAlgToken = `${forged.split(".")[0]}.${payloadSeg}.${token.split(".")[2]}`;
    expect(verifyGrant(badAlgToken, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.Malformed,
    });
  });

  it("rejects a header carrying crit, regardless of its value (RFC 7515 §4.1.11)", async () => {
    const { token } = await mintDurable();
    const payloadSeg = token.split(".")[1] ?? "";
    const forged = craftToken({
      header: {
        alg: "EdDSA",
        typ: "knotrust-grant+jws",
        kid: ks.identity.kid,
        crit: ["exp"],
      },
      payload: { placeholder: true },
    });
    // Reuse a real signed payload segment but a header carrying crit → still malformed.
    const critToken = `${forged.split(".")[0]}.${payloadSeg}.${token.split(".")[2]}`;
    expect(verifyGrant(critToken, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.Malformed,
    });
  });

  it("rejects a payload with v !== 1", () => {
    const token = craftToken({
      header: validHeader(ks.identity.kid),
      payload: {
        v: 2,
        jti: "x",
        iat: NOW,
        exp: NOW + 1,
        iss: "user:x",
        k: "durable",
        su: false,
        p: { type: "user", id: "x" },
        ag: "*",
        t: "github.*",
        s: {},
        r: "sensitive",
        es: "personal",
      },
    });
    expect(verifyGrant(token, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.Malformed,
    });
  });

  it("rejects an ephemeral grant missing callHash (ch required when k=ephemeral)", () => {
    const token = craftToken({
      header: validHeader(ks.identity.kid),
      payload: {
        v: 1,
        jti: "x",
        iat: NOW,
        exp: NOW + 1,
        iss: "user:x",
        k: "ephemeral",
        su: true,
        p: { type: "user", id: "x" },
        ag: "*",
        t: "github.*",
        s: {},
        r: "critical",
        es: "personal",
      },
    });
    expect(verifyGrant(token, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.Malformed,
    });
  });

  it("rejects a durable grant that carries a callHash (§5.2: absent on durable)", () => {
    const token = craftToken({
      header: validHeader(ks.identity.kid),
      payload: {
        v: 1,
        jti: "x",
        iat: NOW,
        exp: NOW + 1,
        iss: "user:x",
        k: "durable",
        su: false,
        p: { type: "user", id: "x" },
        ag: "*",
        t: "github.*",
        s: {},
        r: "sensitive",
        es: "personal",
        ch: "sha256:should-not-be-here",
      },
    });
    expect(verifyGrant(token, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.Malformed,
    });
  });
});

describe("verifyGrant — MAX_GRANT_TOKEN_LENGTH guard (DoS defense-in-depth)", () => {
  it("rejects an 8193-char token instantly as grant_malformed, without decoding", () => {
    expect(MAX_GRANT_TOKEN_LENGTH).toBe(8192);
    const oversized = "a".repeat(MAX_GRANT_TOKEN_LENGTH + 1); // 8193 chars
    const parseSpy = vi.spyOn(JSON, "parse");
    expect(verifyGrant(oversized, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.Malformed,
    });
    expect(parseSpy).not.toHaveBeenCalled();
    parseSpy.mockRestore();
  });

  it("rejects a multi-MB token via the fast length-guard, without ever JSON-decoding it (formerly the 'huge payload' no-throw case)", () => {
    const hugeToken = craftToken({
      header: validHeader(ks.identity.kid),
      payload: "x".repeat(5_000_000),
    });
    expect(hugeToken.length).toBeGreaterThan(1_000_000); // genuinely multi-MB, not just "huge"
    const parseSpy = vi.spyOn(JSON, "parse");
    let result: ReturnType<typeof verifyGrant> | undefined;
    expect(() => {
      result = verifyGrant(hugeToken, goodOpts());
    }).not.toThrow();
    expect(result).toEqual({
      ok: false,
      reason: GrantRejectionReason.Malformed,
    });
    expect(parseSpy).not.toHaveBeenCalled();
    parseSpy.mockRestore();
  });
});

describe("verifyGrant — grant_unknown_key", () => {
  it("rejects when the header kid resolves to no key", async () => {
    const { token } = await mintDurable();
    expect(
      verifyGrant(token, goodOpts({ resolvePublicKey: () => null })),
    ).toEqual({ ok: false, reason: GrantRejectionReason.UnknownKey });
  });
});

describe("verifyGrant — grant_invalid_signature", () => {
  it("rejects a token whose signature segment was tampered", async () => {
    const { token } = await mintDurable();
    const [h, p, s] = token.split(".");
    const flipped = (s ?? "").replace(/^./, (c) => (c === "A" ? "B" : "A"));
    const tampered = `${h}.${p}.${flipped}`;
    expect(verifyGrant(tampered, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.InvalidSignature,
    });
  });

  it("rejects a token whose payload bytes were mutated after signing", async () => {
    const { token } = await mintDurable();
    const [h, , s] = token.split(".");
    // Re-encode a DIFFERENT but still validly-shaped payload; original sig no longer covers it.
    const mutatedPayload = Buffer.from(
      JSON.stringify({
        v: 1,
        jti: "TAMPERED0000001",
        iat: NOW,
        exp: NOW + 999999,
        iss: "user:avijeett007@gmail.com",
        k: "durable",
        su: false,
        p: { type: "user", id: "avijeett007@gmail.com" },
        ag: "*",
        t: "github.*",
        s: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        r: "sensitive",
        es: "personal",
      }),
      "utf8",
    ).toString("base64url");
    const tampered = `${h}.${mutatedPayload}.${s}`;
    expect(verifyGrant(tampered, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.InvalidSignature,
    });
  });

  it("rejects a garbage-length signature without throwing", async () => {
    const { token } = await mintDurable();
    const [h, p] = token.split(".");
    const badSig = Buffer.from("too-short", "utf8").toString("base64url");
    expect(() => verifyGrant(`${h}.${p}.${badSig}`, goodOpts())).not.toThrow();
    expect(verifyGrant(`${h}.${p}.${badSig}`, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.InvalidSignature,
    });
  });
});

describe("verifyGrant — WRONG KEY vs UNKNOWN KEY (R26 distinct cases)", () => {
  it("a DIFFERENT key resolved for the same kid → grant_invalid_signature (not unknown_key)", async () => {
    const { token } = await mintDurable(); // signed by the golden key
    const wrong = makeTestKeyStore(WRONG_SEED_HEX);
    // Same kid the token advertises, but a different key's material.
    const resolvePublicKey = resolverFor(ks.identity.kid, wrong.publicKeyJwk);
    expect(verifyGrant(token, goodOpts({ resolvePublicKey }))).toEqual({
      ok: false,
      reason: GrantRejectionReason.InvalidSignature,
    });
  });
});

describe("verifyGrant — temporal windows", () => {
  it("grant_expired: now >= exp (exp is exclusive)", async () => {
    const { claims, token } = await mintDurable({ ttlSeconds: 3600 });
    expect(
      verifyGrant(token, goodOpts({ nowEpochSeconds: claims.exp })),
    ).toEqual({ ok: false, reason: GrantRejectionReason.Expired });
  });

  it("grant_not_yet_valid: now < nbf (nbf is inclusive)", async () => {
    const { token } = await mintDurable({ nbf: NOW + 100 });
    expect(verifyGrant(token, goodOpts({ nowEpochSeconds: NOW + 10 }))).toEqual(
      { ok: false, reason: GrantRejectionReason.NotYetValid },
    );
  });
});

describe("verifyGrant — pattern matching against the DecisionRequest (R25)", () => {
  it("grant_principal_mismatch: subject id differs", async () => {
    const { token } = await mintDurable();
    const request = durableRequest();
    request.subject = { type: "user", id: "someone-else@example.com" };
    expect(verifyGrant(token, goodOpts({ request }))).toEqual({
      ok: false,
      reason: GrantRejectionReason.PrincipalMismatch,
    });
  });

  it("grant_agent_mismatch: object agent id/type differs from context.agent", async () => {
    const { token } = await mintDurable({
      agent: { id: "codex-cli", type: "ai_agent" },
    });
    // durableRequest's context.agent is claude-desktop → mismatch.
    expect(verifyGrant(token, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.AgentMismatch,
    });
  });

  it("grant_tool_mismatch: action name not covered by the tool pattern", async () => {
    const { token } = await mintDurable(); // tool "github.*"
    const request = durableRequest();
    request.action = { name: "stripe.create_refund" };
    expect(verifyGrant(token, goodOpts({ request }))).toEqual({
      ok: false,
      reason: GrantRejectionReason.ToolMismatch,
    });
  });

  it("grant_scope_mismatch: resource id outside idPattern prefix", async () => {
    const { token } = await mintDurable(); // idPattern "kno2gether/*"
    const request = durableRequest();
    request.resource = { type: "github_repo", id: "someone-else/repo" };
    expect(verifyGrant(token, goodOpts({ request }))).toEqual({
      ok: false,
      reason: GrantRejectionReason.ScopeMismatch,
    });
  });

  it("conditions_unsupported: a non-empty conditions object fails closed", async () => {
    const { token } = await mintDurable({ conditions: { maxAmount: 5000 } });
    expect(verifyGrant(token, goodOpts())).toEqual({
      ok: false,
      reason: GrantRejectionReason.ConditionsUnsupported,
    });
  });
});

describe("verifyGrant — tier_cap_violation (self-escalation, TIER_RANK)", () => {
  it("rejects when claims.tier < resolvedTier", async () => {
    const { token } = await mintDurable(); // tier "sensitive"
    expect(
      verifyGrant(token, goodOpts({ resolvedTier: "critical" as Tier })),
    ).toEqual({ ok: false, reason: GrantRejectionReason.TierCapViolation });
  });
});

describe("verifyGrant — grant_call_mismatch (ephemeral callHash binding)", () => {
  it("rejects when ch is present but opts.callHash is absent", async () => {
    const { token } = await mintEphemeral();
    expect(
      verifyGrant(
        token,
        goodOpts({ request: ephemeralRequest(), resolvedTier: "critical" }),
      ),
    ).toEqual({ ok: false, reason: GrantRejectionReason.CallMismatch });
  });

  it("rejects when opts.callHash does not equal the grant's ch", async () => {
    const { token } = await mintEphemeral();
    expect(
      verifyGrant(
        token,
        goodOpts({
          request: ephemeralRequest(),
          resolvedTier: "critical",
          callHash: "sha256:some-other-call",
        }),
      ),
    ).toEqual({ ok: false, reason: GrantRejectionReason.CallMismatch });
  });
});

describe("verifyGrant — R35 check order: call-hash BEFORE tier-cap", () => {
  // A sub-tier-cap ephemeral grant (tier "sensitive", resolvedTier "critical")
  // whose call-hash ALSO mismatches trips BOTH the tier-cap gate and the
  // call-hash gate. R35 orders call-hash first, so the reported reason must be
  // grant_call_mismatch, NOT tier_cap_violation — this is what keeps the
  // lifecycle pass-through of a tier_cap_violation grant call-bound.
  it("a sub-cap ephemeral grant with a MISMATCHED callHash rejects grant_call_mismatch, not tier_cap_violation", async () => {
    const { token } = await mintEphemeral({ tier: "sensitive" });
    expect(
      verifyGrant(
        token,
        goodOpts({
          request: ephemeralRequest(),
          resolvedTier: "critical",
          callHash: "sha256:some-other-call",
        }),
      ),
    ).toEqual({ ok: false, reason: GrantRejectionReason.CallMismatch });
  });

  it("a sub-cap ephemeral grant with opts.callHash ABSENT rejects grant_call_mismatch, not tier_cap_violation (ch-present-but-callHash-absent, before tier-cap)", async () => {
    const { token } = await mintEphemeral({ tier: "sensitive" });
    expect(
      verifyGrant(
        token,
        goodOpts({ request: ephemeralRequest(), resolvedTier: "critical" }),
      ),
    ).toEqual({ ok: false, reason: GrantRejectionReason.CallMismatch });
  });

  it("a sub-cap ephemeral grant whose callHash MATCHES still reports tier_cap_violation (call-hash passed → tier-cap is the live failure)", async () => {
    const { claims, token } = await mintEphemeral({ tier: "sensitive" });
    const { callHash } = claims;
    if (callHash === undefined) {
      throw new Error(
        "fixture invariant: an ephemeral grant always has callHash",
      );
    }
    expect(
      verifyGrant(
        token,
        goodOpts({
          request: ephemeralRequest(),
          resolvedTier: "critical",
          callHash,
        }),
      ),
    ).toEqual({ ok: false, reason: GrantRejectionReason.TierCapViolation });
  });
});

// ===========================================================================
// 2. Round-trip — the positive path.
// ===========================================================================

describe("verifyGrant — mint→verify round-trip (ok:true)", () => {
  it("verifies a freshly-minted durable grant against a matching request", async () => {
    const { claims, token } = await mintDurable();
    const result = verifyGrant(token, goodOpts());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.claims).toEqual(claims);
      expect(result.coveringGrant).toEqual({
        kind: "durable",
        tierCap: "sensitive",
        exp: claims.exp,
        jti: claims.jti,
      });
    }
  });

  it("verifies an ephemeral grant when opts.callHash matches ch", async () => {
    const { claims, token } = await mintEphemeral();
    const { callHash } = claims;
    if (callHash === undefined) {
      throw new Error(
        "fixture invariant: an ephemeral grant always has callHash",
      );
    }
    const result = verifyGrant(
      token,
      goodOpts({
        request: ephemeralRequest(),
        resolvedTier: "critical",
        callHash,
      }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.coveringGrant.kind).toBe("ephemeral");
      expect(result.coveringGrant.tierCap).toBe("critical");
    }
  });

  it("carries nbf into the coveringGrant when present", async () => {
    const { claims, token } = await mintDurable({ nbf: NOW });
    const result = verifyGrant(token, goodOpts({ nowEpochSeconds: NOW + 10 }));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.coveringGrant.nbf).toBe(claims.nbf);
    }
  });

  it("matches a lone-'*' tool pattern and a '*' agent against any request", async () => {
    const { token } = await mintDurable({
      tool: "*",
      agent: "*",
      scope: {},
    });
    const request = durableRequest();
    request.action = { name: "anything.at_all" };
    request.resource = { type: "whatever", id: "id-123" };
    expect(verifyGrant(token, goodOpts({ request })).ok).toBe(true);
  });
});

// ===========================================================================
// 3. Adversarial no-throw guarantees.
// ===========================================================================

describe("verifyGrant — NEVER throws on hostile input", () => {
  const hostile: Array<[string, string]> = [
    ["empty", ""],
    ["single dot", "."],
    ["two segments", "a.b"],
    ["four segments", "a.b.c.d"],
    ["all dots", "...."],
    ["non-base64 junk", "$$$.%%%.^^^"],
    [
      "header decodes to a number",
      `${Buffer.from("123", "utf8").toString("base64url")}.${Buffer.from("123", "utf8").toString("base64url")}.x`,
    ],
    [
      "payload is a JSON array",
      craftToken({ header: validHeader(ks.identity.kid), payload: [1, 2, 3] }),
    ],
    [
      "payload is JSON null",
      craftToken({ header: validHeader(ks.identity.kid), payload: null }),
    ],
    [
      "lone surrogate in a claim",
      craftToken({
        header: validHeader(ks.identity.kid),
        payload: { v: 1, jti: "\uD800", k: "durable" },
      }),
    ],
  ];

  for (const [label, token] of hostile) {
    it(`no throw + ok:false for: ${label}`, () => {
      let result: ReturnType<typeof verifyGrant> | undefined;
      expect(() => {
        result = verifyGrant(token, goodOpts());
      }).not.toThrow();
      expect(result?.ok).toBe(false);
    });
  }

  it("no throw for non-string token values (null / number / object)", () => {
    for (const bad of [null, 123, {}, undefined, []]) {
      expect(() =>
        verifyGrant(bad as unknown as string, goodOpts()),
      ).not.toThrow();
      expect(verifyGrant(bad as unknown as string, goodOpts()).ok).toBe(false);
    }
  });

  it("no throw + ok:false for every single-byte mutation of the header+payload region", async () => {
    const { token } = await mintDurable();
    const secondDot = token.indexOf(".", token.indexOf(".") + 1);
    for (let i = 0; i < secondDot; i++) {
      const original = token[i] ?? "";
      const replacement = original === "A" ? "B" : "A";
      const mutated = token.slice(0, i) + replacement + token.slice(i + 1);
      let result: ReturnType<typeof verifyGrant> | undefined;
      expect(() => {
        result = verifyGrant(mutated, goodOpts());
      }).not.toThrow();
      expect(result?.ok).toBe(false);
    }
  });

  it("no throw for every single-byte mutation of the signature segment", async () => {
    const { token } = await mintDurable();
    const secondDot = token.indexOf(".", token.indexOf(".") + 1);
    for (let i = secondDot + 1; i < token.length; i++) {
      const original = token[i] ?? "";
      const replacement = original === "A" ? "B" : "A";
      const mutated = token.slice(0, i) + replacement + token.slice(i + 1);
      expect(() => verifyGrant(mutated, goodOpts())).not.toThrow();
    }
  });
});

// ===========================================================================
// 4. On-disk resolvePublicKey seam + path-traversal guard.
// ===========================================================================

describe("createDiskPublicKeyResolver — reads $KNOTRUST_HOME/keys/<kid>.jwk.json", () => {
  let tempHome: string;
  const ORIGINAL_HOME = process.env.KNOTRUST_HOME;

  beforeEach(() => {
    tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-verify-test-"));
    process.env.KNOTRUST_HOME = tempHome;
  });
  afterEach(() => {
    rmSync(tempHome, { recursive: true, force: true });
    if (ORIGINAL_HOME === undefined) delete process.env.KNOTRUST_HOME;
    else process.env.KNOTRUST_HOME = ORIGINAL_HOME;
  });

  it("resolves the real on-disk identity and completes a mint→verify round-trip", async () => {
    const fileKs = await createKeyStore({ backend: "file" });
    const identity = await fileKs.ensureIdentity();
    const { token } = await mintGrant(durableInput(), {
      keyStore: fileKs,
      nowEpochSeconds: NOW,
      generateId: nextId,
    });
    const resolvePublicKey = createDiskPublicKeyResolver();
    expect(resolvePublicKey(identity.kid)).toEqual(identity.publicKeyJwk);

    const result = verifyGrant(token, goodOpts({ resolvePublicKey }));
    expect(result.ok).toBe(true);
  });

  it("returns null for a kid that is not on disk (→ grant_unknown_key)", () => {
    const resolvePublicKey = createDiskPublicKeyResolver();
    expect(resolvePublicKey("nonexistent12345")).toBeNull();
  });

  it("returns null (no fs access) for a path-traversal kid", () => {
    const resolvePublicKey = createDiskPublicKeyResolver();
    for (const evil of [
      "../../etc/passwd",
      "..%2f..%2fetc",
      "a/b",
      "a.b",
      "",
      "x".repeat(200),
    ]) {
      expect(resolvePublicKey(evil)).toBeNull();
    }
  });
});
