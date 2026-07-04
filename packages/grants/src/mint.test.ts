/**
 * @knotrust/grants — mint tests (P0-E3-T2, ruling R27).
 *
 * Mint is NOT an adversarial surface (the caller holds the signing key), so
 * these prove the happy path, the derived-claim rules (`iss`, `iat`/`exp`,
 * `singleUse` default), the programmer-error guards (throw, not fail-closed),
 * and the acceptance token-size MEASUREMENT (recorded as a size ledger; the
 * §5.2 examples measure 568/662 B — over the 512 B target, see the size
 * describe block and the task report's concerns).
 */

import { describe, expect, it } from "vitest";
import { parseWireClaims } from "./claims.js";
import {
  durableInput,
  ephemeralInput,
  makeTestKeyStore,
} from "./grant-test-kit.js";
import { type MintGrantInput, mintGrant } from "./mint.js";

const NOW = 1751553600;
let idCounter = 0;
function deps() {
  return {
    keyStore: makeTestKeyStore(),
    nowEpochSeconds: NOW,
    generateId: () => `01JZ8QAGRANT${String(idCounter++).padStart(3, "0")}`,
  };
}

describe("mintGrant — derived claims (R27)", () => {
  it("derives iat=now, exp=now+ttl, iss=user:<principal.id>, v=1", async () => {
    const { claims } = await mintGrant(durableInput({ ttlSeconds: 3600 }), {
      ...deps(),
      generateId: () => "01JZ8QAGRANTABC",
    });
    expect(claims.v).toBe(1);
    expect(claims.jti).toBe("01JZ8QAGRANTABC");
    expect(claims.iat).toBe(NOW);
    expect(claims.exp).toBe(NOW + 3600);
    expect(claims.iss).toBe("user:avijeett007@gmail.com");
  });

  it("defaults singleUse=false for durable, true for ephemeral", async () => {
    const durable = await mintGrant(durableInput(), deps());
    expect(durable.claims.singleUse).toBe(false);
    expect(durable.claims.kind).toBe("durable");

    const ephemeral = await mintGrant(ephemeralInput(), deps());
    expect(ephemeral.claims.singleUse).toBe(true);
    expect(ephemeral.claims.callHash).toBe("sha256:9f2c1ed41b");
  });

  it("produces a three-segment JWS Compact token with the canonical header", async () => {
    const ks = makeTestKeyStore();
    const { token } = await mintGrant(durableInput(), {
      ...deps(),
      keyStore: ks,
    });
    const segments = token.split(".");
    expect(segments).toHaveLength(3);
    const header = JSON.parse(
      Buffer.from(segments[0] ?? "", "base64url").toString("utf8"),
    );
    expect(header).toEqual({
      alg: "EdDSA",
      typ: "knotrust-grant+jws",
      kid: ks.identity.kid,
    });
  });

  it("serializes the payload with ONLY wire short-names (round-trips via codec)", async () => {
    const { token, claims } = await mintGrant(durableInput(), deps());
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(payload).toHaveProperty("k", "durable");
    expect(payload).not.toHaveProperty("kind");
    expect(parseWireClaims(payload)).toEqual(claims);
  });

  it("omits absent optionals from the wire payload (nbf/c/ad/ch)", async () => {
    const { token } = await mintGrant(durableInput(), deps());
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(payload).not.toHaveProperty("nbf");
    expect(payload).not.toHaveProperty("c");
    expect(payload).not.toHaveProperty("ad");
    expect(payload).not.toHaveProperty("ch");
  });

  it("drops an explicitly-empty conditions {} from the wire payload (mint→wire codec symmetry)", async () => {
    const { token, claims } = await mintGrant(
      durableInput({ conditions: {} }),
      deps(),
    );
    expect(claims.conditions).toEqual({});

    const payload = JSON.parse(
      Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(payload).not.toHaveProperty("c");

    // Round-tripped back through the verify-side decoder, the wire has no
    // `c` key at all, so the recovered claims carry no `conditions` — this
    // is the intended {} === absent equivalence, not a byte-for-byte replay
    // of the caller's original {} input.
    const roundTripped = parseWireClaims(payload);
    expect(roundTripped).not.toBeNull();
    expect(roundTripped?.conditions).toBeUndefined();
  });
});

describe("mintGrant — programmer-error guards (throw, not fail-closed)", () => {
  it("throws when an ephemeral grant is minted without a callHash", async () => {
    // Built inline (not via ephemeralInput) — exactOptionalPropertyTypes
    // forbids passing `callHash: undefined`; the point is the key is ABSENT.
    const noCallHash: MintGrantInput = {
      kind: "ephemeral",
      principal: { type: "user", id: "avijeett007@gmail.com" },
      agent: { id: "codex-cli", type: "ai_agent" },
      tool: "stripe.create_refund",
      scope: { resourceType: "stripe_charge", idPattern: "ch_3PabcXYZ" },
      tier: "critical",
      envelopeScope: "personal",
      ttlSeconds: 120,
    };
    await expect(mintGrant(noCallHash, deps())).rejects.toThrow(/callHash/i);
  });

  it("throws when an ephemeral grant is forced to singleUse:false", async () => {
    await expect(
      mintGrant(ephemeralInput({ singleUse: false }), deps()),
    ).rejects.toThrow(/single/i);
  });

  it("throws when a durable grant carries a callHash (§5.2: absent on durable)", async () => {
    await expect(
      mintGrant(durableInput({ callHash: "sha256:x" }), deps()),
    ).rejects.toThrow(/durable/i);
  });

  it("throws on a non-positive ttl", async () => {
    await expect(
      mintGrant(durableInput({ ttlSeconds: 0 }), deps()),
    ).rejects.toThrow(/ttl/i);
  });
});

describe("mintGrant — token size measurement (acceptance)", () => {
  // ------------------------------------------------------------------------
  // RECORDED FINDING (feeds the "URL/QR budget question", brief §5 / ADR-0004)
  //
  // The acceptance brief targeted ≤ 512 bytes for a typical grant. The
  // architecture §5.2 examples, minted as real JWS Compact (EdDSA header +
  // 64-byte Ed25519 signature), DO NOT fit that target:
  //
  //   • §5.2 durable "github.*" typical grant .... 568 bytes
  //       (582 bytes with a real 26-char ULID jti instead of the placeholder)
  //   • §5.2 ephemeral grant (with callHash) ..... 662 bytes
  //
  // The fixed overhead alone — base64url(EdDSA header) + base64url(64-byte
  // sig) + 2 dots — is 178 bytes before a single claim; base64's ~33%
  // expansion over the short-name JSON payload accounts for the rest. This is
  // exactly the outcome ADR-0004 anticipated ("COSE reserved as a later size
  // optimization only IF measured grant size becomes an actual problem, e.g.
  // URL-embedding or QR-code transfer"). These assertions are a SIZE LEDGER /
  // regression guard around the real measured sizes — NOT the 512 target,
  // which the JWS format does not meet. See the task report's concerns.
  // ------------------------------------------------------------------------
  const DURABLE_MEASURED = 568;
  const EPHEMERAL_MEASURED = 662;

  it(`records the §5.2 durable typical grant size (measured ${DURABLE_MEASURED} B; EXCEEDS the 512 B target)`, async () => {
    const { token } = await mintGrant(durableInput(), deps());
    const bytes = Buffer.byteLength(token, "utf8");
    console.log(
      `[token-size] §5.2 durable typical grant = ${bytes} bytes (target was 512 — EXCEEDED by ${bytes - 512})`,
    );
    expect(bytes).toBe(DURABLE_MEASURED);
    expect(bytes).toBeGreaterThan(512); // codifies the finding: JWS grant > 512 B budget
  });

  it(`records the §5.2 ephemeral (with callHash) grant size (measured ${EPHEMERAL_MEASURED} B)`, async () => {
    const { token } = await mintGrant(ephemeralInput(), deps());
    const bytes = Buffer.byteLength(token, "utf8");
    console.log(
      `[token-size] §5.2 ephemeral grant (with ch) = ${bytes} bytes (target was 512 — EXCEEDED by ${bytes - 512})`,
    );
    expect(bytes).toBe(EPHEMERAL_MEASURED);
  });
});
