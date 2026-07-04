/**
 * @knotrust/grants — claims codec tests (P0-E3-T2).
 *
 * Proves the bijective in-memory `GrantClaims` ↔ wire short-name mapping
 * (architecture §5.2): every claim uses ONLY its short name on the wire,
 * absent optionals stay absent (size matters), and `parseWireClaims` fails
 * closed on every shape violation instead of throwing.
 */

import { describe, expect, it } from "vitest";
import {
  claimsToWire,
  type GrantClaims,
  type GrantClaimsWire,
  parseJwsHeader,
  parseWireClaims,
} from "./claims.js";

const DURABLE_CLAIMS: GrantClaims = {
  v: 1,
  jti: "01JZ8QAGRANT001",
  iat: 1751553600,
  exp: 1754145600,
  iss: "user:avijeett007@gmail.com",
  kind: "durable",
  singleUse: false,
  principal: { type: "user", id: "avijeett007@gmail.com" },
  agent: "*",
  tool: "github.*",
  scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
  tier: "sensitive",
  envelopeScope: "personal",
};

// The exact §5.2 "decoded payload of a durable grant" wire object.
const DURABLE_WIRE: GrantClaimsWire = {
  v: 1,
  jti: "01JZ8QAGRANT001",
  iat: 1751553600,
  exp: 1754145600,
  iss: "user:avijeett007@gmail.com",
  k: "durable",
  su: false,
  p: { type: "user", id: "avijeett007@gmail.com" },
  ag: "*",
  t: "github.*",
  s: { resourceType: "github_repo", idPattern: "kno2gether/*" },
  r: "sensitive",
  es: "personal",
};

// The exact §5.2 "decoded payload of an ephemeral grant" wire object.
const EPHEMERAL_WIRE: GrantClaimsWire = {
  v: 1,
  jti: "01JZ8QEPHEM0001",
  iat: 1751553842,
  exp: 1751553962,
  iss: "user:avijeett007@gmail.com",
  k: "ephemeral",
  su: true,
  p: { type: "user", id: "avijeett007@gmail.com" },
  ag: { id: "codex-cli", type: "ai_agent" },
  t: "stripe.create_refund",
  s: { resourceType: "stripe_charge", idPattern: "ch_3PabcXYZ" },
  r: "critical",
  es: "personal",
  ch: "sha256:9f2c1e...d41b",
};

describe("claimsToWire — short-name mapping (§5.2)", () => {
  it("maps the durable example to EXACTLY the §5.2 wire shape (only short names)", () => {
    expect(claimsToWire(DURABLE_CLAIMS)).toEqual(DURABLE_WIRE);
  });

  it("uses only the canonical short keys, never the long human-readable names", () => {
    const wire = claimsToWire(DURABLE_CLAIMS) as unknown as Record<
      string,
      unknown
    >;
    for (const longName of [
      "kind",
      "singleUse",
      "principal",
      "agent",
      "tool",
      "scope",
      "conditions",
      "tier",
      "envelopeScope",
      "admin",
      "callHash",
    ]) {
      expect(wire).not.toHaveProperty(longName);
    }
  });

  it("drops absent optionals on the wire (no nbf/c/ad/ch keys emitted)", () => {
    const wire = claimsToWire(DURABLE_CLAIMS) as unknown as Record<
      string,
      unknown
    >;
    expect(Object.keys(wire).sort()).toEqual(
      [
        "ag",
        "es",
        "exp",
        "iat",
        "iss",
        "jti",
        "k",
        "p",
        "r",
        "s",
        "su",
        "t",
        "v",
      ].sort(),
    );
    expect(wire).not.toHaveProperty("nbf");
    expect(wire).not.toHaveProperty("c");
    expect(wire).not.toHaveProperty("ad");
    expect(wire).not.toHaveProperty("ch");
  });

  it("emits the optional short names when present (nbf, c, ad, ch)", () => {
    const full: GrantClaims = {
      ...DURABLE_CLAIMS,
      kind: "ephemeral",
      singleUse: true,
      nbf: 1751553600,
      conditions: { maxAmount: 5000 },
      admin: true,
      callHash: "sha256:abc",
    };
    const wire = claimsToWire(full) as unknown as Record<string, unknown>;
    expect(wire.nbf).toBe(1751553600);
    expect(wire.c).toEqual({ maxAmount: 5000 });
    expect(wire.ad).toBe(true);
    expect(wire.ch).toBe("sha256:abc");
  });

  it("drops an explicitly-empty conditions {} from the wire — same as absent (codec symmetry)", () => {
    const withEmptyConditions: GrantClaims = {
      ...DURABLE_CLAIMS,
      conditions: {},
    };
    const wire = claimsToWire(withEmptyConditions) as unknown as Record<
      string,
      unknown
    >;
    expect(wire).not.toHaveProperty("c");
    // Identical wire output to the no-conditions-at-all claims — {} and
    // absent are the same wire shape, matching verify's treatment of {}.
    expect(wire).toEqual(claimsToWire(DURABLE_CLAIMS));
  });
});

describe("parseWireClaims — round-trip bijection", () => {
  it("parses the §5.2 durable wire example back into the claims shape", () => {
    expect(parseWireClaims(DURABLE_WIRE)).toEqual(DURABLE_CLAIMS);
  });

  it("parses the §5.2 ephemeral wire example (with ch) into claims", () => {
    const claims = parseWireClaims(EPHEMERAL_WIRE);
    expect(claims).not.toBeNull();
    expect(claims?.kind).toBe("ephemeral");
    expect(claims?.agent).toEqual({ id: "codex-cli", type: "ai_agent" });
    expect(claims?.callHash).toBe("sha256:9f2c1e...d41b");
  });

  it("round-trips claims → wire → claims unchanged", () => {
    const claims = parseWireClaims(EPHEMERAL_WIRE);
    expect(claims).not.toBeNull();
    if (claims) {
      expect(claimsToWire(claims)).toEqual(EPHEMERAL_WIRE);
    }
  });

  it("strips unknown/extra wire keys (v pins the schema; signature pins bytes)", () => {
    const withExtra = { ...DURABLE_WIRE, xtra: "ignored", zz: 1 };
    expect(parseWireClaims(withExtra)).toEqual(DURABLE_CLAIMS);
  });
});

describe("parseWireClaims — fail-closed shape validation (never throws)", () => {
  const badInputs: Array<[string, unknown]> = [
    ["null", null],
    ["array", [DURABLE_WIRE]],
    ["string", "not-an-object"],
    ["number", 42],
    ["v !== 1", { ...DURABLE_WIRE, v: 2 }],
    ["v is a string", { ...DURABLE_WIRE, v: "1" }],
    ["missing jti", { ...DURABLE_WIRE, jti: undefined }],
    ["empty jti", { ...DURABLE_WIRE, jti: "" }],
    ["non-integer iat", { ...DURABLE_WIRE, iat: 1.5 }],
    ["negative exp", { ...DURABLE_WIRE, exp: -1 }],
    ["nbf wrong type", { ...DURABLE_WIRE, nbf: "soon" }],
    ["bad kind", { ...DURABLE_WIRE, k: "forever" }],
    ["su not boolean", { ...DURABLE_WIRE, su: "false" }],
    ["principal missing id", { ...DURABLE_WIRE, p: { type: "user" } }],
    ["principal bad type", { ...DURABLE_WIRE, p: { type: "robot", id: "x" } }],
    ["agent bad type", { ...DURABLE_WIRE, ag: { id: "x", type: "martian" } }],
    ["agent object missing id", { ...DURABLE_WIRE, ag: { type: "ai_agent" } }],
    ["tool empty", { ...DURABLE_WIRE, t: "" }],
    ["scope not object", { ...DURABLE_WIRE, s: "everything" }],
    ["scope.idPattern wrong type", { ...DURABLE_WIRE, s: { idPattern: 7 } }],
    ["conditions not object", { ...DURABLE_WIRE, c: "nope" }],
    ["bad tier", { ...DURABLE_WIRE, r: "extreme" }],
    ["bad envelopeScope", { ...DURABLE_WIRE, es: "galactic" }],
    ["admin not boolean", { ...DURABLE_WIRE, ad: "yes" }],
    ["ephemeral missing ch", { ...EPHEMERAL_WIRE, ch: undefined }],
    ["durable carrying ch", { ...DURABLE_WIRE, ch: "sha256:x" }],
  ];

  for (const [label, input] of badInputs) {
    it(`returns null (no throw) for: ${label}`, () => {
      let result: GrantClaims | null = DURABLE_CLAIMS;
      expect(() => {
        result = parseWireClaims(input);
      }).not.toThrow();
      expect(result).toBeNull();
    });
  }
});

describe("parseJwsHeader — fail-closed header validation", () => {
  it("accepts the canonical header", () => {
    expect(
      parseJwsHeader({
        alg: "EdDSA",
        typ: "knotrust-grant+jws",
        kid: "abc123",
      }),
    ).toEqual({ alg: "EdDSA", typ: "knotrust-grant+jws", kid: "abc123" });
  });

  const badHeaders: Array<[string, unknown]> = [
    [
      "alg none (alg-confusion)",
      { alg: "none", typ: "knotrust-grant+jws", kid: "k" },
    ],
    ["alg HS256", { alg: "HS256", typ: "knotrust-grant+jws", kid: "k" }],
    ["wrong typ", { alg: "EdDSA", typ: "JWT", kid: "k" }],
    ["missing kid", { alg: "EdDSA", typ: "knotrust-grant+jws" }],
    ["empty kid", { alg: "EdDSA", typ: "knotrust-grant+jws", kid: "" }],
    [
      "crit present (RFC 7515 §4.1.11) — rejected regardless of value",
      { alg: "EdDSA", typ: "knotrust-grant+jws", kid: "k", crit: ["exp"] },
    ],
    ["null", null],
    ["array", []],
  ];

  for (const [label, input] of badHeaders) {
    it(`returns null (no throw) for header: ${label}`, () => {
      expect(() => parseJwsHeader(input)).not.toThrow();
      expect(parseJwsHeader(input)).toBeNull();
    });
  }
});
