import { describe, expect, it } from "vitest";
import type { DecisionRequest, UntrustedToolAnnotations } from "./contract.js";
import {
  type CoveringGrant,
  evaluateTierDefault,
  type L0Decision,
  L0ReasonCode,
  resolveTier,
} from "./l0-evaluator.js";
import type { Tier, TierPolicy, ToolTierEntry } from "./tier-policy.js";

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

/** A fixed clock for every test — the evaluator must never read the real clock. */
const NOW = 1_800_000_000;

function makeRequest(
  overrides: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01TEST00000000000000000000",
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

function makeGrant(overrides: Partial<CoveringGrant> = {}): CoveringGrant {
  return {
    kind: "durable",
    tierCap: "sensitive",
    exp: NOW + 1000,
    jti: "01GRANT0000000000000000000",
    ...overrides,
  };
}

function makePolicy(
  tools: Record<string, ToolTierEntry>,
  unknownToolTier: TierPolicy["unknownToolTier"] = "sensitive",
): TierPolicy {
  return { tools, unknownToolTier };
}

const ACTION = "github.create_issue";

/** Builds a policy with exactly one entry for ACTION at the given tier/source. */
function policyWithEntry(
  tier: Tier,
  source: ToolTierEntry["source"] = "user",
  explicitAllow?: boolean,
): TierPolicy {
  const entry: ToolTierEntry =
    explicitAllow === undefined
      ? { tier, source }
      : { tier, source, explicitAllow };
  return makePolicy({ [ACTION]: entry });
}

// ---------------------------------------------------------------------------
// resolveTier — config precedence + annotation seeding (brief §C5, ruling 2/4)
// ---------------------------------------------------------------------------

describe("resolveTier", () => {
  it("uses the explicit config entry (source: user) verbatim, ignoring unknownToolTier", () => {
    const policy = policyWithEntry("routine", "user");
    expect(resolveTier(ACTION, policy)).toEqual({
      tier: "routine",
      source: "user",
    });
  });

  it("uses a pack entry verbatim", () => {
    const policy = policyWithEntry("critical", "pack");
    expect(resolveTier(ACTION, policy)).toEqual({
      tier: "critical",
      source: "pack",
    });
  });

  it("uses a previously-recorded annotation-seeded entry verbatim (generated config, E5-T2's future output)", () => {
    const policy = policyWithEntry("sensitive", "annotation");
    expect(resolveTier(ACTION, policy)).toEqual({
      tier: "sensitive",
      source: "annotation",
    });
  });

  it("an existing config entry is never overridden by a live toolAnnotations argument, even a destructive one", () => {
    const policy = policyWithEntry("routine", "user");
    const annotations: UntrustedToolAnnotations = {
      trusted: false,
      source: "server_advertised",
      destructiveHint: true,
    };
    expect(resolveTier(ACTION, policy, annotations)).toEqual({
      tier: "routine",
      source: "user",
    });
  });

  it("falls back to unknownToolTier (sensitive) with source 'default' when no entry and no annotations", () => {
    const policy = makePolicy({}, "sensitive");
    expect(resolveTier("unlisted.tool", policy)).toEqual({
      tier: "sensitive",
      source: "default",
    });
  });

  it("falls back to unknownToolTier (critical) with source 'default' when no entry and no annotations", () => {
    const policy = makePolicy({}, "critical");
    expect(resolveTier("unlisted.tool", policy)).toEqual({
      tier: "critical",
      source: "default",
    });
  });

  it("a destructive-looking annotation raises an unlisted tool from sensitive to critical, source 'annotation'", () => {
    const policy = makePolicy({}, "sensitive");
    const annotations: UntrustedToolAnnotations = {
      trusted: false,
      source: "server_advertised",
      destructiveHint: true,
    };
    expect(resolveTier("unlisted.tool", policy, annotations)).toEqual({
      tier: "critical",
      source: "annotation",
    });
  });

  it("a non-destructive annotation never raises an unlisted tool, source stays 'default'", () => {
    const policy = makePolicy({}, "sensitive");
    const annotations: UntrustedToolAnnotations = {
      trusted: false,
      source: "server_advertised",
      destructiveHint: false,
    };
    expect(resolveTier("unlisted.tool", policy, annotations)).toEqual({
      tier: "sensitive",
      source: "default",
    });
  });

  it("a 'safe-looking' annotation (readOnlyHint true) never lowers an unlisted tool below unknownToolTier", () => {
    const policy = makePolicy({}, "sensitive");
    const annotations: UntrustedToolAnnotations = {
      trusted: false,
      source: "server_advertised",
      readOnlyHint: true,
      idempotentHint: true,
      destructiveHint: false,
    };
    expect(resolveTier("unlisted.tool", policy, annotations)).toEqual({
      tier: "sensitive",
      source: "default",
    });
  });

  it("a destructive annotation has nowhere to raise when unknownToolTier is already critical — source stays 'default'", () => {
    const policy = makePolicy({}, "critical");
    const annotations: UntrustedToolAnnotations = {
      trusted: false,
      source: "server_advertised",
      destructiveHint: true,
    };
    expect(resolveTier("unlisted.tool", policy, annotations)).toEqual({
      tier: "critical",
      source: "default",
    });
  });
});

// ---------------------------------------------------------------------------
// evaluateTierDefault — routine tier: always allow, grants irrelevant
// ---------------------------------------------------------------------------

describe("evaluateTierDefault — routine tier", () => {
  const cases: Array<[string, CoveringGrant[]]> = [
    ["no grants", []],
    [
      "grants present but irrelevant (routine never consults them)",
      [makeGrant({ tierCap: "critical" })],
    ],
    [
      "even an expired grant doesn't matter for routine",
      [makeGrant({ tierCap: "critical", exp: NOW - 1000 })],
    ],
  ];

  it.each(
    cases,
  )("%s → allow (routine_default_allow)", (_name, coveringGrants) => {
    const decision = evaluateTierDefault({
      request: makeRequest(),
      tierPolicy: policyWithEntry("routine", "user"),
      coveringGrants,
      nowEpochSeconds: NOW,
    });

    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "routine",
      reasonCode: L0ReasonCode.RoutineDefaultAllow,
    });
  });
});

// ---------------------------------------------------------------------------
// evaluateTierDefault — sensitive tier
// ---------------------------------------------------------------------------

describe("evaluateTierDefault — sensitive tier", () => {
  function run(
    entrySource: ToolTierEntry["source"],
    explicitAllow: boolean | undefined,
    coveringGrants: CoveringGrant[],
  ): L0Decision {
    return evaluateTierDefault({
      request: makeRequest(),
      tierPolicy: policyWithEntry("sensitive", entrySource, explicitAllow),
      coveringGrants,
      nowEpochSeconds: NOW,
    });
  }

  it("no grant, no explicitAllow → deny (no_grant_sensitive) with requestable guidance", () => {
    const decision = run("user", false, []);
    expect(decision).toEqual<L0Decision>({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: L0ReasonCode.NoGrantSensitive,
      requestable: {
        how: "knotrust grant --tool github.create_issue --server github-mcp",
      },
    });
  });

  it("no grant, explicitAllow true on a user entry → allow (explicit_config_allow)", () => {
    const decision = run("user", true, []);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.ExplicitConfigAllow,
    });
  });

  it("no grant, explicitAllow true on a PACK entry → still deny (explicitAllow only honored for source: user)", () => {
    const decision = run("pack", true, []);
    expect(decision).toEqual<L0Decision>({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: L0ReasonCode.NoGrantSensitive,
      requestable: {
        how: "knotrust grant --tool github.create_issue --server github-mcp",
      },
    });
  });

  it("no grant, explicitAllow true on an ANNOTATION entry → still deny (not source: user)", () => {
    const decision = run("annotation", true, []);
    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });

  it("a valid durable grant capped exactly at sensitive → allow (grant_allow), grantRef set", () => {
    const grant = makeGrant({ tierCap: "sensitive", jti: "01GRANT_SENS" });
    const decision = run("user", false, [grant]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_SENS",
    });
  });

  it("a valid EPHEMERAL grant capped exactly at sensitive covers like a durable one → allow (grant_allow), grantRef set (P0-E2-T2 review follow-up)", () => {
    const grant = makeGrant({
      kind: "ephemeral",
      tierCap: "sensitive",
      jti: "01GRANT_EPHEMERAL_SENS",
    });
    const decision = run("user", false, [grant]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_EPHEMERAL_SENS",
    });
  });

  it("a valid grant capped at critical also covers sensitive (higher cap covers) → allow (grant_allow)", () => {
    const grant = makeGrant({ tierCap: "critical", jti: "01GRANT_CRIT" });
    const decision = run("user", false, [grant]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_CRIT",
    });
  });

  it("a grant capped at routine does NOT cover sensitive → deny (no_grant_sensitive)", () => {
    const grant = makeGrant({ tierCap: "routine" });
    const decision = run("user", false, [grant]);
    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });

  it("an expired grant (exp in the past) is treated as absent → deny (no_grant_sensitive)", () => {
    const grant = makeGrant({ tierCap: "sensitive", exp: NOW - 1 });
    const decision = run("user", false, [grant]);
    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });

  it("a grant expiring exactly at now (exp === now) is treated as expired (exp is exclusive)", () => {
    const grant = makeGrant({ tierCap: "sensitive", exp: NOW });
    const decision = run("user", false, [grant]);
    expect(decision.outcome).toBe("deny");
  });

  it("a not-yet-valid grant (nbf in the future) is treated as absent → deny (no_grant_sensitive)", () => {
    const grant = makeGrant({
      tierCap: "sensitive",
      nbf: NOW + 1,
      exp: NOW + 1000,
    });
    const decision = run("user", false, [grant]);
    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });

  it("a grant valid exactly at its nbf (nbf === now) is treated as valid (nbf is inclusive)", () => {
    const grant = makeGrant({
      tierCap: "sensitive",
      nbf: NOW,
      exp: NOW + 1000,
      jti: "01GRANT_NBF_NOW",
    });
    const decision = run("user", false, [grant]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_NBF_NOW",
    });
  });

  it("an expired grant still falls through to explicitAllow when present → allow (explicit_config_allow)", () => {
    const grant = makeGrant({ tierCap: "sensitive", exp: NOW - 1 });
    const decision = run("user", true, [grant]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.ExplicitConfigAllow,
    });
  });

  it("picks the first valid covering grant when one candidate is expired and another is valid", () => {
    const expired = makeGrant({
      tierCap: "sensitive",
      exp: NOW - 1,
      jti: "01GRANT_EXPIRED",
    });
    const valid = makeGrant({ tierCap: "sensitive", jti: "01GRANT_VALID" });
    const decision = run("user", false, [expired, valid]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_VALID",
    });
  });
});

// ---------------------------------------------------------------------------
// evaluateTierDefault — critical tier
// ---------------------------------------------------------------------------

describe("evaluateTierDefault — critical tier", () => {
  function run(
    coveringGrants: CoveringGrant[],
    entrySource: ToolTierEntry["source"] = "user",
    explicitAllow?: boolean,
  ): L0Decision {
    return evaluateTierDefault({
      request: makeRequest(),
      tierPolicy: policyWithEntry("critical", entrySource, explicitAllow),
      coveringGrants,
      nowEpochSeconds: NOW,
    });
  }

  it("no grant → pending_approval (no_grant_critical), wantsApproval: true", () => {
    const decision = run([]);
    expect(decision).toEqual<L0Decision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: L0ReasonCode.NoGrantCritical,
      wantsApproval: true,
    });
  });

  it("a valid grant capped exactly at critical → allow (grant_allow), grantRef set", () => {
    const grant = makeGrant({ tierCap: "critical", jti: "01GRANT_CRIT_OK" });
    const decision = run([grant]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "critical",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_CRIT_OK",
    });
  });

  it("a valid EPHEMERAL grant with tierCap 'critical' covers a critical tool → allow (grant_allow), grantRef set (P0-E2-T2 review follow-up)", () => {
    const grant = makeGrant({
      kind: "ephemeral",
      tierCap: "critical",
      jti: "01GRANT_EPHEMERAL_CRIT",
    });
    const decision = run([grant]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "critical",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_EPHEMERAL_CRIT",
    });
  });

  it("a valid grant capped at sensitive does NOT cover critical (treated as non-covering, not a violation here) → pending_approval", () => {
    const grant = makeGrant({ tierCap: "sensitive" });
    const decision = run([grant]);
    expect(decision).toEqual<L0Decision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: L0ReasonCode.NoGrantCritical,
      wantsApproval: true,
    });
  });

  it("an expired critical-capped grant is treated as absent → pending_approval", () => {
    const grant = makeGrant({ tierCap: "critical", exp: NOW - 1 });
    const decision = run([grant]);
    expect(decision.outcome).toBe("pending_approval");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantCritical);
  });

  it("a not-yet-valid critical-capped grant (nbf future) is treated as absent → pending_approval", () => {
    const grant = makeGrant({
      tierCap: "critical",
      nbf: NOW + 1,
      exp: NOW + 1000,
    });
    const decision = run([grant]);
    expect(decision.outcome).toBe("pending_approval");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantCritical);
  });

  it("explicitAllow on a critical user entry does NOT allow (explicitAllow only applies to sensitive tier)", () => {
    const decision = run([], "user", true);
    expect(decision).toEqual<L0Decision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: L0ReasonCode.NoGrantCritical,
      wantsApproval: true,
    });
  });

  it("picks the first valid critical-capped grant among a mix of insufficient/expired/valid candidates", () => {
    const insufficient = makeGrant({
      tierCap: "sensitive",
      jti: "01GRANT_INSUFFICIENT",
    });
    const expired = makeGrant({
      tierCap: "critical",
      exp: NOW - 1,
      jti: "01GRANT_EXPIRED",
    });
    const valid = makeGrant({ tierCap: "critical", jti: "01GRANT_VALID" });
    const decision = run([insufficient, expired, valid]);
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "critical",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_VALID",
    });
  });
});

// ---------------------------------------------------------------------------
// evaluateTierDefault — unknown/unlisted tool integration (resolveTier composed
// with the full grant/explicitAllow decision, brief §C5)
// ---------------------------------------------------------------------------

describe("evaluateTierDefault — unknown tool", () => {
  const unknownRequest = makeRequest({
    action: { name: "some.unlisted.tool" },
  });

  it("unknownToolTier sensitive, no grant, no annotations → deny (no_grant_sensitive) referencing the real action name", () => {
    const decision = evaluateTierDefault({
      request: unknownRequest,
      tierPolicy: makePolicy({}, "sensitive"),
      coveringGrants: [],
      nowEpochSeconds: NOW,
    });
    expect(decision).toEqual<L0Decision>({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: L0ReasonCode.NoGrantSensitive,
      requestable: {
        how: "knotrust grant --tool some.unlisted.tool --server github-mcp",
      },
    });
  });

  it("unknownToolTier critical, no grant → pending_approval (no_grant_critical)", () => {
    const decision = evaluateTierDefault({
      request: unknownRequest,
      tierPolicy: makePolicy({}, "critical"),
      coveringGrants: [],
      nowEpochSeconds: NOW,
    });
    expect(decision).toEqual<L0Decision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: L0ReasonCode.NoGrantCritical,
      wantsApproval: true,
    });
  });

  it("unknownToolTier sensitive + destructiveHint annotation raises to critical → pending_approval when no grant covers", () => {
    const request = {
      ...unknownRequest,
      toolAnnotations: {
        trusted: false as const,
        source: "server_advertised" as const,
        destructiveHint: true,
      },
    };
    const decision = evaluateTierDefault({
      request,
      tierPolicy: makePolicy({}, "sensitive"),
      coveringGrants: [],
      nowEpochSeconds: NOW,
    });
    expect(decision.tier).toBe("critical");
    expect(decision.outcome).toBe("pending_approval");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantCritical);
  });

  it("unknownToolTier sensitive, a covering grant still allows an unlisted tool → allow (grant_allow)", () => {
    const grant = makeGrant({
      tierCap: "sensitive",
      jti: "01GRANT_UNKNOWN_OK",
    });
    const decision = evaluateTierDefault({
      request: unknownRequest,
      tierPolicy: makePolicy({}, "sensitive"),
      coveringGrants: [grant],
      nowEpochSeconds: NOW,
    });
    expect(decision).toEqual<L0Decision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.GrantAllow,
      grantRef: "01GRANT_UNKNOWN_OK",
    });
  });
});

// ---------------------------------------------------------------------------
// requestable.how — exact CLI invocation template (ruling 5)
// ---------------------------------------------------------------------------

describe("requestable.how format", () => {
  it("uses surface.server when present", () => {
    const request = makeRequest({
      action: { name: "stripe.create_refund" },
      surface: {
        kind: "stdio_proxy",
        instanceId: "px_1",
        server: "stripe-mcp",
      },
    });
    const decision = evaluateTierDefault({
      request,
      tierPolicy: makePolicy({
        "stripe.create_refund": { tier: "sensitive", source: "user" },
      }),
      coveringGrants: [],
      nowEpochSeconds: NOW,
    });
    expect(decision.requestable).toEqual({
      how: "knotrust grant --tool stripe.create_refund --server stripe-mcp",
    });
  });

  it("falls back to the literal placeholder '<server>' when surface.server is absent", () => {
    const request = makeRequest({
      action: { name: "filesystem.read_file" },
      surface: { kind: "sdk", instanceId: "sdk_1" },
    });
    const decision = evaluateTierDefault({
      request,
      tierPolicy: makePolicy({
        "filesystem.read_file": { tier: "sensitive", source: "user" },
      }),
      coveringGrants: [],
      nowEpochSeconds: NOW,
    });
    expect(decision.requestable).toEqual({
      how: "knotrust grant --tool filesystem.read_file --server <server>",
    });
  });
});

// ---------------------------------------------------------------------------
// Purity / determinism (acceptance criterion, ruling 6)
// ---------------------------------------------------------------------------

describe("purity — determinism", () => {
  it("running the full evaluation table twice produces deep-equal results (no ambient clock, no randomness)", () => {
    const table: Array<() => L0Decision> = [
      () =>
        evaluateTierDefault({
          request: makeRequest(),
          tierPolicy: policyWithEntry("routine", "user"),
          coveringGrants: [],
          nowEpochSeconds: NOW,
        }),
      () =>
        evaluateTierDefault({
          request: makeRequest(),
          tierPolicy: policyWithEntry("sensitive", "user", false),
          coveringGrants: [makeGrant({ tierCap: "sensitive" })],
          nowEpochSeconds: NOW,
        }),
      () =>
        evaluateTierDefault({
          request: makeRequest(),
          tierPolicy: policyWithEntry("critical", "user"),
          coveringGrants: [],
          nowEpochSeconds: NOW,
        }),
      () =>
        evaluateTierDefault({
          request: makeRequest({ action: { name: "unlisted" } }),
          tierPolicy: makePolicy({}, "sensitive"),
          coveringGrants: [],
          nowEpochSeconds: NOW,
        }),
    ];

    const run1 = table.map((f) => f());
    const run2 = table.map((f) => f());
    expect(run2).toEqual(run1);
  });

  it("evaluateTierDefault does not mutate its coveringGrants input", () => {
    const grants = [makeGrant({ tierCap: "sensitive" })];
    const frozen = Object.freeze([...grants]);
    expect(() =>
      evaluateTierDefault({
        request: makeRequest(),
        tierPolicy: policyWithEntry("sensitive", "user", false),
        coveringGrants: frozen,
        nowEpochSeconds: NOW,
      }),
    ).not.toThrow();
  });
});
