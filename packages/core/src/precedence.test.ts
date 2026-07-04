import { describe, expect, it } from "vitest";
import type { DecisionRequest } from "./contract.js";
import type { CoveringGrant } from "./l0-evaluator.js";
import { L0ReasonCode } from "./l0-evaluator.js";
import type { AdminEnvelope, PrecedenceDecision } from "./precedence.js";
import { evaluatePrecedence, PrecedenceReasonCode } from "./precedence.js";
import type { Tier, TierPolicy, ToolTierEntry } from "./tier-policy.js";

// ---------------------------------------------------------------------------
// Fixture builders (mirrors l0-evaluator.test.ts's style/conventions)
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000;
const ACTION = "github.create_issue";
const CRITICAL_ACTION = "stripe.create_refund";

function makeRequest(
  overrides: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01TEST00000000000000000000",
    timestamp: "2026-07-03T00:00:00.000Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: ACTION },
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

function policyWithEntry(actionName: string, entry: ToolTierEntry): TierPolicy {
  return makePolicy({ [actionName]: entry });
}

function run(
  request: DecisionRequest,
  tierPolicy: TierPolicy,
  envelope: AdminEnvelope | undefined,
  coveringGrants: readonly CoveringGrant[],
): PrecedenceDecision {
  return evaluatePrecedence({
    request,
    tierPolicy,
    ...(envelope ? { envelope } : {}),
    coveringGrants,
    nowEpochSeconds: NOW,
  });
}

// ---------------------------------------------------------------------------
// Plan-mandated acceptance cases, by name (task brief §"Acceptance verification")
// ---------------------------------------------------------------------------

describe("acceptance: force-approval-over-grant", () => {
  it("admin envelope forceApprovalTiers: [critical] yields pending_approval even with a valid critical-cap grant, not allow", () => {
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const tierPolicy = policyWithEntry(CRITICAL_ACTION, {
      tier: "critical",
      source: "user",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      forceApprovalTiers: ["critical"],
    };
    const grant = makeGrant({ tierCap: "critical", jti: "01GRANT_CRIT" });

    const decision = run(request, tierPolicy, envelope, [grant]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: PrecedenceReasonCode.EnvelopeForceApproval,
      precedenceLayer: 1,
      wantsApproval: true,
    });
  });

  it("forceApprovalTools targets a specific tool regardless of tier", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "routine",
      source: "user",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      forceApprovalTools: [ACTION],
    };

    const decision = run(request, tierPolicy, envelope, []);

    expect(decision.outcome).toBe("pending_approval");
    expect(decision.reasonCode).toBe(
      PrecedenceReasonCode.EnvelopeForceApproval,
    );
    expect(decision.precedenceLayer).toBe(1);
  });
});

describe("acceptance: routine-cap-on-critical deny (self-escalation)", () => {
  it("a grant claiming tier cap routine on a critical tool yields deny (tier_cap_violation), not pending_approval", () => {
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const tierPolicy = policyWithEntry(CRITICAL_ACTION, {
      tier: "critical",
      source: "user",
    });
    const grant = makeGrant({ tierCap: "routine", jti: "01GRANT_SELF_ESC" });

    const decision = run(request, tierPolicy, undefined, [grant]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "deny",
      tier: "critical",
      reasonCode: PrecedenceReasonCode.TierCapViolation,
      precedenceLayer: 3,
    });
  });

  it("mirrors for a sensitive tool: a routine-capped grant is a self-escalation attempt, not a silent fall-through", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
    });
    const grant = makeGrant({ tierCap: "routine" });

    const decision = run(request, tierPolicy, undefined, [grant]);

    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(PrecedenceReasonCode.TierCapViolation);
    expect(decision.precedenceLayer).toBe(3);
  });

  it("when one grant is a self-escalation attempt but ANOTHER grant in the same list validly covers, the covering grant wins (allow)", () => {
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const tierPolicy = policyWithEntry(CRITICAL_ACTION, {
      tier: "critical",
      source: "user",
    });
    const insufficient = makeGrant({
      tierCap: "routine",
      jti: "01GRANT_INSUFFICIENT",
    });
    const covering = makeGrant({
      tierCap: "critical",
      jti: "01GRANT_COVERS",
    });

    const decision = run(request, tierPolicy, undefined, [
      insufficient,
      covering,
    ]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "allow",
      tier: "critical",
      reasonCode: L0ReasonCode.GrantAllow,
      precedenceLayer: 3,
      grantRef: "01GRANT_COVERS",
    });
  });
});

describe("acceptance: pack-clamp floor", () => {
  it("a pack entry assigning routine to a tool the admin envelope floors at sensitive resolves as sensitive, clamped for audit", () => {
    const request = makeRequest({
      action: { name: "community.pack_tool" },
      surface: {
        kind: "stdio_proxy",
        instanceId: "px_test",
        server: "community-mcp",
      },
    });
    const tierPolicy = policyWithEntry("community.pack_tool", {
      tier: "routine",
      source: "pack",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      tierFloors: { "community.pack_tool": "sensitive" },
    };

    const decision = run(request, tierPolicy, envelope, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: L0ReasonCode.NoGrantSensitive,
      precedenceLayer: 4,
      clamped: { from: "routine", to: "sensitive" },
      requestable: {
        how: "knotrust grant --tool community.pack_tool --server community-mcp",
      },
    });
  });

  it("a floor that is LOWER than the resolved tier is a no-op (never lowers, only raises)", () => {
    const request = makeRequest({ action: { name: "community.pack_tool" } });
    const tierPolicy = policyWithEntry("community.pack_tool", {
      tier: "critical",
      source: "pack",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      tierFloors: { "community.pack_tool": "sensitive" },
    };

    const decision = run(request, tierPolicy, envelope, []);

    expect(decision.tier).toBe("critical");
    expect(decision.clamped).toBeUndefined();
  });

  it("user-source entries are NEVER clamped in P0, even under a floor (single-user: the user IS the admin)", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "routine",
      source: "user",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      tierFloors: { [ACTION]: "critical" },
    };

    const decision = run(request, tierPolicy, envelope, []);

    expect(decision.tier).toBe("routine");
    expect(decision.clamped).toBeUndefined();
    expect(decision.outcome).toBe("allow");
    expect(decision.reasonCode).toBe(L0ReasonCode.RoutineDefaultAllow);
  });

  it("an unlisted tool's default-resolved tier is also floored (floor applies whenever the winning source isn't 'user')", () => {
    const request = makeRequest({ action: { name: "unlisted.tool" } });
    const tierPolicy = makePolicy({}, "sensitive");
    const envelope: AdminEnvelope = {
      scope: "personal",
      tierFloors: { "unlisted.tool": "critical" },
    };

    const decision = run(request, tierPolicy, envelope, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: L0ReasonCode.NoGrantCritical,
      precedenceLayer: 4,
      wantsApproval: true,
      clamped: { from: "sensitive", to: "critical" },
    });
  });
});

// ---------------------------------------------------------------------------
// Layer 1 — admin envelope (deny / force approval), independent tests
// ---------------------------------------------------------------------------

describe("layer 1 — admin envelope", () => {
  it("denyTools wins even over an otherwise-unconditional routine allow", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "routine",
      source: "user",
    });
    const envelope: AdminEnvelope = { scope: "personal", denyTools: [ACTION] };

    const decision = run(request, tierPolicy, envelope, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "deny",
      tier: "routine",
      reasonCode: PrecedenceReasonCode.EnvelopeDeny,
      precedenceLayer: 1,
    });
  });

  it("an unrelated denyTools entry has no effect", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "routine",
      source: "user",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      denyTools: ["some.other.tool"],
    };

    const decision = run(request, tierPolicy, envelope, []);

    expect(decision.outcome).toBe("allow");
    expect(decision.precedenceLayer).toBe(4);
  });

  it("undefined envelope = empty envelope; every layer still runs and resolves via the tier default", () => {
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const tierPolicy = policyWithEntry(CRITICAL_ACTION, {
      tier: "critical",
      source: "user",
    });

    const decision = run(request, tierPolicy, undefined, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: L0ReasonCode.NoGrantCritical,
      precedenceLayer: 4,
      wantsApproval: true,
    });
  });
});

// ---------------------------------------------------------------------------
// Layer 2 — explicit config deny
// ---------------------------------------------------------------------------

describe("layer 2 — explicit config deny", () => {
  it("explicitDeny: true on a source: user entry wins over a valid covering grant", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
      explicitDeny: true,
    });
    const grant = makeGrant({ tierCap: "sensitive" });

    const decision = run(request, tierPolicy, undefined, [grant]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: PrecedenceReasonCode.ExplicitConfigDeny,
      precedenceLayer: 2,
    });
  });

  it("explicitDeny: true on a PACK entry is NOT honored (only source: user), falls through to the tier default", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "pack",
      explicitDeny: true,
    });

    const decision = run(request, tierPolicy, undefined, []);

    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
    expect(decision.precedenceLayer).toBe(4);
  });

  it("explicitDeny: true on an ANNOTATION entry is NOT honored (only source: user)", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "annotation",
      explicitDeny: true,
    });

    const decision = run(request, tierPolicy, undefined, []);

    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });
});

// ---------------------------------------------------------------------------
// Layer 3 — grant evaluation: envelope grantCeiling asymmetry (R13)
// ---------------------------------------------------------------------------

describe("layer 3 — grant_exceeds_envelope vs explicit_config_allow fall-through (R13 asymmetry)", () => {
  it("a grant whose native cap covers but is clamped below by grantCeiling, with NO explicit config allow available, is the sole basis for allow → decisive deny grant_exceeds_envelope", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      grantCeiling: "routine",
    };
    const grant = makeGrant({ tierCap: "sensitive", jti: "01GRANT_CEILING" });

    const decision = run(request, tierPolicy, envelope, [grant]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: PrecedenceReasonCode.GrantExceedsEnvelope,
      precedenceLayer: 3,
    });
  });

  it("the SAME ceiling-clamp scenario, but an explicit_config_allow IS independently available at layer 4 → falls through and allows (does NOT decisively deny)", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
      explicitAllow: true,
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      grantCeiling: "routine",
    };
    const grant = makeGrant({ tierCap: "sensitive", jti: "01GRANT_CEILING" });

    const decision = run(request, tierPolicy, envelope, [grant]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.ExplicitConfigAllow,
      precedenceLayer: 4,
    });
  });

  it("a grant capped exactly at the envelope ceiling still covers (ceiling is inclusive, not exclusive)", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      grantCeiling: "sensitive",
    };
    const grant = makeGrant({ tierCap: "sensitive", jti: "01GRANT_AT_CEIL" });

    const decision = run(request, tierPolicy, envelope, [grant]);

    expect(decision.outcome).toBe("allow");
    expect(decision.reasonCode).toBe(L0ReasonCode.GrantAllow);
    expect(decision.grantRef).toBe("01GRANT_AT_CEIL");
  });

  it("no grantCeiling set at all → no clamping, native cap decides", () => {
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const tierPolicy = policyWithEntry(CRITICAL_ACTION, {
      tier: "critical",
      source: "user",
    });
    const grant = makeGrant({ tierCap: "critical", jti: "01GRANT_NO_CEIL" });

    const decision = run(request, tierPolicy, undefined, [grant]);

    expect(decision.outcome).toBe("allow");
    expect(decision.reasonCode).toBe(L0ReasonCode.GrantAllow);
  });
});

// ---------------------------------------------------------------------------
// Layer 3 — R15 ratification locks (review follow-up, P0-E2-T3)
// ---------------------------------------------------------------------------

describe("layer 3 — R15: grant_exceeds_envelope at critical tier is categorically unreachable (no explicit-allow escape hatch)", () => {
  it("a critical tool with a genuinely-covering (tierCap: critical) grant, clamped by grantCeiling: sensitive, denies grant_exceeds_envelope — never pending_approval", () => {
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const tierPolicy = policyWithEntry(CRITICAL_ACTION, {
      tier: "critical",
      source: "user",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      grantCeiling: "sensitive",
    };
    const grant = makeGrant({
      tierCap: "critical",
      jti: "01GRANT_CRIT_CEIL_CLAMPED",
    });

    const decision = run(request, tierPolicy, envelope, [grant]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "deny",
      tier: "critical",
      reasonCode: PrecedenceReasonCode.GrantExceedsEnvelope,
      precedenceLayer: 3,
    });
  });

  it("contrast: the SAME envelope with NO grant at all falls through to layer 4 and resolves pending_approval/no_grant_critical — proving the asymmetry is deliberate, not a missing escape hatch", () => {
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const tierPolicy = policyWithEntry(CRITICAL_ACTION, {
      tier: "critical",
      source: "user",
    });
    const envelope: AdminEnvelope = {
      scope: "personal",
      grantCeiling: "sensitive",
    };

    const decision = run(request, tierPolicy, envelope, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: L0ReasonCode.NoGrantCritical,
      precedenceLayer: 4,
      wantsApproval: true,
    });
  });
});

describe("layer 3 — R15: tier_cap_violation suppresses an available explicit_config_allow (loud fail-closed)", () => {
  it("a sensitive tool with explicitAllow: true PLUS a routine-capped (self-escalating) grant still denies tier_cap_violation — the anomalous grant is surfaced, not papered over by config", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
      explicitAllow: true,
    });
    const grant = makeGrant({
      tierCap: "routine",
      jti: "01GRANT_SELF_ESC_OVER_ALLOW",
    });

    const decision = run(request, tierPolicy, undefined, [grant]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: PrecedenceReasonCode.TierCapViolation,
      precedenceLayer: 3,
    });
  });

  it("contrast: the SAME explicitAllow: true config with NO grant at all allows via explicit_config_allow — proving the grant's mere presence, not the config, flips the outcome", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
      explicitAllow: true,
    });

    const decision = run(request, tierPolicy, undefined, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.ExplicitConfigAllow,
      precedenceLayer: 4,
    });
  });
});

// ---------------------------------------------------------------------------
// Layer 3 — routine tier never consults grants (mirrors L0 semantics)
// ---------------------------------------------------------------------------

describe("layer 3 — routine tier ignores grants entirely, even a self-escalation-shaped one", () => {
  it("a routine-tier tool allows regardless of grant contents (no tier_cap_violation possible at routine)", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "routine",
      source: "user",
    });
    const grant = makeGrant({ tierCap: "routine" });

    const decision = run(request, tierPolicy, undefined, [grant]);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "allow",
      tier: "routine",
      reasonCode: L0ReasonCode.RoutineDefaultAllow,
      precedenceLayer: 4,
    });
  });
});

// ---------------------------------------------------------------------------
// Layer 4 — tier default (delegates to E2-T2's evaluateTierDefault)
// ---------------------------------------------------------------------------

describe("layer 4 — tier default delegation", () => {
  it("sensitive, no grant, no explicit allow → deny (no_grant_sensitive) with requestable guidance", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
    });

    const decision = run(request, tierPolicy, undefined, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "deny",
      tier: "sensitive",
      reasonCode: L0ReasonCode.NoGrantSensitive,
      precedenceLayer: 4,
      requestable: {
        how: "knotrust grant --tool github.create_issue --server github-mcp",
      },
    });
  });

  it("sensitive, no grant, explicit config allow → allow (explicit_config_allow)", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
      explicitAllow: true,
    });

    const decision = run(request, tierPolicy, undefined, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "allow",
      tier: "sensitive",
      reasonCode: L0ReasonCode.ExplicitConfigAllow,
      precedenceLayer: 4,
    });
  });

  it("critical, no grant → pending_approval (no_grant_critical)", () => {
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });
    const tierPolicy = policyWithEntry(CRITICAL_ACTION, {
      tier: "critical",
      source: "user",
    });

    const decision = run(request, tierPolicy, undefined, []);

    expect(decision).toEqual<PrecedenceDecision>({
      outcome: "pending_approval",
      tier: "critical",
      reasonCode: L0ReasonCode.NoGrantCritical,
      precedenceLayer: 4,
      wantsApproval: true,
    });
  });

  it("a temporally-expired grant is treated as absent, falling all the way through to the tier default", () => {
    const request = makeRequest();
    const tierPolicy = policyWithEntry(ACTION, {
      tier: "sensitive",
      source: "user",
    });
    const expired = makeGrant({ tierCap: "sensitive", exp: NOW - 1 });

    const decision = run(request, tierPolicy, undefined, [expired]);

    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
    expect(decision.precedenceLayer).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// Purity / determinism (mirrors l0-evaluator.test.ts's own check)
// ---------------------------------------------------------------------------

describe("purity — determinism", () => {
  it("running the full evaluation table twice produces deep-equal results", () => {
    const table: Array<() => PrecedenceDecision> = [
      () =>
        run(
          makeRequest(),
          policyWithEntry(ACTION, { tier: "routine", source: "user" }),
          undefined,
          [],
        ),
      () =>
        run(
          makeRequest({ action: { name: CRITICAL_ACTION } }),
          policyWithEntry(CRITICAL_ACTION, {
            tier: "critical",
            source: "user",
          }),
          { scope: "personal", forceApprovalTiers: ["critical"] },
          [makeGrant({ tierCap: "critical" })],
        ),
      () =>
        run(
          makeRequest(),
          policyWithEntry(ACTION, { tier: "sensitive", source: "user" }),
          { scope: "personal", grantCeiling: "routine" },
          [makeGrant({ tierCap: "sensitive" })],
        ),
    ];

    const run1 = table.map((f) => f());
    const run2 = table.map((f) => f());
    expect(run2).toEqual(run1);
  });

  it("evaluatePrecedence does not mutate its coveringGrants or envelope input", () => {
    const grants = Object.freeze([makeGrant({ tierCap: "sensitive" })]);
    const envelope: Readonly<AdminEnvelope> = Object.freeze({
      scope: "personal",
      denyTools: Object.freeze(["something.else"]) as readonly string[],
    });

    expect(() =>
      run(
        makeRequest(),
        policyWithEntry(ACTION, { tier: "sensitive", source: "user" }),
        envelope,
        grants,
      ),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Tier ranking sanity (routine < sensitive < critical) reused for envelope math
// ---------------------------------------------------------------------------

describe("tier ordering sanity", () => {
  const tiers: Tier[] = ["routine", "sensitive", "critical"];

  it.each(
    tiers,
  )("%s tier with no policy entry falls back to unknownToolTier", (unknownToolTier) => {
    if (unknownToolTier === "routine") return; // unknownToolTier can never be routine (type-level guarantee)
    const request = makeRequest({ action: { name: "totally.unlisted" } });
    const tierPolicy = makePolicy({}, unknownToolTier);

    const decision = run(request, tierPolicy, undefined, []);

    expect(decision.tier).toBe(unknownToolTier);
  });
});
