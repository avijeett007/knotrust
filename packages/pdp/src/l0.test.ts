import type {
  CoveringGrant,
  DecisionRequest,
  PdpEvaluationContext,
  TierPolicy,
  ToolTierEntry,
} from "@knotrust/core";
import { L0ReasonCode, PrecedenceReasonCode } from "@knotrust/core";
import { describe, expect, it } from "vitest";
import { createL0Adapter } from "./l0.js";

// ---------------------------------------------------------------------------
// Fixture builders (mirrors precedence.test.ts's style/conventions —
// P0-E2-T5, ruling R18: "L0 unit tests must stay green untouched" refers to
// packages/core/src/l0-evaluator.test.ts/precedence.test.ts; THIS file is
// the new adapter-boundary wrapper's own suite).
// ---------------------------------------------------------------------------

const NOW_EPOCH_SECONDS = 1_800_000_000;
const ROUTINE_ACTION = "github.list_issues";
const SENSITIVE_ACTION = "github.create_issue";
const CRITICAL_ACTION = "stripe.create_refund";

function makeRequest(
  overrides: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01TEST00000000000000000000",
    timestamp: "2026-07-03T00:00:00.000Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: SENSITIVE_ACTION },
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

function makePolicy(
  tools: Record<string, ToolTierEntry>,
  unknownToolTier: TierPolicy["unknownToolTier"] = "sensitive",
): TierPolicy {
  return { tools, unknownToolTier };
}

const TIER_POLICY = makePolicy({
  [ROUTINE_ACTION]: { tier: "routine", source: "user" },
  [SENSITIVE_ACTION]: { tier: "sensitive", source: "user" },
  [CRITICAL_ACTION]: { tier: "critical", source: "user" },
});

function makeGrant(overrides: Partial<CoveringGrant> = {}): CoveringGrant {
  return {
    kind: "durable",
    tierCap: "sensitive",
    exp: NOW_EPOCH_SECONDS + 10_000,
    jti: "01GRANT0000000000000000000",
    ...overrides,
  };
}

function makeContext(
  overrides: Partial<PdpEvaluationContext> = {},
): PdpEvaluationContext {
  return {
    tierPolicy: TIER_POLICY,
    coveringGrants: [],
    nowEpochSeconds: NOW_EPOCH_SECONDS,
    ...overrides,
  };
}

describe("createL0Adapter — capabilities", () => {
  it("declares itself as the in-process 'l0' adapter, supporting requestable denial", () => {
    const adapter = createL0Adapter();
    expect(adapter.capabilities).toEqual({
      name: "l0",
      latencyClass: "in_process",
      supportsRequestableDenial: true,
    });
  });
});

describe("createL0Adapter — decide() wraps evaluatePrecedence (thin mapping, no re-implementation)", () => {
  it("routine tier -> allow, evaluatedBy 'L0'", async () => {
    const adapter = createL0Adapter();
    const request = makeRequest({ action: { name: ROUTINE_ACTION } });

    const decision = await adapter.decide(request, makeContext());

    expect(decision.outcome).toBe("allow");
    expect(decision.tier).toBe("routine");
    expect(decision.reasonCode).toBe(L0ReasonCode.RoutineDefaultAllow);
    expect(decision.evaluatedBy).toBe("L0");
    expect(decision.grantRef).toBeUndefined();
    expect(decision.wantsApproval).toBeUndefined();
  });

  it("sensitive tier + covering grant -> allow, grantRef carried through", async () => {
    const adapter = createL0Adapter();
    const request = makeRequest();
    const grant = makeGrant();

    const decision = await adapter.decide(
      request,
      makeContext({ coveringGrants: [grant] }),
    );

    expect(decision.outcome).toBe("allow");
    expect(decision.reasonCode).toBe(L0ReasonCode.GrantAllow);
    expect(decision.grantRef).toBe(grant.jti);
    expect(decision.evaluatedBy).toBe("L0");
  });

  it("sensitive tier, no grant -> deny with requestable guidance", async () => {
    const adapter = createL0Adapter();
    const request = makeRequest();

    const decision = await adapter.decide(request, makeContext());

    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
    expect(decision.requestable).toEqual({
      how: "knotrust grant --tool github.create_issue --server github-mcp",
    });
  });

  it("critical tier, no grant -> pending_approval, wantsApproval true", async () => {
    const adapter = createL0Adapter();
    const request = makeRequest({ action: { name: CRITICAL_ACTION } });

    const decision = await adapter.decide(request, makeContext());

    expect(decision.outcome).toBe("pending_approval");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantCritical);
    expect(decision.wantsApproval).toBe(true);
    expect(decision.evaluatedBy).toBe("L0");
  });

  it("passes the envelope through to the precedence engine (admin envelope deny wins)", async () => {
    const adapter = createL0Adapter();
    const request = makeRequest({ action: { name: ROUTINE_ACTION } });

    const decision = await adapter.decide(
      request,
      makeContext({
        envelope: { scope: "personal", denyTools: [ROUTINE_ACTION] },
      }),
    );

    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(PrecedenceReasonCode.EnvelopeDeny);
  });

  it("passes ctx.nowEpochSeconds through for grant temporal validity (expired grant does not cover)", async () => {
    const adapter = createL0Adapter();
    const request = makeRequest();
    const expiredGrant = makeGrant({ exp: NOW_EPOCH_SECONDS - 1 });

    const decision = await adapter.decide(
      request,
      makeContext({ coveringGrants: [expiredGrant] }),
    );

    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });

  it("never returns deferred_not_eligible (L0 does not decide channel eligibility)", async () => {
    const adapter = createL0Adapter();
    const request = makeRequest();

    const decision = await adapter.decide(request, makeContext());

    expect(decision.outcome).not.toBe("deferred_not_eligible");
  });
});
