/**
 * @knotrust/approval — `withApprovalRequestRegistry` (P0-E6-T3).
 */
import type { DecisionRequest } from "@knotrust/core";
import type { AuditSink } from "@knotrust/store";
import { describe, expect, it } from "vitest";
import type { ApprovalRequest } from "../../lifecycle.js";
import { createApprovalOrchestrator } from "../../lifecycle.js";
import { withApprovalRequestRegistry } from "./registry.js";

const NOW = 1_800_000_000;

function makeDecisionRequest(): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01REGISTRYREQ0000000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_reg1" },
    context: {
      agent: { id: "codex-cli", type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 100 },
    },
    surface: { kind: "stdio_proxy", instanceId: "px-reg-1", server: "stripe" },
  };
}

function makeFakeAudit(): AuditSink {
  let seq = 0;
  return {
    append(event) {
      seq += 1;
      return {
        seq,
        ts: new Date(NOW * 1000).toISOString(),
        prevHash: "0".repeat(64),
        hash: "0".repeat(64),
        ...event,
      };
    },
    flush() {},
    close() {},
    verify() {
      return { ok: true, events: seq };
    },
    onAppend() {
      // no-op — no test in this file subscribes; @knotrust/otel's subscriber
      // contract is covered in that package's own suite, not here.
      return () => {};
    },
  };
}

function makeOrchestrator() {
  return createApprovalOrchestrator({
    mintEphemeralGrant: async () => ({ token: "tok", jti: "jti-1" }),
    decide: async () => ({
      contractVersion: "1.0",
      requestId: "req-1",
      decisionId: "dec-1",
      outcome: "allow",
      tier: "critical",
      reasonCode: "grant_allow",
      cache: { hit: false },
      evaluatedBy: "grant",
      latencyMs: 0,
    }),
    audit: makeFakeAudit(),
    nowEpochSeconds: () => NOW,
    generateId: () => "REGID0001",
  });
}

function makeApprovalRequest(
  decisionRequest: DecisionRequest,
): ApprovalRequest {
  return {
    decisionId: "dec-1",
    requestId: decisionRequest.requestId,
    subject: decisionRequest.subject,
    agent: decisionRequest.context.agent,
    action: decisionRequest.action,
    resource: decisionRequest.resource,
    tier: "critical",
    eligibleChannels: ["block_and_wait"],
    decisionRequest,
  };
}

describe("withApprovalRequestRegistry", () => {
  it("records the ApprovalRequest passed to request(), retrievable by the minted id", async () => {
    const orchestrator = makeOrchestrator();
    const registry = withApprovalRequestRegistry(orchestrator);
    const decisionRequest = makeDecisionRequest();
    const approvalRequest = makeApprovalRequest(decisionRequest);

    const handle = await registry.orchestrator.request(approvalRequest);

    expect(registry.getApprovalRequest(handle.id)).toBe(approvalRequest);
  });

  it("returns undefined for an id never seen by this registry", () => {
    const orchestrator = makeOrchestrator();
    const registry = withApprovalRequestRegistry(orchestrator);
    expect(registry.getApprovalRequest("apr_never_seen")).toBeUndefined();
  });

  it("the wrapped orchestrator still delegates every other method to the real one (status/resolve/cancel/onResolved unaffected)", async () => {
    const orchestrator = makeOrchestrator();
    const registry = withApprovalRequestRegistry(orchestrator);
    const decisionRequest = makeDecisionRequest();
    const approvalRequest = makeApprovalRequest(decisionRequest);

    const handle = await registry.orchestrator.request(approvalRequest);
    expect(handle.state).toBe("pending");

    const status = await registry.orchestrator.status(handle.id);
    expect(status.state).toBe("pending");

    await registry.orchestrator.resolve(handle.id, "approved");
    const resolvedState = await registry.orchestrator.onResolved(handle.id);
    expect(resolvedState).toBe("approved");
  });

  it("a fail-closed-denied request() (e.g. audit failure) is still recorded — harmless, since nothing resolves against a terminal id", async () => {
    const throwingAudit: AuditSink = {
      append() {
        throw new Error("audit down");
      },
      flush() {},
      close() {},
      verify() {
        return { ok: true, events: 0 };
      },
      onAppend() {
        return () => {};
      },
    };
    const orchestrator = createApprovalOrchestrator({
      mintEphemeralGrant: async () => {
        throw new Error("must not be called");
      },
      decide: async () => {
        throw new Error("must not be called");
      },
      audit: throwingAudit,
      nowEpochSeconds: () => NOW,
      generateId: () => "REGID0002",
    });
    const registry = withApprovalRequestRegistry(orchestrator);
    const decisionRequest = makeDecisionRequest();
    const approvalRequest = makeApprovalRequest(decisionRequest);

    const handle = await registry.orchestrator.request(approvalRequest);
    expect(handle.state).toBe("denied"); // fail-closed on the very first audit append

    expect(registry.getApprovalRequest(handle.id)).toBe(approvalRequest);
  });
});
