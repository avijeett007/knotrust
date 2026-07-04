/**
 * @knotrust/pdp — the built-in L0 adapter (P0-E2-T5, ruling R18).
 *
 * "Refactor L0 to implement the `PdpAdapter` interface" means exactly this
 * file: a THIN wrapper around `@knotrust/core`'s `evaluatePrecedence`
 * (P0-E2-T2's tier evaluator, composed under P0-E2-T3's precedence engine).
 * It does not move, re-implement, or duplicate any evaluator/precedence
 * logic — `packages/core/src/l0-evaluator.ts` and
 * `packages/core/src/precedence.ts` are untouched by this task, and their
 * own unit test suites (`l0-evaluator.test.ts`, `precedence.test.ts`) stay
 * green, unmodified (P0-E2-T5 acceptance).
 *
 * `decide()` maps `evaluatePrecedence`'s `PrecedenceDecision` (core's
 * internal shape, with `precedenceLayer`/`clamped` audit detail that has no
 * equivalent in any other adapter) onto the adapter-boundary `PdpDecision`
 * shape (`@knotrust/core`'s `pdp-port.ts`) — dropping the L0-specific audit
 * fields, which stay internal to L0's own evaluation (they are not part of
 * what ANY adapter, including a future Cedar/AuthZEN/OPA one, is expected to
 * report through this uniform boundary).
 */

import {
  evaluatePrecedence,
  type PdpAdapter,
  type PdpDecision,
  type PrecedenceDecision,
} from "@knotrust/core";

function toPdpDecision(decision: PrecedenceDecision): PdpDecision {
  return {
    outcome: decision.outcome,
    tier: decision.tier,
    reasonCode: decision.reasonCode,
    evaluatedBy: "L0",
    ...(decision.requestable !== undefined
      ? { requestable: decision.requestable }
      : {}),
    ...(decision.grantRef !== undefined ? { grantRef: decision.grantRef } : {}),
    ...(decision.wantsApproval === true ? { wantsApproval: true } : {}),
  };
}

/**
 * Builds a fresh L0 adapter instance. Pure/stateless (mirrors
 * `evaluatePrecedence` itself) — safe to call once and reuse, or call again
 * per registration; no internal state is created either way.
 */
export function createL0Adapter(): PdpAdapter {
  return {
    capabilities: {
      name: "l0",
      latencyClass: "in_process",
      // L0's own sensitive-tier-no-grant deny path always carries
      // `requestable` guidance (l0-evaluator.ts's `buildRequestableHow`) —
      // this adapter can always originate it.
      supportsRequestableDenial: true,
    },
    async decide(req, ctx) {
      const decision = evaluatePrecedence({
        request: req,
        tierPolicy: ctx.tierPolicy,
        ...(ctx.envelope !== undefined ? { envelope: ctx.envelope } : {}),
        coveringGrants: ctx.coveringGrants,
        nowEpochSeconds: ctx.nowEpochSeconds,
      });
      return toPdpDecision(decision);
    },
  };
}
