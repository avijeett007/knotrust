/**
 * @knotrust/core — the `PdpAdapter` port (P0-E2-T5, ruling R18).
 *
 * This is the seam that keeps KnoTrust PDP-agnostic (brief §B1, architecture
 * §10.2): every enforcement decision this system makes is produced by an
 * implementation of `PdpAdapter`, never by a surface reaching into core's
 * evaluator/precedence internals directly. Phase 1's Cedar-WASM,
 * AuthZEN-HTTP, and OPA adapters plug into this exact interface — that is
 * the test of this task: no changes to this file, or to
 * `packages/core/src/pipeline.ts` which consumes it, are permitted when
 * those adapters land.
 *
 * ## Why the port lives in core, not in `@knotrust/pdp` (the cycle rationale)
 *
 * The implementation plan's literal deliverable path put the whole
 * interface in `packages/pdp` alongside `packages/core`'s own decision
 * pipeline consuming "only `PdpAdapter`". Taken literally that would create
 * `@knotrust/core` → `@knotrust/pdp` → (`@knotrust/core`, for
 * `evaluatePrecedence`) — a package cycle. The fix (ruling R18) is a
 * standard hexagonal port/adapter split:
 *
 *   - **The PORT (this file) lives in `@knotrust/core`.** `pipeline.ts`,
 *     core's own composed decision pipeline, needs this type to declare
 *     what it depends on. A port a consumer depends on must live where the
 *     consumer lives — otherwise the consumer would have to import its own
 *     dependency's shape from a package that itself depends on the
 *     consumer, which is exactly the cycle above.
 *   - **IMPLEMENTATIONS live in `@knotrust/pdp`**, which depends on
 *     `@knotrust/core` (for these types, and — for the built-in L0
 *     adapter — for `evaluatePrecedence` itself) and never the reverse.
 *     `packages/core/scripts/check-boundaries.mjs` (AST-based) and
 *     `scripts/check-core-boundary.sh` (grep-based) both mechanically ban
 *     any `@knotrust/pdp` import from `packages/core/src` — this file's
 *     existence is what makes that ban possible without core losing the
 *     type it needs.
 *
 * This file is TYPES ONLY — no implementations, no registry, no default
 * export of a concrete adapter. `@knotrust/pdp`'s `adapter.ts` re-exports
 * these types for external callers so nothing outside `@knotrust/core`
 * needs to import from core directly just to name `PdpAdapter`.
 *
 * ## Conformance-tracking discipline (architecture §10, invariant §E6)
 *
 * Every external draft-standard concern an adapter might translate to/from
 * stays entirely behind the adapter that speaks that wire format — never
 * named here, and never named in `pipeline.ts`:
 *
 *   - **AuthZEN 1.0 Authorization API `[STANDARD]`** — Final as of the
 *     OIDF vote (2026-01-12). The generic AuthZEN-HTTP adapter (Phase 1)
 *     speaks its ratified `/access/v1/evaluation` wire format directly;
 *     stable, safe to depend on at that one adapter.
 *   - **AARP/ARAP "Requestable Denial" `[DRAFT]`** and **COAZ
 *     `context.agent` mapping `[DRAFT]`** — both WG Draft 1, actively being
 *     rewritten (open PR as of 2026-07-02; WG issues #481–494 unsettled on
 *     `Subject` vs `Context` placement for agent identity). Any adapter
 *     that speaks these shapes translates at its own boundary; this port
 *     and `pipeline.ts` are expressed purely in KnoTrust-native vocabulary
 *     (`Outcome`, `DecisionResponse["tier"]`, `TierPolicy`, etc.) and never
 *     admit an AuthZEN/AARP/COAZ field name directly.
 *
 * `PdpDecision.reasonCode` is deliberately `string`, not the narrower
 * `L0ReasonCode | PrecedenceReasonCode` union `precedence.ts` uses
 * internally — an external adapter's own reason-code vocabulary (Cedar
 * policy ids, an OPA Rego rule path, an AuthZEN PDP's opaque `context`
 * payload) is never constrained to KnoTrust's L0 vocabulary.
 */

import type { DecisionRequest, DecisionResponse, Outcome } from "./contract.js";
import type { CoveringGrant } from "./l0-evaluator.js";
import type { AdminEnvelope } from "./precedence.js";
import type { TierPolicy } from "./tier-policy.js";

/**
 * Adapter self-description, used for registry keying (`name`) and future
 * capability-aware routing. Not enforced/consumed by `pipeline.ts` in this
 * task (no capability-based branching exists yet) — it exists so a future
 * caller (e.g. a config layer choosing between adapters, or a health check)
 * has a stable place to read it from, without any adapter needing a new
 * interface to expose it later.
 */
export interface PdpCapabilities {
  /** Registry key, e.g. "l0", "cedar", "authzen_http", "opa". */
  name: string;
  /**
   * Whether this adapter can produce AARP-shaped "Requestable Denial"
   * guidance (`PdpDecision.requestable`) on a `deny` outcome. L0 can (a
   * `sensitive`-tier deny with no covering grant); a remote adapter that
   * cannot originate this guidance itself leaves it `undefined`/`false`.
   */
  supportsRequestableDenial?: boolean;
  /**
   * Coarse latency expectation, for future timeout/circuit-breaker tuning.
   * "in_process" (L0, Cedar-WASM) — sub-millisecond, no I/O.
   * "local_http" (an OPA/Cerbos daemon on localhost) — local network hop.
   * "remote" (a hosted AuthZEN-compliant PDP) — network + the far side's
   * own latency budget.
   */
  latencyClass: "in_process" | "local_http" | "remote";
}

/**
 * What an adapter returns from `decide()`. `pipeline.ts` assembles the full
 * `DecisionResponse` envelope (`contractVersion`, `requestId`, `decisionId`,
 * `cache`, `latencyMs`) around this — an adapter never mints those fields
 * itself, matching how `l0-evaluator.ts`'s own `L0Decision` already draws
 * that line (see that module's header note).
 */
export interface PdpDecision {
  outcome: Outcome;
  tier: DecisionResponse["tier"];
  /** Machine-stable but adapter-owned vocabulary — see this file's header on why this is `string`, not `L0ReasonCode`. */
  reasonCode: string;
  reasonUser?: string;
  reasonAdmin?: string;
  /** Present iff `outcome === "deny"` and the adapter can originate requestable guidance (see `PdpCapabilities.supportsRequestableDenial`). */
  requestable?: DecisionResponse["requestable"];
  /** The covering grant's `jti`, when a grant decided the outcome. Internal to the pipeline; never surfaced on `DecisionResponse` directly. */
  grantRef?: string;
  /**
   * True iff the adapter could not resolve the request on its own and
   * wants the approval orchestrator engaged (mirrors `L0Decision.wantsApproval`,
   * widened from the literal `true` to `boolean` since a non-L0 adapter has
   * no equivalent narrowing reason to omit `false` explicitly).
   */
  wantsApproval?: boolean;
  evaluatedBy: DecisionResponse["evaluatedBy"];
}

/**
 * KnoTrust-native inputs every adapter MAY use. These are KnoTrust's own
 * primitives (tier policy, admin envelope, covering grants, clock) — even
 * an external PDP is composed WITH them, not instead of them: a Cedar/OPA
 * adapter typically still needs to know the resolved tier policy and any
 * covering grant evidence to merge with its own policy result, while an
 * AuthZEN-HTTP adapter might ignore most of this and rely almost entirely
 * on the wire call's own response. The L0 adapter (this task) consumes
 * every field directly, unmodified, as `evaluatePrecedence`'s own input
 * shape already expects.
 */
export interface PdpEvaluationContext {
  tierPolicy: TierPolicy;
  envelope?: AdminEnvelope;
  coveringGrants: readonly CoveringGrant[];
  /** Epoch seconds — the injected clock, resolved once by the pipeline before calling the adapter. Never `Date.now()` internally. */
  nowEpochSeconds: number;
}

/**
 * The port itself. `packages/pdp/src/l0.ts` is the built-in implementation
 * (this task); Phase 1 adds Cedar-WASM/AuthZEN-HTTP/OPA implementations
 * against this exact same interface, with zero changes to this file or to
 * `pipeline.ts`.
 */
export interface PdpAdapter {
  readonly capabilities: PdpCapabilities;
  decide(req: DecisionRequest, ctx: PdpEvaluationContext): Promise<PdpDecision>;
}
