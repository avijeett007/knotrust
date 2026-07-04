# ADR-0018: PdpAdapter boundary — port in core, implementations in pdp

**Status:** Accepted (2026-07-03)

## Context

P0-E2-T5's job is the seam that keeps KnoTrust PDP-agnostic (brief §B1: "KnoTrust *fronts* PDPs; the PDP interface is the architectural boundary") — an internal `PdpAdapter` interface that P0-E2-T2's L0 evaluator (`packages/core/src/l0-evaluator.ts`) and P0-E2-T3's precedence engine (`packages/core/src/precedence.ts`) implement as the built-in adapter, and that Phase 1's Cedar-WASM, generic AuthZEN-HTTP, and OPA adapters (ADR-0003) plug into later with **no core changes** — the explicit test of this task.

The implementation plan's literal deliverable path put the whole interface in `packages/pdp`, while separately stating "core's decision pipeline consumes only `PdpAdapter`." Taken together this is a cycle: `@knotrust/core` (the pipeline) would depend on `@knotrust/pdp` (for the `PdpAdapter` type), and `@knotrust/pdp` would depend on `@knotrust/core` (for `evaluatePrecedence`, to implement the built-in L0 adapter). pnpm workspace `dependencies` cannot express a cycle, and even if it could, it would defeat the entire point of `@knotrust/core` importing zero MCP/enforcement-surface concerns (invariant §4.1, already gated by `packages/core/scripts/check-boundaries.mjs` and `scripts/check-core-boundary.sh` for the `@modelcontextprotocol`/`proxy-stdio` case).

## Decision

**Hexagonal port/adapter split**, ratified as orchestrator ruling R18:

- **The port TYPES live in `@knotrust/core`** (`packages/core/src/pdp-port.ts`): `PdpAdapter`, `PdpCapabilities`, `PdpDecision`, `PdpEvaluationContext`. Types and doc-comments only — no implementations, no registry. `packages/core/src/pipeline.ts` (the composed decision pipeline, R19) depends on this file to declare what it accepts; a port a consumer depends on must live where the consumer lives, or the consumer would have to import its own dependency's shape from a package that itself depends on the consumer — exactly the cycle above.

  ```typescript
  export interface PdpCapabilities {
    name: string; // registry key, e.g. "l0"
    supportsRequestableDenial?: boolean;
    latencyClass: "in_process" | "local_http" | "remote";
  }
  export interface PdpDecision {
    outcome: Outcome;
    tier: DecisionResponse["tier"];
    reasonCode: string; // adapter-owned vocabulary, not L0ReasonCode
    reasonUser?: string;
    reasonAdmin?: string;
    requestable?: DecisionResponse["requestable"];
    grantRef?: string;
    wantsApproval?: boolean;
    evaluatedBy: DecisionResponse["evaluatedBy"];
  }
  export interface PdpEvaluationContext {
    tierPolicy: TierPolicy;
    envelope?: AdminEnvelope;
    coveringGrants: readonly CoveringGrant[];
    nowEpochSeconds: number;
  }
  export interface PdpAdapter {
    readonly capabilities: PdpCapabilities;
    decide(req: DecisionRequest, ctx: PdpEvaluationContext): Promise<PdpDecision>;
  }
  ```

  `PdpEvaluationContext` carries KnoTrust-native primitives (tier policy, admin envelope, covering grants, clock) because even an external PDP is composed *with* them, not instead of them — a Cedar/OPA adapter still needs the resolved tier policy and grant evidence to merge with its own policy result; an AuthZEN-HTTP adapter may ignore most of it. The built-in L0 adapter consumes every field directly, unmodified, as `evaluatePrecedence`'s existing input shape already expects.

- **Implementations and the registry live in `@knotrust/pdp`**, which gains a real `"@knotrust/core": "workspace:*"` dependency and stays `private`. `adapter.ts` is the registry (`registerAdapter`/`getAdapter(name)`/`listAdapters`, with the built-in `"l0"` adapter pre-registered by default) plus a re-export of the core port types, so nothing outside `@knotrust/core` needs to import core directly just to name `PdpAdapter`. `l0.ts` is the built-in adapter: a **thin** wrapper mapping `evaluatePrecedence`'s `PrecedenceDecision` onto `PdpDecision` (`evaluatedBy: "L0"`). "Refactor L0 to implement the interface" means this wrapper only — `packages/core/src/l0-evaluator.ts` and `packages/core/src/precedence.ts` are not moved, not rewritten, and their existing unit test suites (`l0-evaluator.test.ts`, `precedence.test.ts`) stay green, untouched.

- **The boundary is mechanically enforced in the direction that matters.** `@knotrust/pdp` depending on `@knotrust/core` is expected and fine (not gated). The gate is the reverse: `@knotrust/core` must never import `@knotrust/pdp`. Both existing boundary gates (P0-E2-T1 ruling 5a/5b) are extended with this rule:
  - `packages/core/scripts/check-boundaries.mjs` (AST-based, package-local `lint:boundaries`) — banned-specifier list gains `^@knotrust/pdp(/|$)`.
  - `scripts/check-core-boundary.sh` (grep-based, repo-level, wired into CI) — banned-substring pattern gains `@knotrust/pdp`.

  Both gates were verified to fire (exit 1, correct diagnostic) against a synthetic `import { getAdapter } from "@knotrust/pdp"` planted in `packages/core/src/`, then verified clean again after the synthetic file was removed.

- **The no-core-changes test.** Phase 1 adds a Cedar-WASM/AuthZEN-HTTP/OPA adapter by adding one new file under `packages/pdp/src/` (mirroring `l0.ts`'s shape) and a `registerAdapter(createXAdapter())` call in `adapter.ts` — zero changes to `pdp-port.ts` or `pipeline.ts`. `packages/pdp/src/adapter.test.ts`'s "no-core-changes conformance" case proves this today: a stub adapter that is not L0, registered and retrieved through the exact same registry API, and `packages/core/src/pipeline.test.ts`'s four-outcome acceptance suite proves the pipeline itself is adapter-agnostic (a stub `PdpAdapter` drives every outcome branch with zero knowledge of which concrete adapter is behind it).

## Conformance-tracking discipline (architecture §10, invariant §E6)

Every external draft-standard concern an adapter might translate to/from stays entirely behind that adapter — never named in `pdp-port.ts`, `pipeline.ts`, or `adapter.ts`'s public API:

- **AuthZEN 1.0 Authorization API `[STANDARD]`** — Final as of the OIDF vote (2026-01-12). The generic AuthZEN-HTTP adapter (Phase 1) speaks its ratified `/access/v1/evaluation` wire format directly at its own boundary; stable, safe to depend on there.
- **AARP/ARAP "Requestable Denial" `[DRAFT]`** and **COAZ `context.agent` mapping `[DRAFT]`** — both WG Draft 1, actively being rewritten (open PR as of 2026-07-02; WG issues #481–494 unsettled on `Subject` vs `Context` placement for agent identity). Any adapter that speaks these shapes translates entirely within its own file. `PdpDecision.requestable` is expressed in KnoTrust-native vocabulary (`{ how: string }`, already ratified by P0-E2-T2's R9), never as a raw AARP `access_request`/Task Handle field.

`PdpDecision.reasonCode` is deliberately typed `string`, not the narrower `L0ReasonCode | PrecedenceReasonCode` union `precedence.ts` uses internally — an external adapter's own reason-code vocabulary (a Cedar policy id, an OPA Rego rule path, an opaque AuthZEN `context` payload) is never constrained to L0's vocabulary. This is the same discipline invariant §E6 already requires of the MCP `SpecAdapter` (architecture §10.1) and the AuthZEN/AARP/COAZ adapters (architecture §10.2), applied to the fourth adapter family this system has: PDPs.

Both gates' header comments and this ADR are the two places this note is required to live (ruling R18's explicit instruction); `pdp-port.ts`'s and `adapter.ts`'s own header doc-comments carry the same note for readers who start there instead of the ADR.

## Consequences

- `@knotrust/pdp` becomes a real package for the first time (previously a placeholder `PKG` export): it gains a genuine `@knotrust/core` dependency, a real `src/adapter.ts` + `src/l0.ts`, and its own test suite (`adapter.test.ts`, `l0.test.ts`).
- `packages/core/src/pipeline.ts` (R19) is the first core module to depend on `pdp-port.ts`; every future core consumer of `PdpAdapter` (e.g. a future config-driven adapter selector) depends on the same file, never on `@knotrust/pdp`.
- Phase 1's three planned adapters (Cedar-WASM, AuthZEN-HTTP, OPA — ADR-0003) have a proven, tested integration point with an explicit acceptance bar (no core diff) rather than an implicit expectation.
- The cache-key-tier seam this task also closes (R19, pinned in `pipeline.ts`) is downstream of this boundary: because `PdpDecision.tier` is adapter-reported and not automatically trusted for cache keying, a misbehaving or divergent external adapter cannot cause a `critical`-resolved decision to be cached under a laxer tier — a security property that falls out of keeping the port narrow and KnoTrust's own tier resolution authoritative.
- Two boundary gates now enforce three package-import bans each (`@modelcontextprotocol/*`, `packages/proxy-*`, `@knotrust/pdp`) instead of two; both were exercised against a real synthetic violation as part of this task's acceptance verification, not just inspected by reading.

## Alternatives considered

- **Interface entirely in `packages/pdp`, as the plan's literal deliverable path states** — rejected: creates the `@knotrust/core` → `@knotrust/pdp` → `@knotrust/core` cycle described in Context. Not just a build-graph inconvenience: it would mean core's own decision pipeline formally depends on a package whose entire purpose is housing enforcement-surface-adjacent, standards-adapter concerns — precisely what invariant §4.1's MCP-import ban exists to keep out of core, just one hop removed.
- **Duplicate the port type in both packages (core's own copy + pdp's own copy)** — rejected: guarantees drift the first time either copy changes; the entire value of a port is that every implementation and every consumer share the exact same contract.
- **Merge `packages/pdp` into `packages/core`** (no separate package at all) — rejected: `packages/core` must stay dependency-free of anything adapter/wire-format-specific (invariant §4.1's spirit, even though the literal banned list only names MCP/proxy today); folding Cedar-WASM (~4.3 MB, ADR-0003), an AuthZEN-HTTP client, and an OPA REST client into core's own dependency tree defeats the "npx and go" minimalism ADR-0003 already protects for the PDP layer specifically.

## References

- Brief §B1 (layered PDP resolution, "KnoTrust fronts PDPs" positioning), §E6 (spec-adapter isolation invariant).
- Implementation plan, task P0-E2-T5.
- Architecture §10 (`Spec-adapter isolation [invariant §E6]`), §10.1 (`SpecAdapter`, the MCP-transport precedent for this same pattern), §10.2 (AuthZEN/AARP/COAZ conformance notes, verbatim maturity claims reused above).
- ADR-0003 (`docs/05-decisions/adr/adr-0003-layered-pdp-l0-cedar-adapters.md`) — the layered-PDP model (L0/Cedar/adapters) this boundary serves.
- `packages/core/src/pdp-port.ts` — the port types.
- `packages/core/src/pipeline.ts` — the composed decision pipeline (R19), the port's first and only core-side consumer.
- `packages/pdp/src/adapter.ts` — the registry + re-exported port types.
- `packages/pdp/src/l0.ts` — the built-in L0 adapter (thin wrapper over `evaluatePrecedence`).
- `packages/core/scripts/check-boundaries.mjs`, `scripts/check-core-boundary.sh` — the two extended, independently-verified boundary gates.
