/**
 * @knotrust/core — surface-agnostic decision core: DecisionRequest contract, tier evaluator, and precedence engine. Imports zero MCP types (brief §E1).
 *
 * Phase-0 epic: P0-E2.
 * P0-E2-T1 landed the DecisionRequest contract v1 + Decision outcomes (contract.ts).
 * P0-E2-T2 landed the L0 tier evaluator (l0-evaluator.ts) + its tier-policy
 * input shapes (tier-policy.ts). P0-E2-T3 landed the precedence engine
 * (precedence.ts), composing the L0 evaluator under the admin envelope.
 * P0-E2-T4 landed the in-process decision cache (decision-cache.ts) with
 * tiered TTLs and versioned invalidation, plus its canonicalization util
 * (canonical-json.ts). P0-E2-T5 landed the `PdpAdapter` port (pdp-port.ts —
 * the seam `@knotrust/pdp`'s adapters implement, brief §B1/§E6), the
 * composed decision pipeline (pipeline.ts, ADR-0018), and a minimal ULID
 * generator for `decisionId` minting (ulid.ts).
 * P0-E5-T4 fix round 2 (R80) relocated the shared leak-pattern source
 * (leak-patterns.ts — token shapes + policy-internal identifiers) here from
 * `@knotrust/test-harness`, so `@knotrust/proxy-stdio`'s production redactor
 * never needs a runtime dependency on a test package; see that file's
 * header for the full rationale.
 */
export const PKG = "@knotrust/core";

export * from "./canonical-json.js";
export * from "./contract.js";
export * from "./decision-cache.js";
export * from "./jcs.js";
export * from "./l0-evaluator.js";
export * from "./leak-patterns.js";
export * from "./pdp-port.js";
export * from "./pipeline.js";
export * from "./precedence.js";
export * from "./tier-policy.js";
export * from "./ulid.js";
