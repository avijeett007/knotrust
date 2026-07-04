/**
 * @knotrust/pdp — `PdpAdapter` implementations + registry, with the
 * built-in L0 evaluator pre-registered as the default adapter (P0-E2-T5).
 *
 * Phase-0 epic: P0-E2 (task P0-E2-T5). Cedar-WASM / AuthZEN-HTTP / OPA
 * adapters are Phase 1 (P1-E2) — they register into this exact same
 * `adapter.ts` registry, against the exact same `PdpAdapter` port
 * (`@knotrust/core`'s `pdp-port.ts`), with zero changes to `@knotrust/core`.
 * See `adapter.ts`'s header and ADR-0018 for the full package-split
 * rationale.
 */
export const PKG = "@knotrust/pdp";

export * from "./adapter.js";
export * from "./l0.js";
