/**
 * @knotrust/test-harness — deterministic integration harness: fake MCP
 * server + fake scripted client (P0-E11-T1).
 *
 * The substrate P0-E5 (stdio proxy), P0-E6 (approval), P0-E9 (dogfood), and
 * the P0-E11 adversarial battery all build their acceptance tests on. See
 * `README.md` for a capability-to-consumer map, and `src/acceptance/` for
 * the two demonstrations (R56) that prove this package speaks real MCP
 * 2025-11-25 JSON-RPC before any of those downstream tasks exist.
 *
 * This barrel re-exports both halves for convenience; downstream packages
 * may instead import the narrower `@knotrust/test-harness/fake-server` /
 * `@knotrust/test-harness/fake-client` subpaths directly.
 */

export * from "./fake-client/index.js";
export * from "./fake-server/index.js";
export {
  type Frame,
  type FrameDirection,
  isMethod,
  isResponseTo,
  scanFrames,
} from "./frame.js";
export {
  APPROVAL_TOKEN_HEX_PATTERN,
  APPROVAL_TOKEN_PREFIXED_PATTERN,
  assertNoLeakedSecrets,
  findLeaks,
  type LeakFinding,
  type LeakKind,
  POLICY_INTERNAL_IDENTIFIERS,
  POLICY_INTERNAL_PATTERNS,
} from "./leak-scan.js";
export { createSeededPrng, type SeededPrng } from "./prng.js";
