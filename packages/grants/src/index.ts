/**
 * @knotrust/grants — Ed25519 identity plus signed grant mint/verify (JWS Compact, alg: EdDSA) and durable/ephemeral grant lifecycle with call-hash binding
 *
 * Phase-0 epic: P0-E3.
 * P0-E3-T1 landed identity keygen & key management (keys.ts, rulings
 * R21–R23): the OS-keychain-default/0600-file-fallback `KeyStore`, whose
 * `sign()` is what E3-T2's grant mint/verify will call — the private key
 * never leaves keys.ts.
 * P0-E3-T2 landed the grant claim schema + bijective wire codec (claims.ts,
 * architecture §5.2), hand-assembled JWS Compact minting (mint.ts, R27), and
 * the adversarially-hardened offline verifier (verify.ts, R26) — every allow
 * the product grants flows through `verifyGrant`.
 * P0-E3-T3 landed the durable/ephemeral lifecycle with call-hash binding and
 * the consume-is-atomic-with-the-decision algorithm (lifecycle.ts, R34/R35).
 * P0-E3-T4 landed revocation (revoke.ts, R39: tombstone-first, audit-per-
 * grant, invalidate-once) and the grant-lifecycle + decision audit wiring
 * (lifecycle.ts, R40: `grant_created`/`grant_consumed`/`decision` events,
 * fail-closed deny/`audit_unavailable` — the seam P0-E5-T3/T5 makes
 * mandatory at the proxy). Claim language for revocation freshness lives in
 * ONE place: `docs/02-product/revocation-claims.md` (R42, ADR-0011).
 */
export const PKG = "@knotrust/grants";

export * from "./callhash.js";
export * from "./claims.js";
export * from "./decider.js";
export * from "./keys.js";
export * from "./lifecycle.js";
export * from "./mint.js";
export * from "./revoke.js";
export * from "./verify.js";
