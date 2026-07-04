/**
 * @knotrust/store — local file-based state: grants directory store, config loading (c12 + jiti), and the hash-chained append-only JSONL audit log
 *
 * Phase-0 epic: P0-E4.
 * P0-E4-T1 landed the file-backed grants directory store (grant-store.ts,
 * rulings R29–R31): individual JWS files under `grants/<jti>.jws`,
 * revocation tombstones under `grants/tombstones/<jti>.json` (a tombstone
 * ALWAYS wins over a lingering `.jws` — R30), and the consumed-jti ledger
 * under `grants/consumed/<jti>` — a `wx`-exclusive-create marker that is
 * this product's REPLAY-PROTECTION primitive, atomic across real OS
 * processes with no locks. The store never parses JWS or verifies
 * signatures itself (R29): callers inject a `decodeIndexEntry` seam so
 * `@knotrust/grants` (E3-T3) can layer real verification on top without a
 * package cycle (store is the LOWER layer).
 * P0-E4-T3 landed the hash-chained append-only JSONL audit log
 * (audit-log.ts, rulings R36–R38): `audit/<yyyymm>.jsonl`, a chain hash
 * that reuses `@knotrust/core`'s frozen `canonicalizeJcs`, tail-only
 * crash recovery, an `audit/.lock` single-writer lock, and a fail-closed
 * `AuditUnavailableError` contract on any append failure (D6).
 * P0-E4-T2 landed config loading (config.ts, rulings R44–R47):
 * `knotrust.config.ts`/`.yaml`/`.json` loaded uniformly via c12 (jiti rides
 * inside c12) and validated by a strict zod schema
 * (`KnotrustConfigSchema`), exported as JSON Schema too
 * (`golden-vectors/schemas/config.v1.schema.json`, kept in sync by a
 * committed-file test). `toTierPolicy`/`toAdminEnvelope` normalize the
 * on-disk config into the exact shapes `@knotrust/core`'s evaluator/
 * precedence engine consume (fresh objects every call, R20); `policyVersion`
 * mints the pipeline's config-epoch content-hash.
 */
export const PKG = "@knotrust/store";

export * from "./audit-log.js";
export * from "./config.js";
export * from "./grant-store.js";
