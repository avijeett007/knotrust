/**
 * @knotrust/grants — revocation (P0-E3-T4, rulings R39–R42).
 *
 * `revokeGrants` is the library revoke path CLI wiring (P0-E7-T2, deferred by
 * R39) composes: it tombstones one or more grants in the store, audits each
 * tombstone, and invalidates exactly once. It never restarts a process and
 * never touches the decision cache directly — `deps.onInvalidate` is the
 * seam a composed system wires to `DecisionCache.bumpGrantSetVersion`
 * (P0-E2-T4). The plan's `configEpoch` (task spec: "bumps `configEpoch`
 * (invalidates decision cache, P0-E2-T4)") is realized concretely by that
 * cache's own `grantSetVersion` field (R16/R20) — there is no separate
 * `configEpoch` value anywhere in this codebase; `onInvalidate` IS the bump.
 *
 * ## Selector semantics (R39)
 *
 * - `{ jti }` — revokes exactly that grant, if it is currently active
 *   (`store.get(jti).status === "active"`). A `jti` that is absent or
 *   already revoked yields `notFound: true` and revokes nothing (idempotent,
 *   never re-tombstones or re-audits an already-revoked grant).
 * - `{ tool }` — revokes every ACTIVE grant whose stored `tool` claim is
 *   EXACTLY equal to the given string, via `store.listBy({ tool })`. This is
 *   the one place in the codebase where that store method's exact-string
 *   semantics are exactly what's wanted: `listBy({ tool: "github.*" })`
 *   revokes the grant literally stored with pattern `"github.*"` — it does
 *   NOT expand the glob and revoke every grant that would MATCH
 *   `"github.*"` at authorization time (that would require walking every
 *   grant and re-running the grants-layer pattern matcher, a materially
 *   different and heavier operation this task does not implement). Passing
 *   a concrete tool name like `"github.create_issue"` here only revokes a
 *   grant stored under that EXACT literal — it will NOT reach a broader
 *   `"github.*"` grant that happens to cover it. Document this at the CLI
 *   layer (P0-E7-T2) too: `knotrust revoke --tool <pattern>` must echo back
 *   exactly what it matched.
 * - `{ all: true }` — revokes every currently active grant in the store.
 *
 * ## Ordering (R39/R43) — tombstone-first, audit-per-grant, invalidate-once
 *
 * For each matched grant: `store.revoke(jti, reason)` (tombstone-first,
 * crash-safe per E4-T1's own revoke() doc-comment) lands BEFORE its
 * `grant_revoked` audit event is appended. `deps.onInvalidate()` fires
 * exactly once per call, in a `finally`-style path that runs whether this
 * function finishes the whole batch or a later step throws partway
 * through — PROVIDED at least one tombstone landed. A selector that
 * matches zero active grants (`notFound: true`) is the only case that
 * never invalidates.
 *
 * This is deliberately NOT withheld on partial failure (R43, closing an
 * under-invalidation hole): if `revokeGrants({ all: true })` tombstones
 * grants 1 and 2 and then its audit sink throws appending grant 2's
 * event (grant 3 never gets tombstoned at all), a composed cache MUST
 * still be bumped. Grants 1 and 2 are already gone from the store, so a
 * fresh `collectCoveringGrants` scan will never serve them again — but a
 * cache that was never told to invalidate keeps serving their stale
 * cached ALLOWs for up to a full TTL, and cache hits never reach the
 * store or the audit sink to self-correct. Invalidating unconditionally
 * whenever ANY tombstone landed is safe because cache bumps are
 * idempotent and pure over-invalidation only costs an extra cache-miss
 * recompute; under-invalidation after a real tombstone is the unsafe
 * direction this fix closes. The original error is rethrown after
 * `onInvalidate` runs, so the caller still sees the failure and can
 * retry.
 *
 * `deps.audit` is optional, matching R40's decision/mint wiring: when
 * absent, revocation still fully happens (tombstone + invalidate), just
 * without an audit trail. This module does NOT fail-closed on an audit
 * append failure the way `decideWithGrants` does (R40) — there is no
 * "decision" here to convert to a deny. A thrown `AuditUnavailableError`
 * from `audit.append` propagates to the caller as-is: the tombstone that
 * already landed for THIS grant stays revoked (store state is the truth,
 * per E4-T1), and — per R43, above — `onInvalidate` still fires for
 * whatever tombstones DID land before this function rethrows and stops.
 * The caller sees the failure and can retry (retrying re-scans
 * `store.list()`/`listBy()`, which already excludes the grants tombstoned
 * in the failed attempt, so a retry only ever appends the REMAINING
 * grants' audit events, never double-audits one that already landed).
 */

import type { AuditSink, GrantRecord, GrantStore } from "@knotrust/store";
import { AuditEventType, computeArgsHash } from "@knotrust/store";
import type { GrantClaims } from "./claims.js";
import { parseWireClaims } from "./claims.js";
import { decodeGrantPayload } from "./lifecycle.js";

// ---------------------------------------------------------------------------
// Public shapes (R39)
// ---------------------------------------------------------------------------

export type RevokeSelector = { jti: string } | { tool: string } | { all: true };

export interface RevokeGrantsDeps {
  store: GrantStore;
  audit?: AuditSink;
  /** Called exactly ONCE per call, in a `finally`-style path, as soon as at least one matched grant's tombstone has landed — even if a later step (another tombstone, an audit append) then throws (R43; see module header). Never called when the selector matched zero active grants. The composed system passes `cache.bumpGrantSetVersion` (see module header). */
  onInvalidate?: () => void;
}

export interface RevokeGrantsResult {
  /** jtis actually tombstoned by this call, in match order. */
  revoked: string[];
  /** `true` iff the selector matched zero active grants (nothing was revoked, `onInvalidate` was NOT called). */
  notFound: boolean;
}

/** Emitted on every `grant_revoked` audit event — this module is the "grants" layer, independent of any live `DecisionRequest.surface` (mint/revoke are not decisions). */
const GRANTS_AUDIT_SURFACE = "grants";

// ---------------------------------------------------------------------------
// Selector → candidate active grants
// ---------------------------------------------------------------------------

function candidatesFor(
  selector: RevokeSelector,
  store: GrantStore,
): GrantRecord[] {
  if ("all" in selector) {
    return store.list().active;
  }
  if ("tool" in selector) {
    // Exact-string match on the STORED tool pattern — see module header.
    return store.listBy({ tool: selector.tool }).active;
  }
  const result = store.get(selector.jti);
  return result.status === "active"
    ? [{ jti: selector.jti, token: result.token }]
    : [];
}

function selectorReason(selector: RevokeSelector): string {
  if ("all" in selector) return "revoked: --all";
  if ("tool" in selector) return `revoked: --tool ${selector.tool}`;
  return `revoked: jti ${selector.jti}`;
}

// ---------------------------------------------------------------------------
// Audit field derivation — decodes the token captured BEFORE revoke() runs
// (a tombstoned grant's .jws may already be unlinked, so this must read the
// token while it is still active; see candidatesFor()).
// ---------------------------------------------------------------------------

interface AuditIdentityFields {
  subject: string;
  agent: string;
  tool: string;
}

const UNKNOWN_AUDIT_FIELDS: AuditIdentityFields = {
  subject: "unknown",
  agent: "unknown",
  tool: "unknown",
};

/**
 * Decodes the grant's claims for audit purposes only. Never throws (mirrors
 * every other decode-for-audit path in this package): a token that fails to
 * decode here is unreachable in practice (`candidatesFor` only ever returns
 * tokens the store's own `decodeGrantIndexEntry` already accepted), but a
 * defensive `null`-claims fallback keeps this function total rather than
 * relying on that invariant to never break silently.
 */
function auditFieldsFor(token: string): AuditIdentityFields {
  const claims: GrantClaims | null = parseWireClaims(decodeGrantPayload(token));
  if (claims === null) return UNKNOWN_AUDIT_FIELDS;
  return {
    subject: claims.principal.id,
    agent: claims.agent === "*" ? "*" : claims.agent.id,
    tool: claims.tool,
  };
}

// ---------------------------------------------------------------------------
// revokeGrants (R39)
// ---------------------------------------------------------------------------

export function revokeGrants(
  selector: RevokeSelector,
  deps: RevokeGrantsDeps,
): RevokeGrantsResult {
  const { store, audit, onInvalidate } = deps;
  const candidates = candidatesFor(selector, store);

  if (candidates.length === 0) {
    return { revoked: [], notFound: true };
  }

  const reason = selectorReason(selector);
  const revoked: string[] = [];

  // R43: `onInvalidate` must fire once whenever at least one tombstone
  // landed, even if a later step in this loop throws (e.g. the audit sink
  // dies mid-batch) — otherwise already-tombstoned grants would keep
  // serving their stale cached ALLOWs for up to a full TTL. The `finally`
  // runs on both the clean-completion path and the throw path, so it must
  // not itself run twice; `revoked.length > 0` is what gates it, not
  // whether an error occurred.
  try {
    for (const candidate of candidates) {
      // Decode BEFORE revoke(): a lingering .jws is best-effort-unlinked by
      // revoke() and may already be gone by the time audit fields are needed.
      const fields = audit ? auditFieldsFor(candidate.token) : null;

      store.revoke(candidate.jti, reason);
      revoked.push(candidate.jti);

      if (audit && fields) {
        audit.append({
          type: AuditEventType.GRANT_REVOKED,
          surface: GRANTS_AUDIT_SURFACE,
          subject: fields.subject,
          agent: fields.agent,
          tool: fields.tool,
          argsHash: computeArgsHash(null),
          reason,
          grantRefs: [candidate.jti],
        });
      }
    }
  } finally {
    if (revoked.length > 0) {
      onInvalidate?.();
    }
  }

  return { revoked, notFound: false };
}
