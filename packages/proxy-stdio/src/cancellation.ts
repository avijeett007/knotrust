/**
 * @knotrust/proxy-stdio — `notifications/cancelled` → pending-approval
 * cancellation bridge (P0-E6-T4, R105).
 *
 * P0-E5-T1 already made `notifications/cancelled` pure PASSTHROUGH (like
 * every message the classifier seam does not specifically intercept) —
 * unchanged here. R105 wires ONE ADDITIONAL, decoupled side effect onto that
 * same passthrough (the `observe` mechanism P0-E5-T2's `tool-inventory.ts`
 * already established, R63): when the client cancels a `tools/call` that is
 * currently held pending approval, the proxy must ALSO cancel that pending
 * approval, so the held call resolves to a deny (`approval_cancelled`)
 * instead of dangling until its timeout — and the child never receives the
 * call it would otherwise have eventually forwarded.
 *
 * ## Why this lives in `proxy-stdio`, not `@knotrust/approval`
 *
 * This module knows NOTHING about approvals — only how to recognize a
 * `notifications/cancelled` client→server notification and extract its
 * `params.requestId` (the ORIGINAL `tools/call`'s own JSON-RPC id — never an
 * internal `apr_...` approval id, which is never wire-visible, R90). What to
 * DO with that id (look up a pending approval, call the lifecycle
 * orchestrator's `cancel()`) is injected as `onCancelled`, a plain callback —
 * `packages/cli`'s `enforcement.ts` wires it to
 * `@knotrust/approval`'s `createDispatchingApprovalOrchestrator`'s own
 * `cancel(jsonRpcRequestId)` method (see that module's header). This keeps
 * the classifier seam free of any runtime dependency on the approval
 * package, mirroring how `enforce.ts`'s own `ApprovalOrchestrator` seam is a
 * STRUCTURAL type, not an import.
 *
 * ## Wiring (`createStdioProxy`'s existing `onClassify` option)
 *
 * `createCancellationClassifier(onCancelled)` returns a standard
 * `ClassifierHook` — the SAME seam `createStdioProxy`'s `onClassify` option
 * already accepts (unused by any CLI path until this task). No change to
 * `proxy.ts`/`classifier.ts` was needed: this is exactly what that seam was
 * built for (R59's own module header: "T2/T3 supply their own hooks via
 * `createStdioProxy`'s `onClassify` option").
 */

import type { ClassifierHook, JsonRpcMessage } from "./classifier.js";

export interface ParsedCancelledNotification {
  /** The ORIGINAL request's JSON-RPC `id` (never the internal approval id). */
  requestId: string | number;
  reason?: string;
}

/**
 * Parses a `notifications/cancelled` message, or `null` if it fails shape
 * validation (wrong method, not a notification, missing/wrong-typed
 * `params.requestId`) — mirrors `enforce.ts`'s own `parseToolsCall`
 * forgiving-`null`-on-malformed discipline (never throws).
 */
export function parseCancelledNotification(
  message: JsonRpcMessage,
): ParsedCancelledNotification | null {
  if (typeof message !== "object" || message === null) return null;
  const m = message as { method?: unknown; params?: unknown };
  if (m.method !== "notifications/cancelled") return null;
  if (typeof m.params !== "object" || m.params === null) return null;
  const requestId = (m.params as { requestId?: unknown }).requestId;
  if (!(typeof requestId === "string" || typeof requestId === "number")) {
    return null;
  }
  const rawReason = (m.params as { reason?: unknown }).reason;
  const reason = typeof rawReason === "string" ? rawReason : undefined;
  return { requestId, ...(reason !== undefined ? { reason } : {}) };
}

/**
 * Builds the R105 cancellation classifier: a standard `ClassifierHook` that
 * is ALWAYS `{action: "passthrough"}` (this task never changes what gets
 * forwarded — the passthrough contract is E5-T1's own, untouched) and, ONLY
 * for a well-formed, client→server `notifications/cancelled`, attaches an
 * `observe` callback that invokes `onCancelled(requestId, reason)` — fired
 * by the relay AFTER the notification is already forwarded (R63's own
 * ordering guarantee), so cancellation can never itself alter or delay what
 * the child/client see on the wire.
 */
export function createCancellationClassifier(
  onCancelled: (requestId: string | number, reason: string | undefined) => void,
): ClassifierHook {
  return (msg, direction) => {
    if (direction === "client_to_server") {
      const parsed = parseCancelledNotification(msg);
      if (parsed !== null) {
        return {
          action: "passthrough",
          observe: () => onCancelled(parsed.requestId, parsed.reason),
        };
      }
    }
    return { action: "passthrough" };
  };
}
