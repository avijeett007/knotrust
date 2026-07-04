/**
 * @knotrust/approval — the pending-approval-request registry (P0-E6-T3,
 * ruling R96).
 *
 * The localhost approval page must render tool/server/tier/argument-summary
 * from the SAME frozen `DecisionRequest` snapshot the lifecycle orchestrator
 * (E6-T1) captured at `request()` time ("render from OUR parse — never
 * re-fetch server-controlled data"). But `ApprovalOrchestrator.status(id)`
 * deliberately returns only `{id, state}` (R90 — no model-visible leakage,
 * `ApprovalHandle` stays a closed, tiny shape) — it never carries the full
 * `ApprovalRequest`, and it must not start doing so just to serve a human
 * UI.
 *
 * `withApprovalRequestRegistry` closes that gap WITHOUT touching
 * `lifecycle.ts`'s public contract at all: it wraps an existing
 * `ApprovalOrchestrator`'s `request()` so every call is ALSO recorded (by
 * the minted `approvalId`) in a private, in-memory `Map` this module owns —
 * then hands back both the (structurally-identical) wrapped orchestrator and
 * a `getApprovalRequest(id)` accessor over that map. Wiring code
 * (`packages/cli`'s `enforcement.ts`) constructs ONE registry per run and
 * hands the WRAPPED orchestrator to both `createBlockAndWaitChannel`
 * (unaffected — it never reads the map) and `createApprovalPageServer`
 * (which does).
 *
 * This keeps the "minimal wiring" scope R100 asks for literally minimal:
 * zero changes to `lifecycle.ts` or `block-and-wait.ts`'s own request/resolve
 * machinery, and the map only ever grows for approvals that actually went
 * through THIS wrapped orchestrator instance (a fresh one per process run in
 * production) — never a cross-process or persistent store.
 */

import type {
  ApprovalHandle,
  ApprovalOrchestrator,
  ApprovalRequest,
} from "../../lifecycle.js";

export interface ApprovalRequestRegistry {
  /** Structurally identical to the wrapped orchestrator — every method delegates, `request()` also records. */
  orchestrator: ApprovalOrchestrator;
  /** The `ApprovalRequest` `request()` was called with for this id, or `undefined` if this id was never seen by this registry. */
  getApprovalRequest(id: string): ApprovalRequest | undefined;
}

export function withApprovalRequestRegistry(
  orchestrator: ApprovalOrchestrator,
): ApprovalRequestRegistry {
  const requests = new Map<string, ApprovalRequest>();

  return {
    orchestrator: {
      ...orchestrator,
      async request(req: ApprovalRequest): Promise<ApprovalHandle> {
        const handle = await orchestrator.request(req);
        // Recorded even if `request()` returned an already-fail-closed-denied
        // handle (a first-audit-append failure, lifecycle.ts's own doc) —
        // harmless: nothing ever resolves against a terminal id, and the
        // page's own `status()` check (server.ts) still catches it.
        requests.set(handle.id, req);
        return handle;
      },
    },
    getApprovalRequest: (id: string) => requests.get(id),
  };
}
