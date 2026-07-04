/**
 * @knotrust/approval — the formal `ApprovalChannel` interface, the
 * multi-channel dispatcher, and the proxy-facing orchestrator adapter
 * (P0-E6-T4; rulings R101–R105; architecture §6.2).
 *
 * ## R101 — `ApprovalChannel` (architecture §6.2, copied verbatim plus the
 * documented `available()`'s second argument)
 *
 * This formalizes the abstraction block-and-wait (E6-T2, `channels/
 * block-and-wait.ts`) and the localhost page (E6-T3, `channels/local-page/`)
 * already implement INFORMALLY, and that Phase-1 elicitation channels and
 * Phase-2 push/SMS will implement going forward:
 *
 *   - `kind` — which {@link ApprovalChannelKind} this channel is.
 *   - `available(req, surface)` — is this channel usable for this request on
 *     this surface (client capability, configuration, transport)? Pure,
 *     synchronous, side-effect-free — the dispatcher calls it to FILTER,
 *     never to present.
 *   - `notify(req, handle)` — presents the approval to the human (stderr
 *     prompt, page URL, elicitation, push). Returns once the PRESENTATION
 *     step is done — it does NOT itself await the human's terminal decision;
 *     resolution flows back out-of-band via `orchestrator.resolve(handle.id,
 *     ...)` (the channel, or a surface it presents, calls that separately —
 *     see block-and-wait.ts's own module header for its hold+heartbeat
 *     mechanics, which now run in the BACKGROUND from `notify()` rather than
 *     blocking its return).
 *
 * The localhost page (E6-T3) remains a resolution SURFACE that block-and-
 * wait's `notify` presents (the URL) — it is NOT itself a separate
 * `ApprovalChannel` in P0 (documented, R101): in P1 the SAME page becomes the
 * human-action target for `elicitation_url` too.
 *
 * ## R101 — the dispatcher's "notify-all, resolve-first" model (the ruling,
 * verbatim): "the RESOLVING channel is the first-available (block-and-wait
 * floor), but ALL registered channels' `notify` is invoked (they're
 * presentation surfaces — e.g. also push a notification) — the resolution is
 * whichever human action arrives first via `orchestrator.resolve`."
 *
 * Concretely: {@link createMultiChannelDispatcher}'s `present()` filters the
 * registered channels down to those whose `available(req, surface)` returns
 * `true` for THIS request/surface, then invokes `notify(req, handle)` on
 * EVERY one of them (not just the first) — concurrently, via
 * `Promise.allSettled` so one channel's failure never blocks or hides
 * another's. Block-and-wait's `available()` always returns `true` (the
 * "always-available floor" — R91/architecture §6.2), so it is always among
 * the notified set; that is what makes it the universal fallback. Which
 * channel actually RESOLVES the approval is decided entirely by which human
 * action reaches `orchestrator.resolve()`/`.cancel()` first (the lifecycle
 * orchestrator's own single-winner latch, `lifecycle.ts`'s `resolving` flag,
 * already makes a second, later resolution a no-op error rather than a
 * double-processing bug) — the dispatcher itself makes no such decision and
 * holds no state past one `present()` call.
 *
 * ## R102 — consolidating the proxy's `pending_approval` wiring behind this
 * interface
 *
 * `@knotrust/proxy-stdio`'s `enforce.ts` keeps its existing, minimal seam
 * (`ApprovalOrchestrator.requestApproval(input): Promise<ApprovalResolution>`
 * — unchanged in shape, since a clean seam is the whole point of R102's
 * "consolidate... behind the interface"). What is now WIRED behind that seam
 * changes: {@link createDispatchingApprovalOrchestrator} implements it by
 * running the canonical sequence the ruling names —
 *
 *   `lifecycleOrchestrator.request(req)` → `dispatcher.present(req, surface,
 *   handle)` (notifies every available channel; block-and-wait is the one
 *   that actually HOLDS + heartbeats, in the background) → `await
 *   lifecycleOrchestrator.onResolved(handle.id)` → map the terminal
 *   `ApprovalState` to the wire-facing `{outcome:"allow"} |
 *   {outcome:"deny", reasonCode?}` (never `{outcome:"pending"}` — this
 *   adapter, like block-and-wait alone before it, always holds until a
 *   terminal state, R93).
 *
 * `packages/cli`'s `enforcement.ts` (E6-T4) is where this adapter is
 * constructed for a real run, replacing E6-T2's direct
 * `createBlockAndWaitChannel(...)` wiring with `createDispatchingApprovalOrchestrator({
 * orchestrator: lifecycleOrchestrator, dispatcher: createMultiChannelDispatcher([
 * blockAndWaitChannel]) })` — block-and-wait registered as the one, always-
 * available floor channel; Phase-1 elicitation channels are additional
 * `ApprovalChannel`s registered on the SAME dispatcher, with zero change to
 * this adapter or to `enforce.ts`.
 *
 * ## R105 — client-cancellation, wired by request id
 *
 * `enforce.ts`'s `ApprovalRequestInput` carries the original `tools/call`'s
 * JSON-RPC `id` (`jsonRpcRequestId`) precisely so this adapter can correlate
 * a LATER `notifications/cancelled` (which the MCP spec addresses by that
 * same JSON-RPC id, `params.requestId` — never by the internal `apr_...`
 * approval id, which is never wire-visible, R90) back to the pending
 * approval it belongs to. `cancel(jsonRpcRequestId)` is this adapter's OWN
 * extra method (beyond the `requestApproval` seam `enforce.ts` calls) —
 * `packages/proxy-stdio`'s cancellation classifier (`cancellation.ts`) is
 * wired directly to THIS method by `packages/cli`'s `enforcement.ts`, which
 * holds the one adapter instance both `createEnforcer` (via the
 * `requestApproval` seam) and the classifier (via `cancel`) share — no change
 * to `enforce.ts`'s `ApprovalOrchestrator` type is needed for this, since
 * `enforce.ts` only ever calls `requestApproval` and never sees the extra
 * method structurally attached to the same object.
 */

import type {
  ApprovalState,
  DecisionRequest,
  DecisionResponse,
  SurfaceMetadata,
  Tier,
} from "@knotrust/core";
import type {
  ApprovalChannelKind,
  ApprovalHandle,
  ApprovalOrchestrator,
  ApprovalRequest,
} from "./lifecycle.js";

// ---------------------------------------------------------------------------
// ApprovalChannel (R101, architecture §6.2)
// ---------------------------------------------------------------------------

export interface ApprovalChannel {
  readonly kind: ApprovalChannelKind;
  /** Pure, synchronous, side-effect-free: is this channel usable for `req` on `surface`? A throw is treated as "not available" by the dispatcher (defensive — a channel's eligibility check must never itself crash presentation). */
  available(req: ApprovalRequest, surface: SurfaceMetadata): boolean;
  /** Presents the approval to the human. Resolves once presentation is under way — NOT once the human has acted (see module header). */
  notify(req: ApprovalRequest, handle: ApprovalHandle): Promise<void>;
}

// ---------------------------------------------------------------------------
// MultiChannelDispatcher (R101 — notify-all, resolve-first)
// ---------------------------------------------------------------------------

export interface ApprovalDispatcher {
  present(
    req: ApprovalRequest,
    surface: SurfaceMetadata,
    handle: ApprovalHandle,
  ): Promise<void>;
}

export interface MultiChannelDispatcherDeps {
  /** Diagnostic sink for a channel's `available()` throwing, or its `notify()` rejecting — NEVER the relayed/model-visible traffic. Best-effort; absent means silent. */
  logger?: (line: string) => void;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Builds the dispatcher over a fixed, ordered list of channels (block-and-
 * wait first, by convention — the always-available floor — then any P1+
 * channels). `present()` filters to the channels `available()` for THIS
 * request/surface, then invokes `notify()` on ALL of them concurrently
 * (R101's ruling) — never just the first. One channel's `available()`
 * throwing or `notify()` rejecting is logged and otherwise swallowed; it
 * never prevents another channel from being notified, and never rejects
 * `present()` itself (a channel is a presentation surface, not a
 * correctness-critical dependency — the lifecycle orchestrator's own
 * `onResolved()`/expiry timeout is what actually bounds how long a call can
 * be held, regardless of how many channels actually got through).
 */
export function createMultiChannelDispatcher(
  channels: readonly ApprovalChannel[],
  deps: MultiChannelDispatcherDeps = {},
): ApprovalDispatcher {
  return {
    async present(req, surface, handle): Promise<void> {
      const available = channels.filter((channel) => {
        try {
          return channel.available(req, surface);
        } catch (err) {
          deps.logger?.(
            `knotrust: approval channel "${channel.kind}" available() threw for ${handle.id} — treated as unavailable: ${errorMessage(err)}`,
          );
          return false;
        }
      });

      const results = await Promise.allSettled(
        available.map((channel) => channel.notify(req, handle)),
      );
      for (const [i, result] of results.entries()) {
        if (result.status === "rejected") {
          deps.logger?.(
            `knotrust: approval channel "${available[i]?.kind}" notify() failed for ${handle.id}: ${errorMessage(result.reason)}`,
          );
        }
      }
    },
  };
}

// ---------------------------------------------------------------------------
// The proxy-facing seam this adapter satisfies (R102) — a STRUCTURAL mirror
// of `@knotrust/proxy-stdio`'s `enforce.ts` `ApprovalRequestInput`/
// `ApprovalResolution`/`ApprovalOrchestrator`, duplicated here (not imported)
// for the SAME reason `channels/block-and-wait.ts` already duplicates it —
// this package takes no runtime dependency on `@knotrust/proxy-stdio`
// (mirrors R86.6's "no runtime dependency on grants/store" discipline, one
// layer up). Keep structurally identical to `enforce.ts`'s own shapes if
// they ever change.
// ---------------------------------------------------------------------------

export interface DispatchingApprovalRequestInput {
  /** The `DecisionRequest` the decider evaluated. */
  request: DecisionRequest;
  /** The decider's `pending_approval` decision for that request. */
  decision: DecisionResponse;
  /** The original `tools/call`'s MCP progress token, when the calling client supplied one (P0-E6-T2) — threaded into the `ApprovalRequest` so any channel's heartbeat (block-and-wait's) can address it. */
  progressToken?: string | number;
  /**
   * The original `tools/call`'s JSON-RPC `id` (P0-E6-T4, R105) — NEVER the
   * internal `apr_...` approval id. Used ONLY to correlate a later
   * `notifications/cancelled` (which the MCP spec addresses by this same
   * JSON-RPC id) back to the approval this call created. Required: every
   * real `tools/call` this adapter is invoked for has one.
   */
  jsonRpcRequestId: string | number;
}

/** A strict SUBSET of `enforce.ts`'s `ApprovalResolution` — this adapter never produces `{outcome:"pending"}` (mirrors block-and-wait's own R93 terminal-only contract, now enforced one layer up). */
export type DispatchingApprovalResolution =
  | { outcome: "allow" }
  | { outcome: "deny"; reasonCode?: string };

export interface DispatchingApprovalOrchestrator {
  requestApproval(
    input: DispatchingApprovalRequestInput,
  ): Promise<DispatchingApprovalResolution>;
  /**
   * Best-effort: cancels the pending approval (if any) currently held for
   * `jsonRpcRequestId` (R105). A no-op — never throws — when no approval is
   * pending for that id (already resolved, or it was never a `pending_approval`
   * call at all), matching `IllegalApprovalTransitionError`'s own "already
   * terminal" case, which this method swallows rather than propagates: a
   * cancellation racing a human's own approve/deny is expected, not an error.
   */
  cancel(jsonRpcRequestId: string | number): Promise<void>;
}

export interface DispatchingApprovalOrchestratorDeps {
  /** The E6-T1 approval lifecycle orchestrator (`request`/`onResolved`/`cancel`). */
  orchestrator: ApprovalOrchestrator;
  /** The multi-channel dispatcher (R101) — typically `createMultiChannelDispatcher([blockAndWaitChannel, ...])`. */
  dispatcher: ApprovalDispatcher;
  /** Diagnostic sink, never the relayed/model-visible traffic. */
  logger?: (line: string) => void;
}

/**
 * `pending_approval` is only ever produced for `sensitive`/`critical` tiers
 * (never `routine`) — but `Tier` is a 3-value union and `ApprovalRequest.tier`
 * is typed to the narrower 2. Mirrors block-and-wait.ts's own identical
 * fail-safe (a `routine` value reaching here is a decider anomaly, not a real
 * runtime path; degrade to the more conservative `"critical"` rather than
 * throwing).
 */
function toApprovalTier(tier: Tier): "sensitive" | "critical" {
  return tier === "sensitive" || tier === "critical" ? tier : "critical";
}

function toApprovalRequest(
  input: DispatchingApprovalRequestInput,
): ApprovalRequest {
  const { request, decision } = input;
  return {
    decisionId: decision.decisionId,
    requestId: request.requestId,
    subject: request.subject,
    agent: request.context.agent,
    action: request.action,
    resource: request.resource,
    tier: toApprovalTier(decision.tier),
    eligibleChannels: ["block_and_wait"],
    decisionRequest: request,
    ...(input.progressToken !== undefined
      ? { progressToken: input.progressToken }
      : {}),
  };
}

/** `ApprovalState` → wire resolution (mirrors block-and-wait.ts's own R93 mapping, now the adapter's job). */
function toResolution(state: ApprovalState): DispatchingApprovalResolution {
  switch (state) {
    case "approved":
      return { outcome: "allow" };
    case "denied":
      return { outcome: "deny", reasonCode: "approval_denied" };
    case "expired":
      return { outcome: "deny", reasonCode: "approval_timeout" };
    case "cancelled":
      return { outcome: "deny", reasonCode: "approval_cancelled" };
    case "requested":
    case "pending":
      // Unreachable in practice — `onResolved()` only ever settles at one of
      // the four terminal states above. Fail closed rather than throw.
      return { outcome: "deny", reasonCode: "approval_internal_error" };
  }
}

/**
 * Creates the R102 proxy-facing adapter: `request → present → onResolved →
 * map`, plus the R105 cancellation bridge. See module header for the full
 * design.
 */
export function createDispatchingApprovalOrchestrator(
  deps: DispatchingApprovalOrchestratorDeps,
): DispatchingApprovalOrchestrator {
  // jsonRpcRequestId -> the lifecycle approval id it created. Populated the
  // instant `request()` resolves, removed once THIS call's own
  // `requestApproval` settles (approve/deny/timeout/cancel all funnel through
  // the same `finally` below) — never grows unbounded across calls.
  const pendingByJsonRpcId = new Map<string | number, string>();

  async function requestApproval(
    input: DispatchingApprovalRequestInput,
  ): Promise<DispatchingApprovalResolution> {
    const approvalRequest = toApprovalRequest(input);
    const handle = await deps.orchestrator.request(approvalRequest);
    pendingByJsonRpcId.set(input.jsonRpcRequestId, handle.id);
    try {
      await deps.dispatcher.present(
        approvalRequest,
        approvalRequest.decisionRequest.surface,
        handle,
      );
      const state = await deps.orchestrator.onResolved(handle.id);
      return toResolution(state);
    } finally {
      pendingByJsonRpcId.delete(input.jsonRpcRequestId);
    }
  }

  async function cancel(jsonRpcRequestId: string | number): Promise<void> {
    const approvalId = pendingByJsonRpcId.get(jsonRpcRequestId);
    if (approvalId === undefined) return; // nothing pending for this id — safe no-op.
    try {
      await deps.orchestrator.cancel(approvalId);
    } catch (err) {
      // Best-effort (R105): a cancellation racing the human's own approve/
      // deny (the lifecycle orchestrator's single-winner latch already
      // rejected one of them) is expected, not a caller-visible error.
      deps.logger?.(
        `knotrust: cancel(${String(jsonRpcRequestId)}) for approval ${approvalId} was a no-op (already resolved): ${errorMessage(err)}`,
      );
    }
  }

  return { requestApproval, cancel };
}
