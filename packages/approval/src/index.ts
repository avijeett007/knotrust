/**
 * @knotrust/approval — approval orchestrator v0: lifecycle state machine, the block-and-wait terminal channel, and the localhost approval page
 *
 * Phase-0 epic: P0-E6.
 * P0-E6-T1 landed the approval lifecycle state machine (lifecycle.ts,
 * rulings R86–R90): `requested → pending → approved|denied|expired|
 * cancelled` (terminal, immutable), with `resolve(id, "approved")` minting a
 * call-hash-bound ephemeral single-use grant and RE-EVALUATING the frozen
 * `DecisionRequest` snapshot through the injected `decide` — approval
 * satisfies a prerequisite, it never bypasses policy (PRD §7).
 * P0-E6-T2 (`channels/block-and-wait.ts`, rulings R91–R95) landed the
 * universal block-and-wait terminal channel: it drives the E6-T1
 * orchestrator through `request()`/`onResolved()`, presents the pending
 * approval to the human via stderr + a `$KNOTRUST_HOME/pending/<id>.json`
 * record (tokened URL, human channels ONLY), emits token-free
 * `notifications/progress` heartbeats while held, and always resolves to a
 * terminal `allow`/`deny` — never `pending_approval` on the wire.
 * P0-E6-T3 (`channels/local-page/`, rulings R96–R100) landed the localhost
 * approval page: a loopback-only, framework-free `node:http` server (ONE
 * `createApprovalPageServer(deps)`, embedded HTML/CSS string assets —
 * survives tsup bundling into the CLI, no runtime file reads) that lets a
 * human Approve-once / Always-allow (mints a durable grant, visible scope +
 * expiry, before resolving) / Deny a pending approval, hardened against the
 * full web-attack battery: loopback bind, `Host` validation (DNS-rebinding
 * defense), `Origin` validation, a CSRF token distinct from the single-use
 * `tok_` URL token, POST-only mutations, no cookies, and HTML-escaped
 * argument rendering. `channels/local-page/registry.ts`'s
 * `withApprovalRequestRegistry` is the minimal wiring seam that lets this
 * page render from the SAME frozen `ApprovalRequest` snapshot the E6-T1
 * orchestrator captured, without any change to `lifecycle.ts`'s or
 * `block-and-wait.ts`'s own contracts.
 * P0-E6-T4 (`channel.ts`, rulings R101–R105) closes the epic: formalizes the
 * `ApprovalChannel` interface (`kind`/`available`/`notify`) both
 * block-and-wait and future Phase-1/2 channels implement, a
 * `MultiChannelDispatcher` (`createMultiChannelDispatcher`) that notifies
 * EVERY available registered channel (not just the first — R101), and
 * `createDispatchingApprovalOrchestrator`, the adapter that satisfies
 * `@knotrust/proxy-stdio`'s `enforce.ts` seam by running `request → present
 * → onResolved → map` (R102) and bridges client-cancellation by JSON-RPC
 * request id (R105). `block-and-wait.ts` was reshaped to CONFORM to
 * `ApprovalChannel` (`notify(req, handle)` replaces the old monolithic
 * `requestApproval(input)`) with zero change to its hold/heartbeat/token
 * properties.
 */
export const PKG = "@knotrust/approval";

export * from "./channel.js";
export * from "./channels/block-and-wait.js";
export * from "./channels/local-page/index.js";
export * from "./lifecycle.js";
