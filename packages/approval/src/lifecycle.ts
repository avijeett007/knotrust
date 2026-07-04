/**
 * @knotrust/approval — the approval lifecycle state machine (P0-E6-T1;
 * rulings R86–R90; architecture §6.1/§6.2; PRD §7).
 *
 * ## State machine (R86)
 *
 * `requested → pending → (approved | denied | expired | cancelled)`. The
 * four right-hand states are TERMINAL: once a record reaches one, no further
 * transition is ever applied to it — a duplicate `resolve()`/`cancel()`, or
 * any attempt to move out of a terminal state, throws
 * `IllegalApprovalTransitionError` rather than silently overwriting it.
 * `request()` performs BOTH of the first two transitions synchronously
 * (`requested` is never observable to a caller unless the very first audit
 * append already failed — see "fail-closed on audit failure" below) —
 * matching architecture §6.1's `request(): Promise<ApprovalHandle> // →
 * requested → pending` comment.
 *
 * ## Approve ⇒ mint ⇒ RE-EVALUATE (R87 — the security heart)
 *
 * `resolve(id, "approved")` does NOT unconditionally resolve to `"approved"`.
 * It:
 *
 *   1. Audits `approval_approved` — a forensic fact ("the human approved at
 *      this instant"), independent of what happens next.
 *   2. Mints an ephemeral, single-use grant via the injected
 *      `mintEphemeralGrant`, bound via `ch = computeCallHash(frozenSnapshot)`
 *      to the FROZEN `DecisionRequest` snapshot captured at `request()` time
 *      (never the live/current request — see "the frozen snapshot" below).
 *   3. RE-EVALUATES that same frozen snapshot through the injected `decide`
 *      — the exact composition the proxy uses (unified decider: cache +
 *      grant collection + precedence + audit). This is the ONLY place the
 *      newly-minted grant can matter: precedence still runs, admin envelope
 *      still governs, self-escalation is still impossible.
 *   4. The approval's TERMINAL state is the re-evaluation's OUTCOME, not an
 *      unconditional allow: `outcome === "allow"` ⇒ terminal state
 *      `"approved"`; anything else (most notably an admin `denyTools`/
 *      `forceApprovalTiers` envelope change slipped in between `request()`
 *      and `resolve()`) ⇒ terminal state `"denied"`, with a SECOND,
 *      corrective audit event carrying the re-evaluation's own `reasonCode`
 *      — even though a human clicked approve. Approval satisfies a
 *      prerequisite; it never bypasses policy (PRD §7).
 *
 * This is why "approved" is reachable from `pending` but is not assigned
 * until AFTER re-evaluation returns — assigning it eagerly at step 1 and
 * later "changing" it to `"denied"` would itself violate the
 * terminal-states-are-immutable invariant this module enforces everywhere
 * else. The audit trail is the only place the human's vote and the policy's
 * final word are both visible.
 *
 * ## Concurrency: the in-flight latch (resolve/cancel are single-winner)
 *
 * `resolve()`'s approve path spans two `await`s (`mintEphemeralGrant`,
 * `decide`) between the `state === "pending"` guard and the terminal write.
 * Without a synchronous latch, two concurrent `resolve("approved")` calls (or
 * a `resolve("approved")` interleaved with a `cancel()`) would BOTH pass that
 * guard — minting/consuming two grants and emitting two `approval_approved`
 * events for one human click, or letting a late `resolve()` OVERWRITE a
 * terminal state a `cancel()` already wrote (an R86 violation). To prevent
 * this, the instant a resolve()/cancel() claims a still-`pending` record it
 * SYNCHRONOUSLY sets an internal `resolving` latch (before its first `await`);
 * any concurrent or re-entrant resolve()/cancel() then sees the latch and is
 * rejected with `IllegalApprovalTransitionError`. Only the latch-winner runs
 * mint/decide and writes the terminal state. `resolving` is an INTERNAL
 * per-record flag SEPARATE from the public `state` — it is never an
 * `ApprovalState`, never surfaced by `status()`/`ApprovalHandle` (R90), and
 * `onResolved()` still settles only at a true terminal state (`resolving` is
 * not terminal). `checkExpiry()` also skips a latched record, so a concurrent
 * expiry sweep cannot yank a mid-resolution record out from under its winner.
 *
 * ## Revoking the orphaned ephemeral grant on non-allow re-eval
 *
 * Because the ephemeral grant is minted BEFORE re-evaluation, a NON-`"allow"`
 * re-eval (e.g. a mid-flight envelope-deny) leaves a `ch`-bound, single-use
 * grant ACTIVE and unconsumed for its full TTL. On any non-allow outcome the
 * approve path therefore best-effort REVOKES that just-minted grant via the
 * injected `revokeGrant(jti)` (E6-T4 wires the real `revokeGrants`), closing
 * the exact-call replay window that a later lifting of the deny would open. A
 * revoke failure is surfaced to stderr and never alters the terminal deny.
 *
 * ## Fail-closed when mint/re-evaluation THROWS (the latch must never survive an error)
 *
 * `resolve()`'s approve path sets the synchronous `resolving` latch (above)
 * BEFORE its two `await`s, then runs `mintEphemeralGrant`/`decide`. If either
 * one REJECTS instead of resolving — a `store.put` failure inside the real
 * `mintEphemeralGrant`, an `AuditUnavailableError` at mint time, or any other
 * propagated exception — the record must not be left latched forever: with
 * `state` stuck at `"pending"` and `resolving` still `true`, `checkExpiry`
 * would keep exempting it from reclamation (see above), `sweepExpired` could
 * never sweep it, a rescue `resolve()`/`cancel()` would keep seeing the latch
 * and be rejected, and — worst of all — `onResolved()`'s `deferred` would
 * NEVER settle, hanging any caller awaiting it (block-and-wait, E6-T2)
 * permanently. `resolve()` therefore wraps the mint + re-evaluation (and the
 * outcome handling that follows) in a `try`/`catch`: on a throw from either,
 * the record is forced straight to terminal `"denied"` — the same terminal
 * state an admin force-deny reaches, just with `reason:
 * "approval_internal_error"` (a new, open-vocabulary reason distinct from
 * `"approval_denied"`/`"approval_timeout"`, so an auditor can tell "the
 * human's vote was overridden by policy" apart from "the approval pipeline
 * itself broke") rather than the re-evaluation's own `reasonCode`. Writing a
 * terminal `state` is what actually neutralizes the latch (every guard checks
 * `state !== "pending"` first; `resolving` itself is never cleared, per its
 * own doc above). The forced deny's own audit call is best-effort — a
 * throwing sink here is surfaced to stderr rather than re-thrown (an audit
 * failure while already handling a production error must not re-brick the
 * record) — and if `mintEphemeralGrant` had already returned before `decide`
 * threw, the now-orphaned grant is best-effort revoked via the same injected
 * `revokeGrant` FIX 3 uses, so a grant minted right before a crash does not
 * linger ACTIVE and consumable.
 *
 * ## The frozen snapshot
 *
 * `ApprovalRequest.decisionRequest` — the exact `DecisionRequest` the PDP
 * evaluated to `pending_approval` — is deep-cloned (`structuredClone`) and
 * deep-frozen (`Object.freeze`, recursively) the instant `request()` is
 * called, and every subsequent read (mint input, re-evaluation input, the
 * call-hash the mint step binds to) uses ONLY that frozen clone. A caller
 * that mutates the object it originally passed in has no effect on the
 * approval already in flight — this is what "the call-hash binds to THIS
 * snapshot" (R86) means operationally, and it is proven in this package's
 * tests by mutating the original object after `request()` returns and
 * asserting the eventually-minted grant's `ch` still matches the
 * PRE-mutation value.
 *
 * ## Extending architecture §6.1's `ApprovalRequest` sketch (documented deviation)
 *
 * The architecture-doc sketch (copied into this task's brief) lists
 * `subject`/`agent`/`action`/`resource` as top-level `ApprovalRequest`
 * fields (channel-display conveniences) but never says how the orchestrator
 * obtains a full `DecisionRequest` to call-hash and re-evaluate. R86 is
 * explicit that each approval record holds "the FROZEN DecisionRequest
 * snapshot," which requires the COMPLETE request (`context.arguments`,
 * `surface`, `toolAnnotations`, ...), not just those four decomposed
 * fields — `computeCallHash`'s SARC normal form alone reads `context.agent`
 * and `context.arguments`, neither reachable from the sketch's flat shape.
 * This module therefore adds one field, `decisionRequest: DecisionRequest`,
 * to `ApprovalRequest` — additive only; every field the architecture sketch
 * specifies is still present, for channel presentation use (E6-T2/T3/T4).
 *
 * P0-E6-T4 adds a second, equally additive field: `progressToken?: string |
 * number` — the original `tools/call`'s MCP progress token
 * (`params._meta.progressToken`), when the calling client supplied one. This
 * module never reads or reasons about it (no state-machine behavior depends
 * on it); it exists purely so the SAME `ApprovalRequest` object the E6-T4
 * proxy-facing adapter (`channel.ts`) builds and hands BOTH to `request()`
 * and to `dispatcher.present()` also carries what a channel's `notify()`
 * (block-and-wait's heartbeat, specifically) needs to address its
 * `notifications/progress` messages at the right client-side token — without
 * this module having to plumb it through `ApprovalRecord`/`resolve()`/
 * `onResolved()` at all. A channel reads `req.progressToken` straight off the
 * object `present()` handed it; this module is untouched either way.
 *
 * ## Expiry — no real timers (R86 ruling, documented)
 *
 * This module NEVER schedules a `setTimeout`/`setInterval` for expiry —
 * real timers make the state machine's most security-relevant edge case
 * (approve-after-deadline) non-deterministic and slow to test. Instead,
 * expiry is evaluated lazily, against the injected clock
 * (`deps.nowEpochSeconds()`), at the top of every method that touches a
 * specific approval (`status`, `resolve`, `cancel`, `onResolved`) — so a
 * call arriving after the deadline sees (and, if still `pending`, first
 * TRANSITIONS the record into) `"expired"` before any other logic runs.
 * Additionally, `sweepExpired(nowEpochSeconds)` — NOT part of the
 * architecture §6.1 sketch, added per R86's explicit instruction — lets a
 * host/proxy run a periodic sweep (its own timer, its own choice of
 * cadence) over every still-`pending` record, returning the ids that were
 * expired during that call. Both mechanisms share one `checkExpiry` step,
 * so they can never disagree about when a deadline has passed.
 *
 * ## Fail-closed on audit failure (R86)
 *
 * Every transition appends exactly one audit event via the injected
 * `AuditSink`. If `audit.append()` throws, the transition must not silently
 * proceed as if nothing happened (an ungoverned-and-unaudited approval is
 * the worst outcome for a "fully audited" product — the same doctrine
 * `@knotrust/grants`/`@knotrust/store` apply to decisions, R40). Instead the
 * record is forced straight to the terminal `"denied"` state (fail-closed),
 * and a best-effort SECOND audit call records that forced denial (a second
 * failure there is swallowed — the deny stands regardless). This applies
 * even to the very first `approval_requested` event: a request whose
 * opening audit line cannot be written never becomes a live `"pending"`
 * approval at all.
 *
 * ## No model-visible leakage (R90)
 *
 * `ApprovalHandle` is `{ id, state }` ONLY — never a token, a URL, or any
 * other channel-delivery detail. Approval records and the audit trail carry
 * full forensic detail (this is the human/audit side of the system), but
 * this module produces nothing a model ever reads; the model-visible
 * envelope remains the proxy's job (E5-T4). A future channel (E6-T3) that
 * mints a human-facing tokened URL must prefix it `tok_`, per the E5-T4
 * contract — that is the channel's concern, never this module's.
 *
 * ## Scope (R86.6)
 *
 * This module is deliberately free of any RUNTIME dependency on
 * `@knotrust/grants`/`@knotrust/store` — it imports ONLY their TYPES
 * (`MintEphemeralGrantInput`/`MintResult`/`AuditSink`), and calls them
 * exclusively through injected functions (`mintEphemeralGrant`, `decide`,
 * `audit`). `@knotrust/core` is imported normally (types, plus the
 * canonicalizer for the one small utility below) — that is explicitly
 * within R86.6's scope. Building the actual channels (block-and-wait is
 * E6-T2, the localhost page is E6-T3) or wiring this orchestrator to the
 * real proxy composition (E6-T4) is out of scope for this task.
 */

import { createHash } from "node:crypto";
import {
  type Action,
  type AgentIdentity,
  type ApprovalState,
  canonicalizeJcs,
  type DecisionRequest,
  type DecisionResponse,
  type Resource,
  type Subject,
} from "@knotrust/core";
import type { MintEphemeralGrantInput, MintResult } from "@knotrust/grants";
import type { AuditSink } from "@knotrust/store";

// ---------------------------------------------------------------------------
// Public shapes (architecture §6.1/§6.2 — copied, plus the documented
// `decisionRequest` addition above)
// ---------------------------------------------------------------------------

/** Architecture §6.2 — copied verbatim so E6-T2/T3/T4 import this rather than redefining it. */
export type ApprovalChannelKind =
  | "elicitation_form"
  | "elicitation_url"
  | "block_and_wait"
  | "web_push"
  | "sms";

export interface ApprovalRequest {
  decisionId: string;
  requestId: string;
  subject: Subject;
  agent: AgentIdentity;
  action: Action;
  resource: Resource;
  tier: "sensitive" | "critical";
  /** Filtered by surface + client capability + context — this module does not filter it further. */
  eligibleChannels: ApprovalChannelKind[];
  /** Default 300s (§ Decision) when omitted — see `CreateApprovalOrchestratorDeps.defaultTimeoutSeconds`. */
  timeoutSeconds?: number;
  /** The full originating `DecisionRequest` this approval is FOR. See module header, "Extending §6.1's sketch." */
  decisionRequest: DecisionRequest;
  /**
   * The original `tools/call`'s MCP progress token (P0-E6-T4), when the
   * calling client supplied one. See module header, "Extending §6.1's
   * sketch" — this module never reads it; it is a pass-through convenience
   * for a channel's `notify()` (block-and-wait's heartbeat, specifically).
   */
  progressToken?: string | number;
}

/** `{id, state}` ONLY — see module header, "No model-visible leakage." */
export interface ApprovalHandle {
  id: string;
  state: ApprovalState;
}

/**
 * The shape this module calls to mint an ephemeral grant — structurally
 * identical to `@knotrust/grants`' real `mintEphemeralGrant`, minus its
 * second (`LifecycleMintDeps`) argument: the proxy (E6-T4) wires a closure
 * over the real store/keyStore/clock/audit and hands this module the
 * single-argument partial application, keeping this module free of a
 * runtime dependency on `@knotrust/grants` (R86.6).
 */
export type MintEphemeralGrantFn = (
  input: MintEphemeralGrantInput,
) => Promise<MintResult>;

/** The unified decider's `decide` — same composition the proxy calls (R87b). */
export type DecideFn = (request: DecisionRequest) => Promise<DecisionResponse>;

export interface CreateApprovalOrchestratorDeps {
  mintEphemeralGrant: MintEphemeralGrantFn;
  decide: DecideFn;
  /**
   * Best-effort revoke of a just-minted ephemeral grant by `jti` — injected so
   * this module keeps NO runtime dependency on `@knotrust/grants` (R86.6); the
   * proxy (E6-T4) wires it over `@knotrust/grants`' `revokeGrants({ jti }, …)`.
   *
   * Called ONLY on the approve path when re-evaluation returns a NON-`"allow"`
   * outcome (FIX 3, the replay-window fix). The ephemeral grant is minted
   * BEFORE re-eval, so a mid-flight envelope-deny would otherwise leave a
   * `ch`-bound, single-use grant ACTIVE and unconsumed for its full ~120s TTL
   * — if that deny were lifted within the window, an exact-call replay could
   * authorize off the stale grant with no fresh approval. Revoking the grant
   * closes that window. The revoke is best-effort: a failure is surfaced to
   * stderr and NEVER changes the terminal deny outcome.
   *
   * Optional: there is no production caller until E6-T4 wires it. When omitted,
   * the orphaned grant is left to lapse on its own TTL (pre-fix behavior).
   */
  revokeGrant?(jti: string): void | Promise<void>;
  audit: AuditSink;
  /** Injected epoch-seconds clock. Never `Date.now()` internally. */
  nowEpochSeconds(): number;
  /** Injected id source — core's ULID generator in production. Prefixed `"apr_"` here, not by the caller. */
  generateId(): string;
  /** Default approval timeout in seconds when `ApprovalRequest.timeoutSeconds` is omitted. Default 300. */
  defaultTimeoutSeconds?: number;
}

export interface ApprovalOrchestrator {
  request(req: ApprovalRequest): Promise<ApprovalHandle>;
  status(id: string): Promise<ApprovalHandle>;
  /**
   * `resolvedChannel` is an addition to architecture §6.1's two-argument
   * sketch (R88: "record the resolution channel so E6-T2/T4 slot in") —
   * optional so today's zero callers (no channel exists yet) are unaffected.
   */
  resolve(
    id: string,
    r: "approved" | "denied",
    resolvedChannel?: ApprovalChannelKind,
  ): Promise<void>;
  cancel(id: string): Promise<void>;
  onResolved(id: string): Promise<ApprovalState>;
  /**
   * NOT part of the architecture §6.1 sketch — added per R86's explicit
   * instruction (no real timers in this module; a host/proxy-driven sweep
   * is the alternative). Expires every still-`pending` record whose
   * deadline is `<= nowEpochSeconds`, audits each, and resolves its
   * `onResolved()` waiter as `"expired"`. Returns the ids that transitioned
   * during THIS call (already-terminal records are untouched and never
   * included).
   */
  sweepExpired(nowEpochSeconds: number): string[];
}

export class ApprovalNotFoundError extends Error {
  constructor(id: string) {
    super(`knotrust: no approval found with id ${id}`);
    this.name = "ApprovalNotFoundError";
  }
}

export class IllegalApprovalTransitionError extends Error {
  /**
   * `from` is widened to include the internal `"resolving"` in-flight latch
   * (see `ApprovalRecord.resolving`): a second, concurrent/re-entrant
   * resolve()/cancel() that loses the latch race is rejected with an accurate
   * forensic reason. `"resolving"` is NOT an `ApprovalState` and is never
   * exposed via `status()`/`ApprovalHandle` — it appears only in this error's
   * message (the human/audit side), never model-visible (R90).
   */
  constructor(
    id: string,
    from: ApprovalState | "resolving",
    attempted: string,
  ) {
    super(
      `knotrust: illegal approval transition — ${id} is in terminal/non-pending state "${from}", cannot ${attempted}`,
    );
    this.name = "IllegalApprovalTransitionError";
  }
}

const DEFAULT_TIMEOUT_SECONDS = 300;

const TERMINAL_STATES: ReadonlySet<ApprovalState> = new Set([
  "approved",
  "denied",
  "expired",
  "cancelled",
]);

/**
 * Mirrors `@knotrust/store`'s `AuditEventType` open vocabulary (`approval_*`
 * members) WITHOUT importing it — `AuditEvent.type` is a plain `string`
 * (open vocabulary, per that module's own header), so matching the literal
 * values is sufficient and keeps this module free of a runtime
 * `@knotrust/store` dependency (R86.6). Keep these six strings byte-for-byte
 * identical to `@knotrust/store`'s `AuditEventType` if that vocabulary ever
 * changes.
 */
const ApprovalAuditType = {
  Requested: "approval_requested",
  Pending: "approval_pending",
  Approved: "approval_approved",
  Denied: "approval_denied",
  Expired: "approval_expired",
  Cancelled: "approval_cancelled",
} as const;

// ---------------------------------------------------------------------------
// computeArgsHash — a deliberate, documented duplicate of
// `@knotrust/store`'s function of the same name/formula (R86.6 keeps this
// module free of a runtime `@knotrust/store` dependency). This repo already
// establishes the pattern of duplicating one small cross-layer helper rather
// than creating a dependency edge purely for it — see `@knotrust/store`'s
// `grant-store.ts`/`@knotrust/grants`'s `keys.ts`, both of which duplicate
// `resolveKnotrustHome` for the identical reason. Keep the formula
// (`"sha256:" + hex(SHA-256(utf8(canonicalizeJcs(args ?? null))))`, never
// throwing) in sync with that module if it ever changes.
// ---------------------------------------------------------------------------

function computeArgsHash(args: unknown): string {
  const normalized = args ?? null;
  let canonical: string;
  try {
    canonical = canonicalizeJcs(normalized);
  } catch {
    return "unavailable";
  }
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `sha256:${digest}`;
}

// ---------------------------------------------------------------------------
// Frozen-snapshot helpers
// ---------------------------------------------------------------------------

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  if (!Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value as Record<string, unknown>)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
  }
  return value;
}

/** Deep-clones (so a caller's later mutation of its own object has zero effect) then deep-freezes (so nothing downstream can mutate it either). */
function freezeSnapshot(request: DecisionRequest): DecisionRequest {
  return deepFreeze(structuredClone(request));
}

/** Mirrors `@knotrust/store`'s `errorMessage` — total, never throws. */
function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Deferred — backs `onResolved()`
// ---------------------------------------------------------------------------

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolveFn: ((value: T) => void) | undefined;
  const promise = new Promise<T>((res) => {
    resolveFn = res;
  });
  // The executor above runs SYNCHRONOUSLY during `new Promise(...)` (per
  // spec), so `resolveFn` is always assigned by the time we reach here.
  return { promise, resolve: resolveFn as (value: T) => void };
}

// ---------------------------------------------------------------------------
// Internal record
// ---------------------------------------------------------------------------

interface ApprovalRecord {
  id: string;
  state: ApprovalState;
  decisionId: string;
  requestId: string;
  tier: "sensitive" | "critical";
  eligibleChannels: ApprovalChannelKind[];
  timeoutSeconds: number;
  /** Epoch seconds, from the injected clock. */
  requestedAt: number;
  frozenSnapshot: DecisionRequest;
  resolvedChannel?: ApprovalChannelKind;
  deferred: Deferred<ApprovalState>;
  /**
   * Internal, synchronous in-flight latch — SEPARATE from the public `state`
   * (never surfaced via `status()`/`ApprovalHandle`, R90). Set `true` the
   * instant a resolve()/cancel() claims a still-`pending` record, BEFORE the
   * first `await`, so any concurrent or re-entrant resolve()/cancel() sees a
   * latched record and is rejected immediately — only the latch-winner runs
   * mint/decide and writes the terminal state (FIX 1: closes the
   * check-then-act race across `resolve()`'s two awaits). Not an
   * `ApprovalState` value; the corresponding illegal-transition error reports
   * it as `"resolving"`. Left `true` once set (a terminal `state` dominates
   * every guard regardless), so it never needs clearing.
   */
  resolving?: boolean;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createApprovalOrchestrator(
  deps: CreateApprovalOrchestratorDeps,
): ApprovalOrchestrator {
  const records = new Map<string, ApprovalRecord>();
  const defaultTimeoutSeconds =
    deps.defaultTimeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;

  function getRecordOrThrow(id: string): ApprovalRecord {
    const record = records.get(id);
    if (record === undefined) {
      throw new ApprovalNotFoundError(id);
    }
    return record;
  }

  function toHandle(record: ApprovalRecord): ApprovalHandle {
    return { id: record.id, state: record.state };
  }

  /**
   * Appends one audit event for `record`. Returns `true` on success. On any
   * throw from `deps.audit.append`, forces `record` fail-closed to a
   * terminal `"denied"` (see module header) and returns `false` — callers
   * use the return value to short-circuit whatever security-sensitive work
   * (minting, re-evaluation) would otherwise follow.
   */
  function safeAudit(
    record: ApprovalRecord,
    partial: { type: string; reason?: string; grantRefs?: string[] },
  ): boolean {
    try {
      deps.audit.append({
        type: partial.type,
        surface: record.frozenSnapshot.surface.kind,
        subject: record.frozenSnapshot.subject.id,
        agent: record.frozenSnapshot.context.agent.id,
        tool: record.frozenSnapshot.action.name,
        argsHash: computeArgsHash(record.frozenSnapshot.context.arguments),
        approvalId: record.id,
        ...(partial.reason !== undefined ? { reason: partial.reason } : {}),
        ...(partial.grantRefs !== undefined
          ? { grantRefs: partial.grantRefs }
          : {}),
      });
      return true;
    } catch (err) {
      // FIX 2: on the deny/cancel/expire paths the terminal `state` is written
      // BEFORE this audit call, so `forceFailClosedDeny` below no-ops (already
      // terminal) and this transition's audit failure would otherwise be lost
      // silently — the forensic `approval_denied`/`approval_cancelled`/
      // `approval_expired` line simply never appears. Capture whether the
      // record was already terminal, then, if so, surface the failure to
      // stderr (mirroring the audit sink's own fail-closed stderr notice) so
      // "every transition is audited, or its audit-failure is itself recorded"
      // still holds (R86). On non-terminal paths (request/approved-audit) the
      // fail-closed deny captures it, so no stderr line is needed there.
      const alreadyTerminal = TERMINAL_STATES.has(record.state);
      forceFailClosedDeny(record, "audit_unavailable");
      if (alreadyTerminal) {
        process.stderr.write(
          `knotrust: approval audit append failed for "${partial.type}" on ${record.id} ` +
            `(already-terminal state "${record.state}"; could not be captured as a fail-closed deny): ` +
            `${errorMessage(err)}\n`,
        );
      }
      return false;
    }
  }

  /**
   * Forces `record` straight to terminal `"denied"`, bypassing normal
   * transition validation — the fail-closed posture this module's OWN audit
   * failures require (R86). No-op if already terminal. Best-effort audits
   * the forced denial itself; a second failure is swallowed (mirrors
   * `@knotrust/grants`' R40 doctrine: the deny stands regardless).
   */
  function forceFailClosedDeny(record: ApprovalRecord, reason: string): void {
    if (TERMINAL_STATES.has(record.state)) return;
    record.state = "denied";
    record.deferred.resolve("denied");
    try {
      deps.audit.append({
        type: ApprovalAuditType.Denied,
        surface: record.frozenSnapshot.surface.kind,
        subject: record.frozenSnapshot.subject.id,
        agent: record.frozenSnapshot.context.agent.id,
        tool: record.frozenSnapshot.action.name,
        argsHash: computeArgsHash(record.frozenSnapshot.context.arguments),
        approvalId: record.id,
        reason,
      });
    } catch {
      // Best-effort — the fail-closed deny stands regardless.
    }
  }

  /**
   * Forces `record` straight to terminal `"denied"` when the approve path's
   * mint/re-evaluation THROWS (FIX 4 — see module header, "Fail-closed when
   * mint/re-evaluation THROWS"). No-op if already terminal (defensive; the
   * `resolving` latch held throughout mint/decide means nothing else can have
   * raced it there, but a stray double-fault must never attempt a second
   * terminal write regardless). Unlike `forceFailClosedDeny` above — where a
   * SECOND audit failure is documented/tested as silently swallowed, because
   * that helper exists specifically to handle THIS module's own audit-append
   * failures — an audit failure here is surfaced to stderr: this path is
   * already reporting an unrelated production error (the mint/decide throw
   * itself), and losing the forced-deny's forensic line silently on top of
   * that would leave no trace of either failure.
   */
  function forceFailClosedDenyOnThrow(
    record: ApprovalRecord,
    reason: string,
  ): void {
    if (TERMINAL_STATES.has(record.state)) return;
    record.state = "denied";
    record.deferred.resolve("denied");
    try {
      deps.audit.append({
        type: ApprovalAuditType.Denied,
        surface: record.frozenSnapshot.surface.kind,
        subject: record.frozenSnapshot.subject.id,
        agent: record.frozenSnapshot.context.agent.id,
        tool: record.frozenSnapshot.action.name,
        argsHash: computeArgsHash(record.frozenSnapshot.context.arguments),
        approvalId: record.id,
        reason,
      });
    } catch (err) {
      process.stderr.write(
        `knotrust: approval audit append failed while recording fail-closed deny for ${record.id} ` +
          `(deny already applied regardless): ${errorMessage(err)}\n`,
      );
    }
  }

  /** Lazily expires `record` if `pending` and its deadline has passed. Idempotent. */
  function checkExpiry(record: ApprovalRecord, now: number): void {
    if (record.state !== "pending") return;
    // FIX 1: a resolve()/cancel() latch-winner has claimed this still-`pending`
    // record and is mid-flight (between its guard and its terminal write). Do
    // NOT expire it out from under that winner — doing so would let the
    // winner's terminal write overwrite an `"expired"` terminal state (an R86
    // terminal-immutability violation). The winner writes the true terminal
    // state momentarily; expiry (if still due) applies to records nobody owns.
    if (record.resolving === true) return;
    if (now < record.requestedAt + record.timeoutSeconds) return;
    record.state = "expired";
    record.deferred.resolve("expired");
    safeAudit(record, {
      type: ApprovalAuditType.Expired,
      reason: "approval_timeout",
    });
  }

  async function request(req: ApprovalRequest): Promise<ApprovalHandle> {
    const id = `apr_${deps.generateId()}`;
    const record: ApprovalRecord = {
      id,
      state: "requested",
      decisionId: req.decisionId,
      requestId: req.requestId,
      tier: req.tier,
      eligibleChannels: req.eligibleChannels,
      timeoutSeconds: req.timeoutSeconds ?? defaultTimeoutSeconds,
      requestedAt: deps.nowEpochSeconds(),
      frozenSnapshot: freezeSnapshot(req.decisionRequest),
      deferred: createDeferred<ApprovalState>(),
    };
    records.set(id, record);

    if (!safeAudit(record, { type: ApprovalAuditType.Requested })) {
      return toHandle(record); // already forced fail-closed to "denied"
    }

    record.state = "pending";
    safeAudit(record, { type: ApprovalAuditType.Pending });
    return toHandle(record);
  }

  async function status(id: string): Promise<ApprovalHandle> {
    const record = getRecordOrThrow(id);
    checkExpiry(record, deps.nowEpochSeconds());
    return toHandle(record);
  }

  async function resolve(
    id: string,
    r: "approved" | "denied",
    resolvedChannel?: ApprovalChannelKind,
  ): Promise<void> {
    const record = getRecordOrThrow(id);
    checkExpiry(record, deps.nowEpochSeconds());
    // FIX 1: reject if already terminal/non-pending OR already latched by a
    // concurrent/re-entrant resolve()/cancel() (`resolving`). `getRecordOrThrow`
    // and `checkExpiry` are synchronous, so this guard-then-latch pair runs
    // atomically w.r.t. the event loop — no `await` between the check and the
    // claim below.
    if (record.state !== "pending" || record.resolving === true) {
      throw new IllegalApprovalTransitionError(
        id,
        record.resolving === true ? "resolving" : record.state,
        `resolve(..., "${r}")`,
      );
    }
    // Synchronous in-flight latch: claim the record BEFORE the first `await`
    // (mint/decide below), so a concurrent resolve()/cancel() is rejected by
    // the guard above rather than passing it and double-processing.
    record.resolving = true;
    if (resolvedChannel !== undefined) {
      record.resolvedChannel = resolvedChannel;
    }

    if (r === "denied") {
      record.state = "denied";
      record.deferred.resolve("denied");
      safeAudit(record, {
        type: ApprovalAuditType.Denied,
        reason: "approval_denied",
      });
      return;
    }

    // r === "approved" — R87, the security heart. See module header.
    if (!safeAudit(record, { type: ApprovalAuditType.Approved })) {
      return; // already forced fail-closed to "denied"; mint/re-eval skipped
    }

    // FIX 4: `minted` is read in the `catch` below (to best-effort revoke a
    // grant that was minted before `decide` threw), so it is declared outside
    // the `try` as `MintResult | undefined` rather than via a
    // definite-assignment `!` (biome forbids non-null assertions);
    // `undefined` there means `mintEphemeralGrant` itself never returned.
    let minted: MintResult | undefined;
    try {
      minted = await deps.mintEphemeralGrant({
        request: record.frozenSnapshot,
        tier: record.tier,
      });

      const decision = await deps.decide(record.frozenSnapshot);

      if (decision.outcome === "allow") {
        record.state = "approved";
        record.deferred.resolve("approved");
        return;
      }

      // Mid-flight admin override (or any other non-"allow" re-evaluation
      // outcome): the human's "approved" vote was already audited above as a
      // forensic fact, but the record's TERMINAL state reflects what the
      // policy actually decided — approval satisfies a prerequisite, it never
      // bypasses policy (PRD §7). `minted.jti` is included so an auditor can
      // see the ephemeral grant existed and was NOT the deciding factor.
      record.state = "denied";
      record.deferred.resolve("denied");
      safeAudit(record, {
        type: ApprovalAuditType.Denied,
        reason: decision.reasonCode,
        grantRefs: [minted.jti],
      });

      // FIX 3: re-eval was NOT "allow", so the ephemeral grant minted above is
      // orphaned — ACTIVE and unconsumed, yet ch-bound and single-use. Left to
      // lapse on its own ~120s TTL, an exact-call replay could authorize off it
      // if the mid-flight deny were lifted within that window, with no fresh
      // approval. Best-effort revoke it now to close that window. A revoke
      // failure is surfaced to stderr and NEVER changes the terminal deny that
      // has already been written/audited/settled above. When no `revokeGrant`
      // is wired (no production caller until E6-T4), the grant is left to expire.
      if (deps.revokeGrant !== undefined) {
        try {
          await deps.revokeGrant(minted.jti);
        } catch (err) {
          process.stderr.write(
            `knotrust: failed to revoke orphaned ephemeral grant ${minted.jti} ` +
              `for ${record.id} after non-allow re-evaluation: ${errorMessage(err)}\n`,
          );
        }
      }
    } catch (err) {
      // FIX 4: `mintEphemeralGrant`/`decide` THREW rather than returning a
      // non-"allow" outcome — see module header, "Fail-closed when
      // mint/re-evaluation THROWS." Left uncaught, this would leave `record`
      // latched (`resolving === true`, `state` stuck at `"pending"`) forever
      // — `checkExpiry` exempts latched records from reclamation, so neither
      // a later `status()`/`onResolved()` call nor `sweepExpired` could ever
      // reclaim it, and a rescue `resolve()`/`cancel()` would keep seeing the
      // latch and be rejected — worst of all, `onResolved()`'s `deferred`
      // would never settle, hanging the awaiting caller (block-and-wait,
      // E6-T2) permanently. Resolve fail-closed to terminal `"denied"`
      // instead; the latch never needs clearing (a terminal `state`
      // dominates every guard, per `ApprovalRecord.resolving`'s own doc).
      process.stderr.write(
        `knotrust: approval mint/re-evaluation threw for ${record.id}; ` +
          `resolving fail-closed to "denied": ${errorMessage(err)}\n`,
      );
      forceFailClosedDenyOnThrow(record, "approval_internal_error");
      // `mintEphemeralGrant` may have already returned before `decide` threw
      // — that grant is now orphaned (ACTIVE, unconsumed, ch-bound,
      // single-use) exactly like the non-allow re-eval case above (FIX 3), so
      // it gets the same best-effort revoke.
      if (minted !== undefined && deps.revokeGrant !== undefined) {
        try {
          await deps.revokeGrant(minted.jti);
        } catch (revokeErr) {
          process.stderr.write(
            `knotrust: failed to revoke orphaned ephemeral grant ${minted.jti} ` +
              `for ${record.id} after mint/re-evaluation threw: ${errorMessage(revokeErr)}\n`,
          );
        }
      }
    }
  }

  async function cancel(id: string): Promise<void> {
    const record = getRecordOrThrow(id);
    checkExpiry(record, deps.nowEpochSeconds());
    // FIX 1: reject if already terminal/non-pending OR already latched by a
    // concurrent/re-entrant resolve()/cancel(). This is what makes the
    // resolve("approved")+cancel() interleaving safe: if a resolve("approved")
    // has already latched the record and parked at its mint/decide await, this
    // cancel() sees `resolving === true` and is rejected here — it can no
    // longer write "cancelled" only for the resolve winner to overwrite it.
    if (record.state !== "pending" || record.resolving === true) {
      throw new IllegalApprovalTransitionError(
        id,
        record.resolving === true ? "resolving" : record.state,
        "cancel()",
      );
    }
    // Synchronous latch — cancel() is fully synchronous through its terminal
    // write below, but claiming the latch keeps the guard symmetric with
    // resolve() and blocks any re-entrant resolve() an audit sink might trigger.
    record.resolving = true;
    record.state = "cancelled";
    record.deferred.resolve("cancelled");
    safeAudit(record, {
      type: ApprovalAuditType.Cancelled,
      reason: "approval_cancelled",
    });
  }

  async function onResolved(id: string): Promise<ApprovalState> {
    const record = getRecordOrThrow(id);
    checkExpiry(record, deps.nowEpochSeconds());
    return record.deferred.promise;
  }

  function sweepExpired(now: number): string[] {
    const expiredIds: string[] = [];
    for (const record of records.values()) {
      if (record.state !== "pending") continue;
      checkExpiry(record, now);
      // `checkExpiry` may have just mutated `record.state` to `"expired"`.
      // TS's control-flow narrowing does not account for that mutation
      // happening inside the call above, so it still treats `record.state`
      // as the pre-call `"pending"` literal here — hence the explicit
      // re-widen via `as ApprovalState` rather than a genuinely-impossible
      // comparison.
      if ((record.state as ApprovalState) === "expired") {
        expiredIds.push(record.id);
      }
    }
    return expiredIds;
  }

  return { request, status, resolve, cancel, onResolved, sweepExpired };
}
