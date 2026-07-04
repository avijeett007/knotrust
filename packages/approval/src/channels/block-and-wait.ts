/**
 * @knotrust/approval — the block-and-wait terminal channel (P0-E6-T2,
 * refactored to CONFORM to the formal `ApprovalChannel` interface in
 * P0-E6-T4; rulings R91–R95, R101; brief §I1/§I2.2; architecture §6.1/§6.2).
 *
 * This is the universal approval fallback that must work on EVERY MCP
 * client (brief §C3/§F): when the unified decider returns `pending_approval`
 * for a `critical` (or envelope-forced) call, this channel is the ALWAYS-
 * AVAILABLE floor `ApprovalChannel` (`kind: "block_and_wait"`, `available()`
 * unconditionally `true`) whose `notify()` presents a fixed-template
 * approval prompt to the HUMAN via stderr (+ a
 * `$KNOTRUST_HOME/pending/<id>.json` record, both carrying the tokened
 * approval URL) and, in the BACKGROUND, emits `notifications/progress`
 * heartbeats to keep the calling MCP client from timing the call out until a
 * TERMINAL `allow`/`deny` is reached (R93). Holding the call itself — the
 * in-flight `tools/call` never surfacing `pending_approval` back to the
 * model — is now the JOINT responsibility of this channel's background
 * hold-until-resolved loop and `channel.ts`'s `createDispatchingApprovalOrchestrator`,
 * which is the piece that actually `await`s the lifecycle orchestrator's
 * `onResolved()` before answering the proxy (R101/R102 — see that module's
 * header for the full sequence).
 *
 * ## P0-E6-T4's reshape: `requestApproval(input)` → `notify(req, handle)`
 *
 * Before this task, `createBlockAndWaitChannel(...)` returned a single
 * `requestApproval(input): Promise<BlockAndWaitResolution>` that did
 * EVERYTHING itself: build the `ApprovalRequest`, call the lifecycle
 * orchestrator's `request()`, present, heartbeat, and `await onResolved()`
 * before returning the terminal resolution. That shape could not host a
 * SECOND channel alongside it (R104's multi-channel proof) because nothing
 * outside this module ever saw the `ApprovalRequest`/`ApprovalHandle` a
 * second channel would need to be notified with — this module built and
 * consumed them privately, end to end.
 *
 * `channel.ts`'s `ApprovalChannel` interface pulls `request()` (creating the
 * handle) and the wire-facing DecisionRequest→ApprovalRequest
 * conversion/ApprovalState→resolution mapping OUT of this module and into
 * the new `createDispatchingApprovalOrchestrator` adapter, which now owns
 * calling `request()` ONCE and handing the resulting `(req, handle)` to
 * EVERY registered channel's `notify()` (via `createMultiChannelDispatcher`,
 * R101) — this is what makes a second, independent channel possible without
 * touching this module at all. What THIS module keeps, unchanged in
 * substance (R101's explicit instruction: "the block-and-wait-specific
 * await + heartbeat hold logic stays"):
 *
 *   - `presentApprovalToHuman` (R91a) — the fixed-template stderr prompt +
 *     the `$KNOTRUST_HOME/pending/<id>.json` record, both still carrying the
 *     tokened URL, still NEVER reaching `sendNotification`/the wire (R92).
 *   - The periodic heartbeat/expiry-probe scheduler (R91) — forces the
 *     lifecycle orchestrator's lazy expiry check and, when the original call
 *     carried a `progressToken`, emits token-free `notifications/progress`
 *     heartbeats.
 *   - Token minting/routing (R92). The terminal-only `ApprovalState` →
 *     wire-resolution mapping, by contrast, now lives in `channel.ts`
 *     (`toResolution`) — answering the proxy is the ADAPTER's job, not this
 *     channel's; the PROPERTY the mapping encodes (the wire never sees
 *     `pending_approval`) is unaffected. This channel simply never produces
 *     or returns a resolution at all anymore; it only presents and waits in
 *     the background to know when to stop.
 *
 * The one behavioral reshape: `notify()` returns (resolves) once
 * presentation is under way and the background hold has been KICKED OFF —
 * NOT once the human has acted. The actual multi-minute wait now happens
 * entirely in the background (`deps.orchestrator.onResolved(handle.id).then(
 * ...)`, fire-and-forget), which is what lets `createMultiChannelDispatcher`
 * notify a SECOND channel concurrently without waiting on this one's full
 * hold duration first (R101's "notify-all" property). The caller that
 * actually needs the terminal outcome — `createDispatchingApprovalOrchestrator`
 * — awaits the SAME lifecycle orchestrator's `onResolved(handle.id)`
 * directly, itself, which resolves at the exact same instant this channel's
 * own background watcher does (they are two `.then` continuations off the
 * identical promise) — so nothing about WHEN the hold actually ends changes,
 * only who is awaiting it and how many parties can watch it happen.
 *
 * ## Two orchestrators, two different jobs — do not conflate
 *
 * This module drives `@knotrust/approval`'s OWN `ApprovalOrchestrator` (the
 * E6-T1 lifecycle state machine: `request`/`status`/`resolve`/`cancel`/
 * `onResolved`) for its `status()`/`onResolved()` methods ONLY now (`request()`
 * is the adapter's call, not this module's) — a completely different
 * interface from `enforce.ts`'s proxy-facing `ApprovalOrchestrator` seam,
 * which this module no longer touches at all (that seam is
 * `channel.ts`/`createDispatchingApprovalOrchestrator`'s job as of P0-E6-T4).
 *
 * ## R91 — the present → (background) hold → resolve sequence
 *
 * `notify(req, handle)`:
 *
 *   1. `presentApprovalToHuman(...)` — R91a: prints a fixed-template prompt
 *      (tool, server, tier, a short human-readable code, and the tokened
 *      approval URL) to stderr ONLY, and writes
 *      `$KNOTRUST_HOME/pending/<approvalId>.json` (the human/audit-side
 *      record `knotrust approvals`, E7, will read) — carrying the SAME
 *      token. Both are human channels; NEITHER is ever handed to
 *      `sendNotification` (see R92 below).
 *   2. Starts one periodic scheduler tick (`deps.scheduler`, default
 *      `setInterval`-backed, injectable for tests — R91's "expose a
 *      tick()") that BOTH (a) forces the lifecycle orchestrator's lazy
 *      expiry check (`orchestrator.status(id)` — R86's own documented
 *      mechanism: expiry is evaluated only when some method touches the
 *      record, so something must call one periodically or a timed-out hold
 *      would never actually settle) and (b) — only when the original
 *      `tools/call` carried a `progressToken` (now read straight off `req`,
 *      P0-E6-T4) — emits a `notifications/progress` heartbeat carrying
 *      NOTHING but a token-free progress count and a static message
 *      (R91a/R92: "carries NO token/policy internals").
 *   3. Fire-and-forget: `orchestrator.onResolved(handle.id)` — the SAME
 *      deferred `onResolved()` the periodic expiry probe (step 2) and/or an
 *      external `resolve()`/`cancel()` call settles — is chained with a
 *      background `.then()` that stops the scheduler and best-effort removes
 *      the now-resolved pending record (the human record's purpose — "this
 *      is still open" — no longer holds once terminal).
 *   4. Returns (resolves) immediately after kicking off steps 1–3 — it does
 *      NOT await the human's decision itself (see module header for why).
 *
 * ## R92 — token routing is the security property
 *
 * The tokened approval URL is delivered to the human via stderr
 * (`presentApprovalToHuman`) and the pending-record file ONLY. It is NEVER
 * placed in the `notifications/progress` heartbeat, and NEVER read back by
 * `enforce.ts`/the dispatcher. If this module MINTS the token (the default —
 * `deps.mintApproval` is the seam the localhost page's URL overrides), it
 * mints `"tok_" + randomBytes(24).toString("base64url")` (32 base64url
 * chars, well over the contractual 22-char/128-bit floor — see
 * `@knotrust/core`'s `leak-patterns.ts` header, the BINDING token-format
 * contract this module honors) via `node:crypto`.
 *
 * ## R93 — terminal-only wire semantics (now the adapter's contract too)
 *
 * This channel itself never resolves or returns a wire-facing outcome at
 * all anymore (`notify()` is `Promise<void>`) — but the PROPERTY R93 named
 * (a `pending_approval` call this channel is part of always eventually
 * settles to a TERMINAL `ApprovalState`, never lingering unresolved) is
 * still what this module's background hold guarantees, via the lifecycle
 * orchestrator's own lazy-expiry contract (R86) that its periodic probe
 * drives.
 */

import { randomBytes } from "node:crypto";
import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { resolveKnotrustHome } from "@knotrust/grants";
import type { ApprovalChannel } from "../channel.js";
import type {
  ApprovalHandle,
  ApprovalOrchestrator,
  ApprovalRequest,
} from "../lifecycle.js";

// ---------------------------------------------------------------------------
// Heartbeat / expiry-probe scheduler seam — injectable so tests never sleep
// a real 10s×N (R91: "inject a scheduler or expose a tick()").
// ---------------------------------------------------------------------------

export interface HeartbeatScheduler {
  /**
   * Schedules `tick` to run repeatedly, roughly every `intervalMs`. Returns a
   * disposer that stops future ticks. The production implementation
   * (`createRealHeartbeatScheduler`) backs this with a real, `unref`'d
   * `setInterval`; tests supply a fake that stores `tick` and lets the test
   * invoke it manually, in lockstep with an independently-advanced fake
   * clock, so a ≥60s hold is provable with zero real wall-clock wait.
   */
  start(intervalMs: number, tick: () => void): () => void;
}

export function createRealHeartbeatScheduler(): HeartbeatScheduler {
  return {
    start(intervalMs, tick) {
      const handle = setInterval(tick, intervalMs);
      // Never let this scheduler alone keep the process alive.
      (handle as unknown as { unref?: () => void }).unref?.();
      return () => clearInterval(handle);
    },
  };
}

/** Default heartbeat / expiry-probe cadence (the Decision: "every 10s"). */
export const DEFAULT_HEARTBEAT_INTERVAL_MS = 10_000;

// ---------------------------------------------------------------------------
// Token/URL/code minting (R92) — the default, self-contained implementation.
// `deps.mintApproval` is the seam E6-T3 (the real localhost page) overrides.
// ---------------------------------------------------------------------------

export interface MintedApproval {
  /** `tok_`-prefixed, >=22 base64url chars (R92 / the E5-T4 binding contract) — human-channel ONLY, never model-visible. */
  token: string;
  /** The tokened approval URL a human opens to approve/deny. Human-channel ONLY. */
  url: string;
  /** A short, human-typeable confirmation code shown alongside the URL — lower-entropy, for a human to read/cross-check, never a substitute for the token. */
  code: string;
}

/** Excludes visually-ambiguous characters (0/O, 1/I) — this code is read and typed by a human. */
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_LENGTH = 6;

/**
 * Exported (P0-E6-T3): the localhost approval page reuses this EXACT
 * generator when the CLI/proxy wires the page's `url()` into this channel's
 * `mintApproval` seam — one token-format source, never a parallel copy that
 * could drift from the `tok_` contract (`@knotrust/core`'s
 * `leak-patterns.ts`).
 */
export function generateApprovalCode(): string {
  const bytes = randomBytes(CODE_LENGTH);
  let code = "";
  for (const byte of bytes) {
    code += CODE_ALPHABET[byte % CODE_ALPHABET.length];
  }
  return code;
}

/**
 * `tok_` + 24 random bytes, base64url-encoded (32 chars — well over the
 * >=22-char/128-bit contractual floor). Exported (P0-E6-T3) for the same
 * reason as {@link generateApprovalCode} above.
 */
export function generateApprovalToken(): string {
  return `tok_${randomBytes(24).toString("base64url")}`;
}

/**
 * Placeholder localhost approval-page URL base — E6-T3 binds the real page
 * to a real port and supplies its own `mintApproval` (or an equivalent
 * override) once it exists; until then this is a documented stand-in that
 * still carries a real, correctly-shaped `tok_` token, so this task's own
 * frame-scan acceptance (R92) is exercised against a realistic value.
 */
const DEFAULT_APPROVAL_BASE_URL = "http://127.0.0.1:8787/approve";

function defaultMintApproval(approvalId: string): MintedApproval {
  const token = generateApprovalToken();
  const code = generateApprovalCode();
  const url = `${DEFAULT_APPROVAL_BASE_URL}?id=${encodeURIComponent(approvalId)}&token=${encodeURIComponent(token)}`;
  return { token, url, code };
}

// ---------------------------------------------------------------------------
// Terminal sanitization — this prompt is read by a HUMAN, not a model, but a
// hostile/compromised tool or server NAME could still try a terminal
// escape-sequence or multi-line spoof against the person about to approve
// it. Strip to printable ASCII (mirrors `@knotrust/proxy-stdio`'s
// `denial-envelope.ts` `sanitizeForCliArg`, duplicated rather than imported —
// this package does not runtime-depend on `proxy-stdio`, see module header).
// ---------------------------------------------------------------------------

const MAX_TERMINAL_FIELD_LENGTH = 200;

function sanitizeForTerminal(raw: string): string {
  const stripped = Array.from(raw)
    .map((ch) => (ch >= "\x20" && ch <= "\x7e" ? ch : ""))
    .join("");
  return stripped.slice(0, MAX_TERMINAL_FIELD_LENGTH);
}

// ---------------------------------------------------------------------------
// The fixed-template stderr prompt (R91a).
// ---------------------------------------------------------------------------

function renderApprovalPrompt(ctx: {
  tool: string;
  server: string | undefined;
  tier: "sensitive" | "critical";
  code: string;
  url: string;
}): string {
  const serverLine =
    ctx.server !== undefined ? ` on server "${ctx.server}"` : "";
  return (
    `\nknotrust: approval required — "${ctx.tool}"${serverLine} (${ctx.tier} tier).\n` +
    `  code:    ${ctx.code}\n` +
    `  approve: ${ctx.url}\n` +
    "  (or respond from the terminal with `knotrust approvals`)\n" +
    "  this call is held until approved, denied, or it times out.\n\n"
  );
}

// ---------------------------------------------------------------------------
// The pending-record file — $KNOTRUST_HOME/pending/<approvalId>.json
// (R91a: "human channel — `knotrust approvals` reads it later, E7").
// ---------------------------------------------------------------------------

interface PendingApprovalRecord {
  approvalId: string;
  tool: string;
  server?: string;
  tier: "sensitive" | "critical";
  subject: string;
  agent: string;
  decisionId: string;
  code: string;
  token: string;
  url: string;
  createdAtEpochSeconds: number;
}

function pendingRecordPath(home: string, approvalId: string): string {
  return path.join(home, "pending", `${approvalId}.json`);
}

/**
 * Write-to-temp-then-rename (fix round 1, Minor 2 — mirrors `@knotrust/store`'s
 * `grant-store.ts` `atomicWriteFileSync`, not exported from that package so
 * replicated here): the SAME directory (rename is only atomic
 * same-filesystem), a per-call random suffix, then an atomic `rename()` over
 * the destination — so a concurrent `knotrust approvals` (E7) reader can
 * never observe a truncated/partial JSON file mid-write.
 */
function atomicWriteFileSync(filePath: string, contents: string): void {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(
    dir,
    `${path.basename(filePath)}.${randomBytes(8).toString("hex")}.tmp`,
  );
  writeFileSync(tmpPath, contents, "utf8");
  try {
    renameSync(tmpPath, filePath);
  } catch (err) {
    // Best-effort cleanup of the tmp file on the failure path only — a
    // successful rename already moved it, so there is nothing to clean up
    // there (matches grant-store.ts's own atomicWriteFileSync).
    try {
      rmSync(tmpPath, { force: true });
    } catch {
      // Best-effort.
    }
    throw err;
  }
}

/** Best-effort — a pending-record write failure must never abort the hold (this is a human-convenience record, not the source of truth; the lifecycle orchestrator's own audit trail already is). */
function writePendingRecord(home: string, record: PendingApprovalRecord): void {
  try {
    const dir = path.join(home, "pending");
    mkdirSync(dir, { recursive: true });
    atomicWriteFileSync(
      pendingRecordPath(home, record.approvalId),
      `${JSON.stringify(record, null, 2)}\n`,
    );
  } catch {
    // Best-effort — see doc-comment above.
  }
}

/** Best-effort removal once the approval reaches a terminal state — a resolved approval is no longer "pending." */
function removePendingRecord(home: string, approvalId: string): void {
  try {
    rmSync(pendingRecordPath(home, approvalId), { force: true });
  } catch {
    // Best-effort.
  }
}

// ---------------------------------------------------------------------------
// presentApprovalToHuman (R91a) — exported standalone so its stderr/
// pending-file side effects are unit-testable independent of the full
// hold/resolve flow.
// ---------------------------------------------------------------------------

export interface PresentDeps {
  /** `$KNOTRUST_HOME` override. Defaults to `resolveKnotrustHome()` (`@knotrust/grants`). */
  home?: string;
  /** Defaults to `process.stderr.write`. Injected in tests. */
  stderrWrite?: (chunk: string) => void;
  /** Defaults to the self-contained `tok_` mint above. E6-T3 overrides this once the real page exists. */
  mintApproval?: (approvalId: string) => MintedApproval;
  /** Injected clock (epoch seconds) — stamps the pending record's `createdAtEpochSeconds` only; never used for any expiry decision (that stays the lifecycle orchestrator's job). */
  nowEpochSeconds: () => number;
}

/**
 * Presents one pending approval to the human: a fixed-template stderr prompt
 * (tool, server, tier, code, URL) and a `$KNOTRUST_HOME/pending/<id>.json`
 * record carrying the same token — BOTH human channels, NEITHER ever
 * reachable from `sendNotification`/the wire (R91a/R92). Returns the minted
 * `{token, url, code}` purely for the caller's/tests' convenience; the
 * caller (`requestApproval`) does not otherwise need it.
 */
export function presentApprovalToHuman(
  approvalRequest: ApprovalRequest,
  handle: ApprovalHandle,
  deps: PresentDeps,
): MintedApproval {
  const mint = deps.mintApproval ?? defaultMintApproval;
  const minted = mint(handle.id);
  const home = deps.home ?? resolveKnotrustHome();

  const tool = sanitizeForTerminal(approvalRequest.decisionRequest.action.name);
  const rawServer = approvalRequest.decisionRequest.surface.server;
  const server =
    rawServer !== undefined ? sanitizeForTerminal(rawServer) : undefined;

  const write =
    deps.stderrWrite ?? ((chunk: string) => void process.stderr.write(chunk));
  write(
    renderApprovalPrompt({
      tool,
      server,
      tier: approvalRequest.tier,
      code: minted.code,
      url: minted.url,
    }),
  );

  writePendingRecord(home, {
    approvalId: handle.id,
    tool: approvalRequest.decisionRequest.action.name,
    ...(rawServer !== undefined ? { server: rawServer } : {}),
    tier: approvalRequest.tier,
    subject: approvalRequest.subject.id,
    agent: approvalRequest.agent.id,
    decisionId: approvalRequest.decisionId,
    code: minted.code,
    token: minted.token,
    url: minted.url,
    createdAtEpochSeconds: deps.nowEpochSeconds(),
  });

  return minted;
}

// ---------------------------------------------------------------------------
// The heartbeat notification (R91a/R92 — no token/policy internals).
// ---------------------------------------------------------------------------

export interface BlockAndWaitProgressNotification {
  jsonrpc: "2.0";
  method: "notifications/progress";
  params: {
    progressToken: string | number;
    progress: number;
    message: string;
  };
}

// ---------------------------------------------------------------------------
// createBlockAndWaitChannel (R91/R94).
// ---------------------------------------------------------------------------

export interface BlockAndWaitChannelDeps {
  /** The E6-T1 approval lifecycle orchestrator this channel drives. */
  orchestrator: ApprovalOrchestrator;
  /**
   * Sends one JSON-RPC message (the `notifications/progress` heartbeat) to
   * the ORIGINAL client on the wire. Proxy-provided (see
   * `@knotrust/proxy-stdio`'s `StdioProxy.sendToClient`). A rejection/throw
   * here is caught and swallowed — a heartbeat delivery failure must never
   * abort the hold (best-effort, matches this codebase's audit doctrine for
   * non-decision side channels).
   */
  sendNotification(
    message: BlockAndWaitProgressNotification,
  ): Promise<void> | void;
  /**
   * The SAME clock the lifecycle orchestrator was itself constructed with
   * (epoch seconds). Used ONLY to stamp the pending-record file
   * (`presentApprovalToHuman`) — the actual expiry DECISION always stays the
   * orchestrator's own job (`orchestrator.status()`/`onResolved()` read
   * their own injected clock internally); this module never re-derives or
   * second-guesses it.
   */
  nowEpochSeconds(): number;
  /**
   * Injected heartbeat/expiry-probe scheduler (R91: "inject a scheduler or
   * expose a tick()"). Defaults to `createRealHeartbeatScheduler()`.
   */
  scheduler?: HeartbeatScheduler;
  /** Heartbeat / expiry-probe interval, milliseconds. Default {@link DEFAULT_HEARTBEAT_INTERVAL_MS} (10s, per the Decision). */
  heartbeatIntervalMs?: number;
  /** `$KNOTRUST_HOME` override, threaded to `presentApprovalToHuman`. Defaults to `resolveKnotrustHome()`. */
  home?: string;
  /** Threaded to `presentApprovalToHuman`. Defaults to the self-contained `tok_` mint. */
  mintApproval?: (approvalId: string) => MintedApproval;
  /** Threaded to `presentApprovalToHuman`. Defaults to `process.stderr.write`. */
  stderrWrite?: (chunk: string) => void;
}

/**
 * Creates the block-and-wait terminal channel (P0-E6-T2, refactored to
 * CONFORM to `ApprovalChannel` in P0-E6-T4, R101). The returned value is a
 * standard `ApprovalChannel` (`kind: "block_and_wait"`, `available()`
 * unconditionally `true` — the always-available floor) — register it with
 * `createMultiChannelDispatcher([blockAndWaitChannel, ...])` and hand THAT
 * to `createDispatchingApprovalOrchestrator` (`channel.ts`), which is what
 * satisfies `@knotrust/proxy-stdio`'s `enforce.ts` seam for a real run.
 */
export function createBlockAndWaitChannel(
  deps: BlockAndWaitChannelDeps,
): ApprovalChannel {
  const scheduler = deps.scheduler ?? createRealHeartbeatScheduler();
  const heartbeatIntervalMs =
    deps.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_INTERVAL_MS;
  const home = deps.home ?? resolveKnotrustHome();

  async function notify(
    req: ApprovalRequest,
    handle: ApprovalHandle,
  ): Promise<void> {
    presentApprovalToHuman(req, handle, {
      home,
      nowEpochSeconds: deps.nowEpochSeconds,
      ...(deps.stderrWrite !== undefined
        ? { stderrWrite: deps.stderrWrite }
        : {}),
      ...(deps.mintApproval !== undefined
        ? { mintApproval: deps.mintApproval }
        : {}),
    });

    // Grab the deferred BEFORE the first scheduler tick — `onResolved()`
    // runs one (harmless) lazy expiry check itself, then hands back the
    // same promise a later tick's forced check will settle. This is also the
    // SAME promise `createDispatchingApprovalOrchestrator` awaits directly —
    // two independent `.then` continuations off one deferred, not a race.
    const resolvedPromise = deps.orchestrator.onResolved(handle.id);

    let elapsedSeconds = 0;
    const stopScheduler = scheduler.start(heartbeatIntervalMs, () => {
      elapsedSeconds += Math.floor(heartbeatIntervalMs / 1000);

      // Force the lifecycle orchestrator's LAZY expiry check (R86: expiry is
      // only ever evaluated when some method touches the record) —
      // independent of whether a heartbeat notification is actually sent
      // below, so a timed-out hold always eventually settles even for a
      // client that supplied no progressToken at all.
      void deps.orchestrator.status(handle.id).catch(() => {
        // Best-effort — a probe failure must never abort the hold; the next
        // tick tries again, and the main `await` below is unaffected either way.
      });

      if (req.progressToken !== undefined) {
        const notification: BlockAndWaitProgressNotification = {
          jsonrpc: "2.0",
          method: "notifications/progress",
          params: {
            progressToken: req.progressToken,
            progress: elapsedSeconds,
            // Fixed, static message — no tool/server/policy content (R92).
            message: "knotrust: awaiting human approval",
          },
        };
        try {
          void Promise.resolve(deps.sendNotification(notification)).catch(
            () => {
              // Best-effort — see deps.sendNotification's own doc-comment.
            },
          );
        } catch {
          // Best-effort (a synchronously-throwing sendNotification is as
          // tolerated as a rejecting one).
        }
      }
    });

    // Fire-and-forget (P0-E6-T4 reshape — see module header): `notify()`
    // itself returns as soon as presentation + the scheduler are under way;
    // the actual multi-minute wait happens here, in the background, so a
    // SECOND channel's `notify()` (R104's multi-channel proof) is never
    // blocked behind this one's full hold duration.
    void resolvedPromise.then(
      () => {
        stopScheduler();
        removePendingRecord(home, handle.id);
      },
      () => {
        // Defensive: `onResolved()` should never reject in practice for a
        // handle this module was just handed (lifecycle.ts's own contract),
        // but a background watcher must never produce an unhandled
        // rejection regardless of how the caller's Promise settles.
        stopScheduler();
        removePendingRecord(home, handle.id);
      },
    );
  }

  return {
    kind: "block_and_wait",
    // The universal, always-available floor (architecture §6.2) — never
    // gated on surface/client capability, unlike a P1 elicitation channel.
    available: () => true,
    notify,
  };
}
