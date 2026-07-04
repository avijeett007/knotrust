/**
 * @knotrust/proxy-stdio — stdio proxy: child spawn + transparent passthrough
 * (P0-E5-T1; rulings R58–R62; architecture §4.1/§4.2).
 *
 * `knotrust -- <server-cmd>` spawns the real MCP server as a child process and
 * proxies line-framed stdio JSON-RPC in both directions. This task is
 * TRANSPORT-ONLY: spawn, wire pipes, frame lines, pass every message through
 * byte/shape-faithfully with `id` correlation preserved, relay child stderr and
 * notifications in real time, shut down cleanly with no orphaned child. There is
 * NO enforcement here — that is P0-E5-T3 (tools/call enforcement), which will
 * hook the {@link ClassifierHook} seam with a genuine non-passthrough routing
 * action (see `classifier.ts`).
 *
 * P0-E5-T2 (rulings R63–R67) adds the `toolInventory` option below: opt-in
 * OBSERVATION of `tools/list` responses (never alteration — forwarding stays
 * byte/shape-faithful either way, see `relay()`) that accumulates a per-server
 * tool inventory across pagination, seeds suggested tiers from annotations,
 * and detects tool-definition drift against a persisted baseline. See
 * `tool-inventory.ts` for the implementation and `classifier.ts` for the
 * `observe` seam capability this is built on.
 *
 * P0-E5-T5 (ruling R82) hardens this transport layer's own crash story: a
 * wrapped server that dies (spontaneously, or mid-call) must never leave a
 * client request hanging forever, and must never surface as a silent, clean
 * exit — see `forward()`'s in-flight bookkeeping (`pendingChildRequests`)
 * and `failPendingChildRequests()`, and `docs/03-engineering/failure-modes.md`
 * for the full failure×behavior table (this module's `ProxyCloseReason` is
 * what the CLI runner, `packages/cli/src/run.ts`, keys its exit code off).
 *
 * ## Why a transport-level relay, not high-level `Server`+`Client` (R58 / ADR-0019)
 *
 * Architecture §4.1 names the punkpeye/mcp-proxy pattern ("compose SDK `Server`
 * client-facing + `Client` child-facing"). R58 required verifying that pattern
 * can pass EVERY message type through faithfully — including methods the SDK
 * does not model. It cannot, at the HIGH level: `@modelcontextprotocol/sdk`'s
 * `Server`/`Client` (`Protocol`) dispatch requests by registered handler and
 * answer `initialize`/`ping` with their OWN baked-in logic and OWN declared
 * capabilities; an unregistered method gets a `MethodNotFound` error rather than
 * being relayed. That structurally cannot relay the child's REAL handshake, nor
 * `resources/*`, `prompts/*`, sampling, or any unknown method, opaquely.
 *
 * Per R58's explicit fallback, this proxy therefore composes the SDK's
 * TRANSPORT layer instead: a {@link StdioServerTransport} on the proxy's own
 * stdin/stdout (client-facing) and a {@link StdioClientTransport} that spawns
 * the child (child-facing). Each transport does the real MCP line framing and
 * JSON-RPC parse/serialize; the relay pumps parsed messages straight across via
 * the classifier seam. Fidelity of that path and the one narrow caveat (Zod's
 * strict inner `error`-object shape) are documented in
 * `docs/05-decisions/adr/adr-0019-stdio-proxy-transport-relay.md`.
 */

import process from "node:process";
import type { Readable, Writable } from "node:stream";
import type { AuditSink } from "@knotrust/store";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import {
  type ClassifierHook,
  type ClassifyDirection,
  composeClassifiers,
  defaultClassifier,
  type JsonRpcMessage,
} from "./classifier.js";
import { type EnforceResult, isToolsCallRequest } from "./enforce.js";
import { createToolInventoryClassifier } from "./tool-inventory.js";

/**
 * The ASYNC enforcement seam (P0-E5-T3, R70) — a dedicated `intercept` the
 * relay AWAITS for every `tools/call` request before forwarding-or-
 * synthesizing. Deliberately separate from the sync {@link ClassifierHook}
 * (which stays pure/synchronous so `tools/list` observation and all other
 * passthrough keep their E5-T1/T2 fidelity and ordering): a decision may need
 * to collect grants, consume a single-use grant, or hold for approval, none of
 * which a synchronous classifier could do. The CLI builds this from
 * `createEnforcer(...).handle` (see `enforce.ts`); when absent the proxy is
 * pure passthrough (T1/T2), unchanged.
 */
export type EnforcementHook = (
  message: JsonRpcMessage,
) => Promise<EnforceResult>;

/** Why the proxy tore down — reported to {@link CreateStdioProxyOptions.onClose}. */
export type ProxyCloseReason =
  /** The real client closed its end (proxy stdin EOF); we shut the child down gracefully. */
  | "client_eof"
  /** The child process exited on its own; we stopped relaying. */
  | "child_exit"
  /** `stop()` was called explicitly (or a proxy signal was propagated). */
  | "stopped";

export interface CreateStdioProxyOptions {
  /**
   * The real MCP server command as an argv array, e.g.
   * `["node", "server.js", "--flag"]`. `serverCommand[0]` is the executable;
   * the rest are its arguments. Must be non-empty.
   */
  serverCommand: string[];
  /**
   * Extra environment variables for the child, layered ON TOP of the full
   * inherited parent environment (architecture §4.2: stdio auth is env-based,
   * MCP §8 exempts stdio from OAuth — so the child inherits the parent env by
   * default). Provided keys override inherited ones.
   */
  env?: Record<string, string>;
  /**
   * The classifier SEAM (R59). Defaults to {@link defaultClassifier}
   * (everything passthrough). T2/T3 supply their own hook here; every message
   * this hook does not intercept still passes through faithfully.
   */
  onClassify?: ClassifierHook;
  /**
   * The ASYNC enforcement seam (P0-E5-T3, R70). When present, every
   * client→server `tools/call` REQUEST is HELD (not forwarded synchronously)
   * while this hook decides it; the relay then either forwards the original
   * call to the child (`allow`) or synthesizes the same-`id` response itself
   * (`deny`/`pending_approval`/`deferred`) so the child NEVER receives a denied
   * call. EVERY other message — `tools/list` (still observed, T2), `initialize`,
   * notifications, responses, unknown methods — passes through synchronously and
   * faithfully exactly as without this option. When absent, the proxy is pure
   * T1/T2 passthrough (unchanged). See this module's `relay()` for the precise
   * ordering model (per-request async: a held call blocks only ITS OWN response;
   * other traffic continues; the client correlates by `id`).
   */
  enforce?: EnforcementHook;
  /**
   * Injectable monotonic clock (ms). Reserved for T3's timing/telemetry; T1
   * uses it only to timestamp optional diagnostic log lines. Defaults to
   * `Date.now`.
   */
  nowMs?: () => number;
  /** Optional diagnostic sink for proxy-internal lifecycle lines (NOT the relayed traffic). */
  logger?: (line: string) => void;
  /**
   * Client-facing input stream — where the real MCP client's requests arrive.
   * Defaults to `process.stdin` (the production `knotrust -- …` path). Injected
   * in tests to drive the proxy without owning the real process stdio.
   */
  stdin?: Readable;
  /** Client-facing output stream — responses/notifications to the real client. Defaults to `process.stdout`. */
  stdout?: Writable;
  /**
   * Sink for the child's stderr, passed straight through in real time
   * (architecture §4.1: MCP permits arbitrary server logging on stderr).
   * Defaults to `process.stderr`.
   */
  stderr?: Writable;
  /**
   * Fired exactly once when the proxy has fully torn down (child reaped, no
   * orphan). The CLI runner uses this to know when to exit.
   */
  onClose?: (info: { reason: ProxyCloseReason }) => void;
  /**
   * Opt-in `tools/list` interception & annotation capture (P0-E5-T2, rulings
   * R63–R67). When provided, the proxy OBSERVES (never alters) every
   * `tools/list` response for `serverName`: forwarding stays byte/shape-
   * faithful passthrough exactly as without this option (R63) — the only
   * difference is a decoupled side effect that accumulates the full tool
   * inventory across pagination, seeds SUGGESTED tiers from annotations, and
   * detects drift against the persisted baseline for this server, emitting a
   * `tool_definition_changed` audit event through `audit` when supplied. When
   * this option is ABSENT, none of that runs — the proxy is pure T1
   * passthrough, unchanged (tested explicitly: absent-opt is the baseline).
   * See `tool-inventory.ts` (`createToolInventoryClassifier`) for the
   * observation logic this composes underneath `onClassify` (or the default
   * classifier) via `composeClassifiers` — `onClassify`'s own routing
   * decisions always take precedence; this option only ever adds an
   * `observe` side effect on top of an existing `"passthrough"`.
   */
  toolInventory?: {
    /** Logical MCP server name this proxy instance fronts — the `<server>` in `$KNOTRUST_HOME/servers/<server>/tool-inventory.json`. */
    serverName: string;
    /** Defaults to `resolveKnotrustHome()` (the `KNOTRUST_HOME` override, else `~/.knotrust`) — see `tool-inventory.ts`. */
    home?: string;
    /** Injected audit sink (E4-T3). When absent, drift detection still runs and the baseline still updates — it just logs nothing (documented seam; always-on audit wiring is T3/E5's job). */
    audit?: AuditSink;
  };
}

export interface StdioProxy {
  /** Spawn the child and begin relaying. Resolves once both transports are live. */
  start(): Promise<void>;
  /**
   * Stop relaying and tear the child down with no orphan. Graceful ladder:
   * stdin-EOF → bounded wait → SIGTERM → SIGKILL (R60). Pass an explicit
   * `signal` to escalate immediately (e.g. propagating a SIGTERM the proxy
   * itself received). Idempotent: repeated/concurrent calls share one teardown.
   */
  stop(signal?: NodeJS.Signals): Promise<void>;
  /** The spawned child's pid, or `undefined` before `start()`. Stays readable after teardown (for orphan checks). */
  readonly childPid: number | undefined;
  /**
   * Sends one message directly to the CLIENT-facing transport, out of band
   * from the normal relay (P0-E6-T2). This is the seam the real
   * block-and-wait approval channel (`@knotrust/approval`'s
   * `createBlockAndWaitChannel`) uses to deliver `notifications/progress`
   * heartbeats to the client WHILE a `tools/call` is held — no in-flight
   * request is required, and this never touches {@link pendingChildRequests}
   * bookkeeping (that tracking is for client→server REQUEST/RESPONSE pairs
   * only; a heartbeat is a bare notification with no `id`, so there is
   * nothing to correlate). A safe no-op (never throws, resolves regardless)
   * before `start()` or after the client-facing transport has torn down —
   * a heartbeat that arrives too early or too late to matter must never
   * crash the caller.
   */
  sendToClient(message: JSONRPCMessage): Promise<void>;
}

/**
 * Extra safety-net wait for the child's `close` event AFTER
 * `StdioClientTransport.close()`'s own EOF→SIGTERM→SIGKILL ladder has run, so
 * `stop()` never resolves while the child is still alive (no orphan, R60/R62e).
 */
const REAP_SAFETY_MS = 3_000;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms).unref();
  });
}

/** True if a pid is still alive (signal-0 probe). A dead/reaped pid throws ESRCH. */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// R82 (P0-E5-T5) — wrapped-server crash never leaves a client request hanging.
//
// A message's `id` (string|number) or `undefined` if absent/non-primitive.
// A REQUEST has both an `id` AND a `method`; a RESPONSE has an `id` but NO
// `method`. These two predicates below are the generic, method-agnostic
// versions of `enforce.ts`'s `isToolsCallRequest` — this bookkeeping applies
// to EVERY client→server request the relay forwards, not just `tools/call`,
// because "the client must never hang forever" (R82) is a transport-level
// guarantee, independent of whether enforcement is even wired.
// ---------------------------------------------------------------------------

function messageId(message: JSONRPCMessage): string | number | undefined {
  const id = (message as { id?: unknown }).id;
  return typeof id === "string" || typeof id === "number" ? id : undefined;
}

function isRequestMessage(message: JSONRPCMessage): boolean {
  return (
    messageId(message) !== undefined &&
    typeof (message as { method?: unknown }).method === "string"
  );
}

function isResponseMessage(message: JSONRPCMessage): boolean {
  return (
    messageId(message) !== undefined &&
    typeof (message as { method?: unknown }).method !== "string"
  );
}

/** JSON-RPC 2.0 reserves -32000..-32099 for implementation-defined "Server error" — distinct from the SDK's own -32601/-32603 protocol-level codes. */
const CHILD_CRASHED_ERROR_CODE = -32000;

function buildChildCrashedError(id: string | number): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: CHILD_CRASHED_ERROR_CODE,
      message:
        "knotrust: the wrapped MCP server disconnected before responding to this call",
    },
  } as unknown as JSONRPCMessage;
}

/**
 * Builds the child's environment: the full inherited parent env (stringified,
 * dropping `undefined` holes) with `extra` layered on top. Full inheritance is
 * deliberate — stdio MCP auth is env-based (architecture §4.2) — and is a
 * superset of the SDK's own `getDefaultEnvironment()` safe-subset default.
 */
function buildChildEnv(extra?: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) {
      env[key] = value;
    }
  }
  if (extra !== undefined) {
    for (const [key, value] of Object.entries(extra)) {
      env[key] = value;
    }
  }
  return env;
}

class StdioProxyImpl implements StdioProxy {
  private readonly command: string;
  private readonly args: string[];
  private readonly env: Record<string, string>;
  private readonly classify: ClassifierHook;
  private readonly enforce: EnforcementHook | undefined;
  private readonly nowMs: () => number;
  private readonly log: ((line: string) => void) | undefined;
  private readonly clientInput: Readable;
  private readonly clientOutput: Writable;
  private readonly childStderrSink: Writable;
  private readonly onClose:
    | ((info: { reason: ProxyCloseReason }) => void)
    | undefined;

  private serverTransport: StdioServerTransport | undefined;
  private clientTransport: StdioClientTransport | undefined;
  private capturedPid: number | undefined;

  private childExited: Promise<void> = Promise.resolve();
  private resolveChildExited: () => void = () => {};
  private teardownPromise: Promise<void> | undefined;
  private onCloseFired = false;

  /**
   * Client→server REQUESTS forwarded to the child but not yet answered
   * (R82) — populated in `forward()` when a request leaves for the child,
   * cleared when its matching response comes back (also `forward()`) or
   * when this proxy tears down for any reason (`runTeardown`'s
   * `failPendingChildRequests`), whichever comes first. This is what lets a
   * spontaneous child crash (or an immediate failed send to an
   * already-dead child) synthesize a same-`id` error result instead of
   * leaving the client waiting forever.
   */
  private readonly pendingChildRequests = new Map<string | number, true>();

  constructor(opts: CreateStdioProxyOptions) {
    const [command, ...args] = opts.serverCommand;
    if (command === undefined) {
      throw new Error(
        'createStdioProxy: serverCommand must be a non-empty argv array (e.g. ["node", "server.js"])',
      );
    }
    this.command = command;
    this.args = args;
    this.env = buildChildEnv(opts.env);
    // nowMs/log must be assigned BEFORE building `classify` below — the
    // tool-inventory observer (when wired) reuses this proxy's own injected
    // clock/logger rather than requiring a caller to duplicate them in
    // `toolInventory` (single source of truth for "what time is it"/"where do
    // diagnostics go", and deterministic-clock tests get that for free here).
    this.nowMs = opts.nowMs ?? Date.now;
    this.log = opts.logger;
    const baseClassifier = opts.onClassify ?? defaultClassifier;
    this.classify =
      opts.toolInventory !== undefined
        ? composeClassifiers(
            baseClassifier,
            createToolInventoryClassifier({
              serverName: opts.toolInventory.serverName,
              ...(opts.toolInventory.home !== undefined
                ? { home: opts.toolInventory.home }
                : {}),
              ...(opts.toolInventory.audit !== undefined
                ? { audit: opts.toolInventory.audit }
                : {}),
              nowMs: this.nowMs,
              ...(this.log !== undefined ? { logger: this.log } : {}),
            }),
          )
        : baseClassifier;
    this.enforce = opts.enforce;
    this.clientInput = opts.stdin ?? process.stdin;
    this.clientOutput = opts.stdout ?? process.stdout;
    this.childStderrSink = opts.stderr ?? process.stderr;
    this.onClose = opts.onClose;
  }

  get childPid(): number | undefined {
    return this.capturedPid;
  }

  /**
   * See {@link StdioProxy.sendToClient}. Sends directly on the client-facing
   * transport — bypassing `forward()`'s {@link pendingChildRequests}
   * bookkeeping entirely, since that bookkeeping only ever tracks
   * client→server REQUEST/RESPONSE `id` pairs and a heartbeat notification
   * has no `id` to correlate. A missing transport (too early/too late) or a
   * rejected `send()` (e.g. the client already hung up) is logged and
   * swallowed — never thrown back at the caller.
   */
  async sendToClient(message: JSONRPCMessage): Promise<void> {
    if (this.serverTransport === undefined) {
      this.diag(
        "sendToClient: no client-facing transport yet/anymore — dropped",
      );
      return;
    }
    try {
      await this.serverTransport.send(message);
    } catch (error) {
      this.diag(`sendToClient failed: ${String(error)}`);
    }
  }

  private diag(line: string): void {
    this.log?.(`[${this.nowMs()}] knotrust-proxy: ${line}`);
  }

  async start(): Promise<void> {
    if (this.clientTransport !== undefined) {
      throw new Error("createStdioProxy: start() already called");
    }

    const clientTransport = new StdioClientTransport({
      command: this.command,
      args: this.args,
      env: this.env,
      // "pipe" (not "inherit") so we own the handle and forward it through the
      // proxy's OWN stderr sink — real-time, and injectable in tests. `.pipe`
      // with `{ end: false }` so the child's stderr closing never ends our sink.
      stderr: "pipe",
    });
    const serverTransport = new StdioServerTransport(
      this.clientInput,
      this.clientOutput,
    );
    this.clientTransport = clientTransport;
    this.serverTransport = serverTransport;

    this.childExited = new Promise<void>((resolve) => {
      this.resolveChildExited = resolve;
    });

    // Forward child stderr straight through, in real time. The PassThrough is
    // available from the getter immediately (before start()), so early child
    // output is not lost.
    clientTransport.stderr?.pipe(this.childStderrSink, { end: false });

    // --- Wire the bidirectional relay through the classifier seam. Callbacks
    // must be installed BEFORE start() so no early message is dropped. ---
    clientTransport.onmessage = (message) => {
      this.relay(message, "server_to_client");
    };
    clientTransport.onclose = () => {
      this.handleChildClose();
    };
    clientTransport.onerror = (error) => {
      this.diag(`child transport error: ${String(error)}`);
    };

    serverTransport.onmessage = (message) => {
      this.relay(message, "client_to_server");
    };
    serverTransport.onerror = (error) => {
      this.diag(`client transport error: ${String(error)}`);
    };

    // Spawn the child FIRST, so it is ready to receive before we start reading
    // client input (otherwise an early client message could hit a not-yet-live
    // child transport).
    await clientTransport.start();
    this.capturedPid = clientTransport.pid ?? undefined;

    await serverTransport.start();

    // Real client closing its end (our stdin EOF) → graceful child shutdown
    // (R60). StdioServerTransport itself does not surface stdin 'end'.
    this.clientInput.once("end", () => {
      void this.teardown("client_eof");
    });

    this.diag(`started; child pid ${String(this.capturedPid)}`);
  }

  /**
   * The relay core.
   *
   * ## Ordering model (R70) — per-request async, notifications never blocked
   *
   * When enforcement is wired AND this is a client→server `tools/call` request,
   * the message is HELD: {@link enforceToolsCall} runs the async decision and,
   * once it resolves, either forwards the ORIGINAL call to the child (`allow`)
   * or sends a synthesized same-`id` response back to the client (`deny`/
   * `pending`/`deferred`). `relay()` returns immediately in that case, so the
   * transport keeps delivering subsequent messages: a held `tools/call` blocks
   * ONLY its own response, never other traffic (other requests, notifications,
   * responses). MCP clients correlate responses by JSON-RPC `id` (proven by the
   * out-of-order-correlation test), so a routine call decided after a held one
   * may legitimately answer first — that is safe, not a client-visible reorder
   * bug. Backpressure is preserved: the eventual forward/synthesize goes through
   * the same transport `send()` (resolves on drain) the synchronous path uses.
   *
   * EVERY other message takes the unchanged synchronous path below: classify →
   * passthrough (byte/shape-faithful) → optional `observe` side effect (R63).
   * The `switch` stays exhaustive on `result.action`, so adding a
   * {@link ClassifyResult} variant is a compile error until handled.
   */
  private relay(message: JSONRPCMessage, direction: ClassifyDirection): void {
    // Async enforcement intercept (R70): hold client→server tools/call.
    if (
      this.enforce !== undefined &&
      direction === "client_to_server" &&
      isToolsCallRequest(message)
    ) {
      this.enforceToolsCall(message);
      return;
    }

    const result = this.classify(message, direction);
    switch (result.action) {
      case "passthrough": {
        this.forward(message, direction);
        if (result.observe !== undefined) {
          try {
            result.observe(message);
          } catch (error) {
            this.diag(`observe hook threw (${direction}): ${String(error)}`);
          }
        }
        break;
      }
      default: {
        const exhaustive: never = result.action;
        throw new Error(
          `knotrust-proxy: unhandled classify action ${String(exhaustive)}`,
        );
      }
    }
  }

  /**
   * Forwards a message unchanged to the opposite transport. Fire-and-forget:
   * `send` resolves on write/drain; a rejected send (e.g. the far side already
   * closed mid-teardown) is logged, not thrown — there is no one left to
   * deliver a throw to.
   *
   * R82 in-flight bookkeeping lives HERE, at the one choke point every
   * forwarded message passes through: a client→server REQUEST is marked
   * pending just before the send attempt; a server→client RESPONSE clears
   * the matching pending entry. If the send itself fails (e.g. the child's
   * stdin pipe is already broken — a race where the child died between our
   * classify step and this send), and this was a pending client→server
   * request, the client must not be left waiting for a response that will
   * never come: synthesize the same-`id` crash error immediately rather
   * than waiting on the child's `close` event, which this exact failure may
   * indicate has already happened (or, more subtly, may never fire at all
   * if the transport considers itself already torn down).
   */
  private forward(message: JSONRPCMessage, direction: ClassifyDirection): void {
    const id = messageId(message);
    if (direction === "client_to_server" && id !== undefined) {
      if (isRequestMessage(message)) {
        this.pendingChildRequests.set(id, true);
      }
    } else if (direction === "server_to_client" && id !== undefined) {
      if (isResponseMessage(message)) {
        this.pendingChildRequests.delete(id);
      }
    }

    const target =
      direction === "client_to_server"
        ? this.clientTransport
        : this.serverTransport;
    target?.send(message).catch((error: unknown) => {
      this.diag(`relay send failed (${direction}): ${String(error)}`);
      if (
        direction === "client_to_server" &&
        id !== undefined &&
        this.pendingChildRequests.delete(id)
      ) {
        this.forward(buildChildCrashedError(id), "server_to_client");
      }
    });
  }

  /**
   * Drains {@link pendingChildRequests}, synthesizing the same-`id` crash
   * error (R82) for every client→server request forwarded to the child but
   * never answered. Called from `runTeardown` BEFORE the client-facing
   * transport closes, for every teardown reason — a spontaneous child crash
   * (`"child_exit"`) is the scenario R82 names explicitly, but draining
   * unconditionally is strictly safer: a request stranded by an explicit
   * `stop()`/signal escalation must not hang either, and an empty map (the
   * common case — every call already resolved) makes this a no-op.
   */
  private failPendingChildRequests(): void {
    const ids = [...this.pendingChildRequests.keys()];
    this.pendingChildRequests.clear();
    for (const id of ids) {
      this.forward(buildChildCrashedError(id), "server_to_client");
    }
  }

  /**
   * Runs the async enforcement decision for one held `tools/call`, then acts:
   * `forward` → send the ORIGINAL call to the child; `respond` → send the
   * synthesized same-`id` result back to the client (the child never sees it).
   * The enforcement hook is designed never to reject (it fails closed to a
   * synthesized deny internally); the `.catch` is belt-and-braces — a truly
   * unexpected rejection fails closed with a JSON-RPC internal error to the
   * same `id`, so the client is never left hanging AND the call never reaches
   * the child ungoverned.
   */
  private enforceToolsCall(message: JSONRPCMessage): void {
    const enforce = this.enforce;
    if (enforce === undefined) return; // unreachable (guarded by caller)
    enforce(message)
      .then((result) => {
        if (result.action === "forward") {
          this.forward(message, "client_to_server");
        } else {
          // Synthesized response travels back to the client (server_to_client).
          this.forward(result.message, "server_to_client");
        }
      })
      .catch((error: unknown) => {
        this.diag(`enforcement hook rejected (fail-closed): ${String(error)}`);
        const id = (message as { id?: unknown }).id;
        if (id !== undefined) {
          this.forward(
            {
              jsonrpc: "2.0",
              id,
              error: {
                code: -32603,
                message: "knotrust: internal enforcement error (call blocked)",
              },
            } as unknown as JSONRPCMessage,
            "server_to_client",
          );
        }
      });
  }

  /** The child exited (spontaneously, or as the tail of our own teardown). */
  private handleChildClose(): void {
    this.resolveChildExited();
    // If we are NOT already tearing down, this is a spontaneous child exit
    // (a crash, R82) — stop relaying and close the client-facing side.
    // `runTeardown` (below) is what actually answers any in-flight request
    // and reports this as a non-`0` exit (R82(ii), the CLI runner's job) —
    // here we just kick that off, never hang, never orphan (R60).
    if (this.teardownPromise === undefined) {
      void this.teardown("child_exit");
    }
  }

  async stop(signal?: NodeJS.Signals): Promise<void> {
    return this.teardown("stopped", signal);
  }

  /** Idempotent: concurrent/repeat callers all await the same teardown. */
  private teardown(
    reason: ProxyCloseReason,
    signal?: NodeJS.Signals,
  ): Promise<void> {
    if (this.teardownPromise === undefined) {
      this.teardownPromise = this.runTeardown(reason, signal);
    }
    return this.teardownPromise;
  }

  private async runTeardown(
    reason: ProxyCloseReason,
    signal?: NodeJS.Signals,
  ): Promise<void> {
    this.diag(`tearing down (${reason}${signal ? `, signal ${signal}` : ""})`);

    // R82: answer any client request still awaiting the child's result
    // BEFORE the client-facing transport closes below — a spontaneous crash
    // (`reason === "child_exit"`) is the scenario this exists for, but
    // draining unconditionally on every teardown reason is strictly safer
    // (see `failPendingChildRequests`'s own doc-comment) and a no-op when
    // nothing is actually pending (the common case).
    this.failPendingChildRequests();

    // The child is only still alive to be killed when this is NOT the child's
    // own spontaneous exit.
    if (reason !== "child_exit") {
      // Explicit escalation signal (e.g. a SIGTERM we received on the proxy,
      // propagated to the child) — best-effort, before the graceful ladder.
      if (signal !== undefined && this.capturedPid !== undefined) {
        try {
          process.kill(this.capturedPid, signal);
        } catch {
          // Already gone — nothing to escalate.
        }
      }
      // StdioClientTransport.close() runs the R60 ladder itself:
      // stdin.end() (EOF) → wait 2s → SIGTERM → wait 2s → SIGKILL.
      await this.clientTransport?.close().catch(() => {
        // best-effort; the reap check below is the real guarantee.
      });
      await this.awaitReap();
    }

    // Now close the client-facing transport (last, so any final child→client
    // output could still flow during a graceful child shutdown).
    await this.serverTransport?.close().catch(() => {});

    if (!this.onCloseFired) {
      this.onCloseFired = true;
      this.onClose?.({ reason });
    }
    this.diag(`torn down (${reason})`);
  }

  /**
   * Guarantee no orphan: wait for the child's `close` event, but never hang —
   * if it hasn't fired within {@link REAP_SAFETY_MS} and the pid is somehow
   * still alive, force SIGKILL and wait again.
   */
  private async awaitReap(): Promise<void> {
    await Promise.race([this.childExited, delay(REAP_SAFETY_MS)]);
    if (this.capturedPid !== undefined && isAlive(this.capturedPid)) {
      try {
        process.kill(this.capturedPid, "SIGKILL");
      } catch {
        // race: exited between the probe and the kill.
      }
      await this.childExited;
    }
  }
}

/**
 * Create a transparent stdio MCP proxy (R59). Spawns `serverCommand` as a child
 * and relays line-framed JSON-RPC in both directions, byte/shape-faithfully,
 * with `id` correlation and notification ordering preserved. See
 * {@link CreateStdioProxyOptions} and this module's header for the design.
 */
export function createStdioProxy(opts: CreateStdioProxyOptions): StdioProxy {
  return new StdioProxyImpl(opts);
}
