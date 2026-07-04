/**
 * @knotrust/test-harness — fake scripted MCP client (P0-E11-T1, R55).
 *
 * `FakeClient` is deliberately NOT a thin wrapper over the SDK's own
 * `Client` class. It hand-constructs every JSON-RPC request/notification
 * itself (over a real SDK `Transport` — `StdioClientTransport`,
 * `InMemoryTransport`, or, later, whatever a proxy under test exposes), for
 * two reasons the SDK's high-level `Client` cannot give us:
 *
 * 1. **Every frame, unconditionally.** `client.frames` must capture every
 *    message sent and received, including malformed/unroutable ones — the
 *    substrate `scanFrames`-based assertions (E5-T4, E11) need. The SDK's
 *    `Client`/`Protocol` classes only surface messages through resolved
 *    request promises and registered notification handlers; a raw
 *    send/onmessage tap is the only place that sees literally everything.
 * 2. **A true "timeout without cancelling."** The SDK's own `Protocol.request`
 *    timeout path (`shared/protocol.js`) ALWAYS sends `notifications/cancelled`
 *    on timeout — it shares the exact same `cancel()` closure used for
 *    explicit `AbortSignal` cancellation. R55 requires two *distinct*
 *    simulated client behaviors: a client that silently gives up (no wire
 *    message at all — `callToolWithTimeout`) and a client that explicitly
 *    cancels (`callToolWithCancel`, which does send
 *    `notifications/cancelled`). Only a hand-rolled request layer can tell
 *    those apart; there is no SDK option that produces the first.
 *
 * The wire format is still 100% real MCP 2025-11-25 JSON-RPC: every message
 * this class builds is sent over the SDK's own real `Transport`
 * implementations, so byte framing (stdio line-delimited JSON, or the
 * in-memory queue) is the SDK's, not reimplemented here.
 */

import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";
import { type Frame, type FrameDirection, scanFrames } from "../frame.js";

export interface FakeClientOptions {
  clientInfo?: { name: string; version: string };
  protocolVersion?: string;
}

interface PendingResponse {
  resolve: (result: unknown) => void;
  reject: (error: unknown) => void;
}

export type ProgressHandler = (params: {
  progress: number;
  total?: number;
  message?: string;
}) => void;

export interface CallToolOptions {
  progressToken?: string | number;
  onProgress?: ProgressHandler;
}

export type CallToolTimeoutResult =
  | { status: "completed"; result: CallToolResult }
  | { status: "timedOut" };

export type CallToolCancelResult =
  | { status: "completed"; result: CallToolResult }
  | { status: "cancelled" };

function tokenKey(token: string | number): string {
  return `${typeof token}:${token}`;
}

function isJsonRpcId(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}

/** True if `message` is a JSON-RPC response object (has `id`, no `method`). */
function isResponseMessage(message: unknown): message is {
  id: string | number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
} {
  return (
    typeof message === "object" &&
    message !== null &&
    "id" in message &&
    isJsonRpcId((message as { id: unknown }).id) &&
    !("method" in message)
  );
}

export class FakeClient {
  readonly frames: Frame[] = [];

  private readonly transport: Transport;
  private readonly options: FakeClientOptions;
  private nextId = 0;
  private nextSeq = 0;
  private started = false;
  private readonly pendingResponses = new Map<
    string | number,
    PendingResponse
  >();
  private readonly progressHandlers = new Map<string, ProgressHandler>();

  constructor(transport: Transport, options: FakeClientOptions = {}) {
    this.transport = transport;
    this.options = options;
    // Per the SDK's Transport contract: callbacks must be installed before
    // start() is called, or early messages may be lost.
    transport.onmessage = (message) => this.handleIncoming(message);
  }

  private recordFrame(direction: FrameDirection, message: unknown): void {
    this.frames.push({
      seq: this.nextSeq++,
      direction,
      atMs: performance.now(),
      message,
    });
  }

  private async sendRaw(message: Record<string, unknown>): Promise<void> {
    this.recordFrame("sent", message);
    await this.transport.send(message as never);
  }

  private handleIncoming(message: unknown): void {
    this.recordFrame("recv", message);

    if (
      typeof message === "object" &&
      message !== null &&
      "method" in message &&
      (message as { method: unknown }).method === "notifications/progress"
    ) {
      const params = (
        message as {
          params?: {
            progressToken?: string | number;
            progress: number;
            total?: number;
            message?: string;
          };
        }
      ).params;
      if (params?.progressToken !== undefined) {
        this.progressHandlers.get(tokenKey(params.progressToken))?.(params);
      }
      return;
    }

    if (isResponseMessage(message)) {
      const pending = this.pendingResponses.get(message.id);
      if (pending === undefined) {
        // No one is waiting anymore (e.g. the call already timed out or was
        // cancelled client-side). The frame is still recorded above — this
        // is the "late arrival after the client already gave up" case R55
        // asks the timeout/cancel simulations to be able to produce.
        return;
      }
      this.pendingResponses.delete(message.id);
      if (message.error !== undefined) {
        pending.reject(
          new Error(`${message.error.message} (code ${message.error.code})`),
        );
      } else {
        pending.resolve(message.result);
      }
    }
  }

  /** Sends a request and registers a pending resolver; does not await the response. */
  private sendRequest(
    method: string,
    params: Record<string, unknown> | undefined,
  ): { id: number; promise: Promise<unknown> } {
    const id = this.nextId++;
    const promise = new Promise<unknown>((resolve, reject) => {
      this.pendingResponses.set(id, { resolve, reject });
    });
    void this.sendRaw({
      jsonrpc: "2.0",
      id,
      method,
      ...(params !== undefined ? { params } : {}),
    }).catch((error) => {
      const pending = this.pendingResponses.get(id);
      this.pendingResponses.delete(id);
      pending?.reject(error);
    });
    return { id, promise };
  }

  private async notify(
    method: string,
    params?: Record<string, unknown>,
  ): Promise<void> {
    await this.sendRaw({
      jsonrpc: "2.0",
      method,
      ...(params !== undefined ? { params } : {}),
    });
  }

  /**
   * Starts the transport and performs the full `initialize` handshake:
   * request → response → `notifications/initialized`. Must be called
   * exactly once, before any other method.
   */
  async connect(): Promise<unknown> {
    if (this.started) {
      throw new Error("FakeClient.connect: already connected");
    }
    this.started = true;
    await this.transport.start();
    const { promise } = this.sendRequest("initialize", {
      protocolVersion: this.options.protocolVersion ?? LATEST_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: this.options.clientInfo ?? {
        name: "knotrust-fake-client",
        version: "0.0.0",
      },
    });
    const result = await promise;
    await this.notify("notifications/initialized");
    return result;
  }

  /** Fetches one `tools/list` page. */
  async listToolsPage(
    cursor?: string,
  ): Promise<{ tools: Tool[]; nextCursor?: string }> {
    const { promise } = this.sendRequest(
      "tools/list",
      cursor !== undefined ? { cursor } : undefined,
    );
    return promise as Promise<{ tools: Tool[]; nextCursor?: string }>;
  }

  /** Collects every `tools/list` page into one array, following `nextCursor`. */
  async listAllTools(): Promise<{ tools: Tool[]; pageCount: number }> {
    const tools: Tool[] = [];
    let cursor: string | undefined;
    let pageCount = 0;
    do {
      const page = await this.listToolsPage(cursor);
      tools.push(...page.tools);
      cursor = page.nextCursor;
      pageCount += 1;
    } while (cursor !== undefined);
    return { tools, pageCount };
  }

  /** Plain `tools/call`, optionally with a progress token/handler. Resolves once the server responds; never times out on its own (use `callToolWithTimeout`/`callToolWithCancel` for that). */
  async callTool(
    name: string,
    args: Record<string, unknown> | undefined,
    opts: CallToolOptions = {},
  ): Promise<CallToolResult> {
    const token =
      opts.progressToken ?? (opts.onProgress ? this.nextId : undefined);
    const params: Record<string, unknown> = { name, arguments: args ?? {} };
    if (token !== undefined) {
      params._meta = { progressToken: token };
    }
    if (opts.onProgress && token !== undefined) {
      this.progressHandlers.set(tokenKey(token), opts.onProgress);
    }
    const { promise } = this.sendRequest("tools/call", params);
    try {
      return (await promise) as CallToolResult;
    } finally {
      if (token !== undefined) {
        this.progressHandlers.delete(tokenKey(token));
      }
    }
  }

  /**
   * Simulates a client-side call deadline. If the server hasn't responded
   * within `deadlineMs`, resolves to `{status: "timedOut"}` WITHOUT sending
   * any wire message — the pending-response bookkeeping is simply dropped,
   * so a response that arrives later is recorded in `frames` (still real
   * traffic) but delivered to no one. This models a naive client that just
   * gives up locally. For the variant that tells the server, see
   * `callToolWithCancel`.
   */
  async callToolWithTimeout(
    name: string,
    args: Record<string, unknown> | undefined,
    opts: CallToolOptions & { deadlineMs: number },
  ): Promise<CallToolTimeoutResult> {
    const token =
      opts.progressToken ?? (opts.onProgress ? this.nextId : undefined);
    const params: Record<string, unknown> = { name, arguments: args ?? {} };
    if (token !== undefined) {
      params._meta = { progressToken: token };
    }
    if (opts.onProgress && token !== undefined) {
      this.progressHandlers.set(tokenKey(token), opts.onProgress);
    }
    const { id, promise } = this.sendRequest("tools/call", params);

    let timer: ReturnType<typeof setTimeout>;
    const timedOut = new Promise<CallToolTimeoutResult>((resolve) => {
      timer = setTimeout(() => {
        this.pendingResponses.delete(id);
        if (token !== undefined) {
          this.progressHandlers.delete(tokenKey(token));
        }
        resolve({ status: "timedOut" });
      }, opts.deadlineMs);
    });
    const completed = promise.then((result): CallToolTimeoutResult => {
      clearTimeout(timer);
      return { status: "completed", result: result as CallToolResult };
    });
    return Promise.race([completed, timedOut]);
  }

  /**
   * Simulates an explicit client-side cancel: if the server hasn't
   * responded within `cancelAfterMs`, sends a real `notifications/cancelled`
   * frame (`params.requestId` = this call's JSON-RPC id) and resolves to
   * `{status: "cancelled"}`. This is the "cancel variant sending
   * notifications/cancelled" R55 asks for, distinct from
   * `callToolWithTimeout`'s silent give-up.
   */
  async callToolWithCancel(
    name: string,
    args: Record<string, unknown> | undefined,
    opts: CallToolOptions & { cancelAfterMs: number; reason?: string },
  ): Promise<CallToolCancelResult> {
    const token =
      opts.progressToken ?? (opts.onProgress ? this.nextId : undefined);
    const params: Record<string, unknown> = { name, arguments: args ?? {} };
    if (token !== undefined) {
      params._meta = { progressToken: token };
    }
    if (opts.onProgress && token !== undefined) {
      this.progressHandlers.set(tokenKey(token), opts.onProgress);
    }
    const { id, promise } = this.sendRequest("tools/call", params);

    let timer: ReturnType<typeof setTimeout>;
    const cancelled = new Promise<CallToolCancelResult>((resolve) => {
      timer = setTimeout(() => {
        this.pendingResponses.delete(id);
        if (token !== undefined) {
          this.progressHandlers.delete(tokenKey(token));
        }
        void this.notify("notifications/cancelled", {
          requestId: id,
          ...(opts.reason !== undefined ? { reason: opts.reason } : {}),
        }).then(() => resolve({ status: "cancelled" }));
      }, opts.cancelAfterMs);
    });
    const completed = promise.then((result): CallToolCancelResult => {
      clearTimeout(timer);
      return { status: "completed", result: result as CallToolResult };
    });
    return Promise.race([completed, cancelled]);
  }

  /** Closes the transport (the "shutdown" step of a scripted conversation). */
  async close(): Promise<void> {
    await this.transport.close();
  }

  // --- Assertion helpers (R55: "helper methods, not bare expects") ---------

  /** Every method name observed in outbound (`sent`) frames, in order. */
  getSentMethods(): string[] {
    return scanFrames(this.frames, (f) => f.direction === "sent")
      .map((f) => (f.message as { method?: unknown }).method)
      .filter((m): m is string => typeof m === "string");
  }

  /** Every method name observed in inbound (`recv`) frames, in order (requests, responses have none, notifications do). */
  getReceivedNotificationMethods(): string[] {
    return scanFrames(this.frames, (f) => f.direction === "recv")
      .map((f) => (f.message as { method?: unknown }).method)
      .filter((m): m is string => typeof m === "string");
  }

  /** Throws unless `methods` appear, in order, as a (possibly non-contiguous) subsequence of sent request/notification methods. */
  assertSentMethodOrder(methods: readonly string[]): void {
    const sent = this.getSentMethods();
    let cursor = 0;
    for (const method of methods) {
      const idx = sent.indexOf(method, cursor);
      if (idx === -1) {
        throw new Error(
          `assertSentMethodOrder: expected "${method}" after position ${cursor} in sent methods ${JSON.stringify(sent)}`,
        );
      }
      cursor = idx + 1;
    }
  }

  /** Throws if any RECEIVED frame's JSON serialization contains any of `substrings`. Generic leak-scan primitive — the harness itself asserts nothing about what should never leak (R57: policy-agnostic); callers supply the substrings. */
  assertNoLeakedSubstrings(substrings: readonly string[]): void {
    for (const frame of this.frames) {
      if (frame.direction !== "recv") {
        continue;
      }
      const serialized = JSON.stringify(frame.message);
      for (const needle of substrings) {
        if (serialized.includes(needle)) {
          throw new Error(
            `assertNoLeakedSubstrings: found "${needle}" in received frame #${frame.seq}: ${serialized}`,
          );
        }
      }
    }
  }

  /** Returns every received frame that is a notification for `method` (e.g. `"notifications/progress"`). */
  receivedNotificationsOf(method: string): Frame[] {
    return scanFrames(
      this.frames,
      (f) =>
        f.direction === "recv" &&
        (f.message as { method?: unknown }).method === method,
    );
  }
}
