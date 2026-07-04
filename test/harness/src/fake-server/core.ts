/**
 * @knotrust/test-harness — fake MCP server core (P0-E11-T1, R53/R54).
 *
 * `buildFakeServer` is the shared-core factoring R53 asks for: it builds a
 * fully-configured, transport-agnostic `@modelcontextprotocol/sdk` `Server`
 * instance (low-level `Server`, not `McpServer` — the deprecation notice on
 * `Server` says "only use for advanced use cases," and drift/chaos/crash/
 * oversized-payload/callLog are exactly that). Nothing in this module
 * touches a transport; `start.ts` (in-process) and `process-entry.ts`
 * (child-process, via `bin.mjs`) each connect the SAME kind of server
 * object to a different `Transport` implementation. That is the whole
 * shared-core idea: one config, one server-building function, two
 * transports.
 *
 * Wire-shape correctness is delegated to the official SDK: this module
 * registers handlers via `Server#setRequestHandler(ListToolsRequestSchema |
 * CallToolRequestSchema, ...)`, so `initialize` capability negotiation,
 * JSON-RPC framing, and result-schema validation are all the SDK's real,
 * spec-conformant implementation — the harness only supplies the
 * configurable *behavior* inside each handler.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  type CallToolResult,
  ListToolsRequestSchema,
  type ListToolsResult,
  type ServerNotification,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import type { SeededPrng } from "../prng.js";
import { formatCallLogLine } from "./call-log.js";
import type {
  CallLogEntry,
  FakeCallToolResult,
  FakeServerConfig,
  FakeToolDef,
  ToolBehaviorSpec,
  ToolRespondSpec,
} from "./types.js";

/** A `buildFakeServer` result: the connectable SDK server plus harness-side introspection. */
export interface FakeServerHandle {
  /** Not yet connected to any transport — call `server.connect(transport)`. */
  server: Server;
  /** Live call log; for in-process mode this array reference IS the log of record. */
  callLog: CallLogEntry[];
  /** Current (possibly drift-patched) served tool definitions, for assertions. */
  getServedTools(): FakeToolDef[];
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function resolveDelay(
  delayMs: ToolBehaviorSpec["delayMs"],
  prng: SeededPrng,
): number {
  if (delayMs === undefined) {
    return 0;
  }
  if (typeof delayMs === "number") {
    return delayMs;
  }
  return prng.nextInt(delayMs.min, delayMs.max);
}

function toWireTool(def: FakeToolDef): Tool {
  return {
    name: def.name,
    ...(def.description !== undefined ? { description: def.description } : {}),
    inputSchema: def.inputSchema,
    ...(def.annotations !== undefined ? { annotations: def.annotations } : {}),
  } as Tool;
}

/**
 * Sends `notifications/progress`/`notifications/message` heartbeats spread
 * across `totalDelayMs`, then resolves once the full delay has elapsed.
 * Progress notifications require the call's own `progressToken` (MCP: the
 * receiver is not obligated to send progress otherwise); absent that, the
 * harness falls back to `notifications/message` log heartbeats so a
 * `chaos.interleaveNotifications` config still produces interleaved traffic
 * on calls that didn't request progress.
 */
async function interleaveDuringDelay(
  totalDelayMs: number,
  progressToken: string | number | undefined,
  sendNotification: (notification: ServerNotification) => Promise<void>,
  prng: SeededPrng,
  notificationBudget: number,
): Promise<void> {
  const steps = Math.max(1, notificationBudget);
  const chunkMs = Math.max(1, Math.floor(totalDelayMs / steps));
  let elapsed = 0;
  for (let i = 0; i < steps; i++) {
    await sleep(chunkMs);
    elapsed += chunkMs;
    if (progressToken !== undefined) {
      await sendNotification({
        method: "notifications/progress",
        params: { progressToken, progress: i + 1, total: steps },
      });
    } else if (prng.next() < 0.5) {
      await sendNotification({
        method: "notifications/message",
        params: { level: "info", data: `chaos heartbeat ${i + 1}/${steps}` },
      });
    }
  }
  const remaining = totalDelayMs - elapsed;
  if (remaining > 0) {
    await sleep(remaining);
  }
}

/** Approximates a byte count using a single-character fill (default `"x"`, one byte in UTF-8/ASCII). */
function oversizedText(bytes: number, fill: string): string {
  const unit = fill.length > 0 ? fill : "x";
  return unit.repeat(Math.max(0, Math.ceil(bytes / unit.length)));
}

interface RespondContext {
  requestId: string | number;
  signal: AbortSignal;
  progressToken: string | number | undefined;
  sendNotification: (notification: ServerNotification) => Promise<void>;
  server: Server;
  isChildProcess: boolean;
}

async function respondToCall(
  spec: ToolRespondSpec,
  args: Record<string, unknown> | undefined,
  ctx: RespondContext,
): Promise<FakeCallToolResult> {
  switch (spec.type) {
    case "echo":
      return { content: [{ type: "text", text: JSON.stringify(args ?? {}) }] };
    case "fixed":
      return {
        content: spec.content,
        ...(spec.isError !== undefined ? { isError: spec.isError } : {}),
      };
    case "error":
      return { content: [{ type: "text", text: spec.message }], isError: true };
    case "oversized":
      return {
        content: [
          { type: "text", text: oversizedText(spec.bytes, spec.fill ?? "x") },
        ],
      };
    case "crash": {
      if (spec.via === "throw") {
        throw new Error("knotrust-fake-server: configured crash (throw)");
      }
      // via === "exit": in child mode, really exit the process — the
      // client observes a genuine dead subprocess, matching production.
      if (ctx.isChildProcess) {
        process.exit(1);
      }
      // In-process mode cannot call process.exit() (it would kill the test
      // runner). Instead close the shared transport: the client observes
      // the same externally-visible symptom — connection closed mid-call,
      // no response ever arrives — without touching the host process. The
      // in-flight response send that follows this handler settling is
      // caught internally by the SDK's Protocol layer (routed to
      // `onerror`), so this never surfaces as an unhandled rejection.
      await ctx.server.close();
      return new Promise<FakeCallToolResult>(() => {
        /* never resolves — the transport is already closed. */
      });
    }
    case "custom":
      if (ctx.isChildProcess) {
        throw new Error(
          "knotrust-fake-server: 'custom' tool behavior handlers cannot run in child-process mode " +
            "(a JS closure cannot cross the process boundary) — use in-process mode for this config.",
        );
      }
      return spec.handler(args, {
        requestId: ctx.requestId,
        signal: ctx.signal,
        // The custom-handler contract (types.ts) deliberately widens the
        // notification shape to an arbitrary {method, params} bag (it must
        // not force every handler author to import SDK notification
        // types); the SDK's own `sendNotification` is narrower
        // (`ServerNotification`'s known method/params union), so adapt with
        // a cast at this one boundary rather than loosening the SDK-facing
        // type everywhere else in this module.
        sendNotification: (notification) =>
          ctx.sendNotification(notification as ServerNotification),
      });
    default: {
      const exhaustive: never = spec;
      throw new Error(
        `knotrust-fake-server: unhandled tool behavior ${JSON.stringify(exhaustive)}`,
      );
    }
  }
}

/**
 * Builds a configured, not-yet-connected fake MCP server. `isChildProcess`
 * controls only how `respond: {type: "crash", via: "exit"}` is realized
 * (see `respondToCall`) — everything else behaves identically in both
 * modes, which is the point: the same `FakeServerConfig` drives the same
 * observable protocol behavior whether connected in-process or spawned as a
 * real child (module doc-comment above).
 */
export function buildFakeServer(
  config: FakeServerConfig,
  prng: SeededPrng,
  options: {
    isChildProcess: boolean;
    onCallLogEntry?: (entry: CallLogEntry) => void;
  } = { isChildProcess: false },
): FakeServerHandle {
  const callLog: CallLogEntry[] = [];
  const tools: FakeToolDef[] = config.tools.map((tool) => ({ ...tool }));
  let freshListCallCount = 0;

  const server = new Server(
    {
      name: config.serverInfo?.name ?? "knotrust-fake-server",
      version: config.serverInfo?.version ?? "0.0.0",
    },
    { capabilities: { tools: {}, logging: {} } },
  );

  server.setRequestHandler(
    ListToolsRequestSchema,
    async (request): Promise<ListToolsResult> => {
      const cursor = request.params?.cursor;
      if (cursor === undefined) {
        freshListCallCount += 1;
        for (const rule of config.driftAfter ?? []) {
          if (freshListCallCount > rule.afterListCallCount) {
            const idx = tools.findIndex((tool) => tool.name === rule.toolName);
            if (idx !== -1) {
              const current = tools[idx];
              if (current !== undefined) {
                tools[idx] = { ...current, ...rule.patch };
              }
            }
          }
        }
      }

      const pageSize = config.pagination?.pageSize ?? Math.max(tools.length, 1);
      const start = cursor !== undefined ? Number(cursor) : 0;
      const page = tools.slice(start, start + pageSize);
      const nextCursorValue =
        start + pageSize < tools.length ? String(start + pageSize) : undefined;
      return {
        tools: page.map(toWireTool),
        ...(nextCursorValue !== undefined
          ? { nextCursor: nextCursorValue }
          : {}),
      };
    },
  );

  server.setRequestHandler(
    CallToolRequestSchema,
    async (request, extra): Promise<CallToolResult> => {
      const { name, arguments: args } = request.params;
      const entry: CallLogEntry = {
        toolName: name,
        arguments: args,
        requestId: extra.requestId,
        receivedAtMs: Date.now(),
      };
      callLog.push(entry);
      options.onCallLogEntry?.(entry);
      if (options.isChildProcess) {
        process.stderr.write(`${formatCallLogLine(entry)}\n`);
      }

      const behavior = config.toolBehaviors?.[name];
      const progressToken = request.params._meta?.progressToken;
      const sendNotification = extra.sendNotification as (
        notification: ServerNotification,
      ) => Promise<void>;

      if (behavior === undefined) {
        return {
          content: [{ type: "text", text: JSON.stringify(args ?? {}) }],
        };
      }

      const delay = resolveDelay(behavior.delayMs, prng);
      if (delay > 0) {
        if (config.chaos?.interleaveNotifications) {
          await interleaveDuringDelay(
            delay,
            progressToken,
            sendNotification,
            prng,
            config.chaos.notificationBudget ?? 2,
          );
        } else {
          await sleep(delay);
        }
      }

      // `FakeCallToolResult` intentionally omits the index signature the
      // SDK's real (`z.core.$loose`) `CallToolResultSchema` carries — cast at
      // this one boundary rather than widening the harness-facing type.
      return (await respondToCall(behavior.respond, args, {
        requestId: extra.requestId,
        signal: extra.signal,
        progressToken,
        sendNotification,
        server,
        isChildProcess: options.isChildProcess,
      })) as CallToolResult;
    },
  );

  return {
    server,
    callLog,
    getServedTools: () => tools.map((tool) => ({ ...tool })),
  };
}
