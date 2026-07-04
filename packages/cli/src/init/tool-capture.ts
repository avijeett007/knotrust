/**
 * knotrust CLI `init` — best-effort `tools/list` capture (P0-E7-T1, R109).
 *
 * `knotrust init` seeds suggested tiers for the generated `knotrust.config.*`
 * by actually talking to the wrapped server: a REAL, one-shot MCP client
 * connection (the SDK's own `Client`/`StdioClientTransport` — the same
 * transport `@knotrust/proxy-stdio`'s runner uses, but here `init` is the
 * CLIENT, not a relay) that runs the `initialize` handshake and pages
 * through a full `tools/list` listing, then builds a `ToolInventory` via
 * `@knotrust/proxy-stdio`'s own `buildToolInventorySnapshot` — the exact
 * same snapshot shape/logic the E5-T2 live observer produces from real
 * traffic, reused here for a single point-in-time capture instead of
 * continuous proxying (R109: "reuse the observer path").
 *
 * **This is deliberately BEST-EFFORT (R109).** The target server may need
 * credentials, network access, or a running dependency `knotrust init`
 * cannot assume it has. ANY failure — the command doesn't exist, the process
 * exits immediately, it never speaks MCP, or it just doesn't answer inside
 * `timeoutMs` — resolves to `undefined` rather than throwing or hanging.
 * `command.ts`'s generated-config step treats `undefined` as "generate a
 * skeleton with `unknownToolTier: sensitive` and a note that tiers will seed
 * on a future successful run," never as a reason to abort `init` itself.
 */

import {
  buildToolInventorySnapshot,
  type ToolInventory,
} from "@knotrust/proxy-stdio";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

export interface CaptureToolInventoryOptions {
  /** Give up (and return `undefined`) if the whole capture hasn't finished by this many ms. Default 8000. */
  timeoutMs?: number;
  /** Safety cap on `tools/list` pagination — never trust a server's `nextCursor` to terminate on its own. Default 50. */
  maxPages?: number;
  /** Extra env for the spawned server (typically the client config entry's own declared `env`), layered UNDER the SDK's safe-subset default (see `StdioClientTransport`'s own `getDefaultEnvironment`). */
  env?: Record<string, string>;
  /** Injectable clock (ms), threaded into the snapshot's `capturedAt`. Defaults to `Date.now`. */
  nowMs?: () => number;
}

const DEFAULT_TIMEOUT_MS = 8_000;
const DEFAULT_MAX_PAGES = 50;

async function pageThroughToolsList(
  client: Client,
  maxPages: number,
): Promise<Tool[]> {
  const tools: Tool[] = [];
  let cursor: string | undefined;
  let pages = 0;
  do {
    const params = cursor !== undefined ? { cursor } : undefined;
    const result = await client.listTools(params);
    tools.push(...(result.tools as Tool[]));
    cursor = result.nextCursor;
    pages++;
  } while (cursor !== undefined && pages < maxPages);
  return tools;
}

function delay(ms: number): Promise<never> {
  return new Promise((_, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`knotrust: tools/list capture timed out after ${ms}ms`));
    }, ms);
    timer.unref();
  });
}

/**
 * Attempts a real one-shot `tools/list` capture against `serverCommand`
 * (the ORIGINAL, unwrapped argv — `["node", "server.js", ...]`, never the
 * knotrust-wrapped form). Returns the built {@link ToolInventory} on success,
 * `undefined` on any failure/timeout (see this module's header). The child
 * is always spawned fresh and torn down before this resolves, whichever way.
 */
export async function captureToolInventory(
  serverCommand: readonly string[],
  opts: CaptureToolInventoryOptions = {},
): Promise<ToolInventory | undefined> {
  const command = serverCommand[0];
  if (command === undefined) return undefined;
  const args = serverCommand.slice(1);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxPages = opts.maxPages ?? DEFAULT_MAX_PAGES;
  const nowMs = opts.nowMs ?? Date.now;

  const client = new Client({ name: "knotrust-init", version: "0.0.0" });
  const transport = new StdioClientTransport({
    command,
    args,
    ...(opts.env !== undefined ? { env: opts.env } : {}),
    // Never let the target server's stderr leak onto knotrust init's own
    // output during a best-effort probe — `stdio.ts`'s SDK default is
    // "inherit", which would pollute this command's real stderr.
    stderr: "ignore",
  });

  try {
    const tools = await Promise.race([
      (async () => {
        await client.connect(transport);
        return pageThroughToolsList(client, maxPages);
      })(),
      delay(timeoutMs),
    ]);
    return buildToolInventorySnapshot(tools, new Date(nowMs()).toISOString());
  } catch {
    return undefined;
  } finally {
    try {
      await client.close();
    } catch {
      // Best-effort teardown — a close() failure must never surface over a
      // successful (or already-failed) capture result.
    }
  }
}
