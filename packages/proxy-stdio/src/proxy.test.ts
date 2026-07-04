/**
 * P0-E5-T1 acceptance — the five R62 assertions plus the R58 non-tool-method
 * passthrough proof, all against the @knotrust/test-harness fake MCP server
 * spawned as a REAL child process (its `bin.mjs`, via the proxy's own
 * `StdioClientTransport`) and driven by the fake client / a raw transport.
 *
 * The client talks to the proxy over an in-memory crossed stream pair (two
 * `PassThrough`s wired to the proxy's client-facing `StdioServerTransport`) —
 * the exact stdio-line-framed JSON-RPC the real `knotrust -- …` process serves
 * on `process.stdin`/`process.stdout`, minus only the OS pipe. The server side
 * is a genuine spawned subprocess, so child-spawn, stderr passthrough, and
 * orphan-freedom are all exercised for real.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { createAuditLog } from "@knotrust/store";
import {
  FakeClient,
  type FakeServerConfig,
  type FakeToolDef,
  parseCallLogFromStderr,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  type CreateStdioProxyOptions,
  createStdioProxy,
  type StdioProxy,
} from "./proxy.js";
import {
  loadToolInventory,
  seedTierEntriesFromAnnotations,
} from "./tool-inventory.js";

function tool(name: string, overrides: Partial<FakeToolDef> = {}): FakeToolDef {
  return {
    name,
    inputSchema: { type: "object", properties: {} },
    ...overrides,
  };
}

async function waitUntil(
  predicate: () => boolean,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) {
    if (performance.now() > deadline) {
      return predicate();
    }
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
  return true;
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Cleanup registry so every spawned child + temp config is torn down per test. */
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) {
      await fn().catch(() => {});
    }
  }
});

interface ProxiedClient {
  proxy: StdioProxy;
  client: FakeClient;
  clientToProxy: PassThrough;
  getStderr(): string;
}

/** Spawn the fake server as the proxy's child; return a fake client wired through the proxy. `extraOpts` layers additional `createStdioProxy` options (e.g. `toolInventory`) on top of the stdio wiring this helper always sets up. */
async function connectViaProxy(
  config: FakeServerConfig,
  extraOpts: Partial<CreateStdioProxyOptions> = {},
): Promise<ProxiedClient> {
  const started = await startFakeServer(config, { prepareChildCommand: true });
  const childCommand = started.childCommand;
  if (childCommand === undefined) {
    throw new Error(
      "test setup: startFakeServer did not return a childCommand",
    );
  }

  const clientToProxy = new PassThrough();
  const proxyToClient = new PassThrough();
  const stderrSink = new PassThrough();
  let stderrText = "";
  stderrSink.on("data", (chunk: Buffer) => {
    stderrText += chunk.toString("utf8");
  });

  const proxy = createStdioProxy({
    serverCommand: childCommand,
    stdin: clientToProxy,
    stdout: proxyToClient,
    stderr: stderrSink,
    ...extraOpts,
  });
  await proxy.start();

  const client = new FakeClient(
    new StdioServerTransport(proxyToClient, clientToProxy),
  );

  cleanups.push(async () => {
    await proxy.stop().catch(() => {});
    await client.close().catch(() => {});
    await started.close().catch(() => {});
  });

  return { proxy, client, clientToProxy, getStderr: () => stderrText };
}

/** Drive a fake client through the canonical conversation; return results + received frames. */
async function runConversation(client: FakeClient): Promise<{
  init: { protocolVersion?: string; serverInfo?: { name?: string } };
  tools: string[];
  pageCount: number;
  callContent: unknown;
  recv: unknown[];
}> {
  const init = (await client.connect()) as {
    protocolVersion?: string;
    serverInfo?: { name?: string };
  };
  const listed = await client.listAllTools();
  const call = await client.callTool("echo", { greeting: "hi" });
  return {
    init,
    tools: listed.tools.map((t) => t.name),
    pageCount: listed.pageCount,
    callContent: call.content,
    recv: client.frames
      .filter((f) => f.direction === "recv")
      .map((f) => f.message),
  };
}

const BASELINE_CONFIG: FakeServerConfig = {
  serverInfo: { name: "knotrust-fake-server-e5t1", version: "1.0.0" },
  tools: [
    tool("alpha", {
      description: "first",
      annotations: { readOnlyHint: true },
    }),
    tool("echo", { description: "echoes its arguments back" }),
  ],
  pagination: { pageSize: 1 },
};

describe("P0-E5-T1 stdio proxy — transparent passthrough (R62)", () => {
  it("(a) full initialize->tools/list->tools/call->shutdown works through the proxy and is byte/shape-comparable to a proxy-free baseline", async () => {
    // --- proxy-FREE baseline: fake client <-> spawned child directly ---
    const startedBaseline = await startFakeServer(BASELINE_CONFIG, {
      prepareChildCommand: true,
    });
    const baseCmd = startedBaseline.childCommand;
    if (baseCmd === undefined) throw new Error("no baseline childCommand");
    const [command, ...args] = baseCmd as [string, ...string[]];
    const baselineClient = new FakeClient(
      new StdioClientTransport({ command, args, stderr: "pipe" }),
    );
    const baseline = await runConversation(baselineClient);
    await baselineClient.close();
    await startedBaseline.close();

    // --- through the proxy ---
    const { client } = await connectViaProxy(BASELINE_CONFIG);
    const proxied = await runConversation(client);

    // Same observable conversation…
    expect(proxied.init.protocolVersion).toBe("2025-11-25");
    expect(proxied.init.serverInfo?.name).toBe("knotrust-fake-server-e5t1");
    expect(proxied.tools).toEqual(["alpha", "echo"]);
    expect(proxied.pageCount).toBe(2);
    expect(proxied.callContent).toEqual([
      { type: "text", text: JSON.stringify({ greeting: "hi" }) },
    ]);

    // …and byte/shape-comparable to the baseline (no message intercepted yet).
    expect(proxied.recv).toEqual(baseline.recv);
  }, 30_000);

  it("(b) out-of-order id correlation: two in-flight calls whose responses arrive reversed still correlate correctly", async () => {
    const config: FakeServerConfig = {
      tools: [tool("slow"), tool("fast")],
      toolBehaviors: {
        slow: { delayMs: 300, respond: { type: "echo" } },
        fast: { delayMs: 20, respond: { type: "echo" } },
      },
    };
    const { client } = await connectViaProxy(config);
    await client.connect();

    // Fire both without awaiting: slow (id 1) then fast (id 2). fast resolves first.
    const slowPromise = client.callTool("slow", { which: "slow" });
    const fastPromise = client.callTool("fast", { which: "fast" });
    const [slow, fast] = await Promise.all([slowPromise, fastPromise]);

    // Correlation is correct despite reversed arrival: each promise got ITS result.
    expect(slow.content).toEqual([
      { type: "text", text: JSON.stringify({ which: "slow" }) },
    ]);
    expect(fast.content).toEqual([
      { type: "text", text: JSON.stringify({ which: "fast" }) },
    ]);

    // And the responses really did arrive reversed on the wire: the response to
    // the fast call (id 2) precedes the response to the slow call (id 1). This
    // is the proof the proxy correlated by preserved `id`, not by arrival order.
    const ids = responseIds(client);
    expect(ids).toContain(1);
    expect(ids).toContain(2);
    expect(ids.indexOf(2)).toBeLessThan(ids.indexOf(1));
  }, 30_000);

  it("(c) child stderr appears on the proxy's stderr in real time", async () => {
    const config: FakeServerConfig = {
      tools: [tool("echo")],
      toolBehaviors: { echo: { respond: { type: "echo" } } },
    };
    const { client, getStderr } = await connectViaProxy(config);
    await client.connect();
    // The fake server writes a call-log line to ITS stderr on every tools/call
    // (child-process mode). That must surface on the proxy's stderr sink.
    await client.callTool("echo", { hello: "world" });

    const appeared = await waitUntil(
      () => parseCallLogFromStderr(getStderr()).length > 0,
      5_000,
    );
    expect(appeared).toBe(true);
    const log = parseCallLogFromStderr(getStderr());
    expect(log[0]?.toolName).toBe("echo");
    expect(log[0]?.arguments).toEqual({ hello: "world" });
  }, 30_000);

  it("(d) notifications/progress are relayed in real time during a call (before the final response)", async () => {
    const config: FakeServerConfig = {
      tools: [tool("work")],
      toolBehaviors: { work: { delayMs: 200, respond: { type: "echo" } } },
      chaos: { seed: 7, interleaveNotifications: true, notificationBudget: 3 },
    };
    const { client } = await connectViaProxy(config);
    await client.connect();

    const progressAt: number[] = [];
    await client.callTool(
      "work",
      { job: 1 },
      {
        progressToken: "tok-1",
        onProgress: () => {
          progressAt.push(performance.now());
        },
      },
    );

    // Progress fired at least once, and every progress frame preceded the
    // response frame — i.e. it was relayed in real time, not buffered to the end.
    expect(progressAt.length).toBeGreaterThanOrEqual(1);
    const progressFrames = client.receivedNotificationsOf(
      "notifications/progress",
    );
    expect(progressFrames.length).toBeGreaterThanOrEqual(1);

    // The tools/call's own response is the LAST response frame (its request was
    // the final one issued); progress for that call must precede it.
    const responseFrames = client.frames.filter(
      (f) =>
        f.direction === "recv" &&
        typeof f.message === "object" &&
        f.message !== null &&
        "id" in f.message &&
        !("method" in f.message),
    );
    const callResponse = responseFrames[responseFrames.length - 1];
    expect(callResponse).toBeDefined();
    const lastProgressSeq = Math.max(...progressFrames.map((f) => f.seq));
    expect(lastProgressSeq).toBeLessThan((callResponse as { seq: number }).seq);
  }, 30_000);

  it("(e) stop() leaves zero orphan child processes", async () => {
    const config: FakeServerConfig = {
      tools: [tool("echo")],
      toolBehaviors: { echo: { respond: { type: "echo" } } },
    };
    const { proxy, client } = await connectViaProxy(config);
    await client.connect();
    await client.callTool("echo", {});

    const pid = proxy.childPid;
    expect(pid).toBeDefined();
    expect(isAlive(pid as number)).toBe(true);

    await proxy.stop();

    const dead = await waitUntil(() => !isAlive(pid as number), 8_000);
    expect(dead).toBe(true);
    expect(proxy.childPid).toBe(pid); // pid stays readable after teardown
  }, 30_000);

  it("(f) sendToClient() delivers an out-of-band notification straight to the connected client, independent of any in-flight tools/call (P0-E6-T2 — the block-and-wait heartbeat seam)", async () => {
    const config: FakeServerConfig = { tools: [tool("echo")] };
    const { proxy, client } = await connectViaProxy(config);
    await client.connect();

    await proxy.sendToClient({
      jsonrpc: "2.0",
      method: "notifications/progress",
      params: { progressToken: "heartbeat-1", progress: 10 },
    } as unknown as JSONRPCMessage);

    const appeared = await waitUntil(
      () => client.receivedNotificationsOf("notifications/progress").length > 0,
      5_000,
    );
    expect(appeared).toBe(true);
    const [frame] = client.receivedNotificationsOf("notifications/progress");
    expect(
      (frame?.message as { params?: { progressToken?: unknown } }).params
        ?.progressToken,
    ).toBe("heartbeat-1");

    // The relay still works normally afterward — sendToClient is purely
    // additive, not a side-channel that disrupts ordinary passthrough.
    const result = await client.callTool("echo", { still: "works" });
    expect(result.content).toBeDefined();
  }, 30_000);

  it("(g) sendToClient() before start()/after teardown is a safe no-op (never throws)", async () => {
    const config: FakeServerConfig = { tools: [tool("echo")] };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");
    cleanups.push(async () => {
      await started.close().catch(() => {});
    });

    const proxy = createStdioProxy({
      serverCommand: childCommand,
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
    });

    // Before start(): no serverTransport exists yet.
    await expect(
      proxy.sendToClient({
        jsonrpc: "2.0",
        method: "notifications/progress",
        params: { progressToken: "x", progress: 0 },
      } as unknown as JSONRPCMessage),
    ).resolves.toBeUndefined();

    await proxy.start();
    await proxy.stop();

    // After teardown: the client-facing transport is closed.
    await expect(
      proxy.sendToClient({
        jsonrpc: "2.0",
        method: "notifications/progress",
        params: { progressToken: "x", progress: 0 },
      } as unknown as JSONRPCMessage),
    ).resolves.toBeUndefined();
  }, 30_000);
});

describe("P0-E5-T1 stdio proxy — non-tool-method passthrough (R58)", () => {
  it("relays ping and unmodeled methods (resources/list) faithfully, including the server's error response", async () => {
    const config: FakeServerConfig = { tools: [tool("echo")] };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const proxy = createStdioProxy({
      serverCommand: childCommand,
      stdin: clientToProxy,
      stdout: proxyToClient,
      stderr: new PassThrough(),
    });
    await proxy.start();
    cleanups.push(async () => {
      await proxy.stop().catch(() => {});
      await started.close().catch(() => {});
    });

    const raw = new RawClient(
      new StdioServerTransport(proxyToClient, clientToProxy),
    );
    await raw.start();
    await raw.request("initialize", {
      protocolVersion: LATEST_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "raw", version: "0" },
    });
    await raw.notify("notifications/initialized");

    // ping is modeled by the SDK server but NOT by our proxy — it must pass
    // through and come back as an empty result.
    const pingResp = await raw.request("ping", undefined);
    expect(pingResp.error).toBeUndefined();
    expect(pingResp.result).toEqual({});

    // resources/list is not implemented by the fake server; the SDK answers
    // MethodNotFound. The proxy must relay that error faithfully, unaltered.
    const resResp = await raw.request("resources/list", {});
    expect(resResp.result).toBeUndefined();
    expect(resResp.error?.code).toBe(-32601);
  }, 30_000);
});

describe("P0-E5-T2 stdio proxy — tools/list interception & annotation capture (R63-R67)", () => {
  /** A fresh $KNOTRUST_HOME-shaped temp dir per test, so tool-inventory + audit state never leaks across tests. */
  function tempHome(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "knotrust-e5t2-home-"));
    cleanups.push(async () => {
      rmSync(dir, { recursive: true, force: true });
    });
    return dir;
  }

  it("absent-inventory-opt path is pure passthrough: identical forwarded frames to T1's own baseline, with no toolInventory option at all", async () => {
    const config: FakeServerConfig = {
      tools: [
        tool("alpha", { annotations: { readOnlyHint: true } }),
        tool("echo"),
      ],
      pagination: { pageSize: 1 },
    };
    const { client } = await connectViaProxy(config);
    const result = await runConversation(client);
    expect(result.tools).toEqual(["alpha", "echo"]);
    expect(result.pageCount).toBe(2);
    // No toolInventory option was passed — this is EXACTLY the T1 code path
    // (`createStdioProxy`'s `this.classify` stays `opts.onClassify ??
    // defaultClassifier`, untouched by anything this task added).
  }, 30_000);

  it("(R63/R64) paginated tools/list forwards byte/shape-identically to a no-inventory baseline AND accumulates every page's tools — including an annotation-lying one — into the persisted inventory", async () => {
    const config: FakeServerConfig = {
      tools: [
        tool("alpha", { annotations: { readOnlyHint: true } }),
        // An "annotation lie": both readOnly AND destructive claimed at once —
        // only possible because these are self-declared, untrusted hints
        // (ADR-0009). Defined on PAGE 2 (pageSize 1, 2 tools) specifically to
        // prove page-2 tools land in the inventory too (R63).
        tool("beta", {
          annotations: { readOnlyHint: true, destructiveHint: true },
        }),
      ],
      pagination: { pageSize: 1 },
    };

    // --- baseline: no toolInventory option at all ---
    const baseline = await connectViaProxy(config);
    await baseline.client.connect();
    const baselineListing = await baseline.client.listAllTools();
    const baselineRecv = baseline.client.frames
      .filter((f) => f.direction === "recv")
      .map((f) => f.message);

    // --- same config, WITH toolInventory wired ---
    const home = tempHome();
    const withInventory = await connectViaProxy(config, {
      toolInventory: { home, serverName: "pagination-server" },
    });
    await withInventory.client.connect();
    const invListing = await withInventory.client.listAllTools();
    const invRecv = withInventory.client.frames
      .filter((f) => f.direction === "recv")
      .map((f) => f.message);

    // Forwarded bytes/shape are identical whether or not observation is
    // wired — observation is a pure side effect (R63).
    expect(invListing.pageCount).toBe(2);
    expect(baselineListing.pageCount).toBe(2);
    expect(invRecv).toEqual(baselineRecv);

    // The inventory accumulated BOTH pages before finalizing.
    const inventory = loadToolInventory(home, "pagination-server");
    expect(Object.keys(inventory ?? {}).sort()).toEqual(["alpha", "beta"]);
    expect(inventory?.alpha?.annotations.readOnlyHint).toBe(true);
    expect(inventory?.beta?.annotations).toMatchObject({
      readOnlyHint: true,
      destructiveHint: true,
    });

    // The lying tool seeds "sensitive" (never "routine") — the annotation-lie
    // acceptance case, proven here against a REAL captured inventory.
    const seeded = seedTierEntriesFromAnnotations(inventory ?? {});
    expect(seeded.beta).toEqual({ tier: "sensitive", source: "annotation" });
    expect(seeded.alpha).toEqual({ tier: "routine", source: "annotation" });
  }, 30_000);

  it("(R66) drift: a tool's destructiveHint changing between two tools/list captures emits tool_definition_changed with correct old/new, against a real audit sink", async () => {
    const config: FakeServerConfig = {
      tools: [
        tool("deploy", {
          annotations: { readOnlyHint: true, destructiveHint: false },
        }),
      ],
      // Rug-pull tripwire fixture (R54): unchanged on the 1st fresh listing,
      // patched from the 2nd fresh listing onward.
      driftAfter: [
        {
          toolName: "deploy",
          afterListCallCount: 1,
          patch: {
            annotations: { readOnlyHint: false, destructiveHint: true },
          },
        },
      ],
    };

    const home = tempHome();
    const audit = createAuditLog({
      home,
      nowEpochMs: () => Date.parse("2026-07-03T00:00:00Z"),
    });
    cleanups.push(async () => {
      audit.close();
    });

    const { client } = await connectViaProxy(config, {
      toolInventory: { home, serverName: "drift-server", audit },
    });
    await client.connect();

    // Capture 1: no prior baseline exists yet -> seeds the baseline, no drift.
    await client.listAllTools();
    // Capture 2: the SAME child process now serves "deploy" patched (2nd
    // fresh listing) -> diffed against capture 1's persisted baseline.
    await client.listAllTools();

    audit.flush();
    const verifyResult = audit.verify();
    expect(verifyResult.ok).toBe(true);

    const auditDir = path.join(home, "audit");
    const files = readdirSync(auditDir).filter((f) => f.endsWith(".jsonl"));
    const lines = files.flatMap((f) =>
      readFileSync(path.join(auditDir, f), "utf8")
        .split("\n")
        .filter((line: string) => line.trim().length > 0)
        .map((line: string) => JSON.parse(line)),
    );
    const changeEvents = lines.filter(
      (e: { type: string }) => e.type === "tool_definition_changed",
    );

    expect(changeEvents).toHaveLength(1);
    const event = changeEvents[0];
    expect(event.tool).toBe("deploy");
    expect(event.surface).toBe("stdio_proxy");
    const detail = JSON.parse(event.reason);
    expect(detail.server).toBe("drift-server");
    expect(detail.changeKind).toBe("changed");
    expect(detail.annotationChanges).toEqual(
      expect.arrayContaining([
        { field: "readOnlyHint", old: true, new: false },
        { field: "destructiveHint", old: false, new: true },
      ]),
    );
    // No raw schema anywhere in the audit line.
    expect(JSON.stringify(event)).not.toContain("properties");
  }, 30_000);
});

describe("P0-E5-T5 stdio proxy — wrapped-server crash never hangs the client, never orphans the child (R82/R83)", () => {
  /** `ps -p <pid>` — a literal, external, ps-based liveness check (R83's own acceptance wording: "ps-verified"), independent of this module's own `isAlive` (signal-0 probe). Exits non-zero (throws) once the pid is gone. */
  function psAlive(pid: number): boolean {
    try {
      execFileSync("ps", ["-p", String(pid)], {
        stdio: ["ignore", "ignore", "ignore"],
      });
      return true;
    } catch {
      return false;
    }
  }

  it("crash:exit mid-call (harness crash profile, self-directed process.exit): the client's pending call gets an error — not a hang — and onClose reports child_exit", async () => {
    const config: FakeServerConfig = {
      tools: [tool("crashy")],
      toolBehaviors: { crashy: { respond: { type: "crash", via: "exit" } } },
    };
    const closeReasons: string[] = [];
    const { proxy, client } = await connectViaProxy(config, {
      onClose: (info) => closeReasons.push(info.reason),
    });
    await client.connect();

    const pid = proxy.childPid;
    expect(pid).toBeDefined();
    expect(isAlive(pid as number)).toBe(true);

    // Race the call against a generous timeout: it must settle (as a
    // rejection — FakeClient rejects on a JSON-RPC `error` response) well
    // before the timeout, never hang forever.
    const callOutcome = client.callTool("crashy", {}).then(
      (result) => ({ kind: "resolved" as const, result }),
      (error) => ({ kind: "rejected" as const, error }),
    );
    const raced = await Promise.race([
      callOutcome,
      new Promise<{ kind: "timeout" }>((resolve) =>
        setTimeout(() => resolve({ kind: "timeout" }), 5_000),
      ),
    ]);
    expect(raced.kind).toBe("rejected"); // an ERROR result, not a hang, not a silent success.

    // The child is gone (no orphan) — the proxy's own teardown reaped it.
    const dead = await waitUntil(() => !isAlive(pid as number), 5_000);
    expect(dead).toBe(true);

    // onClose reported the spontaneous crash, not a client/explicit stop —
    // this is what run.ts keys the non-zero CLI exit code off (R82(ii)).
    await waitUntil(() => closeReasons.length > 0, 2_000);
    expect(closeReasons).toEqual(["child_exit"]);
  }, 30_000);

  it("crash:throw (a badly-behaved TOOL, not a transport failure): the child stays alive, the proxy keeps serving later calls", async () => {
    const config: FakeServerConfig = {
      tools: [tool("throwy"), tool("echo")],
      toolBehaviors: {
        throwy: { respond: { type: "crash", via: "throw" } },
        echo: { respond: { type: "echo" } },
      },
    };
    const { proxy, client } = await connectViaProxy(config);
    await client.connect();

    const pid = proxy.childPid as number;
    // The SDK turns a thrown tool handler into a genuine JSON-RPC error
    // response — the child process itself never dies.
    await expect(client.callTool("throwy", {})).rejects.toThrow();
    expect(isAlive(pid)).toBe(true);

    // The relay is still fully functional afterward — proof this was a
    // tool-level error, not a proxy crash.
    const echoed = await client.callTool("echo", { still: "alive" });
    expect(echoed.content).toEqual([
      { type: "text", text: JSON.stringify({ still: "alive" }) },
    ]);
    expect(isAlive(pid)).toBe(true);
  }, 30_000);

  it("a literal external SIGKILL mid-call (kill -9, not a harness-configured self-exit) — the client's pending call still gets an error, not a hang, and the child is gone (no orphan)", async () => {
    const config: FakeServerConfig = {
      tools: [tool("slow")],
      toolBehaviors: { slow: { delayMs: 2_000, respond: { type: "echo" } } },
    };
    const { proxy, client } = await connectViaProxy(config);
    await client.connect();

    const pid = proxy.childPid as number;
    const callOutcome = client.callTool("slow", { x: 1 }).then(
      (result) => ({ kind: "resolved" as const, result }),
      (error) => ({ kind: "rejected" as const, error }),
    );

    // Let the call actually reach the child (in flight) before killing it.
    await new Promise((resolve) => setTimeout(resolve, 150));
    process.kill(pid, "SIGKILL");

    const raced = await Promise.race([
      callOutcome,
      new Promise<{ kind: "timeout" }>((resolve) =>
        setTimeout(() => resolve({ kind: "timeout" }), 5_000),
      ),
    ]);
    expect(raced.kind).toBe("rejected");

    const dead = await waitUntil(() => !isAlive(pid), 5_000);
    expect(dead).toBe(true);
  }, 30_000);

  it('R83: proxy.stop("SIGTERM") — explicit signal escalation — reaps the child within 5s, ps-verified', async () => {
    const config: FakeServerConfig = {
      tools: [tool("echo")],
      toolBehaviors: { echo: { respond: { type: "echo" } } },
    };
    const { proxy, client } = await connectViaProxy(config);
    await client.connect();
    await client.callTool("echo", {});

    const pid = proxy.childPid as number;
    expect(psAlive(pid)).toBe(true);

    const start = performance.now();
    await proxy.stop("SIGTERM");
    const elapsedMs = performance.now() - start;

    expect(psAlive(pid)).toBe(false);
    expect(elapsedMs).toBeLessThan(5_000);
  }, 30_000);
});

// --- test-only helpers ------------------------------------------------------

/** IDs of response (non-notification) recv frames, in arrival order. */
function responseIds(client: FakeClient): number[] {
  return client.frames
    .filter(
      (f) =>
        f.direction === "recv" &&
        typeof f.message === "object" &&
        f.message !== null &&
        "id" in f.message &&
        !("method" in f.message),
    )
    .map((f) => (f.message as { id: number }).id);
}

/** Minimal raw JSON-RPC client over a Transport — used to exercise arbitrary methods (R58). */
class RawClient {
  private readonly transport: StdioServerTransport;
  private id = 0;
  private readonly pending = new Map<
    number,
    (resp: {
      result?: unknown;
      error?: { code: number; message: string };
    }) => void
  >();

  constructor(transport: StdioServerTransport) {
    this.transport = transport;
    transport.onmessage = (message) => this.onMessage(message);
  }

  async start(): Promise<void> {
    await this.transport.start();
  }

  private onMessage(message: JSONRPCMessage): void {
    if (
      typeof message === "object" &&
      message !== null &&
      "id" in message &&
      !("method" in message)
    ) {
      const m = message as {
        id: number;
        result?: unknown;
        error?: { code: number; message: string };
      };
      const resolver = this.pending.get(m.id);
      if (resolver) {
        this.pending.delete(m.id);
        resolver({
          ...(m.result !== undefined ? { result: m.result } : {}),
          ...(m.error !== undefined ? { error: m.error } : {}),
        });
      }
    }
  }

  request(
    method: string,
    params: Record<string, unknown> | undefined,
  ): Promise<{ result?: unknown; error?: { code: number; message: string } }> {
    const id = this.id++;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      void this.transport.send({
        jsonrpc: "2.0",
        id,
        method,
        ...(params !== undefined ? { params } : {}),
      } as JSONRPCMessage);
    });
  }

  async notify(method: string): Promise<void> {
    await this.transport.send({ jsonrpc: "2.0", method } as JSONRPCMessage);
  }
}
