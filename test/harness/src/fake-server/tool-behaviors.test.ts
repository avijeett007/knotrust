import { describe, expect, it } from "vitest";
import { FakeClient } from "../fake-client/client.js";
import { startFakeServer } from "./start.js";
import type { FakeServerConfig, FakeToolDef } from "./types.js";
import { isChildProcessCompatible } from "./types.js";

function tool(name: string, overrides: Partial<FakeToolDef> = {}): FakeToolDef {
  return {
    name,
    inputSchema: { type: "object", properties: {} },
    ...overrides,
  };
}

describe("startFakeServer — toolBehaviors (R54)", () => {
  it("defaults to echoing arguments when a tool has no configured behavior", async () => {
    const config: FakeServerConfig = { tools: [tool("echo-me")] };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const result = await client.callTool("echo-me", { hello: "world" });
    expect(result.content).toEqual([
      { type: "text", text: JSON.stringify({ hello: "world" }) },
    ]);

    await client.close();
    await started.close();
  });

  it("serves a fixed result", async () => {
    const config: FakeServerConfig = {
      tools: [tool("fixed-tool")],
      toolBehaviors: {
        "fixed-tool": {
          respond: {
            type: "fixed",
            content: [{ type: "text", text: "canned" }],
          },
        },
      },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const result = await client.callTool("fixed-tool", {});
    expect(result.content).toEqual([{ type: "text", text: "canned" }]);
    expect(result.isError).toBeFalsy();

    await client.close();
    await started.close();
  });

  it("serves an isError result", async () => {
    const config: FakeServerConfig = {
      tools: [tool("failing-tool")],
      toolBehaviors: {
        "failing-tool": { respond: { type: "error", message: "boom" } },
      },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const result = await client.callTool("failing-tool", {});
    expect(result.isError).toBe(true);
    expect(result.content).toEqual([{ type: "text", text: "boom" }]);

    await client.close();
    await started.close();
  });

  it("serves an oversized payload of the configured byte size", async () => {
    const config: FakeServerConfig = {
      tools: [tool("big-tool")],
      toolBehaviors: {
        "big-tool": { respond: { type: "oversized", bytes: 10_000 } },
      },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const result = await client.callTool("big-tool", {});
    const block = result.content[0];
    expect(block?.type).toBe("text");
    expect(block && "text" in block ? block.text.length : -1).toBe(10_000);

    await client.close();
    await started.close();
  });

  it("honors a fixed delay before responding", async () => {
    const config: FakeServerConfig = {
      tools: [tool("slow-tool")],
      toolBehaviors: {
        "slow-tool": { delayMs: 40, respond: { type: "echo" } },
      },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const before = performance.now();
    await client.callTool("slow-tool", {});
    expect(performance.now() - before).toBeGreaterThanOrEqual(35);

    await client.close();
    await started.close();
  });

  it("records every tools/call received in the live callLog (R54 — the E5-T3 'denied call never reaches the server' hook)", async () => {
    const config: FakeServerConfig = { tools: [tool("logged")] };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    await client.callTool("logged", { a: 1 });
    await client.callTool("logged", { a: 2 });

    expect(started.inProcess.callLog).toHaveLength(2);
    expect(started.inProcess.callLog.map((e) => e.arguments)).toEqual([
      { a: 1 },
      { a: 2 },
    ]);

    await client.close();
    await started.close();
  });

  it("throws a JSON-RPC protocol error for a configured crash (throw), distinct from a tool-level isError result", async () => {
    const config: FakeServerConfig = {
      tools: [tool("throws")],
      toolBehaviors: { throws: { respond: { type: "crash", via: "throw" } } },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    await expect(client.callTool("throws", {})).rejects.toThrow();

    await client.close();
    await started.close();
  });

  it("a configured crash (exit) in in-process mode closes the connection instead of exiting the test process", async () => {
    const config: FakeServerConfig = {
      tools: [tool("crashes")],
      toolBehaviors: { crashes: { respond: { type: "crash", via: "exit" } } },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const outcome = await client.callToolWithTimeout(
      "crashes",
      {},
      { deadlineMs: 200 },
    );
    expect(outcome.status).toBe("timedOut");

    await started.close();
  });

  it("runs a custom in-process handler", async () => {
    const config: FakeServerConfig = {
      tools: [tool("custom-tool")],
      toolBehaviors: {
        "custom-tool": {
          respond: {
            type: "custom",
            handler: (args) => ({
              content: [
                { type: "text", text: `custom:${JSON.stringify(args)}` },
              ],
            }),
          },
        },
      },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const result = await client.callTool("custom-tool", { n: 1 });
    expect(result.content).toEqual([{ type: "text", text: 'custom:{"n":1}' }]);

    await client.close();
    await started.close();
  });

  it("annotation lies (R54): the harness serves whatever annotations are configured, even when they contradict the tool's actual behavior — data only, never enforced", async () => {
    const config: FakeServerConfig = {
      tools: [
        tool("innocent-looking-deploy", {
          // The lie: this tool is declared read-only/idempotent...
          annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
          },
        }),
      ],
      toolBehaviors: {
        // ...but its actual configured behavior is a hard process crash —
        // about as "destructive" as a fake tool can get. The harness does
        // not compare these two things; it just serves both, faithfully,
        // for whatever's downstream (the proxy's annotation-trust boundary)
        // to not trust.
        "innocent-looking-deploy": { respond: { type: "crash", via: "throw" } },
      },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const listed = await client.listToolsPage();
    expect(listed.tools[0]?.annotations).toEqual({
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    });
    await expect(
      client.callTool("innocent-looking-deploy", {}),
    ).rejects.toThrow();

    await client.close();
    await started.close();
  });

  it("isChildProcessCompatible is false for a config with a custom handler, and startFakeServer refuses to prepare a child command for it", async () => {
    const config: FakeServerConfig = {
      tools: [tool("custom-tool")],
      toolBehaviors: {
        "custom-tool": {
          respond: { type: "custom", handler: () => ({ content: [] }) },
        },
      },
    };
    expect(isChildProcessCompatible(config)).toBe(false);
    await expect(
      startFakeServer(config, { prepareChildCommand: true }),
    ).rejects.toThrow(/custom/);
  });
});
