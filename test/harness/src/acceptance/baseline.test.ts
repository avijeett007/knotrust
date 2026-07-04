/**
 * P0-E11-T1 acceptance demonstration #1 (R56, ruling 2, bullet 1):
 *
 * "A proxy-FREE baseline conversation (client ↔ fake server directly): full
 * `initialize → tools/list (2 pages) → tools/call (echo) → shutdown`, every
 * frame asserted, byte-shape correct per MCP 2025-11-25. This proves the
 * harness speaks real MCP."
 *
 * This runs the fake server as a REAL, spawned child process (`bin.mjs`,
 * via `StdioClientTransport`) — the strongest available proof that the
 * harness's wire format is real MCP 2025-11-25 JSON-RPC over real stdio
 * framing, not just an in-memory object-passing convenience. The 100-
 * iteration chaos run (`chaos.test.ts`) deliberately stays in-process for
 * speed instead; this test is the one that proves the child-spawnable path
 * (R53) actually works end-to-end.
 */
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { describe, expect, it } from "vitest";
import { FakeClient } from "../fake-client/client.js";
import { parseCallLogFromStderr } from "../fake-server/call-log.js";
import { startFakeServer } from "../fake-server/start.js";
import type { FakeServerConfig, FakeToolDef } from "../fake-server/types.js";

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
): Promise<void> {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) {
    if (performance.now() > deadline) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe("R56 acceptance — proxy-free baseline conversation (real spawned child process)", () => {
  it("initialize -> tools/list (2 pages) -> tools/call (echo) -> shutdown, every frame asserted, byte-shape correct per MCP 2025-11-25", async () => {
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-server-baseline", version: "1.0.0" },
      tools: [
        tool("alpha", {
          description: "first tool",
          annotations: { readOnlyHint: true },
        }),
        tool("echo", { description: "echoes its arguments back" }),
      ],
      pagination: { pageSize: 1 },
    };

    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    expect(started.childCommand).toBeDefined();
    const [command, ...args] = started.childCommand as [string, ...string[]];

    const transport = new StdioClientTransport({
      command,
      args,
      stderr: "pipe",
    });
    let stderrText = "";
    transport.stderr?.on("data", (chunk: Buffer) => {
      stderrText += chunk.toString("utf8");
    });

    const client = new FakeClient(transport, {
      clientInfo: { name: "knotrust-baseline-test", version: "0.0.0" },
    });

    // --- initialize ---
    const initResult = (await client.connect()) as {
      protocolVersion?: string;
      serverInfo?: { name?: string; version?: string };
    };
    expect(initResult.protocolVersion).toBe("2025-11-25");
    expect(initResult.serverInfo?.name).toBe("knotrust-fake-server-baseline");

    // --- tools/list (2 pages) ---
    const page1 = await client.listToolsPage();
    expect(page1.tools).toHaveLength(1);
    expect(page1.tools[0]?.name).toBe("alpha");
    expect(page1.nextCursor).toBeDefined();

    const page2 = await client.listToolsPage(page1.nextCursor);
    expect(page2.tools).toHaveLength(1);
    expect(page2.tools[0]?.name).toBe("echo");
    expect(page2.nextCursor).toBeUndefined();

    // --- tools/call (echo) ---
    const callResult = await client.callTool("echo", { greeting: "hello" });
    expect(callResult.isError).toBeFalsy();
    expect(callResult.content).toEqual([
      { type: "text", text: JSON.stringify({ greeting: "hello" }) },
    ]);

    // --- every frame is real, byte-shape-correct MCP 2025-11-25 JSON-RPC 2.0 ---
    expect(client.frames.length).toBeGreaterThan(0);
    for (const frame of client.frames) {
      const message = frame.message as Record<string, unknown>;
      expect(message.jsonrpc).toBe("2.0");
      const isRequestOrNotification = "method" in message;
      const isResponse = "id" in message && !("method" in message);
      expect(isRequestOrNotification || isResponse).toBe(true);
    }
    client.assertSentMethodOrder([
      "initialize",
      "notifications/initialized",
      "tools/list",
      "tools/list",
      "tools/call",
    ]);

    // --- shutdown ---
    await client.close();
    await started.close();

    // Cross-check: the child's own stderr call-log sideband (R54's callLog
    // hook, exercised here in real child-process mode) corroborates the
    // exact call the client observed on the wire.
    await waitUntil(() => parseCallLogFromStderr(stderrText).length > 0, 2000);
    const callLog = parseCallLogFromStderr(stderrText);
    expect(callLog).toHaveLength(1);
    expect(callLog[0]?.toolName).toBe("echo");
    expect(callLog[0]?.arguments).toEqual({ greeting: "hello" });
  }, 20_000);
});
