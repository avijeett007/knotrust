import { describe, expect, it } from "vitest";
import { startFakeServer } from "../fake-server/start.js";
import type { FakeServerConfig, FakeToolDef } from "../fake-server/types.js";
import { FakeClient } from "./client.js";

function tool(name: string, overrides: Partial<FakeToolDef> = {}): FakeToolDef {
  return {
    name,
    inputSchema: { type: "object", properties: {} },
    ...overrides,
  };
}

describe("FakeClient — frame transcript (R55)", () => {
  it("captures every sent and received frame, in order, through a full conversation", async () => {
    const started = await startFakeServer({ tools: [tool("echo-me")] });
    const client = new FakeClient(started.inProcess.clientTransport);

    await client.connect();
    await client.listToolsPage();
    await client.callTool("echo-me", { x: 1 });
    await client.close();
    await started.close();

    expect(client.frames.length).toBeGreaterThan(0);
    // Monotonic seq, alternating-ish sent/recv but always well-formed.
    client.frames.forEach((frame, index) => {
      expect(frame.seq).toBe(index);
    });

    client.assertSentMethodOrder([
      "initialize",
      "notifications/initialized",
      "tools/list",
      "tools/call",
    ]);
  });

  it("assertNoLeakedSubstrings throws only when a RECEIVED frame contains the needle", async () => {
    const started = await startFakeServer({
      tools: [tool("secret-tool")],
      toolBehaviors: {
        "secret-tool": {
          respond: {
            type: "fixed",
            content: [{ type: "text", text: "top-secret-token" }],
          },
        },
      },
    });
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();
    await client.callTool("secret-tool", {});

    expect(() =>
      client.assertNoLeakedSubstrings(["top-secret-token"]),
    ).toThrow();
    expect(() =>
      client.assertNoLeakedSubstrings(["definitely-not-present"]),
    ).not.toThrow();

    await client.close();
    await started.close();
  });
});

describe("FakeClient — progress-token simulation (R55, the P0-E6-T2 heartbeat hook)", () => {
  it("routes notifications/progress for a call's progressToken to onProgress, interleaved during a chaos delay", async () => {
    const config: FakeServerConfig = {
      tools: [tool("slow-tool")],
      toolBehaviors: {
        "slow-tool": { delayMs: 60, respond: { type: "echo" } },
      },
      chaos: { seed: 1, interleaveNotifications: true, notificationBudget: 3 },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const progressEvents: { progress: number; total?: number }[] = [];
    await client.callTool(
      "slow-tool",
      {},
      { progressToken: "tok-1", onProgress: (p) => progressEvents.push(p) },
    );

    expect(progressEvents.length).toBeGreaterThan(0);
    expect(progressEvents.every((p) => typeof p.progress === "number")).toBe(
      true,
    );
    expect(
      client.receivedNotificationsOf("notifications/progress").length,
    ).toBe(progressEvents.length);

    await client.close();
    await started.close();
  });
});

describe("FakeClient — timeout vs. cancel (R55)", () => {
  it("callToolWithTimeout times out WITHOUT sending notifications/cancelled", async () => {
    const config: FakeServerConfig = {
      tools: [tool("slow-tool")],
      toolBehaviors: {
        "slow-tool": { delayMs: 300, respond: { type: "echo" } },
      },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const outcome = await client.callToolWithTimeout(
      "slow-tool",
      {},
      { deadlineMs: 30 },
    );
    expect(outcome.status).toBe("timedOut");
    expect(client.getSentMethods()).not.toContain("notifications/cancelled");

    await client.close();
    await started.close();
  });

  it("callToolWithCancel sends a real notifications/cancelled frame", async () => {
    const config: FakeServerConfig = {
      tools: [tool("slow-tool")],
      toolBehaviors: {
        "slow-tool": { delayMs: 300, respond: { type: "echo" } },
      },
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const outcome = await client.callToolWithCancel(
      "slow-tool",
      {},
      { cancelAfterMs: 30, reason: "test-cancel" },
    );
    expect(outcome.status).toBe("cancelled");
    expect(client.getSentMethods()).toContain("notifications/cancelled");
    const cancelFrame = client.frames.find(
      (f) =>
        f.direction === "sent" &&
        (f.message as { method?: unknown }).method ===
          "notifications/cancelled",
    );
    expect(
      (cancelFrame?.message as { params?: { reason?: string } }).params?.reason,
    ).toBe("test-cancel");

    await client.close();
    await started.close();
  });

  it("a call that completes before its deadline resolves normally (no false timeout)", async () => {
    const started = await startFakeServer({ tools: [tool("fast-tool")] });
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const outcome = await client.callToolWithTimeout(
      "fast-tool",
      { ok: true },
      { deadlineMs: 5000 },
    );
    expect(outcome.status).toBe("completed");

    await client.close();
    await started.close();
  });
});
