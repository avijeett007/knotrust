/**
 * @knotrust/proxy-stdio — `notifications/cancelled` → pending-approval
 * cancellation bridge acceptance (P0-E6-T4, R105).
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import {
  createCancellationClassifier,
  parseCancelledNotification,
} from "./cancellation.js";

function cancelledNotification(
  requestId: unknown,
  reason?: string,
): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    method: "notifications/cancelled",
    params: {
      requestId,
      ...(reason !== undefined ? { reason } : {}),
    },
  } as unknown as JSONRPCMessage;
}

describe("parseCancelledNotification", () => {
  it("parses requestId (number) and reason", () => {
    expect(
      parseCancelledNotification(cancelledNotification(7, "timeout")),
    ).toEqual({ requestId: 7, reason: "timeout" });
  });

  it("parses a STRING requestId as-is (never coerced)", () => {
    expect(parseCancelledNotification(cancelledNotification("req-1"))).toEqual({
      requestId: "req-1",
    });
  });

  it("reason is optional — absent when the notification carries none", () => {
    const parsed = parseCancelledNotification(cancelledNotification(1));
    expect(parsed).toEqual({ requestId: 1 });
    expect(parsed?.reason).toBeUndefined();
  });

  it("returns null for a non-'notifications/cancelled' message", () => {
    expect(
      parseCancelledNotification({
        jsonrpc: "2.0",
        method: "notifications/progress",
        params: { requestId: 1 },
      } as unknown as JSONRPCMessage),
    ).toBeNull();
  });

  it("returns null for a non-object message", () => {
    expect(
      parseCancelledNotification(null as unknown as JSONRPCMessage),
    ).toBeNull();
    expect(
      parseCancelledNotification(undefined as unknown as JSONRPCMessage),
    ).toBeNull();
  });

  it("returns null when params is missing or not an object", () => {
    expect(
      parseCancelledNotification({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
      } as unknown as JSONRPCMessage),
    ).toBeNull();
  });

  it("returns null when requestId is absent or of the wrong type", () => {
    expect(
      parseCancelledNotification({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: {},
      } as unknown as JSONRPCMessage),
    ).toBeNull();
    expect(
      parseCancelledNotification({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: { requestId: { nested: true } },
      } as unknown as JSONRPCMessage),
    ).toBeNull();
  });

  it("a non-string reason is dropped rather than coerced", () => {
    expect(
      parseCancelledNotification({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: { requestId: 1, reason: 12345 },
      } as unknown as JSONRPCMessage),
    ).toEqual({ requestId: 1 });
  });
});

describe("createCancellationClassifier (R105)", () => {
  it("client_to_server notifications/cancelled -> passthrough (byte/shape-faithful, R59/R63 unchanged) + fires onCancelled via the observe side effect", () => {
    const seen: Array<{ requestId: string | number; reason?: string }> = [];
    const classifier = createCancellationClassifier((requestId, reason) => {
      seen.push({ requestId, ...(reason !== undefined ? { reason } : {}) });
    });
    const message = cancelledNotification(9, "client_timeout");

    const result = classifier(message, "client_to_server");
    expect(result.action).toBe("passthrough");
    expect(seen).toEqual([]); // observe not yet invoked — that's the relay's job (R63)

    result.observe?.(message);
    expect(seen).toEqual([{ requestId: 9, reason: "client_timeout" }]);
  });

  it("server_to_client direction never fires onCancelled — cancellation only ever flows client -> proxy", () => {
    const seen: unknown[] = [];
    const classifier = createCancellationClassifier((requestId) => {
      seen.push(requestId);
    });
    const message = cancelledNotification(9);
    const result = classifier(message, "server_to_client");
    expect(result.action).toBe("passthrough");
    expect(result.observe).toBeUndefined();
  });

  it("every other message (tools/call, notifications/progress, responses) passes through untouched, with no observe callback", () => {
    const classifier = createCancellationClassifier(() => {
      throw new Error("must never be called for a non-cancelled message");
    });
    const messages: JSONRPCMessage[] = [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "x", arguments: {} },
      } as unknown as JSONRPCMessage,
      {
        jsonrpc: "2.0",
        method: "notifications/progress",
        params: {},
      } as unknown as JSONRPCMessage,
      { jsonrpc: "2.0", id: 1, result: {} } as unknown as JSONRPCMessage,
    ];
    for (const message of messages) {
      const result = classifier(message, "client_to_server");
      expect(result).toEqual({ action: "passthrough" });
    }
  });

  it("a malformed notifications/cancelled (bad requestId) still passes through, with no observe callback (never crashes the relay)", () => {
    const classifier = createCancellationClassifier(() => {
      throw new Error("must never be called for a malformed notification");
    });
    const result = classifier(
      {
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: {},
      } as unknown as JSONRPCMessage,
      "client_to_server",
    );
    expect(result).toEqual({ action: "passthrough" });
  });
});
