import { describe, expect, it } from "vitest";
import {
  type ClassifierHook,
  type ClassifyDirection,
  composeClassifiers,
  defaultClassifier,
  type JsonRpcMessage,
} from "./classifier.js";

describe("@knotrust/proxy-stdio classifier seam (R59)", () => {
  const bothDirections: ClassifyDirection[] = [
    "client_to_server",
    "server_to_client",
  ];

  const sampleMessages: JsonRpcMessage[] = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "echo", arguments: {} },
    },
    { jsonrpc: "2.0", method: "notifications/progress", params: {} },
    { jsonrpc: "2.0", method: "notifications/cancelled", params: {} },
    { jsonrpc: "2.0", id: 4, method: "resources/list", params: {} },
    { jsonrpc: "2.0", id: 5, method: "prompts/get", params: {} },
    { jsonrpc: "2.0", id: 6, method: "ping" },
    { jsonrpc: "2.0", id: 7, method: "some/unknown/method", params: {} },
    { jsonrpc: "2.0", id: 1, result: {} },
    {
      jsonrpc: "2.0",
      id: 2,
      error: { code: -32601, message: "Method not found" },
    },
  ];

  it("classifies every message type in both directions as passthrough", () => {
    for (const direction of bothDirections) {
      for (const message of sampleMessages) {
        expect(defaultClassifier(message, direction)).toEqual({
          action: "passthrough",
        });
      }
    }
  });

  it("is a pure function (no mutation of the message)", () => {
    const message: JsonRpcMessage = {
      jsonrpc: "2.0",
      id: 42,
      method: "tools/call",
      params: { name: "echo", arguments: { a: 1 } },
    };
    const snapshot = JSON.parse(JSON.stringify(message));
    defaultClassifier(message, "client_to_server");
    expect(message).toEqual(snapshot);
  });

  it("conforms to the ClassifierHook type (T2/T3 hook shape)", () => {
    const hook: ClassifierHook = (_msg, _direction) => ({
      action: "passthrough",
    });
    expect(
      hook({ jsonrpc: "2.0", id: 1, method: "ping" }, "client_to_server"),
    ).toEqual({ action: "passthrough" });
  });
});

describe("ClassifyResult.observe (R63 — the P0-E5-T2 observation capability)", () => {
  it("defaultClassifier never attaches an observe callback", () => {
    const result = defaultClassifier(
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      "client_to_server",
    );
    expect(result).toEqual({ action: "passthrough" });
    expect("observe" in result).toBe(false);
  });

  it("a hook MAY return observe alongside passthrough — the type permits it without a new action variant", () => {
    const seen: JsonRpcMessage[] = [];
    const hook: ClassifierHook = (_msg) => ({
      action: "passthrough",
      observe: (observedMsg) => {
        seen.push(observedMsg);
      },
    });
    const msg: JsonRpcMessage = { jsonrpc: "2.0", id: 9, method: "tools/list" };
    const result = hook(msg, "server_to_client");
    expect(result.action).toBe("passthrough");
    result.observe?.(msg);
    expect(seen).toEqual([msg]);
  });
});

describe("composeClassifiers (R63)", () => {
  it("both hooks are consulted and their observe callbacks both fire, primary first, when both return passthrough", () => {
    const order: string[] = [];
    const primary: ClassifierHook = () => ({
      action: "passthrough",
      observe: () => {
        order.push("primary");
      },
    });
    const secondary: ClassifierHook = () => ({
      action: "passthrough",
      observe: () => {
        order.push("secondary");
      },
    });
    const composed = composeClassifiers(primary, secondary);
    const result = composed(
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      "server_to_client",
    );
    expect(result.action).toBe("passthrough");
    result.observe?.({ jsonrpc: "2.0", id: 1, result: {} });
    expect(order).toEqual(["primary", "secondary"]);
  });

  it("primary's non-passthrough decision wins — secondary is never even consulted", () => {
    let secondaryCalled = false;
    const primary: ClassifierHook = () =>
      ({ action: "deny" }) as unknown as ReturnType<ClassifierHook>;
    const secondary: ClassifierHook = () => {
      secondaryCalled = true;
      return { action: "passthrough" };
    };
    const composed = composeClassifiers(primary, secondary);
    const result = composed(
      { jsonrpc: "2.0", id: 1, method: "tools/call" },
      "client_to_server",
    );
    expect(result).toEqual({ action: "deny" });
    expect(secondaryCalled).toBe(false);
  });

  it("when only secondary supplies observe, that observe still runs", () => {
    let observed = false;
    const primary: ClassifierHook = () => ({ action: "passthrough" });
    const secondary: ClassifierHook = () => ({
      action: "passthrough",
      observe: () => {
        observed = true;
      },
    });
    const composed = composeClassifiers(primary, secondary);
    const result = composed(
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      "server_to_client",
    );
    result.observe?.({ jsonrpc: "2.0", id: 1, result: {} });
    expect(observed).toBe(true);
  });

  it("composing two default-shaped (no-observe) hooks yields a plain passthrough with no observe key", () => {
    const composed = composeClassifiers(defaultClassifier, defaultClassifier);
    const result = composed(
      { jsonrpc: "2.0", id: 1, method: "ping" },
      "client_to_server",
    );
    expect(result).toEqual({ action: "passthrough" });
    expect("observe" in result).toBe(false);
  });
});
