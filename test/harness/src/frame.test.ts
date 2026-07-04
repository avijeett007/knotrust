import { describe, expect, it } from "vitest";
import { type Frame, isMethod, isResponseTo, scanFrames } from "./frame.js";

function frame(
  seq: number,
  direction: Frame["direction"],
  message: unknown,
): Frame {
  return { seq, direction, atMs: seq, message };
}

describe("scanFrames", () => {
  it("filters frames by an arbitrary predicate", () => {
    const frames: Frame[] = [
      frame(0, "sent", { jsonrpc: "2.0", id: 0, method: "initialize" }),
      frame(1, "recv", { jsonrpc: "2.0", id: 0, result: {} }),
      frame(2, "sent", { jsonrpc: "2.0", method: "notifications/initialized" }),
    ];
    const sent = scanFrames(frames, (f) => f.direction === "sent");
    expect(sent.map((f) => f.seq)).toEqual([0, 2]);
  });
});

describe("isMethod", () => {
  it("matches a JSON-RPC message with the given method", () => {
    expect(
      isMethod({ jsonrpc: "2.0", method: "tools/list" }, "tools/list"),
    ).toBe(true);
  });

  it("does not match a different method, or a non-object", () => {
    expect(
      isMethod({ jsonrpc: "2.0", method: "tools/call" }, "tools/list"),
    ).toBe(false);
    expect(isMethod(null, "tools/list")).toBe(false);
    expect(isMethod("tools/list", "tools/list")).toBe(false);
  });
});

describe("isResponseTo", () => {
  it("matches a JSON-RPC response with the given id", () => {
    expect(isResponseTo({ jsonrpc: "2.0", id: 3, result: {} }, 3)).toBe(true);
  });

  it("does not match a request/notification (has a method), or a different id", () => {
    expect(
      isResponseTo({ jsonrpc: "2.0", id: 3, method: "tools/call" }, 3),
    ).toBe(false);
    expect(isResponseTo({ jsonrpc: "2.0", id: 4, result: {} }, 3)).toBe(false);
    expect(isResponseTo(null, 3)).toBe(false);
  });
});
