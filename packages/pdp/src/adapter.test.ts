import type { PdpAdapter } from "@knotrust/core";
import { beforeEach, describe, expect, it } from "vitest";
import { getAdapter, listAdapters, registerAdapter } from "./adapter.js";

function makeStubAdapter(name: string): PdpAdapter {
  return {
    capabilities: { name, latencyClass: "remote" },
    async decide() {
      return {
        outcome: "allow",
        tier: "routine",
        reasonCode: "stub",
        evaluatedBy: "opa",
      };
    },
  };
}

describe("PdpAdapter registry", () => {
  it("pre-registers the built-in 'l0' adapter by default", () => {
    const l0 = getAdapter("l0");

    expect(l0).toBeDefined();
    expect(l0?.capabilities.name).toBe("l0");
    expect(l0?.capabilities.latencyClass).toBe("in_process");
  });

  it("getAdapter returns undefined for an unregistered name", () => {
    expect(getAdapter("does-not-exist")).toBeUndefined();
  });

  it("registerAdapter makes a new adapter retrievable by its capabilities.name", () => {
    const stub = makeStubAdapter("test-stub-register");
    registerAdapter(stub);

    expect(getAdapter("test-stub-register")).toBe(stub);
  });

  it("registerAdapter overwrites a prior registration under the same name", () => {
    const first = makeStubAdapter("test-stub-overwrite");
    const second = makeStubAdapter("test-stub-overwrite");
    registerAdapter(first);
    registerAdapter(second);

    expect(getAdapter("test-stub-overwrite")).toBe(second);
    expect(getAdapter("test-stub-overwrite")).not.toBe(first);
  });

  it("listAdapters includes every registered adapter, including the pre-registered l0", () => {
    const stub = makeStubAdapter("test-stub-list");
    registerAdapter(stub);

    const names = listAdapters().map((a) => a.capabilities.name);
    expect(names).toContain("l0");
    expect(names).toContain("test-stub-list");
  });

  describe("no-core-changes conformance (this task's acceptance test)", () => {
    // Registers a stub adapter that is NOT the built-in L0 implementation
    // and proves the registry (and, by construction, `@knotrust/core`'s
    // `pipeline.ts`, exercised in packages/core/src/pipeline.test.ts) treats
    // it identically to L0 — no core changes are needed to add a new
    // adapter, only a `registerAdapter` call here in `@knotrust/pdp`.
    let stub: PdpAdapter;

    beforeEach(() => {
      stub = makeStubAdapter("test-external-pdp");
      registerAdapter(stub);
    });

    it("an externally-registered adapter is retrievable and satisfies the exact same PdpAdapter port L0 does", async () => {
      const retrieved = getAdapter("test-external-pdp");
      expect(retrieved).toBe(stub);

      const decision = await retrieved?.decide(
        {
          contractVersion: "1.0",
          requestId: "01TEST00000000000000000000",
          timestamp: "2026-07-03T00:00:00.000Z",
          subject: { type: "user", id: "test@example.com" },
          action: { name: "test.action" },
          resource: { type: "test", id: "1" },
          context: {
            agent: { id: "test-agent", type: "ai_agent" },
            env: { time: "2026-07-03T00:00:00Z", surfaceLocal: true },
          },
          surface: { kind: "sdk", instanceId: "sdk_test" },
        },
        {
          tierPolicy: { tools: {}, unknownToolTier: "sensitive" },
          coveringGrants: [],
          nowEpochSeconds: 1_800_000_000,
        },
      );

      expect(decision?.outcome).toBe("allow");
      expect(decision?.evaluatedBy).toBe("opa");
    });
  });
});
