import { describe, expect, it } from "vitest";
import {
  createSeededPrng,
  FakeClient,
  isChildProcessCompatible,
  scanFrames,
  startFakeServer,
} from "./index.js";

describe("@knotrust/test-harness barrel", () => {
  it("re-exports the fake-server, fake-client, prng, and frame surfaces", () => {
    expect(typeof startFakeServer).toBe("function");
    expect(typeof FakeClient).toBe("function");
    expect(typeof createSeededPrng).toBe("function");
    expect(typeof scanFrames).toBe("function");
    expect(typeof isChildProcessCompatible).toBe("function");
  });
});
