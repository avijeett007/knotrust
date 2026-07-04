import { describe, expect, it } from "vitest";
import { PKG } from "./index.js";

describe("@knotrust/core", () => {
  it("exports the package placeholder", () => {
    expect(PKG).toBe("@knotrust/core");
  });
});
