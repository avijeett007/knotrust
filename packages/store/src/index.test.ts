import { describe, expect, it } from "vitest";
import { PKG } from "./index.js";

describe("@knotrust/store", () => {
  it("exports the package placeholder", () => {
    expect(PKG).toBe("@knotrust/store");
  });
});
