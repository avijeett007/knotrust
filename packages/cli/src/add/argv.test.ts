/**
 * `knotrust add <kind> <ref>` — argv parsing (P0-E7-T3, R121). Pure
 * `argv -> Result` unit tests, mirroring `init/argv.test.ts`/
 * `grant/argv.test.ts`'s own convention.
 */

import { describe, expect, it } from "vitest";
import { parseAddArgs } from "./argv.js";

describe("parseAddArgs — dispatch across <kind> (R121: reusable for P1's add pdp/add pack <name>)", () => {
  it("errors when <kind> is missing", () => {
    const result = parseAddArgs([]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("missing <kind>");
  });

  it("errors on an unknown <kind>, naming what IS supported today and what's P1", () => {
    const result = parseAddArgs(["pdp", "cedar"]);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('unknown kind "pdp"');
      expect(result.error).toContain("P1");
    }
  });
});

describe("parseAddArgs — `add pack <path>` (P0-E7-T3, R117)", () => {
  it("parses the bare path with all defaults", () => {
    const result = parseAddArgs(["pack", "./packs/github.yaml"]);
    expect(result).toEqual({
      ok: true,
      kind: "pack",
      args: {
        path: "./packs/github.yaml",
        yes: false,
        dryRun: false,
      },
    });
  });

  it("parses --server", () => {
    const result = parseAddArgs([
      "pack",
      "./packs/github.yaml",
      "--server",
      "github-mcp",
    ]);
    expect(result.ok).toBe(true);
    if (result.ok && result.kind === "pack") {
      expect(result.args.server).toBe("github-mcp");
    }
  });

  it("parses --yes/-y", () => {
    const yes = parseAddArgs(["pack", "p.yaml", "--yes"]);
    expect(yes.ok && yes.kind === "pack" && yes.args.yes).toBe(true);
    const y = parseAddArgs(["pack", "p.yaml", "-y"]);
    expect(y.ok && y.kind === "pack" && y.args.yes).toBe(true);
  });

  it("parses --dry-run and its --diff alias", () => {
    const dryRun = parseAddArgs(["pack", "p.yaml", "--dry-run"]);
    expect(dryRun.ok && dryRun.kind === "pack" && dryRun.args.dryRun).toBe(
      true,
    );
    const diff = parseAddArgs(["pack", "p.yaml", "--diff"]);
    expect(diff.ok && diff.kind === "pack" && diff.args.dryRun).toBe(true);
  });

  it("combines every flag together", () => {
    const result = parseAddArgs([
      "pack",
      "p.yaml",
      "--server",
      "github-mcp",
      "--yes",
      "--dry-run",
    ]);
    expect(result).toEqual({
      ok: true,
      kind: "pack",
      args: {
        path: "p.yaml",
        server: "github-mcp",
        yes: true,
        dryRun: true,
      },
    });
  });

  it("errors when <path> is missing", () => {
    const result = parseAddArgs(["pack"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("missing <path>");
  });

  it("errors when --server has no value", () => {
    const result = parseAddArgs(["pack", "p.yaml", "--server"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("--server requires a value");
  });

  it("errors on an unknown flag", () => {
    const result = parseAddArgs(["pack", "p.yaml", "--bogus"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain('unknown flag "--bogus"');
  });

  it("errors when a second positional is given (accepts exactly one <path>)", () => {
    const result = parseAddArgs(["pack", "p.yaml", "q.yaml"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("exactly one");
  });
});
