/**
 * `add pack` — pack file format + loader (P0-E7-T3, R117). Fixture packs
 * live in temp dirs created per-test — never a real file on disk outside the
 * test's own throwaway directory.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadPackFile, PackError, PackNotFoundError } from "./pack-schema.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), "knotrust-pack-schema-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function writePack(fileName: string, contents: string): string {
  const filePath = path.join(dir, fileName);
  writeFileSync(filePath, contents, "utf8");
  return filePath;
}

describe("loadPackFile — valid packs (R117)", () => {
  it("loads a well-formed YAML pack", async () => {
    const filePath = writePack(
      "github.yaml",
      [
        "name: github-basics",
        "version: 1",
        'description: "Conservative tiers for common github tools"',
        "server: github-mcp",
        "tools:",
        "  github.delete_repo:",
        "    tier: critical",
        "  github.create_issue:",
        "    tier: sensitive",
      ].join("\n"),
    );

    const pack = await loadPackFile(filePath);
    expect(pack.name).toBe("github-basics");
    expect(pack.version).toBe(1);
    expect(pack.server).toBe("github-mcp");
    expect(pack.tools["github.delete_repo"]).toEqual({ tier: "critical" });
    expect(pack.tools["github.create_issue"]).toEqual({ tier: "sensitive" });
  });

  it("loads a well-formed JSON pack (c12 supports both, mirroring knotrust.config.*)", async () => {
    const filePath = writePack(
      "stripe.json",
      JSON.stringify({
        name: "stripe-basics",
        version: "1.0.0",
        tools: {
          "stripe.create_refund": { tier: "sensitive" },
        },
      }),
    );

    const pack = await loadPackFile(filePath);
    expect(pack.name).toBe("stripe-basics");
    expect(pack.version).toBe("1.0.0");
    expect(pack.server).toBeUndefined();
  });

  it("accepts an explicit mapping on a tool entry (without explicit allow/deny)", async () => {
    const filePath = writePack(
      "mapped.yaml",
      [
        "name: mapped-pack",
        "version: 1",
        "tools:",
        "  stripe.create_refund:",
        "    tier: sensitive",
        "    mapping:",
        "      resourceType: charge",
        "      resourceId: arguments.charge_id",
      ].join("\n"),
    );

    const pack = await loadPackFile(filePath);
    expect(pack.tools["stripe.create_refund"]).toEqual({
      tier: "sensitive",
      mapping: { resourceType: "charge", resourceId: "arguments.charge_id" },
    });
  });

  it("a pack with no server field parses fine (server becomes optional at apply time)", async () => {
    const filePath = writePack(
      "no-server.yaml",
      ["name: no-server-pack", "version: 1", "tools: {}"].join("\n"),
    );
    const pack = await loadPackFile(filePath);
    expect(pack.server).toBeUndefined();
    expect(pack.tools).toEqual({});
  });
});

describe("loadPackFile — invalid packs (R117)", () => {
  it("rejects a missing file with PackNotFoundError, naming the exact path", async () => {
    const missing = path.join(dir, "does-not-exist.yaml");
    await expect(loadPackFile(missing)).rejects.toThrow(PackNotFoundError);
    await expect(loadPackFile(missing)).rejects.toThrow(missing);
  });

  it("rejects a bad tier value with PackError naming the offending key path", async () => {
    const filePath = writePack(
      "bad-tier.yaml",
      [
        "name: bad-pack",
        "version: 1",
        "tools:",
        "  github.delete_repo:",
        "    tier: catastrophic",
      ].join("\n"),
    );
    await expect(loadPackFile(filePath)).rejects.toThrow(PackError);
    try {
      await loadPackFile(filePath);
      throw new Error("expected loadPackFile to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(PackError);
      const packError = error as PackError;
      expect(packError.filePath).toBe(filePath);
      expect(
        packError.issues.some(
          (i) => i.path === "tools.github.delete_repo.tier",
        ),
      ).toBe(true);
    }
  });

  it("rejects an unrecognized top-level key (strict schema, no silent typo-acceptance)", async () => {
    const filePath = writePack(
      "typo.yaml",
      [
        "name: typo-pack",
        "version: 1",
        "toolz:",
        "  github.delete_repo:",
        "    tier: critical",
      ].join("\n"),
    );
    await expect(loadPackFile(filePath)).rejects.toThrow(PackError);
  });

  it("rejects a tool entry carrying a `source` (packs never self-declare provenance — add pack stamps it)", async () => {
    const filePath = writePack(
      "self-sourced.yaml",
      [
        "name: self-sourced-pack",
        "version: 1",
        "tools:",
        "  github.delete_repo:",
        "    tier: critical",
        "    source: pack",
      ].join("\n"),
    );
    await expect(loadPackFile(filePath)).rejects.toThrow(PackError);
  });

  it("rejects a missing tools field", async () => {
    const filePath = writePack(
      "no-tools.yaml",
      ["name: no-tools-pack", "version: 1"].join("\n"),
    );
    await expect(loadPackFile(filePath)).rejects.toThrow(PackError);
  });
});

describe("loadPackFile — rejects explicit allow/deny bypass (fix round 1, P0-E7-T3 review, FIX 1)", () => {
  it("rejects a tool entry carrying explicitAllow, naming the field and exit-worthy `invalid pack` shape", async () => {
    const filePath = writePack(
      "explicit-allow.yaml",
      [
        "name: bypass-pack",
        "version: 1",
        "tools:",
        "  stripe.create_refund:",
        "    tier: sensitive",
        "    explicitAllow: true",
      ].join("\n"),
    );
    await expect(loadPackFile(filePath)).rejects.toThrow(PackError);
    try {
      await loadPackFile(filePath);
      throw new Error("expected loadPackFile to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(PackError);
      const packError = error as PackError;
      expect(packError.message).toMatch(/^invalid pack/);
      expect(packError.message).toContain(
        "tools.stripe.create_refund.explicitAllow",
      );
      expect(packError.message).toContain("packs cannot set");
      expect(
        packError.issues.some(
          (i) =>
            i.path === "tools.stripe.create_refund.explicitAllow" &&
            /USER-only/.test(i.message),
        ),
      ).toBe(true);
    }
  });

  it("rejects a tool entry carrying explicitDeny, naming the field", async () => {
    const filePath = writePack(
      "explicit-deny.yaml",
      [
        "name: bypass-pack-2",
        "version: 1",
        "tools:",
        "  github.delete_repo:",
        "    tier: critical",
        "    explicitDeny: true",
      ].join("\n"),
    );
    try {
      await loadPackFile(filePath);
      throw new Error("expected loadPackFile to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(PackError);
      const packError = error as PackError;
      expect(
        packError.issues.some(
          (i) => i.path === "tools.github.delete_repo.explicitDeny",
        ),
      ).toBe(true);
    }
  });

  it("a valid tier(+mapping)-only pack still applies (no explicit flags at all)", async () => {
    const filePath = writePack(
      "tier-only.yaml",
      [
        "name: tier-only-pack",
        "version: 1",
        "tools:",
        "  github.delete_repo:",
        "    tier: critical",
      ].join("\n"),
    );
    const pack = await loadPackFile(filePath);
    expect(pack.tools["github.delete_repo"]).toEqual({ tier: "critical" });
  });
});
