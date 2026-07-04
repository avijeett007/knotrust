/**
 * Suggested-tier `knotrust.config.*` generation + serialization tests
 * (P0-E7-T1, R109).
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ToolInventory } from "@knotrust/proxy-stdio";
import type { KnotrustConfig } from "@knotrust/store";
import { loadKnotrustConfig } from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildGeneratedConfig,
  configFileName,
  serializeConfigJson,
  serializeConfigTs,
  serializeConfigYaml,
  serializeGeneratedConfig,
  toConfigToolEntries,
} from "./config-generate.js";

describe("toConfigToolEntries (the E5-T2 pin adapter)", () => {
  it("adapts tier/source, carries explicitAllow/explicitDeny when present, never adds mapping", () => {
    const result = toConfigToolEntries({
      "github.create_issue": { tier: "sensitive", source: "annotation" },
      "fs.delete": {
        tier: "critical",
        source: "annotation",
        explicitDeny: true,
      },
    });
    expect(result).toEqual({
      "github.create_issue": { tier: "sensitive", source: "annotation" },
      "fs.delete": {
        tier: "critical",
        source: "annotation",
        explicitDeny: true,
      },
    });
    expect(Object.hasOwn(result["fs.delete"] ?? {}, "mapping")).toBe(false);
  });
});

function inventoryOf(
  tools: Record<string, { readOnlyHint?: boolean; destructiveHint?: boolean }>,
): ToolInventory {
  const inventory: ToolInventory = {};
  for (const [name, hints] of Object.entries(tools)) {
    inventory[name] = {
      annotations: {
        trusted: false,
        source: "server_advertised",
        ...hints,
        capturedAt: "2026-01-01T00:00:00.000Z",
      },
      inputSchemaHash: "sha256:deadbeef",
    };
  }
  return inventory;
}

describe("buildGeneratedConfig (R109)", () => {
  it("builds a fresh all-defaults config with seeded tiers when nothing existed before", () => {
    const result = buildGeneratedConfig(undefined, [
      {
        serverName: "github",
        inventory: inventoryOf({
          list_issues: { readOnlyHint: true },
          delete_repo: { destructiveHint: true },
        }),
      },
    ]);
    expect(result.skeletonServers).toEqual([]);
    expect(result.config.version).toBe(1);
    expect(result.config.scope).toBe("personal");
    expect(result.config.unknownToolTier).toBe("sensitive");
    expect(result.config.servers?.github?.tools).toEqual({
      list_issues: { tier: "routine", source: "annotation" },
      delete_repo: { tier: "sensitive", source: "annotation" },
    });
  });

  it("never lets an annotation seed override an existing user/pack entry for the same tool", () => {
    const existing: KnotrustConfig = {
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
      servers: {
        github: {
          tools: {
            delete_repo: {
              tier: "critical",
              source: "user",
              explicitDeny: true,
            },
          },
        },
      },
    };
    const result = buildGeneratedConfig(existing, [
      {
        serverName: "github",
        inventory: inventoryOf({ delete_repo: { readOnlyHint: true } }),
      },
    ]);
    // Annotation lies "readOnlyHint: true" for delete_repo — but a user-sourced
    // `critical` entry for the SAME tool must survive completely untouched.
    expect(result.config.servers?.github?.tools?.delete_repo).toEqual({
      tier: "critical",
      source: "user",
      explicitDeny: true,
    });
  });

  it("refreshes a stale annotation-sourced suggestion on re-run", () => {
    const existing: KnotrustConfig = {
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
      servers: {
        github: {
          tools: { list_issues: { tier: "sensitive", source: "annotation" } },
        },
      },
    };
    const result = buildGeneratedConfig(existing, [
      {
        serverName: "github",
        inventory: inventoryOf({ list_issues: { readOnlyHint: true } }),
      },
    ]);
    expect(result.config.servers?.github?.tools?.list_issues).toEqual({
      tier: "routine",
      source: "annotation",
    });
  });

  it("records skeletonServers and preserves an existing entry untouched when capture failed", () => {
    const existing: KnotrustConfig = {
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
      servers: {
        slack: { tools: { post: { tier: "sensitive", source: "pack" } } },
      },
    };
    const result = buildGeneratedConfig(existing, [
      { serverName: "slack", inventory: undefined },
    ]);
    expect(result.skeletonServers).toEqual(["slack"]);
    expect(result.config.servers?.slack).toEqual(existing.servers?.slack);
  });

  it("gives a brand-new server an empty tools skeleton when capture failed and nothing existed", () => {
    const result = buildGeneratedConfig(undefined, [
      { serverName: "brandnew", inventory: undefined },
    ]);
    expect(result.skeletonServers).toEqual(["brandnew"]);
    expect(result.config.servers?.brandnew).toEqual({});
  });

  it("preserves every other top-level field and every other server untouched", () => {
    const existing: KnotrustConfig = {
      version: 1,
      scope: "org",
      unknownToolTier: "critical",
      approvalTimeoutSeconds: 120,
      envelope: { denyTools: ["dangerous.tool"] },
      servers: {
        other: { tools: { x: { tier: "routine", source: "pack" } } },
      },
    };
    const result = buildGeneratedConfig(existing, [
      {
        serverName: "github",
        inventory: inventoryOf({ read: { readOnlyHint: true } }),
      },
    ]);
    expect(result.config.scope).toBe("org");
    expect(result.config.unknownToolTier).toBe("critical");
    expect(result.config.approvalTimeoutSeconds).toBe(120);
    expect(result.config.envelope).toEqual({ denyTools: ["dangerous.tool"] });
    expect(result.config.servers?.other).toEqual(existing.servers?.other);
    expect(result.config.servers?.github?.tools?.read).toEqual({
      tier: "routine",
      source: "annotation",
    });
  });
});

describe("configFileName", () => {
  it("names the file per format", () => {
    expect(configFileName("yaml")).toBe("knotrust.config.yaml");
    expect(configFileName("json")).toBe("knotrust.config.json");
    expect(configFileName("ts")).toBe("knotrust.config.ts");
  });
});

const sampleConfig: KnotrustConfig = {
  version: 1,
  scope: "personal",
  unknownToolTier: "sensitive",
  approvalTimeoutSeconds: 300,
  servers: {
    github: {
      tools: {
        "github.create_issue": { tier: "sensitive", source: "annotation" },
      },
    },
  },
  envelope: { denyTools: ["dangerous.tool"], forceApprovalTiers: ["critical"] },
};

describe("serializeConfigJson", () => {
  it("serializes with 2-space indent and a trailing newline, no comment support", () => {
    const out = serializeConfigJson(sampleConfig, { skeletonNote: "ignored" });
    expect(out.endsWith("\n")).toBe(true);
    expect(out).not.toContain("ignored");
    expect(JSON.parse(out)).toEqual(sampleConfig);
  });
});

describe("serializeConfigTs", () => {
  it("emits a plain `export default` object literal with no @knotrust/store import", () => {
    const out = serializeConfigTs(sampleConfig);
    expect(out).toContain("export default {");
    // No actual `import` statement — the generated file must never try to
    // resolve a package (like `@knotrust/store`) a real user won't have
    // installed (see this module's header). The doc-comment is allowed to
    // MENTION the package name; it must never appear after a real `import`.
    expect(out).not.toMatch(/^import /m);
    expect(out).toMatch(/^\/\/ Generated by `knotrust init`/);
  });

  it("embeds a skeleton note as leading comments", () => {
    const out = serializeConfigTs(sampleConfig, {
      skeletonNote: 'capture failed for server "slack"',
    });
    expect(out).toContain('// capture failed for server "slack"');
  });
});

describe("serializeConfigYaml", () => {
  it("produces a deterministic, human-readable YAML document", () => {
    const out = serializeConfigYaml(sampleConfig);
    expect(out).toMatch(/^# Generated by `knotrust init`/);
    expect(out).toContain('"version": 1');
    expect(out).toContain('"scope": "personal"');
    expect(out).toContain('"github":');
    expect(out).toContain('"github.create_issue":');
    expect(out).toContain('- "dangerous.tool"');
  });

  it("embeds a skeleton note as leading `#` comments", () => {
    const out = serializeConfigYaml(sampleConfig, {
      skeletonNote: "line one\nline two",
    });
    expect(out).toContain("# line one");
    expect(out).toContain("# line two");
  });
});

describe("serializeGeneratedConfig dispatch", () => {
  it("routes to the right serializer per format, defaulting shape checks", () => {
    expect(serializeGeneratedConfig(sampleConfig, "json")).toContain(
      '"version": 1',
    );
    expect(serializeGeneratedConfig(sampleConfig, "ts")).toContain(
      "export default",
    );
    expect(serializeGeneratedConfig(sampleConfig, "yaml")).toContain(
      "# Generated",
    );
  });
});

describe("serializeConfigYaml round-trips through the REAL loader (c12 + zod)", () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(path.join(tmpdir(), "knotrust-init-yaml-roundtrip-"));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("a generated YAML file loads back to the exact same KnotrustConfig via loadKnotrustConfig", async () => {
    const yaml = serializeConfigYaml(sampleConfig);
    writeFileSync(path.join(tmp, "knotrust.config.yaml"), yaml, "utf8");
    const loaded = await loadKnotrustConfig({ cwd: tmp });
    expect(loaded.config).toEqual(sampleConfig);
  });

  it("round-trips a config with multiple servers, tiers, and explicit flags", async () => {
    const rich: KnotrustConfig = {
      version: 1,
      scope: "org",
      unknownToolTier: "critical",
      approvalTimeoutSeconds: 45,
      servers: {
        github: {
          tools: {
            "issues.create": { tier: "sensitive", source: "annotation" },
            "repo.delete": {
              tier: "critical",
              source: "user",
              explicitDeny: true,
            },
          },
        },
        filesystem: {
          tools: {
            read: { tier: "routine", source: "pack", explicitAllow: true },
          },
        },
      },
      envelope: {
        denyTools: ["fs.rm_rf"],
        forceApprovalTiers: ["critical", "sensitive"],
        tierFloors: { "fs.write": "sensitive" },
        grantCeiling: "sensitive",
      },
      failOpen: { routine: true },
      cacheTtlOverrides: { routine: 30, sensitive: 5 },
    };
    const yaml = serializeConfigYaml(rich);
    writeFileSync(path.join(tmp, "knotrust.config.yaml"), yaml, "utf8");
    const loaded = await loadKnotrustConfig({ cwd: tmp });
    expect(loaded.config).toEqual(rich);
  });
});
