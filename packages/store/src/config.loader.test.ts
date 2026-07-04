/**
 * @knotrust/store — config.ts loader unit tests (P0-E4-T2; rulings
 * R44–R47). Exercises `loadKnotrustConfig` against REAL temp directories on
 * disk (c12 does real file I/O) — every test gets its own fresh
 * `mkdtempSync` dir, never a shared/ambient location.
 *
 * The trio deep-equal test loads the REAL committed `examples/` files
 * directly (copied into a fresh temp dir per format) — this is what "keeps
 * the examples honest" (R44's ruling 5): if a maintainer edits one example
 * file without updating its siblings, this test catches it.
 */

import {
  copyFileSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ConfigError,
  type KnotrustConfig,
  loadKnotrustConfig,
} from "./config.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const examplesDir = path.resolve(here, "..", "..", "..", "examples");

let tempDirs: string[] = [];

/**
 * `realpathSync` immediately after `mkdtempSync`: on macOS, `os.tmpdir()`
 * resolves under `/var/...`, a symlink to `/private/var/...` — c12/pathe
 * report the resolved (realpath'd) absolute path as `configFile`, so a test
 * that independently joins `dir` + filename to build an "expected" path
 * must use the SAME realpath'd base or every string comparison spuriously
 * fails on macOS despite both paths pointing at the identical file.
 */
function freshDir(): string {
  const dir = realpathSync(
    mkdtempSync(path.join(tmpdir(), "knotrust-config-test-")),
  );
  tempDirs.push(dir);
  return dir;
}

beforeEach(() => {
  tempDirs = [];
});

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Trio deep-equal (R44 acceptance)
// ---------------------------------------------------------------------------

describe("loadKnotrustConfig — trio deep-equal (.ts, .yaml, .json load identically)", () => {
  it("normalizes examples/knotrust.config.{ts,yaml,json} to the exact same KnotrustConfig", async () => {
    const tsDir = freshDir();
    copyFileSync(
      path.join(examplesDir, "knotrust.config.ts"),
      path.join(tsDir, "knotrust.config.ts"),
    );
    const yamlDir = freshDir();
    copyFileSync(
      path.join(examplesDir, "knotrust.config.yaml"),
      path.join(yamlDir, "knotrust.config.yaml"),
    );
    const jsonDir = freshDir();
    copyFileSync(
      path.join(examplesDir, "knotrust.config.json"),
      path.join(jsonDir, "knotrust.config.json"),
    );

    const fromTs = await loadKnotrustConfig({ cwd: tsDir });
    const fromYaml = await loadKnotrustConfig({ cwd: yamlDir });
    const fromJson = await loadKnotrustConfig({ cwd: jsonDir });

    expect(fromTs.config).toEqual(fromYaml.config);
    expect(fromYaml.config).toEqual(fromJson.config);

    // The realistic small config the ruling describes: one server, three
    // tools across the three tiers with sources, an envelope floor, a
    // sensitive TTL override.
    expect(fromJson.config).toEqual({
      version: 1,
      scope: "personal",
      identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
      servers: {
        "github-mcp": {
          tools: {
            "github.create_issue": { tier: "routine", source: "annotation" },
            "github.close_issue": {
              tier: "sensitive",
              source: "pack",
              mapping: {
                resourceType: "github_issue",
                resourceId: "arguments.issue_number",
                properties: { repo: "arguments.repo" },
              },
            },
            "github.delete_repo": {
              tier: "critical",
              source: "user",
              explicitDeny: true,
            },
          },
        },
      },
      unknownToolTier: "sensitive",
      envelope: { tierFloors: { "github.create_issue": "sensitive" } },
      approvalTimeoutSeconds: 300,
      cacheTtlOverrides: { sensitive: 30 },
    });
  });

  it("each load reports its own real absolute sourceFile", async () => {
    const jsonDir = freshDir();
    copyFileSync(
      path.join(examplesDir, "knotrust.config.json"),
      path.join(jsonDir, "knotrust.config.json"),
    );
    const { sourceFile } = await loadKnotrustConfig({ cwd: jsonDir });
    expect(sourceFile).toBe(path.join(jsonDir, "knotrust.config.json"));
  });
});

// ---------------------------------------------------------------------------
// Fail-fast with a pointer to the offending key + source file
// ---------------------------------------------------------------------------

describe("loadKnotrustConfig — invalid config fails fast, naming the offending key AND source file", () => {
  it("throws ConfigError naming the nested key path for a bad tier value", async () => {
    const dir = freshDir();
    const file = path.join(dir, "knotrust.config.json");
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        servers: {
          "github-mcp": {
            tools: {
              "github.create_issue": { tier: "bogus", source: "user" },
            },
          },
        },
      }),
    );

    await expect(loadKnotrustConfig({ cwd: dir })).rejects.toThrow(ConfigError);
    try {
      await loadKnotrustConfig({ cwd: dir });
      throw new Error("expected loadKnotrustConfig to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      const configError = err as ConfigError;
      expect(configError.sourceFile).toBe(file);
      expect(
        configError.issues.some(
          (i) => i.path === "servers.github-mcp.tools.github.create_issue.tier",
        ),
      ).toBe(true);
      expect(configError.message).toContain(
        "servers.github-mcp.tools.github.create_issue.tier",
      );
      expect(configError.message).toContain(file);
      // Fix round 1 (P0-E7-T2 review, FIX 1): `ConfigError.message` is NOT
      // self-prefixed with "knotrust: " — every caller that surfaces this to
      // a human (run.ts's top-level guard, init/command.ts) adds its own
      // single "knotrust: " lead-in; a second one baked in here used to
      // produce a doubled "knotrust: knotrust: invalid config …" on stderr.
      expect(configError.message).not.toMatch(/^knotrust:/);
      expect(configError.message).toMatch(/^invalid config/);
    }
  });

  it("throws ConfigError for an unrecognized top-level key, naming the source file", async () => {
    const dir = freshDir();
    const file = path.join(dir, "knotrust.config.yaml");
    writeFileSync(file, "version: 1\nnotARealKey: true\n");

    try {
      await loadKnotrustConfig({ cwd: dir });
      throw new Error("expected loadKnotrustConfig to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      const configError = err as ConfigError;
      expect(configError.sourceFile).toBe(file);
      expect(configError.message).toMatch(/notARealKey/);
    }
  });

  it("rejects a .ts config whose value for a real field evaluates to a function (config must be data)", async () => {
    const dir = freshDir();
    const file = path.join(dir, "knotrust.config.ts");
    writeFileSync(
      file,
      "export default { version: 1, approvalTimeoutSeconds: () => 300 };\n",
    );

    try {
      await loadKnotrustConfig({ cwd: dir });
      throw new Error("expected loadKnotrustConfig to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      const configError = err as ConfigError;
      expect(
        configError.issues.some((i) => i.path === "approvalTimeoutSeconds"),
      ).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// scope: org parses (accepted, inert)
// ---------------------------------------------------------------------------

describe("loadKnotrustConfig — scope: org parses (accepted, inert, §E7)", () => {
  it("loads a config with scope: org without error", async () => {
    const dir = freshDir();
    writeFileSync(
      path.join(dir, "knotrust.config.json"),
      JSON.stringify({ version: 1, scope: "org" }),
    );
    const { config } = await loadKnotrustConfig({ cwd: dir });
    expect(config.scope).toBe("org");
  });
});

// ---------------------------------------------------------------------------
// Defaults applied
// ---------------------------------------------------------------------------

describe("loadKnotrustConfig — defaults applied", () => {
  it("applies timeout 300, scope personal, unknownToolTier sensitive for a minimal config", async () => {
    const dir = freshDir();
    writeFileSync(
      path.join(dir, "knotrust.config.json"),
      JSON.stringify({ version: 1 }),
    );
    const { config } = await loadKnotrustConfig({ cwd: dir });
    expect(config).toEqual({
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
    } satisfies KnotrustConfig);
  });

  it("zero-config: no knotrust.config.* file at all resolves to the same all-defaults config, with no sourceFile", async () => {
    const dir = freshDir();
    const { config, sourceFile } = await loadKnotrustConfig({ cwd: dir });
    expect(config).toEqual({
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
    } satisfies KnotrustConfig);
    expect(sourceFile).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// .ts config actually executes real TypeScript (not just JSON-shaped data)
// ---------------------------------------------------------------------------

describe("loadKnotrustConfig — .ts configs are real TypeScript, executed via c12's bundled jiti", () => {
  it("loads a .ts config using a `satisfies`-annotated object with template-literal string values", async () => {
    const dir = freshDir();
    writeFileSync(
      path.join(dir, "knotrust.config.ts"),
      [
        'const serverName = "github-mcp";',
        "export default {",
        "  version: 1 as const,",
        "  servers: {",
        "    [serverName]: {",
        "      tools: {",
        `        [\`\${serverName.split("-")[0]}.create_issue\`]: { tier: "routine" as const, source: "annotation" as const },`,
        "      },",
        "    },",
        "  },",
        "};",
        "",
      ].join("\n"),
    );

    const { config } = await loadKnotrustConfig({ cwd: dir });
    expect(
      config.servers?.["github-mcp"]?.tools?.["github.create_issue"],
    ).toEqual({ tier: "routine", source: "annotation" });
  });
});

// ---------------------------------------------------------------------------
// Always fresh — never a stale in-process re-read (fix round 1, P0-E7-T3
// review, FIX 3)
// ---------------------------------------------------------------------------

describe("loadKnotrustConfig — always a fresh on-disk read, never stale within one process (fix round 1, P0-E7-T3 review, FIX 3)", () => {
  it("a second load of an evolving .json config reflects the on-disk mutation, not the first load's parse", async () => {
    const dir = freshDir();
    const file = path.join(dir, "knotrust.config.json");
    writeFileSync(
      file,
      JSON.stringify({ version: 1, approvalTimeoutSeconds: 111 }),
    );

    const first = await loadKnotrustConfig({ cwd: dir });
    expect(first.config.approvalTimeoutSeconds).toBe(111);

    writeFileSync(
      file,
      JSON.stringify({ version: 1, approvalTimeoutSeconds: 222 }),
    );
    const second = await loadKnotrustConfig({ cwd: dir });
    expect(second.config.approvalTimeoutSeconds).toBe(222);

    // A third load, a second mutation — not just a one-time unstick.
    writeFileSync(
      file,
      JSON.stringify({ version: 1, approvalTimeoutSeconds: 333 }),
    );
    const third = await loadKnotrustConfig({ cwd: dir });
    expect(third.config.approvalTimeoutSeconds).toBe(333);
  });

  it("a second load of an evolving .ts config reflects the on-disk mutation, not the first load's parse", async () => {
    const dir = freshDir();
    const file = path.join(dir, "knotrust.config.ts");
    writeFileSync(
      file,
      "export default { version: 1, approvalTimeoutSeconds: 111 };\n",
    );

    const first = await loadKnotrustConfig({ cwd: dir });
    expect(first.config.approvalTimeoutSeconds).toBe(111);

    writeFileSync(
      file,
      "export default { version: 1, approvalTimeoutSeconds: 222 };\n",
    );
    const second = await loadKnotrustConfig({ cwd: dir });
    expect(second.config.approvalTimeoutSeconds).toBe(222);
  });

  it("a second load of an evolving .yaml config reflects the on-disk mutation (confirms the pre-existing-fresh format still works)", async () => {
    const dir = freshDir();
    const file = path.join(dir, "knotrust.config.yaml");
    writeFileSync(file, "version: 1\napprovalTimeoutSeconds: 111\n");

    const first = await loadKnotrustConfig({ cwd: dir });
    expect(first.config.approvalTimeoutSeconds).toBe(111);

    writeFileSync(file, "version: 1\napprovalTimeoutSeconds: 222\n");
    const second = await loadKnotrustConfig({ cwd: dir });
    expect(second.config.approvalTimeoutSeconds).toBe(222);
  });

  it("busting the cache does not break a normal repeated load of an UNCHANGED .json config", async () => {
    const dir = freshDir();
    const file = path.join(dir, "knotrust.config.json");
    writeFileSync(
      file,
      JSON.stringify({ version: 1, approvalTimeoutSeconds: 111 }),
    );

    const first = await loadKnotrustConfig({ cwd: dir });
    const second = await loadKnotrustConfig({ cwd: dir });
    expect(first.config).toEqual(second.config);
    expect(second.config.approvalTimeoutSeconds).toBe(111);
  });
});
