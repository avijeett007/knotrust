/**
 * `knotrust add pack <path>` — the command orchestration (P0-E7-T3, rulings
 * R117-R120). Fixture packs + temp configs only — never a real file outside
 * a throwaway per-test directory (STRICT TDD discipline, no real HOME/CWD).
 */

import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import type { KnotrustConfig } from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ConfirmFn } from "./confirm.js";
import { runAddPack } from "./pack-command.js";

let cwd: string;

beforeEach(() => {
  cwd = mkdtempSync(path.join(tmpdir(), "knotrust-add-pack-cwd-"));
});

afterEach(() => {
  rmSync(cwd, { recursive: true, force: true });
});

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

function io(overrides: { stdout?: PassThrough; stderr?: PassThrough } = {}) {
  return {
    stdout: overrides.stdout ?? new PassThrough(),
    stderr: overrides.stderr ?? new PassThrough(),
    cwd,
  };
}

function writePackFile(fileName: string, lines: string[]): string {
  const filePath = path.join(cwd, fileName);
  writeFileSync(filePath, lines.join("\n"), "utf8");
  return filePath;
}

const GITHUB_PACK = [
  "name: github-basics",
  "version: 1",
  "server: github-mcp",
  "tools:",
  "  github.delete_repo:",
  "    tier: critical",
  "  github.create_issue:",
  "    tier: routine",
  "  github.push:",
  "    tier: routine",
];

function readConfig(fileName = "knotrust.config.yaml"): unknown {
  const text = readFileSync(path.join(cwd, fileName), "utf8");
  if (fileName.endsWith(".json")) return JSON.parse(text);
  // yaml — this repo's own generated files are simple enough that the
  // committed `serializeConfigYaml` round-trips through JSON.parse for
  // everything BUT its own quoting; tests instead assert on raw text
  // contents for the yaml case (see below) rather than re-parsing YAML.
  return text;
}

describe("knotrust add pack — invalid input (fail closed, never a raw stack)", () => {
  it("errors when the pack file does not exist", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runAddPack(io({ stderr }), {
      path: "does-not-exist.yaml",
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(1);
    expect(getErr()).toContain("pack file not found");
  });

  it("errors on a pack with an invalid tier", async () => {
    const filePath = writePackFile("bad.yaml", [
      "name: bad-pack",
      "version: 1",
      "server: github-mcp",
      "tools:",
      "  github.delete_repo:",
      "    tier: catastrophic",
    ]);
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runAddPack(io({ stderr }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(1);
    expect(getErr()).toContain("invalid pack");
  });

  it("errors when the pack declares no server and --server is omitted", async () => {
    const filePath = writePackFile("no-server.yaml", [
      "name: no-server-pack",
      "version: 1",
      "tools:",
      "  github.delete_repo:",
      "    tier: critical",
    ]);
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runAddPack(io({ stderr }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(1);
    expect(getErr()).toContain("--server");
  });

  it("--server overrides a missing pack.server declaration", async () => {
    const filePath = writePackFile("no-server.yaml", [
      "name: no-server-pack",
      "version: 1",
      "tools:",
      "  github.delete_repo:",
      "    tier: critical",
    ]);
    const stdout = new PassThrough();
    const code = await runAddPack(io({ stdout }), {
      path: filePath,
      server: "github-mcp",
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
  });

  it("refuses to apply onto an existing knotrust.config.ts (cannot safely regenerate hand-authored TS)", async () => {
    writeFileSync(
      path.join(cwd, "knotrust.config.ts"),
      "export default { version: 1 };\n",
    );
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runAddPack(io({ stderr }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(1);
    expect(getErr()).toContain("TypeScript config");
    // Never touched.
    expect(readFileSync(path.join(cwd, "knotrust.config.ts"), "utf8")).toBe(
      "export default { version: 1 };\n",
    );
  });
});

describe("knotrust add pack — the diff preview (R119, never silent-apply)", () => {
  it("--dry-run prints a human-readable diff and writes NOTHING", async () => {
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runAddPack(io({ stdout }), {
      path: filePath,
      yes: true,
      dryRun: true,
    });
    expect(code).toBe(0);
    const out = getOut();
    expect(out).toContain("NEW: github.delete_repo → critical (from pack)");
    expect(out).toContain("dry run — no changes written");
    expect(existsSync(path.join(cwd, "knotrust.config.yaml"))).toBe(false);
  });

  it("requires confirmation and cancels cleanly when declined (no --yes)", async () => {
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const declineConfirm: ConfirmFn = async () => false;
    const code = await runAddPack(
      io({ stdout }),
      { path: filePath, yes: false, dryRun: false },
      { confirm: declineConfirm },
    );
    expect(code).toBe(0);
    expect(getOut()).toContain("Cancelled");
    expect(existsSync(path.join(cwd, "knotrust.config.yaml"))).toBe(false);
  });

  it("writes atomically after an accepted confirmation (no --yes)", async () => {
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const acceptConfirm: ConfirmFn = async () => true;
    const code = await runAddPack(
      io(),
      { path: filePath, yes: false, dryRun: false },
      { confirm: acceptConfirm },
    );
    expect(code).toBe(0);
    expect(existsSync(path.join(cwd, "knotrust.config.yaml"))).toBe(true);
  });

  it("--yes never invokes the confirm gate at all", async () => {
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    let called = false;
    const spyConfirm: ConfirmFn = async () => {
      called = true;
      return true;
    };
    const code = await runAddPack(
      io(),
      { path: filePath, yes: true, dryRun: false },
      { confirm: spyConfirm },
    );
    expect(code).toBe(0);
    expect(called).toBe(false);
  });
});

describe("knotrust add pack — re-format notice on an EXISTING config (fix round 1, P0-E7-T3 review, FIX 2)", () => {
  const REFORMAT_TEXT =
    "the whole config file will be re-formatted canonically";

  it("prints the notice when applying onto an existing config file", async () => {
    writeFileSync(
      path.join(cwd, "knotrust.config.json"),
      JSON.stringify({
        version: 1,
        scope: "personal",
        unknownToolTier: "sensitive",
        approvalTimeoutSeconds: 300,
      } satisfies KnotrustConfig),
    );
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runAddPack(io({ stderr }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
    expect(getErr()).toContain(REFORMAT_TEXT);
  });

  it("does NOT print the notice when creating a fresh config (nothing new to lose)", async () => {
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runAddPack(io({ stderr }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
    expect(existsSync(path.join(cwd, "knotrust.config.yaml"))).toBe(true);
    expect(getErr()).not.toContain(REFORMAT_TEXT);
  });

  it("prints the notice on --dry-run against an existing config too (a dry run previews what a real apply would do)", async () => {
    writeFileSync(
      path.join(cwd, "knotrust.config.json"),
      JSON.stringify({
        version: 1,
        scope: "personal",
        unknownToolTier: "sensitive",
        approvalTimeoutSeconds: 300,
      } satisfies KnotrustConfig),
    );
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runAddPack(io({ stderr }), {
      path: filePath,
      yes: true,
      dryRun: true,
    });
    expect(code).toBe(0);
    expect(getErr()).toContain(REFORMAT_TEXT);
  });

  it("does NOT print the notice for a true no-op re-apply (nothing is actually written)", async () => {
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const first = await runAddPack(io(), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(first).toBe(0);

    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const second = await runAddPack(io({ stderr }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(second).toBe(0);
    expect(getErr()).not.toContain(REFORMAT_TEXT);
  });
});

describe("knotrust add pack — resulting entries carry source: pack (R117/R118)", () => {
  it("a fresh (skeleton) config gets every pack tool stamped source: pack", async () => {
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const code = await runAddPack(io(), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
    const text = readConfig() as string;
    expect(text).toContain('"unknownToolTier": "sensitive"');
    // The hand-rolled YAML dumper double-quotes every string scalar
    // (config-generate.ts's own documented convention) — assert on that
    // exact shape rather than re-implementing a YAML parser in this test.
    expect(text).toContain('"github.delete_repo"');
    expect(text).toContain('"tier": "critical"');
    expect(text).toContain('"source": "pack"');
  });

  it("preserves the existing config's format (json stays json)", async () => {
    const existing: KnotrustConfig = {
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
    };
    writeFileSync(
      path.join(cwd, "knotrust.config.json"),
      JSON.stringify(existing, null, 2),
    );
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const code = await runAddPack(io(), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
    expect(existsSync(path.join(cwd, "knotrust.config.yaml"))).toBe(false);
    const parsed = readConfig("knotrust.config.json") as KnotrustConfig;
    expect(
      parsed.servers?.["github-mcp"]?.tools?.["github.delete_repo"],
    ).toEqual({ tier: "critical", source: "pack" });
  });

  it("preserves an untouched server's config and other top-level fields", async () => {
    const existing: KnotrustConfig = {
      version: 1,
      scope: "personal",
      unknownToolTier: "critical",
      approvalTimeoutSeconds: 120,
      servers: {
        "other-server": {
          tools: { "other.tool": { tier: "sensitive", source: "user" } },
        },
      },
    };
    writeFileSync(
      path.join(cwd, "knotrust.config.json"),
      JSON.stringify(existing, null, 2),
    );
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const code = await runAddPack(io(), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
    const parsed = readConfig("knotrust.config.json") as KnotrustConfig;
    expect(parsed.unknownToolTier).toBe("critical");
    expect(parsed.approvalTimeoutSeconds).toBe(120);
    expect(parsed.servers?.["other-server"]).toEqual({
      tools: { "other.tool": { tier: "sensitive", source: "user" } },
    });
  });
});

describe("knotrust add pack — precedence-respecting merge at the config level (R118/R120)", () => {
  it("overrides an annotation-seeded entry, keeps a user entry, and notes the KEPT in the diff", async () => {
    const existing: KnotrustConfig = {
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
      servers: {
        "github-mcp": {
          tools: {
            "github.create_issue": { tier: "sensitive", source: "annotation" },
            "github.push": {
              tier: "critical",
              source: "user",
              explicitDeny: true,
            },
          },
        },
      },
    };
    writeFileSync(
      path.join(cwd, "knotrust.config.json"),
      JSON.stringify(existing, null, 2),
    );
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runAddPack(io({ stdout }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
    const out = getOut();
    expect(out).toContain(
      "CHANGE: github.create_issue sensitive → routine (pack)",
    );
    expect(out).toContain(
      "KEPT: github.push → your user setting critical (pack suggested routine)",
    );

    const parsed = readConfig("knotrust.config.json") as KnotrustConfig;
    const tools = parsed.servers?.["github-mcp"]?.tools ?? {};
    expect(tools["github.create_issue"]).toEqual({
      tier: "routine",
      source: "pack",
    });
    // User entry untouched, byte for byte.
    expect(tools["github.push"]).toEqual({
      tier: "critical",
      source: "user",
      explicitDeny: true,
    });
    expect(tools["github.delete_repo"]).toEqual({
      tier: "critical",
      source: "pack",
    });
  });

  it("a pack whose ONLY touched tool is already a user entry prints KEPT and the 'no changes to write' branch (diff non-empty, changed false)", async () => {
    const existing: KnotrustConfig = {
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
      servers: {
        "solo-mcp": {
          tools: { "solo.push": { tier: "critical", source: "user" } },
        },
      },
    };
    writeFileSync(
      path.join(cwd, "knotrust.config.json"),
      JSON.stringify(existing, null, 2),
    );
    const filePath = writePackFile("solo.yaml", [
      "name: solo-pack",
      "version: 1",
      "server: solo-mcp",
      "tools:",
      "  solo.push:",
      "    tier: routine",
    ]);
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runAddPack(io({ stdout }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
    const out = getOut();
    expect(out).toContain(
      "KEPT: solo.push → your user setting critical (pack suggested routine)",
    );
    expect(out).toContain("No changes to write (idempotent no-op).");
    const parsed = readConfig("knotrust.config.json") as KnotrustConfig;
    expect(parsed.servers?.["solo-mcp"]?.tools?.["solo.push"]).toEqual({
      tier: "critical",
      source: "user",
    });
  });

  it("re-applying the identical pack a second time is a clean no-op — same file content, no write-worthy diff", async () => {
    const filePath = writePackFile("github.yaml", GITHUB_PACK);
    const first = await runAddPack(io(), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(first).toBe(0);
    const afterFirst = readFileSync(
      path.join(cwd, "knotrust.config.yaml"),
      "utf8",
    );

    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const second = await runAddPack(io({ stdout }), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(second).toBe(0);
    // Every pack-touched tool is already an identical `source: pack` entry —
    // a TRUE no-op (no diff line at all, not even a CHANGE for "same tier").
    expect(getOut()).toContain(
      "No tools to apply — pack already fully reflected in config.",
    );
    expect(getOut()).not.toContain("CHANGE:");
    expect(getOut()).not.toContain("NEW:");

    const afterSecond = readFileSync(
      path.join(cwd, "knotrust.config.yaml"),
      "utf8",
    );
    expect(afterSecond).toBe(afterFirst);
  });
});
