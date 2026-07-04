/**
 * `knotrust add pack` — dispatch + named acceptances through the REAL
 * `knotrust` argv surface (P0-E7-T3, rulings R117-R121). Mirrors
 * `run.grant.test.ts`'s own convention: this file proves the CLI WIRING
 * itself (usage errors, `--dry-run`, `--yes`, the diff preview, and
 * `source: pack` stamping reached through `runCli`, not just the unit level
 * already covered in `add/argv.test.ts`/`add/pack-command.test.ts`). The
 * headline precedence-integration proof (R120: pack overrides annotation,
 * preserves user, and the new tier actually governs a real
 * `evaluatePrecedence` call) lives in `add/precedence.test.ts`.
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
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runCli } from "./run.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

function io(
  overrides: { stdout?: PassThrough; stderr?: PassThrough; cwd?: string } = {},
) {
  return {
    stdin: new PassThrough(),
    stdout: overrides.stdout ?? new PassThrough(),
    stderr: overrides.stderr ?? new PassThrough(),
    installSignalHandlers: false,
    ...(overrides.cwd !== undefined ? { cwd: overrides.cwd } : {}),
  };
}

let cwd: string;

beforeEach(() => {
  cwd = mkdtempSync(path.join(tmpdir(), "knotrust-cli-add-cwd-"));
});

afterEach(() => {
  rmSync(cwd, { recursive: true, force: true });
});

function writePack(fileName: string, lines: string[]): string {
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
];

describe("knotrust add — usage errors", () => {
  it("requires a <kind>", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["add"], io({ stderr }));
    expect(code).toBe(2);
    expect(getErr()).toContain("missing <kind>");
  });

  it("rejects an unknown <kind>, naming what's supported today and what's P1", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["add", "pdp", "cedar"], io({ stderr }));
    expect(code).toBe(2);
    expect(getErr()).toContain('unknown kind "pdp"');
  });

  it("requires a <path> for add pack", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["add", "pack"], io({ stderr }));
    expect(code).toBe(2);
    expect(getErr()).toContain("missing <path>");
  });

  it("errors cleanly (exit 1, no raw stack) when the pack file does not exist", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(
      ["add", "pack", "nope.yaml", "--yes"],
      io({ stderr, cwd }),
    );
    expect(code).toBe(1);
    const err = getErr();
    expect(err).toContain("pack file not found");
    expect(err).not.toContain(" at "); // no stack-trace-shaped line
  });
});

describe("knotrust add pack — named acceptance: diff preview + --dry-run writes nothing (R119)", () => {
  it("prints a human-readable diff and writes no config", async () => {
    const filePath = writePack("github.yaml", GITHUB_PACK);
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runCli(
      ["add", "pack", filePath, "--dry-run", "--yes"],
      io({ stdout, cwd }),
    );
    expect(code).toBe(0);
    const out = getOut();
    expect(out).toContain("NEW: github.delete_repo → critical (from pack)");
    expect(out).toContain("dry run — no changes written");
    expect(existsSync(path.join(cwd, "knotrust.config.yaml"))).toBe(false);
  });
});

describe("knotrust add pack — named acceptance: --yes applies and stamps source: pack (R117/R118)", () => {
  it("writes a knotrust.config.yaml with the pack's tool stamped source: pack", async () => {
    const filePath = writePack("github.yaml", GITHUB_PACK);
    const code = await runCli(["add", "pack", filePath, "--yes"], io({ cwd }));
    expect(code).toBe(0);
    const configText = readFileSync(
      path.join(cwd, "knotrust.config.yaml"),
      "utf8",
    );
    expect(configText).toContain('"github.delete_repo"');
    expect(configText).toContain('"tier": "critical"');
    expect(configText).toContain('"source": "pack"');
  });

  it("re-applying the same pack through the full CLI surface is a clean idempotent no-op", async () => {
    const filePath = writePack("github.yaml", GITHUB_PACK);
    const first = await runCli(["add", "pack", filePath, "--yes"], io({ cwd }));
    expect(first).toBe(0);
    const afterFirst = readFileSync(
      path.join(cwd, "knotrust.config.yaml"),
      "utf8",
    );

    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const second = await runCli(
      ["add", "pack", filePath, "--yes"],
      io({ stdout, cwd }),
    );
    expect(second).toBe(0);
    expect(getOut()).not.toContain("CHANGE:");
    expect(getOut()).not.toContain("NEW:");

    const afterSecond = readFileSync(
      path.join(cwd, "knotrust.config.yaml"),
      "utf8",
    );
    expect(afterSecond).toBe(afterFirst);
  });
});

describe("knotrust add pack — --server overrides a missing pack.server declaration", () => {
  it("applies against the flag-given server when the pack omits its own", async () => {
    const filePath = writePack("no-server.yaml", [
      "name: no-server-pack",
      "version: 1",
      "tools:",
      "  github.delete_repo:",
      "    tier: critical",
    ]);
    const code = await runCli(
      ["add", "pack", filePath, "--server", "github-mcp", "--yes"],
      io({ cwd }),
    );
    expect(code).toBe(0);
    const configText = readFileSync(
      path.join(cwd, "knotrust.config.yaml"),
      "utf8",
    );
    expect(configText).toContain('"github-mcp"');
  });
});
