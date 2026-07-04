/**
 * knotrust CLI `grant` / `grant list` / `revoke` — dispatch + named
 * acceptances through the REAL `knotrust` argv surface (P0-E7-T2,
 * R111-R114). `run.grant-e2e.test.ts` covers the headline
 * mint->list->allow->revoke->deny composition; this file proves the CLI
 * WIRING itself (usage errors, and the three other named acceptances —
 * `--tier-cap critical` refusal, the destructive-word confirmation, and
 * `--expires`'s exact `exp` — reached through `runCli`, not just the unit
 * level already covered in `grant/argv.test.ts`/`grant/mint-command.test.ts`).
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import { saveToolInventory } from "@knotrust/proxy-stdio";
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

let home: string;
let cwd: string;
let priorHome: string | undefined;
let priorBackend: string | undefined;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "knotrust-cli-grant-home-"));
  cwd = mkdtempSync(path.join(tmpdir(), "knotrust-cli-grant-cwd-"));
  priorHome = process.env.KNOTRUST_HOME;
  priorBackend = process.env.KNOTRUST_KEY_BACKEND;
  process.env.KNOTRUST_HOME = home;
  // NEVER the real OS keychain (R116/TDD discipline).
  process.env.KNOTRUST_KEY_BACKEND = "file";
});

afterEach(() => {
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;
  if (priorBackend === undefined) delete process.env.KNOTRUST_KEY_BACKEND;
  else process.env.KNOTRUST_KEY_BACKEND = priorBackend;
  rmSync(home, { recursive: true, force: true });
  rmSync(cwd, { recursive: true, force: true });
});

describe("knotrust grant — usage errors", () => {
  it("requires --tool and --server", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["grant"], io({ stderr }));
    expect(code).toBe(2);
    expect(getErr()).toContain("--tool is required");
  });

  it("grant list rejects an unknown flag", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["grant", "list", "--bogus"], io({ stderr }));
    expect(code).toBe(2);
    expect(getErr()).toContain("unknown flag");
  });
});

describe("knotrust grant — malformed knotrust.config error prefix (fix round 1, P0-E7-T2 review, FIX 1)", () => {
  it("a malformed-config mint prints exactly one 'knotrust: ' prefix, never 'knotrust: knotrust:'", async () => {
    writeFileSync(
      path.join(cwd, "knotrust.config.json"),
      JSON.stringify({
        version: 1,
        servers: {
          "github-mcp": {
            tools: { "github.create_issue": { tier: "bogus", source: "user" } },
          },
        },
      }),
    );
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(
      [
        "grant",
        "--tool",
        "github.create_issue",
        "--server",
        "github-mcp",
        "--yes",
      ],
      io({ stderr, cwd }),
    );
    expect(code).toBe(1);
    const err = getErr();
    expect(err).not.toContain("knotrust: knotrust:");
    expect((err.match(/knotrust: /g) ?? []).length).toBe(1);
    expect(err).toContain("invalid config");
  });
});

describe("knotrust revoke — usage errors", () => {
  it("requires a selector", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["revoke"], io({ stderr }));
    expect(code).toBe(2);
    expect(getErr()).toContain("requires a jti");
  });
});

describe("knotrust grant — named acceptance: --tier-cap critical refused without --i-understand-critical (R111)", () => {
  it("refuses with exit 2 and never mints", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(
      [
        "grant",
        "--tool",
        "stripe.refund_all",
        "--server",
        "stripe-mcp",
        "--tier-cap",
        "critical",
        "--yes",
      ],
      io({ stderr, cwd }),
    );
    expect(code).toBe(2);
    expect(getErr()).toContain("--i-understand-critical");

    const listStdout = new PassThrough();
    const getListOut = collect(listStdout);
    await runCli(["grant", "list"], io({ stdout: listStdout }));
    expect(getListOut()).toContain("No active grants.");
  });

  it("mints when --i-understand-critical is given", async () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runCli(
      [
        "grant",
        "--tool",
        "stripe.refund_all",
        "--server",
        "stripe-mcp",
        "--tier-cap",
        "critical",
        "--i-understand-critical",
        "--yes",
      ],
      io({ stdout, cwd }),
    );
    expect(code).toBe(0);
    expect(getOut()).toContain("Minted durable grant");
  });
});

describe("knotrust grant — named acceptance: destructive-word confirmation (R111)", () => {
  it("includes 'destructive' in the printed confirmation for a destructiveHint tool", async () => {
    saveToolInventory(home, "github-mcp", {
      "github.delete_repo": {
        annotations: {
          trusted: false,
          source: "server_advertised",
          destructiveHint: true,
        },
        inputSchemaHash: "sha256:x",
      },
    });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runCli(
      [
        "grant",
        "--tool",
        "github.delete_repo",
        "--server",
        "github-mcp",
        "--yes",
      ],
      io({ stdout, cwd }),
    );
    expect(code).toBe(0);
    expect(getOut().toLowerCase()).toContain("destructive");
  });
});

describe("knotrust grant — named acceptance: --expires parses to the EXACT exp (R112)", () => {
  it("grant list --json shows exp = iat + parsed duration", async () => {
    const mintCode = await runCli(
      [
        "grant",
        "--tool",
        "github.create_issue",
        "--server",
        "github-mcp",
        "--expires",
        "12h",
        "--yes",
      ],
      io({ cwd }),
    );
    expect(mintCode).toBe(0);

    const listStdout = new PassThrough();
    const getListOut = collect(listStdout);
    await runCli(["grant", "list", "--json"], io({ stdout: listStdout }));
    const parsed = JSON.parse(getListOut()) as {
      active: Array<{ iat: number; exp: number }>;
    };
    expect(parsed.active).toHaveLength(1);
    const row = parsed.active[0] as { iat: number; exp: number };
    expect(row.exp - row.iat).toBe(43_200); // 12h, exactly
  });

  it("rejects a malformed --expires with a clean usage error, never a raw stack", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(
      [
        "grant",
        "--tool",
        "github.create_issue",
        "--server",
        "github-mcp",
        "--expires",
        "not-a-duration",
        "--yes",
      ],
      io({ stderr, cwd }),
    );
    expect(code).toBe(2);
    expect(getErr()).toContain("invalid duration");
    expect(getErr()).not.toContain(" at "); // no stack-trace-shaped line
  });
});
