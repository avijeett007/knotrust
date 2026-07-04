/**
 * knotrust CLI `audit list|tail|query|verify` — dispatch wiring through the
 * REAL `knotrust` argv surface (P0-E4-T4, R122-R125). Unit-level coverage of
 * each command lives in `audit/*.test.ts`; this file proves the CLI WIRING
 * itself: usage errors reach exit code 2, and each subcommand is actually
 * reachable end-to-end through `runCli` against a real `$KNOTRUST_HOME`.
 */

import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  AuditEventType,
  computeArgsHash,
  createAuditLog,
} from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runCli } from "./run.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

function io(overrides: { stdout?: PassThrough; stderr?: PassThrough } = {}) {
  return {
    stdin: new PassThrough(),
    stdout: overrides.stdout ?? new PassThrough(),
    stderr: overrides.stderr ?? new PassThrough(),
    installSignalHandlers: false,
  };
}

let home: string;
let priorHome: string | undefined;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "knotrust-cli-audit-dispatch-"));
  priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;
});

afterEach(() => {
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;
  rmSync(home, { recursive: true, force: true });
});

describe("knotrust audit — usage errors", () => {
  it("requires a subcommand", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["audit"], io({ stderr }));
    expect(code).toBe(2);
    expect(getErr()).toContain("requires a subcommand");
  });

  it("rejects an unknown subcommand", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["audit", "bogus"], io({ stderr }));
    expect(code).toBe(2);
    expect(getErr()).toContain("unknown subcommand");
  });

  it("query rejects an unknown --outcome", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(
      ["audit", "query", "--outcome", "bogus"],
      io({ stderr }),
    );
    expect(code).toBe(2);
    expect(getErr()).toContain("unknown --outcome");
  });
});

describe("knotrust audit — reachable end-to-end through runCli", () => {
  it("`audit verify` on a fresh (never-appended) home reports intact, exit 0", async () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runCli(["audit", "verify"], io({ stdout }));
    expect(code).toBe(0);
    expect(getOut()).toBe("chain intact (0 events)\n");
  });

  it("`audit list`/`audit tail`/`audit query` all read a real seeded log via KNOTRUST_HOME", async () => {
    const sink = createAuditLog({ home, nowEpochMs: () => Date.now() });
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: "github.create_issue",
      argsHash: computeArgsHash(null),
      outcome: "allow",
    });
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: "stripe.create_refund",
      argsHash: computeArgsHash(null),
      outcome: "deny",
      reason: "no_grant_sensitive",
    });
    sink.close();

    const listStdout = new PassThrough();
    const getListOut = collect(listStdout);
    expect(await runCli(["audit", "list"], io({ stdout: listStdout }))).toBe(0);
    expect(getListOut()).toContain("tool=github.create_issue");
    expect(getListOut()).toContain("tool=stripe.create_refund");

    const tailStdout = new PassThrough();
    const getTailOut = collect(tailStdout);
    expect(
      await runCli(["audit", "tail", "-n", "1"], io({ stdout: tailStdout })),
    ).toBe(0);
    expect(getTailOut()).toContain("tool=stripe.create_refund");
    expect(getTailOut()).not.toContain("tool=github.create_issue");

    const queryStdout = new PassThrough();
    const getQueryOut = collect(queryStdout);
    expect(
      await runCli(
        ["audit", "query", "--outcome", "deny", "--json"],
        io({ stdout: queryStdout }),
      ),
    ).toBe(0);
    const rows = getQueryOut()
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { tool: string; outcome?: string });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.tool).toBe("stripe.create_refund");
  });

  it("`audit verify` on a tampered log through runCli exits non-zero", async () => {
    const sink = createAuditLog({ home, nowEpochMs: () => Date.now() });
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: "github.create_issue",
      argsHash: computeArgsHash(null),
      outcome: "allow",
    });
    sink.close();

    // Tamper: damage the file directly, on disk, via the store's own audit
    // dir layout convention (`<home>/audit/<yyyymm>.jsonl`).
    const auditDir = path.join(home, "audit");
    const filename = readdirSync(auditDir).find((f) => f.endsWith(".jsonl"));
    if (filename === undefined) throw new Error("no audit file found");
    const filePath = path.join(auditDir, filename);
    writeFileSync(
      filePath,
      `${readFileSync(filePath, "utf8").trimEnd()}TAMPER\n`,
    );

    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["audit", "verify"], io({ stderr }));
    expect(code).not.toBe(0);
    expect(getErr()).toContain("knotrust audit verify: chain BROKEN");
  });
});
