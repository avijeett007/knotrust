/**
 * `audit/verify-command.ts` unit + NAMED ACCEPTANCE tests (P0-E4-T4,
 * R122/R124).
 *
 * Headline acceptance (R124): "`verify` on a hand-tampered log exits
 * non-zero naming the first broken seq" — proven below in the "NAMED
 * ACCEPTANCE" describe block.
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
import { canonicalizeJcs } from "@knotrust/core";
import {
  AuditEventType,
  computeArgsHash,
  createAuditLog,
} from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runAuditVerify } from "./verify-command.js";

/** The single `<yyyymm>.jsonl` file a fixture built in this test's `home` produced — avoids re-deriving the month name from `Date.now()` a second time (flaky at a real month boundary). */
function soleAuditFile(home: string): string {
  const auditDir = path.join(home, "audit");
  const files = readdirSync(auditDir).filter((f) => f.endsWith(".jsonl"));
  if (files.length !== 1) {
    throw new Error(
      `expected exactly one .jsonl file, found: ${files.join(", ")}`,
    );
  }
  return path.join(auditDir, files[0] as string);
}

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

let home: string;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "knotrust-cli-audit-verify-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function seed(count: number, nowEpochMs: () => number): void {
  const sink = createAuditLog({ home, nowEpochMs });
  for (let i = 0; i < count; i++) {
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: `tool.call_${i}`,
      argsHash: computeArgsHash(null),
      outcome: "allow",
    });
  }
  sink.close();
}

describe("runAuditVerify() — success path", () => {
  it("an empty/never-appended log is intact with 0 events", () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = runAuditVerify(
      { stdout, stderr: new PassThrough() },
      { home },
    );
    expect(code).toBe(0);
    expect(getOut()).toBe("chain intact (0 events)\n");
  });

  it("prints 'chain intact (N events)' and exits 0 for an untampered chain", () => {
    seed(9, () => Date.now());
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = runAuditVerify(
      { stdout, stderr: new PassThrough() },
      { home },
    );
    expect(code).toBe(0);
    expect(getOut()).toBe("chain intact (9 events)\n");
  });
});

// ---------------------------------------------------------------------------
// NAMED ACCEPTANCE (R124): verify on a tampered log exits non-zero, naming
// the first broken seq.
// ---------------------------------------------------------------------------

describe("NAMED ACCEPTANCE — verify on a tampered log exits non-zero, names the broken seq (R124)", () => {
  it("a hand-tampered field (hash_mismatch) — exits non-zero, stderr names file/seq/kind", () => {
    seed(10, () => Date.now());

    const filePath = soleAuditFile(home);
    const lines = readFileSync(filePath, "utf8").split("\n");
    const tamperedIndex = 4; // seq 5
    const event = JSON.parse(lines[tamperedIndex] as string) as Record<
      string,
      unknown
    >;
    event.tool = "TAMPERED.tool";
    lines[tamperedIndex] = canonicalizeJcs(event);
    writeFileSync(filePath, lines.join("\n"));

    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = runAuditVerify({ stdout, stderr }, { home });

    expect(code).not.toBe(0);
    const err = getErr();
    expect(err).toContain("seq 5");
    expect(err).toContain("hash_mismatch");
    expect(err).toMatch(/\.jsonl:5/); // file:line
  });

  it("a deleted line (seq_gap) — exits non-zero, names the exact seq that's now missing", () => {
    seed(10, () => Date.now());

    const filePath = soleAuditFile(home);
    const lines = readFileSync(filePath, "utf8").split("\n").filter(Boolean);
    lines.splice(4, 1); // delete seq 5 entirely
    writeFileSync(filePath, `${lines.join("\n")}\n`);

    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = runAuditVerify({ stdout, stderr }, { home });

    expect(code).not.toBe(0);
    const err = getErr();
    expect(err).toContain("seq 6"); // the seq that's now unexpectedly at that position
    expect(err).toContain("seq_gap");
  });
});
