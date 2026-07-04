/**
 * `audit/tail-command.ts` unit tests (P0-E4-T4) — `knotrust audit list` /
 * `knotrust audit tail` (deliberate aliases, same implementation).
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  AuditEventType,
  computeArgsHash,
  createAuditLog,
} from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runAuditTail } from "./tail-command.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

let home: string;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "knotrust-cli-audit-tail-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function seed(count: number): void {
  const sink = createAuditLog({ home, nowEpochMs: () => Date.now() });
  for (let i = 0; i < count; i++) {
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: `tool.call_${i}`,
      argsHash: computeArgsHash(null),
      outcome: i % 2 === 0 ? "allow" : "deny",
    });
  }
  sink.close();
}

describe("runAuditTail()", () => {
  it("prints 'No audit events.' for an empty log", () => {
    const stdout = new PassThrough();
    // `collect()` must attach its 'data' listener BEFORE `runAuditTail`
    // writes — a `PassThrough` only starts flowing (emitting synchronously
    // buffered writes) once something is listening.
    const getOut = collect(stdout);
    const code = runAuditTail(
      { stdout, stderr: new PassThrough() },
      { limit: 50, json: false },
      { home },
    );
    expect(code).toBe(0);
    expect(getOut()).toBe("No audit events.\n");
  });

  it("prints every event when there are fewer than the limit, oldest first / newest last (R122)", () => {
    seed(5);
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = runAuditTail(
      { stdout, stderr: new PassThrough() },
      { limit: 50, json: false },
      { home },
    );
    expect(code).toBe(0);
    const lines = getOut().trim().split("\n");
    expect(lines).toHaveLength(5);
    expect(lines[0]).toContain("tool=tool.call_0");
    expect(lines[4]).toContain("tool=tool.call_4"); // newest last
  });

  it("keeps only the LAST N events when the log exceeds the limit (bounded ring buffer, R123)", () => {
    seed(20);
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = runAuditTail(
      { stdout, stderr: new PassThrough() },
      { limit: 3, json: false },
      { home },
    );
    expect(code).toBe(0);
    const lines = getOut().trim().split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[0]).toContain("tool=tool.call_17");
    expect(lines[1]).toContain("tool=tool.call_18");
    expect(lines[2]).toContain("tool=tool.call_19");
  });

  it("--json prints NDJSON — one raw stored event per line, matching the limit", () => {
    seed(4);
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = runAuditTail(
      { stdout, stderr: new PassThrough() },
      { limit: 2, json: true },
      { home },
    );
    expect(code).toBe(0);
    const lines = getOut().trim().split("\n");
    expect(lines).toHaveLength(2);
    const parsed = lines.map((l) => JSON.parse(l) as { tool: string });
    expect(parsed.map((p) => p.tool)).toEqual(["tool.call_2", "tool.call_3"]);
  });

  it("--json on an empty log prints nothing (not the human 'No audit events.' text)", () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    runAuditTail(
      { stdout, stderr: new PassThrough() },
      { limit: 50, json: true },
      { home },
    );
    expect(getOut()).toBe("");
  });
});
