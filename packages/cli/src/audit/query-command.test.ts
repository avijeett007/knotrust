/**
 * `audit/query-command.ts` unit + NAMED ACCEPTANCE tests (P0-E4-T4,
 * R122-R124).
 *
 * Headline acceptance (R124): "`knotrust audit query --outcome deny
 * --since 1h` returns correct rows against a seeded fixture log" — proven
 * below in the "NAMED ACCEPTANCE" describe block, seeding a fixture with
 * events spread across tiers/outcomes/tools/times and asserting the EXACT
 * matching set.
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
import type { AuditQueryArgs } from "./argv.js";
import { runAuditQuery } from "./query-command.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

let home: string;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "knotrust-cli-audit-query-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function baseArgs(over: Partial<AuditQueryArgs> = {}): AuditQueryArgs {
  return { json: true, ...over };
}

function runJson(args: AuditQueryArgs, nowEpochMs?: () => number) {
  const stdout = new PassThrough();
  const getOut = collect(stdout);
  const code = runAuditQuery({ stdout, stderr: new PassThrough() }, args, {
    home,
    ...(nowEpochMs !== undefined ? { nowEpochMs } : {}),
  });
  const text = getOut();
  const rows = text
    .split("\n")
    .filter((l) => l.length > 0)
    .map(
      (l) => JSON.parse(l) as { seq: number; tool: string; outcome?: string },
    );
  return { code, rows };
}

// ---------------------------------------------------------------------------
// NAMED ACCEPTANCE (R124): `query --outcome deny --since 1h` — exact rows.
// ---------------------------------------------------------------------------

describe("NAMED ACCEPTANCE — `audit query --outcome deny --since 1h` (R124)", () => {
  it("returns exactly the deny events within the last hour, across tools/agents/outcomes/times", () => {
    // Fixture timestamps are anchored to REAL Date.now() at fixture-build
    // time, offset by controlled amounts — this test exercises the
    // production default clock (no injected `nowEpochMs`), which is the
    // most faithful proof of the real `--since 1h` wiring end-to-end.
    const now = Date.now();
    const sink = createAuditLog({
      home,
      nowEpochMs: () => now - 3 * 3_600_000,
    }); // 3h ago
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: "stripe.create_refund",
      argsHash: computeArgsHash(null),
      outcome: "deny",
      reason: "no_grant_sensitive",
    }); // seq 1 — OLD deny, outside the 1h window: must NOT match
    sink.close();

    const sink2 = createAuditLog({
      home,
      nowEpochMs: () => now - 45 * 60_000,
    }); // 45m ago — within 1h
    sink2.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: "github.create_issue",
      argsHash: computeArgsHash(null),
      outcome: "allow",
    }); // seq 2 — recent ALLOW: wrong outcome, must NOT match
    sink2.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "codex-cli",
      tool: "github.delete_repo",
      argsHash: computeArgsHash(null),
      outcome: "deny",
      reason: "no_grant_critical",
    }); // seq 3 — recent DENY: MUST match
    sink2.append({
      type: AuditEventType.DECISION,
      surface: "cli",
      subject: "user:local",
      agent: "claude-desktop",
      tool: "stripe.create_refund",
      argsHash: computeArgsHash(null),
      outcome: "pending_approval",
    }); // seq 4 — recent, wrong outcome: must NOT match
    sink2.close();

    const sink3 = createAuditLog({ home, nowEpochMs: () => now - 5_000 }); // 5s ago
    sink3.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: "stripe.create_refund",
      argsHash: computeArgsHash(null),
      outcome: "deny",
      reason: "tier_exceeded",
    }); // seq 5 — very recent DENY: MUST match
    sink3.close();

    const { code, rows } = runJson(
      baseArgs({
        outcome: "deny",
        since: { kind: "duration", seconds: 3_600 },
      }),
    );

    expect(code).toBe(0);
    expect(rows.map((r) => r.seq)).toEqual([3, 5]);
    expect(rows.every((r) => r.outcome === "deny")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Unit-level filter coverage (deterministic injected clock).
// ---------------------------------------------------------------------------

describe("runAuditQuery() — filters (deterministic, injected clock)", () => {
  const NOW = Date.UTC(2026, 6, 4, 12, 0, 0);

  function seedAt(offsetMs: number, over: Record<string, unknown> = {}) {
    const sink = createAuditLog({ home, nowEpochMs: () => NOW - offsetMs });
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: "github.create_issue",
      argsHash: computeArgsHash(null),
      outcome: "deny",
      ...over,
    });
    sink.close();
  }

  it("no filters returns every event", () => {
    seedAt(0);
    seedAt(1_000);
    const { rows } = runJson(baseArgs(), () => NOW);
    expect(rows).toHaveLength(2);
  });

  it("--tool filters by pattern", () => {
    seedAt(0, { tool: "github.create_issue" });
    seedAt(1_000, { tool: "stripe.create_refund" });
    const { rows } = runJson(baseArgs({ tool: "github.*" }), () => NOW);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.tool).toBe("github.create_issue");
  });

  it("--since as a raw ISO timestamp excludes events strictly before it", () => {
    seedAt(2 * 3_600_000); // 2h before NOW
    seedAt(0); // exactly NOW
    const { rows } = runJson(
      baseArgs({
        since: { kind: "timestamp", epochMs: NOW - 3_600_000 }, // 1h before NOW
      }),
      () => NOW,
    );
    expect(rows).toHaveLength(1);
  });

  it("human (non-json) mode prints 'No matching audit events.' when nothing matches", () => {
    seedAt(0, { outcome: "allow" });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = runAuditQuery(
      { stdout, stderr: new PassThrough() },
      { outcome: "deny", json: false },
      { home, nowEpochMs: () => NOW },
    );
    expect(code).toBe(0);
    expect(getOut()).toBe("No matching audit events.\n");
  });

  it("human (non-json) mode prints one compact line per match", () => {
    seedAt(0, { outcome: "deny", tool: "github.create_issue" });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    runAuditQuery(
      { stdout, stderr: new PassThrough() },
      { outcome: "deny", json: false },
      { home, nowEpochMs: () => NOW },
    );
    expect(getOut()).toContain("tool=github.create_issue");
    expect(getOut()).toContain("outcome=deny");
  });
});
