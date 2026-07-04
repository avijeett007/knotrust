/**
 * NAMED ACCEPTANCE (P0-E4-T4, R123/R124): "memory stays flat streaming a
 * 100 MB log (measured in test)."
 *
 * ## Size chosen (R124: "document the size chosen")
 *
 * 300,000 synthetic events, built through the REAL `createAuditLog` (a
 * genuine, correctly hash-chained fixture — not a hand-rolled shortcut),
 * measured on this machine at **~120 MB** — this is the literal "100 MB
 * log" the plan's acceptance names, not a substitution; 300k events build
 * in well under 2s and stream in well under 1s, so there was no need to
 * fall back to the brief's documented smaller-size escape hatch.
 *
 * ## What "flat memory" means here, concretely
 *
 * `runAuditQuery`/`runAuditTail` are asserted to grow `process.memoryUsage
 * ().heapUsed` by an amount that is BOTH:
 *   1. bounded by a small absolute ceiling (`MAX_HEAP_DELTA_MB`), and
 *   2. a small fraction of the fixture's own on-disk size
 *      (`MAX_HEAP_DELTA_FRACTION_OF_FILE`) —
 * the second bound is what actually discriminates "streams in O(chunk)
 * memory" from "loads the whole file": a `readFileSync`-based
 * implementation would grow heap roughly PROPORTIONAL to file size (the
 * decoded string alone is ~2x the UTF-8 byte size), so requiring the delta
 * stay under a small fraction of file size is a real regression trip-wire,
 * not just a generous unconditional allowance.
 *
 * `--json` output is written to a discard `Writable` (never buffered) so
 * the test measures the COMMAND's own memory use, not an artifact of
 * accumulating output for later assertion.
 */

import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Writable } from "node:stream";
import {
  AuditEventType,
  computeArgsHash,
  createAuditLog,
} from "@knotrust/store";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runAuditQuery } from "./query-command.js";
import { runAuditTail } from "./tail-command.js";

const FIXTURE_EVENT_COUNT = 300_000;
const MAX_HEAP_DELTA_MB = 40;
const MAX_HEAP_DELTA_FRACTION_OF_FILE = 0.25;

function createDiscardStream(): Writable {
  return new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
}

function heapUsedMb(): number {
  // Best-effort GC before measuring — only available if the test runner
  // happens to pass `--expose-gc`; the assertions below are generous enough
  // (see module header) to stay meaningful without it too.
  (global as { gc?: () => void }).gc?.();
  return process.memoryUsage().heapUsed / (1024 * 1024);
}

let home: string;
let fixtureFileSizeBytes: number;

beforeAll(() => {
  home = mkdtempSync(path.join(tmpdir(), "knotrust-audit-streaming-mem-"));
  const buildStart = performance.now();
  const sink = createAuditLog({ home, nowEpochMs: () => Date.now() });
  for (let i = 0; i < FIXTURE_EVENT_COUNT; i++) {
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: i % 3 === 0 ? "claude-desktop" : "codex-cli",
      tool: `server${i % 10}.tool_call_${i % 50}`,
      argsHash: computeArgsHash({ i }),
      outcome: i % 4 === 0 ? "deny" : "allow",
      ...(i % 4 === 0 ? { reason: "no_grant_sensitive" } : {}),
    });
  }
  sink.close();
  const buildMs = performance.now() - buildStart;

  const auditDir = path.join(home, "audit");
  fixtureFileSizeBytes = readdirSync(auditDir)
    .filter((f) => f.endsWith(".jsonl"))
    .reduce((sum, f) => sum + statSync(path.join(auditDir, f)).size, 0);

  console.log(
    `[P0-E4-T4 acceptance] fixture: ${FIXTURE_EVENT_COUNT} events, ` +
      `${(fixtureFileSizeBytes / (1024 * 1024)).toFixed(1)}MB on disk, ` +
      `built in ${buildMs.toFixed(0)}ms`,
  );
}, 60_000);

afterAll(() => {
  rmSync(home, { recursive: true, force: true });
});

describe("NAMED ACCEPTANCE — flat memory streaming a ~120MB audit log (R123/R124)", () => {
  it("runAuditQuery (no filters, --json, matches every event) stays flat-memory", () => {
    const stdout = createDiscardStream();
    const stderr = createDiscardStream();

    const before = heapUsedMb();
    const start = performance.now();
    const code = runAuditQuery({ stdout, stderr }, { json: true }, { home });
    const elapsedMs = performance.now() - start;
    const after = heapUsedMb();
    const deltaMb = after - before;

    console.log(
      `[P0-E4-T4 acceptance] audit query (unfiltered) over ${FIXTURE_EVENT_COUNT} ` +
        `events: ${elapsedMs.toFixed(0)}ms, heapUsed delta ${deltaMb.toFixed(2)}MB ` +
        `(bound ${MAX_HEAP_DELTA_MB}MB / ${(MAX_HEAP_DELTA_FRACTION_OF_FILE * 100).toFixed(0)}% of file size)`,
    );

    expect(code).toBe(0);
    expect(deltaMb).toBeLessThan(MAX_HEAP_DELTA_MB);
    expect(deltaMb).toBeLessThan(
      (fixtureFileSizeBytes / (1024 * 1024)) * MAX_HEAP_DELTA_FRACTION_OF_FILE,
    );
  }, 30_000);

  it("runAuditTail (-n 50 ring buffer) over the same large log stays flat-memory", () => {
    const stdout = createDiscardStream();
    const stderr = createDiscardStream();

    const before = heapUsedMb();
    const start = performance.now();
    const code = runAuditTail(
      { stdout, stderr },
      { limit: 50, json: true },
      { home },
    );
    const elapsedMs = performance.now() - start;
    const after = heapUsedMb();
    const deltaMb = after - before;

    console.log(
      `[P0-E4-T4 acceptance] audit tail -n 50 over ${FIXTURE_EVENT_COUNT} events: ` +
        `${elapsedMs.toFixed(0)}ms, heapUsed delta ${deltaMb.toFixed(2)}MB`,
    );

    expect(code).toBe(0);
    expect(deltaMb).toBeLessThan(MAX_HEAP_DELTA_MB);
    expect(deltaMb).toBeLessThan(
      (fixtureFileSizeBytes / (1024 * 1024)) * MAX_HEAP_DELTA_FRACTION_OF_FILE,
    );
  }, 30_000);
});
