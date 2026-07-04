/**
 * @knotrust/bench — Path 4: audit append (amortized per event). Budget:
 * ≤2ms amortized (R150 bullet 4).
 *
 * ## Why this is an ABSOLUTE measurement, not a proxy-on-minus-proxy-off delta
 *
 * R151's methodology ("round-trip WITH the proxy minus round-trip DIRECT to
 * the fake server") is defined for a REQUEST PATH — it presumes a
 * "proxy-off" baseline that does the same user-visible thing without the
 * proxy. There is no such baseline for an audit append: with the proxy off,
 * no audit event is written AT ALL, so "proxy-off" would not be zero-cost by
 * coincidence — it would be undefined (the operation doesn't happen). The
 * honest thing this bench can do is measure `@knotrust/store`'s real
 * `createAuditLog().append()` directly (P0-E4-T3): a real temp-dir-backed,
 * hash-chained JSONL log, batched-fsync (non-`"immediate"`) appends, timed
 * individually so "amortized" reflects the real mix of cheap in-memory
 * writes and the periodic batched fsync — never a synthetic average that
 * hides the fsync spikes inside a single wall-clock/N division.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  AuditEventType,
  computeArgsHash,
  createAuditLog,
} from "@knotrust/store";
import { type MeasureOptions, measureAsync } from "../iterate.js";
import { summarize } from "../stats.js";
import type { AbsolutePathResult } from "../types.js";

const BUDGET_MS_P95 = 2;

export async function benchAuditAppendAmortized(
  opts: MeasureOptions,
): Promise<AbsolutePathResult> {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-bench-audit-"));
  const audit = createAuditLog({ home, nowEpochMs: () => Date.now() });
  let seq = 0;

  try {
    const durations = await measureAsync(async () => {
      seq += 1;
      audit.append({
        type: AuditEventType.DECISION,
        surface: "bench",
        subject: "bench-user",
        agent: "bench-agent",
        tool: "bench_tool",
        argsHash: computeArgsHash({ n: seq }),
        outcome: "allow",
      });
      // append() is itself SYNCHRONOUS (returns AuditEvent, not a Promise) —
      // wrapped in an async closure purely so the one shared `measureAsync`
      // timing loop (`iterate.ts`) works uniformly across every path.
    }, opts);

    return {
      path: "audit-append-amortized",
      budgetMsP95: BUDGET_MS_P95,
      measured: summarize(durations),
      warmupIterations: opts.warmupIterations,
      measuredIterations: opts.measuredIterations,
    };
  } finally {
    try {
      audit.close();
    } catch {
      // best-effort — releasing the writer lock is the goal.
    }
    rmSync(home, { recursive: true, force: true });
  }
}
