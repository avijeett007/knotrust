#!/usr/bin/env node
/**
 * @knotrust/bench — the REAL bench run (P0-E9-T3, R150-R154).
 *
 * This is deliberately NOT part of `pnpm turbo test` (see `package.json`'s
 * `test` script, which only runs `run-bench.smoke.test.ts` — a handful of
 * iterations, seconds not minutes). This script runs the full
 * ≥1000-iterations-per-path measurement `docs/03-engineering/
 * latency-budgets.md` reports numbers from. Run it with:
 *
 *   pnpm --filter @knotrust/bench build && pnpm --filter @knotrust/bench bench
 *
 * (or `pnpm --filter @knotrust/bench bench`, which the `prebench` script
 * already rebuilds for). It prints a human-readable table to stdout and
 * writes the full machine-readable results (plus environment info, for the
 * doc's honesty caveat, R152) to `results/latest.json`.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setupProxyOff } from "./fixtures/proxy-off.js";
import { setupProxyOn } from "./fixtures/proxy-on.js";
import { benchAuditAppendAmortized } from "./paths/audit-append.js";
import { benchCacheHitAllow } from "./paths/cache-hit-allow.js";
import { benchCacheMissGrantVerify } from "./paths/cache-miss-grant-verify.js";
import { benchNonGatedPassthrough } from "./paths/non-gated-passthrough.js";
import { benchProxyReadyToServe } from "./paths/proxy-ready.js";
import type {
  AbsolutePathResult,
  PathResult,
  RoundTripPathResult,
} from "./types.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const resultsDir = path.resolve(here, "..", "results");

// Real iteration counts (R150: "≥1000 iterations/path"). Overridable via env
// for a faster local dry-run — the DEFAULT is what actually satisfies the
// acceptance bar, never a silently-lowered number.
const ROUND_TRIP_WARMUP = envInt("BENCH_ROUND_TRIP_WARMUP", 100);
const ROUND_TRIP_MEASURED = envInt("BENCH_ROUND_TRIP_MEASURED", 1000);
const AUDIT_WARMUP = envInt("BENCH_AUDIT_WARMUP", 50);
const AUDIT_MEASURED = envInt("BENCH_AUDIT_MEASURED", 1000);
// Every iteration is a REAL process spawn (~tens of ms each) — 1000 of these
// takes real wall-clock minutes. Still defaults to the ruling's ≥1000; set
// BENCH_SPAWN_MEASURED lower only for a quick local smoke, never for the
// number that ships in the doc.
const SPAWN_WARMUP = envInt("BENCH_SPAWN_WARMUP", 5);
const SPAWN_MEASURED = envInt("BENCH_SPAWN_MEASURED", 1000);

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function fmt(n: number): string {
  return n.toFixed(3);
}

function isRoundTrip(r: PathResult): r is RoundTripPathResult {
  return "added" in r;
}

function printResult(r: PathResult): void {
  console.log(`\n=== ${r.path} ===`);
  console.log(`budget (added, p95): ${fmt(r.budgetMsP95)} ms`);
  console.log(`warmup=${r.warmupIterations} measured=${r.measuredIterations}`);
  if (isRoundTrip(r)) {
    console.log(
      `ON   p50=${fmt(r.on.p50)} p95=${fmt(r.on.p95)} p99=${fmt(r.on.p99)} mean=${fmt(r.on.mean)} min=${fmt(r.on.min)} max=${fmt(r.on.max)}`,
    );
    console.log(
      `OFF  p50=${fmt(r.off.p50)} p95=${fmt(r.off.p95)} p99=${fmt(r.off.p99)} mean=${fmt(r.off.mean)} min=${fmt(r.off.min)} max=${fmt(r.off.max)}`,
    );
    console.log(
      `ADDED p50=${fmt(r.added.p50)} p95=${fmt(r.added.p95)} p99=${fmt(r.added.p99)}`,
    );
    console.log(
      r.added.p95 <= r.budgetMsP95
        ? `PASS — added p95 ${fmt(r.added.p95)}ms <= budget ${fmt(r.budgetMsP95)}ms`
        : `FAIL — added p95 ${fmt(r.added.p95)}ms > budget ${fmt(r.budgetMsP95)}ms`,
    );
  } else {
    const a = r as AbsolutePathResult;
    console.log(
      `MEASURED p50=${fmt(a.measured.p50)} p95=${fmt(a.measured.p95)} p99=${fmt(a.measured.p99)} mean=${fmt(a.measured.mean)} min=${fmt(a.measured.min)} max=${fmt(a.measured.max)}`,
    );
    console.log(
      a.measured.p95 <= a.budgetMsP95
        ? `PASS — p95 ${fmt(a.measured.p95)}ms <= budget ${fmt(a.budgetMsP95)}ms`
        : `FAIL — p95 ${fmt(a.measured.p95)}ms > budget ${fmt(a.budgetMsP95)}ms`,
    );
  }
}

function environmentInfo(): Record<string, unknown> {
  const cpus = os.cpus();
  return {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cpuModel: cpus[0]?.model ?? "unknown",
    cpuCount: cpus.length,
    totalMemGiB: Math.round((os.totalmem() / 1024 ** 3) * 100) / 100,
    hostname: os.hostname(),
    // Deliberately NO claim of being "the reference machine" (R152) — this
    // is whatever machine actually ran the script.
    note: "This is the machine that ran the bench, NOT a dedicated, isolated reference machine. See docs/03-engineering/latency-budgets.md's honesty caveat.",
  };
}

async function main(): Promise<void> {
  const startedAt = new Date().toISOString();
  console.log(`knotrust bench — started ${startedAt}`);
  console.log(JSON.stringify(environmentInfo(), null, 2));

  const results: PathResult[] = [];

  // Paths 1-3 share ONE proxy-ON harness and ONE proxy-OFF harness (each a
  // single real spawned fake-server child) — see fixtures/proxy-on.ts's
  // module header for why this is the fair comparison.
  console.log("\n--- setting up shared proxy-ON / proxy-OFF harnesses ---");
  const on = await setupProxyOn();
  const off = await setupProxyOff();
  try {
    const cacheHit = await benchCacheHitAllow(on, off, {
      warmupIterations: ROUND_TRIP_WARMUP,
      measuredIterations: ROUND_TRIP_MEASURED,
    });
    printResult(cacheHit);
    results.push(cacheHit);

    const cacheMiss = await benchCacheMissGrantVerify(on, off, {
      warmupIterations: ROUND_TRIP_WARMUP,
      measuredIterations: ROUND_TRIP_MEASURED,
    });
    printResult(cacheMiss);
    results.push(cacheMiss);

    const passthrough = await benchNonGatedPassthrough(on, off, {
      warmupIterations: ROUND_TRIP_WARMUP,
      measuredIterations: ROUND_TRIP_MEASURED,
    });
    printResult(passthrough);
    results.push(passthrough);
  } finally {
    await on.teardown();
    await off.teardown();
  }

  console.log("\n--- audit append (standalone microbenchmark) ---");
  const auditAppend = await benchAuditAppendAmortized({
    warmupIterations: AUDIT_WARMUP,
    measuredIterations: AUDIT_MEASURED,
  });
  printResult(auditAppend);
  results.push(auditAppend);

  console.log(
    "\n--- proxy ready-to-serve after spawn (real process spawn per iteration — this is slow) ---",
  );
  const proxyReady = await benchProxyReadyToServe({
    warmupIterations: SPAWN_WARMUP,
    measuredIterations: SPAWN_MEASURED,
  });
  printResult(proxyReady);
  results.push(proxyReady);

  const finishedAt = new Date().toISOString();
  const output = {
    startedAt,
    finishedAt,
    environment: environmentInfo(),
    results,
  };

  mkdirSync(resultsDir, { recursive: true });
  const outPath = path.join(resultsDir, "latest.json");
  writeFileSync(outPath, `${JSON.stringify(output, null, 2)}\n`, "utf8");
  console.log(`\nwrote ${outPath}`);
}

main().catch((error: unknown) => {
  console.error("knotrust bench FAILED:", error);
  process.exitCode = 1;
});
