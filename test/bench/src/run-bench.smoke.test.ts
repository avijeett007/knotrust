/**
 * @knotrust/bench — smoke test (P0-E9-T3, ruling 6: "the harness IS the
 * deliverable; a smoke test that it runs + produces numbers").
 *
 * Runs every one of the 5 path benchmarks end-to-end against the REAL
 * substrate, with TINY iteration counts (seconds, not the ≥1000-iteration/
 * several-minute real run — that's `run-bench.ts`, invoked via `pnpm
 * --filter @knotrust/bench bench`, deliberately NOT part of this file/the
 * `test` script). This proves the harness actually runs and produces real,
 * finite p50/p95/p99 numbers — it does NOT assert against the ratified
 * budgets (a 2-5 iteration sample is not a meaningful budget check; that is
 * exactly why the acceptance's real run needs ≥1000 iterations and a doc,
 * not a unit test assertion).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ProxyOffHarness, setupProxyOff } from "./fixtures/proxy-off.js";
import { type ProxyOnHarness, setupProxyOn } from "./fixtures/proxy-on.js";
import { benchAuditAppendAmortized } from "./paths/audit-append.js";
import { benchCacheHitAllow } from "./paths/cache-hit-allow.js";
import { benchCacheMissGrantVerify } from "./paths/cache-miss-grant-verify.js";
import { benchNonGatedPassthrough } from "./paths/non-gated-passthrough.js";
import { benchProxyReadyToServe } from "./paths/proxy-ready.js";
import type { RoundTripPathResult } from "./types.js";

const SMOKE_ROUND_TRIP = { warmupIterations: 2, measuredIterations: 5 };

function assertFiniteRoundTrip(r: RoundTripPathResult): void {
  for (const stats of [r.on, r.off]) {
    expect(Number.isFinite(stats.p50)).toBe(true);
    expect(Number.isFinite(stats.p95)).toBe(true);
    expect(Number.isFinite(stats.p99)).toBe(true);
    expect(stats.count).toBe(SMOKE_ROUND_TRIP.measuredIterations);
  }
  expect(Number.isFinite(r.added.p50)).toBe(true);
  expect(Number.isFinite(r.added.p95)).toBe(true);
  expect(Number.isFinite(r.added.p99)).toBe(true);
  expect(r.budgetMsP95).toBeGreaterThan(0);
}

describe("P0-E9-T3 — bench harness smoke (real proxy + decider + cache + grant verify, tiny iteration counts)", () => {
  let on: ProxyOnHarness;
  let off: ProxyOffHarness;

  beforeAll(async () => {
    on = await setupProxyOn();
    off = await setupProxyOff();
  }, 30_000);

  afterAll(async () => {
    await on?.teardown();
    await off?.teardown();
  });

  it("cache-hit-allow: runs end-to-end and produces finite ON/OFF/ADDED p50/p95/p99", async () => {
    const result = await benchCacheHitAllow(on, off, SMOKE_ROUND_TRIP);
    expect(result.path).toBe("cache-hit-allow");
    assertFiniteRoundTrip(result);
  }, 20_000);

  it("cache-miss-l0-eval-plus-grant-verify: runs end-to-end (real Ed25519 verify) and produces finite numbers", async () => {
    const result = await benchCacheMissGrantVerify(on, off, SMOKE_ROUND_TRIP);
    expect(result.path).toBe("cache-miss-l0-eval-plus-grant-verify");
    assertFiniteRoundTrip(result);
  }, 20_000);

  it("non-gated-passthrough: runs end-to-end (tools/list) and produces finite numbers", async () => {
    const result = await benchNonGatedPassthrough(on, off, SMOKE_ROUND_TRIP);
    expect(result.path).toBe("non-gated-passthrough");
    assertFiniteRoundTrip(result);
  }, 20_000);

  it("audit-append-amortized: runs end-to-end against a real audit log and produces finite numbers", async () => {
    const result = await benchAuditAppendAmortized({
      warmupIterations: 2,
      measuredIterations: 20,
    });
    expect(result.path).toBe("audit-append-amortized");
    expect(Number.isFinite(result.measured.p50)).toBe(true);
    expect(Number.isFinite(result.measured.p95)).toBe(true);
    expect(Number.isFinite(result.measured.p99)).toBe(true);
    expect(result.measured.count).toBe(20);
  }, 20_000);

  it("proxy-ready-to-serve-after-spawn: runs end-to-end (real process spawn) and produces finite numbers", async () => {
    const result = await benchProxyReadyToServe({
      warmupIterations: 1,
      measuredIterations: 2,
    });
    expect(result.path).toBe("proxy-ready-to-serve-after-spawn");
    expect(Number.isFinite(result.measured.p50)).toBe(true);
    expect(result.measured.p50).toBeGreaterThan(0);
    expect(result.measured.count).toBe(2);
  }, 30_000);
});
