/**
 * @knotrust/bench — Path 1: cache-hit `allow` (routine fast path). Budget:
 * added p95 ≤ 5ms (R150 bullet 1).
 *
 * The SAME `ROUTINE_TOOL` call, with FIXED arguments, repeated. The very
 * first call against a fresh proxy-ON harness is necessarily a cache MISS
 * (nothing cached yet) — as long as `opts.warmupIterations >= 1`, that one
 * miss is absorbed into the discarded warm-up, so every MEASURED iteration
 * is a genuine decision-cache hit (`@knotrust/core`'s `createDecisionCache`,
 * P0-E2-T4): zero grant-store reads, one `cacheHit:true` audit event, PDR
 * "sub-ms cached fast path" — R150's own description of this path.
 */

import { ROUTINE_TOOL } from "../fixtures/policy.js";
import type { ProxyOffHarness } from "../fixtures/proxy-off.js";
import type { ProxyOnHarness } from "../fixtures/proxy-on.js";
import { type MeasureOptions, measureAsync } from "../iterate.js";
import { subtractPercentiles, summarize } from "../stats.js";
import type { RoundTripPathResult } from "../types.js";

const BUDGET_MS_P95 = 5;
const FIXED_ARGS = { ping: "pong" };

export async function benchCacheHitAllow(
  on: ProxyOnHarness,
  off: ProxyOffHarness,
  opts: MeasureOptions,
): Promise<RoundTripPathResult> {
  if (opts.warmupIterations < 1) {
    throw new Error(
      "benchCacheHitAllow: warmupIterations must be >= 1 so the one unavoidable cache-MISS (first call) is discarded before measurement",
    );
  }

  const onDurations = await measureAsync(async () => {
    const result = await on.client.callTool(ROUTINE_TOOL, FIXED_ARGS);
    if (result.isError) {
      throw new Error(
        "benchCacheHitAllow: unexpected denial on the proxy-ON path",
      );
    }
  }, opts);

  const offDurations = await measureAsync(async () => {
    await off.client.callTool(ROUTINE_TOOL, FIXED_ARGS);
  }, opts);

  const onStats = summarize(onDurations);
  const offStats = summarize(offDurations);
  return {
    path: "cache-hit-allow",
    budgetMsP95: BUDGET_MS_P95,
    on: onStats,
    off: offStats,
    added: subtractPercentiles(onStats, offStats),
    warmupIterations: opts.warmupIterations,
    measuredIterations: opts.measuredIterations,
  };
}
