/**
 * @knotrust/bench — Path 2: cache-miss L0 eval + one grant verify. Budget:
 * added p95 ≤ 15ms (R150 bullet 2).
 *
 * `SENSITIVE_TOOL` is called with a FRESH `callId` argument every iteration
 * (`getMapping` maps `resource.id` to `arguments.callId` — see
 * `fixtures/policy.ts`), so every call's decision-cache key is distinct: a
 * GUARANTEED miss, every iteration, warm-up included (no "first call primes
 * the cache" effect to absorb here, unlike path 1). The proxy-ON harness
 * minted exactly one durable grant scoped `idPattern: "call-*"`
 * (`fixtures/proxy-on.ts`), so each miss runs the real
 * collect-covering-grants → precedence → ONE real Ed25519 `verifyGrant` →
 * allow path (`@knotrust/grants`' `createDecider`/`decideCore`).
 */

import { SENSITIVE_TOOL } from "../fixtures/policy.js";
import type { ProxyOffHarness } from "../fixtures/proxy-off.js";
import type { ProxyOnHarness } from "../fixtures/proxy-on.js";
import { type MeasureOptions, measureAsync } from "../iterate.js";
import { subtractPercentiles, summarize } from "../stats.js";
import type { RoundTripPathResult } from "../types.js";

const BUDGET_MS_P95 = 15;

export async function benchCacheMissGrantVerify(
  on: ProxyOnHarness,
  off: ProxyOffHarness,
  opts: MeasureOptions,
): Promise<RoundTripPathResult> {
  let onCounter = 0;
  const onDurations = await measureAsync(async () => {
    onCounter += 1;
    const result = await on.client.callTool(SENSITIVE_TOOL, {
      callId: `call-on-${onCounter}`,
    });
    if (result.isError) {
      throw new Error(
        `benchCacheMissGrantVerify: unexpected denial on the proxy-ON path: ${JSON.stringify(result.content)}`,
      );
    }
  }, opts);

  let offCounter = 0;
  const offDurations = await measureAsync(async () => {
    offCounter += 1;
    await off.client.callTool(SENSITIVE_TOOL, {
      callId: `call-off-${offCounter}`,
    });
  }, opts);

  const onStats = summarize(onDurations);
  const offStats = summarize(offDurations);
  return {
    path: "cache-miss-l0-eval-plus-grant-verify",
    budgetMsP95: BUDGET_MS_P95,
    on: onStats,
    off: offStats,
    added: subtractPercentiles(onStats, offStats),
    warmupIterations: opts.warmupIterations,
    measuredIterations: opts.measuredIterations,
  };
}
