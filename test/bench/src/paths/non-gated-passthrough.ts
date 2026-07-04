/**
 * @knotrust/bench — Path 3: non-gated message passthrough (list/progress/
 * etc.). Budget: added p95 ≤ 10ms (R150 bullet 3).
 *
 * A `tools/list` request — a non-`tools/call` message — relayed through the
 * proxy's SYNCHRONOUS classify→forward path (`proxy.ts`'s `relay()`): the
 * async enforcement seam only ever intercepts `tools/call` requests, so this
 * path never touches the decider/cache/grants at all, exactly as
 * `createStdioProxy`'s own module header describes for "every other
 * message."
 */
import type { ProxyOffHarness } from "../fixtures/proxy-off.js";
import type { ProxyOnHarness } from "../fixtures/proxy-on.js";
import { type MeasureOptions, measureAsync } from "../iterate.js";
import { subtractPercentiles, summarize } from "../stats.js";
import type { RoundTripPathResult } from "../types.js";

const BUDGET_MS_P95 = 10;

export async function benchNonGatedPassthrough(
  on: ProxyOnHarness,
  off: ProxyOffHarness,
  opts: MeasureOptions,
): Promise<RoundTripPathResult> {
  const onDurations = await measureAsync(async () => {
    await on.client.listToolsPage();
  }, opts);

  const offDurations = await measureAsync(async () => {
    await off.client.listToolsPage();
  }, opts);

  const onStats = summarize(onDurations);
  const offStats = summarize(offDurations);
  return {
    path: "non-gated-passthrough",
    budgetMsP95: BUDGET_MS_P95,
    on: onStats,
    off: offStats,
    added: subtractPercentiles(onStats, offStats),
    warmupIterations: opts.warmupIterations,
    measuredIterations: opts.measuredIterations,
  };
}
