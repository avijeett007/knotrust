/**
 * @knotrust/bench — the timing loop (P0-E9-T3, R150/R151).
 *
 * ONE generic "warm up, then measure" runner every path benchmark uses, so
 * the warm-up/measured split and the wall-clock instrument
 * (`performance.now()`, monotonic, sub-millisecond resolution) are identical
 * across all 5 paths — a reader checking the methodology only needs to read
 * this file once. `fn` is called sequentially and awaited (never
 * parallelized): a real MCP client sends one call, awaits the response, then
 * sends the next — parallelizing would change what's being measured
 * (queueing/concurrency effects, not per-call latency).
 */

export interface MeasureOptions {
  /** Iterations run and DISCARDED before measurement starts (JIT/connection warm-up, R150 "warm process"). */
  warmupIterations: number;
  /** Iterations actually timed and returned. */
  measuredIterations: number;
}

/**
 * Runs `fn` `warmupIterations` times (discarded), then `measuredIterations`
 * more times, timing each with `performance.now()` immediately before/after
 * the awaited call. Returns exactly `measuredIterations` millisecond
 * durations, in the order they ran (NOT sorted — callers needing percentiles
 * use `stats.ts`'s `summarize`).
 */
export async function measureAsync(
  fn: () => Promise<void>,
  opts: MeasureOptions,
): Promise<number[]> {
  for (let i = 0; i < opts.warmupIterations; i++) {
    await fn();
  }
  const durationsMs: number[] = [];
  for (let i = 0; i < opts.measuredIterations; i++) {
    const startMs = performance.now();
    await fn();
    durationsMs.push(performance.now() - startMs);
  }
  return durationsMs;
}

/**
 * Same warm-up/measured split as {@link measureAsync}, but for a path whose
 * timed window is a SUBSET of what one iteration has to do (e.g.
 * "proxy-ready-to-serve": per-iteration setup spawns a fresh fake server and
 * teardown reaps it, but only the spawn→first-response span should count).
 * `fn` does its own setup/timed-span/teardown and returns the span's
 * duration in milliseconds directly — this loop only owns iteration counts,
 * never the clock.
 */
export async function measureAsyncSelfTimed(
  fn: () => Promise<number>,
  opts: MeasureOptions,
): Promise<number[]> {
  for (let i = 0; i < opts.warmupIterations; i++) {
    await fn();
  }
  const durationsMs: number[] = [];
  for (let i = 0; i < opts.measuredIterations; i++) {
    durationsMs.push(await fn());
  }
  return durationsMs;
}
