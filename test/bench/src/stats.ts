/**
 * @knotrust/bench — percentile/summary statistics (P0-E9-T3, rulings R150-R152).
 *
 * Pure math, no I/O — kept separate from the timing/measurement code
 * (`iterate.ts`) and the path benchmarks so it is independently unit-testable
 * (see `stats.test.ts`) and so the exact percentile METHOD is documented in
 * ONE place `docs/03-engineering/latency-budgets.md` can point at verbatim.
 *
 * ## Percentile method (R151 — "state precisely what the harness times")
 *
 * Nearest-rank, over the ascending-sorted sample: for a percentile `p` and
 * `n` samples, the rank is `ceil(p/100 * n)` (1-indexed), clamped into
 * `[1, n]`. This is the same method most `p95`/`p99` latency tooling uses
 * (no interpolation between neighboring samples) — simple, deterministic,
 * and never fabricates a value that wasn't actually observed.
 */

export interface Percentiles {
  p50: number;
  p95: number;
  p99: number;
  mean: number;
  min: number;
  max: number;
  /** Sample count this summary was computed over (post warm-up). */
  count: number;
}

/**
 * Nearest-rank percentile of an ALREADY ascending-sorted array. `p` is in
 * `[0, 100]`. Throws on an empty array — a percentile of zero samples is not
 * a number, and silently returning `NaN` here would let a bug (e.g. an
 * accidentally-skipped measurement loop) masquerade as a real "0ms" result
 * downstream.
 */
export function percentileOfSorted(
  sortedAsc: readonly number[],
  p: number,
): number {
  if (sortedAsc.length === 0) {
    throw new Error(
      "percentileOfSorted: cannot compute a percentile of zero samples",
    );
  }
  if (!(p >= 0 && p <= 100)) {
    throw new Error(
      `percentileOfSorted: p must be in [0, 100], got ${String(p)}`,
    );
  }
  const rank = Math.ceil((p / 100) * sortedAsc.length);
  const index = Math.min(sortedAsc.length, Math.max(1, rank)) - 1;
  const value = sortedAsc[index];
  if (value === undefined) {
    throw new Error("percentileOfSorted: unreachable — index out of bounds");
  }
  return value;
}

/** Summarizes a raw (unsorted) sample of millisecond durations into p50/p95/p99/mean/min/max. */
export function summarize(durationsMs: readonly number[]): Percentiles {
  if (durationsMs.length === 0) {
    throw new Error("summarize: cannot summarize zero samples");
  }
  const sorted = [...durationsMs].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const first = sorted[0];
  const last = sorted[sorted.length - 1];
  if (first === undefined || last === undefined) {
    throw new Error("summarize: unreachable — empty after sort");
  }
  return {
    p50: percentileOfSorted(sorted, 50),
    p95: percentileOfSorted(sorted, 95),
    p99: percentileOfSorted(sorted, 99),
    mean: sum / sorted.length,
    min: first,
    max: last,
    count: sorted.length,
  };
}

/** The three percentiles of `on` minus the corresponding percentile of `off` — the R151 "added latency" delta, keyed percentile-by-percentile (NOT a per-iteration pairwise subtraction — see module header / the doc's methodology section for why). */
export interface AddedLatency {
  p50: number;
  p95: number;
  p99: number;
}

export function subtractPercentiles(
  on: Percentiles,
  off: Percentiles,
): AddedLatency {
  return {
    p50: on.p50 - off.p50,
    p95: on.p95 - off.p95,
    p99: on.p99 - off.p99,
  };
}
