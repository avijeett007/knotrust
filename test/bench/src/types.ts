/** @knotrust/bench — shared result shapes every path benchmark returns (P0-E9-T3). */
import type { AddedLatency, Percentiles } from "./stats.js";

/** Paths 1-3 (R150): a proxy-ON distribution, a proxy-OFF distribution, and their percentile-by-percentile delta (R151's "added latency"). */
export interface RoundTripPathResult {
  path: string;
  /** The ratified p95 budget for ADDED latency (docs/03-engineering/latency-budgets.md), in milliseconds. */
  budgetMsP95: number;
  on: Percentiles;
  off: Percentiles;
  added: AddedLatency;
  warmupIterations: number;
  measuredIterations: number;
}

/** Paths 4-5: no meaningful proxy-OFF baseline exists (an internal component cost / a spawn-readiness cost), so these are reported as an ABSOLUTE distribution, not a delta — see the doc's methodology section for the justification. */
export interface AbsolutePathResult {
  path: string;
  budgetMsP95: number;
  measured: Percentiles;
  warmupIterations: number;
  measuredIterations: number;
}

export type PathResult = RoundTripPathResult | AbsolutePathResult;

export function isRoundTripResult(
  result: PathResult,
): result is RoundTripPathResult {
  return "added" in result;
}
