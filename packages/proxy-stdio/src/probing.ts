/**
 * @knotrust/proxy-stdio — repeated-denial probing detector (P0-E5-T4, R78;
 * architecture §3.2: "repeated-denial patterns... are flagged in audit as a
 * `probe_flagged`/`denial_probing_suspected` event, so an injected 'keep
 * trying variations' strategy is visible to the human even though each
 * individual denial stays terse").
 *
 * `enforce.ts` consults this on every rejected `tools/call` (deny,
 * pending_approval, and deferred_not_eligible alike — from the calling
 * agent's point of view, all three are "my call did not go through," and a
 * probing/injection attempt does not care which technical outcome it hits).
 * This is a SLIDING-WINDOW counter, keyed by `(tool, agent)`, using an
 * injected clock (never `Date.now()`, matching this codebase's convention
 * everywhere else a clock is a dependency) so tests are deterministic.
 *
 * ## Fire-once, then reset (never spam)
 *
 * `recordDenial` returns `true` exactly on the call that CROSSES the
 * threshold (default: the 5th denial for a pair within 60s) — R78 requires
 * this to happen ONCE per burst, not on every subsequent denial once the
 * pair is already "hot." The implementation resets the pair's window
 * entirely the instant it fires: the next denial for that pair starts
 * counting from zero again, requiring a FULL new threshold's worth within a
 * FULL new window before firing again. This is a deliberate, simple
 * "debounce by resetting" policy — not a rolling window that would fire on
 * every single denial once primed — chosen because R78's own acceptance
 * ("exactly one probing event" for a burst of exactly `threshold` denials)
 * is unambiguous about the fire-once behavior for the common case, and
 * "reset, then require a fresh full burst" is the simplest rule that
 * satisfies it without any risk of firing twice for one burst.
 *
 * ## Audit-only — never changes what the model sees (R78)
 *
 * This module has ZERO connection to `denial-envelope.ts`. It only reports
 * `true`/`false` to its caller, which uses that boolean SOLELY to decide
 * whether to also append a `denial_probing_suspected` audit event — the
 * model-visible envelope for the Nth denial is built by the exact same
 * `buildDenialEnvelope` call as the 1st, with the exact same inputs. If
 * probing detection ever influenced the envelope itself, that would leak
 * the fence's shape to precisely the pattern-of-behavior most likely to be
 * an attacker probing it — the one thing this whole design must not do.
 *
 * ## Bounded memory (fix round 1)
 *
 * The ORIGINAL implementation only ever deleted a `(tool, agent)` key from
 * `windows` when it FIRED (crossed the threshold). A pair denied 1..
 * `threshold - 1` times and then never seen again — the common case for a
 * hostile server varying the tool name on every call (`x0`, `x1`, `x2`, ...
 * paired with the same agent, each denied once, never reaching the
 * threshold) — was retained in the Map FOREVER: unbounded memory growth
 * from a trivially cheap-to-mount flood, AND a flood that (by construction)
 * never crosses the threshold also never gets flagged in audit either. Two
 * independent fixes close this:
 *
 *   1. **Empty-window eviction.** Every `recordDenial` call now sweeps the
 *      WHOLE map first: for every tracked pair, timestamps are re-filtered
 *      to the live window, and a pair whose filtered window comes back
 *      EMPTY (every one of its denials has aged out, and it hasn't been
 *      denied again since) is deleted outright — its Map entry is not left
 *      behind as a stale empty array. This piggybacks on the clock this
 *      module already threads through every call, so no timer/background
 *      task is introduced — the very next call (for ANY pair, not
 *      necessarily the stale one) prunes it. The sweep cost is bounded by
 *      `MAX_TRACKED_PAIRS` (below), so it never grows unbounded either.
 *   2. **Hard cap + oldest-touched eviction.** `windows` never exceeds
 *      `MAX_TRACKED_PAIRS` entries. Every touch (read-then-write) of a key
 *      moves it to the END of the Map's iteration order (a `delete` then
 *      `set` — `Map.set` on an ALREADY-PRESENT key does not reorder it on
 *      its own, so the delete-then-set is what makes iteration order double
 *      as recency-of-touch order). When a touch pushes the map size over
 *      the cap, the FIRST key in iteration order — the least-recently-
 *      touched pair — is evicted. This guarantees a flood of distinct tool
 *      names (which defeats fix #1's empty-window sweep, since a
 *      never-repeated name's single-entry window is never actually empty
 *      until a FULL `windowMs` has elapsed) still cannot grow the Map
 *      without bound: it is capped, full stop.
 *
 * Both fixes preserve the fire-once-per-threshold-crossing behavior and
 * per-`(tool, agent)` isolation for the NORMAL (under-cap) case documented
 * above and exercised by the tests below. Empty-window eviction (#1) NEVER
 * discards an in-progress count: by construction it only ever removes a
 * pair whose live window is already empty, so it can never cause a
 * spuriously suppressed fire. Cap eviction (#2) is a coarser, deliberately
 * simple safety valve: under sustained pressure from `MAX_TRACKED_PAIRS`
 * (or more) DISTINCT concurrently-live pairs, it CAN evict a pair's
 * in-progress (non-empty, under-threshold) count if that pair happens to be
 * the least-recently-touched when the cap is hit. This is an accepted
 * trade-off — bounded memory over perfect counting continuity during an
 * already-anomalous flood of that scale — and it can only ever cause a
 * false NEGATIVE (a reset-early count), never a false positive/spurious
 * fire: eviction always resets a count to "not yet counted," never
 * fabricates progress toward the threshold.
 */

export interface ProbingDetectorOptions {
  /** Injected millisecond clock. Never `Date.now()` internally. */
  nowMs: () => number;
  /** Sliding window width in ms. Default 60_000 (60s, matching the plan acceptance). */
  windowMs?: number;
  /** Denials within the window that cross the threshold. Default 5 (matching the plan acceptance). */
  threshold?: number;
  /**
   * Fix round 1 (bounded memory): the max number of distinct `(tool, agent)`
   * pairs tracked at once. Default `MAX_TRACKED_PAIRS` (4096). Overridable so
   * tests can exercise cap-eviction without allocating thousands of entries.
   */
  maxTrackedPairs?: number;
}

export interface ProbingDetector {
  /**
   * Records one denial for `(tool, agent)`. Returns `true` exactly on the
   * call that crosses the threshold (and resets that pair's window so the
   * NEXT `threshold` denials, in a fresh window, are needed to fire again);
   * returns `false` otherwise, including on every call after a fire until
   * the pair re-crosses the threshold.
   */
  recordDenial(tool: string, agent: string): boolean;
  /**
   * Number of distinct `(tool, agent)` pairs currently tracked. Fix round 1
   * (bounded memory): exposed purely for tests/observability into the
   * empty-window-eviction and cap-eviction guarantees documented in this
   * module's header — `enforce.ts`'s enforcement path never consults this.
   */
  trackedPairCount(): number;
}

/** Default sliding-window width (60s) — exported so callers building the audit-event `reason` string can quote the ACTUAL configured value rather than re-hardcoding it. */
export const DEFAULT_PROBING_WINDOW_MS = 60_000;
/** Default threshold (5 denials) — see `DEFAULT_PROBING_WINDOW_MS`'s doc comment. */
export const DEFAULT_PROBING_THRESHOLD = 5;
/**
 * Default hard cap on distinct tracked `(tool, agent)` pairs (fix round 1;
 * see module header's "Bounded memory" section). Exported for the same
 * reason as the two constants above.
 */
export const DEFAULT_MAX_TRACKED_PAIRS = 4096;

function keyOf(tool: string, agent: string): string {
  // A NUL separator can't appear in either a tool name or an agent id under
  // normal operation, and even if a hostile tool name contained one, the
  // worst case is two DIFFERENT pairs sharing one counter (a false
  // negative on independent tracking) — never a crash, never a
  // model-visible effect either way (this module is audit-only, R78).
  return `${tool}\0${agent}`;
}

export function createProbingDetector(
  opts: ProbingDetectorOptions,
): ProbingDetector {
  const { nowMs } = opts;
  const windowMs = opts.windowMs ?? DEFAULT_PROBING_WINDOW_MS;
  const threshold = opts.threshold ?? DEFAULT_PROBING_THRESHOLD;
  const maxTrackedPairs = opts.maxTrackedPairs ?? DEFAULT_MAX_TRACKED_PAIRS;

  const windows = new Map<string, number[]>();

  /**
   * Fix round 1, eviction #1 ("empty-window eviction" — see module header):
   * re-filters EVERY tracked pair's timestamps down to the live window and
   * drops any pair whose live window comes back empty. Run at the start of
   * every `recordDenial` call (for any pair, not just the one being
   * recorded) so a pair denied under the threshold and then never touched
   * again is reclaimed the next time ANYTHING calls in, rather than sitting
   * in the Map forever. Cost is bounded by the current map size, which
   * itself never exceeds `maxTrackedPairs` (eviction #2, below) — so this
   * sweep can never grow unbounded either.
   */
  function sweepExpired(now: number): void {
    for (const [k, timestamps] of windows) {
      const live = timestamps.filter((ts) => now - ts < windowMs);
      if (live.length === 0) {
        windows.delete(k);
      } else if (live.length !== timestamps.length) {
        windows.set(k, live);
      }
    }
  }

  /**
   * Moves `key` to the END of the Map's iteration order. `Map.set` on an
   * ALREADY-PRESENT key updates its value WITHOUT reordering it, so the
   * delete-then-set is what makes iteration order double as
   * recency-of-touch order — required for eviction #2's "drop the
   * oldest-touched entry" (the Map's FIRST key) to actually mean
   * least-recently-touched, not just least-recently-inserted.
   */
  function touch(key: string, value: number[]): void {
    windows.delete(key);
    windows.set(key, value);
  }

  return {
    recordDenial(tool: string, agent: string): boolean {
      const now = nowMs();
      sweepExpired(now);

      const key = keyOf(tool, agent);
      const existing = windows.get(key) ?? [];
      const withinWindow = existing.filter((ts) => now - ts < windowMs);
      withinWindow.push(now);

      if (withinWindow.length >= threshold) {
        windows.delete(key); // reset — see module header ("fire-once, then reset").
        return true;
      }

      touch(key, withinWindow);

      // Fix round 1, eviction #2 ("hard cap + oldest-touched eviction" —
      // see module header): a flood of DISTINCT pairs (each under the
      // threshold, so eviction #1 above never fires for them individually
      // until a full `windowMs` has elapsed) is still bounded because the
      // Map itself is capped here.
      if (windows.size > maxTrackedPairs) {
        const oldest = windows.keys().next().value;
        if (oldest !== undefined) {
          windows.delete(oldest);
        }
      }

      return false;
    },
    trackedPairCount(): number {
      return windows.size;
    },
  };
}
