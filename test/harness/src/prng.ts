/**
 * @knotrust/test-harness — seeded, deterministic PRNG (P0-E11-T1, R54 ruling 4).
 *
 * "Chaos" behavior in the fake MCP server (random per-call delays, jittered
 * notification interleaving) must be reproducible: a failing chaos-profile
 * iteration has to be re-runnable from its logged seed, not shrugged off as
 * flaky. `Math.random()` is therefore banned from every chaos-adjacent code
 * path in this package — every "random" decision consumes this injected,
 * seed-constructed generator instead.
 *
 * Algorithm: mulberry32 (public domain, Tommy Ettinger). It is not
 * cryptographically secure and must never be used for anything security-
 * relevant — this package is test infrastructure only, and the one property
 * that matters here is: same seed in ⇒ identical sequence out, forever,
 * across Node versions and platforms (pure 32-bit integer arithmetic, no
 * platform-dependent floating point tricks beyond the final division).
 */

export interface SeededPrng {
  /** The seed this generator was constructed from (log this on failure). */
  readonly seed: number;
  /** Next pseudo-random float in [0, 1). */
  next(): number;
  /** Next pseudo-random integer in [min, max] inclusive. Requires min <= max. */
  nextInt(min: number, max: number): number;
  /** Picks a pseudo-random element from a non-empty array. */
  pick<T>(items: readonly T[]): T;
}

/**
 * Constructs a deterministic PRNG from a 32-bit integer seed. Two generators
 * constructed from the same seed always produce the same sequence.
 */
export function createSeededPrng(seed: number): SeededPrng {
  // mulberry32 state must be a 32-bit unsigned int; coerce defensively so
  // callers passing e.g. `Date.now()`-derived seeds (for a *documented*
  // pseudo-random top-level seed pick — never inside a chaos loop itself)
  // still get a valid, reproducible generator.
  let state = seed >>> 0;

  function nextRaw(): number {
    state = (state + 0x6d2b79f5) | 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  return {
    seed,
    next: nextRaw,
    nextInt(min: number, max: number): number {
      if (max < min) {
        throw new RangeError(`nextInt: max (${max}) must be >= min (${min})`);
      }
      return min + Math.floor(nextRaw() * (max - min + 1));
    },
    pick<T>(items: readonly T[]): T {
      if (items.length === 0) {
        throw new RangeError("pick: items must be non-empty");
      }
      const idx = Math.floor(nextRaw() * items.length);
      // noUncheckedIndexedAccess: idx is always < items.length by construction.
      return items[Math.min(idx, items.length - 1)] as T;
    },
  };
}
