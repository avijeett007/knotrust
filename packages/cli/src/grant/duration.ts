/**
 * knotrust CLI `grant` — human duration parsing (P0-E7-T2, R112).
 *
 * `--expires <duration>` accepts a sequence of one or more `<digits><unit>`
 * tokens, back to back, with NO separator between them: `"30d"`, `"12h"`,
 * `"90m"`, `"1w"`, and combinations like `"1d12h"` (1 day + 12 hours). Units:
 * `w` (week, 7d), `d` (day), `h` (hour), `m` (minute), `s` (second). Every
 * token contributes its own seconds; the total is the sum. This is a pure,
 * total function — it NEVER throws (mirrors this package's `init/argv.ts`
 * convention for user-supplied argv values: a bad string is a returned
 * `{ ok: false, error }`, never an exception) so a malformed `--expires`
 * value is always R112's "clean error", not a raw stack.
 *
 * Deliberately simple, not a full ISO-8601 duration parser: this is what a
 * human types at a terminal, not a wire format.
 */

const UNIT_SECONDS: Record<string, number> = {
  w: 604_800,
  d: 86_400,
  h: 3_600,
  m: 60,
  s: 1,
};

/** One `<digits><unit>` token, anchored to the start of whatever remains unconsumed. */
const TOKEN = /^(\d+)([wdhms])/;

export type ParseDurationResult =
  | { ok: true; seconds: number }
  | { ok: false; error: string };

const USAGE_HINT =
  'expected one or more digit+unit tokens (w=week, d=day, h=hour, m=minute, s=second), e.g. "30d", "12h", "90m", "1w", or a combination like "1d12h"';

function invalid(input: string): ParseDurationResult {
  return {
    ok: false,
    error: `invalid duration ${JSON.stringify(input)} — ${USAGE_HINT}`,
  };
}

/**
 * Parses a human duration string into a whole number of seconds. Rejects
 * (never throws): an empty/blank string, any character sequence that isn't
 * entirely digit+unit tokens back to back (trailing garbage, a bare number
 * with no unit, a negative sign, an unknown unit letter), and a total of
 * zero or fewer seconds (a `--expires 0d` grant would be born already
 * expired — not a useful duration, so it is rejected the same as any other
 * malformed input rather than silently producing a dead-on-arrival grant).
 */
export function parseDuration(input: string): ParseDurationResult {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    return invalid(input);
  }

  let rest = trimmed;
  let totalSeconds = 0;

  while (rest.length > 0) {
    const match = TOKEN.exec(rest);
    if (match === null) {
      return invalid(input);
    }
    const [full, digits, unit] = match;
    const value = Number(digits);
    if (!Number.isSafeInteger(value)) {
      return invalid(input);
    }
    const unitSeconds = UNIT_SECONDS[unit as keyof typeof UNIT_SECONDS];
    if (unitSeconds === undefined) {
      // Unreachable given TOKEN's `[wdhms]` character class, but
      // `noUncheckedIndexedAccess` cannot see that — a narrow, honest guard
      // beats an unsafe assertion.
      return invalid(input);
    }
    totalSeconds += value * unitSeconds;
    if (!Number.isSafeInteger(totalSeconds)) {
      return invalid(input);
    }
    rest = rest.slice(full.length);
  }

  if (totalSeconds <= 0) {
    return invalid(input);
  }

  return { ok: true, seconds: totalSeconds };
}
