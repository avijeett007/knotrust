/**
 * knotrust CLI `audit query --since <duration|timestamp>` — parsing (P0-E4-T4,
 * R122).
 *
 * Two accepted forms, tried in this order:
 *
 *   1. A human duration (`"1h"`, `"30d"`, `"1d12h"`, ...) — REUSES
 *      `../grant/duration.js`'s `parseDuration` (P0-E7-T2, R112) verbatim,
 *      rather than a second bespoke parser for the same "digits+unit tokens"
 *      grammar. Resolved RELATIVE TO NOW at command-run time.
 *   2. An absolute ISO 8601 / RFC 3339 timestamp (`Date.parse`-parseable),
 *      used as-is.
 *
 * Split into two pure steps, mirroring this package's own layering
 * discipline (`init/argv.ts`, `grant/argv.ts`): `parseSince` validates and
 * classifies the raw string with NO clock dependency at all (so argv
 * parsing — which has no injected clock — can validate `--since` eagerly and
 * fail with a clean usage error, exit 2, before any command body runs);
 * `resolveSinceEpochMs` does the (trivial) arithmetic against an
 * INJECTED "now" only once a `ParsedSince` is in hand. Neither function ever
 * throws.
 */

import { parseDuration } from "../grant/duration.js";

export type ParsedSince =
  | { kind: "duration"; seconds: number }
  | { kind: "timestamp"; epochMs: number };

export type ParseSinceResult =
  | { ok: true; parsed: ParsedSince }
  | { ok: false; error: string };

/**
 * Validates and classifies a raw `--since` value. Never throws. Tries the
 * E7-T2 duration grammar first (it is the common case — `--since 1h`); a
 * string that fails that AND doesn't parse as a timestamp is a single
 * combined usage error mentioning both accepted forms.
 */
export function parseSince(raw: string): ParseSinceResult {
  const duration = parseDuration(raw);
  if (duration.ok) {
    return {
      ok: true,
      parsed: { kind: "duration", seconds: duration.seconds },
    };
  }
  const epochMs = Date.parse(raw);
  if (!Number.isNaN(epochMs)) {
    return { ok: true, parsed: { kind: "timestamp", epochMs } };
  }
  return {
    ok: false,
    error:
      `invalid --since value ${JSON.stringify(raw)} — expected a duration ` +
      `(e.g. "1h", "30d", "1d12h") or an ISO 8601 timestamp ` +
      `(e.g. "2026-07-01T00:00:00.000Z")`,
  };
}

/** Resolves an already-validated `ParsedSince` into an absolute cutoff (epoch ms), relative to `nowEpochMs` for the `"duration"` kind. */
export function resolveSinceEpochMs(
  parsed: ParsedSince,
  nowEpochMs: number,
): number {
  return parsed.kind === "duration"
    ? nowEpochMs - parsed.seconds * 1000
    : parsed.epochMs;
}
