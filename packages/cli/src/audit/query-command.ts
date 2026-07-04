/**
 * knotrust CLI `audit query` (P0-E4-T4, R122/R123/R124) — streams
 * `@knotrust/store`'s lock-free `streamAuditEvents`, applies the AND-composed
 * filter set (`filters.ts`), and prints each match AS IT IS FOUND — no
 * buffering of the result set, which is what keeps this command flat-memory
 * even when many rows match a large log (see `render.ts`'s module header
 * for why this rules out a globally-column-aligned table).
 */

import type { Writable } from "node:stream";
import { resolveKnotrustHome } from "@knotrust/grants";
import { streamAuditEvents } from "@knotrust/store";
import type { AuditQueryArgs } from "./argv.js";
import { type AuditQueryFilters, matchesFilters } from "./filters.js";
import { formatEventJsonLine, formatEventLine } from "./render.js";
import { resolveSinceEpochMs } from "./since.js";

export interface AuditQueryIo {
  stdout: Writable;
  stderr: Writable;
}

export interface AuditQueryDeps {
  /** Defaults to `resolveKnotrustHome()`; injected in tests to a throwaway temp dir. */
  home?: string;
  /** Injected "now" for resolving a `--since <duration>` into an absolute cutoff (R122). Defaults to `Date.now()`. */
  nowEpochMs?: () => number;
}

function buildFilters(
  args: AuditQueryArgs,
  nowEpochMs: () => number,
): AuditQueryFilters {
  return {
    ...(args.tool !== undefined ? { tool: args.tool } : {}),
    ...(args.outcome !== undefined ? { outcome: args.outcome } : {}),
    ...(args.tier !== undefined ? { tier: args.tier } : {}),
    ...(args.since !== undefined
      ? { sinceEpochMs: resolveSinceEpochMs(args.since, nowEpochMs()) }
      : {}),
    ...(args.agent !== undefined ? { agent: args.agent } : {}),
    ...(args.server !== undefined ? { server: args.server } : {}),
  };
}

export function runAuditQuery(
  io: AuditQueryIo,
  args: AuditQueryArgs,
  deps: AuditQueryDeps = {},
): number {
  const home = deps.home ?? resolveKnotrustHome();
  const nowEpochMs = deps.nowEpochMs ?? (() => Date.now());
  const filters = buildFilters(args, nowEpochMs);

  let malformedCount = 0;
  let matched = 0;

  for (const entry of streamAuditEvents(home)) {
    if (entry.event === undefined) {
      malformedCount++;
      continue;
    }
    if (!matchesFilters(entry.event, filters)) continue;
    matched++;
    io.stdout.write(
      args.json
        ? `${formatEventJsonLine(entry.event)}\n`
        : `${formatEventLine(entry.event)}\n`,
    );
  }

  if (malformedCount > 0) {
    io.stderr.write(
      `(${malformedCount} malformed/torn audit line(s) skipped — run ` +
        "`knotrust audit verify` to check chain integrity)\n",
    );
  }

  if (matched === 0 && !args.json) {
    io.stdout.write("No matching audit events.\n");
  }

  return 0;
}
