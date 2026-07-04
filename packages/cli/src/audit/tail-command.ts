/**
 * knotrust CLI `audit list` / `audit tail` (P0-E4-T4, R122) — both dispatch
 * here (see `argv.ts`'s and `render.ts`'s module headers for why they are
 * deliberate aliases).
 *
 * Consumes `@knotrust/store`'s `streamAuditEvents` (lock-free, O(chunk)
 * memory) through a bounded `RingBuffer` of size `args.limit` — O(limit)
 * memory regardless of how many total lines the log holds, the "flat
 * memory" half of R123 for this command.
 */

import type { Writable } from "node:stream";
import { resolveKnotrustHome } from "@knotrust/grants";
import { type AuditEvent, streamAuditEvents } from "@knotrust/store";
import type { AuditRecentArgs } from "./argv.js";
import { formatEventJsonLine, renderEventLines } from "./render.js";
import { createRingBuffer } from "./ring-buffer.js";

export interface AuditTailIo {
  stdout: Writable;
  stderr: Writable;
}

export interface AuditTailDeps {
  /** Defaults to `resolveKnotrustHome()`; injected in tests to a throwaway temp dir. */
  home?: string;
}

export function runAuditTail(
  io: AuditTailIo,
  args: AuditRecentArgs,
  deps: AuditTailDeps = {},
): number {
  const home = deps.home ?? resolveKnotrustHome();
  const ring = createRingBuffer<AuditEvent>(args.limit);
  let malformedCount = 0;

  for (const entry of streamAuditEvents(home)) {
    if (entry.event === undefined) {
      malformedCount++;
      continue;
    }
    ring.push(entry.event);
  }

  // A malformed/torn line is never silently invisible — same discipline as
  // `grant list`'s own "invalid grant file" stderr notice — but never
  // interferes with `--json`'s stdout (always stderr, both modes).
  if (malformedCount > 0) {
    io.stderr.write(
      `(${malformedCount} malformed/torn audit line(s) skipped — run ` +
        "`knotrust audit verify` to check chain integrity)\n",
    );
  }

  const events = ring.toArray();

  if (args.json) {
    for (const event of events) {
      io.stdout.write(`${formatEventJsonLine(event)}\n`);
    }
    return 0;
  }

  if (events.length === 0) {
    io.stdout.write("No audit events.\n");
    return 0;
  }

  io.stdout.write(`${renderEventLines(events)}\n`);
  return 0;
}
