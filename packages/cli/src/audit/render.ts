/**
 * knotrust CLI `audit list|tail|query` — row rendering (P0-E4-T4, R122).
 *
 * ## Output-format choices (R122: "pick, document")
 *
 * - **`--json` is NEWLINE-DELIMITED JSON (NDJSON), not a single JSON
 *   array**, across all three of `list`/`tail`/`query` — one raw, unmodified
 *   `AuditEvent` object per line (R125: "the stored event shape... no added
 *   secrets"). This is the streaming-safe choice (R123): a JSON array needs
 *   the WHOLE result set buffered before the closing `]` can be printed;
 *   NDJSON prints each match the instant it's found, which is what lets
 *   `query` stay flat-memory over an arbitrarily large log. It is also the
 *   more common scripting convention for this shape of tool (`jq -c`, one
 *   object per line).
 *
 * - **Human (non-JSON) rows are ONE COMPACT LINE each**, not a
 *   column-aligned table with a header. `list`/`tail` bound their working
 *   set to `-n` events (default 50) before printing, so a real
 *   dynamically-aligned table (column widths computed from the actual rows,
 *   like `grant list`'s `renderTable`) WOULD be memory-safe there — but
 *   `query` streams and prints as it matches, with no upper bound on match
 *   count against a large log, so computing global column widths would mean
 *   buffering every match first, defeating R123's flat-memory mandate for
 *   the one command most likely to have many matches. Rather than give
 *   `query` a different visual shape than `list`/`tail`, all three share
 *   this ONE streaming-safe compact-line format — `key=value` fields so it
 *   stays greppable/awk-able even in "human" mode, similar in spirit to
 *   `journalctl`/`docker logs`/`kubectl get events` compact output.
 *
 * - **`list`/`tail` display order is chronological ascending — oldest of
 *   the retained window first, newest last** (R122: "newest-last or
 *   newest-first (pick, document)"). This matches Unix `tail`'s own
 *   familiar behavior: the last N lines, printed in their original order,
 *   with the very latest at the bottom of the terminal.
 */

import type { AuditEvent } from "@knotrust/store";

/** NDJSON: exactly the stored event, one per line — never a derived/lossy row shape (R125). */
export function formatEventJsonLine(event: AuditEvent): string {
  return JSON.stringify(event);
}

/**
 * The shared compact human line: `<ts> seq=<seq> type=<type>
 * outcome=<outcome|-> tool=<tool> agent=<agent> argsHash=<argsHash>[
 * reason=<reason>][ grants=<jti,jti,...>]`. Optional fields are omitted
 * entirely when absent (never printed as a literal `"undefined"`).
 * `argsHash` (M3, R125 follow-up) is always present — it's a mandatory
 * field on every `AuditEvent` (`"sha256:" + hex` or the literal
 * `"unavailable"`, never raw arguments) — surfaced here for forensic
 * completeness alongside `--json`, which already includes it. Raw
 * arguments themselves stay OFF in this human line; they only ever appear
 * in the stored event at all when the sink was constructed with
 * `captureRawArgs: true`, and even then this compact line never echoes
 * them.
 */
export function formatEventLine(event: AuditEvent): string {
  const parts = [
    event.ts,
    `seq=${event.seq}`,
    `type=${event.type}`,
    `outcome=${event.outcome ?? "-"}`,
    `tool=${event.tool}`,
    `agent=${event.agent}`,
    `argsHash=${event.argsHash}`,
  ];
  if (event.reason !== undefined) parts.push(`reason=${event.reason}`);
  if (event.grantRefs !== undefined && event.grantRefs.length > 0) {
    parts.push(`grants=${event.grantRefs.join(",")}`);
  }
  return parts.join(" ");
}

/** Renders a bounded set of events (`list`/`tail`'s `-n`-limited window) as human text, one line each, in the array's own order. */
export function renderEventLines(events: readonly AuditEvent[]): string {
  return events.map(formatEventLine).join("\n");
}
