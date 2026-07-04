/**
 * @knotrust/test-harness — call-log stderr sideband (P0-E11-T1, R54).
 *
 * `callLog` (R54: "records every `tools/call` the server actually
 * RECEIVED") is a live in-memory array in in-process mode — the test and
 * the server share a process, so a direct array reference works. In
 * child-process mode there is no shared memory, so the fake server instead
 * writes one JSON line per received call to its OWN stderr (which the
 * architecture already treats as an arbitrary-logging channel the parent
 * process/proxy passes straight through — architecture §4.1). A caller that
 * spawned the child itself and captured its stderr can recover the same
 * log with `parseCallLogFromStderr`.
 *
 * Every line is prefixed with `CALL_LOG_STDERR_MARKER` so a stderr stream
 * that ALSO carries the wrapped process's own free-form logging (the
 * realistic case once E5 wraps a real server) can still find just the
 * call-log lines without false-matching arbitrary text.
 */

import { CALL_LOG_STDERR_MARKER, type CallLogEntry } from "./types.js";

/** Formats one call-log entry as a single stderr line (no embedded newlines). */
export function formatCallLogLine(entry: CallLogEntry): string {
  return `${CALL_LOG_STDERR_MARKER}${JSON.stringify(entry)}`;
}

/**
 * Extracts every call-log entry from a chunk of captured stderr text. Lines
 * that don't carry the marker (the wrapped server's own arbitrary logging)
 * are ignored, not errored on — this must degrade gracefully once E5 wraps
 * a real, noisier server.
 */
export function parseCallLogFromStderr(stderrText: string): CallLogEntry[] {
  const entries: CallLogEntry[] = [];
  for (const line of stderrText.split("\n")) {
    if (!line.startsWith(CALL_LOG_STDERR_MARKER)) {
      continue;
    }
    const jsonPart = line.slice(CALL_LOG_STDERR_MARKER.length);
    try {
      entries.push(JSON.parse(jsonPart) as CallLogEntry);
    } catch {
      // Malformed/truncated line (e.g. stderr chunk split mid-write) — skip
      // rather than throw, since this is best-effort introspection, not the
      // call log of record (that's the in-process array, or the child's
      // own stdout/stderr for anyone who needs perfect fidelity).
    }
  }
  return entries;
}
