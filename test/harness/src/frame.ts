/**
 * @knotrust/test-harness — the frame transcript (P0-E11-T1, R55 ruling 3).
 *
 * A `Frame` is one raw JSON-RPC message observed crossing the wire in one
 * direction, on the fake client's end of a conversation. The fake client
 * (`fake-client/client.ts`) appends every message it sends and every message
 * it receives to an ordered `frames` array, unconditionally — independent of
 * whatever request/response routing logic layers on top. This is the
 * frame-scan substrate later tasks reuse verbatim:
 *
 * - P0-E5-T1's "byte-comparable with and without the proxy" acceptance diffs
 *   two transcripts.
 * - P0-E5-T4/E11's global assertion ("no approval token or policy internals
 *   in any model-visible content") is a `scanFrames` predicate over the
 *   `direction: "recv"` subset.
 * - P0-E6-T2's progress-heartbeat assertion filters frames down to
 *   `notifications/progress` messages related to one request id.
 *
 * Deliberately dumb: a `Frame` is exactly the JSON-RPC message plus a
 * direction and a monotonic timestamp — no interpretation, no schema
 * validation (that already happened, or didn't, at the transport/protocol
 * layer; this module's job is to preserve what was actually observed, warts
 * included, since a malformed or lying frame is precisely what several
 * downstream adversarial tests need to see).
 */

/** Which way a frame crossed the wire, from the fake client's point of view. */
export type FrameDirection = "sent" | "recv";

/**
 * One JSON-RPC message observed on the wire. `message` is intentionally
 * `unknown`-shaped (not typed against the MCP SDK's Zod-inferred unions):
 * frames must be capturable even when they are malformed, oversized, or
 * otherwise don't parse as a valid MCP message — that's the whole point for
 * the adversarial suites this substrate feeds.
 */
export interface Frame {
  /** Monotonic sequence number within one client's transcript, starting at 0. */
  readonly seq: number;
  readonly direction: FrameDirection;
  /** `performance.now()`-relative milliseconds at capture time (monotonic, not wall-clock). */
  readonly atMs: number;
  readonly message: unknown;
}

/**
 * Filters a transcript down to frames matching `predicate`. A thin wrapper
 * over `Array.prototype.filter`, but named and exported so downstream test
 * suites read as "scan the frames for X" rather than reimplementing the
 * same filter/find boilerplate at every call site (R55: "Assertions are
 * helper methods, not bare expects, so downstream suites read cleanly").
 */
export function scanFrames(
  frames: readonly Frame[],
  predicate: (frame: Frame) => boolean,
): Frame[] {
  return frames.filter(predicate);
}

/** True if `message` is a JSON-RPC request or notification for the given method. */
export function isMethod(message: unknown, method: string): boolean {
  return (
    typeof message === "object" &&
    message !== null &&
    "method" in message &&
    (message as { method?: unknown }).method === method
  );
}

/** True if `message` is a JSON-RPC response (success or error) for the given id. */
export function isResponseTo(message: unknown, id: string | number): boolean {
  if (typeof message !== "object" || message === null || !("id" in message)) {
    return false;
  }
  const candidate = message as { id?: unknown; method?: unknown };
  return candidate.method === undefined && candidate.id === id;
}
