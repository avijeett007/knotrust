/**
 * @knotrust/test-harness — fake MCP server configuration surface (P0-E11-T1,
 * R54).
 *
 * This is the malicious-behavior surface the P0-E11-T2..T6 adversarial suite
 * and P0-E5's rug-pull/annotation-trust tests are built on. Every field here
 * maps to one R54 bullet; see the module doc-comment on `core.ts` for how
 * each is actually served.
 *
 * `FakeServerConfig` must remain plain data (JSON-serializable) for every
 * field EXCEPT `toolBehaviors[name].respond` of kind `"custom"`, which
 * carries a real JS function. That one exception is exactly why child-
 * process mode (R53) is only available when a config contains no `"custom"`
 * behaviors — see `assertChildProcessCompatible` in `start.ts`.
 */

/** The subset of JSON Schema (draft 2020-12, object-rooted) MCP tool `inputSchema`/`outputSchema` requires. */
export interface FakeJsonSchemaObject {
  type: "object";
  properties?: Record<string, unknown>;
  required?: string[];
  [key: string]: unknown;
}

/**
 * MCP tool annotations (`readOnlyHint`/`destructiveHint`/`idempotentHint`/
 * `openWorldHint`) — advisory, self-declared metadata (ADR-0009: never a
 * trust decision). This is also where an "annotation lie" (R54) lives: the
 * harness serves whatever is configured here verbatim, truthful or not — it
 * is data, not a claim the harness verifies against the tool's actual
 * `toolBehaviors` entry. See `README.md` "Annotation lies" for a worked
 * example (a `readOnlyHint: true` tool whose configured behavior crashes
 * the process).
 */
export interface FakeToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface FakeToolDef {
  name: string;
  description?: string;
  inputSchema: FakeJsonSchemaObject;
  annotations?: FakeToolAnnotations;
}

/** A minimal `CallToolResult` content block — text or image, enough for every fake behavior this harness needs to express. */
export type FakeContentBlock =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string };

export interface FakeCallToolResult {
  content: FakeContentBlock[];
  isError?: boolean;
}

/**
 * A custom, in-process-only tool handler. Cannot cross a process boundary
 * (functions aren't JSON), which is exactly why configs using this are
 * rejected for child-process mode (R53/R54) rather than silently dropped.
 */
export type CustomToolHandler = (
  args: Record<string, unknown> | undefined,
  ctx: {
    requestId: string | number;
    signal: AbortSignal;
    sendNotification: (notification: {
      method: string;
      params?: Record<string, unknown>;
    }) => Promise<void>;
  },
) => FakeCallToolResult | Promise<FakeCallToolResult>;

/**
 * What a `tools/call` for one tool actually does, once any configured delay
 * has elapsed. Every R54 "toolBehaviors" bullet is one variant:
 * - `echo` — echoes `arguments` back as a text content block.
 * - `fixed` — a canned `CallToolResult`.
 * - `error` — a canned `isError: true` result (tool-level error, NOT a
 *   JSON-RPC protocol error).
 * - `crash` — either exits the process (`"exit"`, real subprocess death in
 *   child mode; in in-process mode, closes the shared transport so the
 *   caller observes the same "connection dropped mid-call" symptom without
 *   killing the test runner — see `core.ts`) or throws inside the handler
 *   (`"throw"`, which the MCP SDK's `Server` turns into a genuine JSON-RPC
 *   error response — a badly-behaved tool implementation, not a transport
 *   failure).
 * - `oversized` — a text content block of a configurable byte size.
 * - `custom` — an arbitrary handler function (in-process only).
 */
export type ToolRespondSpec =
  | { type: "echo" }
  | { type: "fixed"; content: FakeContentBlock[]; isError?: boolean }
  | { type: "error"; message: string }
  | { type: "crash"; via: "exit" | "throw" }
  | { type: "oversized"; bytes: number; fill?: string }
  | { type: "custom"; handler: CustomToolHandler };

export interface ToolBehaviorSpec {
  /**
   * Delay before responding, in milliseconds. A fixed number is
   * deterministic; a `{min, max}` range is resolved via the server's
   * injected seeded PRNG (R54 ruling 4) — never `Math.random()`.
   */
  delayMs?: number | { min: number; max: number };
  respond: ToolRespondSpec;
}

export interface PaginationConfig {
  /** Tools served per `tools/list` page. */
  pageSize: number;
}

/**
 * The rug-pull tripwire (R54): mutates one tool's annotations/inputSchema/
 * description starting from the `afterListCallCount`-th *fresh* `tools/list`
 * call (a "fresh" call is one with `cursor` unset — i.e. the first page of
 * a new listing sequence; a paginated sequence's later pages don't count as
 * separate calls for this purpose). `afterListCallCount: 1` means: the 1st
 * fresh listing serves the tool as originally configured; the 2nd fresh
 * listing onward serves it patched.
 */
export interface DriftRule {
  toolName: string;
  afterListCallCount: number;
  patch: Partial<
    Pick<FakeToolDef, "annotations" | "inputSchema" | "description">
  >;
}

/**
 * Chaos-profile knobs (R54 ruling 4 / R56 ruling 2). `seed` is mandatory —
 * there is no chaos without a logged, reproducible seed. When
 * `interleaveNotifications` is set, any tool call with a resolved delay > 0
 * emits `notifications/progress` (if the call carried a `progressToken`) or
 * `notifications/message` heartbeats spread across the delay window,
 * instead of just sleeping silently.
 */
export interface ChaosConfig {
  seed: number;
  interleaveNotifications?: boolean;
  /** Max heartbeat notifications emitted per delayed call. Default 2. */
  notificationBudget?: number;
}

export interface FakeServerConfig {
  serverInfo?: { name: string; version: string };
  tools: FakeToolDef[];
  pagination?: PaginationConfig;
  toolBehaviors?: Record<string, ToolBehaviorSpec>;
  driftAfter?: DriftRule[];
  chaos?: ChaosConfig;
}

/** One recorded `tools/call` the fake server actually received (R54 "callLog"). */
export interface CallLogEntry {
  toolName: string;
  arguments: unknown;
  requestId: string | number;
  receivedAtMs: number;
}

/** Marker prefix for call-log lines the fake server writes to stderr in child-process mode (see `call-log.ts`). */
export const CALL_LOG_STDERR_MARKER = "KNOTRUST_FAKE_SERVER_CALL_LOG ";

/**
 * True if every `toolBehaviors` entry in `config` is representable as JSON
 * (i.e. contains no `"custom"` handler function). Child-process mode
 * serializes the config to a temp file the spawned process reads back, so a
 * `"custom"` handler — a live closure — cannot survive the trip.
 */
export function isChildProcessCompatible(config: FakeServerConfig): boolean {
  const behaviors = config.toolBehaviors ?? {};
  return Object.values(behaviors).every(
    (behavior) => behavior.respond.type !== "custom",
  );
}
