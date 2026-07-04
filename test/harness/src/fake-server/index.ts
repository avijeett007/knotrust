/**
 * @knotrust/test-harness/fake-server — public barrel (P0-E11-T1).
 */

export { formatCallLogLine, parseCallLogFromStderr } from "./call-log.js";
export { buildFakeServer, type FakeServerHandle } from "./core.js";
export {
  type StartedFakeServer,
  type StartFakeServerOptions,
  startFakeServer,
} from "./start.js";
export type {
  CallLogEntry,
  ChaosConfig,
  CustomToolHandler,
  DriftRule,
  FakeCallToolResult,
  FakeContentBlock,
  FakeJsonSchemaObject,
  FakeServerConfig,
  FakeToolAnnotations,
  FakeToolDef,
  PaginationConfig,
  ToolBehaviorSpec,
  ToolRespondSpec,
} from "./types.js";
export { CALL_LOG_STDERR_MARKER, isChildProcessCompatible } from "./types.js";
