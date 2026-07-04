/**
 * @knotrust/proxy-stdio — MCP stdio proxy.
 *
 * Phase-0 epic P0-E5. P0-E5-T1 shipped the transport-only layer: child spawn
 * + byte/shape-faithful transparent passthrough of stdio JSON-RPC, with a
 * typed classifier SEAM (`classifier.ts`). P0-E5-T2 adds opt-in `tools/list`
 * interception & annotation capture (`tool-inventory.ts`) on top of that
 * seam via `observe` — still pure passthrough, never enforcement.
 * P0-E5-T3 (tools/call → DecisionRequest → enforcement) hooks this seam with
 * a genuine non-passthrough routing action. P0-E5-T4 hardens the synthesized
 * deny/pending/deferred result into the two-layer, injection-conscious
 * denial envelope (`denial-envelope.ts`) plus repeated-denial probing
 * detection (`probing.ts`). P0-E6-T4 adds `cancellation.ts` — the
 * `notifications/cancelled` → pending-approval bridge (R105): a
 * `ClassifierHook`, built for `createStdioProxy`'s existing `onClassify`
 * option, that fires an injected callback (wired to `@knotrust/approval`'s
 * `createDispatchingApprovalOrchestrator`'s `cancel(jsonRpcRequestId)` by
 * `packages/cli`'s `enforcement.ts`) alongside the SAME byte/shape-faithful
 * passthrough this proxy has always given that notification.
 */

export {
  createCancellationClassifier,
  type ParsedCancelledNotification,
  parseCancelledNotification,
} from "./cancellation.js";
export {
  type ClassifierHook,
  type ClassifyDirection,
  type ClassifyResult,
  composeClassifiers,
  defaultClassifier,
  type JsonRpcMessage,
} from "./classifier.js";
export {
  buildDenialEnvelope,
  type DenialEnvelopeCtx,
  type DenialEnvelopeDecision,
  type SafeReasonCode,
  toSafeReasonCode,
} from "./denial-envelope.js";
export {
  type ApprovalOrchestrator,
  type ApprovalRequestInput,
  type ApprovalResolution,
  type BuildDecisionRequestContext,
  buildDecisionRequest,
  type CreateEnforcerOptions,
  createEnforcer,
  type Decider,
  type EnforceResult,
  type Enforcer,
  isToolsCallRequest,
  type ParsedToolsCall,
  parseToolsCall,
} from "./enforce.js";
export {
  createProbingDetector,
  DEFAULT_MAX_TRACKED_PAIRS,
  DEFAULT_PROBING_THRESHOLD,
  DEFAULT_PROBING_WINDOW_MS,
  type ProbingDetector,
  type ProbingDetectorOptions,
} from "./probing.js";
export {
  type CreateStdioProxyOptions,
  createStdioProxy,
  type EnforcementHook,
  type ProxyCloseReason,
  type StdioProxy,
} from "./proxy.js";
export {
  type AnnotationFieldChange,
  buildToolInventorySnapshot,
  computeInputSchemaHash,
  createToolInventoryClassifier,
  diffToolInventory,
  emitToolDefinitionChangeEvent,
  loadToolInventory,
  mergeSeededTiers,
  saveToolInventory,
  seedTierEntriesFromAnnotations,
  type ToolDefinitionChange,
  type ToolDefinitionChangeKind,
  type ToolInventory,
  type ToolInventoryEntry,
  type ToolInventoryHookOptions,
} from "./tool-inventory.js";
