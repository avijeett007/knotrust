/**
 * @knotrust/proxy-stdio — `tools/call` interception → DecisionRequest →
 * enforcement (P0-E5-T3 THE HEART + P0-E5-T4 hardening + P0-E5-T5 fail-
 * closed/fail-open crash & error doctrine; rulings R71-R78, R81, R84).
 *
 * This module owns the two enforcement halves that sit ON the classifier seam
 * (`classifier.ts`) — the async relay plumbing (`proxy.ts`) awaits `handle()`
 * for every `tools/call` before it forwards-or-synthesizes:
 *
 *   - `buildDecisionRequest` (R71) — parses the FULL JSON-RPC `tools/call`
 *     body (`method`, `params.name`, `params.arguments`) into a KnoTrust
 *     `DecisionRequest`, applying the SARC defaults (PRD §12) and the COAZ
 *     dot-path resource mapping (E4-T2's `CoazStyleMapping`).
 *   - `createEnforcer().handle` (R72, hardened by R74-R78) — runs the request
 *     through the injected unified decider (`@knotrust/grants`'
 *     `createDecider`) and maps the outcome to a wire action: `allow`
 *     forwards unchanged; `deny`/`pending_approval`/`deferred_not_eligible`
 *     synthesize a SAME-`id` `CallToolResult` (`isError:true`, built by
 *     `./denial-envelope.js`'s `buildDenialEnvelope`) so the child NEVER
 *     receives the call.
 *
 * ## Headers are NEVER a decision input (brief §C2, R71)
 *
 * A decision is a pure function of the JSON-RPC BODY (`method` / `params`) plus
 * KnoTrust config/session identity — NEVER of transport headers. stdio has no
 * headers, so this constraint is moot here today; it is written into this
 * module's contract now precisely so the Phase-2 HTTP proxy — which WILL see
 * headers — inherits "headers are telemetry only, never authorization input"
 * structurally (ADR-0008), rather than rediscovering it. `buildDecisionRequest`
 * takes no header parameter at all: there is nowhere for a header to enter.
 *
 * ## The two-layer, injection-conscious denial envelope (P0-E5-T4)
 *
 * Every synthesized deny/pending/deferred `CallToolResult` is built by
 * `./denial-envelope.js`'s `buildDenialEnvelope` — a fixed-template
 * `content[].text` + a machine-readable `structuredContent.knotrust` block
 * that interpolates NOTHING from tool-call arguments or server-supplied
 * strings, carries only the R75 SAFE reasonCode subset, and never an
 * approval token or tokened URL. This module's job is just to correlate
 * that result with the request's `id` (`wrapResult`) and select WHICH
 * decision-shaped value to hand it (the real decider decision, or a
 * synthetic one for the decider-threw / orchestrator-resolved-deny cases).
 * The full rationale (matched policy, precedence layer, grant refs) never
 * reaches this module at all — it is written to the audit log upstream, by
 * the decider itself.
 *
 * ## Approval seam (E6) — the `pending_approval` "cannot-hold" case (§I1),
 * now with the REAL block-and-wait channel wired (P0-E6-T2)
 *
 * Block-and-wait / hold-and-resolve is P0-E6. When NO {@link ApprovalOrchestrator}
 * is wired, or one resolves to the non-terminal `{outcome:"pending"}`, a
 * `pending_approval` decision cannot be resolved synchronously by THIS
 * surface — architecture §3.1's "cannot-hold" case (brief §I1) — so the
 * HONEST envelope is `outcome: "pending_approval"` itself (the decision
 * passed straight through to `buildDenialEnvelope`), never a fabricated
 * `deny`. As of P0-E6-T2, the CLI wires `@knotrust/approval`'s
 * `createBlockAndWaitChannel` as the real orchestrator — that channel NEVER
 * resolves to `{outcome:"pending"}` (R93), so once it is wired this branch's
 * cannot-hold fallback is effectively dead in production; it remains the
 * correct behavior for a future surface that genuinely cannot hold (voice,
 * stateless HTTP, URL-mode-that-outlives-the-request). When an orchestrator
 * resolves terminally: `allow` forwards; `deny` synthesizes a `deny`-shaped
 * envelope carrying the orchestrator's own reasonCode (mapped through the
 * same R75 SAFE subset, falling to the catch-all for any orchestrator-
 * invented code, since that vocabulary is not yet type-constrained —
 * E6-T4's job).
 *
 * `parseToolsCall` (below) also extracts the ORIGINAL call's MCP progress
 * token (`params._meta.progressToken`), threading it into
 * `ApprovalRequestInput.progressToken` (P0-E6-T2) — the real block-and-wait
 * channel uses it to address its `notifications/progress` heartbeats so the
 * calling client can correlate them with its own held request and avoid
 * timing it out (the Decision named in the brief). Absent when the caller
 * supplied no token; the channel then holds with no heartbeat (documented
 * no-op), never a crash.
 *
 * ## Repeated-denial probing detection (P0-E5-T4, R78)
 *
 * Every POLICY rejection this module synthesizes — a decider `deny`, pending's
 * cannot-hold / orchestrator-denied cases, and `deferred_not_eligible`, all of
 * which are, from the calling agent's point of view, "my call did not go
 * through" — is recorded against a per-`(tool, agent)` sliding-window counter
 * (`./probing.js`). The R81 decider-threw / `internal_error` fail-closed path
 * is deliberately NOT fed to this counter: a system fault is not the agent
 * probing policy, and its `catch` may not even have a built `request` to key
 * on (`buildDecisionRequest` is itself one of the covered failure points, so it
 * may have thrown before producing one). Only genuine policy denials count
 * toward a probing verdict. Crossing the threshold (default:
 * 5 within 60s) appends ONE `denial_probing_suspected` audit event —
 * audit-only, `Best-effort` (a write failure here is swallowed, never
 * surfaced on the wire: probing detection must never affect what the model
 * sees, nor can a probing-audit failure retroactively change an
 * already-decided response). `audit` is optional so existing callers that
 * do not wire one keep compiling/working unchanged, with probing detection
 * simply inert.
 *
 * ## Fail-closed internal errors, and the ONE narrow fail-open recovery path
 * (P0-E5-T5; rulings R81, R84; `docs/03-engineering/failure-modes.md`)
 *
 * `handle()` wraps the WHOLE decision path — `getMapping`, `buildDecisionRequest`
 * (tier/resource mapping), and `decider.decide` (tier resolution, grant
 * collection, precedence, cache, audit) — in ONE try/catch. Any throw
 * anywhere in that path (R81: "tier resolution, grant collection,
 * precedence, cache, DecisionRequest mapping, envelope build") is caught at
 * this ONE boundary and resolved to `deny`/`internal_error` — audited
 * best-effort as a `type: "decision"` event (the decider never got the
 * chance to audit its own attempt, since it's the thing that threw) — NEVER
 * allowed, and NEVER leaking the raw error/stack to the model (the R75 safe
 * mapping already folds `"internal_error"` into `"unavailable"`,
 * `denial-envelope.ts`).
 *
 * The ONE exception is `failOpen` (R84) — deliberately narrow, and framed as
 * a RECOVERY from THIS internal error, never a normal-operation allow (see
 * ADR-0021). All three must hold simultaneously:
 *
 *   1. The tool's tier, resolved INDEPENDENTLY of the decider that just threw
 *      (via `resolveTierWithEnvelope` against the SAME `tierPolicy`/`envelope`
 *      the real decider would have used — passed in redundantly via
 *      `failOpen.tierPolicy`/`failOpen.envelope` for exactly this reason: the
 *      decider itself cannot be asked, it is what's broken), is `"routine"`.
 *      `sensitive`/`critical` NEVER reach this branch — structurally
 *      impossible per the config schema (`FailOpenConfigSchema` has no such
 *      key), reasserted here at the enforcement layer too (defense in depth).
 *   2. `failOpen.routine === true` was explicitly configured.
 *   3. A decision-path error was actually thrown (this whole branch is
 *      UNREACHABLE from a normal allow/deny/pending/deferred outcome).
 *
 * On all three: the call is ALLOWED instead of denied, but ONLY if the
 * mandatory `fail_open_fired` audit event (tool/agent/tier/error-class, NO
 * argument values — forensic) can actually be appended. **The audit of a
 * fail-open is not optional**: no `audit` sink wired, or the sink itself
 * throwing, both fail back to the ordinary `internal_error` DENY — an
 * unaudited fail-open is strictly worse than a denied call, never the other
 * way around.
 */

import type {
  AdminEnvelope,
  DecisionRequest,
  DecisionResponse,
  Resource,
  Tier,
  TierPolicy,
} from "@knotrust/core";
import { resolveTierWithEnvelope } from "@knotrust/core";
import {
  AuditEventType,
  type AuditSink,
  type CoazStyleMapping,
  computeArgsHash,
  type IdentityConfig,
} from "@knotrust/store";
import type {
  CallToolResult,
  JSONRPCMessage,
} from "@modelcontextprotocol/sdk/types.js";
import type { JsonRpcMessage } from "./classifier.js";
import {
  buildDenialEnvelope,
  type DenialEnvelopeCtx,
  type DenialEnvelopeDecision,
} from "./denial-envelope.js";
import {
  createProbingDetector,
  DEFAULT_PROBING_THRESHOLD,
  DEFAULT_PROBING_WINDOW_MS,
  type ProbingDetector,
} from "./probing.js";

// ---------------------------------------------------------------------------
// Decider seam — a STRUCTURAL type (matches `@knotrust/grants`' `Decider`)
// so this proxy package need not take a runtime dependency on the grants
// engine: the CLI constructs the real `createDecider(...)` and passes it in.
// ---------------------------------------------------------------------------

export interface Decider {
  decide(request: DecisionRequest): Promise<DecisionResponse>;
}

// ---------------------------------------------------------------------------
// Approval orchestrator seam (architecture §6.1) — E6-T4 implements it.
// ---------------------------------------------------------------------------

export interface ApprovalRequestInput {
  request: DecisionRequest;
  /** The pending_approval decision the decider produced. */
  decision: DecisionResponse;
  /**
   * The original `tools/call`'s MCP progress token (`params._meta.progressToken`),
   * when the calling client supplied one (P0-E6-T2). The real block-and-wait
   * channel (`@knotrust/approval`'s `createBlockAndWaitChannel`) uses this to
   * address its `notifications/progress` heartbeats at the ORIGINAL caller's
   * own token, so the client can correlate the heartbeat with its held call
   * and avoid timing it out. Absent when the caller supplied no token — the
   * channel then holds with no heartbeat (documented no-op), never a crash.
   */
  progressToken?: string | number;
  /**
   * The original `tools/call`'s own JSON-RPC `id` (P0-E6-T4, R105) — NEVER
   * the internal `apr_...` approval id (which is never wire-visible, R90).
   * A real orchestrator (`@knotrust/approval`'s
   * `createDispatchingApprovalOrchestrator`) uses this to correlate a LATER
   * `notifications/cancelled` (the MCP spec addresses it by this same
   * JSON-RPC id, `params.requestId`) back to the pending approval this call
   * created, so the proxy's cancellation classifier
   * (`@knotrust/proxy-stdio`'s `cancellation.ts`) can cancel it. This module
   * never reads it back itself — it is purely a pass-through correlation
   * key for whichever orchestrator is wired in.
   */
  jsonRpcRequestId: string | number;
}

/**
 * The terminal resolution of an approval. `"pending"` means "not resolved
 * terminally" — the enforcer then passes the original `pending_approval`
 * decision straight through to `buildDenialEnvelope` as the honest
 * "cannot-hold" envelope (architecture §3.1/§I1; E6-T4's real
 * block-and-wait always returns a terminal `allow`/`deny` instead).
 */
export type ApprovalResolution =
  | { outcome: "allow" }
  | { outcome: "deny"; reasonCode?: string }
  | { outcome: "pending" };

export interface ApprovalOrchestrator {
  /** Invoked when a decision is `pending_approval`. E6-T4 implements block-and-wait (architecture §6.1). */
  requestApproval(input: ApprovalRequestInput): Promise<ApprovalResolution>;
}

// ---------------------------------------------------------------------------
// tools/call parse
// ---------------------------------------------------------------------------

export interface ParsedToolsCall {
  id: string | number;
  name: string;
  arguments?: Record<string, unknown>;
  /** `params._meta.progressToken`, when present and a valid JSON-RPC id shape (P0-E6-T2 — threaded to the approval seam's heartbeats). */
  progressToken?: string | number;
}

/** True iff `message` is a client→server `tools/call` REQUEST (has `method`, an `id`). The relay uses this to decide what to route to enforcement. */
export function isToolsCallRequest(message: JsonRpcMessage): boolean {
  if (typeof message !== "object" || message === null) return false;
  const m = message as { method?: unknown; id?: unknown };
  return (
    m.method === "tools/call" &&
    (typeof m.id === "string" || typeof m.id === "number")
  );
}

/**
 * Parses a `tools/call` request's body, or `null` if it fails shape validation
 * (no `id`, no string `params.name`, non-object `params`) — a malformed call
 * the enforcer passes THROUGH so the child returns its own protocol error (R72:
 * "protocol error passthrough, not a crash"). `arguments` is only carried when
 * it is a plain object; anything else is treated as absent.
 */
export function parseToolsCall(
  message: JsonRpcMessage,
): ParsedToolsCall | null {
  if (typeof message !== "object" || message === null) return null;
  const m = message as { id?: unknown; method?: unknown; params?: unknown };
  if (m.method !== "tools/call") return null;
  if (!(typeof m.id === "string" || typeof m.id === "number")) return null;
  if (typeof m.params !== "object" || m.params === null) return null;
  const name = (m.params as { name?: unknown }).name;
  if (typeof name !== "string" || name.length === 0) return null;
  const rawArgs = (m.params as { arguments?: unknown }).arguments;
  const args =
    typeof rawArgs === "object" && rawArgs !== null && !Array.isArray(rawArgs)
      ? (rawArgs as Record<string, unknown>)
      : undefined;
  const rawMeta = (m.params as { _meta?: unknown })._meta;
  const rawProgressToken =
    typeof rawMeta === "object" && rawMeta !== null
      ? (rawMeta as { progressToken?: unknown }).progressToken
      : undefined;
  const progressToken =
    typeof rawProgressToken === "string" || typeof rawProgressToken === "number"
      ? rawProgressToken
      : undefined;
  return {
    id: m.id,
    name,
    ...(args !== undefined ? { arguments: args } : {}),
    ...(progressToken !== undefined ? { progressToken } : {}),
  };
}

// ---------------------------------------------------------------------------
// buildDecisionRequest (R71)
// ---------------------------------------------------------------------------

export interface BuildDecisionRequestContext {
  /**
   * Proxy subject fallback (E4-T2 config `identity` seam). `subject.id`
   * defaults to `"local-user"` and `subject.type` to `"user"` — a real subject
   * arrives from the OS session later (Phase 1+). Documented placeholder.
   */
  identity?: IdentityConfig;
  /** Agent identity → `context.agent` (NEVER merged into subject, COAZ §C4). `id` defaults to `"unknown-agent"`. */
  agent?: { id?: string };
  /** The per-tool COAZ mapping (E4-T2), if configured for this tool. */
  mapping?: CoazStyleMapping;
  surface: { instanceId: string; server?: string };
  /** Injected millisecond clock → `timestamp`/`env.time` (RFC 3339). */
  nowMs: () => number;
  /** Mints `requestId` (a ULID). */
  generateId: () => string;
}

/**
 * Resolves a mapping value against the call's arguments. A value prefixed
 * `"arguments."` is a DOT-PATH REFERENCE into `arguments` (e.g.
 * `"arguments.charge_id"`, `"arguments.meta.k"`); any other string is a
 * LITERAL (so a static `resourceType: "stripe_charge"` and a dynamic
 * `resourceId: "arguments.charge_id"` both work). An unresolved ref yields
 * `undefined`. Documented, forgiving P0 semantics — resource is best-effort in
 * P0 (R71).
 */
function resolveMappingRef(
  value: string,
  args: Record<string, unknown> | undefined,
): unknown {
  const ARG_PREFIX = "arguments.";
  if (!value.startsWith(ARG_PREFIX)) return value; // literal
  const parts = value.slice(ARG_PREFIX.length).split(".");
  let cur: unknown = args ?? {};
  for (const part of parts) {
    if (typeof cur !== "object" || cur === null) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

/** A mapping ref coerced to a string for `resource.type`/`resource.id` (primitives only; objects/undefined → unresolved). */
function refToString(
  value: string,
  args: Record<string, unknown> | undefined,
): string | undefined {
  const resolved = resolveMappingRef(value, args);
  if (typeof resolved === "string") return resolved;
  if (typeof resolved === "number" || typeof resolved === "boolean") {
    return String(resolved);
  }
  return undefined;
}

function resolveResource(
  toolName: string,
  args: Record<string, unknown> | undefined,
  mapping: CoazStyleMapping | undefined,
  server: string | undefined,
): Resource {
  const type =
    (mapping?.resourceType !== undefined
      ? refToString(mapping.resourceType, args)
      : undefined) ??
    server ??
    "tool";
  const id =
    (mapping?.resourceId !== undefined
      ? refToString(mapping.resourceId, args)
      : undefined) ?? toolName;

  const properties: Record<string, unknown> = {};
  if (mapping?.properties !== undefined) {
    for (const [key, ref] of Object.entries(mapping.properties)) {
      const resolved = resolveMappingRef(ref, args);
      if (resolved !== undefined) properties[key] = resolved;
    }
  }
  return {
    type,
    id,
    ...(Object.keys(properties).length > 0 ? { properties } : {}),
  };
}

/**
 * Maps a parsed `tools/call` onto a `DecisionRequest` (R71; architecture §2 +
 * PRD §12). Pure — the only impurity is the injected clock/id source.
 */
export function buildDecisionRequest(
  parsed: ParsedToolsCall,
  ctx: BuildDecisionRequestContext,
): DecisionRequest {
  const timestamp = new Date(ctx.nowMs()).toISOString();
  const server = ctx.surface.server;
  return {
    contractVersion: "1.0",
    requestId: ctx.generateId(),
    timestamp,
    subject: {
      type: ctx.identity?.subjectType ?? "user",
      id: ctx.identity?.subjectId ?? "local-user",
    },
    action: {
      name: parsed.name,
      properties: { mcpMethod: "tools/call" },
    },
    resource: resolveResource(
      parsed.name,
      parsed.arguments,
      ctx.mapping,
      server,
    ),
    context: {
      // Agent identity is a SIBLING of subject, never merged into it (COAZ §C4).
      agent: { id: ctx.agent?.id ?? "unknown-agent", type: "ai_agent" },
      env: { time: timestamp, surfaceLocal: true },
      // Verbatim arguments (R32) — feeds the call-hash + audit argsHash; never
      // logged raw by default.
      ...(parsed.arguments !== undefined
        ? { arguments: parsed.arguments }
        : {}),
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: ctx.surface.instanceId,
      ...(server !== undefined ? { server } : {}),
      specVersion: "2025-11-25",
      transport: "stdio",
    },
  };
}

// ---------------------------------------------------------------------------
// Envelope synthesis (R74) — the two-layer, injection-conscious denial
// envelope. This module's only remaining job is (a) picking WHICH
// decision-shaped value to hand `buildDenialEnvelope`, and (b) correlating
// its result with the request's own `id`; the templates, the safe-
// reason-code mapping, and the requestable.how sanitization all live in
// `./denial-envelope.js`.
// ---------------------------------------------------------------------------

/** Wraps a `buildDenialEnvelope` result in the JSON-RPC envelope, correlated by `id` (R74: `id` correlation is this module's job, not the envelope builder's). */
function wrapResult(
  id: string | number,
  result: CallToolResult,
): JsonRpcMessage {
  return { jsonrpc: "2.0", id, result } as unknown as JSONRPCMessage;
}

/** The `{tool, server}` view `buildDenialEnvelope` needs for `requestable.how` — NEVER any other field of `parsed`/`request` (R74/R77). */
function ctxFor(
  parsed: ParsedToolsCall,
  server: string | undefined,
): DenialEnvelopeCtx {
  return { tool: parsed.name, ...(server !== undefined ? { server } : {}) };
}

/** The fail-closed deny synthesized when the decider PRODUCES an outcome this switch doesn't recognize (a data anomaly, not a thrown error — never crash the relay). */
function enforcementErrorDecision(): DenialEnvelopeDecision {
  return {
    outcome: "deny",
    decisionId: "",
    tier: "sensitive",
    reasonCode: "enforcement_error",
  };
}

/**
 * The fail-closed deny synthesized for R81's ONE broadened catch — ANY
 * thrown error anywhere in the decision path (mapping/`buildDecisionRequest`/
 * `decider.decide`). `reasonCode: "internal_error"` is the exact code R81
 * names; the R75 safe-code mapping (`denial-envelope.ts`) already folds it
 * into the model-visible `"unavailable"`, alongside `enforcementErrorDecision`'s
 * `"enforcement_error"` and the decider's own `"audit_unavailable"` — three
 * internal codes, one honest "transient/system" story on the wire.
 */
function internalErrorDecision(): DenialEnvelopeDecision {
  return {
    outcome: "deny",
    decisionId: "",
    tier: "sensitive",
    reasonCode: "internal_error",
  };
}

/** `err instanceof Error ? "Name: message" : String(err)` — local-audit-only diagnostic text (never model-visible, never written to the DENY envelope). */
function describeError(err: unknown): string {
  return err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}

// ---------------------------------------------------------------------------
// createEnforcer
// ---------------------------------------------------------------------------

export type EnforceResult =
  | { action: "forward" }
  | { action: "respond"; message: JsonRpcMessage };

export interface CreateEnforcerOptions {
  decider: Decider;
  requestContext: Omit<BuildDecisionRequestContext, "mapping">;
  /** Resolves the per-tool COAZ mapping (from config) for the call being decided. */
  getMapping?: (toolName: string) => CoazStyleMapping | undefined;
  /** E6 approval seam (architecture §6.1). Absent ⇒ pending passes through as the honest "cannot-hold" `pending_approval` envelope (§I1). */
  orchestrator?: ApprovalOrchestrator;
  /** Diagnostic sink for enforcement-internal failures (never the relayed traffic). */
  logger?: (line: string) => void;
  /**
   * Audit sink for the `denial_probing_suspected` event (R78). Optional —
   * absent means probing detection still RUNS (the counter is always live)
   * but its threshold-crossing signal is simply never written anywhere,
   * matching this package's default of never requiring a real audit
   * dependency to be wired for `createEnforcer` to work (mirrors
   * `orchestrator` being optional for the same reason).
   */
  audit?: Pick<AuditSink, "append">;
  /**
   * Overrides the R78 sliding-window defaults (5 denials / 60s) and, since
   * fix round 1's bounded-memory hardening (`./probing.js`'s module
   * header), the tracked-pairs hard cap (default 4096).
   */
  probing?: { windowMs?: number; threshold?: number; maxTrackedPairs?: number };
  /**
   * The R84 fail-open RECOVERY seam (P0-E5-T5) — consumes the on-disk
   * `failOpen.routine` config (E4-T2, structurally routine-only). Absent
   * entirely (the default) ⇒ fail-open never fires; every internal error
   * denies (R81), full stop.
   *
   * `tierPolicy`/`envelope` are used ONLY to independently re-resolve a
   * throwing call's tier for fail-open ELIGIBILITY — never to produce an
   * allow/deny of their own. This is deliberately the SAME
   * `tierPolicy`/`envelope` the real `decider` was constructed with (the
   * CLI wiring, `enforcement.ts`, passes the identical values it also hands
   * `createDecider`): the decider is what just threw, so tier resolution
   * cannot go through it — this is the one place this package redundantly
   * re-derives a tier via `@knotrust/core`'s own `resolveTierWithEnvelope`,
   * purely to tell "routine" from "sensitive"/"critical" when the real
   * decision path is unavailable. Absent ⇒ fail-open can never be eligible
   * (no independent tier to check), regardless of `routine`.
   */
  failOpen?: {
    /** Mirrors `KnotrustConfig["failOpen"]["routine"]` (`@knotrust/store`). Only `true` is ever eligible — absent/`false` never fails open. */
    routine?: boolean;
    tierPolicy?: TierPolicy;
    envelope?: AdminEnvelope;
  };
}

export interface Enforcer {
  /**
   * Decides one `tools/call` message and returns the wire action. NEVER
   * throws: an unexpected decider failure fails closed to a synthesized deny.
   */
  handle(message: JsonRpcMessage): Promise<EnforceResult>;
}

export function createEnforcer(opts: CreateEnforcerOptions): Enforcer {
  const {
    decider,
    requestContext,
    getMapping,
    orchestrator,
    logger,
    audit,
    failOpen,
  } = opts;
  const probingDetector: ProbingDetector = createProbingDetector({
    nowMs: requestContext.nowMs,
    ...opts.probing,
  });
  const probingWindowMs = opts.probing?.windowMs ?? DEFAULT_PROBING_WINDOW_MS;
  const probingThreshold = opts.probing?.threshold ?? DEFAULT_PROBING_THRESHOLD;

  // The SAME subject/agent-default expressions `buildDecisionRequest` uses —
  // computed independently here so the R81/R84 error path always has a
  // subject/agent to audit against, even when the throw happened INSIDE
  // `buildDecisionRequest` itself (i.e. `request` was never built).
  const defaultSubjectId = requestContext.identity?.subjectId ?? "local-user";
  const defaultAgentId = requestContext.agent?.id ?? "unknown-agent";
  // `buildDecisionRequest` always sets this literal — duplicated here (not
  // imported) for the same reason: it must be available even when
  // `buildDecisionRequest` is the thing that threw.
  const STDIO_PROXY_SURFACE = "stdio_proxy";

  /**
   * R84's independent tier re-resolution: `undefined` unless `failOpen`
   * carries a `tierPolicy` (no policy ⇒ no eligibility, ever — see
   * `CreateEnforcerOptions.failOpen`'s own doc-comment). Never throws: a
   * failure here just means "not eligible," never a crash — this function
   * runs ONLY after the real decision path already failed, so it must be
   * strictly more defensive than that path, not equally fragile.
   */
  function tryResolveRoutineTier(toolName: string): Tier | undefined {
    if (failOpen?.tierPolicy === undefined) return undefined;
    try {
      const { tier } = resolveTierWithEnvelope(
        toolName,
        failOpen.tierPolicy,
        failOpen.envelope,
        undefined, // buildDecisionRequest never populates toolAnnotations either (P0 scope).
      );
      return tier;
    } catch {
      return undefined;
    }
  }

  /**
   * The MANDATORY `fail_open_fired` audit append (R84) — returns whether it
   * actually landed. `audit` absent, or `audit.append` throwing, both count
   * as failure: "the audit of a fail-open is not optional," so the caller
   * must fall back to DENY on either.
   */
  function tryAppendFailOpenFired(
    parsed: ParsedToolsCall,
    tier: Tier,
    err: unknown,
  ): boolean {
    if (audit === undefined) return false;
    try {
      audit.append({
        type: AuditEventType.FAIL_OPEN_FIRED,
        surface: STDIO_PROXY_SURFACE,
        subject: defaultSubjectId,
        agent: defaultAgentId,
        tool: parsed.name,
        argsHash: computeArgsHash(null), // NO argument values (R84) — forensic only.
        // First-class `tier` (R126), additive alongside the pre-existing
        // structured `reason` payload — kept for backward-compat so a
        // legacy reader (or `filters.ts`'s `deriveEventTier` fallback) that
        // still parses `reason` as `{tier, cause}` JSON keeps working
        // unchanged.
        tier,
        reason: JSON.stringify({ tier, cause: describeError(err) }),
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Best-effort audits the R81 `internal_error` deny as a `type: "decision"`
   * event — the decider never got the chance to audit its own attempt (it's
   * the thing that threw), so this module owns that one event instead. A
   * failure here does NOT change the outcome (still deny, per R81's own
   * "if audit ALSO fails, still deny — never allow on error"); it is
   * swallowed exactly like `noteRejection`'s best-effort probing audit.
   *
   * `tier` (R126) is set ONLY when resolvable: the real decider is what just
   * threw, so this module has no tier source of its own — the ONE tier it
   * can honestly report is `tryResolveRoutineTier`'s independent
   * re-resolution (R84), which itself only works when the caller wired
   * `failOpen.tierPolicy`. When `failOpen` isn't configured at all (no
   * independent tier policy to consult), `tier` stays `undefined` here and
   * is correctly omitted — never guessed.
   */
  function auditInternalErrorDeny(
    parsed: ParsedToolsCall,
    argsHash: string,
    tier: Tier | undefined,
  ): void {
    if (audit === undefined) return;
    try {
      audit.append({
        type: AuditEventType.DECISION,
        surface: STDIO_PROXY_SURFACE,
        subject: defaultSubjectId,
        agent: defaultAgentId,
        tool: parsed.name,
        argsHash,
        outcome: "deny",
        reason: "internal_error",
        ...(tier !== undefined ? { tier } : {}),
      });
    } catch {
      // Best-effort (R81) — the deny stands regardless of whether THIS
      // audit line landed; see the decider's own `auditUnavailableDeny` for
      // the identical "still deny" doctrine on the real decision path.
    }
  }

  /**
   * Records one rejection toward the R78 sliding-window counter and, on a
   * threshold crossing, best-effort appends the `denial_probing_suspected`
   * audit event. NEVER throws, NEVER affects the wire response — this is
   * called strictly for its audit side effect, after the response the
   * caller will return has already been decided (R78: probing detection
   * must not change what the model sees).
   */
  function noteRejection(
    parsed: ParsedToolsCall,
    request: DecisionRequest,
  ): void {
    const agent = request.context.agent.id;
    const fired = probingDetector.recordDenial(parsed.name, agent);
    if (!fired || !audit) return;
    try {
      audit.append({
        type: AuditEventType.DENIAL_PROBING_SUSPECTED,
        surface: request.surface.kind,
        subject: request.subject.id,
        agent,
        tool: parsed.name,
        argsHash: computeArgsHash(null), // NO argument values (R78) — this event carries counts only.
        reason: `${probingThreshold} denials for "${parsed.name}" by agent "${agent}" within ${probingWindowMs}ms`,
      });
    } catch {
      // Best-effort — a probing-audit write failure must never surface on
      // the wire (the enforcement decision for THIS call is already made).
    }
  }

  return {
    async handle(message: JsonRpcMessage): Promise<EnforceResult> {
      const parsed = parseToolsCall(message);
      if (parsed === null) {
        // Malformed → passthrough; the child returns its own protocol error (R72).
        return { action: "forward" };
      }

      // `ctx` depends only on `parsed`/`requestContext.surface.server` — never
      // on `request` — so it is available even when the try block below
      // throws before `request` itself is ever built (R81: "DecisionRequest
      // mapping" is itself one of the covered failure points).
      const ctx = ctxFor(parsed, requestContext.surface.server);

      // R81 — ONE broadened catch around the WHOLE decision path: getMapping,
      // buildDecisionRequest (tier/resource mapping), and decider.decide
      // (tier resolution, grant collection, precedence, cache, audit) all
      // fail closed to the SAME `internal_error` deny (with R84's narrow
      // fail-open recovery layered on top) rather than each needing its own
      // guard.
      let request: DecisionRequest;
      let decision: DecisionResponse;
      try {
        const mapping = getMapping?.(parsed.name);
        request = buildDecisionRequest(parsed, {
          ...requestContext,
          ...(mapping !== undefined ? { mapping } : {}),
        });
        decision = await decider.decide(request);
      } catch (err) {
        logger?.(
          `knotrust-enforce: internal error deciding "${parsed.name}": ${String(err)}`,
        );

        // R84 — fail-open eligibility: routine tier (resolved independently
        // — the decider is what just threw) AND explicitly configured AND
        // this IS a thrown-error recovery (never a normal-operation allow).
        const tier = tryResolveRoutineTier(parsed.name);
        if (tier === "routine" && failOpen?.routine === true) {
          if (tryAppendFailOpenFired(parsed, tier, err)) {
            return { action: "forward" };
          }
          // The mandatory fail_open_fired audit append failed (or no audit
          // sink was wired at all) — fall through to the ordinary
          // fail-closed deny below. Audit-of-fail-open is not optional.
          logger?.(
            `knotrust-enforce: fail_open_fired audit unavailable for "${parsed.name}" — denying instead (audit-of-fail-open is mandatory)`,
          );
        }

        auditInternalErrorDeny(
          parsed,
          computeArgsHash(parsed.arguments ?? null),
          tier,
        );
        return {
          action: "respond",
          message: wrapResult(
            parsed.id,
            buildDenialEnvelope(internalErrorDecision(), ctx),
          ),
        };
      }

      switch (decision.outcome) {
        case "allow":
          return { action: "forward" };
        case "deny":
          noteRejection(parsed, request);
          return {
            action: "respond",
            message: wrapResult(parsed.id, buildDenialEnvelope(decision, ctx)),
          };
        case "pending_approval": {
          const resolution = orchestrator
            ? await orchestrator.requestApproval({
                request,
                decision,
                jsonRpcRequestId: parsed.id,
                ...(parsed.progressToken !== undefined
                  ? { progressToken: parsed.progressToken }
                  : {}),
              })
            : undefined;
          if (resolution?.outcome === "allow") {
            return { action: "forward" };
          }
          noteRejection(parsed, request);
          if (resolution?.outcome === "deny") {
            const synthetic: DenialEnvelopeDecision = {
              outcome: "deny",
              decisionId: decision.decisionId,
              tier: decision.tier,
              reasonCode: resolution.reasonCode ?? "approval_denied",
            };
            return {
              action: "respond",
              message: wrapResult(
                parsed.id,
                buildDenialEnvelope(synthetic, ctx),
              ),
            };
          }
          // No orchestrator, or a non-terminal "pending" resolution → this
          // surface cannot hold the call synchronously today (architecture
          // §3.1's "cannot-hold" case, brief §I1) — the honest envelope is
          // `pending_approval` itself, passed straight through (E6-T4
          // replaces this branch with real hold-and-resolve, at which point
          // most calls terminate via the `allow`/`deny` branches above
          // instead of ever reaching here).
          return {
            action: "respond",
            message: wrapResult(parsed.id, buildDenialEnvelope(decision, ctx)),
          };
        }
        case "deferred_not_eligible":
          noteRejection(parsed, request);
          return {
            action: "respond",
            message: wrapResult(parsed.id, buildDenialEnvelope(decision, ctx)),
          };
        default: {
          const exhaustive: never = decision.outcome;
          logger?.(`knotrust-enforce: unhandled outcome ${String(exhaustive)}`);
          noteRejection(parsed, request);
          return {
            action: "respond",
            message: wrapResult(
              parsed.id,
              buildDenialEnvelope(enforcementErrorDecision(), ctx),
            ),
          };
        }
      }
    },
  };
}
