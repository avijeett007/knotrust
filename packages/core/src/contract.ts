/**
 * @knotrust/core — DecisionRequest contract v1 + Decision outcomes.
 *
 * The single most load-bearing interface in the system (PRD §8, brief §E1):
 * the versioned internal contract every enforcement surface uses to reach
 * the core. Shapes are copied verbatim from
 * `docs/02-architecture/system-architecture.md` §2/§3 (source of truth on
 * shape — the implementation plan's field summary is a summary, not the
 * contract), plus the `ApprovalHandleRef` shape ruled during P0-E2-T1 (the
 * architecture doc references it in §3 but never defines it; the ruling is
 * now also patched into the architecture doc directly under §3).
 *
 * SARC shape follows the COAZ mapping rule (brief §C4): the HUMAN principal
 * lives in `subject`; AGENT identity lives in `context.agent` — the two are
 * never merged.
 *
 * A language-neutral mirror of every type below lives at
 * `golden-vectors/schemas/decision-request.v1.schema.json` and
 * `golden-vectors/schemas/decision.v1.schema.json` (feeds golden vectors and
 * the Phase 3 Python port); `packages/core/src/contract.test.ts` proves the
 * two stay in sync.
 */

// ---------------------------------------------------------------------------
// The DecisionRequest contract v1 (architecture §2)
// ---------------------------------------------------------------------------

/** @knotrust/core — no dependency on @modelcontextprotocol/sdk anywhere in this file. */
export interface DecisionRequest {
  contractVersion: "1.0"; // bumped on any breaking shape change
  requestId: string; // ULID; correlates request → decision → approval → audit
  timestamp: string; // RFC 3339 (profiled subset of ISO 8601, ADR-0017), when the surface produced the request

  // ---- SARC (COAZ profile; AuthZEN Information Model) ----
  subject: Subject; // the HUMAN principal the agent acts for
  action: Action; // the tool verb
  resource: Resource; // the target object, derived from tool arguments
  context: DecisionContext; // environment + AGENT identity (context.agent)

  // ---- Surface + provenance metadata ----
  surface: SurfaceMetadata;

  // ---- Tool annotations: SEEDS, NEVER TRUST (brief §C5, MCP schema.ts MUST) ----
  toolAnnotations?: UntrustedToolAnnotations;
}

export interface Subject {
  // AuthZEN Subject: REQUIRED type,id
  type: "user" | "service";
  id: string; // e.g. "avijeett007@gmail.com"
  properties?: {
    authn?: "os_session" | "jwt_sub" | "unauthenticated";
    tenant?: string; // present even in P1 (schema-forward for P2 org scope)
    [k: string]: unknown;
  };
}

export interface Action {
  // AuthZEN Action: REQUIRED name
  name: string; // fully-qualified verb, e.g. "stripe.create_refund"
  properties?: { mcpMethod?: string; [k: string]: unknown };
}

export interface Resource {
  // AuthZEN Resource: REQUIRED type,id
  type: string; // e.g. "stripe_charge", "github_repo"
  id: string; // e.g. "ch_3P..." or "kno2gether/openclaw"
  properties?: Record<string, unknown>; // conditions material: amount, path, labels...
}

export interface DecisionContext {
  /** COAZ: agent identity lives HERE, sibling to subject — never in subject. [DRAFT-tracked] */
  agent: AgentIdentity;
  env: {
    time: string; // RFC 3339 (profiled subset of ISO 8601, ADR-0017)
    surfaceLocal: boolean; // human-at-keyboard vs remote/unattended
    voiceSession?: boolean; // drives deferred_not_eligible eligibility
    [k: string]: unknown;
  };
  /** Raw tool-call arguments as the surface received them (verbatim; may contain anything the
   *  model sent). Hashed into the SARC normal form (call-hash binding, ADR/brief §I2.3) and into
   *  audit argsHash — NEVER logged raw by default. Optional: surfaces that carry no arguments omit it.
   *  Added 2026-07-03 (P0-E3-T3, R32): restores the plan's hashed-field list for call-hash binding. */
  arguments?: Record<string, unknown>;
}

export interface AgentIdentity {
  id: string; // stable KnoTrust agent id, e.g. "claude-desktop"
  type: "ai_agent" | "workload" | "user"; // AARP client.actor.type vocabulary
  clientId?: string; // OAuth client_id if available (COAZ derives agent from token.client_id)
  model?: string; // advisory only
}

export interface SurfaceMetadata {
  kind: "stdio_proxy" | "http_proxy" | "sdk" | "client_hook" | "sandbox_broker";
  instanceId: string;
  server?: string; // logical MCP server name being fronted
  specVersion?: "2025-11-25" | "2026-07-28"; // MCP spec the surface negotiated
  transport?: "stdio" | "streamable_http";
}

/** Everything here is self-declared by the server and MAY be a lie. */
export interface UntrustedToolAnnotations {
  trusted: false; // literal false — a constant reminder at the type level
  source: "server_advertised";
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  capturedAt?: string; // RFC 3339 (profiled subset of ISO 8601, ADR-0017); from the tools/list snapshot
}

// ---------------------------------------------------------------------------
// Decision outcomes (architecture §3)
// ---------------------------------------------------------------------------

/**
 * The core returns exactly four outcomes ([KNOTRUST], stable; brief §E2).
 * AuthZEN 1.0's core `decision` [STANDARD] is a bare boolean: `allow` maps to
 * `{decision:true}`, `deny` to `{decision:false}`. `pending_approval` and
 * `deferred_not_eligible` are **not first-class AuthZEN decision values** —
 * they are translated only at adapters, never wired directly onto AARP field
 * names.
 *
 * - **`allow`** — permitted; transparent pass-through at the surface.
 * - **`deny`** — blocked; AuthZEN `{decision:false}`, no further semantics.
 * - **`pending_approval`** — blocked for now, held for a human decision via
 *   an AARP-shaped task handle (see `ApprovalHandleRef` below). AARP's
 *   purpose-built mechanism for this is **"Requestable Denial"**
 *   (`decision:false` + `context.access_request`) — the draft's own front
 *   matter abbreviates the profile **"ARAP"** while the OIDF blog says
 *   **"AARP"**; both names refer to the same `[DRAFT]` spec.
 * - **`deferred_not_eligible`** — not resolvable in the current context
 *   (e.g. a critical action mid-voice-call, PRD §10); also not a first-class
 *   AuthZEN value.
 */
export type Outcome =
  | "allow"
  | "deny"
  | "pending_approval"
  | "deferred_not_eligible";

export interface DecisionResponse {
  contractVersion: "1.0";
  requestId: string;
  decisionId: string; // ULID; the audit anchor
  outcome: Outcome;
  tier: "routine" | "sensitive" | "critical";
  reasonCode: string; // machine-stable, e.g. "no_grant_critical", "policy_deny"
  reasonUser?: string; // model-facing, injection-conscious
  reasonAdmin?: string; // audit-only; may name policy ids, matched rules
  approval?: ApprovalHandleRef; // present iff outcome === "pending_approval"
  /** Present iff outcome === "deny" and the denial is requestable (sensitive tier, no covering grant):
   *  actionable, injection-conscious guidance — never policy internals. (R9, P0-E2-T2) */
  requestable?: {
    how: string; // exact CLI invocation template, e.g. `knotrust grant --tool <tool> --server <server>`
  };
  cache: { hit: boolean; ttlSeconds?: number };
  evaluatedBy: "L0" | "cedar" | "authzen_http" | "opa" | "grant";
  latencyMs: number;
}

// ---------------------------------------------------------------------------
// ApprovalHandleRef (orchestrator ruling, P0-E2-T1)
//
// `ApprovalHandleRef` is referenced by `DecisionResponse.approval` above but
// was defined nowhere in the planning corpus. Ruling: define it here.
// `ApprovalState`'s values are verbatim architecture §6.1 (the approval
// orchestrator's internal lifecycle enum) so `@knotrust/approval` reuses the
// same type rather than defining a parallel one.
// ---------------------------------------------------------------------------

export type ApprovalState =
  | "requested"
  | "pending"
  | "approved"
  | "denied"
  | "expired"
  | "cancelled";

/** Core-side reference to an approval task handle (maps to AARP task handle at the adapter). */
export interface ApprovalHandleRef {
  id: string; // "apr_<ULID>"
  state: ApprovalState;
  expiresAt?: string; // RFC 3339 (profiled subset of ISO 8601, ADR-0017); deadline after which the approval resolves as deny
}
