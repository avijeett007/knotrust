/**
 * @knotrust/proxy-stdio — the two-layer, prompt-injection-conscious denial
 * envelope (P0-E5-T4; rulings R74-R77, R79; architecture §3.1/§3.2, brief
 * §I2.2/§I3).
 *
 * `buildDenialEnvelope` replaces E5-T3's basic inline envelope (`enforce.ts`
 * previously synthesized `content`/`structuredContent` ad hoc per outcome).
 * It is a PURE function of a narrow decision view + a tool/server-name
 * context — nothing else. Two layers:
 *
 *   - **Model-visible** (the return value here — `content`/`structuredContent`):
 *     exactly the ingredients architecture §3.2 names — outcome status, tier
 *     class, and "how a human approves." Zero policy internals: no rule ids,
 *     no matched-policy names, no thresholds, no admin-envelope shape, and
 *     NEVER an approval token or a tokened URL (§I2.2 — those go to human
 *     channels only). Every `content[].text` is a FIXED TEMPLATE, selected
 *     by `(outcome, tier-class, requestable-presence, safe-reason-code)` —
 *     it interpolates NOTHING from tool call arguments or server-supplied
 *     strings, with the one narrow exception of `requestable.how`, which
 *     embeds the tool/server NAME (never an argument value) through its own
 *     sanitizing template (see `buildSafeRequestableHow` below, R77).
 *   - **Audit/human** — the FULL rationale (`reasonAdmin`, matched policy id,
 *     precedence layer, grant refs) is a decider/audit-log concern already
 *     handled upstream of this module (`@knotrust/grants`' decider writes
 *     the `type: "decision"` audit event with the real `reasonCode`); this
 *     module never receives or emits any of that.
 *
 * ## Why buildDenialEnvelope recomputes `requestable.how` itself (R77)
 *
 * `DecisionResponse.requestable.how` is already built upstream (core's
 * `l0-evaluator.ts`, `buildRequestableHow`) directly from
 * `request.action.name` — i.e. the RAW, UNTRUSTED tool name the calling
 * agent/server supplied over `tools/call`, with zero sanitization. A
 * hostile tool name (or a compromised server advertising one) could embed
 * newlines and imperative prose designed to read as a KnoTrust-voiced
 * instruction once concatenated into "run: knotrust grant --tool <name>
 * --server <server>". This module therefore treats `decision.requestable`'s
 * PRESENCE as a signal only ("this deny is grant-requestable") and
 * reconstructs the CLI string itself from `ctx.tool`/`ctx.server` — the
 * proxy's own values for THIS call — through `buildSafeRequestableHow`,
 * which strips every non-printable/whitespace/control character before
 * interpolating. This can't make an adversarial tool name harmless prose,
 * but it DOES guarantee it can never break out of the single-line CLI
 * invocation string into something that reads as a new paragraph of
 * instructions — the concrete bar R77 sets ("the name is data in a
 * CLI-invocation string, not prose").
 *
 * ## The fifth template ("unavailable") — a deliberate addition beyond the
 * plan's literal 4 bullets
 *
 * The task brief names four templates (deny-sensitive-requestable,
 * deny-critical/generic, deferred, pending). `audit_unavailable` /
 * `internal_error` / `enforcement_error` denies are qualitatively different
 * from a policy gate — they are a transient/system failure fail-closed to a
 * deny (R40 doctrine), not a "this needs a human's sign-off" situation.
 * Reusing the generic "requires human approval" wording for them would be
 * actively misleading (there is nothing for a human to approve; retrying
 * later, or asking an administrator to look at the audit log, is the actual
 * next step) — so this module gives them their own honest, still fully
 * fixed-template wording, selected by the SAFE reason code (`"unavailable"`)
 * rather than by tier. This folds cleanly under R75's own framing of that
 * code ("transient/system") and keeps the mapping's job — 5 safe codes in,
 * 5 honest templates out — total.
 */

// Imported as TYPES ONLY (erased at build) so the drift-protection in
// `KnownInternalReasonCode` below tracks core's exported unions without
// adding any runtime import beyond what this module needs at the value
// level (none, for these two). `L0ReasonCode`/`PrecedenceReasonCode` are
// exported from `@knotrust/core` as BOTH a value (the `as const` object)
// and a type (the union of its values) under the same name — importing
// only the type half here is deliberate: this module never needs the
// runtime object.
// Fix round 1 (finding 2) moved the leak patterns below out of a
// hand-copied local list into ONE shared source, so this redactor and
// `@knotrust/test-harness`'s scanner (`leak-scan.ts`'s `findLeaks`) can
// never silently drift apart. Fix round 2 (R80) relocated that shared
// source again — from `@knotrust/test-harness` (a TEST package) into
// `@knotrust/core` — because the round-1 placement forced this PRODUCTION
// package to take a real runtime `dependencies` entry on a test package,
// which the published `knotrust` CLI would then bundle wholesale (tsup
// `noExternal: [/^@knotrust\//]`, `packages/cli/tsup.config.ts`): test
// code shipping inside a supply-chain-trust product's own tarball. `core`
// is the neutral home this package already depends on (for
// `DecisionResponse` and the reason-code unions below); see
// `@knotrust/core`'s `leak-patterns.ts` header for the full rationale.
import {
  APPROVAL_TOKEN_HEX_PATTERN,
  APPROVAL_TOKEN_PREFIXED_PATTERN,
  type DecisionResponse,
  type L0ReasonCode as L0ReasonCodeUnion,
  POLICY_INTERNAL_IDENTIFIERS,
  POLICY_INTERNAL_PATTERNS,
  type PrecedenceReasonCode as PrecedenceReasonCodeUnion,
} from "@knotrust/core";
import { AUDIT_UNAVAILABLE } from "@knotrust/store";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

// ---------------------------------------------------------------------------
// R75 — the SAFE reasonCode closed set + the exhaustive internal→safe map.
// ---------------------------------------------------------------------------

/**
 * The ONLY reasonCode values the model ever sees. Closed set (R75): the
 * model learns "blocked, and whether a grant or a human unblocks it" —
 * never WHY at the policy level.
 */
export type SafeReasonCode =
  | "blocked_needs_grant"
  | "blocked_needs_approval"
  | "blocked_by_policy"
  | "unavailable"
  | "not_eligible_here";

/**
 * The internal reason codes this repo currently produces that a denial can
 * carry, typed precisely enough that adding a new DENY-shaped code to
 * `@knotrust/core`'s `L0ReasonCode`/`PrecedenceReasonCode` (the two enums
 * that mix allow-only and deny-shaped members, or deny-only respectively)
 * without adding a matching `case` below fails typecheck — see the
 * `satisfies never` assertion at the bottom of `toSafeReasonCode`.
 *
 * `L0ReasonCode`'s three allow-only members (`routine_default_allow`,
 * `grant_allow`, `explicit_config_allow`) are deliberately EXCLUDED here —
 * `buildDenialEnvelope` is never called for an `allow` outcome, so they can
 * never legitimately reach this function; `Exclude` (rather than hand-
 * copying the two deny-shaped members' literal values) means a FUTURE new
 * L0ReasonCode member is automatically included here and must be handled,
 * the same drift protection this type gives `PrecedenceReasonCode`
 * (imported here as a full union — every one of its members IS deny/hold
 * shaped, so no exclusion is needed).
 *
 * `@knotrust/grants`' `GrantsDecisionReasonCode.GrantReplayed` ("grant_replayed")
 * is deliberately duplicated as a literal below rather than imported — this
 * package's dependency on `@knotrust/grants` is dev-only (used by
 * `enforce.integration.test.ts`, never by production source); importing a
 * grants type into this production module would force it into a real
 * dependency. This mirrors this repo's own established convention for this
 * exact situation (see `packages/store/src/audit-log.ts`'s header on why
 * its `$KNOTRUST_HOME` resolution is "deliberately duplicated (not
 * imported)").
 */
type KnownInternalReasonCode =
  | Exclude<
      L0ReasonCodeUnion,
      "routine_default_allow" | "grant_allow" | "explicit_config_allow"
    >
  | PrecedenceReasonCodeUnion
  | "grant_replayed" // @knotrust/grants' GrantsDecisionReasonCode.GrantReplayed — see header.
  | typeof AUDIT_UNAVAILABLE
  | "internal_error"
  | "enforcement_error"
  | "channel_not_eligible"; // deferred_not_eligible's reasonCode (architecture §3.1's own example).

function assertNever(_x: never): void {
  // Compile-time exhaustiveness guard only; never actually called at
  // runtime because every KnownInternalReasonCode member is handled above.
}

/**
 * Maps an internal, machine-stable reasonCode (from `DecisionResponse` or —
 * looking ahead to E6-T4 — an approval orchestrator's own resolution) to
 * the SAFE, model-visible code (R75). Exhaustive over `KnownInternalReasonCode`
 * (a new internal code added to `@knotrust/core` without a matching case
 * here fails typecheck, via `assertNever` below). Any string OUTSIDE that
 * known set — including an arbitrary orchestrator-supplied reasonCode,
 * which is not yet type-constrained (E6-T4) — degrades safely to the
 * least-revealing catch-all, `"blocked_by_policy"`, rather than throwing:
 * this function must never crash the enforcement path, and revealing
 * nothing is always a safe default.
 */
export function toSafeReasonCode(internalRaw: string): SafeReasonCode {
  const internal = internalRaw as KnownInternalReasonCode;
  switch (internal) {
    case "no_grant_sensitive":
      return "blocked_needs_grant";
    case "no_grant_critical":
    case "envelope_force_approval":
      return "blocked_needs_approval";
    case "envelope_deny":
    case "explicit_config_deny":
    case "tier_cap_violation":
    case "grant_exceeds_envelope":
    case "grant_replayed":
      return "blocked_by_policy";
    case AUDIT_UNAVAILABLE:
    case "internal_error":
    case "enforcement_error":
      return "unavailable";
    case "channel_not_eligible":
      return "not_eligible_here";
    default:
      assertNever(internal);
      return "blocked_by_policy";
  }
}

// ---------------------------------------------------------------------------
// R74 — buildDenialEnvelope inputs.
// ---------------------------------------------------------------------------

/**
 * Exactly what `buildDenialEnvelope` reads off a `DecisionResponse` — never
 * the full contract (never `reasonAdmin`, `reasonUser`, grant refs, cache,
 * evaluatedBy, latencyMs, precedence layer, or any policy id). A real
 * `DecisionResponse` is always assignable here directly (this is a `Pick`);
 * callers synthesizing a decision-shaped value for a case the decider never
 * produces (e.g. `enforce.ts`'s decider-threw fail path, or an approval
 * orchestrator's terminal-deny resolution) only need to construct this
 * narrower shape, not a full `DecisionResponse`.
 */
export type DenialEnvelopeDecision = Pick<
  DecisionResponse,
  "outcome" | "tier" | "reasonCode" | "decisionId" | "requestable" | "approval"
>;

/**
 * The ONLY per-call inputs besides the decision: the tool + (optional)
 * server NAME, for the `requestable.how` CLI template ONLY. Never tool
 * arguments, never any other server-supplied string (R74/R77).
 */
export interface DenialEnvelopeCtx {
  tool: string;
  server?: string;
}

// ---------------------------------------------------------------------------
// R77 — safe, sanitized requestable.how construction.
// ---------------------------------------------------------------------------

const DEFAULT_SERVER_PLACEHOLDER = "<server>";
const MAX_CLI_ARG_LENGTH = 200;

/**
 * Strips every character outside visible, non-whitespace ASCII
 * (`\x21`-`\x7e`) and truncates to `MAX_CLI_ARG_LENGTH`. This is what
 * defeats a hostile tool/server name (R77): no newline, carriage return,
 * tab, or other control/whitespace character can survive to let the
 * argument visually "escape" the single-line CLI-invocation sentence it
 * sits inside — the residual (a same-line run of printable characters that
 * still spells out English words) is an accepted, documented residual risk
 * exactly as R77 frames it: "the name is data in a CLI-invocation string,
 * not prose," and prose confined to one unbroken line inside `--tool <...>`
 * cannot read as a new instruction the way a blank-line-separated paragraph
 * could.
 */
function sanitizeForCliArg(raw: string): string {
  const stripped = Array.from(raw)
    .map((ch) => (ch >= "\x21" && ch <= "\x7e" ? ch : ""))
    .join("");
  return stripped.slice(0, MAX_CLI_ARG_LENGTH);
}

/**
 * Defense in depth, beyond the newline/control-char strip above: a hostile
 * (or merely coincidentally-named) tool/server could itself be NAMED after
 * one of R75's internal reason codes, after the token shape
 * `@knotrust/test-harness`'s global frame-scan (`findLeaks`,
 * `assertNoLeakedSecrets`) watches for, or after one of the scanner's
 * generic rule/policy/pack-id-shaped identifier patterns — e.g. a tool
 * literally called `tier_cap_violation_probe`, or one literally named
 * `rule-id` (fix round 1, finding 2: this exact name used to survive this
 * function's OLD hand-copied list, reach `requestable.how` verbatim, and
 * then make `assertNoLeakedSecrets` throw downstream — a false positive on
 * an otherwise-correct envelope). The mechanical frame-scan makes no
 * attribution distinction between "the system leaked this" and "the
 * attacker's own chosen name happens to contain this" — its bar is
 * unconditional zero occurrences (R76) — so this function closes that gap
 * unconditionally too, rather than leaving it as a documented residual
 * risk.
 *
 * Fix round 1 (finding 2): every pattern/identifier below is now IMPORTED
 * from a shared source — the same one the scanner (`leak-scan.ts`'s
 * `findLeaks`) consumes — instead of a hand-copied local list. The two
 * could (and did) drift; consuming one shared source makes that a
 * compile-time/import-time fact, not a manual "update both together"
 * reminder. Fix round 2 (R80) moved that shared source from
 * `@knotrust/test-harness` to `@knotrust/core` (imported below from
 * `@knotrust/core` directly) so this production module never runtime-
 * depends on a test package — see the import header above.
 */
const REDACTED_MARKER = "REDACTED";

function redactLeakShapedSubstrings(input: string): string {
  let out = input;
  for (const identifier of POLICY_INTERNAL_IDENTIFIERS) {
    out = out.split(identifier).join(REDACTED_MARKER);
  }
  for (const pattern of [
    APPROVAL_TOKEN_PREFIXED_PATTERN,
    APPROVAL_TOKEN_HEX_PATTERN,
    ...POLICY_INTERNAL_PATTERNS,
  ]) {
    pattern.lastIndex = 0; // these are shared `g`-flagged RegExp objects — reset before reuse.
    out = out.replace(pattern, REDACTED_MARKER);
  }
  return out;
}

function sanitizeToolOrServerName(raw: string): string {
  return redactLeakShapedSubstrings(sanitizeForCliArg(raw));
}

function buildSafeRequestableHow(ctx: DenialEnvelopeCtx): string {
  const tool = sanitizeToolOrServerName(ctx.tool);
  const server =
    ctx.server !== undefined && ctx.server.trim() !== ""
      ? sanitizeToolOrServerName(ctx.server)
      : DEFAULT_SERVER_PLACEHOLDER;
  return `knotrust grant --tool ${tool} --server ${server}`;
}

// ---------------------------------------------------------------------------
// Fixed templates (R74). Every string below is FULLY FIXED at the call
// site — no template ever concatenates raw tool-call arguments or raw
// server-supplied strings; `tierClass` is a closed 3-value enum (safe to
// interpolate) and `how` is always the already-sanitized CLI string above.
// ---------------------------------------------------------------------------

const HUMAN_APPROVAL_HINT =
  "Approve via the KnoTrust prompt or `knotrust approvals`";

function textDenySensitiveRequestable(tierClass: string, how: string): string {
  return (
    `This action was blocked (${tierClass} tier) and was not performed. ` +
    `A human can approve it via the KnoTrust prompt or \`knotrust approvals\`. ` +
    `To request access, run: ${how}. ` +
    `Do not retry automatically — tell the user it needs approval.`
  );
}

function textDenyGeneric(tierClass: string): string {
  return (
    `This action was blocked (${tierClass} tier) and requires human approval; ` +
    `it was not performed. A human can approve it via the KnoTrust prompt or ` +
    `\`knotrust approvals\`. Do not retry automatically — tell the user it needs approval.`
  );
}

function textUnavailable(): string {
  return (
    `This tool call could not be evaluated by KnoTrust and was blocked; it was not performed. ` +
    `This is likely a transient system issue — you may retry shortly, or tell the user to ` +
    `contact an administrator if it persists.`
  );
}

function textPendingApproval(tierClass: string): string {
  return (
    `This action is awaiting human approval and has not been performed yet (${tierClass} tier). ` +
    `You may tell the user approval is pending. Do not retry until it is approved.`
  );
}

const TEXT_DEFERRED =
  "This action is not available in the current context and cannot be approved here. " +
  "Let the user know they can perform or approve it later from a KnoTrust-enabled surface.";

// ---------------------------------------------------------------------------
// buildDenialEnvelope (R74).
// ---------------------------------------------------------------------------

/**
 * Builds the model-visible `CallToolResult` (`isError: true`) for a
 * deny/pending_approval/deferred_not_eligible decision. Pure: the same
 * `(decision, ctx)` pair always produces byte-identical output — this is
 * exactly the property R78's probing-detection acceptance relies on (the
 * Nth denial's envelope is identical to the 1st; detection is audit-only).
 *
 * The caller (`enforce.ts`) is responsible for wrapping this in the
 * JSON-RPC envelope with the request's own `id` — this function has no
 * `id` parameter because `id` correlation is a transport concern, not a
 * denial-content concern (R74).
 */
export function buildDenialEnvelope(
  decision: DenialEnvelopeDecision,
  ctx: DenialEnvelopeCtx,
): CallToolResult {
  const safeReasonCode = toSafeReasonCode(decision.reasonCode);
  const auditRef = decision.decisionId;

  if (decision.outcome === "deny") {
    if (safeReasonCode === "unavailable") {
      return {
        isError: true,
        content: [{ type: "text", text: textUnavailable() }],
        structuredContent: {
          knotrust: {
            outcome: "deny",
            decisionId: decision.decisionId,
            tierClass: decision.tier,
            reasonCode: safeReasonCode,
            retryable: true,
            humanApproval: { possible: false, hint: HUMAN_APPROVAL_HINT },
            auditRef,
          },
        },
      };
    }

    if (decision.requestable !== undefined) {
      const how = buildSafeRequestableHow(ctx);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: textDenySensitiveRequestable(decision.tier, how),
          },
        ],
        structuredContent: {
          knotrust: {
            outcome: "deny",
            decisionId: decision.decisionId,
            tierClass: decision.tier,
            reasonCode: safeReasonCode,
            retryable: false,
            humanApproval: { possible: true, hint: HUMAN_APPROVAL_HINT },
            requestable: { how },
            auditRef,
          },
        },
      };
    }

    return {
      isError: true,
      content: [{ type: "text", text: textDenyGeneric(decision.tier) }],
      structuredContent: {
        knotrust: {
          outcome: "deny",
          decisionId: decision.decisionId,
          tierClass: decision.tier,
          reasonCode: safeReasonCode,
          retryable: false,
          humanApproval: { possible: true, hint: HUMAN_APPROVAL_HINT },
          auditRef,
        },
      },
    };
  }

  if (decision.outcome === "pending_approval") {
    const approvalId = decision.approval?.id;
    return {
      isError: true,
      content: [{ type: "text", text: textPendingApproval(decision.tier) }],
      structuredContent: {
        knotrust: {
          outcome: "pending_approval",
          decisionId: decision.decisionId,
          tierClass: decision.tier,
          reasonCode: safeReasonCode,
          retryable: true,
          humanApproval: { possible: true, hint: HUMAN_APPROVAL_HINT },
          ...(approvalId !== undefined ? { approvalId } : {}),
          auditRef,
        },
      },
    };
  }

  if (decision.outcome === "deferred_not_eligible") {
    return {
      isError: true,
      content: [{ type: "text", text: TEXT_DEFERRED }],
      structuredContent: {
        knotrust: {
          outcome: "deferred_not_eligible",
          decisionId: decision.decisionId,
          tierClass: decision.tier,
          reasonCode: safeReasonCode,
          retryable: false,
          humanApproval: {
            possible: false,
            hint: "Not approvable from this context; use a KnoTrust-enabled surface.",
          },
          auditRef,
        },
      },
    };
  }

  // decision.outcome === "allow" here (the one Outcome member not already
  // handled and returned above) — a programming error at the call site
  // (buildDenialEnvelope must never be invoked for an allow), not a
  // runtime/policy condition. Fail loudly rather than silently emitting a
  // nonsensical denial for an allowed call.
  throw new Error(
    `buildDenialEnvelope: unexpected outcome "${decision.outcome}" — this function must never be called for "allow"`,
  );
}
