/**
 * @knotrust/grants — durable + ephemeral grant lifecycle with call-hash
 * binding (P0-E3-T3, ruling R34).
 *
 * This is the layer that composes three lower pieces into the product's
 * TOCTOU-closing authorization path:
 *
 * - **mint** (E3-T2, `mint.ts`) — signs a grant token.
 * - **verify** (E3-T2, `verify.ts`) — offline-verifies a token against a
 *   concrete `DecisionRequest`, including the call-hash gate.
 * - **the file store** (E4-T1, `@knotrust/store`) — persists grant tokens and
 *   owns the `wx`-atomic consumed-`jti` ledger (the replay primitive).
 * - **precedence** (E2-T3, `@knotrust/core`) — turns a covering-grant set into
 *   a decision under the admin envelope.
 *
 * ## Two mint paths over one format
 *
 * - `mintDurableGrant` — a user pre-authorization: multi-use, explicit `exp`,
 *   NO `su`, NO `ch`.
 * - `mintEphemeralGrant` — minted by the approval orchestrator the instant a
 *   human approves: `su: true`, short `exp` (default **120 s**, architecture
 *   §5.2/Appendix B — headroom for URL-mode / pending redemption), and
 *   `ch = computeCallHash(request)` bound to the EXACT approved call.
 *
 * ## The E4-T1 `listBy` warning (heeded here)
 *
 * `collectCoveringGrants` fetches candidates via `store.list()` — UNFILTERED.
 * The store's `listBy({ tool })` is EXACT-STRING match and would silently drop
 * every glob-scoped grant (`github.*`), a false-deny footgun. Glob/pattern
 * matching against the concrete call is `verifyGrant`'s job, run per-candidate
 * here — never the store's.
 *
 * ## Consume-is-atomic-with-the-decision (the exactly-once algorithm)
 *
 * `decideWithGrants` documents and implements the atomicity: a single-use
 * grant is a pre-satisfied prerequisite (PRD §7) consumed exactly when — and
 * only when — it is the grant that decides an `allow`. Under racing processes
 * the store's `wx` gate arbitrates: the loser re-decides with that grant
 * excluded, yielding a stable `grant_replayed` deny rather than a double-spend.
 */

import type {
  AdminEnvelope,
  CoveringGrant,
  DecisionRequest,
  PrecedenceDecision,
  Tier,
  TierPolicy,
} from "@knotrust/core";
import { evaluatePrecedence, resolveTierWithEnvelope } from "@knotrust/core";
import type {
  AuditSink,
  DecodeIndexEntry,
  GrantIndexEntry,
  GrantStore,
} from "@knotrust/store";
import {
  AUDIT_UNAVAILABLE,
  AuditEventType,
  AuditUnavailableError,
  computeArgsHash,
} from "@knotrust/store";
import { computeCallHash } from "./callhash.js";
import type { GrantClaims } from "./claims.js";
import { parseWireClaims } from "./claims.js";
import type { Ed25519PublicJwk, KeyStore } from "./keys.js";
import { type MintGrantInput, mintGrant } from "./mint.js";
import {
  GrantRejectionReason,
  toCoveringGrant,
  verifyGrant,
} from "./verify.js";

// ---------------------------------------------------------------------------
// Grants-layer decision reason codes — extends core's precedence reasons with
// the one this layer introduces. Kept as a machine-stable const-object union,
// mirroring `GrantRejectionReason` / `PrecedenceReasonCode`.
// ---------------------------------------------------------------------------

export const GrantsDecisionReasonCode = {
  /**
   * A single-use grant that WOULD have allowed this call was already consumed
   * (its `jti` is in the store's consumed ledger) and no other grant/config
   * independently authorizes the call. The exact code the acceptance demands
   * on the second attempt with the same `jti`. Overrides the tier-default
   * reason of the grant-excluded re-run.
   */
  GrantReplayed: "grant_replayed",
} as const;

export type GrantsDecisionReasonCode =
  (typeof GrantsDecisionReasonCode)[keyof typeof GrantsDecisionReasonCode];

/**
 * A `PrecedenceDecision` whose `reasonCode` is widened to also admit the
 * grants-layer `grant_replayed` code (which core's precedence engine has no
 * knowledge of — it is minted HERE when the consumed ledger overrides an
 * otherwise-allowing grant decision) AND `@knotrust/store`'s
 * `AUDIT_UNAVAILABLE` constant (P0-E3-T4, R40) — the fail-closed deny
 * `decideWithGrants` resolves to when an `audit` sink is wired and its
 * `append()` throws `AuditUnavailableError`. `typeof AUDIT_UNAVAILABLE`
 * rather than a third grants-layer const-object member because the exact
 * string is store's own exported constant (R40: "use the exported
 * constant") — redeclaring it here would risk the two literals drifting.
 */
export interface GrantedDecision
  extends Omit<PrecedenceDecision, "reasonCode"> {
  reasonCode:
    | PrecedenceDecision["reasonCode"]
    | GrantsDecisionReasonCode
    | typeof AUDIT_UNAVAILABLE;
}

/** A candidate grant that did not satisfy the call — audit-only, never model-visible. */
export interface RejectedGrant {
  jti: string;
  reason: GrantRejectionReason;
}

// ---------------------------------------------------------------------------
// Store index decoder (R29 seam) — decodes a token's wire payload into the
// store's index fields WITHOUT verifying its signature. The store is the
// lower layer and treats tokens as opaque; this is how the grants layer
// teaches it to extract `jti`/`tool`/`agentId`. Never throws (a garbage token
// resolves to `null`, the store's only `grant_invalid` signal).
// ---------------------------------------------------------------------------

/**
 * Exported (P0-E3-T4) so `revoke.ts` can decode a grant token's claims for
 * audit purposes without duplicating this parsing — both files live in this
 * same package, so re-exporting rather than copying is the natural choice
 * here (contrast the cross-PACKAGE `resolveKnotrustHome` duplication
 * convention documented in `@knotrust/store`'s `grant-store.ts`/`keys.ts`,
 * which exists specifically because THOSE two files must not depend on each
 * other's package).
 */
export function decodeGrantPayload(token: string): unknown {
  const segments = token.split(".");
  if (segments.length !== 3) return undefined;
  const payloadSeg = segments[1];
  if (payloadSeg === undefined || payloadSeg.length === 0) return undefined;
  try {
    return JSON.parse(
      Buffer.from(payloadSeg, "base64url").toString("utf8"),
    ) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * The `DecodeIndexEntry` a `@knotrust/store` `GrantStore` must be constructed
 * with when it backs this lifecycle. Decodes the JWS payload's short-name
 * claims (`claims.ts`) into `{ jti, tool, agentId }`; `agentId` is `null` for
 * a wildcard (`ag: "*"`) grant. Signature verification is NOT done here (R29)
 * — that is `verifyGrant`'s job, upstream of the store in
 * `collectCoveringGrants`.
 */
export const decodeGrantIndexEntry: DecodeIndexEntry = (
  token: string,
): GrantIndexEntry | null => {
  const claims = parseWireClaims(decodeGrantPayload(token));
  if (claims === null) return null;
  const agentId = claims.agent === "*" ? null : claims.agent.id;
  return { jti: claims.jti, tool: claims.tool, agentId };
};

// ---------------------------------------------------------------------------
// Mint paths
// ---------------------------------------------------------------------------

export interface LifecycleMintDeps {
  store: GrantStore;
  keyStore: KeyStore;
  /** Injected clock (epoch seconds) — never `Date.now()`. */
  nowEpochSeconds: number;
  /** Injected id source — core's ULID generator in production. */
  generateId(): string;
  /**
   * Optional audit sink (P0-E3-T4, R40). When present, a successful mint
   * appends exactly one `grant_created` event AFTER `store.put` succeeds
   * (never before — an event for a grant that was never actually persisted
   * would misrepresent store state). Unlike `decideWithGrants`, mint has no
   * "fail-closed to a deny" fallback to convert to on an audit failure — a
   * mint is not a decision — so an `AuditUnavailableError` from `append()`
   * here propagates to the caller as-is (mirroring `mint.ts`'s own posture:
   * mint is not an adversarial surface, and a loud throw is the right
   * failure — see that module's header). The grant is still durably
   * persisted in the store even if this throws; only the audit trail entry
   * is missing, exactly the gap `AuditUnavailableError`/`audit_recovered`
   * exist to make discoverable (`@knotrust/store`'s audit-log.ts header).
   */
  audit?: AuditSink;
}

export interface MintResult {
  token: string;
  jti: string;
}

/** `grant_created`/`grant_revoked`/`grant_consumed` events all originate from this layer, independent of any live `DecisionRequest.surface` (mint/revoke are not decisions) — see `revoke.ts`'s identical constant. */
const GRANTS_AUDIT_SURFACE = "grants";

/**
 * Appends one `grant_created` audit event (R40) for a freshly-persisted
 * grant. `subject` = `principal.id`, `agent` = the agent id or `"*"` for a
 * wildcard grant, `grantRefs` = `[jti]`. `kind` (durable/ephemeral) has no
 * dedicated `AuditEvent` field, so it rides in `reason` (R40: "kind via
 * reason or a kind note in reason field") — kept short and machine-parseable
 * (`"kind=durable"` / `"kind=ephemeral"`) rather than prose. `argsHash` has
 * no natural "arguments" for a mint event, so it is `computeArgsHash(null)`
 * — the same convention `@knotrust/store`'s own internally-generated
 * `audit_recovered` event uses for the identical reason.
 */
function auditGrantCreated(
  audit: AuditSink | undefined,
  claims: GrantClaims,
): void {
  if (!audit) return;
  audit.append({
    type: AuditEventType.GRANT_CREATED,
    surface: GRANTS_AUDIT_SURFACE,
    subject: claims.principal.id,
    agent: claims.agent === "*" ? "*" : claims.agent.id,
    tool: claims.tool,
    argsHash: computeArgsHash(null),
    reason: `kind=${claims.kind}`,
    grantRefs: [claims.jti],
  });
}

/** Durable mint input: everything `mintGrant` needs EXCEPT the derived `kind`/`callHash`. */
export type MintDurableGrantInput = Omit<MintGrantInput, "kind" | "callHash">;

/**
 * Mints a DURABLE grant (kind `durable`, explicit `ttl`, no `su`, no `ch`) and
 * persists it via `store.put`. Durable = a standing pre-authorization written
 * by `knotrust grant ...`; the fast-path enabler (architecture §5.3).
 */
export async function mintDurableGrant(
  input: MintDurableGrantInput,
  deps: LifecycleMintDeps,
): Promise<MintResult> {
  const minted = await mintGrant(
    { ...input, kind: "durable" },
    {
      keyStore: deps.keyStore,
      nowEpochSeconds: deps.nowEpochSeconds,
      generateId: deps.generateId,
    },
  );
  const result = persist(deps.store, minted.token, minted.claims.jti);
  auditGrantCreated(deps.audit, minted.claims);
  return result;
}

export interface MintEphemeralGrantInput {
  /** The EXACT approved call; every hashed field is snapshotted into `ch` here. */
  request: DecisionRequest;
  /** The resolved tier the approval authorized (the grant's `tierCap`). */
  tier: Tier;
  /** Grant lifetime; default 120 s (architecture §5.2/Appendix B). */
  ttlSeconds?: number;
  /** Policy scope that minted it (schema-forward, brief §E7). Default `"personal"`. */
  envelopeScope?: "personal" | "org";
}

/**
 * Mints an EPHEMERAL grant on approval: kind `ephemeral`, `su: true`,
 * `ch = computeCallHash(request)` computed HERE from the frozen request
 * snapshot, and short `exp` (default **120 s** per architecture §5.2/Appendix
 * B — headroom for URL-mode / pending redemption). Scoped tightly to the
 * approved call's principal/agent/tool/resource.id. Persists via `store.put`.
 *
 * The call-hash is what makes this "one approval for THIS call," not "one free
 * critical call": at execution `verifyGrant` re-derives the hash and requires
 * an exact match (brief §I2.3).
 */
export async function mintEphemeralGrant(
  input: MintEphemeralGrantInput,
  deps: LifecycleMintDeps,
): Promise<MintResult> {
  const { request } = input;
  const minted = await mintGrant(
    {
      kind: "ephemeral",
      principal: { type: request.subject.type, id: request.subject.id },
      agent: {
        id: request.context.agent.id,
        type: request.context.agent.type,
      },
      tool: request.action.name,
      scope: {
        resourceType: request.resource.type,
        idPattern: request.resource.id,
      },
      tier: input.tier,
      envelopeScope: input.envelopeScope ?? "personal",
      ttlSeconds: input.ttlSeconds ?? 120,
      callHash: computeCallHash(request),
    },
    {
      keyStore: deps.keyStore,
      nowEpochSeconds: deps.nowEpochSeconds,
      generateId: deps.generateId,
    },
  );
  const result = persist(deps.store, minted.token, minted.claims.jti);
  auditGrantCreated(deps.audit, minted.claims);
  return result;
}

/**
 * Persists a freshly-minted token. A `put` decode failure here is a
 * programmer/environment error (the token was just produced by `mintGrant` and
 * decodes with `decodeGrantIndexEntry` by construction), so it throws loudly
 * rather than being swallowed — contrast the fail-closed verify path.
 */
function persist(store: GrantStore, token: string, jti: string): MintResult {
  const result = store.put(token);
  if (!result.ok) {
    throw new Error(
      `mint: store.put rejected a freshly-minted grant (jti=${jti}, reason=${result.reason}) — this should be impossible`,
    );
  }
  return { token, jti: result.jti };
}

// ---------------------------------------------------------------------------
// collectCoveringGrants — the candidate gather + per-grant verify pass
// ---------------------------------------------------------------------------

export interface CollectCoveringGrantsContext {
  store: GrantStore;
  /**
   * The tier the tool resolved to; each candidate's `tierCap` must cover it.
   * MUST equal the tier `resolveTierWithEnvelope` will re-resolve for the
   * SAME request/policy/envelope (true by construction when called via
   * `decideWithGrants`, which resolves once and passes that exact value
   * here) — a caller other than `decideWithGrants` that supplies a
   * mismatched tier can let a tier-cap pass-through grant (R35's
   * `tier_cap_violation` handling above) produce a consumable allow instead
   * of the ratified loud deny; that invariant is on such callers, not
   * enforced by this function.
   */
  resolvedTier: Tier;
  /** Injected clock (epoch seconds). */
  nowEpochSeconds: number;
  resolvePublicKey(kid: string): Ed25519PublicJwk | null;
}

export interface CollectCoveringGrantsResult {
  /** Grants that verified AND cover the call — fed to `evaluatePrecedence`. */
  coveringGrants: CoveringGrant[];
  /**
   * The `jti`s among `coveringGrants` whose `singleUse` claim is `true`.
   * `decideWithGrants` consults this to know which deciding `grantRef` must be
   * consumed atomically. (Not part of the `CoveringGrant` shape, which core
   * intentionally keeps free of single-use semantics.)
   */
  singleUseJtis: Set<string>;
  /** Candidates that did not satisfy the call — audit-only, never model-visible. */
  rejected: RejectedGrant[];
}

/**
 * Loads ALL active grant tokens from the store (unfiltered — see the module
 * header's `listBy` warning) and runs `verifyGrant` on each against the
 * concrete `request`, passing `callHash = computeCallHash(request)` so the
 * ephemeral call-hash gate is enforced. Tombstoned grants are already excluded
 * by the store (`list()` never returns revoked jtis — architecture §5.4:
 * treated as absent, not a model-visible deny). Undecodable/tampered files the
 * store surfaces under `invalid` are folded into `rejected` as `grant_malformed`
 * for audit.
 *
 * ## Precedence is the single tier-cap authority in composition (R35)
 *
 * Every `verifyGrant` rejection is treated as grant-ABSENCE (folded into
 * `rejected`, audit-only) EXCEPT `tier_cap_violation`. A sub-tier-cap grant is
 * a live self-escalation attempt, and the ratified LOUD deny for it (R15,
 * fixture-locked) lives in the precedence engine, not here. So such a grant is
 * rebuilt into a `CoveringGrant` (from its decoded claims) and PUSHED into
 * `coveringGrants` — precedence then re-derives and fires `tier_cap_violation`
 * from the covering-grant set. Were it folded into `rejected` instead (its
 * pre-R35 fate), that ratified deny would be dead code in composition and the
 * decision would silently flip toward allow/pending. The R35 verify check order
 * (call-hash BEFORE tier-cap, `verify.ts`) guarantees any grant reaching this
 * pass-through is already bound to THIS exact call. A single-use such grant is
 * intentionally NOT added to `singleUseJtis`: it can only produce a precedence
 * deny, never a consumable allow.
 *
 * ## Call-hash unavailable — fail closed (R35)
 *
 * The `callHash` is computed ONCE, not per candidate. If the live request is
 * non-canonicalizable (a bigint/undefined/function/symbol/non-finite in
 * `arguments`/`resource.properties` makes `canonicalizeJcs` throw), the hash is
 * treated as UNAVAILABLE and no exception escapes: ephemeral (ch-carrying)
 * grants fail the call-hash gate (`grant_call_mismatch`), durable grants are
 * unaffected.
 */
export function collectCoveringGrants(
  request: DecisionRequest,
  ctx: CollectCoveringGrantsContext,
): CollectCoveringGrantsResult {
  let callHash: string | undefined;
  try {
    callHash = computeCallHash(request);
  } catch {
    // Non-canonicalizable request → call-hash unavailable; fail closed (see
    // the doc-comment). Ephemeral grants will fail their `ch` gate below.
    callHash = undefined;
  }

  const coveringGrants: CoveringGrant[] = [];
  const singleUseJtis = new Set<string>();
  const rejected: RejectedGrant[] = [];

  const listed = ctx.store.list();

  for (const record of listed.active) {
    const result = verifyGrant(record.token, {
      request,
      resolvedTier: ctx.resolvedTier,
      nowEpochSeconds: ctx.nowEpochSeconds,
      ...(callHash !== undefined ? { callHash } : {}),
      resolvePublicKey: ctx.resolvePublicKey,
    });

    if (result.ok) {
      coveringGrants.push(result.coveringGrant);
      if (result.claims.singleUse) {
        singleUseJtis.add(result.claims.jti);
      }
      continue;
    }

    // R35: a tier_cap_violation is a live self-escalation attempt, NOT an
    // absence — pass it through so precedence fires the ratified loud deny
    // (R15). Every OTHER rejection reason stays absent (audit-only).
    if (result.reason === "tier_cap_violation") {
      const passthrough = coveringGrantFromToken(record.token);
      if (passthrough !== null) {
        coveringGrants.push(passthrough);
        continue;
      }
      // Unreachable in practice (verifyGrant already decoded these bytes);
      // fall through to fail-closed absence if the re-decode somehow fails.
    }

    rejected.push({ jti: record.jti, reason: result.reason });
  }

  // Tampered/undecodable files the store already flagged: absent for
  // authorization, surfaced for audit as grant_malformed.
  for (const bad of listed.invalid) {
    rejected.push({ jti: bad.jti, reason: GrantRejectionReason.Malformed });
  }

  return { coveringGrants, singleUseJtis, rejected };
}

/**
 * Rebuilds the `CoveringGrant` projection (kind, tierCap, exp, nbf, jti) from a
 * grant token's decoded wire claims. Used ONLY for the R35 `tier_cap_violation`
 * pass-through, where `verifyGrant` has already verified the Ed25519 signature
 * over these exact bytes, so the decoded claims are trustworthy. Returns `null`
 * only if the payload fails to decode — unreachable on that path (guarded
 * defensively so a decode surprise fails closed as absence, never throws).
 */
function coveringGrantFromToken(token: string): CoveringGrant | null {
  const claims = parseWireClaims(decodeGrantPayload(token));
  if (claims === null) return null;
  // M2 (P0-E5-T3): reuse verify.ts's single `toCoveringGrant` projection rather
  // than an inline duplicate that could drift from it.
  return toCoveringGrant(claims);
}

// ---------------------------------------------------------------------------
// decideWithGrants — consume-is-atomic-with-the-decision
// ---------------------------------------------------------------------------

export interface DecideWithGrantsContext {
  tierPolicy: TierPolicy;
  envelope?: AdminEnvelope;
  /** Injected clock (epoch seconds). */
  nowEpochSeconds: number;
  resolvePublicKey(kid: string): Ed25519PublicJwk | null;
}

export interface DecideWithGrantsDeps {
  store: GrantStore;
  /**
   * Optional audit sink (P0-E3-T4, R40) — THE SEAM P0-E5 ENFORCES. When
   * present, EVERY call appends exactly one `type: "decision"` event
   * (surface/subject/agent/tool from the request, `argsHash` via
   * `computeArgsHash(request.context.arguments)`, outcome, reason,
   * grantRefs), and the consume path additionally appends one
   * `grant_consumed` event when a single-use grant is consumed. Critical-
   * tier events pass `{ fsync: "immediate" }` (R38).
   *
   * **Fail closed (R38/D6, ratified):** if the append throws
   * `AuditUnavailableError`, the decision — whatever it was — resolves
   * `deny` with reasonCode `audit_unavailable` (`@knotrust/store`'s
   * exported `AUDIT_UNAVAILABLE` constant); that deny is then itself
   * audited best-effort (a second failure is swallowed — the deny stands
   * regardless). An ungoverned-but-unaudited allow is the worst outcome for
   * a product whose pitch is "fully audited."
   *
   * When absent, behavior is byte-for-byte unchanged from E3-T3 — audit
   * here is OPTIONAL by design because mandatory, always-on wiring is the
   * PROXY's obligation, not this library's: P0-E5-T3 (stdio proxy decision
   * path) and P0-E5-T5 (the deny/`audit_unavailable` proxy composition
   * hook) construct the sink and pass it unconditionally.
   */
  audit?: AuditSink;
}

export interface DecideWithGrantsResult {
  decision: GrantedDecision;
  /** The single-use grant `jti` this decision consumed, if any (audit anchor). */
  consumedJti?: string;
  /** Candidate grants that did not satisfy the call — audit-only, never model-visible. */
  rejected: RejectedGrant[];
}

/**
 * Evaluates a request against the persisted grant set AND consumes the
 * deciding single-use grant atomically with the decision.
 *
 * Algorithm (R34):
 *   1. Resolve the tier (envelope-aware, floor-clamped — the SAME resolution
 *      `evaluatePrecedence` uses), collect covering grants, run precedence.
 *   2. If the decision is `allow` whose `grantRef` is a SINGLE-USE grant's
 *      `jti`, `store.consumeOnce(jti)`:
 *        - `"consumed"` → this call won the race; the decision stands.
 *        - `"already_consumed"` → re-run precedence with that grant excluded.
 *          If the re-run still allows (another grant/config, incl. another
 *          single-use grant which is then itself consumed), return that;
 *          otherwise return `deny` with `grant_replayed` (overriding the
 *          tier-default reason).
 *   3. Non-single-use deciding grants (durable) and non-grant decisions
 *      (routine allow, config allow/deny, pending_approval): NO consumption.
 *
 * This is exactly-once under racing processes: the store's `wx` gate is the
 * single arbiter; the loser re-decides and never double-spends.
 *
 * Audit wiring (P0-E3-T4, R40): the decision itself is computed by
 * `decideCore` below, unchanged from E3-T3; this wrapper appends the
 * `grant_consumed` (when a single-use grant was consumed) and `decision`
 * events and applies the fail-closed `audit_unavailable` conversion — see
 * `DecideWithGrantsDeps.audit` for the full contract and the E5-T3/T5 seam
 * note.
 */
export function decideWithGrants(
  request: DecisionRequest,
  ctx: DecideWithGrantsContext,
  deps: DecideWithGrantsDeps,
): DecideWithGrantsResult {
  const result = decideCore(request, ctx, deps);
  const audit = deps.audit;
  if (audit === undefined) {
    return result;
  }

  // R38: critical-tier events are fsynced synchronously before the decision
  // resolves — a crash right after a critical allow must not lose the line.
  const appendOpts =
    result.decision.tier === "critical"
      ? ({ fsync: "immediate" } as const)
      : undefined;
  const argsHash = computeArgsHash(request.context.arguments);

  try {
    if (result.consumedJti !== undefined) {
      audit.append(
        {
          type: AuditEventType.GRANT_CONSUMED,
          surface: request.surface.kind,
          subject: request.subject.id,
          agent: request.context.agent.id,
          tool: request.action.name,
          argsHash,
          reason: "single_use_consumed",
          grantRefs: [result.consumedJti],
        },
        appendOpts,
      );
    }
    audit.append(decisionEvent(request, argsHash, result.decision), appendOpts);
    return result;
  } catch (err) {
    if (!(err instanceof AuditUnavailableError)) throw err;
    // Fail closed (R40): the audit trail could not record this decision, so
    // the decision the caller sees is a deny — even if `decideCore` allowed,
    // and even if a single-use grant was already burned by the consume step
    // (`consumedJti` stays reported honestly; the wx marker on disk is the
    // truth and un-consuming is not a thing). The deny itself is then
    // audited best-effort: if the sink recovered in the interim the trail
    // shows the deny; if not, the second failure is swallowed and the deny
    // stands regardless.
    const denied: DecideWithGrantsResult = {
      decision: auditUnavailableDeny(result.decision),
      ...(result.consumedJti !== undefined
        ? { consumedJti: result.consumedJti }
        : {}),
      rejected: result.rejected,
    };
    try {
      audit.append(
        decisionEvent(request, argsHash, denied.decision),
        appendOpts,
      );
    } catch {
      // Best-effort by contract (R40) — see the comment above.
    }
    return denied;
  }
}

/** Builds the one `type: "decision"` audit event every audited decision appends (R40; field shape per R37). */
function decisionEvent(
  request: DecisionRequest,
  argsHash: string,
  decision: GrantedDecision,
): Parameters<AuditSink["append"]>[0] {
  return {
    type: AuditEventType.DECISION,
    surface: request.surface.kind,
    subject: request.subject.id,
    agent: request.context.agent.id,
    tool: request.action.name,
    argsHash,
    outcome: decision.outcome,
    reason: decision.reasonCode,
    ...(decision.grantRef !== undefined
      ? { grantRefs: [decision.grantRef] }
      : {}),
  };
}

/**
 * Converts a computed decision into the fail-closed `audit_unavailable`
 * deny (R40). Keeps the resolved `tier`, the deciding `precedenceLayer`,
 * and any tier-clamp audit trail from the original decision (they describe
 * what WAS decided before the audit failure converted it); drops
 * `grantRef`/`requestable`/`wantsApproval` — an unauditable call is a hard
 * deny, never an allow anchor or a "go request a grant" nudge.
 */
function auditUnavailableDeny(original: GrantedDecision): GrantedDecision {
  return {
    outcome: "deny",
    tier: original.tier,
    reasonCode: AUDIT_UNAVAILABLE,
    precedenceLayer: original.precedenceLayer,
    ...(original.clamped !== undefined ? { clamped: original.clamped } : {}),
  };
}

/**
 * The unaudited E3-T3 decision algorithm — see `decideWithGrants`'s
 * doc-comment above.
 *
 * Exported (P0-E5-T3, R68) so the unified canonical decider (`decider.ts`)
 * can reuse the EXACT collect → precedence → consume/replay algorithm this
 * function implements, and own the audit + cache + envelope-assembly around
 * it itself (with `latencyMs`/`cacheHit`/fail-closed conversion the decider
 * needs but this pure step must not). `decideWithGrants` continues to wrap
 * this with its own audit exactly as before (its 180+ tests are untouched):
 * this export is purely additive — same body, same behavior, now reachable
 * by two callers instead of one.
 */
export function decideCore(
  request: DecisionRequest,
  ctx: DecideWithGrantsContext,
  deps: DecideWithGrantsDeps,
): DecideWithGrantsResult {
  const { tier } = resolveTierWithEnvelope(
    request.action.name,
    ctx.tierPolicy,
    ctx.envelope,
    request.toolAnnotations,
  );

  const collected = collectCoveringGrants(request, {
    store: deps.store,
    resolvedTier: tier,
    nowEpochSeconds: ctx.nowEpochSeconds,
    resolvePublicKey: ctx.resolvePublicKey,
  });

  const excluded = new Set<string>();
  let replayed = false;

  // Loop only advances when a single-use deciding grant loses the wx race and
  // is excluded; each iteration re-runs precedence over the shrinking set.
  // Bounded by the number of covering grants (each exclusion removes one).
  for (;;) {
    const coveringGrants = collected.coveringGrants.filter(
      (g) => !excluded.has(g.jti),
    );
    const decision = evaluatePrecedence({
      request,
      tierPolicy: ctx.tierPolicy,
      ...(ctx.envelope !== undefined ? { envelope: ctx.envelope } : {}),
      coveringGrants,
      nowEpochSeconds: ctx.nowEpochSeconds,
    });

    const decidingJti =
      decision.outcome === "allow" ? decision.grantRef : undefined;

    // Not a single-use-grant allow: the decision stands as-is. If we only got
    // here after excluding a replayed grant AND still can't allow, that is the
    // replay deny (override the tier-default reason).
    if (
      decidingJti === undefined ||
      !collected.singleUseJtis.has(decidingJti)
    ) {
      if (replayed && decision.outcome !== "allow") {
        return {
          decision: replayDeny(tier, decision.clamped),
          rejected: collected.rejected,
        };
      }
      return { decision, rejected: collected.rejected };
    }

    // A single-use grant decided this allow — consume it atomically.
    const consume = deps.store.consumeOnce(decidingJti);
    if (consume === "consumed") {
      return {
        decision,
        consumedJti: decidingJti,
        rejected: collected.rejected,
      };
    }

    // already_consumed: this jti was spent (by a prior evaluation or a racing
    // process). Exclude it and re-decide.
    excluded.add(decidingJti);
    replayed = true;
  }
}

/**
 * Builds the `grant_replayed` deny. Carries the resolved `tier` and any
 * tier-clamp audit trail, at the grant precedence layer (3); drops
 * `requestable`/`wantsApproval` — a replayed single-use grant is a hard deny,
 * not a "go request a grant" nudge.
 */
function replayDeny(
  tier: Tier,
  clamped: { from: Tier; to: Tier } | undefined,
): GrantedDecision {
  return {
    outcome: "deny",
    tier,
    reasonCode: GrantsDecisionReasonCode.GrantReplayed,
    precedenceLayer: 3,
    ...(clamped !== undefined ? { clamped } : {}),
  };
}
