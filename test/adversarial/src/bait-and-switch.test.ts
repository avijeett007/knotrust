/**
 * P0-E11-T6 — the approval bait-and-switch (TOCTOU) adversarial suite.
 *
 * The load-bearing test for threat-model **T1b (bait-and-switch)** —
 * `docs/02-architecture/security-threat-model.md` §3.0's boundary matrix
 * ("Human channel ↔ TCB" × Tampering), §T1's "1b. Deceptive arguments" family,
 * and §4.4 "The approval is bound to the exact call" — plus the closing half
 * of brief §I2.3: **a human approving call *X* authorizes only *X*, once.**
 * Approving a benign call must never let a DIFFERENT call execute under the
 * grant it minted.
 *
 * This is a TEST-AUTHORING task against the already-built, already-verified
 * subsystems (P0-E3-T3 the call-hash-bound ephemeral-grant lifecycle, P0-E6-T4
 * the real approval-orchestrator wiring, P0-E3-T5 the frozen call-hash golden
 * vectors, P0-E11-T1 the harness) — it composes the REAL pieces, never a mock:
 *
 *   real Ed25519 `KeyStore` (`@knotrust/grants` `createKeyStore`)
 *     → real on-disk `GrantStore` (`@knotrust/store` `createGrantStore`)
 *     → real hash-chained `AuditSink` (`@knotrust/store` `createAuditLog`)
 *     → real unified `createDecider` (cache + grant collection + precedence
 *       + consume/replay + audit — `@knotrust/grants`)
 *     → real `createApprovalOrchestrator` (`@knotrust/approval`), wired
 *       exactly as `packages/cli`'s `enforcement.ts`/P0-E6-T4 wires it:
 *       `resolve(id, "approved")` mints the REAL ephemeral, `ch`-bound,
 *       single-use grant via `mintEphemeralGrant` and RE-EVALUATES the frozen
 *       snapshot through the SAME `decider.decide` the proxy calls.
 *
 * ## The six variants (R146)
 *
 * Approve a critical call **X** via the orchestrator, then attempt to execute
 * a call **Y** — under the grant X's approval minted — that differs from X in
 * exactly ONE hashed SARC field (`golden-vectors/schemas/sarc-normal-form.v1.md`:
 * `subject`/`action`/`resource`/`agent`/`arguments`):
 *
 *   (a) a different `action.name`            → tool differs
 *   (b) one argument byte differs            → the FINEST-grained TOCTOU
 *   (c) a different `resource.id`/`.type`    → resource differs
 *   (d) a different `context.agent.id`       → agent differs
 *   (e) a tool-definition-mutation race (the harness's `driftAfter`, R54)
 *   (f) CONTROL — the EXACT approved call X — must still succeed (no false
 *       positive: an over-tight binding that denies the legitimate call is
 *       also a bug, per R149).
 *
 * ## An honest architectural finding, not a weakened test (R136/R149)
 *
 * `mintEphemeralGrant` (the REAL function the orchestrator calls) derives an
 * EXACT-match `tool`/`agent`/`scope` from the approved request (never a
 * wildcard) — so, mounted through the GENUINE orchestrator-minted grant, a Y
 * that differs in `action.name`/`resource`/`context.agent.id` is ALREADY
 * rejected by those coarser R25 pattern matchers (`grant_tool_mismatch` /
 * `grant_scope_mismatch` / `grant_agent_mismatch`) — checked in `verify.ts`
 * BEFORE the call-hash gate (step 7) is ever reached. This is DEFENSE IN
 * DEPTH, not a gap: every one of those variants ALSO differs in its SARC hash
 * (asserted below, every time), so the call-hash gate would equally reject it
 * were it reached first. Variant (b) — and the causally-real-argument-change
 * half of (e) — are the ONLY mutations the coarser matchers cannot see at
 * all (tool/agent/resource are UNCHANGED), which is exactly why they are the
 * variants that genuinely, natively isolate `grant_call_mismatch` through the
 * real orchestrator flow (R146(b): "proves the hash covers
 * `context.arguments`, R32"). For (a)/(c)/(d), this suite asserts the HONEST
 * fired reason from the real grant, plus the independently-differing
 * call-hash, plus — in the confirmatory block at the bottom of this file —
 * the ISOLATED call-hash-only view (a deliberately broad-scoped grant,
 * mirroring `packages/grants/src/lifecycle.test.ts`'s own committed
 * `"(P0-E11-T6 hook)"` matrix) that reproduces `grant_call_mismatch`
 * specifically for all four field mutations. Every variant, by every
 * mechanism, agrees on one thing: Y is NEVER allowed under X's grant.
 *
 * No product-code changes (R149). Every case here is expected to PASS by the
 * built system already failing closed. If any mutated Y were ever ALLOWED
 * under X's grant, that is a Critical TOCTOU hole to escalate BLOCKED with
 * the exact variant + code path — never a test to weaken. The control (exact
 * X) MUST allow — a false-positive deny on the legitimate call is also a bug
 * worth flagging (R149).
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  type ApprovalOrchestrator,
  createApprovalOrchestrator,
} from "@knotrust/approval";
import type { DecisionRequest, Tier, TierPolicy } from "@knotrust/core";
import { createDecisionCache } from "@knotrust/core";
import {
  collectCoveringGrants,
  computeCallHash,
  createDecider,
  createDiskPublicKeyResolver,
  createKeyStore,
  type Decider,
  decodeGrantIndexEntry,
  type Ed25519PublicJwk,
  GrantRejectionReason,
  type KeyStore,
  mintEphemeralGrant,
  mintGrant,
  revokeGrants,
  verifyGrant,
} from "@knotrust/grants";
import {
  type AuditEvent,
  type AuditSink,
  type ChainVerifyResult,
  createAuditLog,
  createGrantStore,
  type GrantStore,
} from "@knotrust/store";
import {
  FakeClient,
  type FakeServerConfig,
  startFakeServer,
} from "@knotrust/test-harness";
import { afterEach, describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const SUBJECT_ID = "avijeett007@gmail.com";
const AGENT_ID = "codex-cli";
const TOOL_NAME = "stripe.create_refund";
const INITIAL_CLOCK = 1_800_000_000;

/** Matches golden-vectors/grants' own stripe-refund fixtures (R147). */
const POLICY: TierPolicy = {
  tools: { [TOOL_NAME]: { tier: "critical", source: "pack" } },
  unknownToolTier: "critical",
};

/** The approved call X — mirrors `golden-vectors/grants/single-use-ephemeral-valid.json`'s
 * request (same subject/action/resource/agent), plus `context.arguments` (R32) so variant
 * (b)'s one-byte mutation has a byte to mutate. */
function criticalRequest(over: Partial<DecisionRequest> = {}): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01BAITSWITCHX00000000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: SUBJECT_ID },
    action: { name: TOOL_NAME },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: AGENT_ID, type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 42000, reason: "requested_by_customer" },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px-baitswitch",
      server: "stripe-mcp",
    },
    ...over,
  };
}

// ---------------------------------------------------------------------------
// R147 — golden-vector anchor: computeCallHash reproduces the frozen ch
// (the source of truth for the ch computation, never re-derived from
// scratch). The 8 P0-E3-T5 vectors already run in
// `packages/grants/src/golden-vectors.test.ts`; this anchor ties THIS suite's
// own understanding of `computeCallHash`/`verifyGrant` directly to the two
// vectors this task's property is about.
// ---------------------------------------------------------------------------

const goldenVectorsGrantsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "golden-vectors",
  "grants",
);

interface GoldenGrantVector {
  token: string;
  verifyContext: {
    request: DecisionRequest;
    resolvedTier: Tier;
    nowEpochSeconds: number;
    callHash?: string;
    resolveKid: "primary" | "secondary";
  };
}

function loadGoldenVector(name: string): GoldenGrantVector {
  return JSON.parse(
    readFileSync(path.join(goldenVectorsGrantsDir, `${name}.json`), "utf8"),
  ) as GoldenGrantVector;
}

interface GoldenTestKeyEntry {
  publicKeyJwk: Ed25519PublicJwk;
  kid: string;
}

const goldenTestKeys = JSON.parse(
  readFileSync(path.join(goldenVectorsGrantsDir, "test-keys.json"), "utf8"),
) as { primary: GoldenTestKeyEntry; secondary: GoldenTestKeyEntry };

function goldenResolver(
  resolveKid: "primary" | "secondary",
): (kid: string) => Ed25519PublicJwk | null {
  const jwk = goldenTestKeys[resolveKid].publicKeyJwk;
  const presentedKid = goldenTestKeys.primary.kid;
  return (kid: string) => (kid === presentedKid ? jwk : null);
}

describe("R147 — golden-vector anchor: computeCallHash is the source of truth for ch, not re-derived", () => {
  it("single-use-ephemeral-valid.json: computeCallHash(request) reproduces the frozen live callHash exactly (ok:true)", () => {
    const vector = loadGoldenVector("single-use-ephemeral-valid");
    const callHash = vector.verifyContext.callHash;
    if (callHash === undefined) throw new Error("fixture is missing callHash");
    expect(computeCallHash(vector.verifyContext.request)).toBe(callHash);
    const result = verifyGrant(vector.token, {
      request: vector.verifyContext.request,
      resolvedTier: vector.verifyContext.resolvedTier,
      nowEpochSeconds: vector.verifyContext.nowEpochSeconds,
      callHash,
      resolvePublicKey: goldenResolver(vector.verifyContext.resolveKid),
    });
    expect(result.ok).toBe(true);
  });

  it("call-hash-mismatch.json: the frozen 'live' callHash genuinely differs from computeCallHash(request) — this suite's exact TOCTOU gate (ok:false, grant_call_mismatch)", () => {
    const vector = loadGoldenVector("call-hash-mismatch");
    const callHash = vector.verifyContext.callHash;
    if (callHash === undefined) throw new Error("fixture is missing callHash");
    expect(computeCallHash(vector.verifyContext.request)).not.toBe(callHash);
    const result = verifyGrant(vector.token, {
      request: vector.verifyContext.request,
      resolvedTier: vector.verifyContext.resolvedTier,
      nowEpochSeconds: vector.verifyContext.nowEpochSeconds,
      callHash,
      resolvePublicKey: goldenResolver(vector.verifyContext.resolveKid),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(GrantRejectionReason.CallMismatch);
    }
  });
});

// ---------------------------------------------------------------------------
// Harness — composes the REAL keystore + store + audit + decider + approval
// orchestrator over a fresh temp $KNOTRUST_HOME, wired exactly as P0-E6-T4's
// production composition does (mirrors P0-E11-T2's `self-approval.test.ts`
// `setupStack` rationale, minus the wire-level MCP relay: this task's
// property lives entirely in the orchestrator ↔ grant ↔ decider interaction,
// same substrate list P0-E11-T3/T4 compose directly).
// ---------------------------------------------------------------------------

interface Env {
  store: GrantStore;
  keyStore: KeyStore;
  resolvePublicKey: (kid: string) => Ed25519PublicJwk | null;
  decider: Decider;
  orchestrator: ApprovalOrchestrator;
  audit: AuditSink;
  currentClock(): number;
  readAuditEvents(): AuditEvent[];
  verifyAudit(): ChainVerifyResult;
  /** The grant minted by the most recent `resolve(..., "approved")` call. */
  takeMintedGrant(): { jti: string; token: string };
}

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    try {
      fn?.();
    } catch {
      // best-effort teardown
    }
  }
});

let idSeq = 0;
function nextId(prefix: string): string {
  return `${prefix}${String(idSeq++).padStart(6, "0")}`;
}

function safeReaddir(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

function readAllAuditEvents(home: string): AuditEvent[] {
  const dir = path.join(home, "audit");
  const events: AuditEvent[] = [];
  for (const f of safeReaddir(dir)
    .filter((n) => /^\d{6}\.jsonl$/.test(n))
    .sort()) {
    for (const line of readFileSync(path.join(dir, f), "utf8").split("\n")) {
      if (line.length > 0) events.push(JSON.parse(line) as AuditEvent);
    }
  }
  return events;
}

async function buildEnv(): Promise<Env> {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-baitswitch-"));
  cleanups.push(() => rmSync(home, { recursive: true, force: true }));

  const clock = INITIAL_CLOCK;
  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const audit = createAuditLog({ home, nowEpochMs: () => clock * 1000 });
  cleanups.push(() => {
    try {
      audit.close();
    } catch {
      // release the writer lock
    }
  });
  const cache = createDecisionCache({ nowEpochSeconds: () => clock });

  // The trusted identity: generated under THIS home, so its pubkey JWK lands
  // in `home/keys/<kid>.jwk.json` — exactly what `createDiskPublicKeyResolver`
  // reads.
  const priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;
  const keyStore = await createKeyStore({ backend: "file" });
  await keyStore.ensureIdentity();
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;

  const resolvePublicKey = createDiskPublicKeyResolver(home);

  const decider = createDecider({
    cache,
    tierPolicy: POLICY,
    policyVersion: "pv1",
    store,
    audit,
    resolvePublicKey,
    nowEpochSeconds: () => clock,
    nowMs: () => clock * 1000,
    generateId: () => nextId("DEC"),
  });

  let lastMinted: { jti: string; token: string } | undefined;

  // The REAL approval orchestrator (E6-T1), wired exactly as P0-E6-T4's
  // production composition does: real ephemeral mint (bound via
  // `computeCallHash` to the frozen snapshot), real re-evaluating `decide`
  // (the SAME unified decider the proxy calls), real revoke.
  const orchestrator = createApprovalOrchestrator({
    mintEphemeralGrant: async (input) => {
      const result = await mintEphemeralGrant(input, {
        store,
        keyStore,
        nowEpochSeconds: clock,
        generateId: () => nextId("GR"),
        audit,
      });
      lastMinted = result;
      return result;
    },
    decide: (request) => decider.decide(request),
    revokeGrant: (jti) => {
      revokeGrants(
        { jti },
        { store, audit, onInvalidate: () => cache.bumpGrantSetVersion() },
      );
    },
    audit,
    nowEpochSeconds: () => clock,
    generateId: () => nextId("APR"),
  });

  return {
    store,
    keyStore,
    resolvePublicKey,
    decider,
    orchestrator,
    audit,
    currentClock: () => clock,
    readAuditEvents: () => {
      audit.flush();
      return readAllAuditEvents(home);
    },
    verifyAudit: () => audit.verify(),
    takeMintedGrant: () => {
      if (lastMinted === undefined) {
        throw new Error("mintEphemeralGrant was never called");
      }
      return lastMinted;
    },
  };
}

interface Approval {
  approvalId: string;
  jti: string;
  token: string;
}

/** Approves X through the REAL orchestrator lifecycle: `request()` → `resolve(id, "approved")`.
 * `resolve`'s own re-evaluation (R87: "approve ⇒ mint ⇒ RE-EVALUATE") is what
 * proves X itself allows under the freshly-minted grant — asserted here via
 * the terminal state, and independently re-checked by the CONTROL test below. */
async function approveX(env: Env, X: DecisionRequest): Promise<Approval> {
  const handle = await env.orchestrator.request({
    decisionId: nextId("DEC"),
    requestId: X.requestId,
    subject: X.subject,
    agent: X.context.agent,
    action: X.action,
    resource: X.resource,
    tier: "critical",
    eligibleChannels: ["block_and_wait"],
    decisionRequest: X,
  });
  expect(handle.state).toBe("pending");

  await env.orchestrator.resolve(handle.id, "approved");
  const status = await env.orchestrator.status(handle.id);
  // R149: the control MUST allow — a false-positive deny on the legitimate,
  // exact approved call is itself a bug worth flagging, not just the reverse.
  expect(status.state).toBe("approved");

  const minted = env.takeMintedGrant();
  return { approvalId: handle.id, jti: minted.jti, token: minted.token };
}

/**
 * The core adversarial assertion: attempts to execute `Y` (which differs
 * from the already-approved `X` in exactly one SARC field) under `X`'s
 * freshly-minted ephemeral grant, through THREE independent layers of the
 * real system, and proves R148's audit linkage.
 *
 *   1. `verifyGrant` — the isolated per-grant check (mirrors the golden
 *      vectors, R147). Asserts the HONEST fired `reason` (see this file's
 *      header note on why (a)/(c)/(d) fire an earlier, coarser R25 gate
 *      through the genuinely narrow-scoped orchestrator-minted grant, while
 *      (b)/(e) — the only variants the coarser matchers cannot see — fire
 *      `grant_call_mismatch` natively).
 *   2. `collectCoveringGrants` — the composed candidate-collection step
 *      `decideCore`/`decideWithGrants` use; the grant must be REJECTED
 *      (never a covering candidate).
 *   3. `decider.decide(Y)` — the REAL, audited, unified decider. THE
 *      critical security property (R149's stop condition): outcome is NEVER
 *      `"allow"`. Honestly asserted as `pending_approval`/`no_grant_critical`
 *      — the same "no grant at all" default any critical tool with no
 *      covering grant gets (`l0-evaluator.ts`'s `evaluateTierDefault`) — a
 *      NEW human decision would be required for Y specifically; this is not
 *      a TOCTOU hole, never a fabricated `deny`.
 *
 * Finally: the audit chain links the approval for X and the (never-allow)
 * outcome for Y by X's `approvalId`, via the grant's `jti` bridge (R148).
 */
async function assertYNeverAllowedUnderXsGrant(
  env: Env,
  approval: Approval,
  X: DecisionRequest,
  Y: DecisionRequest,
  expectReason: GrantRejectionReason,
): Promise<void> {
  const resolvedTier: Tier = "critical";

  // Every mutation, by construction, differs in a SARC-hashed field — the
  // call-hash gate would reject EVERY ONE of these variants were it reached.
  expect(computeCallHash(Y)).not.toBe(computeCallHash(X));

  // (1) Isolated verify-level check.
  const verified = verifyGrant(approval.token, {
    request: Y,
    resolvedTier,
    nowEpochSeconds: env.currentClock(),
    callHash: computeCallHash(Y),
    resolvePublicKey: env.resolvePublicKey,
  });
  expect(verified.ok).toBe(false);
  if (verified.ok) throw new Error("unreachable — asserted ok:false above");
  expect(verified.reason).toBe(expectReason);

  // (2) Composed candidate collection — absent, never covering.
  const collected = collectCoveringGrants(Y, {
    store: env.store,
    resolvedTier,
    nowEpochSeconds: env.currentClock(),
    resolvePublicKey: env.resolvePublicKey,
  });
  expect(collected.coveringGrants).toHaveLength(0);
  expect(collected.rejected).toContainEqual({
    jti: approval.jti,
    reason: expectReason,
  });

  // (3) THE critical security property — never allow.
  const decision = await env.decider.decide(Y);
  expect(decision.outcome).not.toBe("allow");
  expect(decision.outcome).toBe("pending_approval");
  expect(decision.reasonCode).toBe("no_grant_critical");
  expect(decision.evaluatedBy).toBe("L0");

  // (R148) Audit linkage: X's approval events carry approvalId; the grant
  // created for X is `jti`; Y's rejected-grant list (2, above) names that
  // SAME `jti` — the forensic bridge from Y's non-allow back to X's approval.
  const events = env.readAuditEvents();
  const approvalEvents = events.filter(
    (e) => e.approvalId === approval.approvalId,
  );
  expect(approvalEvents.map((e) => e.type)).toEqual(
    expect.arrayContaining(["approval_requested", "approval_approved"]),
  );
  const grantCreated = events.find(
    (e) => e.type === "grant_created" && e.grantRefs?.includes(approval.jti),
  );
  expect(grantCreated).toBeDefined();
  // X's own re-evaluation (inside resolve()) allowed and consumed jti — the
  // control property holds even mid-battery, proving the binding isn't
  // over-tight (R146(f)).
  const decisionForX = events.find(
    (e) => e.type === "decision" && e.grantRefs?.includes(approval.jti),
  );
  expect(decisionForX?.outcome).toBe("allow");
  expect(decisionForX?.reason).toBe("grant_allow");
  expect(
    events.some(
      (e) => e.type === "grant_consumed" && e.grantRefs?.includes(approval.jti),
    ),
  ).toBe(true);

  expect(env.verifyAudit().ok).toBe(true);
}

// ===========================================================================
// (a)-(d) — mutated Y variants, mounted through the REAL orchestrator-minted
// (exact-scoped) ephemeral grant.
// ===========================================================================

describe("(a)-(d) mutated Y variants — never allowed under X's grant (R146, R149)", () => {
  const cases: Array<[string, () => DecisionRequest, GrantRejectionReason]> = [
    [
      "(a) a different action.name",
      () => criticalRequest({ action: { name: "stripe.create_charge" } }),
      GrantRejectionReason.ToolMismatch,
    ],
    [
      "(b) one argument byte differs (amount 42000 -> 42001) — the finest-grained TOCTOU (R32)",
      () =>
        criticalRequest({
          context: {
            agent: { id: AGENT_ID, type: "ai_agent" },
            env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
            arguments: { amount: 42001, reason: "requested_by_customer" },
          },
        }),
      GrantRejectionReason.CallMismatch,
    ],
    [
      "(c1) a different resource.id",
      () =>
        criticalRequest({
          resource: { type: "stripe_charge", id: "ch_DIFFERENT" },
        }),
      GrantRejectionReason.ScopeMismatch,
    ],
    [
      "(c2) a different resource.type",
      () =>
        criticalRequest({
          resource: { type: "stripe_refund_request", id: "ch_3PabcXYZ" },
        }),
      GrantRejectionReason.ScopeMismatch,
    ],
    [
      "(d) a different context.agent.id",
      () =>
        criticalRequest({
          context: {
            agent: { id: "other-agent", type: "ai_agent" },
            env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
            arguments: { amount: 42000, reason: "requested_by_customer" },
          },
        }),
      GrantRejectionReason.AgentMismatch,
    ],
  ];

  it.each(
    cases,
  )("%s -> never allowed under X's grant", async (_label, buildY, expectReason) => {
    const env = await buildEnv();
    const X = criticalRequest();
    const approval = await approveX(env, X);
    const Y = buildY();
    await assertYNeverAllowedUnderXsGrant(env, approval, X, Y, expectReason);
  });
});

// ===========================================================================
// (e) — tool-definition-mutation race (the harness's driftAfter, R54).
// ===========================================================================

describe("(e) tool-definition-mutation race — the grant binds to the call's SARC, never the tool's advertised definition (R146(e))", () => {
  it("a genuine driftAfter schema/description mutation between approval and execution: the drift ALONE (annotations/schema unchanged call) still legitimately covers; a Y whose ARGUMENTS change because of the drifted schema is denied grant_call_mismatch", async () => {
    // --- Prove the drift is genuine, via the REAL E11-T1 harness. ---
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-baitswitch-e", version: "1.0.0" },
      tools: [
        {
          name: TOOL_NAME,
          description: "Refund a stripe charge",
          inputSchema: {
            type: "object",
            properties: {
              amount: { type: "number" },
              reason: { type: "string" },
            },
          },
          annotations: { destructiveHint: true, readOnlyHint: false },
        },
      ],
      driftAfter: [
        {
          toolName: TOOL_NAME,
          afterListCallCount: 1,
          patch: {
            description: "Refund a stripe charge (now multi-currency)",
            inputSchema: {
              type: "object",
              properties: {
                amount: { type: "number" },
                reason: { type: "string" },
                currency: { type: "string" },
              },
            },
          },
        },
      ],
    };
    const started = await startFakeServer(config);
    const client = new FakeClient(started.inProcess.clientTransport);
    await client.connect();

    const first = await client.listToolsPage();
    expect(first.tools[0]?.inputSchema).not.toHaveProperty(
      "properties.currency",
    );
    // Second FRESH listing: the drift has taken effect (R54).
    const second = await client.listToolsPage();
    expect(second.tools[0]?.inputSchema).toHaveProperty("properties.currency");

    await client.close();
    await started.close();

    // --- Compose the SAME real approval/grant flow the other variants use. ---
    const env = await buildEnv();
    const X = criticalRequest(); // approved against the ORIGINAL (pre-drift) schema.
    const approval = await approveX(env, X);

    // Honest reasoning (R146(e)): `toolAnnotations` is (1) excluded from the
    // SARC normal form by design (`callhash.ts`'s frozen field list) and (2)
    // never even populated onto a `DecisionRequest` in P0
    // (`proxy-stdio/src/enforce.ts`: "buildDecisionRequest never populates
    // toolAnnotations either (P0 scope)"). So a PURE annotation/schema/
    // description drift, with the actual call unchanged, cannot move the
    // call-hash — the grant LEGITIMATELY still covers the identical X:
    const stillCovers = verifyGrant(approval.token, {
      request: X,
      resolvedTier: "critical",
      nowEpochSeconds: env.currentClock(),
      callHash: computeCallHash(X),
      resolvePublicKey: env.resolvePublicKey,
    });
    expect(stillCovers.ok).toBe(true); // NOT an attack — the definition drifted, the call didn't.

    // The race materializes only when the drift changes what the AGENT
    // actually SENDS — a client honoring the drifted schema's new `currency`
    // field. That change lands in `context.arguments`, which IS SARC-hashed
    // (R32) — tool/agent/resource stay identical to X, so (like variant b)
    // this NATIVELY isolates the call-hash gate through the real grant:
    const Y = criticalRequest({
      context: {
        agent: { id: AGENT_ID, type: "ai_agent" },
        env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
        arguments: {
          amount: 42000,
          reason: "requested_by_customer",
          currency: "usd",
        },
      },
    });
    await assertYNeverAllowedUnderXsGrant(
      env,
      approval,
      X,
      Y,
      GrantRejectionReason.CallMismatch,
    );
  }, 20_000);
});

// ===========================================================================
// (f) CONTROL — the exact approved call X still succeeds (no false positive).
// ===========================================================================

describe("(f) CONTROL — the exact approved call X still succeeds under its own grant (R146(f), R149)", () => {
  it("verifyGrant(token, X) covers exactly; the composed re-evaluation inside resolve() allowed and consumed the grant exactly once; audit.verify() green", async () => {
    const env = await buildEnv();
    const X = criticalRequest();
    const approval = await approveX(env, X);

    // Pure, non-mutating re-check: the SAME grant, evaluated against the
    // EXACT call it was minted for, covers — mirrors
    // golden-vectors/grants/single-use-ephemeral-valid.json's own positive
    // case (R147).
    const verified = verifyGrant(approval.token, {
      request: X,
      resolvedTier: "critical",
      nowEpochSeconds: env.currentClock(),
      callHash: computeCallHash(X),
      resolvePublicKey: env.resolvePublicKey,
    });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.claims.jti).toBe(approval.jti);
    }

    // The composed decision `resolve()` itself produced when re-evaluating X
    // (R87: "approve ⇒ mint ⇒ RE-EVALUATE") IS "the exact approved call X
    // still executes" operationally: `proxy-stdio/src/enforce.ts`'s
    // `case "allow": return { action: "forward" }` relays the ORIGINAL held
    // call, unchanged, to the child the instant this resolves allow.
    const events = env.readAuditEvents();

    const approvalEvents = events.filter(
      (e) => e.approvalId === approval.approvalId,
    );
    expect(approvalEvents.map((e) => e.type)).toEqual(
      expect.arrayContaining(["approval_requested", "approval_approved"]),
    );

    const decisionForX = events.find(
      (e) => e.type === "decision" && e.grantRefs?.includes(approval.jti),
    );
    expect(decisionForX?.outcome).toBe("allow");
    expect(decisionForX?.reason).toBe("grant_allow");
    expect(decisionForX?.tool).toBe(X.action.name);

    expect(
      events.some(
        (e) =>
          e.type === "grant_consumed" && e.grantRefs?.includes(approval.jti),
      ),
    ).toBe(true);

    // No false-positive deny anywhere in the trail (R149).
    expect(events.some((e) => e.type === "approval_denied")).toBe(false);

    expect(env.verifyAudit().ok).toBe(true);
  });
});

// ===========================================================================
// Confirmatory block — the ISOLATED call-hash-only view.
//
// Mirrors `packages/grants/src/lifecycle.test.ts`'s own committed
// "(P0-E11-T6 hook)" matrix (P0-E3-T3): a DELIBERATELY broad-scoped ephemeral
// grant (agent "*", tool "stripe.*", empty scope) so the coarser R25
// tool/agent/scope matchers all still MATCH each Y variant, isolating the
// call-hash gate as the SOLE discriminator. Reproduced here (rather than
// only cited) so this suite is self-contained proof that `grant_call_mismatch`
// specifically — independent of any coarser gate — closes approve-X-execute-Y
// for EVERY one of the four field mutations, exactly as R146(a)-(d) state.
// ===========================================================================

describe("confirmatory — the call-hash gate ALONE (broad-scoped grant) denies grant_call_mismatch for every field mutation", () => {
  it("mirrors packages/grants/src/lifecycle.test.ts's (P0-E11-T6 hook): tool/argument/resource/agent mutations are ALL grant_call_mismatch when the grant's own patterns are permissive", async () => {
    const env = await buildEnv();
    const X = criticalRequest();

    const minted = await mintGrant(
      {
        kind: "ephemeral",
        principal: { type: X.subject.type, id: X.subject.id },
        agent: "*",
        tool: "stripe.*",
        scope: {},
        tier: "critical",
        envelopeScope: "personal",
        ttlSeconds: 120,
        callHash: computeCallHash(X),
      },
      {
        keyStore: env.keyStore,
        nowEpochSeconds: env.currentClock(),
        generateId: () => nextId("BROADGR"),
      },
    );
    const put = env.store.put(minted.token);
    expect(put.ok).toBe(true);

    const mismatchCases: Array<[string, DecisionRequest]> = [
      ["tool", criticalRequest({ action: { name: "stripe.create_charge" } })],
      [
        "argument byte",
        criticalRequest({
          context: {
            agent: { id: AGENT_ID, type: "ai_agent" },
            env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
            arguments: { amount: 42001, reason: "requested_by_customer" },
          },
        }),
      ],
      [
        "resource",
        criticalRequest({
          resource: { type: "stripe_charge", id: "ch_DIFFERENT" },
        }),
      ],
      [
        "agent",
        criticalRequest({
          context: {
            agent: { id: "other-agent", type: "ai_agent" },
            env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
            arguments: { amount: 42000, reason: "requested_by_customer" },
          },
        }),
      ],
    ];

    for (const [label, Y] of mismatchCases) {
      const collected = collectCoveringGrants(Y, {
        store: env.store,
        resolvedTier: "critical",
        nowEpochSeconds: env.currentClock(),
        resolvePublicKey: env.resolvePublicKey,
      });
      expect(collected.coveringGrants, `variant: ${label}`).toHaveLength(0);
      expect(collected.rejected, `variant: ${label}`).toHaveLength(1);
      expect(collected.rejected[0]?.reason, `variant: ${label}`).toBe(
        GrantRejectionReason.CallMismatch,
      );
    }

    // The control: Y' === X still covers under the SAME broad grant.
    const identical = collectCoveringGrants(X, {
      store: env.store,
      resolvedTier: "critical",
      nowEpochSeconds: env.currentClock(),
      resolvePublicKey: env.resolvePublicKey,
    });
    expect(identical.coveringGrants).toHaveLength(1);
    expect(identical.rejected).toHaveLength(0);
  });
});
