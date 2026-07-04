/**
 * P0-E11-T3 — the grant-replay adversarial battery.
 *
 * The load-bearing test for threat-model **T4 (Grant theft / forgery /
 * replay, case d)** (`docs/02-architecture/security-threat-model.md`):
 * "replay a legitimate single-use grant; use an expired grant; over-scope a
 * grant beyond what was authorized" — plus the untrusted-issuer half of "forge
 * a grant the proxy will accept."  Its mitigations (§4.4) are the `jti` +
 * `single_use` consumed ledger, expiry, scope matching, and Ed25519
 * verification against ONLY locally-trusted keys.
 *
 * This is a TEST-AUTHORING task against the already-built, already-verified
 * subsystems (P0-E3-T2/T3 grant mint/verify/lifecycle, P0-E4-T1 the file
 * store's consumed-`jti` ledger, P0-E5-T3 the unified `createDecider`) — it
 * composes the REAL pieces:
 *
 *   real Ed25519 `KeyStore` (`@knotrust/grants` `createKeyStore`)
 *     → real `mintDurableGrant`/`mintEphemeralGrant` (JWS Compact, EdDSA)
 *     → real on-disk `GrantStore` (`@knotrust/store` `createGrantStore` —
 *       `grants/<jti>.jws` + the `wx`-atomic `grants/consumed/<jti>` ledger)
 *     → real `verifyGrant`/`collectCoveringGrants` (`@knotrust/grants`)
 *     → real unified `createDecider` (cache + `decideCore`'s
 *       collect → precedence → consume/replay algorithm)
 *
 * — then mounts six adversarial variants and proves each fails CLOSED with
 * the PRECISE reason code (R137):
 *
 *   1. single-use replay, same process           → `grant_replayed`
 *   2. single-use replay, RESTARTED process       → `grant_replayed`
 *      (the durability proof: a FRESH store/cache/decider instance sharing
 *      only the on-disk `$KNOTRUST_HOME` — never the original store object —
 *      still denies the replay, proving the consumed-`jti` ledger is a
 *      durable on-disk marker, not an in-process Set/Map)
 *   3. copied-file variant                        → still `grant_replayed`
 *      (re-instating the exact `.jws` bytes, or duplicating them under a
 *      NEW filename, never resurrects a consumed authorization)
 *   4. expired-grant reuse                         → `grant_expired` (verify)
 *      + the tier's no-grant default (decision)
 *   5. scope mismatch                              → `grant_scope_mismatch`
 *      (verify) + the tier's no-grant default (decision)
 *   6. untrusted issuer (a genuinely different,
 *      second locally-generated Ed25519 identity)  → `grant_unknown_key`
 *      (verify) + the tier's no-grant default (decision) — see variant 6's
 *      own comment for the reason-code mapping this ruling (R137) demands be
 *      documented.
 *
 * No product-code changes (R136/R139): every variant here PASSES by failing
 * closed in the ALREADY-BUILT system. If any variant were ever accepted
 * (yielded `allow`), that would be a Critical product bug to escalate BLOCKED
 * with the exact code path — never a test to weaken.
 *
 * Every tier-default assertion below deliberately uses a `sensitive`-tier
 * tool (never `critical`): `no_grant_sensitive` resolves `deny`
 * (`packages/core/src/l0-evaluator.ts`), matching this suite's uniform
 * "every variant yields deny" acceptance line, whereas `no_grant_critical`
 * resolves `pending_approval` — a different outcome this suite does not need
 * to reason about.
 */

import {
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { DecisionRequest, TierPolicy } from "@knotrust/core";
import { createDecisionCache, L0ReasonCode } from "@knotrust/core";
import {
  collectCoveringGrants,
  createDecider,
  createDiskPublicKeyResolver,
  createKeyStore,
  type Decider,
  decodeGrantIndexEntry,
  type Ed25519PublicJwk,
  GrantRejectionReason,
  GrantsDecisionReasonCode,
  type KeyStore,
  mintDurableGrant,
  mintEphemeralGrant,
} from "@knotrust/grants";
import { createGrantStore, type GrantStore } from "@knotrust/store";
import { afterEach, describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const SUBJECT_ID = "avijeett007@gmail.com";
const AGENT_ID = "codex-cli";
const HUMAN_AGENT_ID = "claude-desktop";
const INITIAL_CLOCK = 1_800_000_000;

/** One tier policy for the whole battery: a critical stripe refund (for the
 * replay variants, which need a single-use grant deciding an allow) and a
 * sensitive github issue create (for the expiry/scope/untrusted-issuer
 * variants, which need `no_grant_sensitive` — a DENY — as their tier
 * default; see module header). */
const POLICY: TierPolicy = {
  tools: {
    "stripe.create_refund": { tier: "critical", source: "pack" },
    "github.create_issue": { tier: "sensitive", source: "pack" },
  },
  unknownToolTier: "sensitive",
};

function criticalRequest(over: Partial<DecisionRequest> = {}): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01REPLAYCRITICAL00000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: SUBJECT_ID },
    action: { name: "stripe.create_refund" },
    resource: { type: "stripe_charge", id: "ch_3PabcXYZ" },
    context: {
      agent: { id: AGENT_ID, type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
      arguments: { amount: 42000, reason: "requested_by_customer" },
    },
    surface: { kind: "stdio_proxy", instanceId: "px-replay", server: "stripe" },
    ...over,
  };
}

function sensitiveRequest(
  over: Partial<DecisionRequest> = {},
): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01REPLAYSENSITIVE0000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: SUBJECT_ID },
    action: { name: "github.create_issue" },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: HUMAN_AGENT_ID, type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
    },
    surface: { kind: "stdio_proxy", instanceId: "px-replay", server: "github" },
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Harness — composes the REAL keystore + store + decider over a fresh temp
// $KNOTRUST_HOME. No audit sink: audit is optional on `createDecider`
// (`decider.ts`'s own doc-comment: "optional here only so unit tests can
// probe the un-audited path") and is not part of this task's substrate list
// (grant mint/verify + lifecycle + consume ledger, grant store, decider) —
// omitting it keeps the restarted-process variant free of any audit-log
// single-writer-lock close/reopen dance that would be orthogonal noise here.
// ---------------------------------------------------------------------------

interface Env {
  home: string;
  store: GrantStore;
  keyStore: KeyStore;
  resolvePublicKey: (kid: string) => Ed25519PublicJwk | null;
  decider: Decider;
  advanceClock(deltaSeconds: number): void;
  currentClock(): number;
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

async function buildEnv(): Promise<Env> {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-replay-"));
  cleanups.push(() => rmSync(home, { recursive: true, force: true }));

  let clock = INITIAL_CLOCK;
  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
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
    resolvePublicKey,
    nowEpochSeconds: () => clock,
    nowMs: () => clock * 1000,
    generateId: () => nextId("DEC"),
  });

  return {
    home,
    store,
    keyStore,
    resolvePublicKey,
    decider,
    advanceClock: (deltaSeconds: number) => {
      clock += deltaSeconds;
    },
    currentClock: () => clock,
  };
}

/** Generates a SECOND, wholly independent local Ed25519 identity under its
 * own temp home — never written into `env.home/keys/`, so `env`'s resolver
 * can never resolve its kid (variant 6). */
async function buildUntrustedKeyStore(): Promise<{
  keyStore: KeyStore;
  home: string;
}> {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-attacker-"));
  cleanups.push(() => rmSync(home, { recursive: true, force: true }));
  const priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;
  const keyStore = await createKeyStore({ backend: "file" });
  await keyStore.ensureIdentity();
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;
  return { keyStore, home };
}

function jwsPathFor(home: string, jti: string): string {
  return path.join(home, "grants", `${jti}.jws`);
}

// ===========================================================================
// (1) Single-use ephemeral grant replay — SAME process.
// ===========================================================================

describe("(1) single-use ephemeral grant replay — same process — T4", () => {
  it("the first decide() consumes the grant (allow, grant_allow); the IDENTICAL second decide() denies grant_replayed, never allow", async () => {
    const env = await buildEnv();
    const request = criticalRequest();

    await mintEphemeralGrant(
      { request, tier: "critical" },
      {
        store: env.store,
        keyStore: env.keyStore,
        nowEpochSeconds: env.currentClock(),
        generateId: () => nextId("JTI"),
      },
    );

    const first = await env.decider.decide(request);
    expect(first.outcome).toBe("allow");
    expect(first.reasonCode).toBe(L0ReasonCode.GrantAllow);

    // Re-present the IDENTICAL call. The exactly-once consumed-jti gate must
    // deny it — this is the precise defense a replay attack targets.
    const second = await env.decider.decide(request);
    expect(second.outcome).toBe("deny");
    expect(second.reasonCode).toBe(GrantsDecisionReasonCode.GrantReplayed);
  });
});

// ===========================================================================
// (2) Single-use ephemeral grant replay — RESTARTED PROCESS. THE DURABILITY
//     PROOF: a fresh store/cache/decider instance sharing ONLY the on-disk
//     home (no reference to the original in-memory objects) must still deny.
// ===========================================================================

describe("(2) single-use ephemeral grant replay — RESTARTED PROCESS (durable, not in-memory) — T4", () => {
  it("mint + consume in one store/decider instance; a BRAND NEW store/cache/decider over the SAME $KNOTRUST_HOME still denies grant_replayed", async () => {
    const env = await buildEnv();
    const request = criticalRequest({ requestId: "01REPLAYRESTART00000001" });

    const minted = await mintEphemeralGrant(
      { request, tier: "critical" },
      {
        store: env.store,
        keyStore: env.keyStore,
        nowEpochSeconds: env.currentClock(),
        generateId: () => nextId("JTI"),
      },
    );

    const first = await env.decider.decide(request);
    expect(first.outcome).toBe("allow");
    expect(first.reasonCode).toBe(L0ReasonCode.GrantAllow);

    // --- Simulate a process restart: brand-new objects, ZERO shared
    //     references to `env.store`/`env`'s cache — only the on-disk home
    //     is shared. If the consumed-jti ledger were an in-process Set/Map
    //     rather than the real `grants/consumed/<jti>` file, THIS is exactly
    //     the scenario that would silently allow the replay. ---
    const restartedStore = createGrantStore({
      home: env.home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    const restartedCache = createDecisionCache({
      nowEpochSeconds: () => env.currentClock(),
    });
    const restartedResolvePublicKey = createDiskPublicKeyResolver(env.home);
    const restartedDecider = createDecider({
      cache: restartedCache,
      tierPolicy: POLICY,
      policyVersion: "pv1",
      store: restartedStore,
      resolvePublicKey: restartedResolvePublicKey,
      nowEpochSeconds: () => env.currentClock(),
      nowMs: () => env.currentClock() * 1000,
      generateId: () => nextId("RESTARTDEC"),
    });

    // Direct, store-level proof: the FRESH store object reports the jti
    // consumed purely by reading the disk — it was never told this in-memory.
    expect(restartedStore.isConsumed(minted.jti)).toBe(true);

    // Full-decision proof: the fresh decider, over the fresh store/cache,
    // still denies the replay with the precise reason code.
    const second = await restartedDecider.decide(request);
    expect(second.outcome).toBe("deny");
    expect(second.reasonCode).toBe(GrantsDecisionReasonCode.GrantReplayed);
  });
});

// ===========================================================================
// (3) Copied-file variant — you cannot resurrect a consumed authorization by
//     duplicating its file on disk.
// ===========================================================================

describe("(3) copied-file variant — file duplication never un-consumes a jti — T4", () => {
  it("restoring the identical .jws bytes under the SAME jti filename after consumption still denies grant_replayed (the consumed marker is a separate ledger)", async () => {
    const env = await buildEnv();
    const request = criticalRequest({ requestId: "01REPLAYCOPYA0000000001" });

    const minted = await mintEphemeralGrant(
      { request, tier: "critical" },
      {
        store: env.store,
        keyStore: env.keyStore,
        nowEpochSeconds: env.currentClock(),
        generateId: () => nextId("JTI"),
      },
    );

    const first = await env.decider.decide(request);
    expect(first.outcome).toBe("allow");

    // Delete the grant's .jws file, then write back the EXACT same bytes
    // under the EXACT same filename — "the attacker had a backup copy and
    // restores it after consumption." The consumed ledger
    // (`grants/consumed/<jti>`) lives in a wholly separate file untouched by
    // this dance.
    const jwsPath = jwsPathFor(env.home, minted.jti);
    const originalBytes = readFileSync(jwsPath, "utf8");
    unlinkSync(jwsPath);
    writeFileSync(jwsPath, originalBytes);

    expect(env.store.isConsumed(minted.jti)).toBe(true);

    const second = await env.decider.decide(request);
    expect(second.outcome).toBe("deny");
    expect(second.reasonCode).toBe(GrantsDecisionReasonCode.GrantReplayed);
  });

  it("copying the SAME token bytes to a NEW filename is flagged tampered/malformed by the store's filename===claimed-jti invariant — it never becomes a covering grant, and the consumed original still denies grant_replayed", async () => {
    const env = await buildEnv();
    const request = criticalRequest({ requestId: "01REPLAYCOPYB0000000001" });

    const minted = await mintEphemeralGrant(
      { request, tier: "critical" },
      {
        store: env.store,
        keyStore: env.keyStore,
        nowEpochSeconds: env.currentClock(),
        generateId: () => nextId("JTI"),
      },
    );

    const first = await env.decider.decide(request);
    expect(first.outcome).toBe("allow");

    const originalBytes = readFileSync(
      jwsPathFor(env.home, minted.jti),
      "utf8",
    );
    const copyJti = `${minted.jti}-copy`;
    writeFileSync(jwsPathFor(env.home, copyJti), originalBytes);

    // Store level: the copy is undecodable-as-itself — its claimed jti
    // (the ORIGINAL's) does not match the filename it was found under, so
    // the store treats it as a tampered/misplaced file, never a fresh grant.
    const listed = env.store.list();
    expect(listed.invalid.some((g) => g.jti === copyJti)).toBe(true);
    expect(listed.active.some((g) => g.jti === minted.jti)).toBe(true);

    // Lifecycle level: the copy is folded into `rejected` as grant_malformed
    // — never a CoveringGrant. The ORIGINAL (correctly-named) file still
    // verifies fine (verifyGrant has no notion of consumption — that gate is
    // decideCore's, layered on top), so it's still the one and only
    // covering grant here; only the exactly-once consume gate stops it.
    const collected = collectCoveringGrants(request, {
      store: env.store,
      resolvedTier: "critical",
      nowEpochSeconds: env.currentClock(),
      resolvePublicKey: env.resolvePublicKey,
    });
    expect(collected.coveringGrants.some((g) => g.jti === minted.jti)).toBe(
      true,
    );
    expect(collected.coveringGrants.some((g) => g.jti === copyJti)).toBe(false);
    expect(
      collected.rejected.some(
        (r) => r.jti === copyJti && r.reason === GrantRejectionReason.Malformed,
      ),
    ).toBe(true);

    // Decision level: still grant_replayed — the copy under a new name never
    // resurrects the spent authorization.
    const second = await env.decider.decide(request);
    expect(second.outcome).toBe("deny");
    expect(second.reasonCode).toBe(GrantsDecisionReasonCode.GrantReplayed);
  });
});

// ===========================================================================
// (4) Expired-grant reuse — an expired grant is "absent" (architecture §5.4):
//     grant_expired at verify, the tier's no-grant default at decision.
// ===========================================================================

describe("(4) expired-grant reuse — treated as absent, tier default applies — T4", () => {
  it("a grant past its exp is grant_expired at verify AND deny/no_grant_sensitive at decision — never a revived allow", async () => {
    const env = await buildEnv();
    const request = sensitiveRequest({ requestId: "01REPLAYEXPIRED0000001" });
    const ttlSeconds = 3600;

    const minted = await mintDurableGrant(
      {
        principal: { type: "user", id: SUBJECT_ID },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds,
      },
      {
        store: env.store,
        keyStore: env.keyStore,
        nowEpochSeconds: env.currentClock(),
        generateId: () => nextId("JTI"),
      },
    );

    // Valid right now — a sanity baseline, not the point of the test.
    const beforeExpiry = await env.decider.decide(request);
    expect(beforeExpiry.outcome).toBe("allow");
    expect(beforeExpiry.reasonCode).toBe(L0ReasonCode.GrantAllow);

    // Advance the fake clock past exp (exclusive: now >= exp). This exceeds
    // the sensitive-tier decision-cache TTL (60s, `decision-cache.ts`) by a
    // wide margin, so the fresh evaluation below cannot be a stale cache hit.
    env.advanceClock(ttlSeconds);

    // Verify layer: the PRECISE rejection reason, asserted directly.
    const collected = collectCoveringGrants(request, {
      store: env.store,
      resolvedTier: "sensitive",
      nowEpochSeconds: env.currentClock(),
      resolvePublicKey: env.resolvePublicKey,
    });
    expect(collected.coveringGrants).toHaveLength(0);
    expect(collected.rejected).toEqual([
      { jti: minted.jti, reason: GrantRejectionReason.Expired },
    ]);

    // Decision layer: absent grant → the sensitive tier's no-grant default,
    // a deny — never an allow revived from the now-expired grant.
    const after = await env.decider.decide(request);
    expect(after.outcome).toBe("deny");
    expect(after.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });
});

// ===========================================================================
// (5) Scope mismatch — a durable grant scoped to one resource does not cover
//     a call against a different one: grant_scope_mismatch at verify, the
//     tier's no-grant default at decision.
// ===========================================================================

describe("(5) durable grant scoped elsewhere — grant_scope_mismatch, doesn't cover — T4", () => {
  const cases: Array<[string, DecisionRequest["resource"]]> = [
    [
      "a different repo owner (idPattern prefix mismatch)",
      { type: "github_repo", id: "someone-else/repo" },
    ],
    [
      "a different resourceType entirely",
      { type: "other_resource", id: "kno2gether/openclaw" },
    ],
  ];

  it.each(
    cases,
  )("same tool/principal/agent, temporally valid, but %s → grant_scope_mismatch (verify) + deny/no_grant_sensitive (decision)", async (_label, mismatchedResource) => {
    const env = await buildEnv();
    const minted = await mintDurableGrant(
      {
        principal: { type: "user", id: SUBJECT_ID },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      {
        store: env.store,
        keyStore: env.keyStore,
        nowEpochSeconds: env.currentClock(),
        generateId: () => nextId("JTI"),
      },
    );

    const request = sensitiveRequest({ resource: mismatchedResource });

    const collected = collectCoveringGrants(request, {
      store: env.store,
      resolvedTier: "sensitive",
      nowEpochSeconds: env.currentClock(),
      resolvePublicKey: env.resolvePublicKey,
    });
    expect(collected.coveringGrants).toHaveLength(0);
    expect(collected.rejected).toEqual([
      { jti: minted.jti, reason: GrantRejectionReason.ScopeMismatch },
    ]);

    const decision = await env.decider.decide(request);
    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });
});

// ===========================================================================
// (6) Untrusted issuer — a grant signed by a genuinely different, second
//     locally-generated Ed25519 identity.
// ===========================================================================

describe("(6) grant signed by an untrusted (non-locally-trusted) key — T4", () => {
  it("a real, validly-self-signed grant from a SECOND independent local identity is rejected grant_unknown_key at verify (its kid is never in OUR keys/ dir) + deny/no_grant_sensitive at decision", async () => {
    const env = await buildEnv();

    // A wholly separate local identity — generated under its OWN temp
    // $KNOTRUST_HOME, so its public key JWK is written to THAT home's
    // `keys/` directory, never `env.home/keys/`. `env.resolvePublicKey`
    // (`createDiskPublicKeyResolver(env.home)`) therefore has no way to ever
    // resolve this kid — it is not "an unknown attacker," it is a real,
    // independently-generated KnoTrust identity that simply never became
    // locally trusted by THIS home.
    const attacker = await buildUntrustedKeyStore();

    const request = sensitiveRequest({ requestId: "01REPLAYUNTRUSTED00001" });

    // Minted with the ATTACKER's key, but persisted into the REAL victim
    // store — modeling "a hostile/forged grant somehow lands in the local
    // grants directory" (e.g. disk tampering, a compromised writer). It is a
    // real, well-formed, validly-self-signed 3-segment JWS that would fully
    // cover this exact call (every pattern matches) if its key were trusted.
    const forged = await mintDurableGrant(
      {
        principal: { type: "user", id: SUBJECT_ID },
        agent: "*",
        tool: "github.*",
        scope: { resourceType: "github_repo", idPattern: "kno2gether/*" },
        tier: "sensitive",
        envelopeScope: "personal",
        ttlSeconds: 2_592_000,
      },
      {
        store: env.store,
        keyStore: attacker.keyStore,
        nowEpochSeconds: env.currentClock(),
        generateId: () => nextId("JTI"),
      },
    );
    expect(forged.token.split(".")).toHaveLength(3);

    // Verify layer — the PRECISE mapping this ruling (R137) requires be
    // documented: the plan names this case "grant_untrusted_issuer", but the
    // real E3-T2 vocabulary has no such code. `verifyGrant` checks key
    // resolution BEFORE the signature (`verify.ts` step 2 vs 3): a kid that
    // resolves to NO local key is `grant_unknown_key`; a kid that resolves
    // to SOME key but the wrong one is `grant_invalid_signature` (that
    // second sub-case is already golden-vector-locked as
    // `golden-vectors/grants/wrong-key.json`). A genuinely different,
    // second locally-generated identity's kid is — overwhelmingly, by the
    // SHA-256 derivation — never present among trusted keys at all, so the
    // real system produces `grant_unknown_key` here.
    const collected = collectCoveringGrants(request, {
      store: env.store,
      resolvedTier: "sensitive",
      nowEpochSeconds: env.currentClock(),
      resolvePublicKey: env.resolvePublicKey,
    });
    expect(collected.coveringGrants).toHaveLength(0);
    expect(collected.rejected).toEqual([
      { jti: forged.jti, reason: GrantRejectionReason.UnknownKey },
    ]);

    // Decision layer: absent grant → the sensitive tier's no-grant default —
    // a deny, never an allow from the untrusted-issuer grant.
    const decision = await env.decider.decide(request);
    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });
});
