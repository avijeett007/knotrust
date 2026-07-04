/**
 * P0-E11-T4 — the store-tamper detection adversarial suite.
 *
 * The load-bearing test for threat-model **T5 (Local store tampering, case
 * e)** (`docs/02-architecture/security-threat-model.md`) — "an attacker (or
 * the agent's ungated file tool) edits or truncates the audit log to erase
 * evidence of what was attempted, or edits a grant/policy file on disk" —
 * plus the local-store half of **T4 (Grant theft / forgery / replay)**:
 * "Local stores" column names both T5 and T4 (`§3.0`'s coverage matrix), and
 * T4's own mitigation list names key storage (`§I2.1`) whose residual is a
 * pubkey swap.
 *
 * This is a TEST-AUTHORING task against the already-built, already-verified
 * subsystems (P0-E4-T3 audit log + `verify()`, P0-E4-T4 the real `knotrust
 * audit verify` CLI, P0-E3-T2 grant verify, P0-E4-T1 the grant store, P0-E3-T1
 * the keystore) — it composes the REAL pieces, never a mock:
 *
 *   - **Audit tamper battery** — a real `@knotrust/store` `createAuditLog`
 *     sink seeds a real hash-chained JSONL fixture; each sub-case hand-edits
 *     the raw bytes on disk exactly the way a same-UID attacker or a crash
 *     would, then the ACTUAL SHIPPED BINARY (`packages/cli/dist/bin.js`,
 *     built by `pnpm turbo build` ahead of this suite — see `BUILT_CLI_BIN`
 *     below) is spawned as `knotrust audit verify` against that fixture,
 *     exactly as a human running the real CLI would. Every detectable case
 *     asserts the CLI's real exit code and the real stderr naming
 *     `file:line (seq N): kind` — never a hand-rolled expectation of what the
 *     tool *should* say.
 *   - **Grant tamper** — a real Ed25519 `KeyStore` mints a real durable grant
 *     via `mintDurableGrant`/`@knotrust/store`'s `createGrantStore`; a byte is
 *     hand-edited directly in the persisted `<jti>.jws` payload segment on
 *     disk, then the real `store.list()`, `collectCoveringGrants`, and the
 *     unified `createDecider` are run over the tampered file.
 *   - **Pubkey swap** — a real second Ed25519 identity's public key JWK is
 *     written OVER the original's `keys/<kid>.jwk.json` (same filename, same
 *     `kid`, different key material) and every previously-valid grant is
 *     re-verified/re-decided against the swapped file.
 *
 * ## R141 — honest about the audit chain's known limit (NOT weakened here)
 *
 * `audit-log.ts`'s own module header and `docs/03-engineering/
 * local-store-layout.md` §"audit/" already document this precisely: the hash
 * chain is **tamper-EVIDENT, not tamper-PROOF**. It reliably catches
 * accidental, naive, or partial tampering — a line edited without redoing
 * every downstream hash, a middle line deleted, a reorder, a write torn
 * mid-append — because `verify()` finds the first hash/prevHash/seq mismatch
 * at the tamper point. It does **NOT** catch a same-UID attacker who cleanly
 * deletes a WHOLE trailing run of the most-recent lines (or one who
 * recomputes the entire downstream chain to match): the chain is unkeyed
 * SHA-256 with no signature and no external anchor over the head, so a
 * cleanly-truncated-at-a-line-boundary suffix is indistinguishable from a
 * chain that simply never grew past that point. This suite proves the
 * DETECTABLE cases fail closed (every one below), and separately — honestly,
 * not by omission — proves the clean-trailing-run-deletion case is
 * UNDETECTABLE by `verify()` alone (see test "(1g)" below): it asserts
 * `verify()` reports the chain intact with the reduced count, exactly the
 * documented gap, never a false claim of detection.
 *
 * ## R142 — test-authoring, no product-code changes
 *
 * Every case here is expected to PASS by the built system already failing
 * closed / already detecting the tamper. If a tampered grant were ever
 * HONORED (yielded `allow`), or a DETECTABLE audit tamper went undetected,
 * that would be a Critical product bug to escalate BLOCKED with the exact
 * code path — never a test to weaken. The one non-test change this task
 * makes is the key-management doc note this suite proves true: swapping the
 * `keys/<kid>.jwk.json` public key invalidates every existing grant signed
 * under the original key (`docs/03-engineering/local-store-layout.md`
 * §"`keys/<kid>.jwk.json`").
 */

import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
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
  type KeyStore,
  mintDurableGrant,
} from "@knotrust/grants";
import {
  AuditEventType,
  computeArgsHash,
  createAuditLog,
  createGrantStore,
  type GrantStore,
} from "@knotrust/store";
import { afterEach, describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// The REAL shipped CLI binary. `pnpm turbo build` (acceptance step 1, and
// every workspace-wide `build`/`test` run) builds `packages/cli` via `tsup`
// BEFORE this package's tests run — turbo runs a named task across every
// workspace package that defines it, independent of this package's own
// `package.json` dependency graph, so `dist/bin.js` is guaranteed fresh by
// the time these tests execute under the acceptance command. This suite
// spawns it exactly as a human invoking `npx knotrust audit verify` would —
// no in-process shortcut, no mock — the same posture `packages/cli`'s own
// `run.built-bin.test.ts` (ADR-0016) established for "the bundled binary
// actually works," applied here to "the bundled binary actually detects."
// ---------------------------------------------------------------------------

const here = path.dirname(fileURLToPath(import.meta.url));
const BUILT_CLI_BIN = path.resolve(here, "../../../packages/cli/dist/bin.js");

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Spawns the REAL built `knotrust audit verify` against `home`. */
function runKnotrustAuditVerify(home: string): CliResult {
  const result = spawnSync(
    process.execPath,
    [BUILT_CLI_BIN, "audit", "verify"],
    {
      encoding: "utf8",
      env: { ...process.env, KNOTRUST_HOME: home },
    },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
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

function freshHome(prefix: string): string {
  const home = mkdtempSync(path.join(tmpdir(), prefix));
  cleanups.push(() => rmSync(home, { recursive: true, force: true }));
  return home;
}

// ===========================================================================
// (1) Audit tamper battery — real hash-chained fixture, real `knotrust audit
//     verify` CLI. T5.
// ===========================================================================

/** 10 real `type: "decision"` events via the REAL `createAuditLog` sink — a fixed injected clock (never `Date.now()`) keeps every run in one `<yyyymm>.jsonl` file, so line numbers are stable. */
const AUDIT_EVENT_COUNT = 10;

function seedAuditLog(home: string): void {
  let clockMs = 1_800_000_000_000;
  const sink = createAuditLog({ home, nowEpochMs: () => clockMs });
  for (let i = 0; i < AUDIT_EVENT_COUNT; i++) {
    clockMs += 1000;
    sink.append({
      type: AuditEventType.DECISION,
      surface: "mcp-stdio",
      subject: "user:local",
      agent: "claude-desktop",
      tool: `tool.call_${i}`,
      argsHash: computeArgsHash(null),
      outcome: "allow",
    });
  }
  // Close BEFORE any raw-file tampering below — releases the writer lock and
  // guarantees every byte is flushed, so the CLI's lock-free read sees
  // exactly what we wrote, never a buffered-but-unwritten tail.
  sink.close();
}

function soleAuditFile(home: string): string {
  const dir = path.join(home, "audit");
  const files = readdirSync(dir).filter((f) => f.endsWith(".jsonl"));
  if (files.length !== 1) {
    throw new Error(
      `expected exactly one .jsonl file, found: ${files.join(", ")}`,
    );
  }
  return path.join(dir, files[0] as string);
}

function readRawLines(filePath: string): string[] {
  return readFileSync(filePath, "utf8")
    .split("\n")
    .filter((l) => l.length > 0);
}

function writeRawLines(filePath: string, lines: string[]): void {
  writeFileSync(filePath, `${lines.join("\n")}\n`);
}

describe("(1) audit tamper battery — knotrust audit verify pinpoints every detectable tamper — T5", () => {
  it("(1a) an untampered chain: exits 0, 'chain intact (N events)'", () => {
    const home = freshHome("knotrust-tamper-audit-clean-");
    seedAuditLog(home);

    const result = runKnotrustAuditVerify(home);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(`chain intact (${AUDIT_EVENT_COUNT} events)\n`);
    expect(result.stderr).toBe("");
  });

  it("(1b) edit a byte in a middle line's claim value → hash_mismatch, CLI exits non-zero naming file:line and seq", () => {
    const home = freshHome("knotrust-tamper-audit-edit-");
    seedAuditLog(home);
    const filePath = soleAuditFile(home);
    const lines = readRawLines(filePath);

    // Line index 4 = the 5th append (seq 5), tool "tool.call_4". A single
    // character flip inside that string VALUE — everything else on the line
    // (seq, prevHash, hash, every other field) is untouched, so the stored
    // `hash` no longer matches the recomputed hash of the (now-different)
    // event content.
    const tamperedIndex = 4;
    const original = lines[tamperedIndex] as string;
    expect(original).toContain('"tool.call_4"');
    lines[tamperedIndex] = original.replace('"tool.call_4"', '"Xool.call_4"');
    writeRawLines(filePath, lines);

    const result = runKnotrustAuditVerify(home);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("seq 5");
    expect(result.stderr).toContain("hash_mismatch");
    expect(result.stderr).toMatch(/\.jsonl:5\b/);
  });

  it("(1c) swap two adjacent lines (seq 5 and 6) → detected at the first swapped position", () => {
    const home = freshHome("knotrust-tamper-audit-swap-");
    seedAuditLog(home);
    const filePath = soleAuditFile(home);
    const lines = readRawLines(filePath);

    const line5 = lines[4] as string;
    const line6 = lines[5] as string;
    lines[4] = line6;
    lines[5] = line5;
    writeRawLines(filePath, lines);

    const result = runKnotrustAuditVerify(home);

    expect(result.status).not.toBe(0);
    // ASSERT THE ACTUAL KIND THE BUILT VERIFY REPORTS (R140): `verifyChain`
    // checks `parsed.seq === expectedSeq` BEFORE it ever looks at prevHash or
    // the recomputed hash — so a swap is caught as `seq_gap` (seq 6 showing
    // up where seq 5 was expected), not `hash_mismatch`/`prevhash_mismatch`.
    // Still fully detected, at the FIRST swapped position — just a
    // different, equally valid `kind` label than "hash mismatch" would be.
    expect(result.stderr).toContain("seq 6");
    expect(result.stderr).toContain("seq_gap");
    expect(result.stderr).toMatch(/\.jsonl:5\b/);
  });

  it("(1d) truncate the log mid-write (a torn tail, no trailing newline) → torn_line at the next expected seq", () => {
    const home = freshHome("knotrust-tamper-audit-torn-");
    seedAuditLog(home);
    const filePath = soleAuditFile(home);
    const raw = readFileSync(filePath, "utf8");

    // Cut bytes off the very end, landing INSIDE the last line's content
    // (never at a clean newline boundary) — exactly the shape a crash
    // mid-`write()` leaves (audit-log.ts's own "torn tail" crash-recovery
    // doc). This is the "cut the tail mid ... line" half of R140's truncate
    // bullet.
    const cut = raw.slice(0, raw.length - 20);
    expect(cut.endsWith("\n")).toBe(false);
    writeFileSync(filePath, cut);

    const result = runKnotrustAuditVerify(home);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`seq ${AUDIT_EVENT_COUNT}`);
    expect(result.stderr).toContain("torn_line");
  });

  it("(1e) delete a MIDDLE line entirely → seq_gap naming the seq that's now unexpectedly there", () => {
    const home = freshHome("knotrust-tamper-audit-delete-");
    seedAuditLog(home);
    const filePath = soleAuditFile(home);
    const lines = readRawLines(filePath);

    // Delete seq 5 (index 4) outright — this also demonstrates R140's
    // truncate bullet's second alternative ("removes a MIDDLE line's worth"):
    // mechanically identical to a byte-range truncation that happens to
    // remove exactly one whole middle line.
    lines.splice(4, 1);
    writeRawLines(filePath, lines);

    const result = runKnotrustAuditVerify(home);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("seq 6");
    expect(result.stderr).toContain("seq_gap");
    expect(result.stderr).toMatch(/\.jsonl:5\b/);
  });

  it("(1f) back-date/alter the `seq` field alone on a middle line → still detected (the built verify reports seq_gap, not hash_mismatch)", () => {
    const home = freshHome("knotrust-tamper-audit-seqalter-");
    seedAuditLog(home);
    const filePath = soleAuditFile(home);
    const lines = readRawLines(filePath);

    // Alter ONLY the `seq` field's value on line 5 (index 4) — leave `hash`,
    // `prevHash`, and every other field byte-identical. `seq` genuinely IS
    // part of the hashed event content (audit-log.ts: `hash =
    // sha256(canonicalizeJcs(eventWithoutHash))`, and `seq` is a top-level
    // field of that object), so this edit DOES also break the hash. But
    // `verifyChain` checks `parsed.seq !== expectedSeq` strictly BEFORE it
    // ever reaches the hash recomputation — any standalone edit to a line's
    // own `seq` value is therefore caught by that earlier, cheaper
    // seq-continuity check first. ASSERT THE ACTUAL KIND (R140): `seq_gap`,
    // naming the tampered (back-dated/altered) value itself — not
    // `hash_mismatch`. This is still full detection, at the same position,
    // just via a different (and strictly earlier) check than a hash
    // recomputation would need.
    const obj = JSON.parse(lines[4] as string) as Record<string, unknown>;
    expect(obj.seq).toBe(5);
    obj.seq = 999; // "altered" — any value other than the true 5 proves the point
    lines[4] = JSON.stringify(obj);
    writeRawLines(filePath, lines);

    const result = runKnotrustAuditVerify(home);

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("seq 999");
    expect(result.stderr).toContain("seq_gap");
    expect(result.stderr).toMatch(/\.jsonl:5\b/);
  });

  it("(1g) HONEST LIMIT (R141): a clean deletion of a whole trailing run of the most-recent lines is undetectable by verify() alone", () => {
    const home = freshHome("knotrust-tamper-audit-trailing-");
    seedAuditLog(home);
    const filePath = soleAuditFile(home);
    const lines = readRawLines(filePath);

    // Remove the last 3 lines WHOLE (seq 8, 9, 10), leaving a clean
    // newline-terminated file with a perfectly consistent internal chain of
    // 7 events. This is the documented, known gap (audit-log.ts's module
    // header; docs/03-engineering/local-store-layout.md §"audit/"; security
    // threat model §T5's residual): with no external anchor over the chain
    // head, a clean trailing-run deletion is indistinguishable from "the
    // chain simply never grew past event 7." This test does NOT claim
    // detection that doesn't exist — it asserts the honest limit: verify()
    // reports the chain INTACT (not broken) with the reduced count.
    const truncated = lines.slice(0, AUDIT_EVENT_COUNT - 3);
    writeRawLines(filePath, truncated);

    const result = runKnotrustAuditVerify(home);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(
      `chain intact (${AUDIT_EVENT_COUNT - 3} events)\n`,
    );
    expect(result.stderr).toBe("");
  });
});

// ===========================================================================
// (2) Grant tamper — a tampered .jws payload never covers a call. T4.
// ===========================================================================

const SUBJECT_ID = "avijeett007@gmail.com";
const HUMAN_AGENT_ID = "claude-desktop";
const INITIAL_CLOCK = 1_800_000_000;

/** `github.create_issue` resolves `sensitive` — `no_grant_sensitive` is a DENY (`packages/core/src/l0-evaluator.ts`), matching every "never honored" assertion below to a real tier-default deny, never an ambiguous outcome. */
const POLICY: TierPolicy = {
  tools: { "github.create_issue": { tier: "sensitive", source: "pack" } },
  unknownToolTier: "sensitive",
};

function githubRequest(over: Partial<DecisionRequest> = {}): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01STORETAMPERREQ000001",
    timestamp: "2026-07-04T12:00:00Z",
    subject: { type: "user", id: SUBJECT_ID },
    action: { name: "github.create_issue" },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: HUMAN_AGENT_ID, type: "ai_agent" },
      env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
    },
    surface: { kind: "stdio_proxy", instanceId: "px-tamper", server: "github" },
    ...over,
  };
}

interface GrantEnv {
  home: string;
  store: GrantStore;
  keyStore: KeyStore;
  kid: string;
  resolvePublicKey: (kid: string) => Ed25519PublicJwk | null;
  decider: Decider;
  currentClock(): number;
}

let idSeq = 0;
function nextId(prefix: string): string {
  return `${prefix}${String(idSeq++).padStart(6, "0")}`;
}

/** Composes the REAL keystore + store + decider over a fresh temp `$KNOTRUST_HOME` — no audit sink (mirrors P0-E11-T3's `grant-replay.test.ts` harness rationale: audit is optional on `createDecider` and orthogonal to this task's substrate). */
async function buildGrantEnv(): Promise<GrantEnv> {
  const home = freshHome("knotrust-tamper-grant-");

  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const cache = createDecisionCache({ nowEpochSeconds: () => INITIAL_CLOCK });

  const priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;
  const keyStore = await createKeyStore({ backend: "file" });
  const identity = await keyStore.ensureIdentity();
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;

  const resolvePublicKey = createDiskPublicKeyResolver(home);

  const decider = createDecider({
    cache,
    tierPolicy: POLICY,
    policyVersion: "pv1",
    store,
    resolvePublicKey,
    nowEpochSeconds: () => INITIAL_CLOCK,
    nowMs: () => INITIAL_CLOCK * 1000,
    generateId: () => nextId("DEC"),
  });

  return {
    home,
    store,
    keyStore,
    kid: identity.kid,
    resolvePublicKey,
    decider,
    currentClock: () => INITIAL_CLOCK,
  };
}

function jwsPathFor(home: string, jti: string): string {
  return path.join(home, "grants", `${jti}.jws`);
}

describe("(2) grant tamper — a tampered .jws payload never decides an allow — T4", () => {
  it("(2a) a byte flip that breaks the payload's JSON decode: store.list().invalid[] surfaces grant_invalid, folded to grant_malformed upstream, never covers the call, tier default applies, no crash", async () => {
    const env = await buildGrantEnv();
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

    const jwsPath = jwsPathFor(env.home, minted.jti);
    const original = readFileSync(jwsPath, "utf8").trim();
    const [header, payload, sig] = original.split(".");
    if (header === undefined || payload === undefined || sig === undefined) {
      throw new Error("minted token is not a 3-segment JWS — test setup bug");
    }

    // Flip ONE raw base64url character in the middle of the ON-DISK payload
    // segment — the most literal reading of "edit a byte in a stored grant
    // .jws payload." This shifts the underlying decoded bytes, which —
    // given this fixture's fixed content — breaks JSON.parse deterministically.
    const mid = Math.floor(payload.length / 2);
    const chars = payload.split("");
    const origChar = chars[mid] as string;
    chars[mid] = origChar === "A" ? "B" : "A";
    const tamperedPayload = chars.join("");

    // Prove the premise rather than assume it: this byte flip really does
    // break decode for this exact fixture. If a future fixture change ever
    // makes this flip decode-preserving, THIS assertion fails loudly here —
    // never silently degrading into a no-op test.
    let stillDecodes = true;
    try {
      JSON.parse(Buffer.from(tamperedPayload, "base64url").toString("utf8"));
    } catch {
      stillDecodes = false;
    }
    expect(stillDecodes).toBe(false);

    writeFileSync(jwsPath, `${header}.${tamperedPayload}.${sig}\n`);

    let listed: ReturnType<GrantStore["list"]> | undefined;
    expect(() => {
      listed = env.store.list();
    }).not.toThrow();
    expect(listed?.invalid).toEqual([
      { jti: minted.jti, reason: "grant_invalid" },
    ]);
    expect(listed?.active).toEqual([]);

    const request = githubRequest();
    let collected: ReturnType<typeof collectCoveringGrants> | undefined;
    expect(() => {
      collected = collectCoveringGrants(request, {
        store: env.store,
        resolvedTier: "sensitive",
        nowEpochSeconds: env.currentClock(),
        resolvePublicKey: env.resolvePublicKey,
      });
    }).not.toThrow();
    expect(collected?.coveringGrants).toEqual([]);
    expect(collected?.rejected).toEqual([
      { jti: minted.jti, reason: GrantRejectionReason.Malformed },
    ]);

    const decision = await env.decider.decide(request);
    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });

  it("(2b) a byte flip inside a claim's string VALUE that keeps the JSON valid still fails Ed25519 verification (grant_invalid_signature) — never honored, tier default applies, no crash", async () => {
    const env = await buildGrantEnv();
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

    const jwsPath = jwsPathFor(env.home, minted.jti);
    const original = readFileSync(jwsPath, "utf8").trim();
    const [header, payload, sig] = original.split(".");
    if (header === undefined || payload === undefined || sig === undefined) {
      throw new Error("minted token is not a 3-segment JWS — test setup bug");
    }

    // Decode, flip one character strictly INSIDE the `"t":"..."` (tool)
    // claim's string value — keeps the JSON syntactically valid (so THIS
    // file decodes fine and the store's scan will call it "active"), but the
    // decoded claims — and therefore the signed bytes — genuinely differ
    // from what the signature covers.
    const decodedJson = Buffer.from(payload, "base64url").toString("utf8");
    const marker = '"t":"';
    const markerIdx = decodedJson.indexOf(marker);
    expect(markerIdx).toBeGreaterThan(-1);
    const valueStart = markerIdx + marker.length;
    const targetChar = decodedJson[valueStart] as string;
    const replacement = targetChar === "g" ? "Z" : "g";
    const mutatedJson =
      decodedJson.slice(0, valueStart) +
      replacement +
      decodedJson.slice(valueStart + 1);
    expect(mutatedJson).not.toBe(decodedJson);
    // Sanity: still valid JSON (proves this is the "signature fails, decode
    // doesn't" branch, distinct from (2a)'s decode-breaking flip).
    expect(() => JSON.parse(mutatedJson)).not.toThrow();

    const tamperedPayload = Buffer.from(mutatedJson, "utf8").toString(
      "base64url",
    );
    writeFileSync(jwsPath, `${header}.${tamperedPayload}.${sig}\n`);

    let listed: ReturnType<GrantStore["list"]> | undefined;
    expect(() => {
      listed = env.store.list();
    }).not.toThrow();
    // Decode succeeded and the claimed jti still matches the filename, so the
    // STORE's own (signature-blind, R29) scan calls this "active" — the
    // store's job ends at decodability, never signature verification.
    expect(listed?.invalid).toEqual([]);
    expect(listed?.active).toEqual([
      { jti: minted.jti, token: `${header}.${tamperedPayload}.${sig}` },
    ]);

    const request = githubRequest();
    let collected: ReturnType<typeof collectCoveringGrants> | undefined;
    expect(() => {
      collected = collectCoveringGrants(request, {
        store: env.store,
        resolvedTier: "sensitive",
        nowEpochSeconds: env.currentClock(),
        resolvePublicKey: env.resolvePublicKey,
      });
    }).not.toThrow();
    expect(collected?.coveringGrants).toEqual([]);
    expect(collected?.rejected).toEqual([
      { jti: minted.jti, reason: GrantRejectionReason.InvalidSignature },
    ]);

    const decision = await env.decider.decide(request);
    expect(decision.outcome).toBe("deny");
    expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
  });
});

// ===========================================================================
// (3) Pubkey swap — replacing a trusted key invalidates every existing grant
//     signed under it. T4 (key-management doc note).
// ===========================================================================

describe("(3) pubkey swap — replacing keys/<kid>.jwk.json invalidates every existing grant signed under the original key — T4", () => {
  it("mints 3 durable grants under identity A (each currently covers its call); overwriting keys/<kid_A>.jwk.json with a DIFFERENT identity's pubkey (same kid filename) invalidates ALL of them — grant_invalid_signature, never honored, tier default for each, no crash", async () => {
    const env = await buildGrantEnv();

    const resourceIds = ["repo-alpha", "repo-beta", "repo-gamma"];
    const minted = await Promise.all(
      resourceIds.map((id) =>
        mintDurableGrant(
          {
            principal: { type: "user", id: SUBJECT_ID },
            agent: "*",
            tool: "github.*",
            scope: {
              resourceType: "github_repo",
              idPattern: `kno2gether/${id}`,
            },
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
        ),
      ),
    );
    const requests = resourceIds.map((id) =>
      githubRequest({
        resource: { type: "github_repo", id: `kno2gether/${id}` },
      }),
    );

    // Baseline (verify layer, no decision-cache involvement): every grant
    // genuinely covers its OWN exact call under the ORIGINAL key. `store.
    // list()` is unfiltered (by design, R29/R35), so each check also runs
    // the OTHER two grants through `verifyGrant` — they correctly reject as
    // `grant_scope_mismatch` (a different repo), proof this store is doing
    // real per-candidate verification, not just trusting the one match.
    for (let i = 0; i < minted.length; i++) {
      const collected = collectCoveringGrants(requests[i] as DecisionRequest, {
        store: env.store,
        resolvedTier: "sensitive",
        nowEpochSeconds: env.currentClock(),
        resolvePublicKey: env.resolvePublicKey,
      });
      expect(collected.coveringGrants.map((g) => g.jti)).toEqual([
        minted[i]?.jti,
      ]);
      const otherJtis = minted
        .filter((_, j) => j !== i)
        .map((m) => m.jti)
        .sort();
      expect(
        collected.rejected.every(
          (r) => r.reason === GrantRejectionReason.ScopeMismatch,
        ),
      ).toBe(true);
      expect(collected.rejected.map((r) => r.jti).sort()).toEqual(otherJtis);
    }

    // A SECOND, wholly independent local Ed25519 identity, generated under
    // its OWN temp home — never sharing any key material with `env.home`.
    const otherHome = freshHome("knotrust-tamper-pubkeyswap-other-");
    const priorHome = process.env.KNOTRUST_HOME;
    process.env.KNOTRUST_HOME = otherHome;
    const otherKeyStore = await createKeyStore({ backend: "file" });
    const otherIdentity = await otherKeyStore.ensureIdentity();
    if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
    else process.env.KNOTRUST_HOME = priorHome;
    expect(otherIdentity.kid).not.toBe(env.kid);

    // The swap: overwrite `keys/<kid_A>.jwk.json` (SAME filename — the kid
    // string embedded in every already-minted grant's JWS header is
    // unchanged) with the SECOND identity's public key JWK content. This is
    // the literal "replace the keys/<kid>.jwk.json public key ... with a
    // DIFFERENT key" (R140) — no new file, no renamed kid, just different
    // bytes under the name every old grant's header still names.
    const jwkPathA = path.join(env.home, "keys", `${env.kid}.jwk.json`);
    const jwkContentB = readFileSync(
      path.join(otherHome, "keys", `${otherIdentity.kid}.jwk.json`),
      "utf8",
    );
    writeFileSync(jwkPathA, jwkContentB);

    // Every previously-valid grant now fails verification: the kid resolves
    // (the file is still there, still named `<kid_A>.jwk.json`) to a REAL
    // but WRONG public key — Ed25519 signature verification fails ⇒
    // `grant_invalid_signature` (R140's first documented alternative; the
    // "kid changes" alternative — an unresolvable kid ⇒ `grant_unknown_key`
    // — is already proven by P0-E11-T3's `grant-replay.test.ts` variant (6)
    // "untrusted issuer" and is not duplicated here). The signature check
    // runs BEFORE pattern matching (`verify.ts` step 3 vs step 5), so ALL
    // THREE grants now fail this way for EVERY request, regardless of which
    // one used to be the scope-matching candidate — proving the swap
    // invalidates the full set, not just the one grant each request used to
    // resolve.
    const allJtis = minted.map((m) => m.jti).sort();
    for (let i = 0; i < minted.length; i++) {
      let collected: ReturnType<typeof collectCoveringGrants> | undefined;
      expect(() => {
        collected = collectCoveringGrants(requests[i] as DecisionRequest, {
          store: env.store,
          resolvedTier: "sensitive",
          nowEpochSeconds: env.currentClock(),
          resolvePublicKey: env.resolvePublicKey,
        });
      }).not.toThrow();
      expect(collected?.coveringGrants).toEqual([]);
      expect(
        collected?.rejected.every(
          (r) => r.reason === GrantRejectionReason.InvalidSignature,
        ),
      ).toBe(true);
      expect(collected?.rejected.map((r) => r.jti).sort()).toEqual(allJtis);
    }

    // Full decision-level proof, end to end, via a FRESH cache instance (so
    // no pre-swap cached "allow" from the baseline loop above could ever
    // mask the swap's effect — the point here is the offline verify/store
    // property, not decision-cache TTL timing): every previously-valid
    // grant now decides the tier's no-grant default, never an allow.
    const freshCache = createDecisionCache({
      nowEpochSeconds: () => env.currentClock(),
    });
    const freshDecider = createDecider({
      cache: freshCache,
      tierPolicy: POLICY,
      policyVersion: "pv1",
      store: env.store,
      resolvePublicKey: env.resolvePublicKey,
      nowEpochSeconds: () => env.currentClock(),
      nowMs: () => env.currentClock() * 1000,
      generateId: () => nextId("SWAPDEC"),
    });
    for (const request of requests) {
      const decision = await freshDecider.decide(request as DecisionRequest);
      expect(decision.outcome).toBe("deny");
      expect(decision.reasonCode).toBe(L0ReasonCode.NoGrantSensitive);
    }
  });
});
