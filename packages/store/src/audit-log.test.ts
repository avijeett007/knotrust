/**
 * @knotrust/store — audit-log.ts unit tests (P0-E4-T3; rulings R36–R38).
 *
 * Every test gets its own fresh temp `home` (via `mkdtempSync`), passed
 * explicitly through `createAuditLog({ home, nowEpochMs, ... })` — never the
 * real `~/.knotrust`. The clock is ALWAYS injected (`nowEpochMs`), never
 * `Date.now()`, so every timestamp/file-rotation assertion in this suite is
 * deterministic.
 *
 * This file uses the REAL `node:fs` (no mocking) — it proves the log's
 * actual on-disk behavior: chain hashing, `verify()`'s tamper detection,
 * cross-file rotation, crash-recovery (torn tail), and the writer lock.
 * EACCES-style fault injection and fsync-batching timing live in the
 * sibling `audit-log.fault-injection.test.ts`, which mocks `node:fs`.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { canonicalizeJcs } from "@knotrust/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AUDIT_GENESIS_PREV_HASH,
  type AuditEvent,
  AuditEventType,
  type AuditSink,
  computeArgsHash,
  createAuditLog,
  streamAuditEvents,
  verifyAuditChain,
} from "./audit-log.js";

// ---------------------------------------------------------------------------
// Harness — fresh temp home per test, injected fake clock.
// ---------------------------------------------------------------------------

let tempHome: string;
let sink: AuditSink | undefined;

beforeEach(() => {
  tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-audit-test-"));
  sink = undefined;
});

afterEach(() => {
  try {
    sink?.close();
  } catch {
    // best-effort — some tests intentionally leave the sink broken
  }
  rmSync(tempHome, { recursive: true, force: true });
});

function auditDirPath(): string {
  return path.join(tempHome, "audit");
}

/** `noUncheckedIndexedAccess`/possibly-undefined narrowing without `!` (biome's `noNonNullAssertion`). */
function must<T>(value: T | undefined, label = "value"): T {
  if (value === undefined) {
    throw new Error(`must(): ${label} was unexpectedly undefined`);
  }
  return value;
}

function fakeClock(startMs: number): {
  now: () => number;
  set: (ms: number) => void;
} {
  let current = startMs;
  return {
    now: () => current,
    set: (ms: number) => {
      current = ms;
    },
  };
}

const JUNE_15_2026 = Date.UTC(2026, 5, 15, 12, 0, 0);

function baseEvent(over: Partial<Parameters<AuditSink["append"]>[0]> = {}) {
  return {
    type: AuditEventType.DECISION,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "claude-desktop",
    tool: "github.create_issue",
    argsHash: computeArgsHash({ repo: "knotrust", title: "test" }),
    outcome: "allow",
    ...over,
  };
}

function readLines(filePath: string): unknown[] {
  const raw = readFileSync(filePath, "utf8");
  return raw
    .split("\n")
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l));
}

// ---------------------------------------------------------------------------
// createAuditLog() — construction, directory layout, permissions.
// ---------------------------------------------------------------------------

describe("createAuditLog()", () => {
  it("creates <home>/audit as 0700", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    sink.append(baseEvent());

    expect(statSync(auditDirPath()).mode & 0o777).toBe(0o700);
  });

  it("creates the current month's file named <yyyymm>.jsonl", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    sink.append(baseEvent());

    expect(existsSync(path.join(auditDirPath(), "202606.jsonl"))).toBe(true);
  });

  it("uses KNOTRUST_HOME when opts.home is omitted", () => {
    const ORIGINAL = process.env.KNOTRUST_HOME;
    process.env.KNOTRUST_HOME = tempHome;
    try {
      const clock = fakeClock(JUNE_15_2026);
      sink = createAuditLog({ nowEpochMs: clock.now });
      sink.append(baseEvent());
      expect(existsSync(path.join(tempHome, "audit", "202606.jsonl"))).toBe(
        true,
      );
    } finally {
      if (ORIGINAL === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = ORIGINAL;
    }
  });
});

// ---------------------------------------------------------------------------
// append() — chain construction, field shape, genesis.
// ---------------------------------------------------------------------------

describe("append()", () => {
  it("assigns seq starting at 1 and genesis prevHash (64 zeros) for the first event", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const first = sink.append(baseEvent());

    expect(first.seq).toBe(1);
    expect(first.prevHash).toBe(AUDIT_GENESIS_PREV_HASH);
    expect(AUDIT_GENESIS_PREV_HASH).toBe("0".repeat(64));
    expect(first.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("chains seq/prevHash monotonically across successive appends", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const a = sink.append(baseEvent());
    const b = sink.append(baseEvent());
    const c = sink.append(baseEvent());

    expect([a.seq, b.seq, c.seq]).toEqual([1, 2, 3]);
    expect(b.prevHash).toBe(a.hash);
    expect(c.prevHash).toBe(b.hash);
  });

  it("stamps ts as RFC 3339 from the injected clock, never Date.now()", () => {
    const fixedMs = Date.UTC(2026, 0, 2, 3, 4, 5, 6);
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => fixedMs });

    const event = sink.append(baseEvent());

    expect(event.ts).toBe(new Date(fixedMs).toISOString());
  });

  it("hash = sha256(utf8(canonicalizeJcs(event-without-hash-including-prevHash))) — R36 exact formula", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const event = sink.append(baseEvent());
    const { hash, ...withoutHash } = event;
    const expectedHash = createHash("sha256")
      .update(canonicalizeJcs(withoutHash), "utf8")
      .digest("hex");

    expect(hash).toBe(expectedHash);
  });

  it("writes exactly one JSONL line per append, parseable and matching the returned event", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const event = sink.append(baseEvent());
    const lines = readLines(path.join(auditDirPath(), "202606.jsonl"));

    expect(lines).toEqual([event]);
  });

  it("omits optional fields entirely (never null/undefined) when not supplied", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const event = sink.append({
      type: AuditEventType.GRANT_CREATED,
      surface: "cli",
      subject: "user:local",
      agent: "codex-cli",
      tool: "stripe.create_refund",
      argsHash: computeArgsHash(null),
    });

    expect("outcome" in event).toBe(false);
    expect("reason" in event).toBe(false);
    expect("grantRefs" in event).toBe(false);
    expect("approvalId" in event).toBe(false);
    expect("latencyMs" in event).toBe(false);
    expect("cacheHit" in event).toBe(false);
    expect("rawArgs" in event).toBe(false);
    expect("tier" in event).toBe(false);
  });

  it("carries through outcome/reason/grantRefs/approvalId/latencyMs/cacheHit/tier when supplied", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const event = sink.append(
      baseEvent({
        outcome: "deny",
        reason: "tier_exceeded",
        grantRefs: ["01JZGRANT0001", "01JZGRANT0002"],
        approvalId: "01JZAPPROVAL001",
        latencyMs: 42,
        cacheHit: true,
        tier: "critical",
      }),
    );

    expect(event.outcome).toBe("deny");
    expect(event.reason).toBe("tier_exceeded");
    expect(event.grantRefs).toEqual(["01JZGRANT0001", "01JZGRANT0002"]);
    expect(event.approvalId).toBe("01JZAPPROVAL001");
    expect(event.latencyMs).toBe(42);
    expect(event.cacheHit).toBe(true);
    expect(event.tier).toBe("critical");
  });

  it("exports AuditEventType constants for the P0 vocabulary", () => {
    expect(AuditEventType.DECISION).toBe("decision");
    expect(AuditEventType.GRANT_CREATED).toBe("grant_created");
    expect(AuditEventType.GRANT_REVOKED).toBe("grant_revoked");
    expect(AuditEventType.GRANT_CONSUMED).toBe("grant_consumed");
    expect(AuditEventType.APPROVAL_REQUESTED).toBe("approval_requested");
    expect(AuditEventType.APPROVAL_PENDING).toBe("approval_pending");
    expect(AuditEventType.APPROVAL_APPROVED).toBe("approval_approved");
    expect(AuditEventType.APPROVAL_DENIED).toBe("approval_denied");
    expect(AuditEventType.APPROVAL_EXPIRED).toBe("approval_expired");
    expect(AuditEventType.APPROVAL_CANCELLED).toBe("approval_cancelled");
    expect(AuditEventType.FAIL_OPEN_FIRED).toBe("fail_open_fired");
    expect(AuditEventType.TOOL_DEFINITION_CHANGED).toBe(
      "tool_definition_changed",
    );
    expect(AuditEventType.DENIAL_PROBING_SUSPECTED).toBe(
      "denial_probing_suspected",
    );
    expect(AuditEventType.PROBE_FLAGGED).toBe("probe_flagged");
    expect(AuditEventType.AUDIT_RECOVERED).toBe("audit_recovered");
    // P0-E6-T3: the localhost approval page's own rejection vocabulary.
    expect(AuditEventType.APPROVAL_CHANNEL_VIOLATION).toBe(
      "approval_channel_violation",
    );
  });

  it("a decision-type event can carry cacheHit: true (cache hits audited distinctly, brief §E5)", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const event = sink.append(
      baseEvent({ type: AuditEventType.DECISION, cacheHit: true }),
    );

    expect(event.type).toBe("decision");
    expect(event.cacheHit).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computeArgsHash() — R37 exact formula.
// ---------------------------------------------------------------------------

describe("computeArgsHash()", () => {
  it("hashes canonicalizeJcs(args) with a sha256: prefix", () => {
    const args = { b: 2, a: 1 };
    const expected = `sha256:${createHash("sha256").update(canonicalizeJcs(args), "utf8").digest("hex")}`;

    expect(computeArgsHash(args)).toBe(expected);
  });

  it("treats undefined the same as null (arguments ?? null)", () => {
    expect(computeArgsHash(undefined)).toBe(computeArgsHash(null));
  });

  it("never throws — non-canonicalizable input yields the literal 'unavailable'", () => {
    let result: string | undefined;
    expect(() => {
      result = computeArgsHash({ fn: () => 1 });
    }).not.toThrow();
    expect(result).toBe("unavailable");

    expect(computeArgsHash(BigInt(1))).toBe("unavailable");

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(computeArgsHash(cyclic)).toBe("unavailable");
  });

  it("is deterministic regardless of key order (canonical JSON)", () => {
    expect(computeArgsHash({ a: 1, b: 2 })).toBe(
      computeArgsHash({ b: 2, a: 1 }),
    );
  });
});

// ---------------------------------------------------------------------------
// Raw-args hygiene — default-off, opt-in via captureRawArgs.
// ---------------------------------------------------------------------------

describe("raw-args capture (secrets hygiene)", () => {
  const SENTINEL = "SUPER_SECRET_SENTINEL_VALUE_0xDEADBEEF";

  it("never writes rawArgs to disk by default, even if the caller supplies it", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    sink.append(
      baseEvent({
        argsHash: computeArgsHash({ secret: SENTINEL }),
        // biome-ignore lint/suspicious/noExplicitAny: intentionally passing an extra field a careless caller might include
        ...({ rawArgs: { secret: SENTINEL } } as any),
      }),
    );
    sink.close();

    const raw = readFileSync(path.join(auditDirPath(), "202606.jsonl"), "utf8");
    expect(raw).not.toContain(SENTINEL);
    expect(raw).not.toContain("rawArgs");
  });

  it("writes rawArgs when the sink is constructed with captureRawArgs: true", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({
      home: tempHome,
      nowEpochMs: clock.now,
      captureRawArgs: true,
    });

    const event = sink.append(
      baseEvent({
        argsHash: computeArgsHash({ secret: SENTINEL }),
        // biome-ignore lint/suspicious/noExplicitAny: rawArgs is a beyond-frozen-schema field, added only when captureRawArgs is on
        ...({ rawArgs: { secret: SENTINEL } } as any),
      }),
    );
    sink.close();

    expect(
      (event as unknown as { rawArgs: { secret: string } }).rawArgs,
    ).toEqual({ secret: SENTINEL });
    const raw = readFileSync(path.join(auditDirPath(), "202606.jsonl"), "utf8");
    expect(raw).toContain(SENTINEL);
  });
});

// ---------------------------------------------------------------------------
// verify() — happy path + full tamper matrix with exact break positions.
// ---------------------------------------------------------------------------

describe("verify()", () => {
  it("reports { ok: true, events: 0 } for a freshly-constructed, never-appended log", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    expect(sink.verify()).toEqual({ ok: true, events: 0 });
  });

  it("reports { ok: true, events: n } for an untampered chain", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 25; i++) sink.append(baseEvent());

    expect(sink.verify()).toEqual({ ok: true, events: 25 });
  });

  it("10k-event chain: builds and verifies, streaming (not slurping) — states elapsed time", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const buildStart = performance.now();
    for (let i = 0; i < 10_000; i++) {
      sink.append(baseEvent({ latencyMs: i % 500 }));
    }
    const buildMs = performance.now() - buildStart;

    const verifyStart = performance.now();
    const result = sink.verify();
    const verifyMs = performance.now() - verifyStart;

    console.log(
      `[P0-E4-T3 acceptance] 10k-event build: ${buildMs.toFixed(1)}ms, verify: ${verifyMs.toFixed(1)}ms`,
    );

    expect(result).toEqual({ ok: true, events: 10_000 });
    // Generous sanity bound, not a tight perf assertion (brief: memory
    // assertion optional; elapsed time must be STATED, not necessarily
    // gated) — this just catches an accidental O(n^2) regression.
    expect(verifyMs).toBeLessThan(10_000);
  });

  it("tamper: editing one field (without recomputing hash) is detected as hash_mismatch at the exact seq", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 10; i++) sink.append(baseEvent());
    sink.close();

    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const lines = readFileSync(filePath, "utf8").split("\n");
    const tamperedLineIndex = 4; // seq 5 (0-indexed line 4)
    const event = JSON.parse(must(lines[tamperedLineIndex])) as Record<
      string,
      unknown
    >;
    event.tool = "TAMPERED.tool";
    lines[tamperedLineIndex] = canonicalizeJcs(event);
    writeFileSync(filePath, lines.join("\n"));

    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const result = sink.verify();

    expect(result).toEqual({
      ok: false,
      breakAt: {
        file: "202606.jsonl",
        line: 5,
        seq: 5,
        kind: "hash_mismatch",
      },
    });
  });

  it("tamper: deleting a line is detected as seq_gap at the exact position", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 10; i++) sink.append(baseEvent());
    sink.close();

    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const lines = readFileSync(filePath, "utf8").split("\n").filter(Boolean);
    lines.splice(4, 1); // delete seq 5 entirely; seq 6 now sits at line 5
    writeFileSync(filePath, `${lines.join("\n")}\n`);

    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const result = sink.verify();

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.breakAt.file).toBe("202606.jsonl");
      expect(result.breakAt.line).toBe(5);
      expect(result.breakAt.kind).toBe("seq_gap");
      expect(result.breakAt.seq).toBe(6);
    }
  });

  it("tamper: swapping two lines is detected at the exact position (seq_gap, out-of-order)", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 10; i++) sink.append(baseEvent());
    sink.close();

    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const lines = readFileSync(filePath, "utf8").split("\n").filter(Boolean);
    const tmp = must(lines[2]);
    lines[2] = must(lines[5]);
    lines[5] = tmp;
    writeFileSync(filePath, `${lines.join("\n")}\n`);

    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const result = sink.verify();

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.breakAt.file).toBe("202606.jsonl");
      expect(result.breakAt.line).toBe(3); // first disrupted position
      expect(result.breakAt.kind).toBe("seq_gap");
    }
  });

  it("tamper: isolated prevHash edit (self-consistent hash, broken link) is detected as prevhash_mismatch", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 5; i++) sink.append(baseEvent());
    sink.close();

    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const lines = readFileSync(filePath, "utf8").split("\n").filter(Boolean);
    const event = JSON.parse(must(lines[2])) as Record<string, unknown>; // seq 3
    event.prevHash = "f".repeat(64); // wrong, but re-derive a self-consistent hash
    const { hash: _oldHash, ...withoutHash } = event;
    const newHash = createHash("sha256")
      .update(canonicalizeJcs(withoutHash), "utf8")
      .digest("hex");
    lines[2] = canonicalizeJcs({ ...withoutHash, hash: newHash });
    writeFileSync(filePath, `${lines.join("\n")}\n`);

    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const result = sink.verify();

    expect(result).toEqual({
      ok: false,
      breakAt: {
        file: "202606.jsonl",
        line: 3,
        seq: 3,
        kind: "prevhash_mismatch",
      },
    });
  });

  it("R126: tier is additive and hash-chain-safe — a mixed chain of old-style (no tier) and new-style (tier) events still verifies clean", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const oldStyle1 = sink.append(baseEvent()); // pre-R126 shape: no tier at all
    const newStyle = sink.append(baseEvent({ tier: "sensitive" }));
    const oldStyle2 = sink.append(baseEvent());
    const critical = sink.append(baseEvent({ tier: "critical" }));

    expect("tier" in oldStyle1).toBe(false);
    expect(newStyle.tier).toBe("sensitive");
    expect("tier" in oldStyle2).toBe(false);
    expect(critical.tier).toBe("critical");

    // The chain hash-links correctly across the mix — an event's hash is
    // computed over its OWN canonical form (including its own optional
    // `tier` or lack thereof), so a neighbor's differing field set never
    // perturbs it.
    expect(newStyle.prevHash).toBe(oldStyle1.hash);
    expect(oldStyle2.prevHash).toBe(newStyle.hash);
    expect(critical.prevHash).toBe(oldStyle2.hash);
    expect(sink.verify()).toEqual({ ok: true, events: 4 });
  });

  it("tamper: an unparseable line in the MIDDLE of the file (not the tail) is detected as torn_line, not silently skipped", () => {
    // Note: a torn line strictly at the TAIL of the newest file is instead
    // healed by createAuditLog()'s own open-time crash recovery (quarantine
    // + resume) before verify() ever gets a chance to see it — proven in
    // the "crash recovery" describe block below. verify()'s own torn_line
    // detection is reachable directly via a mid-file corruption like this.
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 5; i++) sink.append(baseEvent());
    sink.close();

    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const lines = readFileSync(filePath, "utf8").split("\n").filter(Boolean);
    lines[2] = "{not valid json at all §§§";
    writeFileSync(filePath, `${lines.join("\n")}\n`);

    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const result = sink.verify();

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.breakAt.file).toBe("202606.jsonl");
      expect(result.breakAt.line).toBe(3);
      expect(result.breakAt.kind).toBe("torn_line");
      expect(result.breakAt.seq).toBe(3); // expected seq at that position
    }
  });
});

// ---------------------------------------------------------------------------
// Rotation across a simulated month boundary + cross-file continuity.
// ---------------------------------------------------------------------------

describe("month rotation", () => {
  it("rotates to a new <yyyymm>.jsonl file when the clock crosses a month boundary", () => {
    const clock = fakeClock(Date.UTC(2026, 5, 30, 23, 0, 0)); // June 30
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    sink.append(baseEvent());
    expect(existsSync(path.join(auditDirPath(), "202606.jsonl"))).toBe(true);

    clock.set(Date.UTC(2026, 6, 1, 0, 30, 0)); // July 1
    sink.append(baseEvent());
    expect(existsSync(path.join(auditDirPath(), "202607.jsonl"))).toBe(true);

    expect(
      readdirSync(auditDirPath()).filter((n) => n.endsWith(".jsonl")),
    ).toEqual(expect.arrayContaining(["202606.jsonl", "202607.jsonl"]));
  });

  it("the chain spans files: last hash of file N = prevHash of file N+1's first event", () => {
    const clock = fakeClock(Date.UTC(2026, 5, 30, 23, 0, 0));
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const juneEvents = [sink.append(baseEvent()), sink.append(baseEvent())];
    clock.set(Date.UTC(2026, 6, 1, 0, 0, 1));
    const julyFirst = sink.append(baseEvent());

    expect(julyFirst.seq).toBe(3);
    expect(julyFirst.prevHash).toBe(must(juneEvents[1]).hash);
  });

  it("verify() streams both files in order and validates cross-file continuity", () => {
    const clock = fakeClock(Date.UTC(2026, 5, 30, 23, 0, 0));
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 5; i++) sink.append(baseEvent());
    clock.set(Date.UTC(2026, 6, 1, 0, 0, 1));
    for (let i = 0; i < 5; i++) sink.append(baseEvent());

    expect(sink.verify()).toEqual({ ok: true, events: 10 });
  });

  it("re-opening the log after a process restart (fresh createAuditLog call) resumes seq/hash correctly from the newest file's tail", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    sink.append(baseEvent());
    const second = sink.append(baseEvent());
    sink.close();

    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const third = sink.append(baseEvent());

    expect(third.seq).toBe(3);
    expect(third.prevHash).toBe(second.hash);
  });

  it("re-opening resumes correctly even after a month boundary with no writes yet in the new month", () => {
    const clock = fakeClock(Date.UTC(2026, 5, 15, 12, 0, 0));
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const last = sink.append(baseEvent());
    sink.close();

    // Process "restarts" a month later, having never written anything in
    // July yet — bootstrap must fall back to June's tail for prevHash/seq.
    clock.set(Date.UTC(2026, 6, 10, 0, 0, 0));
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const next = sink.append(baseEvent());

    expect(next.seq).toBe(2);
    expect(next.prevHash).toBe(last.hash);
    expect(existsSync(path.join(auditDirPath(), "202607.jsonl"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Crash recovery — torn final line, quarantine, resume, stderr notice.
// ---------------------------------------------------------------------------

describe("crash recovery (torn final line)", () => {
  it("quarantines a torn tail line to <file>.torn, resumes from the last intact line, and logs to stderr", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const first = sink.append(baseEvent());
    const second = sink.append(baseEvent());
    sink.close();

    // Simulate a crash mid-append: append a partial (unterminated,
    // unparseable-as-a-whole) fragment directly, bypassing the sink.
    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const beforeSize = statSync(filePath).size;
    appendFileSync(filePath, '{"seq":3,"ts":"2026-06-15T12:00');
    expect(statSync(filePath).size).toBeGreaterThan(beforeSize);

    const stderrWrites: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    // biome-ignore lint/suspicious/noExplicitAny: matching Writable#write's overload set well enough for a spy
    (process.stderr as any).write = (chunk: any, ...rest: any[]) => {
      stderrWrites.push(String(chunk));
      return originalWrite(chunk, ...rest);
    };

    let recovered: AuditSink;
    try {
      recovered = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    } finally {
      process.stderr.write = originalWrite;
    }
    sink = recovered;

    // Quarantine file exists and contains the torn fragment.
    const tornPath = `${filePath}.torn`;
    expect(existsSync(tornPath)).toBe(true);
    expect(readFileSync(tornPath, "utf8")).toContain('"seq":3');

    // stderr got a notice naming the recovery.
    expect(stderrWrites.some((w) => /torn|quarantin/i.test(w))).toBe(true);

    // Resumes from the last intact line (seq 2) — the next real append is
    // seq 3, chained off the second event's hash, not the torn fragment.
    const third = recovered.append(baseEvent());
    expect(third.seq).toBe(3);
    expect(third.prevHash).toBe(second.hash);

    // The main .jsonl file no longer contains the torn fragment's bytes.
    const mainContent = readFileSync(filePath, "utf8");
    expect(mainContent).not.toContain('"seq":3,"ts":"2026-06-15T12:00');

    // The recovered chain (2 original + 1 new) verifies clean.
    expect(recovered.verify()).toEqual({ ok: true, events: 3 });
    expect(first.seq).toBe(1);
  });

  it("recovers correctly even when the torn line is the ONLY line in the file (falls back to genesis)", () => {
    mkdirSync(auditDirPath(), { recursive: true, mode: 0o700 });
    const filePath = path.join(auditDirPath(), "202606.jsonl");
    writeFileSync(filePath, '{"seq":1,"ts":"2026-06-15T00:00:00.000Z"');

    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const first = sink.append(baseEvent());
    expect(first.seq).toBe(1);
    expect(first.prevHash).toBe(AUDIT_GENESIS_PREV_HASH);
    expect(existsSync(`${filePath}.torn`)).toBe(true);
  });

  it("torn tail cut mid-multi-byte UTF-8 char: truncates byte-exact at the last real newline (not off-by-N from decode/re-encode), preserves the exact raw torn bytes in .torn", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const first = sink.append(baseEvent());
    const second = sink.append(baseEvent());
    sink.close();

    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const beforeSize = statSync(filePath).size;

    // Simulate a crash mid-append whose final write cuts a multi-byte
    // UTF-8 character in half: a plain ASCII prefix followed by ONLY the
    // lead byte of a 3-byte sequence (e.g. "日" = E6 97 A5), no trailing
    // newline. A decode-then-re-encode byte count (TextDecoder's lenient
    // U+FFFD substitution is always 3 UTF-8 bytes on re-encode, regardless
    // of how many raw bytes were actually truncated) would mis-truncate
    // here; a raw-byte scan for the last 0x0A must not.
    const asciiPrefix = Buffer.from(
      '{"seq":3,"ts":"2026-06-15T12:00:00.000Z","note":"',
      "utf8",
    );
    const partialMultiByte = Buffer.from([0xe6]); // lead byte only — incomplete
    const tornRaw = Buffer.concat([asciiPrefix, partialMultiByte]);
    appendFileSync(filePath, tornRaw);
    expect(statSync(filePath).size).toBe(beforeSize + tornRaw.length);

    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    // Byte-exact: truncated to precisely where event 2's line ended — a
    // stale decode/re-encode-based computation would have chopped 2 extra
    // bytes off the END of event 2's own (valid, untorn) line here.
    expect(statSync(filePath).size).toBe(beforeSize);
    expect(readLines(filePath)).toEqual([first, second]);

    // The exact raw torn bytes are preserved byte-for-byte in .torn.
    const tornPath = `${filePath}.torn`;
    expect(existsSync(tornPath)).toBe(true);
    const tornFileContent = readFileSync(tornPath);
    expect(tornFileContent.includes(tornRaw)).toBe(true);

    // Chain resumes cleanly: the next real append chains off event 2.
    const third = sink.append(baseEvent());
    expect(third.seq).toBe(3);
    expect(third.prevHash).toBe(second.hash);
    expect(sink.verify()).toEqual({ ok: true, events: 3 });
  });
});

// ---------------------------------------------------------------------------
// Constructor lock release on failed initialization (post-acquireLock).
// ---------------------------------------------------------------------------

describe("constructor lock release on bootstrap/open failure", () => {
  it("releases audit/.lock if bootstrapChainState/openCurrentFile throws after acquireLock() already succeeded, so a later createAuditLog() in this same process can succeed once the failure is cleared", () => {
    const clock = fakeClock(JUNE_15_2026);
    mkdirSync(auditDirPath(), { recursive: true, mode: 0o700 });
    // A directory shaped like a valid month file forces
    // bootstrapChainState()'s recoverTailState() to throw (EISDIR opening a
    // directory with the "r+" flag) — deterministic on any OS/user, unlike
    // a chmod-based unreadable-file trick that a root/CI environment can
    // silently bypass (see this suite's own header and the fault-injection
    // suite's header for why chmod tricks are avoided here).
    mkdirSync(path.join(auditDirPath(), "202606.jsonl"));

    expect(() => {
      createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    }).toThrow();

    // The lock must NOT have leaked: acquireLock() succeeded, but
    // construction failed afterward, and that failure must release it —
    // otherwise it stays held by this (still-running) pid for the rest of
    // the process's lifetime, with no sink around to ever close() it.
    expect(existsSync(path.join(auditDirPath(), ".lock"))).toBe(false);

    // Clear the failure condition and prove a fresh createAuditLog() in
    // THIS SAME PROCESS now succeeds — it would instead throw "already
    // locked" (this process's own pid is always "alive") if the first
    // attempt's lock had leaked.
    rmSync(path.join(auditDirPath(), "202606.jsonl"), { recursive: true });
    expect(() => {
      sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    }).not.toThrow();
    const event = must(sink).append(baseEvent());
    expect(event.seq).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Writer lock — single-process ownership, stale-lock takeover.
// ---------------------------------------------------------------------------

describe("writer lock (audit/.lock)", () => {
  it("a second sink against the same home fails loudly instead of corrupting the chain", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    expect(() =>
      createAuditLog({ home: tempHome, nowEpochMs: clock.now }),
    ).toThrow(/lock/i);
  });

  it("creates audit/.lock containing this process's pid", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });

    const lockContent = readFileSync(
      path.join(auditDirPath(), ".lock"),
      "utf8",
    ).trim();
    expect(lockContent).toBe(String(process.pid));
  });

  it("releases the lock on close(), allowing a fresh sink afterwards", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    sink.close();

    expect(() => {
      const second = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
      second.close();
    }).not.toThrow();
    sink = undefined;
  });

  it("takes over a stale lock (held by a pid that is no longer running)", () => {
    mkdirSync(auditDirPath(), { recursive: true, mode: 0o700 });
    // A guaranteed-dead pid: spawn a trivial child and wait for it to exit.
    const child = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
    const deadPid = child.pid;
    expect(typeof deadPid).toBe("number");

    const lockFd = openSync(path.join(auditDirPath(), ".lock"), "wx");
    writeSync(lockFd, String(deadPid));
    closeSync(lockFd);

    const clock = fakeClock(JUNE_15_2026);
    expect(() => {
      sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    }).not.toThrow();

    // Takeover rewrote the lock with OUR pid.
    const lockContent = readFileSync(
      path.join(auditDirPath(), ".lock"),
      "utf8",
    ).trim();
    expect(lockContent).toBe(String(process.pid));

    // And the sink works normally afterwards.
    const event = must(sink).append(baseEvent());
    expect(event.seq).toBe(1);
  });

  it("does NOT take over a lock held by a live pid (this process)", () => {
    mkdirSync(auditDirPath(), { recursive: true, mode: 0o700 });
    const lockFd = openSync(path.join(auditDirPath(), ".lock"), "wx");
    writeSync(lockFd, String(process.pid)); // definitely alive: it's us
    closeSync(lockFd);

    const clock = fakeClock(JUNE_15_2026);
    expect(() =>
      createAuditLog({ home: tempHome, nowEpochMs: clock.now }),
    ).toThrow(/lock/i);
  });
});

// ---------------------------------------------------------------------------
// flush() / close().
// ---------------------------------------------------------------------------

describe("flush() / close()", () => {
  it("flush() is safe to call with nothing pending", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    expect(() => must(sink).flush()).not.toThrow();
  });

  it("close() is idempotent", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    sink.append(baseEvent());
    sink.close();
    expect(() => must(sink).close()).not.toThrow();
  });

  it("append() after close() throws (fail-closed, not a silent no-op)", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    sink.close();

    expect(() => must(sink).append(baseEvent())).toThrow();
  });
});

// ---------------------------------------------------------------------------
// onAppend() — the P0-E8-T1 subscriber hook (R127): the seam an OPTIONAL
// @knotrust/otel exporter attaches to WHEN THE USER CONFIGURES
// telemetryExport. Never subscribing (the default) must cost nothing beyond
// this sink's own machinery; a subscribed listener must never be able to
// break — or even observe a difference in — the append() contract itself.
// ---------------------------------------------------------------------------

describe("onAppend() — R127 subscriber hook", () => {
  it("with zero listeners registered, append() behaves exactly as before (no cost, no behavior change)", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const result = must(sink).append(baseEvent());
    expect(result.seq).toBe(1);
    expect(result.outcome).toBe("allow");
  });

  it("calls a registered listener synchronously with the exact appended event, once per append", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const seen: AuditEvent[] = [];
    must(sink).onAppend((event) => seen.push(event));

    const returned = must(sink).append(baseEvent());
    // Synchronous: the listener has already fired by the time append() returns.
    expect(seen).toEqual([returned]);

    const returned2 = must(sink).append(
      baseEvent({ tool: "github.close_issue" }),
    );
    expect(seen).toEqual([returned, returned2]);
  });

  it("notifies every registered listener, in registration order", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const calls: string[] = [];
    must(sink).onAppend(() => calls.push("first"));
    must(sink).onAppend(() => calls.push("second"));

    must(sink).append(baseEvent());
    expect(calls).toEqual(["first", "second"]);
  });

  it("unsubscribe (the returned function) stops further notifications", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const seen: AuditEvent[] = [];
    const unsubscribe = must(sink).onAppend((event) => seen.push(event));

    must(sink).append(baseEvent());
    expect(seen).toHaveLength(1);

    unsubscribe();
    must(sink).append(baseEvent());
    expect(seen).toHaveLength(1);
  });

  it("a throwing listener is caught and logged, never breaks append() or marks the sink broken", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    must(sink).onAppend(() => {
      throw new Error("boom — a misbehaving telemetry consumer");
    });
    const seen: AuditEvent[] = [];
    must(sink).onAppend((event) => seen.push(event));

    let result: AuditEvent | undefined;
    expect(() => {
      result = must(sink).append(baseEvent());
    }).not.toThrow();
    expect(result?.outcome).toBe("allow");
    // The throwing listener didn't stop the SECOND listener from firing too.
    expect(seen).toHaveLength(1);

    // The sink is still healthy — a further append still succeeds normally.
    expect(() => must(sink).append(baseEvent())).not.toThrow();
  });

  // The internally-generated `audit_recovered` marker event also routes
  // through the same `writeEventRaw` choke point this hook is wired to, so
  // it notifies listeners too — proven with the real `node:fs` fault
  // injection needed to force that path, in the sibling
  // `audit-log.fault-injection.test.ts` (see its "onAppend()" describe
  // block), not here (this file never mocks `node:fs`).
});

// ---------------------------------------------------------------------------
// streamAuditEvents() / verifyAuditChain() — the LOCK-FREE read exports
// P0-E4-T4's `knotrust audit list|tail|query|verify` CLI is built on.
// ---------------------------------------------------------------------------

function collectEvents(home: string): AuditEvent[] {
  const events: AuditEvent[] = [];
  for (const entry of streamAuditEvents(home)) {
    if (entry.event !== undefined) events.push(entry.event);
  }
  return events;
}

describe("streamAuditEvents()", () => {
  it("yields nothing for a home with no audit dir at all (fresh install)", () => {
    expect([...streamAuditEvents(tempHome)]).toEqual([]);
  });

  it("streams every appended event, in seq order, across a single month file", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const appended = [
      sink.append(baseEvent()),
      sink.append(baseEvent()),
      sink.append(baseEvent()),
    ];
    sink.close();
    sink = undefined;

    expect(collectEvents(tempHome)).toEqual(appended);
  });

  it("streams across a month rotation boundary in file-then-seq order", () => {
    const clock = fakeClock(Date.UTC(2026, 5, 30, 23, 0, 0));
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    const june = [sink.append(baseEvent()), sink.append(baseEvent())];
    clock.set(Date.UTC(2026, 6, 1, 0, 0, 1));
    const july = [sink.append(baseEvent()), sink.append(baseEvent())];
    sink.close();
    sink = undefined;

    expect(collectEvents(tempHome)).toEqual([...june, ...july]);
  });

  it("reports each raw line's file + 1-indexed line number alongside the parsed event", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    sink.append(baseEvent());
    sink.append(baseEvent());
    sink.close();
    sink = undefined;

    const entries = [...streamAuditEvents(tempHome)];
    expect(
      entries.map((e) => ({ file: e.file, lineNumber: e.lineNumber })),
    ).toEqual([
      { file: "202606.jsonl", lineNumber: 1 },
      { file: "202606.jsonl", lineNumber: 2 },
    ]);
  });

  it("yields event: undefined (never throws) for a malformed mid-file line", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 3; i++) sink.append(baseEvent());
    sink.close();
    sink = undefined;

    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const lines = readFileSync(filePath, "utf8").split("\n").filter(Boolean);
    lines[1] = "{not valid json §§§";
    writeFileSync(filePath, `${lines.join("\n")}\n`);

    const entries = [...streamAuditEvents(tempHome)];
    expect(entries).toHaveLength(3);
    expect(entries[0]?.event).not.toBeUndefined();
    expect(entries[1]?.event).toBeUndefined();
    expect(entries[2]?.event).not.toBeUndefined();
  });

  it("is LOCK-FREE: reads correctly even while a live sink from the SAME home holds audit/.lock", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    sink.append(baseEvent());
    sink.append(baseEvent());
    // `sink` is still open — audit/.lock is held by THIS process right now.
    // A concurrent forensic read must not throw "already locked" the way a
    // second createAuditLog() against this home would.
    expect(existsSync(path.join(auditDirPath(), ".lock"))).toBe(true);

    expect(() => collectEvents(tempHome)).not.toThrow();
    expect(collectEvents(tempHome)).toHaveLength(2);
  });

  it("uses KNOTRUST_HOME when home is omitted, mirroring createAuditLog's default", () => {
    const ORIGINAL = process.env.KNOTRUST_HOME;
    process.env.KNOTRUST_HOME = tempHome;
    try {
      const clock = fakeClock(JUNE_15_2026);
      sink = createAuditLog({ nowEpochMs: clock.now });
      sink.append(baseEvent());
      sink.close();
      sink = undefined;

      expect([...streamAuditEvents()]).toHaveLength(1);
    } finally {
      if (ORIGINAL === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = ORIGINAL;
    }
  });
});

describe("verifyAuditChain()", () => {
  it("reports { ok: true, events: 0 } for a home with no audit dir at all", () => {
    expect(verifyAuditChain(tempHome)).toEqual({ ok: true, events: 0 });
  });

  it("matches sink.verify()'s result exactly for an untampered chain", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 12; i++) sink.append(baseEvent());

    expect(verifyAuditChain(tempHome)).toEqual(sink.verify());
    expect(verifyAuditChain(tempHome)).toEqual({ ok: true, events: 12 });
  });

  it("detects a tampered chain (hash_mismatch) identically to sink.verify()", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 5; i++) sink.append(baseEvent());
    sink.close();
    sink = undefined;

    const filePath = path.join(auditDirPath(), "202606.jsonl");
    const lines = readFileSync(filePath, "utf8").split("\n");
    const event = JSON.parse(must(lines[2])) as Record<string, unknown>;
    event.tool = "TAMPERED.tool";
    lines[2] = canonicalizeJcs(event);
    writeFileSync(filePath, lines.join("\n"));

    expect(verifyAuditChain(tempHome)).toEqual({
      ok: false,
      breakAt: { file: "202606.jsonl", line: 3, seq: 3, kind: "hash_mismatch" },
    });
  });

  it("is LOCK-FREE: verifies correctly even while a live sink from the SAME home holds audit/.lock", () => {
    const clock = fakeClock(JUNE_15_2026);
    sink = createAuditLog({ home: tempHome, nowEpochMs: clock.now });
    for (let i = 0; i < 4; i++) sink.append(baseEvent());
    expect(existsSync(path.join(auditDirPath(), ".lock"))).toBe(true);

    expect(() => verifyAuditChain(tempHome)).not.toThrow();
    expect(verifyAuditChain(tempHome)).toEqual({ ok: true, events: 4 });
  });

  it("uses KNOTRUST_HOME when home is omitted, mirroring createAuditLog's default", () => {
    const ORIGINAL = process.env.KNOTRUST_HOME;
    process.env.KNOTRUST_HOME = tempHome;
    try {
      const clock = fakeClock(JUNE_15_2026);
      sink = createAuditLog({ nowEpochMs: clock.now });
      sink.append(baseEvent());
      sink.close();
      sink = undefined;

      expect(verifyAuditChain()).toEqual({ ok: true, events: 1 });
    } finally {
      if (ORIGINAL === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = ORIGINAL;
    }
  });
});
