/**
 * @knotrust/store — audit-log.ts fault-injection tests (P0-E4-T3; R38).
 *
 * Mocks `node:fs` (same `vi.mock` + override-seam technique as
 * `grant-store.test.ts` — see that file's header for why: `node:fs`'s
 * exported bindings are non-configurable, so `vi.spyOn` can't touch them
 * directly) to deterministically inject write/fsync failures without
 * relying on `chmod` (which real root/CI environments can bypass) or real
 * timing races.
 *
 * Covers the ratified fail-closed contract (R38, D6): an audit-append
 * failure throws `AuditUnavailableError`, is written to stderr, and the
 * NEXT append retries from scratch — emitting `audit_recovered` first if
 * that retry succeeds. Also proves the fsync-batching write strategy
 * (immediate for `fsync: "immediate"`, batched ≤100ms otherwise) and the
 * exact P0-E5-T5 composition hook: a decide-wrapper that denies with
 * `AUDIT_UNAVAILABLE` on any `append()` throw.
 */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AUDIT_UNAVAILABLE,
  type AuditEvent,
  AuditEventType,
  type AuditSink,
  AuditUnavailableError,
  computeArgsHash,
  createAuditLog,
} from "./audit-log.js";

// ---------------------------------------------------------------------------
// node:fs interception seam — mirrors grant-store.test.ts's fsOverrides.
// ---------------------------------------------------------------------------

const fsOverrides = vi.hoisted(() => ({
  writeSync: null as ((...args: unknown[]) => unknown) | null,
  fsyncSync: null as ((...args: unknown[]) => unknown) | null,
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    writeSync: (...args: unknown[]) =>
      fsOverrides.writeSync
        ? fsOverrides.writeSync(...args)
        : // biome-ignore lint/suspicious/noExplicitAny: passthrough to the real overload set
          (actual.writeSync as any)(...args),
    fsyncSync: (...args: unknown[]) =>
      fsOverrides.fsyncSync
        ? fsOverrides.fsyncSync(...args)
        : // biome-ignore lint/suspicious/noExplicitAny: passthrough to the real overload set
          (actual.fsyncSync as any)(...args),
  };
});

function eaccesError(
  message = "EACCES: permission denied",
): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = "EACCES";
  return err;
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

let tempHome: string;
let sink: AuditSink | undefined;

beforeEach(() => {
  tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-audit-fault-test-"));
  sink = undefined;
  fsOverrides.writeSync = null;
  fsOverrides.fsyncSync = null;
});

afterEach(() => {
  fsOverrides.writeSync = null;
  fsOverrides.fsyncSync = null;
  try {
    sink?.close();
  } catch {
    // best-effort — some tests intentionally leave the sink broken
  }
  rmSync(tempHome, { recursive: true, force: true });
});

/** `noUncheckedIndexedAccess`/possibly-undefined narrowing without `!` (biome's `noNonNullAssertion`). */
function must<T>(value: T | undefined, label = "value"): T {
  if (value === undefined) {
    throw new Error(`must(): ${label} was unexpectedly undefined`);
  }
  return value;
}

const FIXED_MS = Date.UTC(2026, 5, 15, 12, 0, 0);

function baseEvent(over: Partial<Parameters<AuditSink["append"]>[0]> = {}) {
  return {
    type: AuditEventType.DECISION,
    surface: "mcp-stdio",
    subject: "user:local",
    agent: "claude-desktop",
    tool: "github.create_issue",
    argsHash: computeArgsHash({ repo: "knotrust" }),
    outcome: "allow",
    ...over,
  };
}

// ---------------------------------------------------------------------------
// append() failure ⇒ AuditUnavailableError, stderr, fail-closed.
// ---------------------------------------------------------------------------

describe("append() failure handling", () => {
  it("throws AuditUnavailableError (carrying the original error as .cause) when the underlying write fails", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    sink.append(baseEvent()); // first append succeeds normally

    const originalErr = eaccesError();
    fsOverrides.writeSync = () => {
      throw originalErr;
    };

    let caught: unknown;
    try {
      sink.append(baseEvent());
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(AuditUnavailableError);
    expect((caught as AuditUnavailableError).cause).toBe(originalErr);
  });

  it("writes the failure to stderr before throwing", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    fsOverrides.writeSync = () => {
      throw eaccesError();
    };

    const stderrWrites: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    // biome-ignore lint/suspicious/noExplicitAny: matching Writable#write's overload set well enough for a spy
    (process.stderr as any).write = (chunk: any, ...rest: any[]) => {
      stderrWrites.push(String(chunk));
      return originalWrite(chunk, ...rest);
    };

    try {
      expect(() => must(sink).append(baseEvent())).toThrow(
        AuditUnavailableError,
      );
    } finally {
      process.stderr.write = originalWrite;
    }

    expect(stderrWrites.some((w) => /EACCES|audit/i.test(w))).toBe(true);
  });

  it("recovers on the next successful append, emitting audit_recovered first (carrying lastGoodSeq) and preserving chain continuity", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    const first = sink.append(baseEvent());
    expect(first.seq).toBe(1);

    fsOverrides.writeSync = () => {
      throw eaccesError();
    };
    expect(() => must(sink).append(baseEvent())).toThrow(AuditUnavailableError);

    fsOverrides.writeSync = null; // "permissions restored"
    const recoveredResultEvent = sink.append(
      baseEvent({ tool: "post-recovery.call" }),
    );

    // seq 2 is the internally-emitted audit_recovered event; seq 3 is the
    // caller's originally-intended event, both chained correctly off seq 1.
    expect(recoveredResultEvent.seq).toBe(3);
    expect(recoveredResultEvent.prevHash).not.toBe(first.hash); // seq 2 (audit_recovered) sits between them
    expect(recoveredResultEvent.tool).toBe("post-recovery.call");

    const result = sink.verify();
    expect(result).toEqual({ ok: true, events: 3 });

    // Confirm an audit_recovered event actually exists in the chain (seq 2)
    // and carries lastGoodSeq: 1 — the seq of the last event confirmed
    // durable (seq 1) before the failed append that never made it to disk.
    const rawLines = readFileSync(
      path.join(tempHome, "audit", "202606.jsonl"),
      "utf8",
    )
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l) as AuditEvent);
    const recoveredMarker = rawLines.find(
      (e) => e.type === AuditEventType.AUDIT_RECOVERED,
    );
    expect(recoveredMarker?.seq).toBe(2);
    expect(recoveredMarker?.lastGoodSeq).toBe(1);

    sink.close();
    sink = undefined;
  });

  it("stays broken and throws again if the recovery attempt itself also fails", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    fsOverrides.writeSync = () => {
      throw eaccesError();
    };

    expect(() => must(sink).append(baseEvent())).toThrow(AuditUnavailableError);
    expect(() => must(sink).append(baseEvent())).toThrow(AuditUnavailableError);
  });
});

// ---------------------------------------------------------------------------
// onAppend() (P0-E8-T1, R127) — the internally-generated `audit_recovered`
// marker also notifies listeners, because it routes through the SAME
// `writeEventRaw` choke point every other event does (see audit-log.ts's own
// module header). The happy-path onAppend() contract (ordering, unsubscribe,
// a throwing listener never breaking append()) is covered without any fs
// mocking in the sibling audit-log.test.ts; this one test needs the REAL
// fault-injection machinery this file provides to force the recovery path.
// ---------------------------------------------------------------------------

describe("onAppend() — notifies for the internal audit_recovered marker too", () => {
  it("a registered listener sees audit_recovered (seq 2) before the caller's post-recovery event (seq 3)", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    sink.append(baseEvent()); // seq 1

    fsOverrides.writeSync = () => {
      throw eaccesError();
    };
    expect(() => must(sink).append(baseEvent())).toThrow(AuditUnavailableError);
    fsOverrides.writeSync = null; // "permissions restored"

    const seenTypes: string[] = [];
    must(sink).onAppend((event) => seenTypes.push(event.type));

    must(sink).append(baseEvent({ tool: "post-recovery.call" }));

    expect(seenTypes).toEqual([
      AuditEventType.AUDIT_RECOVERED,
      AuditEventType.DECISION,
    ]);
  });
});

// ---------------------------------------------------------------------------
// fsync batching — immediate vs. deferred (≤100ms).
// ---------------------------------------------------------------------------

describe("fsync batching", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("fsync:'immediate' fsyncs synchronously before append() returns", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    let fsyncCalls = 0;
    fsOverrides.fsyncSync = () => {
      fsyncCalls++;
    };

    sink.append(baseEvent(), { fsync: "immediate" });

    expect(fsyncCalls).toBe(1);
  });

  it("a default (non-immediate) append does NOT fsync synchronously, but does within the batch window", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    let fsyncCalls = 0;
    fsOverrides.fsyncSync = () => {
      fsyncCalls++;
    };

    sink.append(baseEvent());
    expect(fsyncCalls).toBe(0);

    vi.advanceTimersByTime(100);
    expect(fsyncCalls).toBe(1);
  });

  it("batches multiple rapid appends into a single deferred fsync", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    let fsyncCalls = 0;
    fsOverrides.fsyncSync = () => {
      fsyncCalls++;
    };

    sink.append(baseEvent());
    sink.append(baseEvent());
    sink.append(baseEvent());
    expect(fsyncCalls).toBe(0);

    vi.advanceTimersByTime(100);
    expect(fsyncCalls).toBe(1);
  });

  it("clamps a caller-supplied fsyncBatchMs above 100 down to 100", () => {
    sink = createAuditLog({
      home: tempHome,
      nowEpochMs: () => FIXED_MS,
      fsyncBatchMs: 5_000,
    });
    let fsyncCalls = 0;
    fsOverrides.fsyncSync = () => {
      fsyncCalls++;
    };

    sink.append(baseEvent());
    vi.advanceTimersByTime(100);
    expect(fsyncCalls).toBe(1);
  });

  it("honors a smaller caller-supplied fsyncBatchMs", () => {
    sink = createAuditLog({
      home: tempHome,
      nowEpochMs: () => FIXED_MS,
      fsyncBatchMs: 20,
    });
    let fsyncCalls = 0;
    fsOverrides.fsyncSync = () => {
      fsyncCalls++;
    };

    sink.append(baseEvent());
    vi.advanceTimersByTime(20);
    expect(fsyncCalls).toBe(1);
  });

  it("flush() forces a pending fsync immediately, synchronously", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    let fsyncCalls = 0;
    fsOverrides.fsyncSync = () => {
      fsyncCalls++;
    };

    sink.append(baseEvent());
    expect(fsyncCalls).toBe(0);
    sink.flush();
    expect(fsyncCalls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// P0-E5-T5 hook: the exact deny-on-audit-failure composition proof.
// ---------------------------------------------------------------------------

describe("EACCES composition test (P0-E5-T5 hook)", () => {
  /**
   * This is the contract the real proxy's `tools/call` interception
   * (P0-E5-T3) composes with its fail-closed error handling (P0-E5-T5):
   * append the audit event BEFORE returning a decision, and if that
   * append throws, resolve `deny` with reason `AUDIT_UNAVAILABLE` instead
   * of letting an ungoverned-but-unaudited `allow` through. `audit-log.ts`
   * itself only needs to prove the seam (`AuditUnavailableError` +
   * `AUDIT_UNAVAILABLE`) is sufficient to build this on top of — the real
   * composition lives in the future proxy package, not here.
   */
  function fakeDecideWrapper(
    auditSink: AuditSink,
    event: Parameters<AuditSink["append"]>[0],
  ): { outcome: "allow" | "deny"; reason?: string } {
    try {
      auditSink.append(event);
      return { outcome: "allow" };
    } catch (err) {
      if (err instanceof AuditUnavailableError) {
        return { outcome: "deny", reason: AUDIT_UNAVAILABLE };
      }
      throw err;
    }
  }

  it("resolves deny/audit_unavailable when the audit append fails (simulated EACCES)", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });
    fsOverrides.writeSync = () => {
      throw eaccesError();
    };

    const decision = fakeDecideWrapper(sink, baseEvent());

    expect(decision).toEqual({ outcome: "deny", reason: "audit_unavailable" });
    expect(AUDIT_UNAVAILABLE).toBe("audit_unavailable");
  });

  it("resolves allow when the audit append succeeds", () => {
    sink = createAuditLog({ home: tempHome, nowEpochMs: () => FIXED_MS });

    const decision = fakeDecideWrapper(sink, baseEvent());

    expect(decision).toEqual({ outcome: "allow" });
  });
});
