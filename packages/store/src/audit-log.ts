/**
 * @knotrust/store — append-only JSONL audit log with hash chaining
 * (P0-E4-T3; rulings R36–R38; `docs/03-engineering/local-store-layout.md`
 * §"audit/"). This is the tamper-evident spine behind "everything the agent
 * *tried* is hash-chain audited" — every decision, including denials,
 * cache hits, fail-open firings, approval lifecycle transitions, and grant
 * lifecycle events, is meant to append one line here (brief §E5: attempts,
 * not just executions).
 *
 * ## Chain definition (R36) — write it to be stable
 *
 * Each line is one JSON object. `hash = lowercase-hex(SHA-256(utf8(
 * canonicalizeJcs(eventWithoutHashField))))`, where the hashed object
 * INCLUDES `prevHash` — this is an exact, cross-language-reproducible
 * restatement of the plan's `SHA-256(prevHash + canonical-line-bytes)`
 * intent, reusing `@knotrust/core`'s FROZEN `canonicalizeJcs` (the same
 * canonicalizer the SARC call-hash pins) rather than a bespoke concatenation
 * scheme. The bytes actually WRITTEN to disk for each line are also
 * `canonicalizeJcs(fullEventIncludingHash)` — the on-disk format and the
 * hash-input format are the same canonicalizer, applied to the parsed
 * object either way, so re-reading a line and re-hashing it is always
 * byte-reproducible regardless of how the line was originally constructed.
 *
 * Genesis `prevHash` is `AUDIT_GENESIS_PREV_HASH` (64 zeros). `seq` starts
 * at 1, is global-monotonic, and is CONTINUOUS ACROSS month files — the
 * chain spans files: the last hash of file N is the `prevHash` of file
 * N+1's first event. `ts` is RFC 3339 (ADR-0017) from the INJECTED clock
 * (`nowEpochMs`), never `Date.now()`; file naming (`<yyyymm>.jsonl`) derives
 * from that same instant.
 *
 * **Deviation from R38's literal `Omit<...>` sketch, documented:** R38's
 * API sketch types `append`'s input as `Omit<AuditEvent, "seq"|"prevHash"|
 * "hash">`, which would still require the caller to supply `ts`. R36 is
 * explicit and more specific — "`ts` ... from injected clock" — so this
 * module additionally omits `"ts"` from the caller-supplied shape and
 * synthesizes it internally from `opts.nowEpochMs()` at append time. A
 * caller cannot forge a timestamp disconnected from the sink's own clock.
 *
 * ## Crash recovery — the tail-only open (R36)
 *
 * On construction, this module locates its resume state by reading ONLY
 * THE TAIL of the newest `<yyyymm>.jsonl` file (falling back to older files
 * only if the newest is empty/wholly torn) — never a full-file scan; see
 * `recoverTailState`/`readTail` below for the bounded backward-read
 * strategy. If the tail's final line is torn (a crash mid-`write()`: the
 * file doesn't end in the newline every clean append terminates a line
 * with), that fragment is quarantined to `<file>.torn` (appended, never
 * overwritten, so repeated crash+recovery cycles keep full forensic
 * history), the live file is truncated back to its last intact line, a
 * notice is written to stderr, and the chain resumes from that intact line.
 * **Tamper-evident, not tamper-proof** (security-threat-model §5.1, T5;
 * architecture §9.3's "tamper-evident-lite" doctrine). This chain reliably
 * catches accidental, naive, or partial tampering — editing a line without
 * redoing everything downstream, deleting a line from the middle,
 * truncating mid-write — because the next `verify()` finds the first
 * hash/prevHash mismatch at the tamper point. It does NOT catch a
 * privileged local writer (the same OS user this process runs as) who
 * edits a line AND recomputes every downstream hash to match: the chain is
 * unkeyed SHA-256 with no signature and no external anchor over the head,
 * so a fully-recomputed chain is indistinguishable from one that was never
 * touched. External anchoring/witnessing — periodic head export via OTel,
 * or signing the head — is the real fix for that case; it is future work,
 * not shipped in P0. Separately, a hash-chain can only ever detect
 * insertion/edit/reorder WITHIN the chain, or a torn write at the very
 * tail — it cannot detect wholesale deletion of a clean trailing run of
 * the most-recent events (the same inherent limitation as any
 * hash-chained/git-like commit log); this is a documented property, not a
 * bug.
 *
 * ## Fail-closed on audit-write failure (R38, D6 — ratified)
 *
 * `append()` is synchronous: the line is `writeSync`'d immediately (so a
 * concurrent reader, e.g. `verify()`, sees it right away), and fsync is
 * BATCHED via a timer capped at `fsyncBatchMs` (default/clamp 100ms) unless
 * `opts.fsync === "immediate"` (callers pass this for `critical`-tier
 * events), which fsyncs synchronously before returning. ANY failure in this
 * path — the write itself, or a later batched fsync — writes a notice to
 * stderr, marks the sink `broken`, and (for `append()`) throws
 * `AuditUnavailableError` carrying the original error as `.cause`. The
 * caller composing this (the future proxy, P0-E5-T3/T5) is expected to
 * treat that throw as `deny` with reason `AUDIT_UNAVAILABLE` — an
 * ungoverned-but-unaudited allow is the worst outcome for a product whose
 * pitch is "fully audited." The NEXT `append()` call after a failure
 * retries directory/file bootstrap from scratch; if that succeeds, it
 * FIRST emits an internally-generated `audit_recovered` event (documenting
 * the gap, and carrying `lastGoodSeq` — the seq of the last event
 * confirmed durable before the failure, so a forensic reader can bound how
 * much may be missing; see `AuditEvent.lastGoodSeq`) before writing the
 * caller's originally-requested event — both sharing the now-freshly-
 * recovered chain state, never silently skipped.
 *
 * A deferred (batched, non-"immediate") fsync that fails happens
 * asynchronously, after the `append()` call that scheduled it has already
 * returned success — that failure cannot retroactively deny an
 * already-resolved call. It still marks the sink `broken` and logs to
 * stderr, surfacing on the NEXT `append()`/`flush()` via the same recovery
 * path. This is a documented, accepted limitation of batching durability
 * confirmation.
 *
 * ## Writer lock — single-process ownership (R38)
 *
 * P0 does not support multiple processes appending to the same log
 * concurrently (single proxy process owns it). `<home>/audit/.lock` is an
 * exclusive (`"wx"`) create containing this process's pid; a second
 * `createAuditLog()` against the same home throws loudly instead of
 * risking a corrupted chain from two interleaved writers. If the pid the
 * lock names is no longer running (checked via `process.kill(pid, 0)`), the
 * lock is treated as stale and taken over. This takeover is best-effort,
 * not atomic across two processes racing a takeover simultaneously — an
 * accepted gap given P0 explicitly doesn't support concurrent writers; it
 * only needs to handle the common "old process died, a new one starts
 * later" case.
 *
 * ## Argument hashing & raw-args hygiene (R37)
 *
 * `computeArgsHash` implements `"sha256:" + hex(SHA-256(utf8(
 * canonicalizeJcs(arguments ?? null))))`, NEVER throwing — a
 * non-canonicalizable input (a function, a cycle, a bigint, ...) yields the
 * literal string `"unavailable"` instead. Callers compute this themselves
 * (via this exported helper) and supply it as `argsHash` on the event they
 * hand to `append()`. Raw arguments are a DIFFERENT, optional field
 * (`rawArgs`, beyond the plan's frozen field list) a caller may also
 * attach — but this sink only ever persists it when constructed with
 * `captureRawArgs: true`; the default (`false`) STRIPS a caller-supplied
 * `rawArgs` before it ever reaches disk, regardless of caller behavior —
 * defense in depth for the "raw args never appear in the log by default"
 * acceptance bar, not merely a documented caller convention.
 *
 * ## Event type vocabulary (R37)
 *
 * `AuditEvent.type` is a plain `string` — an OPEN vocabulary later tasks
 * extend — but `AuditEventType` exports the P0 set as named constants so
 * call sites get typo-safety without a closed union type.
 */

import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { canonicalizeJcs } from "@knotrust/core";

// ---------------------------------------------------------------------------
// Public event shape (R37)
// ---------------------------------------------------------------------------

/**
 * One audited line. Field list is the plan's exact schema
 * (`{seq, ts, prevHash, hash, type, surface, subject, agent, tool,
 * argsHash, outcome, reason, grantRefs, approvalId?, latencyMs}`), with
 * `outcome`/`reason`/`grantRefs`/`latencyMs` all optional per R37
 * ("optional for non-decision types" — generalized here to "optional
 * unless the caller has one to report"), plus `cacheHit` (R37: cache hits
 * are `type: "decision"` with `cacheHit: true`) and `rawArgs` (only present
 * when the sink is constructed with `captureRawArgs: true` — see module
 * header). Optional fields are OMITTED entirely when absent, never present
 * with value `undefined` (matches this repo's `exactOptionalPropertyTypes`
 * discipline and keeps the canonicalizer's strict-rejection contract
 * happy — see `@knotrust/core`'s `canonicalizeJcs`).
 */
export interface AuditEvent {
  seq: number;
  /** RFC 3339 (profiled subset of ISO 8601, ADR-0017), from the injected clock. */
  ts: string;
  /** 64 lowercase hex chars. Genesis value: `AUDIT_GENESIS_PREV_HASH`. */
  prevHash: string;
  /** 64 lowercase hex chars — `sha256(canonicalizeJcs(this event minus "hash"))`, see module header. */
  hash: string;
  /** Open vocabulary (R37) — see `AuditEventType` for the P0 set. */
  type: string;
  surface: string;
  subject: string;
  agent: string;
  tool: string;
  /** `"sha256:" + hex` or the literal `"unavailable"` — see `computeArgsHash`. */
  argsHash: string;
  outcome?: string;
  reason?: string;
  grantRefs?: string[];
  approvalId?: string;
  latencyMs?: number;
  /** `type: "decision"` events only (R37: cache hits are audited distinctly). */
  cacheHit?: boolean;
  /**
   * The resolved `Tier` (`"routine"|"sensitive"|"critical"`) behind this
   * event — additive (R126, a P0-E4-T4 follow-up, NOT part of R37's frozen
   * field list). OPTIONAL and OMITTED when the caller doesn't have one, so
   * every event written before this fix, and any event type this ruling
   * doesn't touch, still verifies unchanged: `hash` is computed per-event
   * over that event's OWN canonical form (see module header), so adding an
   * optional key to NEW events cannot perturb any OLD event's hash, and
   * `isWellFormedEvent` below does not require this field. Emitted on every
   * `type: "decision"` event (`@knotrust/grants`' `decider.ts`) and on
   * `fail_open_fired` (`@knotrust/proxy-stdio`'s `enforce.ts`) — see those
   * modules for exactly where. Kept as a plain `string` here (not this
   * repo's `Tier` union from `@knotrust/core`) so this package doesn't take
   * on a `@knotrust/core` type dependency purely for a log-schema
   * annotation; every real caller passes an actual `Tier` value, which is
   * always a valid `string`.
   */
  tier?: string;
  /** Only ever present when the sink was constructed with `captureRawArgs: true`. */
  rawArgs?: unknown;
  /**
   * Only ever present on internally-generated `type: "audit_recovered"`
   * events (see module header, "Fail-closed on audit-write failure") — the
   * `seq` of the last event this sink can confirm was durably appended
   * before the failure that this event is recovering from (`0` if none).
   * Bounds the forensic gap for a reader: **at least one event with
   * `seq > lastGoodSeq` may be missing** — the caller's own event that
   * triggered the original failure, and possibly others, were never
   * written and have no seq at all, so this is a lower bound, not an exact
   * count of what's missing.
   */
  lastGoodSeq?: number;
}

/** The P0 event-type vocabulary (R37) — open, not a closed union; see module header. */
export const AuditEventType = {
  DECISION: "decision",
  GRANT_CREATED: "grant_created",
  GRANT_REVOKED: "grant_revoked",
  GRANT_CONSUMED: "grant_consumed",
  APPROVAL_REQUESTED: "approval_requested",
  APPROVAL_PENDING: "approval_pending",
  APPROVAL_APPROVED: "approval_approved",
  APPROVAL_DENIED: "approval_denied",
  APPROVAL_EXPIRED: "approval_expired",
  APPROVAL_CANCELLED: "approval_cancelled",
  /**
   * A rejected request against the localhost approval page (P0-E6-T3, R98):
   * bad/missing `Host` (DNS-rebinding attempt), bad/missing `Origin`,
   * bad/missing CSRF token, a replayed (already-consumed) or forged URL
   * token, or the wrong HTTP method against a mutating endpoint. `reason`
   * carries which (`bad_host`/`bad_origin`/`bad_csrf`/`bad_token`/
   * `replayed_token`/`wrong_method`) — NEVER the token value itself.
   */
  APPROVAL_CHANNEL_VIOLATION: "approval_channel_violation",
  FAIL_OPEN_FIRED: "fail_open_fired",
  TOOL_DEFINITION_CHANGED: "tool_definition_changed",
  DENIAL_PROBING_SUSPECTED: "denial_probing_suspected",
  PROBE_FLAGGED: "probe_flagged",
  /** Emitted internally by this sink after recovering from an append failure — carries `lastGoodSeq` (see `AuditEvent.lastGoodSeq`); see module header. */
  AUDIT_RECOVERED: "audit_recovered",
} as const;

/** Genesis `prevHash` (R36): 64 zeros. */
export const AUDIT_GENESIS_PREV_HASH = "0".repeat(64);

/** Canonical `reason` a fail-closed wrapper resolves with when `append()` throws `AuditUnavailableError` (R38, D6). */
export const AUDIT_UNAVAILABLE = "audit_unavailable";

/**
 * Thrown by `append()`/`flush()` on any underlying write/fsync failure.
 * Carries the original error as `.cause` (standard `Error` cause chaining).
 */
export class AuditUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "AuditUnavailableError";
  }
}

export type ChainVerifyResult =
  | { ok: true; events: number }
  | {
      ok: false;
      breakAt: {
        file: string;
        /** 1-indexed line number within `file`. */
        line: number;
        seq: number;
        kind: "hash_mismatch" | "seq_gap" | "prevhash_mismatch" | "torn_line";
      };
    };

export interface AuditSink {
  /**
   * Synchronous: data is written immediately (visible to a concurrent
   * `verify()` right away); fsync is batched (see module header) unless
   * `opts.fsync === "immediate"`. Throws `AuditUnavailableError` on ANY
   * write failure — see module header for the fail-closed contract and the
   * `audit_recovered` recovery behavior on the next successful call.
   */
  append(
    event: Omit<AuditEvent, "seq" | "prevHash" | "hash" | "ts">,
    opts?: { fsync?: "immediate" },
  ): AuditEvent;
  /** Forces any pending batched fsync synchronously. Throws `AuditUnavailableError` if that fsync fails. */
  flush(): void;
  close(): void;
  /** Streams every file in seq order; see `ChainVerifyResult`. */
  verify(): ChainVerifyResult;
  /**
   * Subscribes to every event this sink successfully appends — invoked
   * SYNCHRONOUSLY, in registration order, immediately after the write (P0-E8-T1,
   * R127: "a synchronous per-append callback the sink invokes"). This is the
   * seam an OPTIONAL subscriber (`@knotrust/otel`'s exporter is the first and,
   * as of P0, only one) attaches to WHEN THE USER CONFIGURES it — this sink
   * itself has NO notion of OTel, telemetry, or export; it just runs a plain
   * listener list. With zero listeners ever registered (the default for every
   * user who never sets `telemetryExport`), this hook costs one empty-`Set`
   * iteration per append and constructs nothing extra — see this package's
   * `@knotrust/otel` consumer for the "off by default ⇒ zero telemetry
   * construction" half of that contract, which lives THERE, not here.
   *
   * Fires for EVERY successful append this sink ever makes, including the
   * internally-generated `audit_recovered` marker (both route through the
   * same `writeEventRaw` choke point — see this module's "Fail-closed on
   * audit-write failure" header section) — a subscriber sees the recovery
   * marker exactly like any other event, in seq order, with no special
   * casing needed on either side.
   *
   * A listener that throws is caught and logged to stderr, never rethrown —
   * a broken or misbehaving telemetry consumer must never be able to fail an
   * `append()` call or mark this sink `broken`; the audit trail's own
   * fail-closed contract (R38, R40) is strictly more important than any
   * subscriber's delivery. Returns an unsubscribe function.
   */
  onAppend(listener: (event: AuditEvent) => void): () => void;
}

export interface CreateAuditLogOptions {
  /** Defaults to `resolveKnotrustHome()` (the `KNOTRUST_HOME` override, else `~/.knotrust`). */
  home?: string;
  /** Epoch milliseconds. Never `Date.now()` internally — always this injected function. */
  nowEpochMs(): number;
  /** Default `false` — raw arguments never appear in the log unless explicitly opted in (secrets hygiene, R37). */
  captureRawArgs?: boolean;
  /** Deferred-fsync batching window in ms. Default 100, clamped to a ceiling of 100 (a smaller value is honored as-is). */
  fsyncBatchMs?: number;
}

// ---------------------------------------------------------------------------
// $KNOTRUST_HOME resolution — deliberately duplicated (not imported) from
// grant-store.ts's function of the same name/behavior, matching THIS
// repo's established convention for this specific tiny helper (see
// grant-store.ts's own header on its duplication from
// packages/grants/src/keys.ts). Read fresh on every call — never cached —
// so tests can point a whole sink at a fresh temp dir per case.
// ---------------------------------------------------------------------------

function resolveKnotrustHome(): string {
  const override = process.env.KNOTRUST_HOME;
  if (override !== undefined && override.trim() !== "") {
    return override;
  }
  return path.join(homedir(), ".knotrust");
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

const AUDIT_DIR_MODE = 0o700;
const DEFAULT_FSYNC_BATCH_MS = 100;
const LOCK_FILENAME = ".lock";
const AUDIT_FILE_RE = /^\d{6}\.jsonl$/;

function isErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && "code" in err;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function warnStderr(message: string): void {
  process.stderr.write(message.endsWith("\n") ? message : `${message}\n`);
}

function auditDirOf(home: string): string {
  return path.join(home, "audit");
}

function ensureAuditDir(auditDir: string): void {
  mkdirSync(auditDir, { recursive: true, mode: AUDIT_DIR_MODE });
  // mkdirSync's `mode` only applies at creation time — re-enforce it even
  // if `auditDir` pre-existed with looser permissions from something else
  // (mirrors grant-store.ts's ensureSecureDir / keys.ts's
  // ensureKnotrustHomeDir).
  chmodSync(auditDir, AUDIT_DIR_MODE);
}

function yyyymmFromIso(iso: string): string {
  return `${iso.slice(0, 4)}${iso.slice(5, 7)}`;
}

// ---------------------------------------------------------------------------
// computeArgsHash() — R37 exact formula, never throws.
// ---------------------------------------------------------------------------

export function computeArgsHash(args: unknown): string {
  const normalized = args ?? null;
  let canonical: string;
  try {
    canonical = canonicalizeJcs(normalized);
  } catch {
    return "unavailable";
  }
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `sha256:${digest}`;
}

// ---------------------------------------------------------------------------
// Chain hash (R36).
// ---------------------------------------------------------------------------

function computeEventHash(eventWithoutHash: Omit<AuditEvent, "hash">): string {
  const canonical = canonicalizeJcs(eventWithoutHash);
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Writer lock (R38) — audit/.lock, "wx" + pid, stale-lock takeover.
// ---------------------------------------------------------------------------

function lockPathOf(auditDir: string): string {
  return path.join(auditDir, LOCK_FILENAME);
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if (isErrnoException(err) && err.code === "ESRCH") return false;
    // EPERM (exists, different owner) or anything else: treat as alive —
    // the safe default when we can't positively prove it's dead.
    return true;
  }
}

function writeLockFile(lockFile: string): void {
  const fd = openSync(lockFile, "wx");
  try {
    writeSync(fd, String(process.pid));
  } finally {
    closeSync(fd);
  }
}

function readLockPid(lockFile: string): number | null {
  try {
    const raw = readFileSync(lockFile, "utf8").trim();
    const parsed = Number.parseInt(raw, 10);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
  } catch {
    return null;
  }
}

function acquireLock(auditDir: string): void {
  const lockFile = lockPathOf(auditDir);
  try {
    writeLockFile(lockFile);
    return;
  } catch (err) {
    if (!isErrnoException(err) || err.code !== "EEXIST") throw err;
  }

  const heldPid = readLockPid(lockFile);
  if (heldPid !== null && !isPidAlive(heldPid)) {
    warnStderr(
      `knotrust: audit log lock at ${lockFile} was held by pid ${heldPid}, which is no longer running — taking over.`,
    );
    try {
      unlinkSync(lockFile);
    } catch {
      // Best-effort — if this races another takeover, the wx create below
      // will just fail again and report the (new) conflict honestly.
    }
    writeLockFile(lockFile);
    return;
  }

  throw new Error(
    `knotrust: audit log already locked (${lockFile}${heldPid !== null ? ` by pid ${heldPid}` : ""}) — ` +
      "a second concurrent writer process is not supported in P0 (single proxy process owns the log). " +
      "If that process is gone, remove the lock file manually.",
  );
}

function releaseLock(auditDir: string): void {
  try {
    unlinkSync(lockPathOf(auditDir));
  } catch {
    // Best-effort — nothing meaningful to do if this fails during shutdown.
  }
}

// ---------------------------------------------------------------------------
// File listing + tail-only crash recovery (R36).
// ---------------------------------------------------------------------------

function listAuditFiles(auditDir: string): string[] {
  if (!existsSync(auditDir)) return [];
  return readdirSync(auditDir)
    .filter((name) => AUDIT_FILE_RE.test(name))
    .sort();
}

const INITIAL_TAIL_WINDOW = 8 * 1024;
const MAX_TAIL_WINDOW = 8 * 1024 * 1024;

/** Reads the last `windowSize` bytes of an already-open fd of known `size`, lenient-decoded (see caller for why a possibly-partial leading multi-byte char is harmless here). */
function readTail(fd: number, size: number, windowSize: number): string {
  const toRead = Math.min(size, windowSize);
  const buf = Buffer.alloc(toRead);
  readSync(fd, buf, 0, toRead, size - toRead);
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

interface TailRecovery {
  empty: boolean;
  lastSeq?: number;
  lastHash?: string;
}

const NEWLINE_SCAN_CHUNK = 64 * 1024;

/**
 * Byte-exact backward scan of an already-open fd of known `size` for the
 * last `0x0A` (newline) byte, returning the byte offset immediately AFTER
 * it — i.e. exactly where the last cleanly-terminated line ends — or `0` if
 * the file contains no newline at all (the entire file is one torn
 * fragment, e.g. a crash on the very first write). Operates on raw bytes
 * only, never a decoded string: a crash can tear a write mid-multi-byte
 * UTF-8 sequence, and `TextDecoder`'s lenient replacement-character
 * substitution for that dangling partial sequence does NOT round-trip to
 * the same byte length on re-encode (a `U+FFFD` replacement char is always
 * 3 UTF-8 bytes, regardless of whether the actual truncated sequence was 1,
 * 2, or 3 bytes) — so deriving a truncation offset from decoded text length
 * mis-truncates by that byte-count delta. Scanning raw bytes sidesteps
 * encoding entirely.
 */
function findLastNewlineOffset(fd: number, size: number): number {
  let end = size;
  while (end > 0) {
    const chunkSize = Math.min(end, NEWLINE_SCAN_CHUNK);
    const start = end - chunkSize;
    const buf = Buffer.alloc(chunkSize);
    readSync(fd, buf, 0, chunkSize, start);
    const idx = buf.lastIndexOf(0x0a);
    if (idx !== -1) return start + idx + 1;
    end = start;
  }
  return 0;
}

function quarantineTornTail(
  filePath: string,
  fd: number,
  size: number,
  nowEpochMs: () => number,
): void {
  const newSize = findLastNewlineOffset(fd, size);
  const tornLength = size - newSize;
  const tornBuf = Buffer.alloc(tornLength);
  readSync(fd, tornBuf, 0, tornLength, newSize);
  const tornPath = `${filePath}.torn`;
  const stamp = new Date(nowEpochMs()).toISOString();
  // Raw bytes, not a decoded/re-encoded string — the torn fragment is
  // preserved byte-for-byte in `.torn` even when it ends mid-multi-byte
  // character (see `findLastNewlineOffset`'s doc comment).
  writeFileSync(
    tornPath,
    Buffer.concat([
      Buffer.from(
        `--- torn fragment quarantined at ${stamp} (crash mid-append recovery) ---\n`,
        "utf8",
      ),
      tornBuf,
      Buffer.from("\n", "utf8"),
    ]),
    { flag: "a" },
  );
  ftruncateSync(fd, newSize);
  warnStderr(
    `knotrust: audit log crash recovery — quarantined a torn final line in ${filePath} to ${tornPath}; resuming from the last intact line.`,
  );
}

function parseIntactLine(candidate: string): TailRecovery | null {
  const trimmed = candidate.trim();
  if (trimmed.length === 0) return null;
  try {
    const parsed = JSON.parse(trimmed) as Partial<AuditEvent>;
    if (typeof parsed.seq === "number" && typeof parsed.hash === "string") {
      return { empty: false, lastSeq: parsed.seq, lastHash: parsed.hash };
    }
  } catch {
    // Fall through — treated as no usable line found here.
  }
  return null;
}

function interpretTail(
  fd: number,
  size: number,
  usable: string[],
  filePath: string,
  nowEpochMs: () => number,
): TailRecovery {
  const last = usable[usable.length - 1];
  const intact = usable.slice(0, -1);
  if (last !== undefined && last.length > 0) {
    // No trailing newline: a crash mid-write. Quarantine (byte-exact, off
    // the raw fd — see quarantineTornTail) and continue with whatever
    // intact lines came before it. `last`'s decoded length only serves to
    // detect PRESENCE of a torn fragment here; the truncation offset itself
    // is derived from raw bytes, never this decoded string.
    quarantineTornTail(filePath, fd, size, nowEpochMs);
  }
  for (let i = intact.length - 1; i >= 0; i--) {
    const candidate = intact[i];
    if (candidate === undefined) continue;
    const result = parseIntactLine(candidate);
    if (result) return result;
  }
  return { empty: true };
}

/**
 * Locates resume state (`{lastSeq, lastHash}`) for `filePath` by reading
 * ONLY its tail, growing the read window only if needed (bounded at
 * `MAX_TAIL_WINDOW`) — never a full-file scan (R36). Also performs
 * torn-tail quarantine as a side effect when found (see module header).
 */
function recoverTailState(
  filePath: string,
  nowEpochMs: () => number,
): TailRecovery {
  const fd = openSync(filePath, "r+");
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return { empty: true };

    let windowSize = Math.min(size, INITIAL_TAIL_WINDOW);
    for (;;) {
      const text = readTail(fd, size, windowSize);
      const rawLines = text.split("\n");
      const readWholeFile = windowSize >= size;
      // When we didn't read the whole file, the FIRST element of the split
      // may be a fragment of a line that started before our window — it is
      // never used as a real line, only as a boundary marker.
      const usable = readWholeFile ? rawLines : rawLines.slice(1);

      if (usable.length >= 2 || readWholeFile) {
        return interpretTail(fd, size, usable, filePath, nowEpochMs);
      }
      const grown = Math.min(size, windowSize * 2);
      if (grown === windowSize || grown >= MAX_TAIL_WINDOW) {
        return interpretTail(fd, size, usable, filePath, nowEpochMs);
      }
      windowSize = grown;
    }
  } finally {
    closeSync(fd);
  }
}

function bootstrapChainState(
  auditDir: string,
  nowEpochMs: () => number,
): { lastSeq: number; lastHash: string } {
  const files = listAuditFiles(auditDir);
  for (let i = files.length - 1; i >= 0; i--) {
    const filename = files[i];
    if (filename === undefined) continue;
    const result = recoverTailState(path.join(auditDir, filename), nowEpochMs);
    if (
      !result.empty &&
      result.lastSeq !== undefined &&
      result.lastHash !== undefined
    ) {
      return { lastSeq: result.lastSeq, lastHash: result.lastHash };
    }
  }
  return { lastSeq: 0, lastHash: AUDIT_GENESIS_PREV_HASH };
}

function openCurrentFile(
  auditDir: string,
  nowEpochMs: () => number,
): { fd: number; yyyymm: string; filePath: string } {
  const yyyymm = yyyymmFromIso(new Date(nowEpochMs()).toISOString());
  const filePath = path.join(auditDir, `${yyyymm}.jsonl`);
  const fd = openSync(filePath, "a");
  return { fd, yyyymm, filePath };
}

// ---------------------------------------------------------------------------
// verify() — streaming reader, bounded memory (R38's ChainVerifyResult).
// ---------------------------------------------------------------------------

const CHUNK_SIZE = 64 * 1024;

/** One raw line from `iterLinesSync` — see its doc-comment. */
interface RawLine {
  line: string;
  /** 1-indexed line number within the file. */
  lineNumber: number;
  /** `true` for a final line with no trailing newline (a torn/incomplete write). */
  unterminated: boolean;
}

/**
 * Streams `filePath` line-by-line with O(chunk) memory (`CHUNK_SIZE`) —
 * never loading the whole file. A generator (not a callback) so a consumer
 * can `break` out of a `for...of` early; the generator protocol calls this
 * function's `.return()` in that case, which still runs the `finally`
 * below and closes the fd — no leak either way. Shared low-level reader
 * for `verifyChain` (chain validation, below) and `streamAuditEvents`
 * (P0-E4-T4's lock-free CLI reader, further below) — ONE chunked-read
 * implementation, two independent consumers layered on top.
 */
function* iterLinesSync(filePath: string): Generator<RawLine, void, void> {
  const fd = openSync(filePath, "r");
  try {
    const buf = Buffer.alloc(CHUNK_SIZE);
    const decoder = new TextDecoder("utf-8");
    let leftover = "";
    let lineNumber = 0;
    for (;;) {
      const bytesRead = readSync(fd, buf, 0, CHUNK_SIZE, null);
      if (bytesRead === 0) break;
      leftover += decoder.decode(buf.subarray(0, bytesRead), { stream: true });
      let nlIndex = leftover.indexOf("\n");
      while (nlIndex !== -1) {
        const line = leftover.slice(0, nlIndex);
        leftover = leftover.slice(nlIndex + 1);
        lineNumber++;
        yield { line, lineNumber, unterminated: false };
        nlIndex = leftover.indexOf("\n");
      }
    }
    leftover += decoder.decode();
    if (leftover.length > 0) {
      lineNumber++;
      yield { line: leftover, lineNumber, unterminated: true };
    }
  } finally {
    closeSync(fd);
  }
}

function isWellFormedEvent(value: unknown): value is AuditEvent {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.seq === "number" &&
    typeof v.ts === "string" &&
    typeof v.prevHash === "string" &&
    typeof v.hash === "string" &&
    typeof v.type === "string" &&
    typeof v.surface === "string" &&
    typeof v.subject === "string" &&
    typeof v.agent === "string" &&
    typeof v.tool === "string" &&
    typeof v.argsHash === "string"
  );
}

function verifyChain(auditDir: string): ChainVerifyResult {
  const files = listAuditFiles(auditDir);
  let expectedSeq = 1;
  let runningHash = AUDIT_GENESIS_PREV_HASH;
  let totalEvents = 0;

  for (const filename of files) {
    const filePath = path.join(auditDir, filename);
    for (const { line, lineNumber, unterminated } of iterLinesSync(filePath)) {
      if (unterminated) {
        return {
          ok: false,
          breakAt: {
            file: filename,
            line: lineNumber,
            seq: expectedSeq,
            kind: "torn_line",
          },
        };
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        return {
          ok: false,
          breakAt: {
            file: filename,
            line: lineNumber,
            seq: expectedSeq,
            kind: "torn_line",
          },
        };
      }
      if (!isWellFormedEvent(parsed)) {
        return {
          ok: false,
          breakAt: {
            file: filename,
            line: lineNumber,
            seq: expectedSeq,
            kind: "torn_line",
          },
        };
      }
      if (parsed.seq !== expectedSeq) {
        return {
          ok: false,
          breakAt: {
            file: filename,
            line: lineNumber,
            seq: parsed.seq,
            kind: "seq_gap",
          },
        };
      }
      if (parsed.prevHash !== runningHash) {
        return {
          ok: false,
          breakAt: {
            file: filename,
            line: lineNumber,
            seq: parsed.seq,
            kind: "prevhash_mismatch",
          },
        };
      }
      const { hash: storedHash, ...withoutHash } = parsed;
      const recomputed = computeEventHash(withoutHash);
      if (recomputed !== storedHash) {
        return {
          ok: false,
          breakAt: {
            file: filename,
            line: lineNumber,
            seq: parsed.seq,
            kind: "hash_mismatch",
          },
        };
      }
      runningHash = storedHash;
      expectedSeq = parsed.seq + 1;
      totalEvents++;
    }
  }

  return { ok: true, events: totalEvents };
}

// ---------------------------------------------------------------------------
// streamAuditEvents() / verifyAuditChain() — LOCK-FREE read-only exports for
// the `knotrust audit list|tail|query|verify` CLI (P0-E4-T4, rulings
// R122-R125). Both operate directly on the audit directory via the SAME
// low-level `iterLinesSync` chunked reader `verifyChain` uses above — NEVER
// through `createAuditLog()`/`AuditSink`, and therefore never touch
// `audit/.lock`: a forensic read (a human running `knotrust audit tail` in a
// second terminal while the real proxy process is running and holds the
// writer lock) must never contend with, or be blocked by, the live writer.
// Both stream with O(chunk) memory regardless of file size — the
// flat-memory acceptance (R123/R124) for the CLI's list/tail/query surfaces.
// ---------------------------------------------------------------------------

/** One raw line from `streamAuditEvents()` — see its own doc-comment. */
export interface AuditLogEntry {
  /** `<yyyymm>.jsonl` filename this line came from. */
  file: string;
  /** 1-indexed line number within `file`. */
  lineNumber: number;
  /**
   * The parsed, well-formed event — `undefined` if this line failed to
   * parse as JSON, didn't satisfy `isWellFormedEvent`, or is an
   * unterminated (torn) final line. This iterator performs NO chain
   * validation (hash/prevHash/seq continuity) — that remains
   * `verifyAuditChain`'s job; a caller wanting tamper detection uses that
   * function, not this one. `undefined` here just means "not a decodable
   * event," nothing more — the CLI layer decides whether to surface or
   * silently skip it.
   */
  event: AuditEvent | undefined;
}

/**
 * Streams every line across every `<yyyymm>.jsonl` file under `home`'s
 * `audit/` dir, in file-then-position order (which is seq order for an
 * untampered chain — this function does not itself check that), with
 * O(chunk) memory: never loading a whole file, let alone the whole
 * directory, into memory at once. The sole reader behind `knotrust audit
 * list|tail|query` (P0-E4-T4): those commands filter / keep-last-N as they
 * consume this generator, never before. Defaults `home` the same way
 * `createAuditLog` does (`KNOTRUST_HOME` override, else `~/.knotrust`).
 */
export function* streamAuditEvents(
  home?: string,
): Generator<AuditLogEntry, void, void> {
  const auditDir = auditDirOf(home ?? resolveKnotrustHome());
  const files = listAuditFiles(auditDir);
  for (const filename of files) {
    const filePath = path.join(auditDir, filename);
    for (const { line, lineNumber, unterminated } of iterLinesSync(filePath)) {
      if (unterminated) {
        yield { file: filename, lineNumber, event: undefined };
        continue;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        yield { file: filename, lineNumber, event: undefined };
        continue;
      }
      yield {
        file: filename,
        lineNumber,
        event: isWellFormedEvent(parsed) ? parsed : undefined,
      };
    }
  }
}

/**
 * Standalone, lock-free chain verification for `knotrust audit verify`
 * (P0-E4-T4) — the SAME check `AuditSink.verify()` runs (this function IS
 * `verifyChain` above; the sink method is a one-line delegate to it too),
 * but reachable WITHOUT constructing a full sink, which would call
 * `acquireLock` and throw if a real proxy process already holds
 * `audit/.lock`. A read-only forensic command must stay usable
 * concurrently with a live writer.
 */
export function verifyAuditChain(home?: string): ChainVerifyResult {
  return verifyChain(auditDirOf(home ?? resolveKnotrustHome()));
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

function stripUndefinedShallow<T extends object>(obj: T): T {
  const out = {} as T;
  for (const key of Object.keys(obj) as (keyof T)[]) {
    if (obj[key] !== undefined) out[key] = obj[key];
  }
  return out;
}

export function createAuditLog(opts: CreateAuditLogOptions): AuditSink {
  const home = opts.home ?? resolveKnotrustHome();
  const nowEpochMs = opts.nowEpochMs;
  const captureRawArgs = opts.captureRawArgs ?? false;
  const fsyncBatchMs = Math.min(
    opts.fsyncBatchMs ?? DEFAULT_FSYNC_BATCH_MS,
    DEFAULT_FSYNC_BATCH_MS,
  );

  const auditDir = auditDirOf(home);
  ensureAuditDir(auditDir);
  acquireLock(auditDir);

  // Once the lock is ours, any failure while finishing construction must
  // release it before rethrowing — otherwise a bootstrap/open failure
  // leaves `.lock` held by this (still-live) pid with no sink around to
  // ever call close(), wedging every future createAuditLog() against this
  // home for the rest of the process's lifetime.
  let chainState: { lastSeq: number; lastHash: string };
  let current: { fd: number; yyyymm: string; filePath: string };
  try {
    chainState = bootstrapChainState(auditDir, nowEpochMs);
    current = openCurrentFile(auditDir, nowEpochMs);
  } catch (err) {
    releaseLock(auditDir);
    throw err;
  }
  let broken = false;
  let closed = false;
  let dirty = false;
  let fsyncTimer: ReturnType<typeof setTimeout> | null = null;

  // R127 subscriber hook — see `AuditSink.onAppend`'s own doc-comment for the
  // full contract. A plain `Set` (registration order preserved, per spec) —
  // no dependency on `node:events`'s `EventEmitter` for something this small.
  const appendListeners = new Set<(event: AuditEvent) => void>();

  function onAppend(listener: (event: AuditEvent) => void): () => void {
    appendListeners.add(listener);
    return () => {
      appendListeners.delete(listener);
    };
  }

  function notifyAppendListeners(event: AuditEvent): void {
    if (appendListeners.size === 0) return; // the common case: nobody ever subscribed.
    for (const listener of appendListeners) {
      try {
        listener(event);
      } catch (err) {
        warnStderr(
          `knotrust: an audit onAppend listener threw (ignored — the audit trail's own contract takes priority): ${errorMessage(err)}`,
        );
      }
    }
  }

  function clearPendingTimer(): void {
    if (fsyncTimer) {
      clearTimeout(fsyncTimer);
      fsyncTimer = null;
    }
  }

  function scheduleFsync(): void {
    if (fsyncTimer) return; // already scheduled; will cover this write too
    fsyncTimer = setTimeout(() => {
      fsyncTimer = null;
      try {
        fsyncSync(current.fd);
        dirty = false;
      } catch (err) {
        warnStderr(
          `knotrust: deferred audit fsync failed: ${errorMessage(err)}`,
        );
        broken = true;
      }
    }, fsyncBatchMs);
    fsyncTimer.unref?.();
  }

  function rotateIfNeeded(tsIso: string): void {
    const desiredYyyymm = yyyymmFromIso(tsIso);
    if (desiredYyyymm === current.yyyymm) return;
    try {
      if (dirty) fsyncSync(current.fd);
    } catch {
      // Best-effort — a failure here is reported (broken=true) by the
      // write path that set `dirty`, not duplicated here.
    }
    clearPendingTimer();
    dirty = false;
    closeSync(current.fd);
    current = openCurrentFile(auditDir, () => Date.parse(tsIso));
  }

  function recoverFromBrokenState(): boolean {
    try {
      ensureAuditDir(auditDir);
      chainState = bootstrapChainState(auditDir, nowEpochMs);
      current = openCurrentFile(auditDir, nowEpochMs);
      broken = false;
      return true;
    } catch (err) {
      warnStderr(
        `knotrust: audit log recovery attempt failed: ${errorMessage(err)}`,
      );
      return false;
    }
  }

  function writeEventRaw(
    partial: Omit<AuditEvent, "seq" | "prevHash" | "hash" | "ts">,
    tsIso: string,
    fsyncMode?: "immediate",
  ): AuditEvent {
    rotateIfNeeded(tsIso);
    const seq = chainState.lastSeq + 1;
    const prevHash = chainState.lastHash;
    try {
      const withoutHash: Omit<AuditEvent, "hash"> = {
        seq,
        ts: tsIso,
        prevHash,
        ...partial,
      };
      const hash = computeEventHash(withoutHash);
      const full: AuditEvent = { ...withoutHash, hash };
      const line = `${canonicalizeJcs(full)}\n`;
      writeSync(current.fd, line, null, "utf8");
      dirty = true;
      if (fsyncMode === "immediate") {
        fsyncSync(current.fd);
        dirty = false;
        clearPendingTimer();
      } else {
        scheduleFsync();
      }
      chainState = { lastSeq: seq, lastHash: hash };
      // R127: every successful write notifies subscribers with the FULL,
      // final event (post seq/prevHash/hash) — the single choke point every
      // append (caller-initiated or the internal audit_recovered marker)
      // passes through, so a listener needs no special casing for either.
      notifyAppendListeners(full);
      return full;
    } catch (err) {
      warnStderr(`knotrust: audit log append failed: ${errorMessage(err)}`);
      broken = true;
      try {
        closeSync(current.fd);
      } catch {
        // Best-effort — the write failure above is what matters.
      }
      throw new AuditUnavailableError(
        "knotrust: audit log append failed — call denied fail-closed (see AUDIT_UNAVAILABLE)",
        { cause: err },
      );
    }
  }

  function append(
    event: Omit<AuditEvent, "seq" | "prevHash" | "hash" | "ts">,
    appendOpts?: { fsync?: "immediate" },
  ): AuditEvent {
    if (closed) {
      throw new AuditUnavailableError("knotrust: audit log is closed");
    }
    const tsIso = new Date(nowEpochMs()).toISOString();

    if (broken) {
      const recovered = recoverFromBrokenState();
      if (!recovered) {
        throw new AuditUnavailableError(
          "knotrust: audit log append failed — recovery attempt also failed, call denied fail-closed",
        );
      }
      // `recoverFromBrokenState()` just re-bootstrapped `chainState` from
      // what's actually durable on disk — its `lastSeq` IS the seq of the
      // last event this sink can confirm survived the failure. Stamp it on
      // the marker so a forensic reader can bound the gap (see
      // `AuditEvent.lastGoodSeq`) without having to diff two `verify()`
      // runs.
      const lastGoodSeq = chainState.lastSeq;
      writeEventRaw(
        {
          type: AuditEventType.AUDIT_RECOVERED,
          surface: "audit",
          subject: "system",
          agent: "system",
          tool: "audit_log",
          argsHash: computeArgsHash(null),
          reason:
            "resumed after an audit-write failure; see stderr for the original error — at least one event after lastGoodSeq may be missing",
          lastGoodSeq,
        },
        tsIso,
      );
    }

    const { rawArgs, ...rest } = event as Omit<
      AuditEvent,
      "seq" | "prevHash" | "hash" | "ts"
    > & {
      rawArgs?: unknown;
    };
    const withRawArgs =
      captureRawArgs && "rawArgs" in event ? { ...rest, rawArgs } : rest;
    return writeEventRaw(
      stripUndefinedShallow(withRawArgs),
      tsIso,
      appendOpts?.fsync,
    );
  }

  function flush(): void {
    if (closed) return;
    clearPendingTimer();
    if (!dirty) return;
    try {
      fsyncSync(current.fd);
      dirty = false;
    } catch (err) {
      warnStderr(
        `knotrust: audit log flush (fsync) failed: ${errorMessage(err)}`,
      );
      broken = true;
      throw new AuditUnavailableError("knotrust: audit log flush failed", {
        cause: err,
      });
    }
  }

  function close(): void {
    if (closed) return;
    clearPendingTimer();
    if (dirty) {
      try {
        fsyncSync(current.fd);
      } catch (err) {
        warnStderr(
          `knotrust: audit log close: final fsync failed: ${errorMessage(err)}`,
        );
      }
    }
    try {
      closeSync(current.fd);
    } catch {
      // Best-effort on shutdown.
    }
    releaseLock(auditDir);
    closed = true;
  }

  function verify(): ChainVerifyResult {
    return verifyChain(auditDir);
  }

  return { append, flush, close, verify, onAppend };
}
