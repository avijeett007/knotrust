/**
 * @knotrust/store — file-backed grants directory store (P0-E4-T1; rulings
 * R29–R31; `docs/03-engineering/local-store-layout.md` §2).
 *
 * ## Dependency direction (R29) — store is the LOWER layer
 *
 * `packages/grants` (E3-T3) will import THIS module for the consumed-`jti`
 * ledger; this module therefore never imports `@knotrust/grants` — that
 * would make a cycle. It follows that this module never parses JWS or
 * verifies a signature: it treats every token as an opaque string. Where a
 * caller needs to look inside a token (extracting `jti` on `put()`,
 * filtering by `tool`/`agent` in `listBy()`), it injects a decoder:
 *
 * ```
 * createGrantStore({ decodeIndexEntry: (token) => GrantIndexEntry | null })
 * ```
 *
 * `DecodeIndexEntry` is ONE function, not a `decode()` + per-claim-accessor
 * pair — the two call sites this module has (`put`'s `jti` extraction,
 * `listBy`'s `tool`/`agentId` filter) want exactly the same three fields, so
 * a single small seam beats a wider one nothing here needs. A `null` return
 * means "undecodable/garbage" and is the ONLY thing this module ever means
 * by `grant_invalid` — signature-level verification is `@knotrust/grants`'
 * job, upstream of this store (R29).
 *
 * `resolveKnotrustHome()` below is a deliberate, documented DUPLICATE of
 * `packages/grants/src/keys.ts`'s function of the same name and behavior —
 * see that duplication note on the function itself.
 *
 * ## On-disk layout (R30)
 *
 * ```
 * <home>/grants/<jti>.jws            the token text, exactly, + trailing "\n"
 * <home>/grants/tombstones/<jti>.json  { jti, revokedAt, reason? } (RFC 3339)
 * <home>/grants/consumed/<jti>         empty marker, created with O_EXCL
 * ```
 *
 * A tombstone is the ONLY thing that makes a grant revoked. `revoke()`
 * writes the tombstone FIRST (atomically), then best-effort-unlinks the
 * `.jws` — an unlink failure is tolerated and never surfaces as an error,
 * because tombstone presence alone already makes every read path (`get()`,
 * `list()`, `listBy()`) treat the jti as revoked/excluded regardless of
 * whether the `.jws` file is still sitting there. This is the invariant
 * that makes revocation crash-safe: a process that dies between the
 * tombstone write and the unlink has still fully revoked the grant.
 *
 * ## The replay-protection primitive (R30)
 *
 * `consumeOnce(jti)` creates `grants/consumed/<jti>` with the `"wx"` flag
 * (`O_CREAT | O_EXCL`) — a single `open()` syscall that either creates the
 * file (this call is the first-and-only winner: `"consumed"`) or fails
 * `EEXIST` (someone already won: `"already_consumed"`). This is POSIX-level
 * atomic across independent OS processes with NO lock file, NO read-then-
 * write, and NO in-process coordination — the single-use gate a real replay
 * defense needs. `packages/grants` (E3-T3) wires this into ephemeral/
 * single-use grant decisions; the multi-process test in
 * `grant-store.concurrent.test.ts` is this primitive's proof.
 *
 * ## Write discipline (R31)
 *
 * Every file this module writes (`.jws`, tombstone `.json`) goes through
 * `atomicWriteFileSync`: write to `<name>.<random>.tmp` in the SAME
 * directory, then `rename()` — atomic on POSIX same-filesystem renames, so
 * a reader either sees the fully-old or the fully-new file, never a torn
 * one. `consumeOnce`'s marker is the one exception: it has no "old"
 * version to replace, so the `wx`-exclusive create IS its own atomic
 * commit, with no temp file needed. Directories are created `0700` lazily
 * and re-`chmod`'d on every write path that touches them, mirroring
 * `keys.ts`'s `ensureKnotrustHomeDir` — defensive against a directory that
 * pre-existed with looser permissions from something else.
 *
 * No locks, no native dependencies — everything above is `node:fs`,
 * `node:path`, `node:crypto`, `node:os` builtins only.
 */

import { randomBytes as nodeRandomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

// ---------------------------------------------------------------------------
// Injected decoder seam (R29)
// ---------------------------------------------------------------------------

export interface GrantIndexEntry {
  jti: string;
  tool: string;
  /** `null` = the grant's `agent` claim is `"*"` (any agent). */
  agentId: string | null;
}

/**
 * Decodes an opaque token into the store's index fields, or `null` if the
 * token is undecodable/garbage. SHOULD never throw, but if it does, every
 * call site in this module catches it and treats the throw exactly like the
 * documented `null` return — `put()` reports `decode_failed`, and the
 * `list()`/`listBy()` scan reports the file under `invalid: grant_invalid` —
 * never an uncaught exception (P0-E4-T1 review round 1, FIX 3).
 */
export type DecodeIndexEntry = (token: string) => GrantIndexEntry | null;

// ---------------------------------------------------------------------------
// Public result/record shapes
// ---------------------------------------------------------------------------

export type PutResult =
  | { ok: true; jti: string }
  | { ok: false; reason: "decode_failed" };

export type GetResult =
  | { status: "active"; token: string }
  | { status: "revoked" }
  | { status: "absent" };

export interface GrantRecord {
  jti: string;
  token: string;
}

export interface InvalidGrant {
  jti: string;
  reason: "grant_invalid";
}

/**
 * Shared shape for `list()` and `listBy()`. `list()` is exactly `listBy({})`
 * (ruling 6 requires BOTH to surface tampered files under `invalid`, so one
 * scan implementation backs both instead of `list()` skipping decode
 * entirely and silently returning garbage as if it were a real token).
 */
export interface ListResult {
  active: GrantRecord[];
  invalid: InvalidGrant[];
}

export interface ListByFilter {
  /**
   * WARNING: EXACT-STRING match against the stored grant's `tool` claim —
   * this store does NOT expand or evaluate glob patterns. A grant stored
   * with `tool: "github.*"` is NOT returned by
   * `listBy({ tool: "github.create_issue" })`; only
   * `listBy({ tool: "github.*" })` (matching the literal stored string)
   * returns it.
   *
   * Do NOT use this filter to fetch candidate grants for authorizing one
   * concrete tool call — that silently misses every glob-scoped grant (a
   * false-deny footgun). For authorization, fetch unfiltered (or filter by
   * `agentId` only) and let the grants-layer matcher (upstream of this
   * store, per R29) evaluate glob patterns against the concrete tool name.
   */
  tool?: string;
  agentId?: string;
}

export type ConsumeResult = "consumed" | "already_consumed";

export interface GrantStoreStats {
  active: number;
  revoked: number;
  consumed: number;
  invalid: number;
}

export interface RevokeTombstone {
  jti: string;
  /** RFC 3339 (profiled subset of ISO 8601, ADR-0017), matching every other timestamp this codebase emits. */
  revokedAt: string;
  reason?: string;
}

export interface GrantStore {
  put(token: string): PutResult;
  get(jti: string): GetResult;
  remove(jti: string): void;
  revoke(jti: string, reason?: string): void;
  list(): ListResult;
  /**
   * WARNING: `filter.tool` is EXACT-STRING match against each stored
   * grant's `tool` claim — it does NOT expand or evaluate glob patterns. A
   * grant stored with `tool: "github.*"` is NOT returned when filtering by
   * a concrete tool name like `"github.create_issue"`.
   *
   * Do NOT call this to gather candidate grants for authorizing one
   * concrete tool invocation — that silently drops every glob-scoped grant
   * (false-deny). Fetch unfiltered (or filter by `agentId` only) instead,
   * and let the grants-layer matcher evaluate glob patterns. See
   * `ListByFilter.tool`.
   */
  listBy(filter: ListByFilter): ListResult;
  consumeOnce(jti: string): ConsumeResult;
  isConsumed(jti: string): boolean;
  stats(): GrantStoreStats;
}

export interface CreateGrantStoreOptions {
  /** Defaults to `resolveKnotrustHome()` (the `KNOTRUST_HOME` override, else `~/.knotrust`). */
  home?: string;
  decodeIndexEntry: DecodeIndexEntry;
  /**
   * Epoch milliseconds — stamps `revoke()`'s tombstone `revokedAt` (P0-E4-T2
   * preliminary item: this was the one non-injected clock left in the
   * revocation path). Defaults to `Date.now`, so omitting this option is
   * behavior-neutral; tests can inject a fixed clock for a deterministic
   * `revokedAt` assertion, matching every other clock-carrying module in
   * this codebase (l0-evaluator.ts, decision-cache.ts, audit-log.ts, ...).
   */
  nowEpochMs?: () => number;
}

// ---------------------------------------------------------------------------
// $KNOTRUST_HOME resolution — duplicated, not imported, from
// packages/grants/src/keys.ts's function of the same name and behavior.
// R29 makes store the LOWER layer (grants imports store, never the
// reverse), so store cannot depend on grants even for this one trivial
// helper. Read fresh on every call — never cached — so tests can point a
// whole store at a fresh temp dir per case with no module-reload
// gymnastics. Keep both copies in sync if the resolution rule ever changes.
// ---------------------------------------------------------------------------

function resolveKnotrustHome(): string {
  const override = process.env.KNOTRUST_HOME;
  if (override !== undefined && override.trim() !== "") {
    return override;
  }
  return path.join(homedir(), ".knotrust");
}

// ---------------------------------------------------------------------------
// Layout paths
// ---------------------------------------------------------------------------

const DIR_MODE = 0o700;
const JWS_SUFFIX = ".jws";
const TOMBSTONE_SUFFIX = ".json";

function grantsDir(home: string): string {
  return path.join(home, "grants");
}

function tombstonesDir(home: string): string {
  return path.join(grantsDir(home), "tombstones");
}

function consumedDir(home: string): string {
  return path.join(grantsDir(home), "consumed");
}

function jwsPath(home: string, jti: string): string {
  return path.join(grantsDir(home), `${jti}${JWS_SUFFIX}`);
}

function tombstonePath(home: string, jti: string): string {
  return path.join(tombstonesDir(home), `${jti}${TOMBSTONE_SUFFIX}`);
}

function consumedMarkerPath(home: string, jti: string): string {
  return path.join(consumedDir(home), jti);
}

// ---------------------------------------------------------------------------
// jti safety — every jti that reaches a path-construction function goes
// through this, whether it came from a caller directly (get/remove/revoke/
// consumeOnce/isConsumed) or via the injected decoder (put). Defense in
// depth against a decoder (or a caller) handing back a jti containing path
// separators — this module is the last line of defense before that string
// becomes a filesystem path.
// ---------------------------------------------------------------------------

const SAFE_JTI = /^[A-Za-z0-9_-]+$/;

function assertSafeJti(jti: string): void {
  if (!SAFE_JTI.test(jti)) {
    throw new Error(
      `knotrust/store: refusing unsafe jti ${JSON.stringify(jti)} — expected to match ${SAFE_JTI}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Directory + atomic-write helpers (R31)
// ---------------------------------------------------------------------------

function ensureSecureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  // mkdirSync's `mode` only applies at creation time — re-enforce it even
  // if `dir` pre-existed with looser permissions from something else
  // (mirrors keys.ts's ensureKnotrustHomeDir).
  chmodSync(dir, DIR_MODE);
}

function ensureGrantsTree(home: string): void {
  ensureSecureDir(home);
  ensureSecureDir(grantsDir(home));
}

function ensureTombstonesDir(home: string): void {
  ensureGrantsTree(home);
  ensureSecureDir(tombstonesDir(home));
}

// Memoized per `home` after the first successful call (P0-E4-T1 review
// round 2): ensureSecureDir's mkdir+chmod pair is cheap but redundant on
// every consumeOnce() call once the directory demonstrably already exists
// with the right mode, so this skips two syscalls per replay-protection
// check after the first. The self-heal chmod (re-enforcing 0700 against a
// directory that pre-existed with looser permissions — see
// ensureSecureDir's own comment) still runs on the FIRST call for a given
// home; a directory whose permissions are loosened by something else AFTER
// that first call is not re-detected until the process restarts — an
// accepted tradeoff, since consumeOnce()'s correctness comes from the
// O_EXCL create itself, not from the directory mode being continuously
// re-asserted. If the directory is deleted entirely (not just loosened)
// after being memoized, consumeOnce() detects the resulting ENOENT on its
// "wx" open, evicts this `home` from the memo, and retries once — see
// consumeOnce() below; this Set only ever skips the redundant
// mkdir+chmod, it never causes a real gap in the ledger.
const consumedDirEnsuredHomes = new Set<string>();

function ensureConsumedDir(home: string): void {
  if (consumedDirEnsuredHomes.has(home)) return;
  ensureGrantsTree(home);
  ensureSecureDir(consumedDir(home));
  consumedDirEnsuredHomes.add(home);
}

function randomSuffix(): string {
  return Buffer.from(nodeRandomBytes(8)).toString("hex");
}

/**
 * Write-to-temp-then-rename (R31): the SAME directory (rename is only
 * atomic same-filesystem), a per-call random suffix (safe under concurrent
 * writers — including two independent OS processes racing the same jti,
 * per the acceptance test), then an atomic `rename()` over the destination.
 */
function atomicWriteFileSync(filePath: string, contents: string): void {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(
    dir,
    `${path.basename(filePath)}.${randomSuffix()}.tmp`,
  );
  writeFileSync(tmpPath, contents);
  try {
    renameSync(tmpPath, filePath);
  } catch (err) {
    // A successful rename already moved tmpPath to filePath — there is
    // nothing to clean up on that path, so cleanup only ever runs here, on
    // the failure path (P0-E4-T1 review round 2: skip the
    // guaranteed-ENOENT unlinkSync the success path used to attempt).
    // Best-effort so a failed atomic write never leaks a stray
    // "<name>.<random>.tmp" file — this never surfaces its own error, since
    // the renameSync failure below is what the caller needs to see, not a
    // cleanup failure layered on top of it.
    try {
      unlinkSync(tmpPath);
    } catch {
      // Intentionally swallowed — see comment above.
    }
    throw err;
  }
}

function stripTrailingNewline(raw: string): string {
  return raw.endsWith("\n") ? raw.slice(0, -1) : raw;
}

function errnoCode(err: unknown): string | undefined {
  if (err instanceof Error && "code" in err) {
    return (err as NodeJS.ErrnoException).code;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// put()
// ---------------------------------------------------------------------------

function put(
  home: string,
  decodeIndexEntry: DecodeIndexEntry,
  token: string,
): PutResult {
  // decodeIndexEntry is documented (see the module doc comment) to NEVER
  // throw, but a caller-supplied decoder is untrusted input from this
  // module's point of view — a throw here is treated exactly like the
  // documented `null` return (undecodable/garbage), never an uncaught
  // exception (fix for P0-E4-T1 review round 1).
  let entry: GrantIndexEntry | null;
  try {
    entry = decodeIndexEntry(token);
  } catch {
    return { ok: false, reason: "decode_failed" };
  }
  if (entry === null) {
    return { ok: false, reason: "decode_failed" };
  }
  assertSafeJti(entry.jti);
  ensureGrantsTree(home);
  const normalized = stripTrailingNewline(token);
  atomicWriteFileSync(jwsPath(home, entry.jti), `${normalized}\n`);
  return { ok: true, jti: entry.jti };
}

// ---------------------------------------------------------------------------
// get()
// ---------------------------------------------------------------------------

function get(home: string, jti: string): GetResult {
  assertSafeJti(jti);
  // Tombstone wins, unconditionally — R30. Checked BEFORE the .jws exists
  // check so a lingering .jws (failed unlink) can never resurrect an
  // "active" result.
  if (existsSync(tombstonePath(home, jti))) {
    return { status: "revoked" };
  }
  const filePath = jwsPath(home, jti);
  if (!existsSync(filePath)) {
    return { status: "absent" };
  }
  // A concurrent remove()/revoke() can unlink the .jws in the window
  // between the existsSync check above and this read — ENOENT here means
  // exactly what a failed existsSync would have meant (the grant is gone),
  // not a crash. Any OTHER errno (permissions, I/O error, etc.) still
  // throws — only ENOENT is a tolerated race, never silently swallowed
  // wholesale (fix for P0-E4-T1 review round 1).
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch (err) {
    if (errnoCode(err) === "ENOENT") {
      return { status: "absent" };
    }
    throw err;
  }
  return { status: "active", token: stripTrailingNewline(raw) };
}

// ---------------------------------------------------------------------------
// remove()
// ---------------------------------------------------------------------------

function remove(home: string, jti: string): void {
  assertSafeJti(jti);
  try {
    unlinkSync(jwsPath(home, jti));
  } catch (err) {
    if (errnoCode(err) !== "ENOENT") {
      throw err;
    }
  }
}

// ---------------------------------------------------------------------------
// revoke()
// ---------------------------------------------------------------------------

function revoke(
  home: string,
  nowEpochMs: () => number,
  jti: string,
  reason?: string,
): void {
  assertSafeJti(jti);
  ensureTombstonesDir(home);
  const tombstone: RevokeTombstone = {
    jti,
    revokedAt: new Date(nowEpochMs()).toISOString(),
    ...(reason !== undefined ? { reason } : {}),
  };
  atomicWriteFileSync(
    tombstonePath(home, jti),
    `${JSON.stringify(tombstone)}\n`,
  );
  // Best-effort only, by design (R30): the tombstone we just committed
  // above is what makes this jti revoked, unconditionally. ANY unlink
  // failure — ENOENT because it was never there, a permission error, a
  // process that dies right here — is tolerated and never surfaces.
  try {
    unlinkSync(jwsPath(home, jti));
  } catch {
    // Intentionally swallowed — see comment above.
  }
}

// ---------------------------------------------------------------------------
// list() / listBy() — one shared scan, per ruling 6 (both surface tampered
// files under `invalid`).
// ---------------------------------------------------------------------------

/** Tombstoned jtis (by filename, `.json` stripped) — used to exclude revoked grants even when their `.jws` lingers. */
function readRevokedJtiSet(home: string): Set<string> {
  const dir = tombstonesDir(home);
  if (!existsSync(dir)) return new Set();
  const out = new Set<string>();
  for (const name of readdirSync(dir)) {
    if (name.endsWith(TOMBSTONE_SUFFIX)) {
      out.add(name.slice(0, -TOMBSTONE_SUFFIX.length));
    }
  }
  return out;
}

function listJwsFilenames(home: string): string[] {
  const dir = grantsDir(home);
  if (!existsSync(dir)) return [];
  // Suffix filtering also naturally excludes the tombstones/ and consumed/
  // subdirectories (neither ends in ".jws"), and any stray "<jti>.jws.<r>.tmp"
  // left behind by a crash mid-write (it ends in ".tmp", not ".jws").
  return readdirSync(dir).filter((name) => name.endsWith(JWS_SUFFIX));
}

interface ScannedEntry extends GrantRecord {
  indexed: GrantIndexEntry;
}

function scanActiveGrants(
  home: string,
  decodeIndexEntry: DecodeIndexEntry,
): { entries: ScannedEntry[]; invalid: InvalidGrant[] } {
  const revoked = readRevokedJtiSet(home);
  const entries: ScannedEntry[] = [];
  const invalid: InvalidGrant[] = [];

  for (const filename of listJwsFilenames(home)) {
    const jti = filename.slice(0, -JWS_SUFFIX.length);
    if (revoked.has(jti)) continue; // tombstone wins even if .jws lingers (R30)

    // A concurrent remove()/revoke() can unlink a .jws file in the window
    // between the readdirSync above and this read — that file simply isn't
    // there anymore to scan, so it's skipped, exactly as if readdirSync had
    // never listed it. Any OTHER errno still throws (fix for P0-E4-T1
    // review round 1).
    let rawToken: string;
    try {
      rawToken = readFileSync(path.join(grantsDir(home), filename), "utf8");
    } catch (err) {
      if (errnoCode(err) === "ENOENT") continue;
      throw err;
    }
    const token = stripTrailingNewline(rawToken);
    // decodeIndexEntry is documented to NEVER throw, but — same as put()'s
    // call site — a throw from a caller-supplied decoder is treated exactly
    // like its documented `null` return (grant_invalid), never an uncaught
    // exception (fix for P0-E4-T1 review round 1).
    let indexed: GrantIndexEntry | null;
    try {
      indexed = decodeIndexEntry(token);
    } catch {
      indexed = null;
    }
    // A decode failure is undecodable/garbage (R29's grant_invalid). A
    // decode SUCCESS whose claimed jti doesn't match the filename it was
    // found under is treated the same way: the file's identity — the
    // filename, which R30 makes the canonical jti — doesn't match its own
    // content, which is exactly the "misplaced/tampered file" case this
    // channel exists to surface, never a crash.
    if (indexed === null || indexed.jti !== jti) {
      invalid.push({ jti, reason: "grant_invalid" });
      continue;
    }
    entries.push({ jti, token, indexed });
  }

  return { entries, invalid };
}

function matchesFilter(
  indexed: GrantIndexEntry,
  filter: ListByFilter,
): boolean {
  if (filter.tool !== undefined && indexed.tool !== filter.tool) {
    return false;
  }
  if (filter.agentId !== undefined) {
    // A grant scoped to "*" (agentId === null) applies to every agent, so
    // it matches any requested agentId; store-level filtering is a plain
    // index lookup, not glob/pattern policy evaluation — that belongs to
    // the authorization layer upstream (packages/pdp / packages/grants),
    // never here.
    const matchesAgent =
      indexed.agentId === null || indexed.agentId === filter.agentId;
    if (!matchesAgent) return false;
  }
  return true;
}

function list(home: string, decodeIndexEntry: DecodeIndexEntry): ListResult {
  const { entries, invalid } = scanActiveGrants(home, decodeIndexEntry);
  return { active: entries.map(({ jti, token }) => ({ jti, token })), invalid };
}

function listBy(
  home: string,
  decodeIndexEntry: DecodeIndexEntry,
  filter: ListByFilter,
): ListResult {
  const { entries, invalid } = scanActiveGrants(home, decodeIndexEntry);
  const active = entries
    .filter((entry) => matchesFilter(entry.indexed, filter))
    .map(({ jti, token }) => ({ jti, token }));
  return { active, invalid };
}

// ---------------------------------------------------------------------------
// consumeOnce() / isConsumed() — the replay-protection primitive (R30).
// ---------------------------------------------------------------------------

function openConsumedMarker(home: string, jti: string): number {
  return openSync(consumedMarkerPath(home, jti), "wx");
}

function consumeOnce(home: string, jti: string): ConsumeResult {
  assertSafeJti(jti);
  ensureConsumedDir(home);
  // "wx" = O_CREAT | O_EXCL — the ENTIRE atomicity guarantee lives in this
  // one syscall. No read-then-write anywhere in this path.
  let fd: number;
  try {
    fd = openConsumedMarker(home, jti);
  } catch (err) {
    if (errnoCode(err) === "EEXIST") {
      return "already_consumed";
    }
    if (errnoCode(err) !== "ENOENT") {
      throw err;
    }
    // grants/consumed/ itself is gone — most likely deleted out from under
    // a live process after ensureConsumedDir()'s memo (consumedDirEnsuredHomes,
    // above) already marked this `home` as done, so the cheap early-return
    // never re-checked the directory actually still exists. Self-heal:
    // bypass the memo, force-recreate the directory, and retry the "wx"
    // open EXACTLY once — still a single O_EXCL create, so exactly-once
    // semantics are preserved (this is not a loop; a second ENOENT/other
    // error here is a real, unrecovered failure and propagates).
    consumedDirEnsuredHomes.delete(home);
    ensureConsumedDir(home);
    try {
      fd = openConsumedMarker(home, jti);
    } catch (retryErr) {
      if (errnoCode(retryErr) === "EEXIST") {
        return "already_consumed";
      }
      throw retryErr;
    }
  }
  // By the time we reach here the marker file already exists durably on
  // disk — this call has already won, unconditionally (P0-E4-T1 review
  // round 2). A closeSync() failure now is a separate, much rarer
  // OS-level error unrelated to whether the create succeeded; surfacing it
  // as a thrown exception would mislead a caller into treating a WON,
  // DURABLE single-use consumption as if it hadn't happened — the
  // fail-OPEN risk a replay-protection primitive can least afford.
  // Best-effort close, swallowed, so the winning "consumed" result is
  // always reported accurately (fail-closed: the marker's existence is
  // truth, not this close() call's success).
  try {
    closeSync(fd);
  } catch {
    // Intentionally swallowed — see comment above.
  }
  return "consumed";
}

function isConsumed(home: string, jti: string): boolean {
  assertSafeJti(jti);
  return existsSync(consumedMarkerPath(home, jti));
}

// ---------------------------------------------------------------------------
// stats()
// ---------------------------------------------------------------------------

function countDirEntries(dir: string): number {
  if (!existsSync(dir)) return 0;
  return readdirSync(dir).length;
}

function stats(
  home: string,
  decodeIndexEntry: DecodeIndexEntry,
): GrantStoreStats {
  const { entries, invalid } = scanActiveGrants(home, decodeIndexEntry);
  return {
    active: entries.length,
    // Counted via the same tombstone-suffix filter as the scan above (not
    // a raw directory-entry count) so a stray ".tmp" left by a crash
    // mid-write never inflates this number.
    revoked: readRevokedJtiSet(home).size,
    consumed: countDirEntries(consumedDir(home)),
    invalid: invalid.length,
  };
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createGrantStore(opts: CreateGrantStoreOptions): GrantStore {
  const home = opts.home ?? resolveKnotrustHome();
  const decodeIndexEntry = opts.decodeIndexEntry;
  const nowEpochMs = opts.nowEpochMs ?? Date.now;

  return {
    put: (token) => put(home, decodeIndexEntry, token),
    get: (jti) => get(home, jti),
    remove: (jti) => remove(home, jti),
    revoke: (jti, reason) => revoke(home, nowEpochMs, jti, reason),
    list: () => list(home, decodeIndexEntry),
    listBy: (filter) => listBy(home, decodeIndexEntry, filter),
    consumeOnce: (jti) => consumeOnce(home, jti),
    isConsumed: (jti) => isConsumed(home, jti),
    stats: () => stats(home, decodeIndexEntry),
  };
}
