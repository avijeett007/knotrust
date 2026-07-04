/**
 * @knotrust/proxy-stdio — `tools/list` interception & annotation capture
 * (P0-E5-T2; rulings R63–R67; architecture §4.2; ADR-0009).
 *
 * This module is the OBSERVATION side of the classifier seam `classifier.ts`
 * extends for this task: `createToolInventoryClassifier` builds a
 * {@link ClassifierHook} that NEVER alters routing (every message it sees
 * still passes through byte/shape-faithfully — see `proxy.ts`'s `relay()`)
 * but, for `tools/list` traffic, layers on an `observe` side effect that:
 *
 * 1. **Accumulates the full tool inventory across pagination.** A
 *    `tools/list` listing may span N pages (`nextCursor`); this hook tracks
 *    the outstanding request (by JSON-RPC `id`) to know whether each
 *    response is the FIRST page of a fresh listing (`cursor` was unset on
 *    the request) or a continuation, and only finalizes (diffs + persists)
 *    once a listing's last page (no `nextCursor`) arrives — so a tool
 *    defined only on page 2 still lands in the inventory (R63).
 * 2. **Seeds SUGGESTED tiers from annotations** (`seedTierEntriesFromAnnotations`)
 *    — conservatively, and marked `source: "annotation"`, per ADR-0009:
 *    annotations are SEEDS, NEVER TRUST. `mergeSeededTiers` is the
 *    companion function `knotrust init` (P0-E7-T1) reuses to fold seeds into
 *    real config WITHOUT ever overriding a pack/user entry (R65).
 * 3. **Detects tool-definition drift** against the PERSISTED baseline for
 *    this server (`diffToolInventory`), emitting an audit
 *    `tool_definition_changed` event per changed/added/removed tool when an
 *    `AuditSink` is supplied (the rug-pull tripwire — threat model PRD §13).
 *    After comparison, the new snapshot REPLACES the persisted baseline.
 *
 * ## Why this is all synchronous (no `async`/`Promise` anywhere in this file)
 *
 * `ClassifyResult.observe` is typed `(msg) => void`, not
 * `=> void | Promise<void>` (see `classifier.ts`) — deliberately. This
 * module's local-store I/O (`loadToolInventory`/`saveToolInventory`) uses
 * plain synchronous `node:fs` calls, exactly like `packages/store`'s
 * `audit-log.ts`/`grant-store.ts` (this repo's established convention for
 * small local-store reads/writes: synchronous, no async ceremony). Because
 * the relay invokes `observe` inline, in the same synchronous turn as
 * `relay()` itself (see `proxy.ts`), there is no reentrancy/interleaving
 * concern to worry about — Node's single-threaded event loop means no other
 * message can be classified while a `finalize()` call is running. A rare
 * multi-KB JSON read/write blocking the loop for a fraction of a
 * millisecond, once per completed `tools/list` listing, is an accepted,
 * deliberate tradeoff for the simplicity this buys.
 *
 * ## Persistence path (layout doc: `docs/03-engineering/local-store-layout.md`)
 *
 * `$KNOTRUST_HOME/servers/<server>/tool-inventory.json` — one JSON file per
 * logical MCP server name, holding the full `ToolInventory` map (every tool
 * this server has ever advertised, as of the last successful capture).
 * Written via write-to-temp-then-`rename` (same discipline as
 * `grant-store.ts`'s `atomicWriteFileSync`, duplicated here as a local
 * helper — `@knotrust/store` does not currently export a reusable
 * atomic-write util to import instead, matching R64's documented fallback).
 *
 * ## First-ever capture vs. drift (an explicit design choice)
 *
 * `diffToolInventory` treats "no persisted file existed at all yet" (`prior
 * === undefined`) as "nothing to compare against — emit no drift events,"
 * NOT as "every tool is newly added." The alternative (report every tool as
 * `tool_added` on a server's very first `knotrust` run) would flood the
 * audit log with pure noise on every fresh install rather than signal. Once
 * a baseline DOES exist, a tool present in the new capture but absent from
 * that baseline (or vice versa) is genuine drift and IS reported
 * (`changeKind: "added"` / `"removed"`).
 *
 * ## Audit event shape — folding `tool_added`/`tool_removed` into one type
 *
 * R66 asks for a documented choice between minting new `tool_added`/
 * `tool_removed` audit-event types or folding them into
 * `AuditEventType.TOOL_DEFINITION_CHANGED` with a change-kind field. This
 * module folds them in: every drift event this hook emits has
 * `type: "tool_definition_changed"` and a `changeKind` of `"added"` /
 * `"removed"` / `"changed"` inside its JSON-encoded `reason` (see
 * `emitToolDefinitionChangeEvent` below for the exact shape and why the
 * detail lives in `reason` rather than a new `AuditEvent` field). `tool_added`
 * is not a separate emitted lifecycle event — see `AuditEventType`
 * (`packages/store/src/audit-log.ts`), which already reserves
 * `TOOL_DEFINITION_CHANGED` for exactly this task.
 *
 * ## Encoding "what changed" into `AuditEvent.reason`
 *
 * `AuditEvent`'s schema (R37) is a fixed flat shape with no generic
 * "details" field — the closest fit is `reason?: string`, and existing call
 * sites already pack compact structured info into it (e.g.
 * `packages/grants/src/lifecycle.ts`'s `` reason: `kind=${claims.kind}` ``).
 * This hook packs a small JSON object into `reason`
 * (`{ server, changeKind, annotationChanges?, schemaHashChanged? }`) rather
 * than inventing a terser encoding, because the payload here is inherently
 * structured (a list of per-annotation-field old/new pairs) and JSON is the
 * least lossy, least bespoke way to carry that — while explicitly NEVER
 * including the raw `inputSchema` (R66: "NO raw schema in the audit line by
 * default" — only a boolean `schemaHashChanged` flag).
 */

import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import type { UntrustedToolAnnotations } from "@knotrust/core";
import { canonicalizeJcs, type ToolTierEntry } from "@knotrust/core";
import {
  AuditEventType,
  type AuditSink,
  computeArgsHash,
} from "@knotrust/store";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ClassifierHook, JsonRpcMessage } from "./classifier.js";

// ---------------------------------------------------------------------------
// $KNOTRUST_HOME resolution — deliberately duplicated (not imported), matching
// this repo's established convention for this exact tiny helper (see
// `packages/store/src/audit-log.ts`'s own header note on the same
// duplication from `grant-store.ts`/`keys.ts`). Read fresh on every call —
// never cached — so tests can point a whole hook at a fresh temp dir.
// ---------------------------------------------------------------------------

function resolveKnotrustHome(): string {
  const override = process.env.KNOTRUST_HOME;
  if (override !== undefined && override.trim() !== "") {
    return override;
  }
  return path.join(homedir(), ".knotrust");
}

// ---------------------------------------------------------------------------
// The inventory shape (R64)
// ---------------------------------------------------------------------------

/**
 * One tool's captured annotations + input-schema fingerprint, as of the last
 * successful `tools/list` capture. `annotations` reuses `@knotrust/core`'s
 * `UntrustedToolAnnotations` (`trusted: false` / `source: "server_advertised"`
 * literal fields) — the SAME shape a `DecisionRequest` carries — rather than
 * a parallel type, so the trust boundary (annotations are self-declared by
 * the server and MAY be a lie, ADR-0009) is visible at the type itself, not
 * just in a comment.
 */
export interface ToolInventoryEntry {
  annotations: UntrustedToolAnnotations;
  /** `"sha256:" + hex(SHA-256(utf8(canonicalizeJcs(inputSchema))))`, or the literal `"unavailable"` on a non-canonicalizable input (never throws — mirrors `computeArgsHash`'s contract, `packages/store/src/audit-log.ts`). */
  inputSchemaHash: string;
  /** Kept alongside the hash for regeneration/diff/inspection (`knotrust init`, forensic review). */
  inputSchema?: object;
}

/** Per-server tool inventory: every tool name this server has advertised, as of the last capture. Persisted at `$KNOTRUST_HOME/servers/<server>/tool-inventory.json`. */
export type ToolInventory = Record<string, ToolInventoryEntry>;

// ---------------------------------------------------------------------------
// Hashing (R64) — never throws, mirrors `computeArgsHash`'s contract.
// ---------------------------------------------------------------------------

/**
 * SHA-256 content hash of `inputSchema`'s canonical JSON form (via
 * `@knotrust/core`'s frozen `canonicalizeJcs`). Never throws: a schema that
 * cannot be canonicalized (unrealistic for JSON-Schema-shaped data that
 * arrived over the JSON-RPC wire, but a hostile/malformed server is exactly
 * the untrusted input this module must not crash on) yields the literal
 * string `"unavailable"` instead — mirroring
 * `packages/store/src/audit-log.ts`'s `computeArgsHash`.
 */
export function computeInputSchemaHash(inputSchema: unknown): string {
  let canonical: string;
  try {
    canonical = canonicalizeJcs(inputSchema ?? null);
  } catch {
    return "unavailable";
  }
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `sha256:${digest}`;
}

// ---------------------------------------------------------------------------
// Snapshot building
// ---------------------------------------------------------------------------

/**
 * Builds a fresh `ToolInventory` snapshot from a fully-accumulated tool list
 * (every page of one completed `tools/list` listing), stamping every entry
 * with the SAME `capturedAt` instant (the whole listing is one capture).
 * `tool.annotations` fields absent from the wire stay absent here too (never
 * defaulted to `false`) — "the server didn't say" and "the server said
 * false" are different facts, and `seedTierEntriesFromAnnotations` below
 * treats them differently (absent falls to the conservative
 * `unknownToolTier` default; explicit `false` still isn't `true`, so it
 * doesn't independently change the mapping either — but the distinction
 * matters for `diffToolInventory`, which must not report a no-op "changed
 * from undefined to false" drift that isn't really drift).
 */
export function buildToolInventorySnapshot(
  tools: readonly Tool[],
  capturedAt: string,
): ToolInventory {
  const inventory: ToolInventory = {};
  for (const tool of tools) {
    const hints = tool.annotations ?? {};
    inventory[tool.name] = {
      annotations: {
        trusted: false,
        source: "server_advertised",
        ...(hints.readOnlyHint !== undefined
          ? { readOnlyHint: hints.readOnlyHint }
          : {}),
        ...(hints.destructiveHint !== undefined
          ? { destructiveHint: hints.destructiveHint }
          : {}),
        ...(hints.idempotentHint !== undefined
          ? { idempotentHint: hints.idempotentHint }
          : {}),
        ...(hints.openWorldHint !== undefined
          ? { openWorldHint: hints.openWorldHint }
          : {}),
        capturedAt,
      },
      inputSchemaHash: computeInputSchemaHash(tool.inputSchema),
      inputSchema: tool.inputSchema as object,
    };
  }
  return inventory;
}

// ---------------------------------------------------------------------------
// Drift detection (R66)
// ---------------------------------------------------------------------------

export type ToolDefinitionChangeKind = "added" | "removed" | "changed";

const ANNOTATION_FIELDS = [
  "readOnlyHint",
  "destructiveHint",
  "idempotentHint",
  "openWorldHint",
] as const;

type AnnotationHintField = (typeof ANNOTATION_FIELDS)[number];

export interface AnnotationFieldChange {
  field: AnnotationHintField;
  old: boolean | undefined;
  new: boolean | undefined;
}

/** One drift finding — the shape both `diffToolInventory`'s return value and `emitToolDefinitionChangeEvent`'s input share. */
export interface ToolDefinitionChange {
  server: string;
  tool: string;
  changeKind: ToolDefinitionChangeKind;
  /** Present only for `changeKind: "changed"` entries that changed at least one hint. */
  annotationChanges?: AnnotationFieldChange[];
  /** Present (and `true`) only for `changeKind: "changed"` entries whose `inputSchemaHash` changed. Never carries the raw schema (R66). */
  schemaHashChanged?: boolean;
}

/**
 * Compares a freshly-captured `next` inventory against the previously
 * PERSISTED `prior` baseline for `serverName` (or `undefined` if this is the
 * very first capture ever recorded for this server — see this module's
 * header for why that yields no findings rather than "every tool added").
 * Pure: no I/O, no clock reads. Order: changed tools first (by
 * `Object.entries` iteration order of `next`), then removed tools (by
 * `Object.keys` iteration order of `prior`) — deterministic given
 * deterministic inputs, not documented as a stable public ordering contract
 * beyond that.
 */
export function diffToolInventory(
  serverName: string,
  prior: ToolInventory | undefined,
  next: ToolInventory,
): ToolDefinitionChange[] {
  if (prior === undefined) {
    return [];
  }
  const changes: ToolDefinitionChange[] = [];
  for (const [toolName, entry] of Object.entries(next)) {
    const priorEntry = prior[toolName];
    if (priorEntry === undefined) {
      changes.push({ server: serverName, tool: toolName, changeKind: "added" });
      continue;
    }
    const annotationChanges: AnnotationFieldChange[] = [];
    for (const field of ANNOTATION_FIELDS) {
      const oldVal = priorEntry.annotations[field];
      const newVal = entry.annotations[field];
      if (oldVal !== newVal) {
        annotationChanges.push({ field, old: oldVal, new: newVal });
      }
    }
    const schemaHashChanged =
      priorEntry.inputSchemaHash !== entry.inputSchemaHash;
    if (annotationChanges.length > 0 || schemaHashChanged) {
      changes.push({
        server: serverName,
        tool: toolName,
        changeKind: "changed",
        ...(annotationChanges.length > 0 ? { annotationChanges } : {}),
        ...(schemaHashChanged ? { schemaHashChanged: true } : {}),
      });
    }
  }
  for (const toolName of Object.keys(prior)) {
    if (!(toolName in next)) {
      changes.push({
        server: serverName,
        tool: toolName,
        changeKind: "removed",
      });
    }
  }
  return changes;
}

const STDIO_PROXY_AUDIT_SURFACE = "stdio_proxy";

/**
 * Appends one `tool_definition_changed` audit event for `change` (R66). Field
 * mapping onto `AuditEvent`'s fixed flat schema (`packages/store/src/audit-log.ts`,
 * R37) — chosen because this is a system-detected, non-decision event with
 * no human/agent principal to name:
 * - `surface: "stdio_proxy"` — the surface kind this always originates from.
 * - `subject`/`agent: "system"` — mirrors `audit-log.ts`'s own
 *   `AUDIT_RECOVERED` internal-event convention (no human/agent principal
 *   applies to a passively-observed server-side definition change).
 * - `tool` — the actual tool name (native field, exact fit).
 * - `argsHash: computeArgsHash(null)` — mirrors `GRANT_CREATED`/
 *   `GRANT_REVOKED`'s own precedent for non-call-argument-bearing events
 *   (`packages/grants/src/lifecycle.ts`/`revoke.ts`).
 * - `reason` — a compact JSON encoding of `{ server, changeKind,
 *   annotationChanges?, schemaHashChanged? }` (see this module's header for
 *   why `reason` and why JSON, and the explicit "no raw schema" guarantee).
 *
 * Does not catch `AuditUnavailableError` — that is the caller's
 * (`createToolInventoryClassifier`'s `finalize`) job, so a broken audit sink
 * degrades this ONE event (logged, not fatal) without ever blocking the
 * inventory baseline update.
 */
export function emitToolDefinitionChangeEvent(
  audit: AuditSink,
  change: ToolDefinitionChange,
): void {
  const detail: {
    server: string;
    changeKind: ToolDefinitionChangeKind;
    annotationChanges?: AnnotationFieldChange[];
    schemaHashChanged?: boolean;
  } = { server: change.server, changeKind: change.changeKind };
  if (change.annotationChanges !== undefined) {
    detail.annotationChanges = change.annotationChanges;
  }
  if (change.schemaHashChanged !== undefined) {
    detail.schemaHashChanged = change.schemaHashChanged;
  }
  audit.append({
    type: AuditEventType.TOOL_DEFINITION_CHANGED,
    surface: STDIO_PROXY_AUDIT_SURFACE,
    subject: "system",
    agent: "system",
    tool: change.tool,
    argsHash: computeArgsHash(null),
    reason: JSON.stringify(detail),
  });
}

// ---------------------------------------------------------------------------
// Tier seeding (R65) — the shared function `knotrust init` reuses.
// ---------------------------------------------------------------------------

/**
 * Seeds SUGGESTED tier entries from a captured inventory's annotations —
 * conservatively, per brief §C5 / ADR-0009 (annotations are seeds, NEVER
 * trust). Every returned entry has `source: "annotation"`; this function
 * NEVER writes tiers into real config itself — that is `mergeSeededTiers`'s
 * job, and merging is where pack/user precedence is actually enforced (R65).
 *
 * Mapping (brief §C5, conservative — destructive-looking never routes to
 * `"routine"`):
 * - `destructiveHint === true` (whether or not `readOnlyHint` is also
 *   `true` — see "conflicting" below) → `"sensitive"`.
 * - `readOnlyHint === true` and NOT `destructiveHint === true` →
 *   `"routine"`.
 * - neither hint `true` (both absent/`false`, or only `openWorldHint`/
 *   `idempotentHint` present) → `opts.unknownToolTier` (default
 *   `"sensitive"`, matching `TierPolicy.unknownToolTier`'s own default).
 * - **conflicting** (`readOnlyHint === true` AND `destructiveHint === true`
 *   at once — a self-contradiction only possible because these are
 *   self-declared, untrusted hints, i.e. exactly an "annotation lie"): takes
 *   the HIGHER of the two candidate tiers (`"sensitive"`), never the lower
 *   — a server that lies in a way that WOULD have suggested `"routine"`
 *   never gets the benefit of that lie.
 */
export function seedTierEntriesFromAnnotations(
  inventory: ToolInventory,
  opts: { unknownToolTier?: "sensitive" | "critical" } = {},
): Record<string, ToolTierEntry> {
  const unknownToolTier = opts.unknownToolTier ?? "sensitive";
  const seeded: Record<string, ToolTierEntry> = {};
  for (const [toolName, entry] of Object.entries(inventory)) {
    const { readOnlyHint, destructiveHint } = entry.annotations;
    const tier: ToolTierEntry["tier"] =
      destructiveHint === true
        ? "sensitive"
        : readOnlyHint === true
          ? "routine"
          : unknownToolTier;
    seeded[toolName] = { tier, source: "annotation" };
  }
  return seeded;
}

/**
 * Folds `seeded` annotation entries into `existing` config tools, WITHOUT
 * ever overriding a higher-authority entry (R65) — the function
 * `seedTierEntriesFromAnnotations`'s own doc-comment promises is
 * "merging ... is the precedence engine's + config's job," realized here.
 *
 * Precedence: a tool already claimed by a `"user"` or `"pack"` sourced entry
 * is left COMPLETELY untouched — an annotation-seeded suggestion (of any
 * tier, including `"routine"`) never overrides a pack/user entry (of any
 * tier, including `"critical"`), proven by this module's own test suite. A
 * tool with NO existing entry, or whose existing entry is ITSELF
 * `source: "annotation"` (a stale suggestion from an earlier capture, not a
 * higher-authority source), IS replaced by the fresher seed — re-running
 * `knotrust init` refreshes annotation-derived suggestions without that
 * counting as "overriding a higher-authority source," since annotation
 * never outranks annotation.
 *
 * Returns a brand-new object (never mutates `existing`), mirroring this
 * repo's `packages/store/src/config.ts` "R20: normalizers return fresh
 * objects" discipline even though this function does not itself live in
 * that package.
 */
export function mergeSeededTiers(
  existing: Record<string, ToolTierEntry> | undefined,
  seeded: Record<string, ToolTierEntry>,
): Record<string, ToolTierEntry> {
  const merged: Record<string, ToolTierEntry> = { ...(existing ?? {}) };
  for (const [toolName, seededEntry] of Object.entries(seeded)) {
    const current = merged[toolName];
    if (current === undefined || current.source === "annotation") {
      merged[toolName] = seededEntry;
    }
  }
  return merged;
}

// ---------------------------------------------------------------------------
// Persistence (R64) — `$KNOTRUST_HOME/servers/<server>/tool-inventory.json`,
// write-to-temp-then-rename (local copy of `grant-store.ts`'s discipline —
// `@knotrust/store` exports no reusable atomic-write util to import instead).
// ---------------------------------------------------------------------------

const SAFE_SERVER_NAME = /^[A-Za-z0-9._-]+$/;

/**
 * Guards the one caller-supplied string that becomes a filesystem path
 * segment — refuses path separators/traversal rather than silently
 * normalizing them away. The character class alone still allows the
 * dot-only segments `"."` / `".."` (dots are otherwise legitimate — e.g.
 * `"server.v2"`), and `path.join` gives those two exact strings special
 * "same dir"/"parent dir" meaning, so they are rejected explicitly here
 * (C-1). See `assertWithinServersDir` (used by `toolInventoryDirOf`) for
 * the second, `path.resolve`-based layer of defense-in-depth underneath
 * this one.
 */
function assertSafeServerName(serverName: string): void {
  if (
    !SAFE_SERVER_NAME.test(serverName) ||
    serverName === "." ||
    serverName === ".."
  ) {
    throw new Error(
      `knotrust/proxy-stdio: refusing unsafe server name ${JSON.stringify(serverName)} for tool-inventory path — expected to match ${SAFE_SERVER_NAME} and not be "." or ".."`,
    );
  }
}

/**
 * Belt-and-braces defense in depth alongside `assertSafeServerName`'s
 * character-class check (C-1): re-derives the `servers/` root and confirms
 * the directory `serverName` resolved to is still inside it, via
 * `path.resolve` rather than trusting the un-resolved string. Given
 * `assertSafeServerName` already runs first at every public entry point,
 * nothing reaches here today that trips this — it exists so a future loosening
 * of that regex (or a caller that forgets to call it) still can't make
 * `mkdirSync`/`chmodSync`/any file read-write below escape
 * `$KNOTRUST_HOME/servers/`. Throws rather than silently clamping, matching
 * `assertSafeServerName`'s own fail-closed discipline.
 */
function assertWithinServersDir(
  home: string,
  dir: string,
  serverName: string,
): void {
  const root = path.resolve(home, "servers") + path.sep;
  const resolved = path.resolve(dir);
  if (!resolved.startsWith(root)) {
    throw new Error(
      `knotrust/proxy-stdio: refusing tool-inventory directory for server ${JSON.stringify(serverName)} — resolved to ${resolved}, outside ${root}`,
    );
  }
}

function toolInventoryDirOf(home: string, serverName: string): string {
  const dir = path.join(home, "servers", serverName);
  assertWithinServersDir(home, dir, serverName);
  return dir;
}

function toolInventoryFilePath(home: string, serverName: string): string {
  return path.join(toolInventoryDirOf(home, serverName), "tool-inventory.json");
}

const DIR_MODE = 0o700;

/** Mirrors `grant-store.ts`'s `ensureSecureDir`: 0700, re-`chmod`'d even if the directory pre-existed with looser permissions. */
function ensureSecureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  chmodSync(dir, DIR_MODE);
}

function randomSuffix(): string {
  return Buffer.from(randomBytes(8)).toString("hex");
}

/** Write-to-temp-then-`rename`: same directory (rename is only atomic same-filesystem), per-call random suffix, atomic `rename()` over the destination. Local copy of `grant-store.ts`'s `atomicWriteFileSync` (R64 — see this module's header). */
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
    try {
      unlinkSync(tmpPath);
    } catch {
      // Intentionally swallowed — the renameSync failure below is what the
      // caller needs to see, not a cleanup failure layered on top of it.
    }
    throw err;
  }
}

/**
 * Loads the persisted `ToolInventory` baseline for `serverName`, or
 * `undefined` if none exists yet OR the file is unreadable/corrupt — a
 * damaged baseline is treated exactly like "no prior capture" (see this
 * module's header on why that yields no drift findings) rather than
 * crashing observation, which must never be fatal to the proxy.
 */
export function loadToolInventory(
  home: string,
  serverName: string,
): ToolInventory | undefined {
  assertSafeServerName(serverName);
  const filePath = toolInventoryFilePath(home, serverName);
  if (!existsSync(filePath)) {
    return undefined;
  }
  try {
    const raw = readFileSync(filePath, "utf8");
    return JSON.parse(raw) as ToolInventory;
  } catch {
    return undefined;
  }
}

/** Persists `inventory` as the new baseline for `serverName`, replacing whatever was there before (atomic — a reader never observes a torn/partial file). */
export function saveToolInventory(
  home: string,
  serverName: string,
  inventory: ToolInventory,
): void {
  assertSafeServerName(serverName);
  ensureSecureDir(toolInventoryDirOf(home, serverName));
  atomicWriteFileSync(
    toolInventoryFilePath(home, serverName),
    `${JSON.stringify(inventory, null, 2)}\n`,
  );
}

// ---------------------------------------------------------------------------
// The classifier hook (R63/R67) — wired via `createStdioProxy`'s
// `toolInventory` option (see `proxy.ts`).
// ---------------------------------------------------------------------------

export interface ToolInventoryHookOptions {
  /** Logical MCP server name — the `<server>` in the persisted path. */
  serverName: string;
  /** Defaults to `resolveKnotrustHome()`. */
  home?: string;
  /** Injected audit sink. Absent ⇒ drift detection still runs and the baseline still updates; it just logs nothing (R66 — documented seam). */
  audit?: AuditSink;
  /** Injectable clock (ms) for `annotations.capturedAt`. Defaults to `Date.now`. */
  nowMs?: () => number;
  /** Optional diagnostic sink for this hook's own best-effort failures (never the relayed traffic). */
  logger?: (line: string) => void;
}

/** True for a JSON-RPC REQUEST (has both `method` and `id`) — as opposed to a notification (`method`, no `id`) or a response (`id`, no `method`). */
function isRequestMessage(msg: JsonRpcMessage): msg is JsonRpcMessage & {
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
} {
  return (
    typeof msg === "object" && msg !== null && "method" in msg && "id" in msg
  );
}

/** True for a JSON-RPC RESPONSE (has `id`, no `method`) — either a result or an error response. */
function isResponseMessage(
  msg: JsonRpcMessage,
): msg is JsonRpcMessage & { id: string | number } {
  return (
    typeof msg === "object" && msg !== null && "id" in msg && !("method" in msg)
  );
}

/**
 * Builds the `tools/list`-observing {@link ClassifierHook} `createStdioProxy`
 * composes underneath its `onClassify` (or default) classifier when
 * `toolInventory` is supplied. Every message this hook sees still resolves
 * to `{ action: "passthrough" }` (it never denies/alters ANYTHING — R63);
 * for `tools/list` requests/responses it also does the bookkeeping/
 * `observe` work described in this module's header.
 *
 * Per-instance state (closed over, one instance per proxy/server): a map of
 * in-flight `tools/list` request ids → whether that request was a "fresh"
 * listing start (`cursor` unset) or a continuation, and an accumulator of
 * tools collected so far in the current in-progress listing. Both are plain
 * in-memory bookkeeping (no I/O) done directly in the returned function
 * (still "pure and synchronous" per `ClassifierHook`'s contract) — only the
 * finalize step (invoked from `observe`, once a listing's last page
 * arrives) touches disk.
 */
export function createToolInventoryClassifier(
  opts: ToolInventoryHookOptions,
): ClassifierHook {
  const serverName = opts.serverName;
  assertSafeServerName(serverName);
  const home = opts.home ?? resolveKnotrustHome();
  const nowMs = opts.nowMs ?? Date.now;
  const audit = opts.audit;
  const logger = opts.logger;

  const pendingListRequests = new Map<string | number, { fresh: boolean }>();
  // C-3: this accumulator holds pages for at most ONE tools/list pagination
  // sequence in flight at a time on this connection. Concurrent, OVERLAPPING
  // tools/list listings (interleaved fresh + continuation responses for two
  // requests at once) would cross-contaminate each other's pages here —
  // that isn't a real single-client MCP usage pattern (a client pages one
  // listing to completion before starting another), so it's accepted; a
  // partial/contaminated listing is never itself persisted regardless
  // (finalize only runs once a listing's last page, `nextCursor ===
  // undefined`, arrives).
  let accumulator: Tool[] = [];

  function finalize(tools: Tool[]): void {
    try {
      const capturedAt = new Date(nowMs()).toISOString();
      const next = buildToolInventorySnapshot(tools, capturedAt);
      const prior = loadToolInventory(home, serverName);
      const changes = diffToolInventory(serverName, prior, next);
      if (audit !== undefined) {
        for (const change of changes) {
          try {
            emitToolDefinitionChangeEvent(audit, change);
          } catch (error) {
            logger?.(
              `tool-inventory: failed to audit "${change.tool}" ${change.changeKind} on server "${serverName}": ${String(error)}`,
            );
          }
        }
        // C-2: force the drift signal(s) just emitted above durably to disk
        // BEFORE the baseline file below is overwritten — otherwise a crash
        // between a buffered audit append and the persisted baseline update
        // could lose the very tool_definition_changed event (the rug-pull
        // tripwire) this hook exists to guarantee survives. Best-effort like
        // the emits above: a broken/unavailable audit sink degrades only the
        // audit trail (logged), never blocks the baseline advance.
        try {
          audit.flush();
        } catch (error) {
          logger?.(
            `tool-inventory: audit flush failed before baseline advance on server "${serverName}": ${String(error)}`,
          );
        }
      }
      saveToolInventory(home, serverName, next);
    } catch (error) {
      logger?.(
        `tool-inventory: capture failed for server "${serverName}": ${String(error)}`,
      );
    }
  }

  return (msg, direction) => {
    if (direction === "client_to_server" && isRequestMessage(msg)) {
      if (msg.method === "tools/list") {
        const cursor = (msg.params as { cursor?: unknown } | undefined)?.cursor;
        pendingListRequests.set(msg.id, { fresh: cursor === undefined });
      }
      return { action: "passthrough" };
    }

    if (direction === "server_to_client" && isResponseMessage(msg)) {
      const pending = pendingListRequests.get(msg.id);
      if (pending === undefined) {
        return { action: "passthrough" };
      }
      pendingListRequests.delete(msg.id);
      if ("error" in msg) {
        // A failed tools/list carries nothing to capture — the pending
        // entry above is still cleared so it can never leak.
        return { action: "passthrough" };
      }
      const result = (msg as { result?: unknown }).result as
        | { tools?: Tool[]; nextCursor?: string }
        | undefined;
      const pageTools = result?.tools ?? [];
      const nextCursor = result?.nextCursor;
      return {
        action: "passthrough",
        observe: () => {
          if (pending.fresh) {
            // A fresh listing supersedes whatever partial accumulation was
            // in flight (e.g. an abandoned prior pagination sequence).
            accumulator = [];
          }
          accumulator.push(...pageTools);
          // C-4: the MCP SDK types `nextCursor` as an optional string, so
          // "no more pages" is properly signaled by OMITTING it. A
          // non-spec-compliant server that instead sends `null` or `""` to
          // mean the same thing would fail this strict `=== undefined`
          // check and this listing would never finalize (it just keeps
          // accumulating until a fresh listing resets it) — compliant
          // servers are unaffected.
          if (nextCursor === undefined) {
            const finalTools = accumulator;
            accumulator = [];
            finalize(finalTools);
          }
        },
      };
    }

    return { action: "passthrough" };
  };
}
