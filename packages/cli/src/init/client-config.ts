/**
 * knotrust CLI `init` — client MCP config read/rewrite/write (P0-E7-T1,
 * rulings R106–R108).
 *
 * ## Path resolution (R106)
 *
 * `defaultClientConfigCandidates(clientId, cwd)` returns the STANDARD path(s)
 * to auto-detect for a given `init claude|codex` target, in priority order —
 * "auto-detect over prompting" (shadcn init playbook): the first candidate
 * that EXISTS on disk wins; if none exist, `readClientConfig` throws
 * {@link ClientConfigNotFoundError} naming every path it looked for, rather
 * than inventing a file or guessing.
 *
 * `init claude` checks TWO surfaces sharing the exact same `mcpServers` JSON
 * shape — Claude Code's project-scoped `.mcp.json` (checked FIRST: its mere
 * presence in `cwd` is a deliberate, specific signal this directory is a
 * Claude Code project) and Claude Desktop's global
 * `claude_desktop_config.json` (checked second, as the fallback). This
 * priority order is a documented default, not user-overridable yet — no
 * `--client-scope` disambiguator exists in P0-E7-T1 (future work if two
 * candidates both existing and disagreeing turns out to matter in practice).
 *
 * `init codex` targets `~/.codex/config.toml` (the documented real path).
 * **Documented assumption (R106):** the exact Codex TOML grammar is not
 * implemented here — this module reads/writes that path's content as the
 * SAME JSON-shaped `{ mcpServers: { <name>: { command, args, env } } }` shape
 * Claude uses, exactly per R106's fallback ("if the exact Codex format is
 * uncertain, support the JSON-shaped `mcpServers` variant and note the
 * assumption"). A real Codex TOML file will therefore fail the JSON parse
 * step below and abort via {@link ClientConfigParseError} — safe (no partial
 * write) but not yet a real Codex integration; full TOML support is
 * out-of-scope follow-on work, not silently pretended away here.
 *
 * Every default path is also **env-overridable** (`KNOTRUST_CLAUDE_DESKTOP_CONFIG`
 * / `KNOTRUST_CLAUDE_CODE_CONFIG` / `KNOTRUST_CODEX_CONFIG`), mirroring this
 * repo's established `KNOTRUST_HOME` convention — this is what lets the
 * built-binary regression test (a real child process, R110) point `init` at
 * a fixture without touching a real user's files. Unit tests in THIS package
 * instead inject a custom candidate-resolving function outright (faster, no
 * env mutation, no risk of parallel-test interference) — see `command.ts`'s
 * `InitOptions.clientConfigCandidates`.
 *
 * ## The rewrite (R107)
 *
 * `rewriteClientConfig` is a PURE function: given the parsed client config and
 * a `ServerSelection`, it returns a brand-new parsed object with only the
 * selected `mcpServers[name]` entries replaced — every other top-level key,
 * every other server entry, is carried over UNTOUCHED (same object
 * reference where unchanged, though the caller re-serializes the whole tree
 * regardless). Wrapping replaces `{command, args}` with `{command:
 * "knotrust", args: ["--", <original command>, ...<original args>]}`;
 * `env` and any other per-entry keys are preserved verbatim. Idempotent:
 * `isWrappedEntry` recognizes an entry already routed through knotrust
 * (`command === "knotrust"` or its basename is, AND `args[0] === "--"`) and
 * such entries are never re-wrapped or offered as wrappable again.
 */

import { randomBytes } from "node:crypto";
import {
  existsSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

// ---------------------------------------------------------------------------
// Path resolution (R106)
// ---------------------------------------------------------------------------

export type ClientKind = "claude-desktop" | "claude-code" | "codex";
export type ClientId = "claude" | "codex";

export interface ClientConfigCandidate {
  kind: ClientKind;
  path: string;
}

function envOverride(name: string): string | undefined {
  const value = process.env[name];
  return value !== undefined && value.trim() !== "" ? value : undefined;
}

function defaultClaudeDesktopPath(): string {
  const override = envOverride("KNOTRUST_CLAUDE_DESKTOP_CONFIG");
  if (override !== undefined) return override;
  const home = homedir();
  if (process.platform === "darwin") {
    return path.join(
      home,
      "Library",
      "Application Support",
      "Claude",
      "claude_desktop_config.json",
    );
  }
  if (process.platform === "win32") {
    const appData = envOverride("APPDATA");
    const base = appData ?? path.join(home, "AppData", "Roaming");
    return path.join(base, "Claude", "claude_desktop_config.json");
  }
  // Linux and everything else: XDG-style convention (documented assumption —
  // Claude Desktop's own Linux distribution story is far less standardized
  // than macOS/Windows; R106 only names the macOS path explicitly).
  return path.join(home, ".config", "Claude", "claude_desktop_config.json");
}

function defaultClaudeCodeConfigPath(cwd: string): string {
  return (
    envOverride("KNOTRUST_CLAUDE_CODE_CONFIG") ?? path.join(cwd, ".mcp.json")
  );
}

function defaultCodexConfigPath(): string {
  return (
    envOverride("KNOTRUST_CODEX_CONFIG") ??
    path.join(homedir(), ".codex", "config.toml")
  );
}

/**
 * The standard candidate path(s) for `clientId`, in auto-detect priority
 * order (first EXISTING wins — see `readClientConfig`). See this module's
 * header for the "claude" two-surface order and the Codex format assumption.
 */
export function defaultClientConfigCandidates(
  clientId: ClientId,
  cwd: string,
): ClientConfigCandidate[] {
  if (clientId === "codex") {
    return [{ kind: "codex", path: defaultCodexConfigPath() }];
  }
  return [
    { kind: "claude-code", path: defaultClaudeCodeConfigPath(cwd) },
    { kind: "claude-desktop", path: defaultClaudeDesktopPath() },
  ];
}

// ---------------------------------------------------------------------------
// Read + parse (R106/R108 — malformed config never partially writes)
// ---------------------------------------------------------------------------

export class ClientConfigNotFoundError extends Error {
  readonly candidates: readonly ClientConfigCandidate[];

  constructor(candidates: readonly ClientConfigCandidate[]) {
    super(
      `knotrust: no client MCP config found. Expected one of:\n${candidates
        .map((c) => `  - ${c.path} (${c.kind})`)
        .join("\n")}`,
    );
    this.name = "ClientConfigNotFoundError";
    this.candidates = candidates;
  }
}

/** Thrown on invalid JSON (or a non-object top level) — the caller must abort with NO write (R108). */
export class ClientConfigParseError extends Error {
  readonly path: string;

  constructor(filePath: string, cause: unknown) {
    super(
      `knotrust: client config at ${filePath} is not valid JSON — aborting with no changes written (${String(cause)})`,
    );
    this.name = "ClientConfigParseError";
    this.path = filePath;
  }
}

export interface ClientConfigDoc {
  path: string;
  kind: ClientKind;
  /** The exact original file text — the diff/atomic-write "old" side. */
  raw: string;
  parsed: Record<string, unknown>;
}

export function findExistingCandidate(
  candidates: readonly ClientConfigCandidate[],
): ClientConfigCandidate | undefined {
  return candidates.find((c) => existsSync(c.path));
}

/** Reads and JSON-parses the first existing candidate. Throws {@link ClientConfigNotFoundError} / {@link ClientConfigParseError} rather than ever returning a partial/guessed result. */
export function readClientConfig(
  candidates: readonly ClientConfigCandidate[],
): ClientConfigDoc {
  const found = findExistingCandidate(candidates);
  if (found === undefined) {
    throw new ClientConfigNotFoundError(candidates);
  }
  const raw = readFileSync(found.path, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new ClientConfigParseError(found.path, error);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ClientConfigParseError(
      found.path,
      new Error("expected a JSON object at the top level"),
    );
  }
  return {
    path: found.path,
    kind: found.kind,
    raw,
    parsed: parsed as Record<string, unknown>,
  };
}

// ---------------------------------------------------------------------------
// Server-entry wrap/unwrap (R107)
// ---------------------------------------------------------------------------

export const MCP_SERVERS_KEY = "mcpServers";
export const KNOTRUST_COMMAND = "knotrust";

export interface ServerEntry {
  [key: string]: unknown;
}

function entryCommand(entry: ServerEntry): string | undefined {
  const command = entry.command;
  return typeof command === "string" ? command : undefined;
}

function entryArgs(entry: ServerEntry): unknown[] {
  const args = entry.args;
  return Array.isArray(args) ? args : [];
}

/** True when `entry` already routes through `knotrust -- <original command>`. */
export function isWrappedEntry(entry: ServerEntry): boolean {
  const command = entryCommand(entry);
  if (command === undefined) return false;
  const looksLikeKnotrust =
    command === KNOTRUST_COMMAND || path.basename(command) === KNOTRUST_COMMAND;
  if (!looksLikeKnotrust) return false;
  return entryArgs(entry)[0] === "--";
}

/** Replaces `{command, args}` with the knotrust-wrapped form (R107); every other key on `entry` (including `env`) is preserved verbatim. Never mutates `entry`. */
export function wrapEntry(entry: ServerEntry): ServerEntry {
  const originalCommand = entry.command;
  const originalArgs = entryArgs(entry);
  return {
    ...entry,
    command: KNOTRUST_COMMAND,
    args: ["--", originalCommand, ...originalArgs],
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function mcpServersOf(
  parsed: Record<string, unknown>,
): Record<string, unknown> {
  const raw = parsed[MCP_SERVERS_KEY];
  return isPlainObject(raw) ? raw : {};
}

export interface ServerPartition {
  /** Servers with a real string `command` that are NOT already wrapped — offerable to select/wrap this run. */
  wrappable: string[];
  /** Servers already routed through knotrust — always a no-op this run. */
  alreadyWrapped: string[];
}

/**
 * Splits every `mcpServers` entry into wrappable vs. already-wrapped. An
 * entry whose value isn't a plain object, or has no string `command`, is
 * silently excluded from BOTH lists (documented assumption: this module only
 * ever touches entries shaped like a real server declaration — an odd/
 * malformed nested entry is left alone rather than crashing the whole
 * command over one unrelated typo elsewhere in the file).
 */
export function partitionServers(
  parsed: Record<string, unknown>,
): ServerPartition {
  const wrappable: string[] = [];
  const alreadyWrapped: string[] = [];
  for (const [name, value] of Object.entries(mcpServersOf(parsed))) {
    if (!isPlainObject(value) || entryCommand(value) === undefined) continue;
    if (isWrappedEntry(value)) alreadyWrapped.push(name);
    else wrappable.push(name);
  }
  return { wrappable, alreadyWrapped };
}

export type ServerSelection =
  | { mode: "all" }
  | { mode: "one"; server: string }
  | { mode: "subset"; servers: string[] };

export interface RewritePlan {
  parsed: Record<string, unknown>;
  /** `false` iff nothing needed to change (nothing selected, or every selected server was already wrapped) — the idempotent no-op signal. */
  changed: boolean;
  wrapped: string[];
  alreadyWrapped: string[];
  /** Wrappable servers that existed but were NOT part of this run's selection. */
  notSelected: string[];
  /** Set when `selection.mode === "one"` named a server absent from `mcpServers` entirely. */
  unknownServer?: string;
}

/**
 * Pure: computes the rewritten client config for `selection` without
 * touching disk. Returns `changed: false` (same `parsed` reference back) when
 * there is genuinely nothing to do — the idempotent-second-run contract
 * (R107) and the "nothing to preview" dry-run case both key off this flag.
 */
export function rewriteClientConfig(
  parsed: Record<string, unknown>,
  selection: ServerSelection,
): RewritePlan {
  const { wrappable, alreadyWrapped } = partitionServers(parsed);

  let toWrap: string[];
  let unknownServer: string | undefined;
  if (selection.mode === "all") {
    toWrap = wrappable;
  } else if (selection.mode === "one") {
    if (wrappable.includes(selection.server)) {
      toWrap = [selection.server];
    } else {
      toWrap = [];
      if (!alreadyWrapped.includes(selection.server)) {
        unknownServer = selection.server;
      }
    }
  } else {
    toWrap = selection.servers.filter((s) => wrappable.includes(s));
  }

  const notSelected = wrappable.filter((s) => !toWrap.includes(s));

  if (toWrap.length === 0) {
    return {
      parsed,
      changed: false,
      wrapped: [],
      alreadyWrapped,
      notSelected,
      ...(unknownServer !== undefined ? { unknownServer } : {}),
    };
  }

  const servers = mcpServersOf(parsed);
  const newServers: Record<string, unknown> = { ...servers };
  for (const name of toWrap) {
    const entry = servers[name];
    if (isPlainObject(entry)) {
      newServers[name] = wrapEntry(entry);
    }
  }
  const newParsed = { ...parsed, [MCP_SERVERS_KEY]: newServers };
  return {
    parsed: newParsed,
    changed: true,
    wrapped: toWrap,
    alreadyWrapped,
    notSelected,
    ...(unknownServer !== undefined ? { unknownServer } : {}),
  };
}

// ---------------------------------------------------------------------------
// Serialization + atomic write
// ---------------------------------------------------------------------------

/** Sniffs the original file's indent (spaces or tab) from its first indented line, defaulting to 2 spaces — a best-effort nod to "preserve formatting as faithfully as JSON allows" (R107); exact byte-level whitespace of the original is not otherwise reproduced (comments don't exist in JSON to lose, but re-serialization is still a fresh `JSON.stringify`, not a text patch). */
export function detectIndent(raw: string): string | number {
  const match = /\n([ \t]+)\S/.exec(raw);
  const indent = match?.[1];
  if (indent === undefined) return 2;
  return indent.includes("\t") ? "\t" : indent.length;
}

export function serializeClientConfig(
  parsed: Record<string, unknown>,
  indent: string | number,
): string {
  return `${JSON.stringify(parsed, null, indent)}\n`;
}

function randomSuffix(): string {
  return Buffer.from(randomBytes(8)).toString("hex");
}

/**
 * Write-to-temp-then-`rename` in the SAME directory (rename is only atomic
 * same-filesystem) — a crash mid-write leaves either the OLD file intact or
 * the fully-written NEW one, never a torn/partial client config (R108: a
 * corrupted `claude_desktop_config.json` breaks the user's Claude). Local
 * copy of `packages/store/src/grant-store.ts`'s / `tool-inventory.ts`'s
 * identical helper — this repo's established convention for this exact tiny
 * primitive is to duplicate it locally rather than add a cross-package
 * export (see `tool-inventory.ts`'s own header note on the same point).
 */
export function atomicWriteFileSync(filePath: string, contents: string): void {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(
    dir,
    `${path.basename(filePath)}.${randomSuffix()}.tmp`,
  );
  writeFileSync(tmpPath, contents, "utf8");
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
