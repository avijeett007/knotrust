/**
 * knotrust CLI `init` — the orchestrator (P0-E7-T1, rulings R106–R110).
 *
 * Ties together every sibling module in this directory into the single
 * `knotrust init claude|codex` flow the plan's acceptance criteria describe:
 *
 *   1. Auto-detect + read the client's MCP config (`client-config.ts`, R106).
 *      A missing config or malformed JSON ABORTS here — before ANYTHING else
 *      runs — with no write anywhere (R108).
 *   2. Resolve WHICH servers to wrap: `--server <name>` (one), `--yes` (all),
 *      else an interactive `@clack/prompts` multiselect
 *      (`select-servers.ts`) — auto-detect over prompting, per the shadcn
 *      init playbook.
 *   3. Compute the rewrite (`rewriteClientConfig`, pure) and its unified diff
 *      against the ORIGINAL file text. `--dry-run`/`--diff`: print the diff,
 *      write NOTHING. Otherwise: atomic write (R108). Idempotent: nothing
 *      newly wrapped ⇒ no diff, no write, clean no-op message.
 *   4. For every server WRAPPED THIS RUN (not the idempotent no-op case):
 *      best-effort `tools/list` capture (`tool-capture.ts`) against the
 *      server's ORIGINAL (pre-wrap) command, seed suggested tiers
 *      (`config-generate.ts`'s `buildGeneratedConfig`), and diff/write a
 *      `knotrust.config.*` the exact same dry-run/atomic-write/confirm
 *      discipline as step 3 — R109.
 *
 * ## Injectable seams (`InitDeps`) — why, and what real tests use
 *
 * Every side-effecting seam this command touches beyond plain file I/O is
 * injectable, so `command.test.ts` never spawns a real interactive prompt or
 * a real child process by default:
 *
 *   - `clientConfigCandidates` — tests point candidates at temp-dir fixtures
 *     instead of real OS paths (R106; never touches a real user's Claude
 *     config).
 *   - `selectServers` — tests inject a deterministic fake instead of a real
 *     TTY prompt (which would hang in CI).
 *   - `confirmOverwrite` — same reasoning, for the "overwrite an existing
 *     knotrust.config?" confirmation (R109).
 *   - `captureToolInventory` — most command-level tests inject a fast,
 *     deterministic fake (the fixture client config's "server command" is
 *     rarely a real spawnable MCP server); ONE dedicated test in this
 *     package still exercises the REAL capture against
 *     `@knotrust/test-harness`'s fake server end-to-end, proving the
 *     production wiring (not just each unit in isolation).
 *
 * ## The `knotrust.config.ts` scope boundary (documented, not silently punted)
 *
 * An EXISTING `knotrust.config.ts` is never regenerated — `loadKnotrustConfig`
 * can EXECUTE it (c12's bundled jiti), but safely re-emitting arbitrary
 * hand-authored TypeScript (preserving whatever logic/comments/imports it
 * contains) is a different, much harder problem than re-serializing our OWN
 * `KnotrustConfig` object graph, which is exactly what `config-generate.ts`'s
 * serializers do for a `.yaml`/`.json` existing file (or a fresh one). This
 * command therefore skips config generation entirely (with a clear notice)
 * when the existing config resolves to a `.ts` file, rather than risk
 * clobbering hand-written logic.
 *
 * ## Config-generation resilience — never crash AFTER the client config is
 * already wrapped (fix round 1, P0-E7-T1 review)
 *
 * By the time step 4's `knotrust.config` generation phase starts, step 3's
 * client-config write has ALREADY happened (R108's atomic write). That write
 * is the critical, load-bearing half of `init` and must stand no matter what
 * happens next. `knotrust.config` generation is explicitly BEST-EFFORT
 * (R109) — including the EXISTING-config load this phase starts with, which
 * can throw if a hand-edited `knotrust.config.*` is broken (a schema
 * violation → `ConfigError`, or a genuine parse/syntax error `c12`/jiti
 * doesn't wrap — see `loadKnotrustConfig`'s own doc-comment). The whole
 * generation phase below (existing-config load, the tools/list capture loop,
 * the merge, and the final diff/write) therefore runs inside ONE try/catch:
 * any failure degrades to a clean, actionable stderr NOTICE via
 * {@link describeConfigGenerationFailure} and a clean exit (`0` — the client
 * wrap already succeeded) rather than an uncaught throw reaching `run.ts`
 * with a raw stack trace. `describeConfigGenerationFailure` distinguishes an
 * INVALID existing config (tell the user to fix it by hand) from every other
 * failure (generic best-effort notice — the config seeds itself on the next
 * successful run). Best-effort tools/list CAPTURE failure is a separate,
 * already-handled case (resolves to `undefined`, never throws — see the
 * outcomes loop and `buildSkeletonNote` below) and never reaches this catch.
 * `run.ts`'s `runCli` and `bin.ts` both also carry a top-level catch as
 * defense-in-depth, so that even a failure this module's own authors didn't
 * anticipate still degrades to a clean one-line `knotrust: <message>` instead
 * of a raw stack trace.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import type { Writable } from "node:stream";
import type { ToolInventory } from "@knotrust/proxy-stdio";
import { ConfigError, loadKnotrustConfig } from "@knotrust/store";
import type { InitArgs } from "./argv.js";
import {
  atomicWriteFileSync,
  type ClientConfigCandidate,
  ClientConfigNotFoundError,
  ClientConfigParseError,
  type ClientId,
  defaultClientConfigCandidates,
  detectIndent,
  MCP_SERVERS_KEY,
  partitionServers,
  readClientConfig,
  rewriteClientConfig,
  type ServerSelection,
  serializeClientConfig,
} from "./client-config.js";
import {
  buildGeneratedConfig,
  type CaptureOutcome,
  type ConfigFormat,
  configFileName,
  serializeGeneratedConfig,
} from "./config-generate.js";
import { unifiedDiff } from "./diff.js";
import {
  type ConfirmOverwrite,
  confirmOverwriteInteractively,
  type SelectServers,
  ServerSelectionCancelledError,
  selectServersInteractively,
} from "./select-servers.js";
import { captureToolInventory as realCaptureToolInventory } from "./tool-capture.js";

export interface InitIo {
  stdout: Writable;
  stderr: Writable;
  /** Directory searched for the Claude Code `.mcp.json` candidate and the generated `knotrust.config.*`. Defaults to `process.cwd()`; injected in tests. */
  cwd?: string;
}

type CaptureFn = (
  serverCommand: string[],
  opts: { env?: Record<string, string> },
) => Promise<ToolInventory | undefined>;

export interface InitDeps {
  clientConfigCandidates?: (
    clientId: ClientId,
    cwd: string,
  ) => ClientConfigCandidate[];
  selectServers?: SelectServers;
  confirmOverwrite?: ConfirmOverwrite;
  captureToolInventory?: CaptureFn;
  nowMs?: () => number;
  /** Passed through to the real `captureToolInventory` when no fake is injected. */
  captureTimeoutMs?: number;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function formatFromPath(sourceFile: string): ConfigFormat {
  if (sourceFile.endsWith(".json")) return "json";
  if (sourceFile.endsWith(".ts")) return "ts";
  return "yaml";
}

interface OriginalServerCommand {
  command: string[];
  env?: Record<string, string>;
}

/** Reads server `name`'s ORIGINAL (pre-wrap) `{command, args, env}` straight off the untouched `doc.parsed` — this is what gets spawned for the tools/list capture, never the knotrust-wrapped form. */
function originalServerCommand(
  parsed: Record<string, unknown>,
  name: string,
): OriginalServerCommand | undefined {
  const servers = parsed[MCP_SERVERS_KEY];
  if (typeof servers !== "object" || servers === null) return undefined;
  const entry = (servers as Record<string, unknown>)[name];
  if (typeof entry !== "object" || entry === null) return undefined;
  const record = entry as Record<string, unknown>;
  const command = record.command;
  if (typeof command !== "string") return undefined;
  const rawArgs = Array.isArray(record.args) ? record.args : [];
  const args = rawArgs.filter((a): a is string => typeof a === "string");
  const rawEnv = record.env;
  let env: Record<string, string> | undefined;
  if (typeof rawEnv === "object" && rawEnv !== null) {
    const entries = Object.entries(rawEnv as Record<string, unknown>).filter(
      (pair): pair is [string, string] => typeof pair[1] === "string",
    );
    if (entries.length > 0) env = Object.fromEntries(entries);
  }
  return { command: [command, ...args], ...(env !== undefined ? { env } : {}) };
}

function buildSkeletonNote(servers: readonly string[]): string {
  return [
    `knotrust: tools/list capture did not complete for: ${servers.join(", ")}`,
    "(best-effort — the server may need credentials/network access",
    "unavailable during `knotrust init`). Suggested tiers for these servers",
    "will be seeded the next time `knotrust init` runs successfully against",
    "them; until then every unlisted tool on these servers falls back to",
    "`unknownToolTier`.",
  ].join("\n");
}

/**
 * Renders any failure caught around the `knotrust.config` generation phase
 * into a clean, actionable message — see this file's "Config-generation
 * resilience" module header section for why this exists and what it
 * deliberately does NOT need to handle (best-effort capture failure, which
 * never throws).
 */
function describeConfigGenerationFailure(error: unknown): string {
  if (error instanceof ConfigError) {
    const detail = error.message.replace(/^knotrust:\s*/, "");
    return (
      `${detail} — fix the existing knotrust.config by hand, then re-run ` +
      "`knotrust init` to generate suggested tiers."
    );
  }
  const reason = error instanceof Error ? error.message : String(error);
  return (
    `${reason} — fix or create knotrust.config manually; it will be seeded ` +
    "automatically the next time `knotrust init` runs successfully."
  );
}

/**
 * Runs `knotrust init <claude|codex>` end to end. Returns the process exit
 * code (0 success/no-op/dry-run, 1 on any abort — malformed/missing client
 * config, unknown `--server` name, or a cancelled interactive prompt).
 * Never calls `process.exit` itself.
 */
export async function runInit(
  io: InitIo,
  args: InitArgs,
  deps: InitDeps = {},
): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const candidatesFn =
    deps.clientConfigCandidates ?? defaultClientConfigCandidates;
  const candidates = candidatesFn(args.client, cwd);

  let doc: ReturnType<typeof readClientConfig>;
  try {
    doc = readClientConfig(candidates);
  } catch (error) {
    if (
      error instanceof ClientConfigNotFoundError ||
      error instanceof ClientConfigParseError
    ) {
      write(io.stderr, `${error.message}\n`);
      return 1;
    }
    throw error;
  }

  const { wrappable } = partitionServers(doc.parsed);

  let selection: ServerSelection;
  if (args.server !== undefined) {
    selection = { mode: "one", server: args.server };
  } else if (args.yes || wrappable.length === 0) {
    // `--yes`, or nothing left to prompt about (already all wrapped / no
    // servers at all) — `rewriteClientConfig` resolves the latter to a clean
    // no-op regardless.
    selection = { mode: "all" };
  } else {
    const selector = deps.selectServers ?? selectServersInteractively;
    try {
      const chosen = await selector(wrappable, wrappable);
      selection = { mode: "subset", servers: chosen };
    } catch (error) {
      if (error instanceof ServerSelectionCancelledError) {
        write(io.stderr, `${error.message}\n`);
        return 1;
      }
      throw error;
    }
  }

  const plan = rewriteClientConfig(doc.parsed, selection);

  if (plan.unknownServer !== undefined) {
    write(
      io.stderr,
      `knotrust init: server "${plan.unknownServer}" not found in ${doc.path} (${MCP_SERVERS_KEY}). No changes written.\n`,
    );
    return 1;
  }

  write(io.stdout, `\n=== ${doc.kind} config: ${doc.path} ===\n`);
  if (!plan.changed) {
    write(
      io.stdout,
      plan.alreadyWrapped.length > 0
        ? `Already wrapped: ${plan.alreadyWrapped.join(", ")}. Nothing to do (idempotent no-op).\n`
        : "No wrappable MCP servers found. Nothing to do.\n",
    );
  } else {
    const indent = detectIndent(doc.raw);
    const newClientText = serializeClientConfig(plan.parsed, indent);
    const clientDiff = unifiedDiff(doc.raw, newClientText, {
      fromLabel: doc.path,
      toLabel: doc.path,
    });
    write(
      io.stdout,
      clientDiff.length > 0 ? clientDiff : "(no textual changes)\n",
    );
    if (args.dryRun) {
      write(io.stdout, "\n(dry run — no changes written)\n");
    } else {
      atomicWriteFileSync(doc.path, newClientText);
      write(io.stdout, `\nWrapped: ${plan.wrapped.join(", ")}.\n`);
    }
  }

  // ---- suggested-tier knotrust.config generation (R109) ----
  if (plan.wrapped.length === 0) {
    return 0;
  }

  // Everything from here down is best-effort (R109): the client config above
  // is ALREADY wrapped and that write must stand no matter what happens in
  // this phase. See this file's "Config-generation resilience" module header
  // section — ANY failure below (an invalid/unparseable existing config, a
  // capture-loop surprise, a write failure) degrades to a clean NOTICE and a
  // clean exit, never an uncaught throw.
  try {
    const existingLoaded = await loadKnotrustConfig({ cwd });
    const existingSourceFile = existingLoaded.sourceFile;
    if (existingSourceFile?.endsWith(".ts")) {
      write(
        io.stdout,
        `\n=== knotrust.config ===\nExisting ${existingSourceFile} is a TypeScript config — ` +
          "skipping suggested-tier regeneration (out of scope for automatic " +
          "regeneration of hand-authored TS; edit it directly).\n",
      );
      return 0;
    }
    const existingConfig =
      existingSourceFile !== undefined ? existingLoaded.config : undefined;

    const capture: CaptureFn =
      deps.captureToolInventory ??
      ((serverCommand, opts) =>
        realCaptureToolInventory(serverCommand, {
          ...(opts.env !== undefined ? { env: opts.env } : {}),
          ...(deps.captureTimeoutMs !== undefined
            ? { timeoutMs: deps.captureTimeoutMs }
            : {}),
          ...(deps.nowMs !== undefined ? { nowMs: deps.nowMs } : {}),
        }));

    const outcomes: CaptureOutcome[] = [];
    for (const serverName of plan.wrapped) {
      const original = originalServerCommand(doc.parsed, serverName);
      if (original === undefined) {
        outcomes.push({ serverName, inventory: undefined });
        continue;
      }
      const inventory = await capture(original.command, {
        ...(original.env !== undefined ? { env: original.env } : {}),
      });
      outcomes.push({ serverName, inventory });
    }

    const { config: newConfig, skeletonServers } = buildGeneratedConfig(
      existingConfig,
      outcomes,
    );

    const targetFormat =
      existingSourceFile !== undefined
        ? formatFromPath(existingSourceFile)
        : args.configFormat;
    const targetPath =
      existingSourceFile ?? path.join(cwd, configFileName(targetFormat));
    const oldConfigText =
      existingSourceFile !== undefined
        ? readFileSync(existingSourceFile, "utf8")
        : "";
    const skeletonNote =
      skeletonServers.length > 0
        ? buildSkeletonNote(skeletonServers)
        : undefined;
    const newConfigText = serializeGeneratedConfig(newConfig, targetFormat, {
      ...(skeletonNote !== undefined ? { skeletonNote } : {}),
    });
    const configDiff = unifiedDiff(oldConfigText, newConfigText, {
      fromLabel: targetPath,
      toLabel: targetPath,
    });

    write(
      io.stdout,
      `\n=== knotrust.config (suggested tiers): ${targetPath} ===\n`,
    );
    if (configDiff.length === 0) {
      write(io.stdout, "(no changes)\n");
      return 0;
    }
    write(io.stdout, configDiff);
    if (skeletonNote !== undefined) {
      write(io.stderr, `\n${skeletonNote}\n`);
    }

    if (args.dryRun) {
      write(io.stdout, "\n(dry run — no changes written)\n");
      return 0;
    }

    if (existingSourceFile !== undefined && !args.yes) {
      const confirm = deps.confirmOverwrite ?? confirmOverwriteInteractively;
      const proceed = await confirm();
      if (!proceed) {
        write(
          io.stdout,
          "Skipped — existing knotrust.config left untouched.\n",
        );
        return 0;
      }
    }

    atomicWriteFileSync(targetPath, newConfigText);
    write(io.stdout, `Wrote ${targetPath}.\n`);
    return 0;
  } catch (error) {
    write(
      io.stderr,
      `\nknotrust: wrapped the ${doc.kind} config successfully; could not ` +
        `generate/update knotrust.config: ${describeConfigGenerationFailure(error)}\n`,
    );
    return 0;
  }
}
