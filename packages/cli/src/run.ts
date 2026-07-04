/**
 * knotrust CLI runner (P0-E5-T1, ruling R61).
 *
 * Argv contract: `knotrust [subcommand …] -- <server command> [args…]`.
 * Everything AFTER the first `--` is the real MCP server command to spawn and
 * proxy; everything before it is a knotrust subcommand.
 *
 * - `knotrust -- node server.js` → run the stdio proxy end-to-end
 *   (P0-E5-T1: the FLAGSHIP surface; this is what actually wraps a server).
 * - `knotrust init claude|codex` (no `--`) → routes to `./init/command.js`'s
 *   `runInit` (P0-E7-T1, rulings R106–R110): auto-detect + rewrite the
 *   client's MCP config to route the chosen servers through `knotrust --`,
 *   then best-effort generate a suggested-tier `knotrust.config.*`. Argv
 *   after the `"init"` token is parsed by `./init/argv.js`'s `parseInitArgs`
 *   (a usage/parse error here returns exit code 2, same as any other bad
 *   invocation below — never reaches `runInit` at all).
 * - `knotrust grant` / `knotrust grant list` / `knotrust revoke` (no `--`) →
 *   P0-E7-T2: mint/list/revoke durable grants against the real grant store +
 *   keystore + decider substrate (`grant/argv.js` parses argv;
 *   `grant/mint-command.js`, `grant/list-command.js`, `grant/revoke-
 *   command.js` compose the real `@knotrust/grants`/`@knotrust/store`
 *   primitives).
 * - `knotrust add pack <path>` (no `--`) → P0-E7-T3 (rulings R117–R121):
 *   applies a LOCAL, unsigned YAML policy pack into `knotrust.config.*`,
 *   previewing a human-readable tier diff before any write (Homebrew
 *   tap-trust lesson — never silent-apply) and requiring confirmation unless
 *   `--yes`. `add/argv.js` parses argv as a `<kind> <ref>` dispatch (only
 *   `"pack"` implemented in P0 — the GitHub registry + signature/hash
 *   verification for a fetched `add pack <name>`, and `add pdp cedar`,
 *   arrive in P1 as new `<kind>` branches, not a redesign of this surface);
 *   `add/pack-command.js` composes `add/pack-schema.js` (load + validate)
 *   and `add/pack-merge.js` (the precedence-respecting merge: pack overrides
 *   an annotation-seeded entry, never a user's explicit entry).
 * - `knotrust audit list|tail|query|verify` (no `--`) → P0-E4-T4 (rulings
 *   R122–R125): the human/forensic window over the hash-chained JSONL audit
 *   log (`@knotrust/store`'s `audit-log.ts`, P0-E4-T3). `audit/argv.js`
 *   parses the `<sub> [flags]` dispatch; `audit/tail-command.js` implements
 *   BOTH `list` and `tail` (deliberate aliases — see that file's own header),
 *   `audit/query-command.js` implements the filtered `query`, and
 *   `audit/verify-command.js` implements chain-integrity `verify`. All four
 *   read via `@knotrust/store`'s LOCK-FREE `streamAuditEvents`/
 *   `verifyAuditChain` exports — never `AuditSink`/`createAuditLog` — so a
 *   forensic read never contends with a live proxy process's writer lock.
 *   `approvals` remains stubbed below; it lands in its own later P0-E7-Tx
 *   task.
 *
 * The proxy plumbing lives in `@knotrust/proxy-stdio` (bundled into this CLI at
 * publish time via tsup `noExternal`, ADR-0016); this module only parses argv
 * and manages the process-level lifecycle (signals, exit code). It is split out
 * of `bin.ts` so it is unit-testable with injected streams (no real process
 * stdio required) — `bin.ts` is the thin `process`-bound wrapper.
 *
 * ## Zero-config is now OBSERVED + AUDITED, never a silent lie (P0-E5-T3 fix
 * round 1, Must-fix 1)
 *
 * Before this fix, a zero-config `knotrust -- <server>` run wired NOTHING —
 * no observer, no audit, pure passthrough — yet printed a notice claiming
 * "observe-only" mode, which was false: nothing was ever observed. That is
 * a real problem in a tool whose entire promise is visibility. This module
 * now ACTUALLY wires the E5-T2 tool-inventory observer plus a real audit
 * sink on the zero-config path (`buildZeroConfigObserver` below), so the
 * notice is true: tool-definition drift IS captured and audited from the
 * very first run. `tools/call` still stays pure passthrough on this path —
 * no enforcement hook is wired — because enforce-by-default is a deliberate
 * config-gated seam (R73; E7/E9), not something a first run should silently
 * opt a user into. See `RunBundle`/`resolveRunBundle` for the composition;
 * the config-PRESENT path (`buildEnforcement`, `enforcement.ts`) is
 * unchanged by this fix.
 *
 * ## Fail-closed crash & error behavior (P0-E5-T5; rulings R82, R83)
 *
 * `runProxy` is also where the two process-level halves of the fail-closed
 * doctrine live (`docs/03-engineering/failure-modes.md` has the full table):
 *
 *   - **R82(ii) exit-code mirroring** — `onClose`'s `reason` is what this
 *     module keys the final exit code off: `"child_exit"` (the wrapped
 *     server exited/crashed WITHOUT this proxy asking it to — `proxy.ts`'s
 *     own R82 in-flight bookkeeping already made sure no client request was
 *     left hanging) is a FAILURE and exits non-zero; `"client_eof"`/
 *     `"stopped"` are deliberate, requested shutdowns and exit `0`. The
 *     official SDK's `StdioClientTransport` does not surface the child's
 *     actual numeric exit code through its `onclose` callback (verified by
 *     reading the installed SDK source — the `child_process` `'close'`
 *     event's `code` argument is received and discarded), so this is a
 *     fixed non-zero code, not literal exit-code mirroring; see the task
 *     report for the full rationale.
 *   - **R83 fatal-error handlers** — `uncaughtException`/`unhandledRejection`
 *     on the process are installed alongside the existing SIGTERM/SIGINT
 *     propagation (same `io.installSignalHandlers` gate, for the identical
 *     reason: a test running inside a shared vitest worker process must
 *     never install a REAL global process-error handler that outlives the
 *     test). On any of the four (SIGTERM, SIGINT, uncaughtException,
 *     unhandledRejection), the child is terminated (SIGTERM→SIGKILL
 *     escalation, `proxy.ts`'s existing R60 ladder) BEFORE this process
 *     exits — a proxy that dies must take its child with it, never leaving
 *     an ungoverned server outliving its governor.
 */

import path from "node:path";
import type { Readable, Writable } from "node:stream";
import { resolveKnotrustHome } from "@knotrust/grants";
import {
  type CreateStdioProxyOptions,
  createStdioProxy,
} from "@knotrust/proxy-stdio";
import { createAuditLog, loadKnotrustConfig } from "@knotrust/store";
import { parseAddArgs } from "./add/argv.js";
import { runAddPack } from "./add/pack-command.js";
import { parseAuditArgs } from "./audit/argv.js";
import { runAuditQuery } from "./audit/query-command.js";
import { runAuditTail } from "./audit/tail-command.js";
import { runAuditVerify } from "./audit/verify-command.js";
import { buildEnforcement, type EnforcementBundle } from "./enforcement.js";
import {
  parseGrantListArgs,
  parseGrantMintArgs,
  parseRevokeArgs,
} from "./grant/argv.js";
import { runGrantList } from "./grant/list-command.js";
import { runGrantMint } from "./grant/mint-command.js";
import { runRevoke } from "./grant/revoke-command.js";
import { INIT_USAGE, parseInitArgs } from "./init/argv.js";
import { runInit } from "./init/command.js";

/** Injected process I/O + signal surface, so the runner is testable off the real process. */
export interface CliIo {
  stdin: Readable;
  stdout: Writable;
  stderr: Writable;
  /**
   * Gates installing REAL, process-global handlers: SIGTERM/SIGINT
   * propagation to the child, AND (P0-E5-T5, R83) `uncaughtException`/
   * `unhandledRejection` fatal-error handlers. Defaults to `true`
   * (production). Tests set this `false` so a shared vitest worker process
   * never accumulates global process-error listeners across test files.
   */
  installSignalHandlers?: boolean;
  /** Directory searched for `knotrust.config.*` (R73). Defaults to `process.cwd()`; injected in tests. */
  cwd?: string;
}

export interface ParsedArgs {
  /** knotrust subcommand tokens (before `--`). */
  subcommand: string[];
  /** The server command argv (after `--`), or `undefined` if no `--` was given. */
  serverCommand: string[] | undefined;
}

/** Split argv on the FIRST `--`: before → subcommand, after → server command. */
export function parseArgs(argv: string[]): ParsedArgs {
  const sep = argv.indexOf("--");
  if (sep === -1) {
    return { subcommand: argv, serverCommand: undefined };
  }
  return {
    subcommand: argv.slice(0, sep),
    serverCommand: argv.slice(sep + 1),
  };
}

const USAGE =
  "usage: knotrust -- <server command> [args...]   (e.g. knotrust -- node server.js)";

/**
 * Run the CLI. Returns the process exit code. Never calls `process.exit` itself
 * (the `bin.ts` wrapper does), so it is safe to await in tests.
 *
 * ## Top-level defense-in-depth (fix round 1, P0-E7-T1 review)
 *
 * This wraps `dispatchCli` in one more try/catch, ON TOP of whatever narrower
 * handling already exists inside it (`resolveRunBundle`'s own catch below;
 * `init/command.ts`'s `runInit` best-effort config-generation guard around
 * its own post-client-write phase). Every code path this CLI has today is
 * already expected to resolve cleanly rather than throw — but "already
 * expected to" is exactly the assumption that let the `runInit` bug this
 * fix closes ship in the first place. This catch is the backstop for
 * whatever the next one turns out to be: NOTHING this CLI does should ever
 * put a raw Node stack trace in front of a user — any error that slips past
 * every narrower handler still degrades to a single clean `knotrust:
 * <message>` line on stderr and exit code `1`, never a stack dump. `bin.ts`
 * carries a second, outermost copy of this same guard, purely as a second
 * layer (this function is what actually gets exercised by tests, since
 * `bin.ts` binds to the real, untestable process streams).
 */
export async function runCli(argv: string[], io: CliIo): Promise<number> {
  try {
    return await dispatchCli(argv, io);
  } catch (error) {
    io.stderr.write(
      `knotrust: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return 1;
  }
}

async function dispatchCli(argv: string[], io: CliIo): Promise<number> {
  const { subcommand, serverCommand } = parseArgs(argv);

  if (serverCommand === undefined) {
    // No `--`: this is a subcommand invocation.
    const name = subcommand[0];

    // `init claude|codex` — P0-E7-T1. `grant`/`grant list`/`revoke` — P0-E7-T2.
    // `add pack <path>` — P0-E7-T3 (below). Every other subcommand (audit/
    // approvals) stays stubbed; they land in their own later P0-E7-Tx tasks.
    if (name === "init") {
      const parsed = parseInitArgs(subcommand.slice(1));
      if (!parsed.ok) {
        io.stderr.write(`${parsed.error}\n`);
        return 2;
      }
      return runInit(
        {
          stdout: io.stdout,
          stderr: io.stderr,
          ...(io.cwd !== undefined ? { cwd: io.cwd } : {}),
        },
        parsed.args,
      );
    }

    if (name === "grant") {
      const rest = subcommand.slice(1);
      if (rest[0] === "list") {
        const parsed = parseGrantListArgs(rest.slice(1));
        if (!parsed.ok) {
          io.stderr.write(`${parsed.error}\n`);
          return 2;
        }
        return runGrantList(
          { stdout: io.stdout, stderr: io.stderr },
          parsed.args,
        );
      }
      const parsed = parseGrantMintArgs(rest);
      if (!parsed.ok) {
        io.stderr.write(`${parsed.error}\n`);
        return 2;
      }
      return runGrantMint(
        {
          stdout: io.stdout,
          stderr: io.stderr,
          ...(io.cwd !== undefined ? { cwd: io.cwd } : {}),
        },
        parsed.args,
      );
    }

    if (name === "revoke") {
      const parsed = parseRevokeArgs(subcommand.slice(1));
      if (!parsed.ok) {
        io.stderr.write(`${parsed.error}\n`);
        return 2;
      }
      return runRevoke({ stdout: io.stdout, stderr: io.stderr }, parsed.args);
    }

    if (name === "add") {
      const parsed = parseAddArgs(subcommand.slice(1));
      if (!parsed.ok) {
        io.stderr.write(`${parsed.error}\n`);
        return 2;
      }
      // Only `parsed.kind === "pack"` exists in P0 (R121) — `parseAddArgs`
      // itself already rejects every other `<kind>` as a usage error, so
      // this is the sole branch today; a P1 `<kind>` adds a sibling branch
      // here, never a redesign of this dispatch.
      return runAddPack(
        {
          stdout: io.stdout,
          stderr: io.stderr,
          ...(io.cwd !== undefined ? { cwd: io.cwd } : {}),
        },
        parsed.args,
      );
    }

    if (name === "audit") {
      const parsed = parseAuditArgs(subcommand.slice(1));
      if (!parsed.ok) {
        io.stderr.write(`${parsed.error}\n`);
        return 2;
      }
      const cmd = parsed.command;
      const cmdIo = { stdout: io.stdout, stderr: io.stderr };
      // `list` and `tail` are deliberate aliases dispatched to the SAME
      // implementation (see `audit/argv.ts`'s and `audit/render.ts`'s own
      // module headers for why).
      if (cmd.kind === "list" || cmd.kind === "tail") {
        return runAuditTail(cmdIo, cmd.args);
      }
      if (cmd.kind === "query") {
        return runAuditQuery(cmdIo, cmd.args);
      }
      return runAuditVerify(cmdIo);
    }

    io.stderr.write(
      name === undefined || name.length === 0
        ? `knotrust: no command given.\n${USAGE}\n`
        : `knotrust: subcommand "${name}" is not implemented yet ` +
            `(approvals arrives in P0-E7-Tx; init: ${INIT_USAGE}).\n${USAGE}\n`,
    );
    return 2;
  }

  if (serverCommand.length === 0) {
    io.stderr.write(`knotrust: nothing after "--" to run.\n${USAGE}\n`);
    return 2;
  }

  // R73: enable enforcement when a config is present; ZERO-CONFIG wires the
  // E5-T2 observer + audit instead (this fix — see module header). Either
  // branch failing to load/wire is fatal (fail closed) — never a silent drop
  // to passthrough with a notice the user would wrongly believe is honest.
  let bundle: RunBundle;
  try {
    bundle = await resolveRunBundle(io, serverCommand);
  } catch (error) {
    io.stderr.write(
      `knotrust: refusing to run — failed to initialize: ${String(error)}\n`,
    );
    return 1;
  }

  return runProxy(serverCommand, io, bundle);
}

/**
 * What `runProxy` wires into `createStdioProxy` for this invocation. Exactly
 * one of `enforce`/`toolInventory` is ever populated by `resolveRunBundle`:
 *
 * - Config present → `enforce` (full R73 enforcement, `buildEnforcement`,
 *   unchanged by this fix).
 * - Zero-config → `toolInventory` (this fix, Must-fix 1): a REAL tool-
 *   inventory observer + audit sink, so `tools/list` drift is actually
 *   captured — but no `enforce` hook, so `tools/call` stays pure passthrough.
 */
interface RunBundle {
  enforce?: EnforcementBundle["enforce"];
  toolInventory?: CreateStdioProxyOptions["toolInventory"];
  /**
   * Present only on the config-enforcement path (P0-E6-T2) — wires the
   * real proxy's client-facing send into the block-and-wait channel's
   * heartbeat seam once the proxy exists. See `enforcement.ts`'s module
   * header ("the sendNotification chicken-and-egg").
   */
  bindProxySender?: EnforcementBundle["bindProxySender"];
  /**
   * Present only on the config-enforcement path (P0-E6-T4, R105) — the
   * `notifications/cancelled` -> pending-approval cancellation classifier.
   * Threaded straight through to `createStdioProxy`'s `onClassify` option.
   */
  onClassify?: EnforcementBundle["onClassify"];
  /**
   * Releases whatever this bundle opened (an audit writer lock, at minimum;
   * on the enforcement path, also a bounded OTel exporter shutdown — P0-E8-T1,
   * see `EnforcementBundle["close"]`'s own doc-comment). Safe to call once, on
   * teardown. ASYNC: `runProxy`'s `onClose` handler awaits this before
   * resolving the process exit code, so a configured OTel collector gets a
   * real chance to receive the run's last spans — see `enforcement.ts`.
   */
  close(): Promise<void>;
}

/**
 * Loads `knotrust.config.*` from `io.cwd` and builds this run's `RunBundle`:
 *
 * - A real config FILE found → full R73 enforcement (`buildEnforcement`,
 *   unchanged by this fix): `tools/call` is gated by the decider.
 * - No config file → the ZERO-CONFIG path (this fix, Must-fix 1):
 *   `tools/call` stays pure passthrough (no `enforce` hook — enforce-by-
 *   default is a deliberate config-gated seam, R73/E7/E9, not something a
 *   first run should silently opt a user into), but `buildZeroConfigObserver`
 *   wires the E5-T2 tool-inventory observer + a real audit sink, so the
 *   printed notice — "tool inventory + drift detection are active and
 *   audited" — is actually true, not the previous version's false "observe-
 *   only" claim over a wire with nothing listening on it.
 *
 * Either branch may throw (config load/wire failure, or audit-sink
 * construction failure — e.g. lock contention from a concurrent `knotrust`
 * run against the same `$KNOTRUST_HOME`) — the caller treats that as fatal
 * (fail closed) rather than silently falling back to a passthrough the
 * printed notice would then misdescribe.
 */
async function resolveRunBundle(
  io: CliIo,
  serverCommand: string[],
): Promise<RunBundle> {
  const loaded = await loadKnotrustConfig(
    io.cwd !== undefined ? { cwd: io.cwd } : {},
  );
  if (loaded.sourceFile === undefined) {
    return buildZeroConfigObserver(io, serverCommand);
  }
  io.stderr.write(
    `knotrust: enforcement enabled (config: ${loaded.sourceFile}).\n`,
  );
  const enforcement = await buildEnforcement(loaded.config, {
    stderrWrite: (chunk) => {
      io.stderr.write(chunk);
    },
  });
  return {
    enforce: enforcement.enforce,
    bindProxySender: enforcement.bindProxySender,
    onClassify: enforcement.onClassify,
    close: enforcement.close,
  };
}

/**
 * Fixed fallback server name for the zero-config observer, used whenever a
 * stable name can't be safely derived from the server command (see
 * `deriveZeroConfigServerName`). Same literal `enforcement.ts`'s
 * `resolveServerName` falls back to for an unconfigured server, so both
 * paths degrade identically.
 */
const FALLBACK_SERVER_NAME = "default";

/**
 * Duplicated, read-only copy of `@knotrust/proxy-stdio`'s tool-inventory
 * safe-server-name character class (`tool-inventory.ts`'s
 * `assertSafeServerName`, which is not exported from that package — this
 * repo's established convention for a tiny path-safety predicate is to
 * duplicate it locally rather than add a cross-package export for one
 * boolean check; see `@knotrust/store`'s two independent
 * `resolveKnotrustHome` copies for the same convention). Keep in sync with
 * `packages/proxy-stdio/src/tool-inventory.ts`'s `SAFE_SERVER_NAME`. Used
 * here purely as a pre-flight check so `createStdioProxy` never throws on
 * an unsafe derived name — the E5-T2 guard would reject it anyway, but
 * failing the whole run over a cosmetic naming choice would be a
 * disproportionate response to something this module can trivially avoid.
 */
const SAFE_SERVER_NAME = /^[A-Za-z0-9._-]+$/;

function isSafeServerName(name: string): boolean {
  return SAFE_SERVER_NAME.test(name) && name !== "." && name !== "..";
}

/**
 * Derives a STABLE `serverName` for the zero-config observer (this fix):
 * repeated `knotrust -- <same server>` runs must share one persisted
 * tool-inventory baseline for drift detection to mean anything, so this
 * can NOT be a fresh id every invocation. Mirrors `enforcement.ts`'s
 * `resolveServerName` override precedence:
 *
 *   1. `KNOTRUST_SERVER` env override (the SAME override the config-present
 *      path honors) — used AS-IS, exactly like `resolveServerName`, since it
 *      is already meant to BE a server name, not a path to derive one from.
 *   2. The basename of the last non-flag argv token (typically the real
 *      script/module/package target — e.g. `["node", "server.js"]` →
 *      `"server.js"`), falling back to the basename of `serverCommand[0]`
 *      (the executable) when every token looks like a flag.
 *
 * Either candidate is then checked against `isSafeServerName`; anything that
 * fails it (path separators, a bare `.`/`..`, an empty string, a scoped
 * package name's `@`/`/`, …) falls back to `FALLBACK_SERVER_NAME` rather
 * than letting `createStdioProxy` throw — never crash the flagship
 * zero-config path over a naming edge case.
 */
function deriveZeroConfigServerName(serverCommand: string[]): string {
  const override = process.env.KNOTRUST_SERVER;
  if (override !== undefined && override.trim() !== "") {
    return isSafeServerName(override) ? override : FALLBACK_SERVER_NAME;
  }
  const lastNonFlag = [...serverCommand]
    .reverse()
    .find((token) => !token.startsWith("-"));
  const candidate = lastNonFlag ?? serverCommand[0] ?? FALLBACK_SERVER_NAME;
  const base = path.basename(candidate);
  return isSafeServerName(base) ? base : FALLBACK_SERVER_NAME;
}

/**
 * Builds the zero-config `RunBundle` (this fix, Must-fix 1): a real
 * `AuditSink` at `$KNOTRUST_HOME/audit` plus the `serverName` the E5-T2
 * tool-inventory observer will persist
 * `$KNOTRUST_HOME/servers/<serverName>/tool-inventory.json` under (see
 * `deriveZeroConfigServerName`). No `enforce` hook — `tools/call` stays pure
 * passthrough; enabling enforcement by default is `knotrust init`'s job
 * (R73), not a zero-config default. The printed notice is the ONE place
 * this CLI tells the user what is/isn't happening — keep it in sync with
 * what this function actually wires: tool inventory capture + drift
 * detection ARE active and audited; `tools/call` is NOT gated or enforced.
 */
function buildZeroConfigObserver(
  io: CliIo,
  serverCommand: string[],
): RunBundle {
  const home = resolveKnotrustHome();
  const serverName = deriveZeroConfigServerName(serverCommand);
  const audit = createAuditLog({ home, nowEpochMs: () => Date.now() });
  io.stderr.write(
    "knotrust: no knotrust.config found — tool inventory capture and drift " +
      `detection are ACTIVE and audited (server "${serverName}"); tools/call ` +
      "is NOT gated or enforced (pure passthrough). Run `knotrust init` to " +
      "enable enforcement.\n",
  );
  return {
    toolInventory: { home, audit, serverName },
    // `async` purely to satisfy `RunBundle["close"]`'s now-`Promise<void>`
    // signature (P0-E8-T1 — see that interface's own doc-comment); this
    // zero-config path has no OTel exporter to await (that only exists on
    // the enforcement path, `buildEnforcement`), so this resolves exactly as
    // fast as the old synchronous version did.
    close: async () => {
      try {
        audit.close();
      } catch {
        // best-effort on shutdown — releasing the writer lock is the goal,
        // same discipline as `enforcement.ts`'s `buildEnforcement().close()`.
      }
    },
  };
}

/** Spawn + relay the server command, resolving with the exit code once torn down. */
function runProxy(
  serverCommand: string[],
  io: CliIo,
  bundle: RunBundle,
): Promise<number> {
  return new Promise<number>((resolve) => {
    let settled = false;
    const finish = (code: number): void => {
      if (!settled) {
        settled = true;
        resolve(code);
      }
    };

    // R83: once a fatal error has been observed, EVERY path that resolves
    // the exit code must honor that failure — set synchronously, BEFORE
    // `proxy.stop()` is even called, so that `onClose` firing (as part of
    // `stop()`'s own teardown, possibly before `onFatal`'s own `.finally`
    // below runs) already sees it and reports the failing code, rather than
    // racing `onClose`'s reason-based default (`"stopped"` → 0) to resolve
    // first.
    let fatalCode: number | undefined;

    const proxy = createStdioProxy({
      serverCommand,
      stdin: io.stdin,
      stdout: io.stdout,
      stderr: io.stderr,
      ...(bundle.enforce !== undefined ? { enforce: bundle.enforce } : {}),
      ...(bundle.toolInventory !== undefined
        ? { toolInventory: bundle.toolInventory }
        : {}),
      ...(bundle.onClassify !== undefined
        ? { onClassify: bundle.onClassify }
        : {}),
      onClose: async (info) => {
        removeProcessHandlers();
        // AWAITED (P0-E8-T1, unlike before this task): `bundle.close()` is
        // now `Promise<void>` specifically so a configured OTel exporter's
        // bounded shutdown (`@knotrust/otel`'s `SHUTDOWN_TIMEOUT_MS`, ≤5s —
        // see `enforcement.ts`'s `close()` doc-comment) gets a real chance to
        // complete before `finish()` resolves this run's exit code and
        // `bin.ts` calls `process.exit()`. `createStdioProxy`'s `onClose`
        // itself does not await this callback's return value (it is typed
        // `() => void`) — that's fine: what matters is that `finish(...)`
        // below, which resolves THIS function's own enclosing `runProxy`
        // promise, now waits for it. For a run with no OTel exporter (the
        // default), `bundle.close()` resolves just as fast as its old
        // synchronous version did, so this adds no observable delay.
        await bundle.close();
        // R82(ii): a spontaneous child exit (the wrapped server crashed, or
        // otherwise disappeared without this proxy asking it to) must
        // surface as failure — a non-zero exit a caller can act on, never a
        // silent `0` that reads as "ran to a normal, requested completion."
        // `"client_eof"` (the real client hung up) and `"stopped"` (an
        // explicit stop()/signal) are deliberate, requested shutdowns and
        // exit `0` — UNLESS a fatal error already claimed this run first.
        finish(fatalCode ?? (info.reason === "child_exit" ? 1 : 0));
      },
    });

    // P0-E6-T2: wire the real proxy's client-facing send into the
    // block-and-wait channel's heartbeat seam, right away — well before any
    // `tools/call` could possibly arrive (the child hasn't even been
    // spawned yet; see `enforcement.ts`'s module header). Absent on the
    // zero-config path (no `enforce` hook there at all).
    bundle.bindProxySender?.((message) => proxy.sendToClient(message));

    const onSignal = (signal: NodeJS.Signals): void => {
      // SIGTERM/SIGINT to the proxy → propagate to the child (R60/R83).
      void proxy.stop(signal);
    };

    // R83: a proxy fatal error must take its child with it. Installed
    // alongside the signal handlers, under the SAME gate — see `CliIo`'s
    // `installSignalHandlers` doc-comment for why a shared test-runner
    // process must never install these unconditionally.
    const onFatal = (label: string, error: unknown): void => {
      fatalCode = 1;
      io.stderr.write(
        `knotrust: ${label} — terminating the wrapped server and exiting: ${String(error)}\n`,
      );
      removeProcessHandlers();
      void proxy
        .stop("SIGTERM")
        .catch(() => {
          // Best-effort — the SIGTERM→SIGKILL escalation ladder INSIDE
          // stop() (R60) is the real guarantee, not this catch.
        })
        .finally(() => finish(fatalCode ?? 1));
    };
    const onUncaughtException = (error: unknown): void =>
      onFatal("uncaught exception", error);
    const onUnhandledRejection = (reason: unknown): void =>
      onFatal("unhandled rejection", reason);

    let handlersInstalled = false;
    const removeProcessHandlers = (): void => {
      if (handlersInstalled) {
        process.off("SIGTERM", onSignal);
        process.off("SIGINT", onSignal);
        process.off("uncaughtException", onUncaughtException);
        process.off("unhandledRejection", onUnhandledRejection);
        handlersInstalled = false;
      }
    };
    if (io.installSignalHandlers !== false) {
      process.on("SIGTERM", onSignal);
      process.on("SIGINT", onSignal);
      process.on("uncaughtException", onUncaughtException);
      process.on("unhandledRejection", onUnhandledRejection);
      handlersInstalled = true;
    }

    proxy.start().catch((error: unknown) => {
      io.stderr.write(`knotrust: failed to start proxy: ${String(error)}\n`);
      removeProcessHandlers();
      finish(1);
    });
  });
}
