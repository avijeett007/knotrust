/**
 * knotrust CLI `add pack <path>` — the command orchestration (P0-E7-T3,
 * rulings R117-R120).
 *
 * Ties `pack-schema.ts` (load + validate the local YAML), `pack-merge.ts`
 * (the precedence-respecting merge) and `@knotrust/store`'s config
 * loader/schema together into the flow the plan's acceptance describes:
 *
 *   1. Load the pack file (R117). A missing/invalid pack ABORTS here —
 *      before anything else runs, no write anywhere.
 *   2. Resolve the target `servers.<server>` key: `--server <name>` if
 *      given, else the pack's own optional `server` field, else a clean
 *      usage-shaped error (never a guess).
 *   3. Load the existing `knotrust.config.*` (or the schema's all-defaults
 *      skeleton when none exists — `loadKnotrustConfig`'s own documented
 *      zero-config behavior, reused as-is rather than reinvented).
 *   4. Merge (`mergePackIntoTools`) and print the human-readable diff (R119)
 *      — UNCONDITIONALLY, even under `--yes`/`--dry-run` (transparency is
 *      never gated, mirroring `grant/mint-command.ts`'s R116 discipline for
 *      the identical reason).
 *   5. Nothing to write (a true idempotent re-apply, or a pack whose every
 *      touched tool was `KEPT`) → clean no-op message, no confirm prompt, no
 *      write — mirroring `init/command.ts`'s own "nothing newly wrapped ⇒ no
 *      write" precedent.
 *   6. `--dry-run`: stop here, write nothing.
 *   7. Confirm unless `--yes` (R119's Homebrew tap-trust discipline).
 *   8. Atomic write (`atomicWriteFileSync`, reused from `init/client-
 *      config.ts` — a corrupt config breaks the proxy, so this is never a
 *      plain `writeFileSync`).
 *
 * ## The `knotrust.config.ts` scope boundary (same as `init`, not reinvented)
 *
 * An existing `knotrust.config.ts` can be EXECUTED (c12's bundled jiti) but
 * not safely RE-EMITTED (arbitrary hand-authored TypeScript) — this command
 * refuses to apply a pack onto one, with a clear message, exactly mirroring
 * `init/command.ts`'s own documented scope boundary for suggested-tier
 * generation. Unlike `init` (where this is a best-effort SKIP because the
 * client-config wrap already succeeded independently), here it is the
 * command's entire purpose, so it is a hard failure (exit 1), not a clean
 * no-op exit 0.
 *
 * ## P0 packs are unsigned (R117) — the notice this command always prints
 *
 * `UNSIGNED_NOTICE` is printed on every real invocation (not gated by
 * `--yes`/`--dry-run`) — the local-file-trust caveat this task's diff preview
 * exists to mitigate, but cannot fully replace (P1-E3 adds registry fetch +
 * signature/content-hash verification).
 *
 * ## The re-format notice — existing config only (fix round 1, P0-E7-T3
 * review, FIX 2)
 *
 * `serializeGeneratedConfig` re-serializes the WHOLE target config file
 * canonically, not just the tools this pack touches — schema defaults get
 * materialized, key order/whitespace/comments are whatever the generator
 * produces, never what a human originally wrote. The diff preview above
 * (R119) is honest about the TOOL-TIER changes; it says nothing about this
 * file-wide side effect, which a human editing `knotrust.config.yaml` by
 * hand (adding their own comments, a preferred key order) would not expect
 * a `knotrust add pack` run to silently erase. `REFORMAT_NOTICE` closes that
 * gap: printed once, right before the write/confirm gate, but ONLY when an
 * EXISTING config file is the target — a freshly created config has no
 * prior formatting to lose, so there is nothing to warn about.
 */

import path from "node:path";
import type { Writable } from "node:stream";
import type { KnotrustConfig, ServerConfigEntry } from "@knotrust/store";
import { loadKnotrustConfig } from "@knotrust/store";
import { atomicWriteFileSync } from "../init/client-config.js";
import {
  type ConfigFormat,
  configFileName,
  DEFAULT_CONFIG_FORMAT,
  serializeGeneratedConfig,
} from "../init/config-generate.js";
import type { AddPackArgs } from "./argv.js";
import { type ConfirmFn, confirmInteractively } from "./confirm.js";
import { mergePackIntoTools } from "./pack-merge.js";
import { loadPackFile } from "./pack-schema.js";

export interface AddPackIo {
  stdout: Writable;
  stderr: Writable;
  /** Directory searched for the pack file (relative paths) and `knotrust.config.*`. Defaults to `process.cwd()`; injected in tests. */
  cwd?: string;
}

export interface AddPackDeps {
  /** Injected confirmation gate. Defaults to the real `@clack/prompts` implementation. */
  confirm?: ConfirmFn;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

/** Duplicated from `init/command.ts`'s own (unexported) helper of the identical name — this repo's established convention for a tiny path-suffix predicate with no shared package boundary to justify a cross-import (see `pack-schema.ts`'s header for the same convention, named). */
function formatFromPath(sourceFile: string): ConfigFormat {
  if (sourceFile.endsWith(".json")) return "json";
  if (sourceFile.endsWith(".ts")) return "ts";
  return "yaml";
}

const UNSIGNED_NOTICE =
  "knotrust: pack files are UNSIGNED local files in Phase 0 — no hash/signature " +
  "verification (the GitHub registry + verification arrive in P1). Only apply " +
  "packs you trust.\n";

/**
 * Printed only when an EXISTING `knotrust.config.*` is about to be
 * rewritten (fix round 1, P0-E7-T3 review, FIX 2) — see this module's header
 * for the full "why". Never printed when there is no existing file (a fresh
 * config is written pristine — nothing to lose, nothing to warn about).
 */
const REFORMAT_NOTICE =
  "knotrust: note — the whole config file will be re-formatted canonically " +
  "(comments and custom formatting are not preserved).\n";

/**
 * Runs `knotrust add pack <path>` end to end. Returns the process exit code
 * (0 success/no-op/dry-run/cancelled, 1 on any abort — missing/invalid pack
 * file, no resolvable target server, or an existing `knotrust.config.ts`).
 * Never calls `process.exit` itself.
 */
export async function runAddPack(
  io: AddPackIo,
  args: AddPackArgs,
  deps: AddPackDeps = {},
): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const confirm = deps.confirm ?? confirmInteractively;

  let pack: Awaited<ReturnType<typeof loadPackFile>>;
  try {
    pack = await loadPackFile(path.resolve(cwd, args.path));
  } catch (error) {
    write(
      io.stderr,
      `knotrust add pack: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return 1;
  }

  const serverName = args.server ?? pack.server;
  if (serverName === undefined) {
    write(
      io.stderr,
      `knotrust add pack: pack "${pack.name}" does not declare a "server" — ` +
        "pass --server <name>.\n",
    );
    return 1;
  }

  const loaded = await loadKnotrustConfig({ cwd });
  const base = loaded.config;

  if (loaded.sourceFile?.endsWith(".ts")) {
    write(
      io.stderr,
      `knotrust add pack: existing ${loaded.sourceFile} is a TypeScript config — ` +
        "cannot safely apply a pack onto hand-authored TS (out of scope for " +
        "automatic regeneration, mirroring `knotrust init`'s own scope boundary); " +
        "edit it by hand, or switch to knotrust.config.yaml/json.\n",
    );
    return 1;
  }

  const existingServerEntry = base.servers?.[serverName];
  const result = mergePackIntoTools(existingServerEntry?.tools, pack.tools);

  write(io.stderr, UNSIGNED_NOTICE);
  write(io.stdout, `\n=== pack: ${pack.name} (server: ${serverName}) ===\n`);

  if (result.diff.length === 0) {
    write(
      io.stdout,
      "No tools to apply — pack already fully reflected in config.\n",
    );
    return 0;
  }

  for (const line of result.diff) {
    write(io.stdout, `${line.text}\n`);
  }

  if (!result.changed) {
    write(io.stdout, "\nNo changes to write (idempotent no-op).\n");
    return 0;
  }

  // Fix round 1, P0-E7-T3 review, FIX 2 — only once we know there is a real
  // write pending (the two no-op returns above already ruled that out), and
  // only when it lands on an EXISTING file (a fresh config has nothing to
  // reformat away). Printed for `--dry-run` too: a dry run previews exactly
  // what a real apply would do to this file, and that includes this.
  if (loaded.sourceFile !== undefined) {
    write(io.stderr, REFORMAT_NOTICE);
  }

  if (args.dryRun) {
    write(io.stdout, "\n(dry run — no changes written)\n");
    return 0;
  }

  if (!args.yes) {
    const proceed = await confirm(
      `Apply pack "${pack.name}" to server "${serverName}"?`,
    );
    if (!proceed) {
      write(io.stdout, "\nCancelled — no changes written.\n");
      return 0;
    }
  }

  const newServers: Record<string, ServerConfigEntry> = {
    ...(base.servers ?? {}),
    [serverName]: { ...(existingServerEntry ?? {}), tools: result.tools },
  };
  const newConfig: KnotrustConfig = { ...base, servers: newServers };

  const targetFormat: ConfigFormat =
    loaded.sourceFile !== undefined
      ? formatFromPath(loaded.sourceFile)
      : DEFAULT_CONFIG_FORMAT;
  const targetPath =
    loaded.sourceFile ?? path.join(cwd, configFileName(targetFormat));

  const newConfigText = serializeGeneratedConfig(newConfig, targetFormat);
  atomicWriteFileSync(targetPath, newConfigText);
  write(io.stdout, `\nWrote ${targetPath}.\n`);
  return 0;
}
