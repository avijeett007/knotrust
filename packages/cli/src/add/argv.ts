/**
 * knotrust CLI `add <kind> <ref>` — argv parsing (P0-E7-T3, ruling R121).
 *
 * `add` is deliberately structured as a `<kind>` dispatch, not a `pack`-only
 * command, so P1 only ever needs to ADD a new `<kind>` branch here (a
 * GitHub-fetched `add pack <name>` and `add pdp cedar`, per the task brief's
 * P0-E7-Tx epic-B list) — never to redesign this argv surface. Only `"pack"`
 * is implemented in Phase 0; every other `<kind>` is a clean, named usage
 * error pointing at what P1 adds, mirroring `init/argv.ts`/`grant/argv.ts`'s
 * own "pure `argv -> Result`, no I/O, no exceptions" convention.
 */

export const ADD_USAGE = "usage: knotrust add <kind> <ref> [options]";
export const ADD_PACK_USAGE =
  "usage: knotrust add pack <path> [--server <name>] [--yes] [--dry-run]";

export interface AddPackArgs {
  /** The local pack file path, as given on argv (resolved against `io.cwd` by `pack-command.ts`, never here). */
  path: string;
  /** `--server <name>`: overrides the pack's own optional `server` field as the target `servers.<server>` config key. */
  server?: string;
  /** `--yes`/`-y`: skip the interactive confirmation gate (the diff is still always printed — R119). */
  yes: boolean;
  /** `--dry-run` or its `--diff` alias: print the diff, write nothing. */
  dryRun: boolean;
}

export type ParseAddArgsResult =
  | { ok: true; kind: "pack"; args: AddPackArgs }
  | { ok: false; error: string };

function packErr(message: string): ParseAddArgsResult {
  return {
    ok: false,
    error: `knotrust add pack: ${message}. ${ADD_PACK_USAGE}`,
  };
}

function parsePackArgs(rest: readonly string[]): ParseAddArgsResult {
  let pathArg: string | undefined;
  let server: string | undefined;
  let yes = false;
  let dryRun = false;

  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (token === "--server") {
      const value = rest[i + 1];
      if (value === undefined) return packErr("--server requires a value");
      server = value;
      i++;
      continue;
    }
    if (token === "--yes" || token === "-y") {
      yes = true;
      continue;
    }
    if (token === "--dry-run" || token === "--diff") {
      dryRun = true;
      continue;
    }
    if (token?.startsWith("-")) {
      return packErr(`unknown flag "${token}"`);
    }
    if (pathArg !== undefined) {
      return packErr("accepts exactly one <path>");
    }
    pathArg = token;
  }

  if (pathArg === undefined) {
    return packErr("missing <path>");
  }

  return {
    ok: true,
    kind: "pack",
    args: {
      path: pathArg,
      ...(server !== undefined ? { server } : {}),
      yes,
      dryRun,
    },
  };
}

/** Parses the argv tokens AFTER `"add"`. Never throws — every failure is a returned `{ ok: false, error }` (`run.ts`'s dispatcher turns that into exit code 2, same as every other bad invocation). */
export function parseAddArgs(argv: readonly string[]): ParseAddArgsResult {
  const kind = argv[0];
  if (kind === undefined) {
    return { ok: false, error: `knotrust add: missing <kind>. ${ADD_USAGE}` };
  }
  if (kind !== "pack") {
    return {
      ok: false,
      error:
        `knotrust add: unknown kind "${kind}" — only "pack" is implemented in ` +
        'Phase 0 (a GitHub-fetched "add pack <name>" with signature/hash ' +
        'verification, and "add pdp cedar", arrive in P1). ' +
        ADD_USAGE,
    };
  }
  return parsePackArgs(argv.slice(1));
}
