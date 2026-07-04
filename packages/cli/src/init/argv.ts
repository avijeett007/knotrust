/**
 * knotrust CLI `init` — argv parsing (P0-E7-T1, R106–R109).
 *
 * Shape: `knotrust init <claude|codex> [--yes] [--dry-run|--diff] [--server
 * <name>] [--config-format <yaml|json|ts>]`. `run.ts`'s dispatcher hands this
 * module everything AFTER the literal `"init"` token (see `run.ts`'s own
 * subcommand-routing comment); this module never sees `"init"` itself.
 *
 * A pure `argv -> Result` function (no I/O, no process access) so every
 * error path — missing client, unknown flag, a value-taking flag with no
 * value, an invalid `--config-format` — is trivially unit-testable without
 * spinning up `runCli` at all.
 */

import type { ClientId } from "./client-config.js";
import { type ConfigFormat, DEFAULT_CONFIG_FORMAT } from "./config-generate.js";

export const INIT_USAGE =
  "usage: knotrust init <claude|codex> [--yes] [--dry-run|--diff] [--server <name>] [--config-format <yaml|json|ts>]";

export interface InitArgs {
  client: ClientId;
  /** `--yes`/`-y`: wrap ALL wrappable servers, zero prompts (R107/R108). */
  yes: boolean;
  /** `--dry-run` or its alias `--diff`: print the exact diff(s), write nothing (R108). */
  dryRun: boolean;
  /** `--server <name>`: target exactly one server, zero prompts. */
  server?: string;
  /** `--config-format <yaml|json|ts>`: format for the generated `knotrust.config.*` (R109). Defaults to {@link DEFAULT_CONFIG_FORMAT}. */
  configFormat: ConfigFormat;
}

export type ParseInitArgsResult =
  | { ok: true; args: InitArgs }
  | { ok: false; error: string };

function isClientId(value: string): value is ClientId {
  return value === "claude" || value === "codex";
}

function isConfigFormat(value: string): value is ConfigFormat {
  return value === "yaml" || value === "json" || value === "ts";
}

/** Parses the argv tokens AFTER `"init"`. Never throws — every failure is a returned `{ ok: false, error }`. */
export function parseInitArgs(argv: readonly string[]): ParseInitArgsResult {
  const clientToken = argv[0];
  if (clientToken === undefined) {
    return {
      ok: false,
      error: `knotrust init: missing client — ${INIT_USAGE}`,
    };
  }
  if (!isClientId(clientToken)) {
    return {
      ok: false,
      error: `knotrust init: unknown client "${clientToken}" — expected "claude" or "codex". ${INIT_USAGE}`,
    };
  }

  let yes = false;
  let dryRun = false;
  let server: string | undefined;
  let configFormat: ConfigFormat = DEFAULT_CONFIG_FORMAT;

  for (let i = 1; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--yes" || token === "-y") {
      yes = true;
      continue;
    }
    if (token === "--dry-run" || token === "--diff") {
      dryRun = true;
      continue;
    }
    if (token === "--server") {
      const value = argv[i + 1];
      if (value === undefined) {
        return {
          ok: false,
          error: `knotrust init: --server requires a value. ${INIT_USAGE}`,
        };
      }
      server = value;
      i++;
      continue;
    }
    if (token === "--config-format") {
      const value = argv[i + 1];
      if (value === undefined) {
        return {
          ok: false,
          error: `knotrust init: --config-format requires a value. ${INIT_USAGE}`,
        };
      }
      if (!isConfigFormat(value)) {
        return {
          ok: false,
          error: `knotrust init: unknown --config-format "${value}" — expected yaml, json, or ts. ${INIT_USAGE}`,
        };
      }
      configFormat = value;
      i++;
      continue;
    }
    return {
      ok: false,
      error: `knotrust init: unknown flag "${token ?? ""}". ${INIT_USAGE}`,
    };
  }

  return {
    ok: true,
    args: {
      client: clientToken,
      yes,
      dryRun,
      ...(server !== undefined ? { server } : {}),
      configFormat,
    },
  };
}
