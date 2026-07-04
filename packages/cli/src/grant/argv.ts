/**
 * knotrust CLI `grant` / `grant list` / `revoke` — argv parsing (P0-E7-T2,
 * R111-R114).
 *
 * Pure `argv -> Result` functions (no I/O, no process access), mirroring
 * `init/argv.ts`'s convention: every error path (missing required flag, a
 * value-taking flag with no value, an unknown flag, a bad `--tier-cap`/
 * `--expires` value, an ambiguous `revoke` selector) is a returned
 * `{ ok: false, error }`, never an exception — `run.ts`'s dispatcher turns
 * that into a clean usage message and exit code 2, same as every other bad
 * invocation.
 */

import type { Tier } from "@knotrust/core";
import { parseDuration } from "./duration.js";

const SAFE_JTI = /^[A-Za-z0-9_-]+$/;

// ---------------------------------------------------------------------------
// `knotrust grant --tool <pat> --server <name> ...` (R111)
// ---------------------------------------------------------------------------

export const GRANT_MINT_USAGE =
  "usage: knotrust grant --tool <pattern> --server <name> [--agent <pattern>] " +
  "[--tier-cap routine|sensitive|critical] [--expires <duration>] " +
  "[--resource <type:idPattern|idPattern>] [--yes] [--i-understand-critical]";

export interface GrantMintArgs {
  tool: string;
  server: string;
  /** Default `"*"` (any agent). */
  agent: string;
  /** Default `"sensitive"`. */
  tierCap: Tier;
  /** Parsed from `--expires` (default `"30d"`) — already validated seconds. */
  ttlSeconds: number;
  resource?: string;
  /** Skip the interactive confirmation gate (the plain-words text is still always printed — R116). */
  yes: boolean;
}

export type ParseGrantMintArgsResult =
  | { ok: true; args: GrantMintArgs }
  | { ok: false; error: string };

const DEFAULT_EXPIRES = "30d";
const DEFAULT_TIER_CAP: Tier = "sensitive";

function isTier(value: string): value is Tier {
  return value === "routine" || value === "sensitive" || value === "critical";
}

function mintErr(message: string): ParseGrantMintArgsResult {
  return {
    ok: false,
    error: `knotrust grant: ${message}. ${GRANT_MINT_USAGE}`,
  };
}

export function parseGrantMintArgs(
  argv: readonly string[],
): ParseGrantMintArgsResult {
  let tool: string | undefined;
  let server: string | undefined;
  let agent = "*";
  let tierCap: Tier = DEFAULT_TIER_CAP;
  let expiresRaw = DEFAULT_EXPIRES;
  let resource: string | undefined;
  let yes = false;
  let iUnderstandCritical = false;

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    switch (token) {
      case "--tool": {
        const value = argv[++i];
        if (value === undefined) return mintErr("--tool requires a value");
        tool = value;
        break;
      }
      case "--server": {
        const value = argv[++i];
        if (value === undefined) return mintErr("--server requires a value");
        server = value;
        break;
      }
      case "--agent": {
        const value = argv[++i];
        if (value === undefined) return mintErr("--agent requires a value");
        agent = value;
        break;
      }
      case "--tier-cap": {
        const value = argv[++i];
        if (value === undefined) return mintErr("--tier-cap requires a value");
        if (!isTier(value)) {
          return mintErr(
            `unknown --tier-cap "${value}" — expected routine, sensitive, or critical`,
          );
        }
        tierCap = value;
        break;
      }
      case "--expires": {
        const value = argv[++i];
        if (value === undefined) return mintErr("--expires requires a value");
        expiresRaw = value;
        break;
      }
      case "--resource": {
        const value = argv[++i];
        if (value === undefined) return mintErr("--resource requires a value");
        resource = value;
        break;
      }
      case "--yes":
      case "-y":
        yes = true;
        break;
      case "--i-understand-critical":
        iUnderstandCritical = true;
        break;
      default:
        return mintErr(`unknown flag "${token ?? ""}"`);
    }
  }

  if (tool === undefined) return mintErr("--tool is required");
  if (server === undefined) return mintErr("--server is required");

  // R111's intentional friction: a durable CRITICAL grant is a standing
  // pre-authorization for the most dangerous tier — refused outright unless
  // the caller explicitly acknowledges that with --i-understand-critical.
  if (tierCap === "critical" && !iUnderstandCritical) {
    return mintErr(
      "--tier-cap critical requires an explicit --i-understand-critical flag " +
        "(a durable critical grant is a standing pre-authorization for the most " +
        "dangerous tier — this friction is intentional, PRD §7)",
    );
  }

  const duration = parseDuration(expiresRaw);
  if (!duration.ok) {
    return mintErr(`--expires ${duration.error}`);
  }

  return {
    ok: true,
    args: {
      tool,
      server,
      agent,
      tierCap,
      ttlSeconds: duration.seconds,
      ...(resource !== undefined ? { resource } : {}),
      yes,
    },
  };
}

// ---------------------------------------------------------------------------
// `knotrust grant list` (R113)
// ---------------------------------------------------------------------------

export const GRANT_LIST_USAGE = "usage: knotrust grant list [--json]";

export interface GrantListArgs {
  json: boolean;
}

export type ParseGrantListArgsResult =
  | { ok: true; args: GrantListArgs }
  | { ok: false; error: string };

export function parseGrantListArgs(
  argv: readonly string[],
): ParseGrantListArgsResult {
  let json = false;
  for (const token of argv) {
    if (token === "--json") {
      json = true;
      continue;
    }
    return {
      ok: false,
      error: `knotrust grant list: unknown flag "${token}". ${GRANT_LIST_USAGE}`,
    };
  }
  return { ok: true, args: { json } };
}

// ---------------------------------------------------------------------------
// `knotrust revoke <jti> | --tool <pattern> | --all` (R114)
// ---------------------------------------------------------------------------

export const REVOKE_USAGE =
  "usage: knotrust revoke <jti> | --tool <pattern> | --all [--yes]";

export type RevokeSelector = { jti: string } | { tool: string } | { all: true };

export interface RevokeArgs {
  selector: RevokeSelector;
  yes: boolean;
}

export type ParseRevokeArgsResult =
  | { ok: true; args: RevokeArgs }
  | { ok: false; error: string };

function revokeErr(message: string): ParseRevokeArgsResult {
  return { ok: false, error: `knotrust revoke: ${message}. ${REVOKE_USAGE}` };
}

export function parseRevokeArgs(
  argv: readonly string[],
): ParseRevokeArgsResult {
  let tool: string | undefined;
  let all = false;
  let yes = false;
  const positionals: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "--tool") {
      const value = argv[++i];
      if (value === undefined) return revokeErr("--tool requires a value");
      tool = value;
      continue;
    }
    if (token === "--all") {
      all = true;
      continue;
    }
    if (token === "--yes" || token === "-y") {
      yes = true;
      continue;
    }
    if (token?.startsWith("-")) {
      return revokeErr(`unknown flag "${token}"`);
    }
    if (token !== undefined) positionals.push(token);
  }

  const selectorsGiven =
    (tool !== undefined ? 1 : 0) +
    (all ? 1 : 0) +
    (positionals.length > 0 ? 1 : 0);
  if (selectorsGiven === 0) {
    return revokeErr("requires a jti, --tool <pattern>, or --all");
  }
  if (selectorsGiven > 1) {
    return revokeErr("accepts exactly one of: <jti>, --tool <pattern>, --all");
  }
  if (positionals.length > 1) {
    return revokeErr("accepts at most one jti positional");
  }

  let selector: RevokeSelector;
  if (all) {
    selector = { all: true };
  } else if (tool !== undefined) {
    selector = { tool };
  } else {
    const jti = positionals[0] as string;
    if (!SAFE_JTI.test(jti)) {
      return revokeErr(`invalid jti ${JSON.stringify(jti)}`);
    }
    selector = { jti };
  }

  return { ok: true, args: { selector, yes } };
}
