/**
 * knotrust CLI `audit list|tail|query|verify` — argv parsing (P0-E4-T4,
 * R122).
 *
 * Pure `argv -> Result` functions (no I/O, no process access, no clock
 * reads) — mirrors this package's established convention (`init/argv.ts`,
 * `grant/argv.ts`): every error path (missing subcommand, an unknown flag, a
 * value-taking flag with no value, a bad `--outcome`/`--tier`/`--since`
 * value) is a returned `{ ok: false, error }`, never an exception. `run.ts`'s
 * dispatcher turns that into a clean usage message and exit code 2, same as
 * every other bad invocation.
 *
 * `list` and `tail` are DELIBERATE aliases (documented, R122's "pick,
 * document" for list/tail's own overlap): both parse into the SAME
 * `AuditRecentArgs` shape and are dispatched to the SAME command
 * implementation (`tail-command.ts`) — `list` is the more discoverable name
 * for a human browsing recent activity, `tail` matches the familiar Unix
 * "last N lines" mental model; there is no behavioral difference between
 * them.
 */

import type { Tier } from "@knotrust/core";
import { type ParsedSince, parseSince } from "./since.js";

export const AUDIT_USAGE =
  "usage: knotrust audit <list|tail|query|verify> [flags]";
export const AUDIT_LIST_USAGE =
  "usage: knotrust audit list [-n <count>] [--json]";
export const AUDIT_TAIL_USAGE =
  "usage: knotrust audit tail [-n <count>] [--json]";
export const AUDIT_QUERY_USAGE =
  "usage: knotrust audit query [--tool <pattern>] " +
  "[--outcome allow|deny|pending_approval|deferred_not_eligible] " +
  "[--tier routine|sensitive|critical] [--since <duration|timestamp>] " +
  "[--agent <pattern>] [--server <name>] [--json]";
export const AUDIT_VERIFY_USAGE = "usage: knotrust audit verify";

const DEFAULT_LIMIT = 50;

const OUTCOMES = [
  "allow",
  "deny",
  "pending_approval",
  "deferred_not_eligible",
] as const;
type Outcome = (typeof OUTCOMES)[number];
function isOutcome(value: string): value is Outcome {
  return (OUTCOMES as readonly string[]).includes(value);
}

const TIERS: readonly Tier[] = ["routine", "sensitive", "critical"];
function isTier(value: string): value is Tier {
  return (TIERS as readonly string[]).includes(value);
}

export interface AuditRecentArgs {
  /** Default 50 (R122: "default last N, e.g. 50"). */
  limit: number;
  json: boolean;
}

export interface AuditQueryArgs {
  tool?: string;
  outcome?: Outcome;
  tier?: Tier;
  since?: ParsedSince;
  agent?: string;
  server?: string;
  json: boolean;
}

export type AuditCommand =
  | { kind: "list"; args: AuditRecentArgs }
  | { kind: "tail"; args: AuditRecentArgs }
  | { kind: "query"; args: AuditQueryArgs }
  | { kind: "verify" };

export type ParseAuditArgsResult =
  | { ok: true; command: AuditCommand }
  | { ok: false; error: string };

function err(message: string, usage: string): { ok: false; error: string } {
  return { ok: false, error: `knotrust audit: ${message}. ${usage}` };
}

function parseRecentArgs(
  argv: readonly string[],
  usage: string,
): { ok: true; args: AuditRecentArgs } | { ok: false; error: string } {
  let limit = DEFAULT_LIMIT;
  let json = false;

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token === "-n" || token === "--limit") {
      const value = argv[++i];
      if (value === undefined) {
        return err(`${token} requires a value`, usage);
      }
      // `/^\d+$/`, not `Number.parseInt`, catches trailing-garbage inputs
      // like `"1.5"` (parseInt truncates at the decimal and would silently
      // accept it as `1`) or `"3abc"` — this flag takes a whole count, not
      // a leading numeric prefix.
      if (!/^\d+$/.test(value)) {
        return err(
          `invalid count ${JSON.stringify(value)} for ${token} — expected a positive integer`,
          usage,
        );
      }
      const parsed = Number.parseInt(value, 10);
      if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        return err(
          `invalid count ${JSON.stringify(value)} for ${token} — expected a positive integer`,
          usage,
        );
      }
      limit = parsed;
      continue;
    }
    if (token === "--json") {
      json = true;
      continue;
    }
    return err(`unknown flag ${JSON.stringify(token ?? "")}`, usage);
  }

  return { ok: true, args: { limit, json } };
}

function parseQueryArgs(
  argv: readonly string[],
): { ok: true; args: AuditQueryArgs } | { ok: false; error: string } {
  let tool: string | undefined;
  let outcome: Outcome | undefined;
  let tier: Tier | undefined;
  let since: ParsedSince | undefined;
  let agent: string | undefined;
  let server: string | undefined;
  let json = false;

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    switch (token) {
      case "--tool": {
        const value = argv[++i];
        if (value === undefined) {
          return err("--tool requires a value", AUDIT_QUERY_USAGE);
        }
        tool = value;
        break;
      }
      case "--outcome": {
        const value = argv[++i];
        if (value === undefined) {
          return err("--outcome requires a value", AUDIT_QUERY_USAGE);
        }
        if (!isOutcome(value)) {
          return err(
            `unknown --outcome ${JSON.stringify(value)} — expected one of ${OUTCOMES.join(", ")}`,
            AUDIT_QUERY_USAGE,
          );
        }
        outcome = value;
        break;
      }
      case "--tier": {
        const value = argv[++i];
        if (value === undefined) {
          return err("--tier requires a value", AUDIT_QUERY_USAGE);
        }
        if (!isTier(value)) {
          return err(
            `unknown --tier ${JSON.stringify(value)} — expected one of ${TIERS.join(", ")}`,
            AUDIT_QUERY_USAGE,
          );
        }
        tier = value;
        break;
      }
      case "--since": {
        const value = argv[++i];
        if (value === undefined) {
          return err("--since requires a value", AUDIT_QUERY_USAGE);
        }
        const result = parseSince(value);
        if (!result.ok) {
          return err(result.error, AUDIT_QUERY_USAGE);
        }
        since = result.parsed;
        break;
      }
      case "--agent": {
        const value = argv[++i];
        if (value === undefined) {
          return err("--agent requires a value", AUDIT_QUERY_USAGE);
        }
        agent = value;
        break;
      }
      case "--server": {
        const value = argv[++i];
        if (value === undefined) {
          return err("--server requires a value", AUDIT_QUERY_USAGE);
        }
        server = value;
        break;
      }
      case "--json":
        json = true;
        break;
      default:
        return err(
          `unknown flag ${JSON.stringify(token ?? "")}`,
          AUDIT_QUERY_USAGE,
        );
    }
  }

  return {
    ok: true,
    args: {
      ...(tool !== undefined ? { tool } : {}),
      ...(outcome !== undefined ? { outcome } : {}),
      ...(tier !== undefined ? { tier } : {}),
      ...(since !== undefined ? { since } : {}),
      ...(agent !== undefined ? { agent } : {}),
      ...(server !== undefined ? { server } : {}),
      json,
    },
  };
}

/** Parses `knotrust audit <sub> [flags]`'s argv — everything AFTER the literal `"audit"` token. */
export function parseAuditArgs(argv: readonly string[]): ParseAuditArgsResult {
  const sub = argv[0];
  const rest = argv.slice(1);

  if (sub === undefined) {
    return err(
      "requires a subcommand (list, tail, query, or verify)",
      AUDIT_USAGE,
    );
  }

  if (sub === "list") {
    const result = parseRecentArgs(rest, AUDIT_LIST_USAGE);
    return result.ok
      ? { ok: true, command: { kind: "list", args: result.args } }
      : { ok: false, error: result.error };
  }

  if (sub === "tail") {
    const result = parseRecentArgs(rest, AUDIT_TAIL_USAGE);
    return result.ok
      ? { ok: true, command: { kind: "tail", args: result.args } }
      : { ok: false, error: result.error };
  }

  if (sub === "query") {
    const result = parseQueryArgs(rest);
    return result.ok
      ? { ok: true, command: { kind: "query", args: result.args } }
      : { ok: false, error: result.error };
  }

  if (sub === "verify") {
    const first = rest[0];
    if (first !== undefined) {
      return err(`unknown flag ${JSON.stringify(first)}`, AUDIT_VERIFY_USAGE);
    }
    return { ok: true, command: { kind: "verify" } };
  }

  return err(
    `unknown subcommand ${JSON.stringify(sub)} — expected list, tail, query, or verify`,
    AUDIT_USAGE,
  );
}
