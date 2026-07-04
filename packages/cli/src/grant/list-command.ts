/**
 * knotrust CLI `grant list` — tabulate active grants (P0-E7-T2, R113, R116).
 *
 * Read-only: no keystore, no audit sink, just the real file-backed grant
 * store (`@knotrust/store`). Tombstoned grants are excluded by
 * `store.list()` itself (R30 — a tombstone always wins). R116: never dumps
 * the raw signed JWS — every row is built from the DECODED claims only.
 *
 * ## Invalid grant files are surfaced, never silently dropped (fix round 1,
 * P0-E7-T2 review, FIX 2)
 *
 * `store.list()` returns `{ active, invalid }` — `invalid` names every
 * `.jws` file that failed to decode (undecodable/tampered/corrupt, R29's
 * `grant_invalid`). Before this fix, this command read only `active` and
 * threw `invalid` away entirely: a corrupt grant file — exactly the kind of
 * thing a supply-chain-security tool must never let a human miss — vanished
 * with zero signal in both table and `--json` mode. Now a non-empty
 * `invalid` always prints a one-line stderr notice (both modes — stderr
 * never interferes with a script parsing `--json`'s stdout), and `--json`
 * additionally includes a structured `invalid` field so a script sees it
 * too, not just a human reading the table.
 */

import path from "node:path";
import type { Writable } from "node:stream";
import {
  decodeGrantIndexEntry,
  decodeGrantPayload,
  parseWireClaims,
  resolveKnotrustHome,
} from "@knotrust/grants";
import { createGrantStore } from "@knotrust/store";
import type { GrantListArgs } from "./argv.js";
import {
  deriveServerLabel,
  formatAbsolute,
  formatRelativeShort,
  shortJti,
} from "./format.js";

export interface GrantListIo {
  stdout: Writable;
  stderr: Writable;
}

export interface GrantListDeps {
  /** Defaults to `resolveKnotrustHome()`; injected in tests to a throwaway temp dir. */
  home?: string;
  /** Injected epoch-seconds clock (the "relative" column's `now`). Defaults to `Math.floor(Date.now() / 1000)`. */
  nowEpochSeconds?: () => number;
}

/** One `grant list` row — the shape both the table and `--json` render from (never the raw token). */
export interface GrantListRow {
  jti: string;
  tool: string;
  /** Best-effort label — see `format.ts`'s `deriveServerLabel` doc-comment: NOT literally the `--server` value given at mint time (that is not persisted on the grant). */
  server: string;
  agent: string;
  tierCap: string;
  kind: string;
  singleUse: boolean;
  iat: number;
  exp: number;
  expiresAt: string;
  expiresIn: string;
}

/** `--json`'s top-level shape (fix round 1, P0-E7-T2 review, FIX 2): `active` is exactly what the bare-array shape used to be; `invalid` is new — a script can check `invalid.count > 0` without parsing the stderr notice. */
export interface GrantListJsonOutput {
  active: GrantListRow[];
  invalid: { count: number; jtis: string[] };
}

function toRow(
  nowEpochSeconds: number,
  jti: string,
  token: string,
): GrantListRow | undefined {
  const claims = parseWireClaims(decodeGrantPayload(token));
  if (claims === null) return undefined;
  return {
    jti,
    tool: claims.tool,
    server: deriveServerLabel(claims.tool),
    agent: claims.agent === "*" ? "*" : claims.agent.id,
    tierCap: claims.tier,
    kind: claims.kind,
    singleUse: claims.singleUse,
    iat: claims.iat,
    exp: claims.exp,
    expiresAt: formatAbsolute(claims.exp),
    expiresIn: formatRelativeShort(nowEpochSeconds, claims.exp),
  };
}

const COLUMNS: Array<{
  key: keyof GrantListRow;
  label: string;
  render(row: GrantListRow): string;
}> = [
  { key: "jti", label: "JTI", render: (r) => shortJti(r.jti) },
  { key: "tool", label: "TOOL", render: (r) => r.tool },
  // Header is "NAMESPACE", not "SERVER" (fix round 1, P0-E7-T2 review, FIX
  // 3): the value is derived from the tool PATTERN's leading dot-namespace
  // segment (see `deriveServerLabel`'s doc-comment) — it is NOT the mint-time
  // `--server` value, which is not persisted on the grant at all. "SERVER"
  // read as if it were that literal value; "NAMESPACE" doesn't. The `row.server`
  // field/key name is left as-is (internal plumbing, not user-facing).
  { key: "server", label: "NAMESPACE", render: (r) => r.server },
  { key: "agent", label: "AGENT", render: (r) => r.agent },
  { key: "tierCap", label: "TIER-CAP", render: (r) => r.tierCap },
  { key: "kind", label: "KIND", render: (r) => r.kind },
  {
    key: "expiresAt",
    label: "EXPIRES",
    render: (r) => `${r.expiresAt} (${r.expiresIn})`,
  },
  {
    key: "singleUse",
    label: "SINGLE-USE",
    render: (r) => (r.singleUse ? "yes" : "no"),
  },
];

function renderTable(rows: readonly GrantListRow[]): string {
  const widths = COLUMNS.map((col) =>
    Math.max(col.label.length, ...rows.map((row) => col.render(row).length)),
  );
  const line = (cells: readonly string[]): string =>
    cells
      .map((cell, i) => cell.padEnd(widths[i] ?? 0))
      .join("  ")
      .trimEnd();
  const header = line(COLUMNS.map((c) => c.label));
  const body = rows.map((row) => line(COLUMNS.map((c) => c.render(row))));
  return [header, ...body].join("\n");
}

export function runGrantList(
  io: GrantListIo,
  args: GrantListArgs,
  deps: GrantListDeps = {},
): number {
  const home = deps.home ?? resolveKnotrustHome();
  const nowEpochSeconds =
    deps.nowEpochSeconds ?? (() => Math.floor(Date.now() / 1000));

  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const { active, invalid } = store.list();
  const now = nowEpochSeconds();
  const rows = active
    .map(({ jti, token }) => toRow(now, jti, token))
    .filter((row): row is GrantListRow => row !== undefined);

  // FIX 2: a corrupt/tampered grant file must never vanish with zero
  // signal — always to stderr, in BOTH modes, so it never corrupts a
  // script's `--json` stdout parsing while still reaching a human watching
  // the terminal.
  if (invalid.length > 0) {
    io.stderr.write(
      `(${invalid.length} invalid grant file(s) skipped — run \`knotrust audit verify\` ` +
        `or inspect ${path.join(home, "grants")})\n`,
    );
  }

  if (args.json) {
    const output: GrantListJsonOutput = {
      active: rows,
      invalid: { count: invalid.length, jtis: invalid.map((g) => g.jti) },
    };
    io.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    return 0;
  }

  if (rows.length === 0) {
    io.stdout.write("No active grants.\n");
    return 0;
  }

  io.stdout.write(`${renderTable(rows)}\n`);
  return 0;
}
