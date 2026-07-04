/**
 * knotrust CLI `revoke` — per P0-E3-T4's `revokeGrants` (P0-E7-T2, R114/R116).
 *
 * `revoke <jti> | --tool <pattern> | --all` tombstones the matched grant(s)
 * in the REAL store, appends `grant_revoked` audit event(s), and confirms
 * (plain words, listing exactly what will be revoked) unless `--yes`.
 *
 * ## Cross-process cache invalidation — documented, not silently punted
 *
 * `revokeGrants`'s `onInvalidate` seam exists so a composed system (the
 * long-running `knotrust -- <server>` proxy) can bump its IN-PROCESS
 * decision cache the instant a revoke happens. This CLI invocation is a
 * SEPARATE process from any such proxy — there is no live decision cache
 * here to bump, so `onInvalidate` is simply omitted. Revocation still takes
 * effect on that proxy's NEXT decision, because the grant STORE (not any
 * in-process cache) is the source of truth every decision re-reads from —
 * the in-proxy cache bump is a same-process optimization, never required
 * for cross-process correctness. This is exactly the local-mode claim
 * `docs/02-product/revocation-claims.md` (ADR-0011) already documents:
 * "effectively immediate... for this mode only," realized by "the store IS
 * the cache."
 */

import type { Writable } from "node:stream";
import {
  decodeGrantIndexEntry,
  decodeGrantPayload,
  parseWireClaims,
  resolveKnotrustHome,
  revokeGrants,
} from "@knotrust/grants";
import type { GrantRecord, GrantStore } from "@knotrust/store";
import { createAuditLog, createGrantStore } from "@knotrust/store";
import type { RevokeArgs, RevokeSelector } from "./argv.js";
import { type ConfirmFn, confirmInteractively } from "./confirm.js";
import {
  buildRevokeConfirmationText,
  type RevokeCandidateSummary,
} from "./format.js";

export interface RevokeIo {
  stdout: Writable;
  stderr: Writable;
}

export interface RevokeDeps {
  /** Defaults to `resolveKnotrustHome()`; injected in tests to a throwaway temp dir. */
  home?: string;
  /** Injected millisecond clock (the audit sink's `nowEpochMs`). Defaults to `Date.now`. */
  nowMs?: () => number;
  /** Injected confirmation gate. Defaults to the real `@clack/prompts` implementation. */
  confirm?: ConfirmFn;
}

/** Mirrors `@knotrust/grants`' private `revoke.ts` `candidatesFor` — read-only, for the PREVIEW shown before confirming (the real mutation always goes through `revokeGrants` itself). */
function candidatesFor(
  selector: RevokeSelector,
  store: GrantStore,
): GrantRecord[] {
  if ("all" in selector) return store.list().active;
  if ("tool" in selector) return store.listBy({ tool: selector.tool }).active;
  const result = store.get(selector.jti);
  return result.status === "active"
    ? [{ jti: selector.jti, token: result.token }]
    : [];
}

function summarize(
  candidates: readonly GrantRecord[],
): RevokeCandidateSummary[] {
  const summaries: RevokeCandidateSummary[] = [];
  for (const { jti, token } of candidates) {
    const claims = parseWireClaims(decodeGrantPayload(token));
    summaries.push({
      jti,
      tool: claims?.tool ?? "(unknown)",
      tierCap: claims?.tier ?? "sensitive",
      agentPattern:
        claims === null ? "?" : claims.agent === "*" ? "*" : claims.agent.id,
    });
  }
  return summaries;
}

export async function runRevoke(
  io: RevokeIo,
  args: RevokeArgs,
  deps: RevokeDeps = {},
): Promise<number> {
  const home = deps.home ?? resolveKnotrustHome();
  const nowMs = deps.nowMs ?? Date.now;
  const confirm = deps.confirm ?? confirmInteractively;

  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const candidates = candidatesFor(args.selector, store);

  if (candidates.length === 0) {
    io.stdout.write("No matching active grants — nothing to revoke.\n");
    return 0;
  }

  const confirmationText = buildRevokeConfirmationText(
    args.selector,
    summarize(candidates),
  );
  io.stdout.write(`${confirmationText}\n`);

  if (!args.yes) {
    const proceed = await confirm(confirmationText);
    if (!proceed) {
      io.stdout.write("Cancelled — no grants revoked.\n");
      return 0;
    }
  }

  const audit = createAuditLog({ home, nowEpochMs: nowMs });
  try {
    // No `onInvalidate` — see this module's header on cross-process
    // revocation semantics (R114).
    const result = revokeGrants(args.selector, { store, audit });
    if (result.notFound) {
      io.stdout.write("No matching active grants — nothing to revoke.\n");
    } else {
      io.stdout.write(
        `Revoked ${result.revoked.length} grant(s): ${result.revoked.join(", ")}\n`,
      );
    }
    return 0;
  } finally {
    // Releases the audit writer's exclusive lock — load-bearing for
    // sequential same-process invocations (see `mint-command.ts`'s identical
    // note).
    audit.close();
  }
}
