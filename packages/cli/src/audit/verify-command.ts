/**
 * knotrust CLI `audit verify` (P0-E4-T4, R122/R124) — chain integrity over
 * every `<yyyymm>.jsonl` file.
 *
 * Runs the LOCK-FREE `verifyAuditChain` (never `AuditSink.verify()`, which
 * would require constructing a full sink and holding `audit/.lock` — see
 * `@knotrust/store`'s own doc-comment on `verifyAuditChain` for why a
 * read-only forensic command must stay usable concurrently with a live
 * writer). On success, prints `"chain intact (N events)"` and returns exit
 * 0 (R122's exact wording). On a break, names the file, line, seq, and kind
 * of the FIRST break and returns non-zero (R124's headline acceptance).
 */

import type { Writable } from "node:stream";
import { resolveKnotrustHome } from "@knotrust/grants";
import { verifyAuditChain } from "@knotrust/store";

export interface AuditVerifyIo {
  stdout: Writable;
  stderr: Writable;
}

export interface AuditVerifyDeps {
  /** Defaults to `resolveKnotrustHome()`; injected in tests to a throwaway temp dir. */
  home?: string;
}

export function runAuditVerify(
  io: AuditVerifyIo,
  deps: AuditVerifyDeps = {},
): number {
  const home = deps.home ?? resolveKnotrustHome();
  const result = verifyAuditChain(home);

  if (result.ok) {
    io.stdout.write(`chain intact (${result.events} events)\n`);
    return 0;
  }

  const { file, line, seq, kind } = result.breakAt;
  io.stderr.write(
    `knotrust audit verify: chain BROKEN — first break at ${file}:${line} ` +
      `(seq ${seq}): ${kind}\n`,
  );
  return 1;
}
