/**
 * knotrust CLI `grant`/`revoke` — the interactive confirmation gate (P0-E7-T2,
 * R111/R114/R116). All mutations confirm unless `--yes`.
 *
 * `ConfirmFn` is a plain injectable function type for exactly the same
 * reason `init/select-servers.ts`'s `SelectServers`/`ConfirmOverwrite` are:
 * so the real, TTY-driven `@clack/prompts` implementation is NEVER exercised
 * by an automated test (which would otherwise hang on stdin in CI). Every
 * test in this package either passes `--yes` (bypassing this entirely) or
 * injects a deterministic fake via the command's own `deps.confirm`. The
 * real implementation below is exercised only by a human running `knotrust
 * grant`/`knotrust revoke` interactively.
 */

import * as clack from "@clack/prompts";

/** Shows `message` (the plain-words confirmation text) and resolves to whether the human approved. Resolves `false` on cancel (Ctrl-C/Esc) — same as an explicit decline. */
export type ConfirmFn = (message: string) => Promise<boolean>;

export const confirmInteractively: ConfirmFn = async () => {
  // The confirmation TEXT itself is printed by the caller (unconditionally,
  // even under --yes — R116: transparency is never gated). This prompt is
  // only the y/n GATE, so it asks a short, generic question rather than
  // re-echoing the (already-printed) text into clack's own message box.
  const answer = await clack.confirm({ message: "Proceed?" });
  if (clack.isCancel(answer)) return false;
  return answer;
};
