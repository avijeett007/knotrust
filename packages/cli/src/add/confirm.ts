/**
 * knotrust CLI `add pack` — the interactive confirmation gate (P0-E7-T3,
 * R119: never silent-apply — every write confirms unless `--yes`).
 *
 * Same tiny, injectable-function pattern as `grant/confirm.ts` and
 * `init/select-servers.ts`'s `ConfirmOverwrite` — duplicated locally rather
 * than cross-imported from a sibling command group, mirroring this repo's
 * established convention for a tiny shared shape (see e.g. `run.ts`'s own
 * note on the two independent `resolveKnotrustHome` copies, or
 * `pack-schema.ts`'s duplicated `CoazStyleMapping` shape). `add` is meant to
 * stay a self-contained reusable core for P1's `add pdp`/`add pack <name>`
 * (R121) — reaching into `grant/` for a confirmation helper would cut against
 * that. The real, TTY-driven `@clack/prompts` implementation is exercised
 * only by a human running `knotrust add pack` interactively; every test
 * either passes `--yes`/`--dry-run` or injects a deterministic fake.
 */

import * as clack from "@clack/prompts";

/** Shows `message` and resolves to whether the human approved. Resolves `false` on cancel (Ctrl-C/Esc) — same as an explicit decline, never a green light to write. */
export type ConfirmFn = (message: string) => Promise<boolean>;

export const confirmInteractively: ConfirmFn = async (message) => {
  const answer = await clack.confirm({ message });
  if (clack.isCancel(answer)) return false;
  return answer;
};
