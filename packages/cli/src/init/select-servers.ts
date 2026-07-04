/**
 * knotrust CLI `init` — interactive server selection (P0-E7-T1, R107/R110).
 *
 * shadcn init playbook: auto-detect over prompting. Interactive selection is
 * therefore the LAST resort, reached only when the caller has neither
 * `--yes` (wrap all, zero prompts) nor `--server <name>` (target one, zero
 * prompts) — see `command.ts`'s `resolveSelection`. When it IS reached, this
 * is the one place `@clack/prompts` (R110) is used: a `multiselect` over the
 * wrappable server names, every one pre-selected (wrapping everything is the
 * default outcome; the user deselects what they don't want).
 *
 * `SelectServers` is a plain injectable function type specifically so this
 * real, TTY-driven prompt is NEVER exercised by an automated test (which
 * would otherwise hang waiting on stdin in CI) — every test in this package
 * either passes `--yes`/`--server` (bypassing selection entirely) or injects
 * a deterministic fake `SelectServers` via `InitOptions.selectServers`
 * (`command.ts`). The real `@clack/prompts`-backed implementation below is
 * exercised only by a human running `knotrust init` interactively.
 */

import * as clack from "@clack/prompts";

/** Given the wrappable server names (pre-selected `preselected`), resolves to the subset the user actually wants wrapped this run. */
export type SelectServers = (
  candidates: readonly string[],
  preselected: readonly string[],
) => Promise<string[]>;

/** Thrown when the user cancels the prompt (Ctrl-C / Esc) — `command.ts` treats this as a clean abort, no write. */
export class ServerSelectionCancelledError extends Error {
  constructor() {
    super("knotrust: server selection cancelled — no changes written.");
    this.name = "ServerSelectionCancelledError";
  }
}

/**
 * The real, `@clack/prompts`-backed selector. Every candidate starts
 * pre-selected (wrapping everything is the documented default outcome of
 * `init`, matching `--yes`'s behavior — interactive mode differs only in
 * letting the user deselect some before confirming).
 */
export const selectServersInteractively: SelectServers = async (
  candidates,
  preselected,
) => {
  const chosen = await clack.multiselect({
    message: "Select MCP servers to route through knotrust:",
    options: candidates.map((name) => ({ value: name, label: name })),
    initialValues: [...preselected],
    required: false,
  });
  if (clack.isCancel(chosen)) {
    throw new ServerSelectionCancelledError();
  }
  return chosen;
};

/**
 * The "never overwrite an existing knotrust.config without confirmation"
 * seam (R109). Resolves `false` on cancel (Ctrl-C/Esc) — same as an explicit
 * decline — since a cancelled prompt is never a green light to write.
 */
export type ConfirmOverwrite = () => Promise<boolean>;

export const confirmOverwriteInteractively: ConfirmOverwrite = async () => {
  const answer = await clack.confirm({
    message:
      "An existing knotrust.config already has suggested tiers for these " +
      "server(s) — overwrite it with the freshly-captured suggestions?",
  });
  if (clack.isCancel(answer)) return false;
  return answer;
};
