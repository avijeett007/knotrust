# RUNBOOK — dogfooding OpenClaw through KnoTrust (P0-E9-T1)

> **Status: this is the owner's script, not a session log.** No command in
> this file has been run against a real OpenClaw MCP server as part of this
> task — that server is not present in this repo/environment (see
> `../README.md` for the full honesty framing). What HAS been run for real
> is the harness-based proof (`test/adversarial/src/dogfood.e2e.test.ts`)
> against a faithful MCP stand-in configured with this exact tool surface.
> Run the steps below against the real OpenClaw MCP server(s) when they are
> reachable, and record the terminal output as this task's real-server
> evidence.

## 0. Prerequisites

- `knotrust` built and on `PATH` (`pnpm turbo build --filter=knotrust`, or
  `npm install -g knotrust` once published).
- The real OpenClaw MCP server command available locally (however OpenClaw
  is normally launched — e.g. `openclaw-mcp-server` or `node
  path/to/openclaw/server.js`).
- Node ≥ 22 (the CLI's floor).

## 1. Get a config in place

Two equally valid starting points — pick one:

**(a) Use this directory's hand-reviewed config directly (recommended).**
Copy `knotrust.config.yaml` from this directory into the working directory
you'll launch `knotrust` from. Its tiers were assigned by hand-review (R156)
against a plausible OpenClaw tool surface; if OpenClaw's real tool names
differ, edit the `servers.openclaw.tools` keys to match before your first
real run — an unlisted tool never gets a silent free pass
(`unknownToolTier: sensitive`), so a rename is a **safe direction to get
wrong** (it fails toward more scrutiny, never less).

**(b) Let `knotrust init` seed one from OpenClaw's own annotations.**

```sh
knotrust init claude --server openclaw --yes
# or: knotrust init codex --server openclaw --yes
```

This auto-detects OpenClaw in your MCP client's config, rewrites it to route
through `knotrust --`, and captures OpenClaw's real `tools/list` (including
its own annotations, e.g. `readOnlyHint`) into a generated
`knotrust.config.yaml` — annotations seed the routine bucket only (never
critical); hand-review and tighten before trusting it, exactly as this
directory's own config was reviewed.

Optionally layer a policy pack on top (`source: pack` entries):

```sh
knotrust add pack ./openclaw-pack.yaml --server openclaw --yes
```

(`add pack` always prints the exact tier diff before writing — confirm it
matches your review before confirming.)

## 2. Wrap the real OpenClaw MCP server

```sh
knotrust -- <openclaw server command> [args...]
```

e.g.:

```sh
knotrust -- openclaw-mcp-server --workspace ~/code/myproject
```

`knotrust` prints `enforcement enabled (config: <path>)` on stderr once it
has found and validated the config above — if you instead see the
zero-config notice ("no knotrust.config found..."), the config file was not
found in the directory you launched from; fix the working directory or pass
one explicitly before proceeding (a zero-config run never gates
`tools/call` — see `../FINDINGS.md`, "zero-config is observe-only").

Point your real agent client (Claude Code, Codex, or whatever wraps
OpenClaw) at this `knotrust --` invocation instead of the bare OpenClaw
command — `knotrust init` (step 1b) already does this rewrite for you; if
you used 1a, do it by hand in your client's MCP server config.

## 3. The three-tier walkthrough (≥ 3 real sessions)

Drive **three separate agent sessions** (or three turns within one — the
acceptance is about tier coverage, not process count) that each exercise one
tier:

1. **Routine — fast path, uninterrupted.** Ask the agent to do something
   that maps to a `routine` tool (e.g. "read `README.md`" →
   `openclaw.read_file`). It should complete with no visible pause and no
   approval prompt. Confirm: `knotrust audit tail` shows one `decision`
   event, `outcome=allow`, `tier=routine`, for that call.
2. **Sensitive, un-granted — Requestable Denial.** Ask the agent to do
   something that maps to a `sensitive` tool you have **not** granted (e.g.
   "edit this file" → `openclaw.write_file`). The call should return an
   error result whose model-visible text says the action was blocked and
   names `knotrust grant --tool openclaw.write_file --server openclaw` as
   how to request access — **relay that to the agent conversationally and
   confirm it says so back to you** (the whole point of the Requestable
   Denial: the agent can explain what happened and what to do, without ever
   seeing a policy internal or an approval token). Confirm: `knotrust audit
   tail` shows one `decision` event, `outcome=deny`, `tier=sensitive`.
3. **Critical — block, approve on the page, complete.** Ask the agent to do
   something that maps to a `critical` tool (e.g. "run this shell command"
   → `openclaw.run_shell`, or "deploy this" → `openclaw.deploy`). The call
   should **hold** — `knotrust` prints an `approve: http://127.0.0.1:<port
   >/approve?...` line on stderr (and, if your client supports progress
   notifications, the agent should tell you it's waiting on approval).
   Open that URL in a browser, review the rendered tool/args/tier summary,
   and click **Approve**. The original agent call should then complete
   normally, exactly as if it had never been intercepted. Confirm:
   `knotrust audit tail` shows the full chain — `decision(pending_approval)
   -> approval_requested -> approval_pending -> approval_approved ->
   grant_created -> grant_consumed -> decision(allow)`.

## 4. Verify the audit chain

```sh
knotrust audit verify
```

Expect `chain intact (N events)` and exit code `0`. If it reports a break,
stop — do not continue dogfooding on a broken chain; escalate as a Critical
bug with the exact `file:line`/`seq`/`kind` it names.

## 5. File every rough edge

Anything that felt wrong, surprising, or like a gap while running the above
— an unclear error message, a tool that should have tiered differently, a
missing flag, an approval-page rendering issue — gets filed as an issue in
the org's real issue tracker (not this repo's task-planning corpus).
`../FINDINGS.md` lists what the **harness-based** dogfood pass already
surfaced (including one already-known, already-pinned cross-cutting issue,
`E9-I1`, that a real two-adopter dogfood run — OpenClaw *and* Knotie
wrapped at the same time — will hit immediately if both point at the same
`$KNOTRUST_HOME`); start there, and expect the real-server run to surface
more that a harness stand-in structurally cannot (OpenClaw-specific tool
semantics, real latency, real error shapes from a real server crash, etc.).

## 6. What "exercised" already means, honestly

`test/adversarial/src/dogfood.e2e.test.ts` runs this exact tool surface (via
`examples/dogfood/openclaw/knotrust.config.yaml`, loaded and validated for
real) through the real proxy/decider/approval/page/audit stack, driven by
the E11-T1 harness's fake MCP server standing in for OpenClaw's wire
protocol. Run it yourself:

```sh
pnpm --filter @knotrust/adversarial-tests test -- dogfood.e2e.test.ts
```

That is real, CI-wired proof the *product* does what steps 1–4 above
describe. It is not a substitute for running steps 1–4 against the real
OpenClaw MCP server — see `../README.md`.
