# RUNBOOK — dogfooding a local Knotie MCP path through KnoTrust (P0-E9-T2)

> **Status: this is the owner's script, not a session log.** No command in
> this file has been run against the real Knotie path as part of this task —
> that system is not present in this repo/environment (see `../README.md`
> for the full honesty framing). What HAS been run for real is the
> harness-based proof (`test/adversarial/src/dogfood.e2e.test.ts`) against a
> faithful MCP stand-in configured with this exact tool surface.

## 0. Prerequisites

Same as `../openclaw/RUNBOOK.md` §0, substituting the real Knotie MCP path's
launch command for OpenClaw's.

## 1. Get a config in place

Same two options as `../openclaw/RUNBOOK.md` §1 — either copy
`knotrust.config.yaml` from this directory directly (recommended; its tiers
are hand-reviewed per R156 against a plausible Knotie personal-assistant
tool surface — edit `servers.knotie.tools` keys to match Knotie's real tool
names before your first real run), or run `knotrust init --server knotie
--yes` to seed one from Knotie's own tool annotations and hand-review from
there.

## 2. Wrap the real Knotie MCP path

```sh
knotrust -- <knotie server command> [args...]
```

Same enforcement-enabled confirmation and same zero-config caveat as
`../openclaw/RUNBOOK.md` §2.

## 3. The three-tier walkthrough (≥ 3 real sessions)

Identical structure to `../openclaw/RUNBOOK.md` §3, substituting this
config's tool names:

1. **Routine — fast path.** e.g. "what's on my calendar today?" →
   `knotie.get_calendar`. Completes uninterrupted; `knotrust audit tail`
   shows one `decision`, `outcome=allow`, `tier=routine`.
2. **Sensitive, un-granted — Requestable Denial.** e.g. "text Alice that I'm
   running late" → `knotie.send_message`. Blocked with the Requestable
   Denial naming `knotrust grant --tool knotie.send_message --server
   knotie`; confirm the agent relays that back to you conversationally.
   `knotrust audit tail` shows `decision`, `outcome=deny`, `tier=sensitive`.
3. **Critical — block, approve on the page, complete.** e.g. "transfer $50
   to my roommate" → `knotie.transfer_funds`. Holds; approve at the printed
   `http://127.0.0.1:<port>/approve?...` URL; the call then completes.
   `knotrust audit tail` shows the full
   `decision(pending_approval) -> ... -> decision(allow)` chain.

## 4. Verify the audit chain

```sh
knotrust audit verify
```

Same expectation as `../openclaw/RUNBOOK.md` §4.

## 5. File every rough edge

Same process as `../openclaw/RUNBOOK.md` §5 — see `../FINDINGS.md` first,
including `E9-I1`: if you are dogfooding Knotie **at the same time** as
OpenClaw (the realistic scenario this task pairs the two adopters to
surface) and both point at the same `$KNOTRUST_HOME`, the *second* one to
start will fail closed with an "audit log already locked" error — this is
already known and pinned (see `E9-I1` in `../FINDINGS.md` for the
workaround and the recommended fix direction). Point each adopter's
`KNOTRUST_HOME` at a distinct directory as the immediate workaround if you
need both running concurrently before that lands.

## 6. Voice-outcome findings (this task's second purpose)

Knotie is also the future voice-surface muscle memory (brief §E2's fourth
outcome, `deferred_not_eligible`, wired for real in Phase 2). See
`VOICE-FINDINGS.md` in this directory for the concrete trigger case this
dogfood pass identified, and
`docs/04-roadmap/implementation-plan.md`'s Phase 2 outline (§5, after
`P2-E4`) for the pointer tying it to that build.

## 7. What "exercised" already means, honestly

```sh
pnpm --filter @knotrust/adversarial-tests test -- dogfood.e2e.test.ts
```

Same harness-based proof described in `../openclaw/RUNBOOK.md` §6, run
against THIS directory's config and tool surface. Real, CI-wired proof the
product does what steps 1–4 above describe — not a substitute for running
them against the real Knotie path. See `../README.md`.
