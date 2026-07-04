# KnoTrust dogfood — OpenClaw + Knotie (P0-E9)

This directory is the deliverable for **P0-E9-T1** (protect OpenClaw
end-to-end) and **P0-E9-T2** (protect a local Knotie MCP path end-to-end) —
the two "protect our own agents" dogfood tasks (PRD §2). Read this file
first; it is the honest framing every other file here depends on.

## The reality constraint (read this before anything else)

**OpenClaw's real MCP server(s) and the real Knotie MCP path are not
present in this build repo/environment.** They are separate KnoTrust-org
systems. This task therefore does **not** claim that "≥ 3 real OpenClaw
sessions" or "≥ 3 real Knotie sessions" were run against those real systems
— because they were not, and claiming otherwise would be dishonest. Nothing
in this directory, or in the test suite it points to, fabricates a real
session against a system this repo cannot reach.

## What this directory IS

1. **`openclaw/`** and **`knotie/`** — a realistic, hand-reviewed
   `knotrust.config.yaml` for each adopter's plausible tool surface (tiers
   assigned by hand-review across routine/sensitive/critical, per R156),
   plus a `RUNBOOK.md` giving the **exact** commands to run the real dogfood
   once each adopter's MCP server is reachable: `knotrust init` (or this
   directory's config directly), `knotrust -- <server command>`, the
   three-tier walkthrough, `knotrust audit verify`. Those runbooks are the
   owner's script — written to be run, not narrated.
2. **A real, CI-wired, harness-based end-to-end proof** —
   [`test/adversarial/src/dogfood.e2e.test.ts`](../../test/adversarial/src/dogfood.e2e.test.ts)
   — that composes the **fully-built system** (the real proxy, decider,
   grant store, block-and-wait approval channel, the real localhost
   approval page, the real hash-chained audit log — exactly what
   `packages/cli`'s `enforcement.ts` wires together in production) and
   drives it, through the E11-T1 test harness's fake MCP server/client (a
   faithful MCP 2025-11-25 stand-in — not OpenClaw, not Knotie, but the same
   wire protocol and enforcement pipeline either would go through), against
   **these exact two config files**, proving:
   - a **routine** call runs uninterrupted on the fast path (allow,
     forwarded, result relayed);
   - a **sensitive**, un-granted call produces the Requestable Denial —
     `structuredContent.knotrust.requestable.how` names an actionable
     `knotrust grant --tool … --server …` command, with **zero policy
     internals** anywhere in the model-visible frames (the E5-T4 property,
     checked with the real `assertNoLeakedSecrets` scanner, not a bespoke
     substring check);
   - a **critical** call **blocks**, is approved via a **real HTTP POST**
     to the real localhost approval page (not a direct function call), and
     **completes** — the original call's result flows back on the original
     JSON-RPC id;
   - **the real audit-chain verification** (`verifyAuditChain`, the exact
     function `knotrust audit verify` calls) is green afterward, over the
     whole session's hash-chained log.

   It also demonstrates a real, dogfood-discovered cross-cutting issue —
   `E9-I1`, see `FINDINGS.md` — by literally wrapping both adopters'
   configs against one shared `$KNOTRUST_HOME` and showing the second proxy
   fails closed, not open, not hung, not corrupt.
3. **`FINDINGS.md`** — the rough edges and observations this harness-based
   pass actually surfaced while building and running the proof above,
   standing in for "issues filed" (there is no real run to file issues
   *from* — see below).
4. **`knotie/VOICE-FINDINGS.md`** — a short design note (not a build) naming
   a concrete case where a critical mid-voice-call action should return
   `deferred_not_eligible` instead of blocking, feeding Phase 2.

## What this directory is NOT

- **Not** a record of real OpenClaw or Knotie sessions. No terminal capture
  in this directory or its git history was produced by an actual OpenClaw or
  Knotie MCP server.
- **Not** a claim that the acceptance bar's "≥ 3 real sessions" language has
  been literally satisfied against the real systems. It has been satisfied
  against the harness stand-in, which is what "the harness-based dogfood
  proof" means throughout this directory — the honest substitute the task's
  own ratified rulings (R157/R158) call for when the real systems aren't
  reachable.
- **Not** a source of "issues filed" in the literal sense (there is no
  ticket tracker entry this task can point to for a run that didn't happen)
  — `FINDINGS.md` is the equivalent artifact, explicitly scoped as
  harness-sourced.

## Running the harness-based proof yourself

```sh
pnpm --filter @knotrust/adversarial-tests test -- dogfood.e2e.test.ts
```

It also runs as part of `pnpm turbo test` (CI: `.github/workflows/ci.yml`'s
main `lint typecheck test build` job), same as every other suite in
`test/adversarial`.

## Running the real dogfood (the owner's step)

Once OpenClaw's MCP server(s) and/or the real Knotie MCP path are reachable
from wherever you run this: follow `openclaw/RUNBOOK.md` and/or
`knotie/RUNBOOK.md` verbatim, and record the real terminal output as this
task's real-server evidence. File whatever rough edges surface — expect the
real run to surface things a harness stand-in structurally cannot (real
tool semantics, real latency, real crash/error shapes).
