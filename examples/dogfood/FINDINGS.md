# Dogfood findings (P0-E9-T1 / P0-E9-T2)

**Honest scope:** every finding below came from actually building and
running the **harness-based** dogfood proof
(`test/adversarial/src/dogfood.e2e.test.ts`) — driving the real
proxy/decider/approval/audit stack against these two adopters' configs
through the E11-T1 fake MCP server. There is no real-server run to file
issues *from* (see `README.md`); this list stands in for "issues filed," and
is explicitly **not exhaustive** — the real-server dogfood against OpenClaw
and Knotie's actual MCP servers may surface things a harness stand-in
structurally cannot (real tool semantics, real network/process latency,
real crash/error shapes, real client-side agent behavior around the
Requestable Denial and approval-hold UX).

## 1. `E9-I1` — multi-server audit single-writer lock (top finding, R159)

**Status: known, pinned, fails closed (safe).**

`$KNOTRUST_HOME/audit/.lock` is an exclusive, single-writer-process lock
(`packages/store/src/audit-log.ts`, R38 — see
`docs/03-engineering/local-store-layout.md` line 89: "P0 does not support
multiple processes appending to the same log concurrently"). Dogfooding
OpenClaw *and* Knotie is, by construction, **two separate `knotrust --`
proxy processes** — and if both point at the same `$KNOTRUST_HOME` (the
default, unless overridden), the **second** one to start fails at
initialization: `createAuditLog()` throws `"audit log already locked
(<path> by pid <n>) — a second concurrent writer process is not supported
in P0"`, and `knotrust`'s own top-level guard turns that into `"knotrust:
refusing to run — failed to initialize: ..."` and a non-zero exit — **fails
closed**, not open, not hung, not silently corrupting the chain.

This is exactly the kind of thing dogfood exists to surface, and — per
R159 — it already has: `test/adversarial/src/dogfood.e2e.test.ts`'s `E9-I1`
suite demonstrates this literally: wraps OpenClaw's config, then attempts to
wrap Knotie's config against the *same* `$KNOTRUST_HOME` while the first is
still running, and asserts the second attempt fails closed with exactly
this error — then confirms a fresh writer against the same home succeeds
again once the first is torn down (proving it's specifically the
concurrent-lock condition, not general breakage).

**Immediate workaround (documented in both RUNBOOKs):** point each
adopter's `KNOTRUST_HOME` at a distinct directory (`KNOTRUST_HOME=~/.knotrust-openclaw
knotrust -- ...` / `KNOTRUST_HOME=~/.knotrust-knotie knotrust -- ...`) when
running both concurrently. Cost: no unified audit view across adopters
until the real fix lands.

**Recommended resolution direction (P1):** per-server audit scoping —
`$KNOTRUST_HOME/servers/<server>/audit/` with its own lock, keyed by the
same `serverName` `enforcement.ts` already resolves per proxy instance —
rather than a shared-writer daemon/multiplexer (which would add a
background process and an IPC surface this product doesn't otherwise need).
Per-server scoping keeps the existing single-writer-per-log invariant
intact (still one writer per file) while letting N proxies coexist under
one `$KNOTRUST_HOME`; a unified cross-server view becomes a read-side
concern (`knotrust audit query` fanning out across `servers/*/audit/`)
rather than a write-side one. Not attempted here — R160 scopes this task to
integration + docs, not new product code, and this is a real design change
that deserves its own task.

## 2. `init codex` targets a TOML file it doesn't really parse as TOML

**Status: known, documented (R106), not this task's to fix.**

`knotrust init codex` targets `~/.codex/config.toml` (the real path), but
the loader treats it as JSON (`packages/cli/src/init/client-config.ts`'s own
"documented assumption," R106) — a real Codex config file will fail the
JSON parse cleanly rather than silently mis-wiring. Relevant here because if
either adopter's agent client is wired through Codex rather than Claude
Code/Desktop, `knotrust init codex --yes` will not correctly rewrite a real
`config.toml` yet — the runbooks' step 1 alternative (hand-editing / copying
this directory's config directly, option (a)) is the reliable path until
full TOML support lands.

## 3. Zero-config is observe-only, not enforcement — easy to mistake for protection

**Status: known, by design (R73), worth over-communicating in the runbooks.**

A first `knotrust -- <server>` run with **no** `knotrust.config.*` present
wires tool-inventory capture + audit observation only — `tools/call` stays
pure passthrough, **not gated** (R73's deliberate config-gated seam; see
`run.ts`'s own header). Someone dogfooding OpenClaw or Knotie for the first
time who skips the config step (RUNBOOK §1) and jumps straight to `knotrust
-- <server>` will see a real "tool inventory capture and drift detection are
ACTIVE" notice and could reasonably — wrongly — read that as "I'm
protected now." Both RUNBOOKs here call this out explicitly (§2, "if you
instead see the zero-config notice... a zero-config run never gates
tools/call") specifically because this dogfood pass noticed how easy the
misread is.

## 4. Hand-tiering ~7–8 tools per adopter works, but is a manual, per-tool exercise

**Status: ergonomics observation, not a defect.**

Both `knotrust.config.yaml` files in this directory hand-tier 7–8 tools
across three buckets. That was straightforward at this scale (a single
`servers.<name>.tools` block, three tiers, R156's read/write/critical
heuristic). It is not obviously straightforward at OpenClaw or Knotie's
*real*, potentially much larger tool surface — `knotrust add pack` (bundles
+ mandatory diff preview before writing, R119) is the intended scaling path,
but a pack cannot itself express `source: user` fields
(`explicitAllow`/`explicitDeny` are pack-schema-rejected on purpose,
`add/pack-schema.ts`'s own doc-comment) — so the realistic real-adopter flow
is **annotation-seed → apply a pack for the bulk of the surface → hand-pin
the small critical set directly in the config file**, which is exactly the
three-`source`-marker pattern both configs in this directory already
demonstrate. Worth writing up as a "getting started" guide in P1 (docs, not
code) rather than leaving each adopter to discover the pattern independently.

## 5. `requestable.how`'s CLI-invocation assumption

**Status: observation, feeds Phase 2/voice thinking (ties to
`knotie/VOICE-FINDINGS.md`).**

The Requestable Denial's actionable guidance
(`knotrust grant --tool <t> --server <s>`) is genuinely actionable and
conversationally relayable **when the human and the agent session share a
`$KNOTRUST_HOME` and a shell** — true for both dogfood configs here (a local
CLI/desktop session). It is a silent assumption that stops holding the
moment the agent runs somewhere the human doesn't have a terminal open
against the same home (a remote session, or — the sharper case — a voice
call, where there is no CLI for the human to type into at all). This is not
a defect in P0 (out of scope; Phase 1/2 concerns per the roadmap), but it is
the same underlying shape as the `deferred_not_eligible` finding in
`knotie/VOICE-FINDINGS.md` and worth keeping in view together.

## 6. Already mitigated, worth naming: the in-process stale-config-read trap

**Status: not a live issue — flagging the provenance, since it was fixed
*for* this exact task ahead of time.**

`packages/store/src/config.ts`'s `bustNativeRequireCache` fix (fix round 1,
P0-E7-T3 review) names "the upcoming E9 dogfood" directly in its own
doc-comment as the scenario it protects: an in-process reload of a
`.json` config that changed on disk. This dogfood pass's own harness e2e
test loads two *different* config paths (OpenClaw's, Knotie's) in one
process, plus a third loaded-then-reused case in the `E9-I1` suite — no
stale-parse was observed in any of them, confirming the fix holds for the
pattern it was written for.
