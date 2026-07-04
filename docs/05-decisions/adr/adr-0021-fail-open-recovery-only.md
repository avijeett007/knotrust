# ADR-0021: fail-open is a recovery-from-error mechanism, never a normal-operation allow

**Status:** Accepted (2026-07-04)

## Context

P0-E5-T5 closes the stdio proxy epic by codifying PRD §13 / brief §E3's
fail-closed doctrine at the proxy layer (rulings R81–R85): a decision-pipeline
internal error must deny, a wrapped-server crash must never silently degrade
to an ungoverned connection, a proxy fatal error must take its child with it,
and — the one deliberate exception — fail-open, where explicitly configured,
must fire with an audit event every single time.

`packages/store/src/config.ts` already defines `failOpen.routine` (P0-E4-T2)
as a structurally routine-only, opt-in boolean — the schema has no
`sensitive`/`critical` key at all, so a config author cannot even typo their
way into a dangerous fail-open. What P0-E4-T2 did **not** do — because it was
out of scope for a schema-definition task — is specify **when**, precisely,
that boolean is consulted. Two readings are both superficially plausible:

1. **"Fail-open" as a normal-operation degradation mode** — e.g., "if the
   decider is slow, or if we're under load, let `routine` calls through
   without waiting for a real decision," trading latency for governance on
   the theory that routine calls are low-stakes anyway.
2. **"Fail-open" as a recovery mechanism** — the decision path was ASKED to
   decide and it THREW (a genuine internal error — a bug, an unexpected
   `undefined`, an out-of-memory condition inside a dependency, anything that
   is not a normal `allow`/`deny`/`pending_approval`/`deferred_not_eligible`
   outcome) — and, only in that failure, `routine`-tier calls are allowed
   through rather than joining every other tier in a hard deny.

These are not the same feature. Reading 1 treats fail-open as a **latency or
load-shedding** lever a config author reaches for proactively. Reading 2
treats it as a **last-resort recovery** a config author accepts reluctantly,
for one narrow, low-stakes tier, in exchange for the risk that an evaluator
bug means an unaudited-feeling gap in coverage (mitigated by the mandatory
`fail_open_fired` audit event, never by omitting it).

The orchestrator's ruling (R84) is explicit and binding: reading 2 — recovery
only. This ADR records that decision and its rationale, because "fail-open"
is exactly the kind of feature name a future change (or a future engineer
skimming the config schema without this context) could easily misread as
reading 1, and getting this wrong is a genuine security regression, not a
cosmetic one.

## Decision

**Fail-open is a RECOVERY mechanism, never a normal-operation allow.** All
three conditions in R84 must hold simultaneously before a call is ever
allowed through this path:

1. **The tool's tier, resolved independently of the decision path that just
   failed, is `routine`.** `sensitive`/`critical` can never reach this
   branch — structurally impossible per `FailOpenConfigSchema` (no such key
   exists in the schema at all), reasserted at the enforcement layer too
   (`createEnforcer`'s `tryResolveRoutineTier`, `packages/proxy-stdio/src/enforce.ts`)
   as defense in depth.
2. **`failOpen.routine === true` was explicitly configured.** Absent or
   `false` never fails open — opt-in, never an implicit default.
3. **The decision path actually threw.** This is the load-bearing
   distinction from reading 1: there is no code path in `createEnforcer`
   where a NORMAL, successfully-computed `allow`/`deny`/`pending_approval`/
   `deferred_not_eligible` outcome gets reinterpreted through the fail-open
   lens. Fail-open is checked ONLY inside the `catch` block wrapping the
   whole decision path (`getMapping` → `buildDecisionRequest` →
   `decider.decide`) — there is no other entry point into it, by
   construction, not by convention.

On all three: the call is allowed, but **only if** the mandatory
`fail_open_fired` audit event (`tool`, `agent`, `tier`, the internal error's
class/reason — never argument values) can actually be appended. No audit
sink wired, or the sink itself throwing, both fall back to the ordinary
`internal_error` deny — "the audit of a fail-open is not optional" is not a
figure of speech: an unaudited fail-open is strictly worse than a denied
call, in a product whose entire pitch is "fully audited," and the code
enforces that ordering rather than documenting it as a caller's
responsibility.

### Why tie eligibility to an INDEPENDENT tier resolution, not the decider's own

Because the decider is the thing that just threw, it cannot be asked what
tier it would have resolved. `createEnforcer`'s `failOpen` option therefore
carries its own `tierPolicy`/`envelope` — the CLI wiring
(`packages/cli/src/enforcement.ts`) passes the IDENTICAL values it also hands
`createDecider`, so this redundant resolution (via `@knotrust/core`'s
`resolveTierWithEnvelope`) stays consistent with what the decider would have
produced under normal operation, while remaining fully independent of the
decider's own internal state.

## Consequences

- A config author who writes `failOpen: { routine: true }` is opting into
  "if the evaluator breaks, routine calls keep working and I'll see it in the
  audit log" — not "routine calls skip governance to save latency." Any
  future feature request for the latter (a genuine load-shedding /
  latency-budget mechanism) is a DIFFERENT feature, needing its own name,
  its own config key, and its own ADR — it must never be retrofitted onto
  this one by loosening the "thrown error only" condition.
- `docs/03-engineering/failure-modes.md` states this doctrine in its header
  (fail-closed by default; fail-open is explicit, per-class, recovery-only,
  audited every firing; audit-write failure always fails closed) so the
  full failure × behavior × audit × exit-code table has one place that
  frames what every row underneath it is measured against.
- Tested adversarially (`packages/proxy-stdio/src/enforce.test.ts`,
  `enforce.integration.test.ts`): a routine tool under an induced evaluator
  throw fails open with exactly one audited event; a sensitive or critical
  tool under the identical throw and identical config still denies; a
  broken (or absent) audit sink for the `fail_open_fired` event itself
  denies rather than allowing unaudited.

## Alternatives considered

- **A `failOpen.routine` that also degrades proactively under latency
  pressure (a timeout-based fail-open).** Rejected for this task: conflates
  two different risk postures under one config key and one code path, and
  was not what R84 asked for. A genuine timeout/load-shedding feature, if
  ever built, should be its own explicitly-named, separately-audited
  mechanism — not a silent broadening of this one.
- **Making the `fail_open_fired` audit best-effort (swallow a write failure
  and allow anyway), mirroring `denial_probing_suspected`'s best-effort
  audit.** Rejected: probing detection is a secondary signal layered on top
  of an ALREADY-DECIDED response (R78: it must never change what the model
  sees). Fail-open's audit event is not secondary — it is the ONLY record
  that this call bypassed a real decision at all — so it must be able to
  veto the allow itself, not just best-effort log around it.
