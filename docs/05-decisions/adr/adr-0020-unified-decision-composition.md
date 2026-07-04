# ADR-0020: unified decision composition — one canonical decider in `@knotrust/grants`

**Status:** Accepted (2026-07-04)

## Context

P0-E5-T3 (`tools/call` → `DecisionRequest` → enforcement) is the heart of the
product: the stdio proxy intercepts every `tools/call`, parses the full JSON-RPC
body into a `DecisionRequest`, runs it through a decision, and enforces the
outcome (allow forwards; deny/pending/deferred short-circuit with a synthesized
same-`id` result the child never sees).

The whole-branch review flagged that, before this task, there were **two
disjoint decision entry points and neither was complete** (seam obligation
E5-I1):

- `@knotrust/core`'s `createDecisionPipeline().decide()` — cache + a
  `PdpAdapter`, but **no** grant collection, single-use consume, or audit.
- `@knotrust/grants`' `decideWithGrants()` — grant collection + single-use
  consume + fail-closed audit, but **no** cache.

The proxy needs BOTH in one path. Two further seam obligations rode along:
E5-I2 (the cache must exclude all consume-dependent / transient outcomes) and
E5-I3 (the classifier/relay is synchronous but enforcement is asynchronous).

A binding constraint (R68): if unifying the two entry points could not preserve
the `PdpAdapter` boundary (ADR-0018) for Phase 1 without a core change, STOP and
return NEEDS_CONTEXT rather than silently breaking the adapter seam.

## Decision

**Build ONE canonical decider — `createDecider` in `@knotrust/grants`
(`decider.ts`) — that the proxy calls, and leave `createDecisionPipeline` in
core unchanged as the cache + `PdpAdapter` PRIMITIVE.**

### Home and composition order (E5-I1, R68)

The decider lives in `@knotrust/grants` because that is the one package that
already imports core (cache, precedence, ULID) AND store (grant store, audit)
AND owns the grant lifecycle. `createDecider({ cache, tierPolicy, envelope,
policyVersion, store, audit, resolvePublicKey, nowEpochSeconds, nowMs,
generateId }) → decide(request): Promise<DecisionResponse>` composes, in order:

1. Resolve the tier ONCE via `resolveTierWithEnvelope` (core's exported,
   envelope-aware, floor-clamped resolution — never re-derived).
2. `cache.get`, keyed with the EFFECTIVE policy version — the caller's
   config-epoch `policyVersion` fused with a SHA-256 fingerprint of
   `{ tierPolicy, envelope }` (the R20 rule). Because `tierPolicy`/`envelope`
   are fixed per decider instance, the fingerprint is computed ONCE at
   construction (the pipeline memoizes per-request because it takes them per
   request; the decider does not need to).
   - **HIT** → audit ONE `decision` event with `cacheHit: true` (E5 pinned) and
     return, with ZERO grant-store reads.
3. **MISS** → `decideCore` (the shared collect → precedence → single-use
   consume/replay algorithm, now exported from `lifecycle.ts` and reused by both
   `decideWithGrants` and the decider — one body, one source of truth).
4. Audit the decision FAIL-CLOSED: an `AuditUnavailableError` from `append()`
   converts the decision to `deny`/`audit_unavailable`, re-audited best-effort
   (R40 doctrine).
5. `cache.set`, GATED by `isCacheableDecision` (E5-I2, below).

The decider REUSES core's cache PRIMITIVE (`createDecisionCache`'s `get`/`set`),
the single tier resolution, and the R20 fingerprint scheme — so cache-key
semantics are identical to the pipeline's. It does **not** wrap
`createDecisionPipeline().decide()`, because the grants + consume + audit +
cacheability-gating seam sits EXACTLY between `cache.get` and `cache.set`, which
the pinned pipeline flow deliberately does not expose (its `cache.set` is
unconditional beyond the tier/outcome guard).

### Cacheability exclusions (E5-I2, R69)

`isCacheableDecision(decision, decidingGrantSingleUse)` is the explicit
predicate gated on before `cache.set`. Beyond the pinned cache's own
tier/outcome guard, it excludes: non-`allow`/`deny` outcomes; `critical` tier; a
**single-use `grant_allow`** (`decidingGrantSingleUse`, signalled by the decider
having consumed a grant to produce the allow — caching it would replay the
single-use grant forever); `grant_replayed` (a function of the consumed-ledger
state, not of request+policy); and `audit_unavailable` (a transient failure).
The rule, stated positively: cache ONLY outcomes that are a pure function of
`(request, policy, NON-single-use grants)`.

### Async relay, ordering-preserving (E5-I3, R70)

The sync `ClassifierHook` (passthrough + `observe`) is left intact — `tools/list`
observation and all other passthrough keep their E5-T1/T2 fidelity. Enforcement
is added as a DEDICATED async seam (`EnforcementHook`) the relay AWAITS only for
client→server `tools/call` requests. The ordering model is **per-request async**:
a held `tools/call` blocks ONLY its own response; every other message
(notifications, other requests, responses) continues to flow synchronously.
MCP clients correlate by JSON-RPC `id`, so a routine call decided after a held
one may legitimately answer first — safe, not a client-visible reorder bug.
Backpressure is preserved: the eventual forward/synthesize uses the same
transport `send()` (resolves on drain) the synchronous path uses.

### The `PdpAdapter` boundary is preserved (no NEEDS_CONTEXT)

Step 3 evaluates precedence DIRECTLY (via `decideCore` → `evaluatePrecedence`),
the L0 default — exactly as `decideWithGrants` already did, so no new dependency
edge is introduced (grants has always imported `evaluatePrecedence`). The
`PdpAdapter` port (core's `pdp-port.ts`) and `createDecisionPipeline` are
UNCHANGED. Phase 1 (P1-E2-T1) threads an injected `PdpAdapter` into the decider
by turning `decideCore`'s `evaluatePrecedence(...)` call into
`adapter.decide(request, ctx)` and giving the decider an `adapter` dep — a P1
injection needing ZERO core change. Unification therefore did NOT break the
adapter seam; the STOP/NEEDS_CONTEXT condition did not arise.

## Consequences

- The proxy has ONE decision function to call; there is no second, incomplete
  path to keep in sync. `decideWithGrants` is untouched (its 180+ tests stay
  green) — the decider reuses its extracted `decideCore` rather than replacing
  it, and owns its OWN enriched (`latencyMs`/`cacheHit`) fail-closed audit.
- E5-I1's proof is a spanning integration test composing the REAL cache + REAL
  grant store + REAL hash-chained audit log + the decider (miss→allow cached,
  hit→allow with zero grant-store reads, covering-grant allow, single-use
  consumed exactly once, revoke+bump → fresh deny, exactly one decision event
  per decide incl. cache hits). The plan acceptance is proven end-to-end through
  the proxy + a real spawned fake server.
- Enforcement is CONFIG-GATED at the CLI: a real `knotrust.config.*` enables it;
  a zero-config run stays transparent passthrough (T1/T2) with a notice. This is
  a deliberate deviation from a literal "zero-config → default L0 enforcement"
  reading, taken because (a) the P0-E5-T1 passthrough acceptance must stay green
  and (b) silently denying every tool on a user's first zero-config run is a bad
  adoption default. A future toggle can flip zero-config to enforce.

## Alternatives considered

- **Wrap `createDecisionPipeline().decide()` inside the decider.** Rejected: the
  grants/consume/audit/cacheability seam is precisely between the pipeline's
  `cache.get` and `cache.set`, which the pinned flow does not expose, and the
  E5-I2 exclusions (single-use / replayed / audit_unavailable) cannot be
  expressed through the pinned cache's tier/outcome-only guard.
- **Widen the synchronous `ClassifyResult` into a `respond` union and make
  `classify()` async.** Rejected in favour of a dedicated async `EnforcementHook`
  (R70 explicitly permits "a dedicated async intercept"): it keeps the sync
  classifier's purity and the T1/T2 observation fidelity untouched, and confines
  all async decision plumbing to one place.
- **Move the decider into core.** Rejected: core imports neither store nor
  grants (boundary-gated, ADR-0018), and must not — the decider needs the grant
  store and audit sink, which live above core.
