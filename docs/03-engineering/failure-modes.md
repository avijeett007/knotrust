# Fail-closed crash & error behavior (the stdio proxy)

Codifies PRD §13 / brief §E3's fail-closed doctrine at the proxy layer
(P0-E5-T5; rulings R81–R85), closing the stdio proxy epic (P0-E5). This is
the map of every failure this surface names, what the proxy actually does
about it, what the calling agent (the MCP client) sees on the wire, what
lands in the audit log, and what exit code the `knotrust` process reports.

## Doctrine (read this first)

**Fail-closed by default.** Anything the decision path cannot resolve to a
normal outcome — a thrown error anywhere in tier resolution, grant
collection, precedence, cache, `DecisionRequest` mapping, or the audit
append itself — resolves to a `deny`, never an `allow`. A crash in the
wrapped MCP server never silently degrades the client to an ungoverned
direct connection (there is nothing to degrade to on stdio; the contract is
simply: no ungoverned path, ever). A fatal error in the proxy itself always
takes its child down with it — an orphaned, ungoverned server that outlives
its own governor is the one outcome this doctrine treats as categorically
unacceptable, worse than any single denied call.

**Fail-open is the ONE deliberate exception, and it is narrow on purpose**
(ADR-0021 has the full rationale). It applies only when ALL of the
following hold simultaneously:

- the tool's tier — resolved **independently** of the decision path that
  just failed (the failed path cannot be asked) — is `routine`;
- `failOpen.routine === true` was **explicitly** configured (absent/`false`
  never fails open — opt-in, never implicit);
- the decision path **actually threw** (fail-open is a RECOVERY from a
  thrown internal error, never a reinterpretation of a normal, successfully
  computed `allow`/`deny`/`pending_approval`/`deferred_not_eligible`
  outcome).

`sensitive`/`critical` tools can never fail open — structurally impossible
per the on-disk config schema (`FailOpenConfigSchema` has no such key at
all) and reasserted at the enforcement layer too, as defense in depth.

Every fail-open firing appends a `fail_open_fired` audit event — **every
single time**, never silently — and that audit append is itself mandatory,
not best-effort: if it fails (or no audit sink is wired at all), the call
falls back to the ordinary `internal_error` deny. An unaudited fail-open is
strictly worse than a denied call, in a product whose whole pitch is "fully
audited" — so the code enforces that ordering, it does not merely document
it as a caller's obligation.

## The table

| # | Failure | Proxy behavior | Wire result (what the client sees) | Audit event | Exit code |
|---|---|---|---|---|---|
| 1 | **Decision-pipeline internal error** — a thrown error anywhere in `getMapping`/`buildDecisionRequest`/`decider.decide` (tier resolution, grant collection, precedence, cache, resource mapping) | Caught at the ONE enforcement boundary (`createEnforcer.handle`, `packages/proxy-stdio/src/enforce.ts`); resolved to `deny`; the child NEVER receives the call | Synthesized `CallToolResult` (`isError: true`), safe reasonCode `unavailable` (R75 mapping folds `internal_error` into it — never the raw error/stack; frame-scan clean) | ONE best-effort `type: "decision"` event, `outcome: "deny"`, `reason: "internal_error"` | n/a (the proxy process itself is unaffected — this is a per-call outcome) |
| 2 | **Audit-append failure** — the audit sink itself throws while trying to record event #1's own deny (or the decider's own internal audit, `AUDIT_UNAVAILABLE`) | Deny STANDS regardless (R40/R81 doctrine: "if audit ALSO fails, still deny — never allow on error"); the failed append is swallowed, not retried inline | Same as #1 — the model never learns whether its OWN audit line landed | The attempted event is lost for this call; the NEXT successful `append()` on a healed sink emits `audit_recovered` (`@knotrust/store`, R38) documenting the gap | n/a |
| 3 | **Child spontaneous crash** (no in-flight call at the moment it dies) | `handleChildClose()` → `teardown("child_exit")`; no orphan (R60 ladder was never needed — the child is already gone) | Nothing pending to answer; the client simply stops receiving traffic from this server | none new (nothing was in flight) | **Non-zero** (`run.ts`'s `runProxy` maps `reason === "child_exit"` → exit `1`, never a silent `0`) |
| 4 | **Child crash mid-call** (`crash:exit`, `kill -9`, or any other death while a `tools/call` is in flight) | The relay tracks every client→server REQUEST forwarded to the child (`pendingChildRequests`, `packages/proxy-stdio/src/proxy.ts`); on the child's `close` (or an immediate failed `send()` to an already-dead child), every still-pending request gets a synthesized same-`id` JSON-RPC error BEFORE the client-facing transport closes — the client is never left hanging | A JSON-RPC **error** response (code `-32000`, "the wrapped MCP server disconnected before responding to this call") for that call's `id` — not a hang, not a silent drop | none new for this event itself (the ORIGINAL call, if it had reached enforcement, already has its own decision event; the crash-error synthesis is a transport-layer guarantee, not a policy decision) | **Non-zero** (same `child_exit` mapping as #3) |
| 5 | **Proxy uncaught exception** | `process.on("uncaughtException", ...)` (installed alongside SIGTERM/SIGINT in `run.ts`'s `runProxy`, same `installSignalHandlers` gate) terminates the child (`proxy.stop("SIGTERM")`, the existing R60 SIGTERM→SIGKILL ladder) BEFORE the process exits | n/a — the client's transport tears down along with the process; whatever was in flight is answered by #4's own bookkeeping first if it was a tracked request | none new (this is a process-lifecycle event, not a decision) | Exit `1` (a `fatalCode` set synchronously before teardown, so it wins even if the child's own `onClose` fires first — see `run.ts`'s ordering note) |
| 6 | **Proxy SIGTERM/SIGINT** (an external signal to the running `knotrust` process) | Propagated to the child (`proxy.stop(signal)`) — the SAME R60 escalation ladder: explicit signal sent immediately, then the SDK's own stdin-EOF→2s→SIGTERM→2s→SIGKILL ladder, then a 3s safety-net reap check. Verified end to end against a REAL spawned child: gone within 5s, ps-verified | n/a — the process is shutting down deliberately | none new | `0` (a requested, deliberate shutdown — not a failure) |
| 7 | **stdin EOF** (the real client hangs up) | `teardown("client_eof")` — the SAME graceful ladder as #6, no explicit signal (the child gets a chance to shut down cleanly via stdin EOF first) | n/a | none new | `0` |
| 8 | **Fail-open fired** — a `routine` tool, `failOpen.routine: true`, the decision path threw | The call is ALLOWED (forwarded to the child) instead of denied | The child's REAL response — indistinguishable on the wire from an ordinary allow (this is the point: routine work keeps working) | ONE `fail_open_fired` event — `tool`, `agent`, `tier: "routine"`, the internal error's class/reason (JSON-encoded in `reason`) — **no argument values** (forensic only) | n/a |
| 9 | **Fail-open eligible, but the `fail_open_fired` audit append itself fails** (or no audit sink is wired at all) | Falls back to the ordinary `internal_error` DENY (#1) — "the audit of a fail-open is not optional" | Same as #1 | The `fail_open_fired` event never lands; the fallback `internal_error` deny is still best-effort audited as a normal `type: "decision"` event (#1's own row) | n/a |

## Why the SDK's exit code isn't literally mirrored (row 3/4)

The task's plan literally names "mirror the child's exit code where
sensible." The official `@modelcontextprotocol/sdk`'s `StdioClientTransport`
does **not** surface the child's actual numeric exit code through its
public API: reading the installed SDK source
(`dist/esm/client/stdio.js`), the underlying `child_process` `'close'`
event's `code` argument is received and immediately discarded —
`this._process.on('close', _code => { this._process = undefined;
this.onclose?.(); })`. Reaching into that class's private `_process` field
to recover it would be a fragile, undocumented coupling to SDK internals
this repo deliberately avoids elsewhere (ADR-0019 commits to composing the
SDK's public transport surface, not patching around it). A **fixed non-zero
exit code** is therefore the "where sensible" realization: it always
signals failure distinctly from a clean `0`, satisfies the acceptance bar
exactly as stated ("the proxy exits non-zero"), and is honestly documented
here rather than silently approximated.

## Acceptance cases this table proves (by name)

- **kill-9-mid-call → client-error + proxy-nonzero-exit** — row 4, tested
  against a REAL spawned child (both the harness's `crash:exit` self-directed
  `process.exit(1)` AND a literal external `SIGKILL` sent by the test) —
  `packages/proxy-stdio/src/proxy.test.ts`, `packages/cli/src/run.crash.test.ts`.
- **evaluator-throw → internal_error deny + audit** — row 1, tested with an
  adversarial throwing decider/mapping stub, both in isolation
  (`enforce.test.ts`) and against a real spawned child + real hash-chained
  audit log (`enforce.integration.test.ts`).
- **fail-open-routine → allow + fail_open_fired** — row 8, same real-child +
  real-audit-log rigor, plus the sensitive/critical-never-fails-open and
  broken-audit-denies adversarial cases (rows 8/9) — `enforce.test.ts`,
  `enforce.integration.test.ts`.
- **kill-proxy → child-gone-in-5s-no-orphan** — row 6, `ps`-verified (not
  just a signal-0 probe) — `proxy.test.ts`; plus a real-process SIGTERM sent
  to the running `knotrust` invocation itself (the production
  `installSignalHandlers` wiring, not `proxy.stop()` called directly) —
  `run.crash.test.ts`. Row 5 (uncaught exception / unhandled rejection) is
  proven the same way via `process.emit(...)`, the standard technique for
  exercising these handlers without genuinely crashing the test runner.

## References

- `packages/proxy-stdio/src/enforce.ts` — rows 1, 2, 8, 9 (the R81 broadened
  catch and R84's fail-open seam; see the module's own doc-comment for the
  full design).
- `packages/proxy-stdio/src/proxy.ts` — rows 3, 4 (the R82 in-flight
  request bookkeeping, `pendingChildRequests`/`failPendingChildRequests`)
  and the R60/R83 SIGTERM→SIGKILL escalation ladder rows 5–7 build on.
- `packages/cli/src/run.ts` — rows 3–7 (the R82(ii) exit-code mapping and
  the R83 `uncaughtException`/`unhandledRejection` fatal-error handlers).
- `packages/cli/src/enforcement.ts` — wires `config.failOpen.routine` and
  the shared `tierPolicy`/`envelope` through to `createEnforcer`'s
  `failOpen` option (row 8/9's real-config path).
- ADR-0021 (`docs/05-decisions/adr/adr-0021-fail-open-recovery-only.md`) —
  the binding "recovery-only, never normal-operation" doctrine this table's
  header states.
- ADR-0019 (`docs/05-decisions/adr/adr-0019-stdio-proxy-transport-relay.md`)
  — why this repo composes the SDK's transport surface rather than patching
  it, the reasoning behind the fixed-exit-code choice above.
- `docs/03-engineering/local-store-layout.md` §"audit/" — the hash-chained
  audit log's own fail-closed contract (`AuditUnavailableError`, R38, D6)
  that row 2 rests on.
