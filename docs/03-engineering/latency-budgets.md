# Latency validation: budgets vs measured (P0-E9-T3)

The phase-exit gate's latency proof: a benchmark harness measuring the
**added** latency the knotrust proxy imposes — proxy-on minus proxy-off — for
five paths, against the ratified budget table (rulings R150-R154), backing
PRD §13's "sub-ms cached fast path" claim with a real number rather than an
assertion.

Harness: `test/bench/` (the `@knotrust/bench` workspace package). Substrate:
the REAL `@knotrust/proxy-stdio` proxy, the REAL unified
`@knotrust/grants` decider, the REAL `@knotrust/core` decision cache, the
REAL file-backed grant store + hash-chained audit log
(`@knotrust/store`), a REAL Ed25519 file `KeyStore`, and the P0-E11-T1
harness fake server/client (`@knotrust/test-harness`). No product code was
changed to produce these numbers (R154) — this task only measures and
reports.

## The ratified budget table

| Path | Budget (added, p95) |
|---|---|
| Cache-hit `allow` (routine fast path) | ≤ 5 ms |
| Cache-miss L0 eval incl. one grant verify (Ed25519) | ≤ 15 ms |
| Non-gated message passthrough (list/progress/etc.) | ≤ 10 ms |
| Audit append (amortized per event) | ≤ 2 ms |
| Proxy ready-to-serve after spawn (excl. `npx` install) | ≤ 750 ms |

## Methodology (R151 — read this before quoting a number)

**"Added latency" = (round-trip WITH the knotrust proxy in the path) MINUS
(round-trip DIRECT to the fake server, no proxy).** Both runs are driven by
the same `@knotrust/test-harness` `FakeClient` against the same
`FakeServerConfig` (two tools, `routine_tool` and `sensitive_tool`, plus
whatever `tools/list` reports). Concretely, for the three round-trip paths:

- **proxy-ON** (`test/bench/src/fixtures/proxy-on.ts`): `FakeClient` ↔
  (in-memory `PassThrough` pair) ↔ `createStdioProxy` (real async
  `tools/call` enforcement wired via `createEnforcer`/`createDecider`) ↔
  (real spawned child process, real stdio framing) ↔ the fake MCP server.
- **proxy-OFF** (`test/bench/src/fixtures/proxy-off.ts`): `FakeClient` ↔
  (real spawned child process, real stdio framing, `StdioClientTransport`)
  ↔ the SAME fake MCP server config directly — no proxy in the path at all
  (mirrors `test/harness/src/acceptance/baseline.test.ts`'s own R56
  proxy-free baseline).

**Why the proxy-ON client-facing hop is in-memory, and what that means for
the numbers below (read this before quoting a number):**
`createStdioProxy`'s child-facing hop is ALWAYS a real spawned OS process
(baked into `packages/proxy-stdio/src/proxy.ts` — the same spawn cost a
production `knotrust -- <server>` run pays), and both the proxy-ON
harness's child-facing hop and the proxy-OFF harness's ONLY hop talk to the
identical fake-server child over that identical real stdio mechanism — so
JSON-RPC request/response framing is exercised for real, end-to-end, on the
server/child side in both runs. What is NOT real on the proxy-ON side is
the CLIENT-facing hop: `FakeClient` ↔ proxy talks over an in-memory
`PassThrough` pair — JSON-RPC framing/parsing still happens, there is just
no OS pipe underneath it. A production deployment puts a REAL OS pipe on
that side too (the client process talks to the `knotrust` proxy process
over its own real stdio/IPC channel, not an in-memory stream). Subtracting
proxy-ON's total from proxy-OFF's total therefore isolates the proxy's own
classify/relay/async-enforcement compute plus a ~0-cost in-memory hop on
the client-facing side — it does NOT include the real OS-pipe round-trip a
production client↔proxy connection actually pays on that same side.

**These added-latency figures are consequently a LOWER BOUND on the full
client-observed added latency in production, not the true added-latency
figure.** A real deployment adds roughly one more real OS-pipe round-trip
(client-process ↔ proxy-process) on top of everything measured here —
sub-millisecond, but real, and not zero. (An earlier version of this doc
justified the in-memory client-facing hop by calling a second real pipe a
"double-count against a single-hop baseline" — that reasoning was wrong:
the client↔proxy hop and the proxy↔server hop are two genuinely different
hops in a real deployment, not the same hop counted twice, so the
in-memory simplification here is a real, acknowledged gap in what's
measured, not a double-counting correction.)

This does not change any pass/fail conclusion in the table below. Even
adding a generous ~0.5 ms stand-in for that missing real IPC hop, all three
round-trip paths (1-3, below) still pass their budgets with a large
margin: cache-hit `allow` ~0.6 ms vs. the 5 ms budget (~8x margin instead
of the reported 56x), cache-miss L0 eval ~1.8 ms vs. the 15 ms budget (~8x
margin instead of the reported 11x), non-gated passthrough ~0.5 ms vs. the
10 ms budget (~20x margin instead of the reported 910x). Paths 4-5 (audit
append, proxy ready-to-serve) are absolute measurements, not
proxy-on-minus-off deltas (see below), so this particular
client-facing-hop caveat does not apply to them the same way. A reviewer
who wants the real (rather than lower-bound) number for paths 1-3 can
re-run `test/bench` with the client-facing hop swapped for a second real
spawn/pipe (the harness's `fixtures/proxy-on.ts` is the one place that
would change) and compare.

**Measured start/end, per path:**

1. **Cache-hit `allow`** — `client.callTool("routine_tool", <fixed args>)`,
   timed start-to-resolved-response. The harness's own first call against a
   fresh proxy is unavoidably a cache MISS (nothing cached yet); that one
   call is absorbed into the discarded warm-up (`warmupIterations >= 1`), so
   every MEASURED iteration is a genuine decision-cache hit — zero
   grant-store reads, `cacheHit: true` on the decision's audit event.
2. **Cache-miss L0 eval + one grant verify** — `client.callTool
   ("sensitive_tool", { callId: "call-<n>" })` with a FRESH `callId` every
   iteration (mapped to `resource.id` via the tool's COAZ-style `mapping`),
   so the decision-cache key is different every time — a guaranteed miss,
   warm-up included. The proxy-ON harness minted exactly one durable grant
   scoped `idPattern: "call-*"`, so each miss runs the real
   collect-covering-grants → precedence → exactly one real Ed25519
   `verifyGrant` → allow path.
3. **Non-gated passthrough** — `client.listToolsPage()` (a `tools/list`
   request — not a `tools/call`), which the proxy's SYNCHRONOUS
   classify→forward path relays without ever touching the
   decider/cache/grants.
4. **Audit append (amortized)** — see "Why paths 4 and 5 are absolute, not a
   delta" below.
5. **Proxy ready-to-serve after spawn** — see the same section.

**Warm-up / iteration counts / percentile method:** every path warms up
first (iterations run and discarded — JIT/connection warm-up, "warm
process" per R150) and then times `warmupIterations >= 100` (paths 1-3),
`>= 50` (path 4), or `>= 5` (path 5, since every iteration is a real process
spawn) real, discarded warm-up calls, followed by `>= 1000` MEASURED
iterations per path (R150's acceptance floor), each timed individually with
`performance.now()` (monotonic, sub-millisecond resolution). Percentiles are
nearest-rank over the ascending-sorted measured sample (`test/bench/src/
stats.ts`'s `summarize`/`percentileOfSorted`) — no interpolation. "Added
latency's p95" is **the proxy-ON run's p95 minus the proxy-OFF run's p95**
(and likewise p50/p99) — two independently-computed percentiles subtracted,
NOT a per-iteration pairwise delta (the two runs are not time-paired; R151
itself describes "run both, subtract" at the aggregate level).

### Why paths 4 and 5 are absolute measurements, not a proxy-on-minus-off delta

R151's delta methodology presumes a "proxy-off" baseline that does the same
user-visible thing without the proxy. Two of the five paths have no such
baseline:

- **Audit append** — with the proxy off, no audit event is written at all;
  "proxy-off" is not zero-cost by coincidence, it is *undefined* (the
  operation doesn't happen). This path instead measures
  `@knotrust/store`'s real `createAuditLog().append()` directly: a real
  temp-dir-backed, hash-chained JSONL log, batched (non-`"immediate"`)
  fsync, each `append()` call timed individually so "amortized" reflects
  the real mix of cheap in-memory writes and the periodic batched fsync —
  never a synthetic wall-clock/N average that would hide fsync spikes.
- **Proxy ready-to-serve after spawn** — with no proxy, there is nothing to
  spawn. This measures, per iteration, exactly the span from calling
  `proxy.start()` (child spawn begins) to the client's `initialize`
  handshake resolving (the first request the proxy actually serves);
  per-iteration setup/teardown (building the fake-server config, closing
  everything down) is excluded from the timed span
  (`measureAsyncSelfTimed`, `test/bench/src/iterate.ts`). "excl. `npx`
  install": the spawned command is a direct `node <bin.mjs>` invocation
  (`@knotrust/test-harness`'s `childCommand`), never routed through `npx`'s
  own package-resolution/download overhead.

## Honest environment caveat (R152 — read before trusting these numbers)

**This is NOT the dedicated, isolated reference machine the acceptance
criterion's "on the reference machine" language refers to.** These numbers
were measured on the machine that happened to implement this task:

| | |
|---|---|
| Machine | Apple MacBook Air, Apple M4, 10 CPU cores, 16 GiB RAM |
| OS | macOS (Darwin), arm64 |
| Node.js | v22.23.1 |
| Load | An interactive developer laptop mid-session — NOT a dedicated, quiesced benchmark box; background processes (editor, other tooling) were running throughout |

This is a **fast** consumer machine (Apple Silicon M4), not a shared/noisy CI
runner and not necessarily representative of a typical user's or a
shared-CI reference machine's hardware — numbers here could plausibly be
*better* than a slower or more contended machine would produce, and a shared
CI runner is typically noisier (more p99 jitter from neighboring workloads)
than this box was during the run. **The formal reference-machine validation
this acceptance criterion ultimately wants is an OWNER step** (run
`pnpm --filter @knotrust/bench bench` on the actual designated reference
machine and paste its output into this section, or a follow-up section
below it) — what follows is this task's own honest, real, unfudged run on
this environment, not a substitute for that.

Two independent full runs (each ≥1000 measured iterations/path, run
back-to-back on 2026-07-04) produced consistent results — reported below is
the second run; both runs are summarized in the "run-to-run stability" note
after the table.

## Measured vs budget

Ran via `pnpm --filter @knotrust/bench build && pnpm --filter @knotrust/bench bench` (`test/bench/src/run-bench.ts`). Full raw output (both runs) is in the task report; `test/bench/results/latest.json` (gitignored — regenerated per run) holds the full machine-readable numbers for whichever run was most recent locally.

| Path | Budget (added, p95) | Measured p50 | Measured p95 | Measured p99 | Pass/Fail | Notes |
|---|---|---|---|---|---|---|
| Cache-hit `allow` | ≤ 5 ms | 0.049 ms | **0.089 ms** | 0.503 ms | **PASS** (56x margin) | ON p50/p95/p99 = 0.109/0.169/0.696 ms; OFF = 0.060/0.080/0.193 ms. |
| Cache-miss L0 + 1 grant verify | ≤ 15 ms | 1.197 ms | **1.335 ms** | 4.850 ms | **PASS** (11x margin) | ON p50/p95/p99 = 1.248/1.421/5.046 ms; OFF = 0.051/0.086/0.196 ms. |
| Non-gated passthrough | ≤ 10 ms | 0.005 ms | **0.011 ms** | 0.104 ms | **PASS** (910x margin) | ON p50/p95/p99 = 0.057/0.078/0.283 ms; OFF = 0.052/0.067/0.179 ms. |
| Audit append (amortized) | ≤ 2 ms | 0.007 ms | **0.010 ms** | 0.015 ms | **PASS** (200x margin) | Absolute measurement (see methodology) — not a delta. |
| Proxy ready-to-serve after spawn | ≤ 750 ms | 72.108 ms | **76.941 ms** | 97.671 ms | **PASS** (9.7x margin) | Absolute measurement (see methodology) — not a delta. |

All 1000-iteration measured samples; warm-up counts per path are documented
in the methodology section above. Every path meets its ratified p95 budget
on this machine, with the tightest margin (proxy-ready-to-serve, ~9.7x) still
comfortable.

**Run-to-run stability:** a first full run (also ≥1000 iterations/path,
run immediately before the reported one) produced: cache-hit added p95 =
0.076 ms; cache-miss added p95 = 1.255 ms; passthrough added p95 = 0.009 ms;
audit-append p95 = 0.010 ms; proxy-ready p95 = 74.709 ms — all within ~15%
of the reported run's numbers, and every path passed in both runs. This is
NOT a substitute for a dedicated reference-machine run (a truly noisy shared
CI runner could still push p99/p95 higher, especially for the process-spawn
path) but it is real evidence these are not one-off flukes.

## R154 — no perf bug found, nothing flagged

No path exceeded its budget, let alone by a wide, repeatable margin. There is
no finding to flag here, and no product code was touched to produce these
numbers (R154's "do not tune product code to hit a number" was never in
tension with anything observed — every path already passed by a wide
margin). One honest observation, not a finding: the cache-miss path's p99
(4.85 ms) is noticeably higher than its own p50 (1.2 ms) — most likely GC
pauses / OS scheduling jitter on a shared developer laptop rather than
anything algorithmic (the whole distribution, p50 through p99, still sits
comfortably under the 15 ms budget), but a reference-machine run with a
larger, quieter sample is the right place to confirm that read.

## How to run this yourself

- **Smoke test** (part of `pnpm turbo build test lint typecheck`; seconds,
  not minutes; tiny iteration counts — proves the harness runs and produces
  real numbers, per-path, but is NOT a budget check):
  ```
  pnpm --filter @knotrust/bench test
  ```
- **The real ≥1000-iteration/path run** (what this doc's numbers come from;
  takes roughly 60-90 seconds on the machine above — dominated by the
  proxy-ready-to-serve path's 1000 real process spawns):
  ```
  pnpm --filter @knotrust/bench build
  pnpm --filter @knotrust/bench bench
  ```
  Prints a human-readable table to stdout and writes the full
  machine-readable result (with environment info) to
  `test/bench/results/latest.json` (gitignored). Iteration counts are
  overridable via `BENCH_ROUND_TRIP_WARMUP`/`BENCH_ROUND_TRIP_MEASURED`/
  `BENCH_AUDIT_WARMUP`/`BENCH_AUDIT_MEASURED`/`BENCH_SPAWN_WARMUP`/
  `BENCH_SPAWN_MEASURED` env vars for a faster local dry run — the defaults
  above are what actually satisfies R150's ≥1000 floor and are what this
  doc reports; never lower them to make a number look better.

## CI trend job (R153 — soft-fail on shared runners, hard bar is the reference machine)

`.github/workflows/ci.yml`'s `bench-trend` job runs the real
`pnpm --filter @knotrust/bench bench` run on every push/PR, on GitHub's
shared `ubuntu-latest` runners, and uploads the resulting
`test/bench/results/latest.json` as a workflow artifact (`bench-results-<run
id>`) — a record of the trend over time, downloadable/diffable across runs.
The job's steps are **non-blocking**: `continue-on-error: true` on the bench
step itself, so a noisy/contended shared runner producing a slow run (GitHub
Actions runners are 2-vCPU shared hardware, nothing like a dedicated
reference machine, and can be 3-10x slower or jitterier than a quiet
developer laptop) never fails the build or blocks a merge. This is
deliberate, matching R153 exactly: **hard pass/fail numbers require a
dedicated reference machine (an owner-run step, not CI)**; CI's job is only
to keep recording the trend so a genuine regression (a step change between
runs, not routine shared-runner noise) is visible over time to whoever is
watching, without ever gating anyone's merge on shared-runner noise.

A follow-up (not in this task's scope, and not required by R153's literal
text) would compare each run's artifact against the previous run's and post
a warning comment on drift beyond some threshold — noted here as a
recommendation, not implemented, since automating trend-regression detection
is a separate, larger piece of work than "the CI job exists and reports the
trend."
