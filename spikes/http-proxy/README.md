# SPIKE — stateless HTTP resumption (P0-E10-T1)

**Status: throwaway, non-production, spike-quality. Do not import from here.
Never wired into any `@knotrust/*` package. Not a pnpm workspace member.
Not published (irrelevant to `npm pack` on `packages/cli` — see the
findings doc for the verification).**

This directory exists to answer one question for the Phase-2 HTTP proxy: can
a `critical`-tier tool call that needs human approval be paused on one
proxy replica and resumed on a **different** replica that shares **no**
in-memory state with the first, using only the MCP 2026-07-28 RC's
SEP-2322 (Multi Round-Trip Requests) `InputRequiredResult`/`requestState`
mechanism?

The real deliverable is
[`docs/03-engineering/spike-http-findings.md`](../../docs/03-engineering/spike-http-findings.md).
This code is just what produced the evidence for that doc.

## What's here

- `src/call-hash.mjs` — a **simplified stand-in** for
  `@knotrust/grants`'s real `computeCallHash` (P0-E3-T3,
  `packages/grants/src/callhash.ts`). Deliberately reimplemented small and
  local rather than imported, to keep this spike fully isolated from
  product packages (R164). Production Phase-2 code must use the real,
  frozen, JCS-canonical SARC v1 form, not this stand-in.
- `src/request-state.mjs` — the `requestState` encoding scheme: AES-256-GCM
  encrypt+authenticate, with the authenticated-associated-data (AAD) input
  set to `principal|callHash` (§I2.4's "MAC input binds principal + call
  hash" ruling). See the findings doc for why this is the whole security
  property in one primitive, not a separate string-compare that a future
  engineer could forget.
- `src/policy.mjs` — a two-entry tool→tier map, just enough to make one
  tool `critical` and one `routine`.
- `src/fake-upstream-server.mjs` — a tiny plain `node:http` server standing
  in for the real (already-governed-elsewhere) MCP tool server. Runs as its
  own OS process.
- `src/replica.mjs` — the actual spike: a minimal Hono app implementing
  `POST /mcp` (the normal call path, mints `requestState` on a critical
  call) and `POST /mcp/resume` (the MRTR resume path, verifies + decrypts
  `requestState` and, if approved, forwards to the upstream). Runs as its
  own OS process — two separate instances (`REPLICA_NAME=A`/`B`) are
  spawned as two separate **processes**, not just two JS closures, so "no
  shared in-memory state" is a process-boundary fact, not a promise.
- `src/run-demo.mjs` — spawns the upstream + both replicas as child
  processes, drives the whole flow with real HTTP calls over loopback, and
  prints every step. This is the script the findings doc's captured
  terminal output comes from.

## Running it

```sh
cd spikes/http-proxy
npm install   # standalone install — this is NOT part of the pnpm workspace
npm run demo
```

Everything (upstream + replica A + replica B + the driving client) runs
from that one command; it prints a numbered step for each part of the
flow and exits 0 on success. The shared "KMS" key is a hardcoded demo
value passed to both replica processes via `SHARED_SECRET_HEX` — see the
findings doc for what a real Phase-2 key-management story needs instead.

## Explicitly NOT here (R161 — spike scope discipline)

No tests. No retry/backoff. No real TLS. No persistence layer. No replay
/single-use tracking (noted as a left-open item in the findings doc). No
attempt at the actual MCP JSON-RPC wire shape beyond what's needed to
demonstrate the `InputRequiredResult`/`requestState` mechanics — this is
not a `SpecAdapter` implementation, it's a crypto-and-flow proof.
