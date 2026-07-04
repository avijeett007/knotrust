# `@knotrust/test-harness`

Deterministic integration harness for KnoTrust: a configurable fake MCP
server and a scripted fake MCP client, both speaking **real MCP 2025-11-25
JSON-RPC** (via `@modelcontextprotocol/sdk` 1.x — the same baseline
`packages/proxy-stdio` builds on, per ADR-0006). This is the substrate
P0-E5 (stdio proxy), P0-E6 (approval), P0-E9 (dogfood), and the P0-E11
adversarial battery all build their acceptance tests on (task P0-E11-T1,
rulings R53–R57).

This package builds **only** the harness — server, client, and frame
transcript. It contains no proxy, no policy enforcement, and no assertions
about KnoTrust policy behavior (R57): it is policy-agnostic test
infrastructure. The two acceptance demonstrations in `src/acceptance/` prove
the harness is usable *before* any of the downstream tasks below exist.

## Layout

```
src/
  prng.ts              seeded, deterministic PRNG (mulberry32) — every "random"
                        chaos behavior in this package consumes this, never Math.random()
  frame.ts             Frame type + scanFrames/isMethod/isResponseTo helpers
  fake-server/
    types.ts           FakeServerConfig and every R54 configurability surface
    core.ts            buildFakeServer — the shared core (tools/list pagination,
                        driftAfter, toolBehaviors, callLog, chaos interleaving)
    start.ts           startFakeServer — in-process transport (always) +
                        spawnable child command (opt-in via prepareChildCommand)
    process-entry.ts   child-process entry logic (reads a JSON config file,
                        connects buildFakeServer's core to a real StdioServerTransport)
    bin.mjs            committed, NOT tsc-compiled, plain-JS bootstrap that
                        imports process-entry.ts's compiled dist output —
                        this is the file a proxy spawns as a child process
    call-log.ts         stderr sideband for callLog in child-process mode
  fake-client/
    client.ts           FakeClient — hand-rolled JSON-RPC over a real SDK
                         Transport; frame transcript, tools/list pagination,
                         tools/call, progress-token routing, timeout-without-
                         cancel, and cancel-with-notifications/cancelled
  acceptance/
    baseline.test.ts    R56 demo #1 — proxy-free, REAL spawned child process
    chaos.test.ts       R56 demo #2 — 100-iteration seeded chaos run, in-process
```

## Why the fake server wraps the SDK's `Server`, and the fake client doesn't

The fake **server** (`core.ts`) is a `@modelcontextprotocol/sdk` low-level
`Server` (not the high-level `McpServer` — its own deprecation notice says
"only use for advanced use cases," and drift/chaos/crash/oversized-payload/
callLog are exactly that). Wire correctness (initialize capability
negotiation, JSON-RPC framing, `CallToolResult`/`ListToolsResult` schema
validation) is the SDK's real, spec-conformant implementation; this package
only supplies the configurable *behavior* inside each handler.

The fake **client** (`client.ts`) deliberately does NOT use the SDK's
high-level `Client` class. Two R55 requirements the SDK's `Client` cannot
give us directly:

1. **Every frame, unconditionally.** `client.frames` must capture every
   message sent and received — including malformed/unroutable ones. The
   SDK's `Client`/`Protocol` only surfaces messages through resolved request
   promises and notification handlers; a raw `send`/`onmessage` tap is the
   only place that sees literally everything.
2. **A true "timeout without cancelling".** The SDK's own `Protocol.request`
   timeout path ALWAYS sends `notifications/cancelled` on timeout (it
   shares the same internal `cancel()` closure used for explicit
   `AbortSignal` cancellation — verified by reading
   `dist/esm/shared/protocol.js` in the installed SDK). R55 requires two
   *distinct* simulated behaviors: a client that silently gives up
   (`callToolWithTimeout` — no wire message at all) and a client that
   explicitly cancels (`callToolWithCancel` — sends a real
   `notifications/cancelled`). Only a hand-rolled request layer can produce
   the first; there is no SDK option for it.

Both fake-server and fake-client still ride on the SDK's own `Transport`
implementations (`StdioServerTransport`/`StdioClientTransport`/
`InMemoryTransport`) for actual byte framing, so the wire format is real
throughout — only the request/response bookkeeping above the transport is
hand-rolled on the client side.

## R53 — one config, two transports

```ts
const started = await startFakeServer(config, { prepareChildCommand: true });
// started.inProcess.clientTransport — an InMemoryTransport client end,
//   connected to a real Server instance running in THIS process. Hand it
//   straight to `new FakeClient(started.inProcess.clientTransport)`.
// started.childCommand — argv (e.g. via process.execPath + bin.mjs + a
//   temp config file) for the CALLER to spawn as a real subprocess, e.g.
//   `child_process.spawn(...)` or
//   `new StdioClientTransport({ command: childCommand[0], args: childCommand.slice(1) })`.
//   startFakeServer never spawns this itself — the point is that whoever's
//   child-spawn logic is under test (P0-E5's proxy) does the spawning.
```

`prepareChildCommand` defaults to `false`: preparing it writes a small temp
JSON config file, which the 100-iteration chaos acceptance (in-process only,
per R56) skips paying for on every iteration. Both forms are configured
identically and behave identically from the outside — they are two
*separate* running server instances sharing one config, not one process
wearing two hats (see `start.ts`'s module doc-comment for the full
rationale). A config using a `"custom"` tool-behavior handler (a live JS
closure) cannot cross the process boundary; `isChildProcessCompatible()`
reports this, and `startFakeServer({ prepareChildCommand: true })` throws a
clear error for such a config rather than silently dropping the handler.

## Capability → downstream consumer map

| Harness capability | R ruling | Consumed by |
|---|---|---|
| Child-spawnable `bin.mjs` + `StdioClientTransport`/`StdioServerTransport` real stdio framing | R53 | P0-E5-T1 (child spawn + passthrough), P0-E9 (dogfood) |
| In-process `InMemoryTransport` pair (fast, no subprocess) | R53 | P0-E11-T1's own chaos acceptance; any unit-level test that doesn't need a real subprocess |
| `pagination` (real `nextCursor` across N pages) | R54 | P0-E5-T2 (`tools/list` interception & annotation capture — paginated passthrough) |
| `driftAfter` (rug-pull tripwire: tool annotations/schema change between listings) | R54 | P0-E5-T2, P0-E11 tool-poisoning/rug-pull cases |
| `toolBehaviors` (echo / fixed / isError / delay / crash / oversized / custom) | R54 | P0-E5-T3 (`tools/call` interception → enforcement), P0-E5-T5 (fail-closed crash/error behavior), P0-E11-T2..T6 (malicious-server batteries) |
| Annotation lies (configured `tools[].annotations` contradicting actual behavior — data only, never enforced) | R54 | The proxy's annotation-trust boundary (ADR-0009) — P0-E5-T2 must prove it does NOT trust these |
| `callLog` (every `tools/call` the server actually received) | R54 | P0-E5-T3's acceptance: "a denied call NEVER reaches the server" |
| Seeded PRNG (`prng.ts`, no `Math.random`) driving all chaos delays | R54 | P0-E11-T1's own 100-iteration chaos acceptance; any future chaos-profile reuse |
| `client.frames` (every frame sent/received, ordered) + `scanFrames`/`assertNoLeakedSubstrings`/`assertSentMethodOrder` | R55 | P0-E5-T4 (structured denial envelope, byte-comparable passthrough), the global "no approval token or policy internals in any model-visible content" frame scan (brief §I2.2/§I3) |
| `tools/list` pagination collection (`listAllTools`) | R55 | P0-E5-T1/T2 acceptance (paginated passthrough) |
| Progress-token simulation (`callTool({progressToken, onProgress})`, chaos-interleaved `notifications/progress`) | R55 | P0-E6-T2 (block-and-wait channel — the 10s heartbeat decision D7) |
| `callToolWithTimeout` (silent client give-up, no `notifications/cancelled`) | R55 | P0-E6-T2 (client-side timeout robustness), P0-E9-T3 (latency/timeout budget validation) |
| `callToolWithCancel` (explicit `notifications/cancelled`) | R55 | P0-E6 cancellation handling, P0-E11 adversarial cancel-race cases |

## The two acceptance demonstrations (R56)

Run with `pnpm --filter @knotrust/test-harness test` (or `pnpm turbo test`
from the repo root).

- **`src/acceptance/baseline.test.ts`** — spawns the fake server as a REAL
  child process (`bin.mjs` via `StdioClientTransport`) and drives a full
  `initialize → tools/list (2 pages) → tools/call (echo) → shutdown`
  conversation, asserting every frame is byte-shape-correct JSON-RPC 2.0.
  This is the strongest proof available that the harness speaks real MCP
  2025-11-25 over real stdio framing, not just in-memory object-passing.
- **`src/acceptance/chaos.test.ts`** — 100 consecutive iterations, each with
  a distinct logged seed (`900000`..`900099`), each running a full
  passthrough-shaped conversation with seeded random per-call delays and
  interleaved `notifications/progress`/`notifications/message`. Runs
  **in-process** (no child spawn, no temp-file I/O) specifically to stay
  fast for CI, per R56's explicit allowance; a real run of this suite
  completed all 100 iterations in **~1.8 seconds** (measured locally; see
  the task report for the exact captured figure). On failure, the thrown
  error embeds the failing iteration's seed so it is independently
  reproducible outside the loop.
