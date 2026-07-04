# ADR-0019: stdio proxy — SDK-transport relay, not high-level `Server`+`Client`

**Status:** Accepted (2026-07-04)

## Context

P0-E5-T1 is the FLAGSHIP surface's first task: `knotrust -- <server-cmd>` spawns
the real MCP server as a child process and proxies stdio JSON-RPC in both
directions. This task is transport-only — a byte/shape-faithful transparent
relay with a classifier SEAM that P0-E5-T2 (tools/list capture) and P0-E5-T3
(tools/call → `DecisionRequest` → enforcement) hook later. No interception or
enforcement is built here.

Architecture §4.1 names the punkpeye/mcp-proxy pattern: "compose SDK `Server`
(client-facing) + `Client` (child-facing)." Orchestrator ruling **R58** required
this task to actually verify that pattern can pass EVERY message type through
faithfully — `initialize`, `tools/list`, `tools/call`, notifications
(`progress`/`cancelled`), `ping`, `resources/*`, `prompts/*`, sampling, AND any
method the SDK does not model — with `id` correlation preserved. R58 further
directed: if the SDK's high-level `Server` cannot do opaque passthrough of
arbitrary methods, drop to a transport-level relay and **document the split
precisely** (this ADR); and if even that cannot achieve faithful passthrough,
STOP rather than silently drop methods. It does achieve faithful passthrough, so
this ADR records the split rather than a NEEDS_CONTEXT.

## Decision

**The proxy composes the SDK's TRANSPORT layer, not its high-level `Server`/
`Client` (`Protocol`) classes.** Concretely (`packages/proxy-stdio/src/proxy.ts`):

- **Client-facing:** a `StdioServerTransport` bound to the proxy's own
  stdin/stdout (injectable in tests). It reads the real MCP client's messages
  and writes responses/notifications back.
- **Child-facing:** a `StdioClientTransport` that spawns `serverCommand` as a
  child process, inheriting the full parent environment plus any `env` overrides
  (architecture §4.2: stdio MCP auth is env-based; MCP §8 exempts stdio from
  OAuth). Its `stderr: "pipe"` handle is `.pipe(sink, { end: false })`-ed to the
  proxy's own stderr so arbitrary child logging passes straight through in real
  time (architecture §4.1), without the child's stderr close ending the sink.
- **The relay** pumps each parsed `JSONRPCMessage` from one transport to the
  other, unchanged, through the classifier SEAM (`classifier.ts`). In P0-E5-T1
  the sole `ClassifyResult` is `{ action: "passthrough" }`. The relay switches
  exhaustively on `result.action`, so T2/T3 adding a variant is a compile error
  until the relay handles it — the seam cannot be extended silently.

### Why NOT the high-level `Server`+`Client`

The SDK's `Server`/`Client` extend `Protocol`, which **dispatches requests by
registered handler**: an unregistered method returns a `MethodNotFound` (-32601)
error rather than being relayed (`shared/protocol.js`: `handler =
_requestHandlers.get(method) ?? fallbackRequestHandler`, else MethodNotFound).
Worse for a transparent proxy, `Server` **bakes in its own `initialize` and
`ping` handlers** (`server/index.js`: `_oninitialize` returns *the proxy's own*
`getCapabilities()`/`serverInfo`; `Protocol` pre-registers `ping`). So a
high-level composition would:

1. Answer the client's `initialize` with the PROXY's capabilities and
   serverInfo, never relaying the child's real handshake — capability
   negotiation would be silently rewritten.
2. Answer `ping` itself.
3. `MethodNotFound` every method without a registered handler — `resources/*`,
   `prompts/*`, sampling, and any future/unknown method — unless each is
   explicitly modeled and capability-gated.

A `fallbackRequestHandler` does not rescue this: `initialize` and `ping` are
pre-registered and never reach the fallback, so the handshake and liveness
checks are still answered locally, not relayed. Faithful passthrough of the
child's real `initialize` is therefore structurally impossible at the high
level. The transport layer, by contrast, does the real MCP line framing and
JSON-RPC parse/serialize and nothing else — exactly what a faithful relay needs.

The typed-`tools/call` access R58 valued in the SDK-composition pattern (for
T3's enforcement) is **still available**, at the SEAM: the classifier hook
receives the fully-typed `JSONRPCMessage` (aliased as `JsonRpcMessage`), so T2/T3
inspect/redirect `tools/list`/`tools/call` there without the proxy itself
running a `Protocol`.

## Fidelity analysis (the "byte-comparable modulo intercepted messages" bar)

A message crossing the proxy is parsed by the receiving transport
(`JSON.parse` → `JSONRPCMessageSchema.parse`) and re-serialized by the sending
transport (`JSON.stringify`). Fidelity of that round trip:

- **Requests / notifications:** `JSONRPCRequestSchema`/`JSONRPCNotificationSchema`
  are `.strict()` at the top level (only the standard `jsonrpc`/`id`/`method`/
  `params` keys, which is all a real message carries) but their `params` is
  `BaseRequestParamsSchema.loose()` — **passthrough**, so `_meta`, `name`,
  `arguments`, `cursor`, progress tokens, and any nested field survive intact.
- **Success responses:** `result` is `ResultSchema = z.looseObject(...)` —
  **passthrough**, so every tool result field (content, `isError`, `_meta`,
  arbitrary extra keys) survives intact.
- **Error responses:** `JSONRPCErrorResponseSchema` relays `code`/`message`/
  `data` faithfully. **One narrow caveat:** its inner `error` object is a plain
  (stripping) `z.object`, so a non-standard key placed DIRECTLY inside `error`
  (beyond `code`/`message`/`data`) would be dropped. This is the sole
  non-faithful edge; it does not affect any standard MCP message, the E11
  acceptance vectors, or real servers (which put extra detail under
  `error.data`, which IS relayed).

"Byte-comparable" is realized as **shape-comparable**: the acceptance compares
the parsed messages the client observes with vs. without the proxy
(`FakeClient.frames`, deep-equal via `toEqual`). Zod may reorder object keys
during parse, but the client normalizes both paths through the same
`JSONRPCMessageSchema.parse`, so the observed frames are deep-equal. The
proxy-through path adds one idempotent parse+serialize hop and injects nothing;
P0-E5-T1's acceptance test (a) confirms the two transcripts are `toEqual`.

## Consequences

- `@knotrust/proxy-stdio` gains a real runtime dependency on
  `@modelcontextprotocol/sdk` (client + server stdio transports, `JSONRPCMessage`
  type). It is a `private` package, bundled into the published CLI via tsup
  `noExternal` (ADR-0016), so it may use a `catalog:` specifier.
- The published `knotrust` CLI declares `@modelcontextprotocol/sdk` as its one
  genuine third-party **runtime `dependency`**, with a **concrete `^1.29.0`**
  specifier (never `catalog:`), and marks it `external` in tsup. Rationale: the
  SDK's own transitive tree (`cross-spawn`, `zod`, …) is left for the consumer's
  package manager rather than inlined, and `npm pack` (which, unlike
  `pnpm publish`, does not rewrite `workspace:`/`catalog:` specifiers) stays
  clean — the E1-T3 manifest discipline. `pack-manifest.mjs` continues to strip
  `devDependencies` (which carry the `workspace:*`/`catalog:` specifiers) for the
  packing window.
- Shutdown/lifecycle (R60) rides the SDK `StdioClientTransport.close()` ladder —
  stdin-EOF → 2s → SIGTERM → 2s → SIGKILL — with a proxy-side reap safety-net so
  `stop()` never resolves with the child still alive (no orphan). Precise
  child-exit-code mirroring is deferred to P0-E5-T5, which hardens crash
  semantics; T1 exits 0 on clean teardown.
- The classifier SEAM is the single insertion point for T2/T3. Adding a
  non-passthrough `ClassifyResult` variant is a compile error at the relay's
  exhaustive switch until handled.

## Alternatives considered

- **High-level `Server`+`Client` composition (architecture §4.1's literal
  wording).** Rejected for faithful passthrough: rewrites the `initialize`
  handshake to the proxy's own capabilities, self-answers `ping`, and
  `MethodNotFound`s every unmodeled/unknown method — it cannot relay the child's
  real handshake or arbitrary methods opaquely (see "Why NOT" above). R58
  explicitly anticipated and authorized this fallback.
- **Raw line-level byte pump (no SDK at all).** Rejected: it would be
  byte-faithful but reimplements framing the SDK already does correctly, and
  gives T3 no typed message to enforce on. The SDK-transport relay is faithful
  AND hands T2/T3 typed messages at the seam — R58's stated reason for
  preferring an SDK-based design.
- **Hybrid: high-level `Server` with `fallbackRequestHandler` for non-tool
  methods.** Rejected: `initialize`/`ping` are pre-registered and bypass the
  fallback, so the handshake is still not relayed; and a single transport has one
  `onmessage`, so a `Protocol` and a raw relay cannot both consume the same
  stream. More moving parts, strictly less faithful.

## References

- Architecture §4.1 (proxy data-flow: line framer → classifier →
  [adapter→core | pass-through]; punkpeye/mcp-proxy pattern), §4.2 (process
  model, env-based stdio auth).
- Orchestrator rulings R58 (SDK composition vs. raw pump — this decision),
  R59 (proxy API + classifier seam), R60 (shutdown/lifecycle), R61 (CLI runner +
  bundling), R62 (harness-based acceptance).
- `packages/proxy-stdio/src/proxy.ts`, `packages/proxy-stdio/src/classifier.ts`
  — the relay and the seam.
- `packages/cli/src/run.ts`, `packages/cli/src/bin.ts` — the CLI runner.
- `@modelcontextprotocol/sdk` 1.29.0: `shared/stdio.ts` (`ReadBuffer`,
  `serializeMessage`/`deserializeMessage`), `client/stdio.ts`
  (`StdioClientTransport` spawn + close ladder), `server/stdio.ts`
  (`StdioServerTransport`), `types.ts` (`JSONRPCMessageSchema` — the fidelity
  analysis above), `shared/protocol.ts`/`server/index.ts` (handler dispatch,
  baked-in `initialize`/`ping`).
- ADR-0016 (tsup CLI bundling), ADR-0002 (single published artifact),
  ADR-0015 (ESM-only).
