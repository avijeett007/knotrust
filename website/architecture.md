# Architecture

> New here? This page describes how KnoTrust is built internally. For a
> plain-language explanation of what it does and why, see the
> [Introduction](/guide/introduction) first.

## Overview

KnoTrust is a **Policy Enforcement Point (PEP)** — a thin enforcement edge
in front of the MCP action surface. It maps every `tools/call` into a
`DecisionRequest`, resolves it through a **surface-agnostic decision core**,
and enforces the outcome: allow, deny, hold for human approval, or defer.
It is not itself a policy engine — it *fronts* one.

The load-bearing structural principle: **enforcement surfaces are plugins
that produce `DecisionRequest`s into a core that knows nothing about MCP.**
The stdio proxy is surface #1 today. A streamable-HTTP proxy, an SDK, and
(later) client-native hooks and an OS-sandbox broker are future surfaces
that reuse the exact same core, unchanged — the core has zero dependency on
MCP types, checked as an architectural boundary, not just a convention.

```
 Enforcement surfaces (plugins)              @knotrust/core (pure TS, no MCP types)
 ┌─────────────────────────────┐             ┌───────────────────────────────────┐
 │ #1 stdio proxy (flagship)    │             │ Tier evaluator                     │
 │ #2 streamable HTTP proxy     │  Decision   │ Precedence engine                  │
 │ #3 SDK (TS, then Python)     │──Request───▶│ Grant verifier (Ed25519 JWS)        │
 │ future: client hooks,        │             │ Decision cache                     │
 │ sandbox broker               │             │ Approval orchestrator              │
 └─────────────────────────────┘             │ PDP interface                       │
                                              └───────────────┬─────────────────────┘
                                                              │
                          ┌───────────────────────────────────┼──────────────────────┐
                          ▼                                   ▼                      ▼
                 PDP implementations                Approval channels        Local stores (files)
                 L0 built-in · Cedar-WASM            form / URL elicitation   grants · policy ·
                 (opt-in) · AuthZEN-HTTP · OPA        block-and-wait · push    hash-chained audit
```

**Data flow, in one sentence:** surface → `DecisionRequest` → cache lookup
(fast path) → on a miss, tier + precedence + grants + policy engine →
outcome → (if `critical` and uncovered) approval orchestrator → channel →
resolution → ephemeral grant minted → re-evaluate → outcome enforced on the
wire → an audit event appended at every step along the way.

## The `DecisionRequest` contract

Every surface's only door into the core is a single, versioned internal
contract — `DecisionRequest` — carrying:

- **Subject / Action / Resource / Context (SARC)** — the AuthZEN
  information model. The human principal lives in `subject`; the agent's own
  identity lives as a sibling in `context.agent`, **never merged into
  `subject`** — the two must stay distinguishable.
- **Surface metadata** — which surface produced this request (`stdio_proxy`,
  `http_proxy`, `sdk`, …) and what it knows about the transport.
- **Tool annotations, explicitly marked untrusted** — a server's own
  self-declared `readOnlyHint`/`destructiveHint` flow through as *seeds*
  for a suggested risk tier, typed so the "never trust these outright" rule
  is enforced by the type system, not just a comment.

The core never imports anything MCP-shaped; the stdio proxy's own adapter is
what translates JSON-RPC into this contract.

## The four decision outcomes

The core returns exactly one of four outcomes for every request:

| Outcome | What happens on the wire |
|---|---|
| <span class="outcome outcome-allow">allow</span> | Transparent pass-through — the client sees the real server's result, unmodified. |
| <span class="outcome">deny</span> | Synthesized as an MCP **tool execution error** (`isError: true`), reusing the client's original request id — never a raw JSON-RPC protocol error, so the model can see and adapt to it in-context. |
| <span class="outcome">pending_approval</span> | Returned only when a call can't be held open synchronously (a URL-mode handoff, an async/voice surface, stateless HTTP) — carries a handle the caller can poll or await. |
| <span class="outcome">deferred_not_eligible</span> | A first-class "this isn't available right now" — e.g. a critical action attempted mid voice-call, where holding synchronously would degrade the call. |

`block_and_wait` (the universal approval floor — see
[Core Concepts](/guide/core-concepts#approvals-block-and-wait)) holds the
call open and resolves it to a terminal `allow`/`deny` directly, rather than
surfacing `pending_approval` at all.

## The stdio proxy (surface #1)

`knotrust -- <server command>` is zero-daemon, single-session, and has no
resident process: it reads config, spawns the real MCP server as a child
process, and wires three pipes — client→proxy, proxy→child, and
child→proxy/client — framing JSON-RPC one message per line.

- **Every `tools/call` body is parsed and decided** — headers are never
  trusted for an allow/deny decision, on principle, even once future MCP
  transports carry routing headers.
- **`tools/list` is passed through unmodified**, while the proxy snapshots
  each tool's annotations to seed suggested tiers and to detect drift
  (a tool that quietly starts behaving differently after trust is
  established — a "rug-pull") on the next capture.
- **Everything else** — `initialize`, `resources/*`, `prompts/*`,
  notifications, progress, cancellation — passes straight through in real
  time.
- **Fail-closed, always.** If the wrapped server crashes, an in-flight call
  resolves to `deny`, never a silent allow. Malformed JSON-RPC gets a real
  protocol error (the one legitimate use of that channel); everything else
  that goes wrong on the decision path fails closed by default, with
  fail-open reserved for explicitly-configured, always-audited `routine`
  classes only.

## The grant model

A **grant** is a pre-satisfied prerequisite — signed Ed25519, serialized as
compact JWS (`alg: EdDSA`), verified fully offline against a local public
key. Durable grants are minted ahead of time (`knotrust grant`); ephemeral,
single-use grants are minted automatically the instant a human approves a
critical escalation, and are bound to a hash of the exact call that was
approved. See [Core Concepts](/guide/core-concepts#signed-grants) for the
full model and the precedence rules that keep a grant from ever
self-escalating.

## Caching & the fast path

The "sub-millisecond common case" comes from a local decision cache keyed on
a canonical, hashed form of the SARC request — subject, action, resource,
agent, tier, plus the current policy and grant-set versions, so **any**
policy or grant change automatically invalidates the relevant keys rather
than serving something stale. `routine` calls get a long TTL (default 1h);
`sensitive` calls get a short one (≤ 60s, bounding any stale-grant window);
`critical` calls are **never** cached — every one re-derives from scratch.

## Audit pipeline

Every decision — allow, deny, a cache hit, an approval-lifecycle
transition, a fail-open firing — appends one event to an append-only,
hash-chained JSONL log, exportable over OpenTelemetry/OTLP (SigNoz as the
reference receiver). See
[the audit trail](/guide/core-concepts#the-audit-trail) and
[Security](/security#tamper-evident-not-tamper-proof) for exactly what that
guarantees and what it doesn't.

## Package layout

KnoTrust ships as a single `knotrust` npm package; internally, the codebase
is a pnpm + Turborepo monorepo split by responsibility, bundled together at
publish time so a first-time user only ever installs one package:

| Package | Responsibility |
|---|---|
| `@knotrust/core` | Surface-agnostic decision core: the `DecisionRequest` contract, tier evaluator, precedence engine. Zero MCP imports. |
| `@knotrust/pdp` | The policy-decision-point adapter interface and registry, with the built-in `L0` evaluator as the default. |
| `@knotrust/grants` | Ed25519 identity and signed grant mint/verify (JWS Compact), durable and ephemeral grant lifecycle. |
| `@knotrust/store` | Local file-based state: the grants directory store, config loading, the hash-chained audit log. |
| `@knotrust/proxy-stdio` | The MCP stdio proxy: child spawn/passthrough, `tools/list` interception, `tools/call` enforcement. |
| `@knotrust/approval` | The approval orchestrator: lifecycle state machine, the block-and-wait channel, the localhost approval page. |
| `@knotrust/otel` | An OpenTelemetry OTLP exporter for decision spans and audit events — off by default. |
| `knotrust` (the CLI) | The `knotrust` command itself — the runner, `init`, `grant`/`revoke`, `add` — bundling every package above at publish time. |

## What's next on this core

Everything above is the Phase 0/1 surface: the stdio proxy, local mode, and
the built-in `L0` policy engine. The same decision core is designed to grow
new surfaces without changing itself — a streamable HTTP proxy for stateless
transports, a TypeScript (then Python) SDK for framework-native
integrations, and, further out, client-native hooks and an OS-sandbox broker
that would make enforcement non-cooperative rather than config-dependent.
None of that is required to use KnoTrust today; it's what "surface-agnostic
core" is actually for.
