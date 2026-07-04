# Introduction

## What is KnoTrust?

KnoTrust is a **local-first policy enforcement and human-approval layer for
the Model Context Protocol (MCP)**. It sits between an MCP client (Claude
Desktop, Codex CLI, or any MCP-native agent) and the real MCP server it's
talking to, watches every `tools/call`, and decides — in real time — whether
that call should run, be refused, or wait for a human.

Concretely, it ships as a single `knotrust` CLI. Its flagship surface is a
**stdio proxy**: you wrap an MCP server's launch command in `knotrust --`,
and from then on every tool call that server would have run instead passes
through KnoTrust's decision core first.

```sh [Terminal]
knotrust -- node my-mcp-server.js
```

## The problem it solves

Agents increasingly *act*, not just answer — and they act through MCP:
Stripe, databases, deploy pipelines, payment rails. Today, giving an agent
that kind of access means picking between two bad options:

- a coarse OAuth scope granted once at connect time and never revisited, or
- a client that nags for approval on *every* call — which trains people to
  click "allow" without reading, and then to turn approval prompts off
  entirely (often called "YOLO mode").

Neither option is auditable, and neither is portable: a native client's own
allowlist is per-client, per-call, and it's the first thing YOLO mode
bypasses.

KnoTrust's approach: encode a durable, risk-tiered, portable grant **once**,
enforce it server-side regardless of the client's approval mode, and keep a
record of everything the agent attempted — including in YOLO mode. Most
calls a session makes are routine and safe; KnoTrust's job is to stop
re-litigating those every single time, while still catching and holding the
rare action that actually needs a human's attention.

## The four decision outcomes

Every `tools/call` KnoTrust intercepts resolves to exactly one of four
outcomes:

| Outcome | Meaning |
|---|---|
| <span class="outcome outcome-allow">allow</span> | The call is forwarded to the real server, transparently. |
| <span class="outcome">deny</span> | The call is blocked and never reaches the server. The agent sees a structured, in-context refusal it can adapt to — not a raw protocol error. |
| <span class="outcome">pending_approval</span> | The call is awaiting an out-of-band human decision (used when the call can't be held open — e.g. a URL-mode handoff, or an async/voice surface). |
| <span class="outcome">deferred_not_eligible</span> | The call needs human approval, but the current context can't support it (e.g. a critical action attempted mid voice-call) — a first-class "not right now," not a crash. |

Read more in [Core Concepts](/guide/core-concepts) and the full
[system architecture](/architecture).

## The grant: KnoTrust's core primitive

A **grant** is a pre-satisfied prerequisite — `{principal, agent, tool,
resource scope, conditions, risk tier, granted_by, expiry, single_use}` —
signed with Ed25519 (JWS Compact, `alg: EdDSA`) so it can be verified fully
offline, with no network call and no external service. There are two kinds:

- **Durable grants** you mint ahead of time with `knotrust grant`, for calls
  you're happy to pre-authorize (e.g. "this agent may open GitHub issues on
  my repos").
- **Ephemeral grants**, minted automatically the instant a human approves a
  one-off critical action. These are single-use and bound to the exact call
  that was approved — approving one refund doesn't authorize a different
  one.

Grants can never widen their own scope, and nothing the agent *says* can
mint or expand a grant: policy and grants are files signed by a key held
entirely outside model reasoning. That separation is the structural basis
for KnoTrust's injection-resistance — see [Security](/security).

## Risk tiers

Every tool call is classified into one of three tiers, and the tier drives
everything else — whether a durable grant can satisfy it, whether it's
cached, and whether it can ever fail open:

<p>
<span class="tier tier-routine">routine</span>
<span class="tier tier-sensitive">sensitive</span>
<span class="tier tier-critical">critical</span>
</p>

Tiers are *seeded* from an MCP server's own tool annotations
(`readOnlyHint`/`destructiveHint`), but those annotations are self-declared
by the server and are **never trusted blindly** — the MCP spec itself warns
against it. Annotations only produce a suggested tier; your own
`knotrust.config` and any installed policy pack always override the seed,
and an unannotated, destructive-looking tool defaults to `sensitive` or
higher rather than `routine`.

## What KnoTrust is not

- **Not a sandbox.** KnoTrust governs the MCP action surface only. Your
  agent's own shell, file, and network tools — a `Bash` call, a raw `curl`,
  a direct file write — never become MCP calls, so KnoTrust never sees them
  and can't gate them.
- **Not a replacement for running agents in a sandbox.** The physical
  containment layer (a disposable container, a least-privilege OS account
  with no production credentials) is not KnoTrust's job. We recommend it —
  and for the grant-signing key specifically, that recommendation is
  load-bearing, not just good practice. See [Security](/security).
- **Not something that can enforce its own presence.** Wrapping a server in
  `knotrust --` is config-cooperative: anything with write access to your
  MCP client's config (including your agent's own ungated file tool) can
  remove the wrapper. KnoTrust is honest about this rather than claiming
  otherwise.

## Standards it builds on

KnoTrust maps every tool call into the **AuthZEN Authorization API 1.0**'s
Subject/Action/Resource/Context (SARC) model — the same shape the industry
is converging on for externalized authorization. Where the surrounding
approval-and-agent-authorization standards (AARP, COAZ) are still early
working drafts, KnoTrust implements its own stable, versioned internal
contract shaped like those drafts, and keeps the actual wire format for each
behind an adapter — so a still-moving draft spec never becomes a breaking
change in your policy or grants.

## Where to go next

- [Installation & Quickstart](/guide/installation) — wrap a real MCP server
  and walk all three risk tiers end to end.
- [Core Concepts](/guide/core-concepts) — grants, approvals, and the audit
  trail in depth.
- [Configuration](/guide/configuration) — `knotrust.config`, tiers, and
  policy packs.
- [CLI Reference](/reference/cli) — every command and flag.
- [Architecture](/architecture) — the stdio proxy, the decision core, and
  the package layout.
