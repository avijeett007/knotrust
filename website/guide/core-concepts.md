# Core Concepts

## Risk tiers

In plain terms: every action your agent tries gets sorted into one of
three buckets — safe reads that run automatically, changes that need a
one-time approval, and dangerous or irreversible actions that always stop
and wait for a human.

Every tool call KnoTrust intercepts is classified into one of three tiers,
in order of increasing consequence:

<p>
<span class="tier tier-routine">routine</span>
<span class="tier tier-sensitive">sensitive</span>
<span class="tier tier-critical">critical</span>
</p>

| Tier | Fast path | Cacheable | Can fail open? |
|---|---|---|---|
| `routine` | Yes — the common case | Yes, long TTL (default 1h) | Yes, but only per-class, explicit, and audited on every occurrence |
| `sensitive` | Needs a matching grant | Yes, short TTL (≤ 60s) | Never |
| `critical` | Needs a human, every time (unless a durable grant already covers it) | Never cached | Never |

**Tiers are seeded, never trusted, from a server's own tool annotations**
(`readOnlyHint` / `destructiveHint`). The MCP spec itself warns that clients
must treat annotations from untrusted servers as just that — untrusted — so
KnoTrust only lets an annotation *suggest* a tier. Precedence for the final
tier is: **your explicit `knotrust.config` entry > a signed policy pack >
the annotation-derived seed > the unknown/unannotated default**, and an
unannotated, destructive-looking tool defaults to `sensitive` or higher, never
`routine`. A policy pack can raise a tool's tier but can never lower it below
whatever an admin envelope has floored it at.

## Signed grants

In plain terms: a grant is a pre-approval you sign once, so KnoTrust
doesn't have to ask you about the same safe action every time — like
handing someone a standing permission slip instead of asking again on
every single occasion.

A **grant** is the thing that lets a call skip re-approval: a pre-satisfied
prerequisite of the shape `{principal, agent, tool, resource scope,
conditions, risk tier, granted_by, expiry, single_use}`, signed Ed25519 and
serialized as a compact JWS (`alg: EdDSA`). Verification is fully local —
no network call, no external service — by resolving the signer's public key
from `~/.knotrust/keys/` and checking the signature, expiry, and scope match.

There are two kinds:

- **Durable grants** — minted ahead of time with `knotrust grant`, long-lived
  (default 30 days), and the reason KnoTrust doesn't nag you every session
  for the same safe call.
- **Ephemeral grants** — minted automatically the moment a human approves a
  one-off `critical` escalation. These are `single_use`, short-lived
  (~120s), and — critically — bound to a hash of the *exact* call that was
  approved (`call_hash`). Approving one refund can never be reused to
  authorize a different one; this closes the "approve X, then quietly
  execute Y" bait-and-switch.

**No self-escalation, by construction.** A grant's tier can never exceed the
authority that minted it; an ephemeral grant can never exceed the admin
policy envelope; and nothing an agent *says* — in tool arguments, in a tool
result, in its own reasoning — can create or widen a grant. Grants are only
ever created out-of-band: by an operator running `knotrust grant`, or by an
authenticated human approving an escalation. See
[Security](/security#the-injection-defense-argument) for the full argument.

**Precedence, top to bottom, first decisive layer wins:**

1. The **admin/org policy envelope** — the outer ceiling; can force approval
   or denial on a tier regardless of any personal grant.
2. A matching **personal grant**, within the envelope.
3. The **default** — unknown, unannotated, or an uncovered `critical` call
   falls closed (denied) by default.

## Approvals & block-and-wait

In plain terms: when your agent tries something risky enough to need a
real person's sign-off, KnoTrust pauses the action and asks you — wherever
you happen to be looking, whether that's a terminal or a browser tab —
rather than letting it run and hoping for the best.

When a `critical` call has no matching grant, it escalates to the approval
orchestrator, which walks a lifecycle of
`requested → pending → approved | denied | expired | cancelled`. Because
client support for MCP's own interactive elicitation is still uneven across
the ecosystem, the approval subsystem is **channel-plural**: it tries
richer channels first and always has a floor that works everywhere.

- **`elicitation_form`** — a simple in-client confirm, on clients that
  support MCP form-mode elicitation.
- **`elicitation_url`** — bounces to the **localhost approval page** the
  proxy itself serves, opened in an isolated browser view the model can't
  read from.
- **`block_and_wait`** — the universal floor. The proxy holds the
  `tools/call` open, prints the approval prompt (and/or the approval page
  URL) to the terminal, and waits. This is what makes the flagship demo work
  on *any* MCP client, regardless of what it does or doesn't support.

Whichever channel resolves it, approval always re-evaluates the original
call rather than trusting the human's "yes" directly — the decision core
stays authoritative. The localhost approval page is hardened specifically
against the agent that's waiting on it: it binds to `127.0.0.1` only, every
approval link carries an unguessable single-use token that's **delivered to
the human's own channel and never placed anywhere the model can read it**,
mutations are POST-only with CSRF protection, and `Origin`/`Host` are
validated against DNS-rebinding. See [Security](/security) for the full
threat model behind this design.

## The audit trail

In plain terms: KnoTrust keeps a running record of everything your agent
tried — like a receipt roll you can scroll back through — so if something
goes wrong, you can see exactly what happened and when.

Every decision KnoTrust makes — allow, deny, a cache hit, an approval
request, a grant minted, a fail-open firing — appends exactly one event to
an append-only, hash-chained JSONL log under `~/.knotrust/audit/`. Each
event's hash covers the previous event's hash, so editing, deleting, or
reordering any line breaks the chain from that point forward; `knotrust
audit verify` walks the whole chain and names the exact break if one exists.

Two things are worth being precise about, because overclaiming here is
exactly the kind of thing that loses a security-literate audience's trust:

- **Attempts are audited, not just executions.** A `deny` is recorded with
  the same rigor as an `allow` — the point of the log is "everything the
  agent tried," not just what actually ran.
- **Tamper-*evident*, not tamper-*proof*.** The chain reliably catches
  accidental corruption and naive edits. It does **not** catch a same-account
  attacker who rewrites the whole chain from the tampering point forward, or
  who cleanly deletes a trailing run of the most recent events — a local
  hash chain with no external anchor can't distinguish that from "the log
  never grew past there." Real tamper-evidence comes from exporting the log
  off-box (KnoTrust exports over OpenTelemetry/OTLP, with SigNoz as the
  reference receiver) — the exported copy, not the local file alone, is what
  an auditor should trust. KnoTrust will never market the local OSS log as
  "immutable"; that's reserved for a future enterprise tier with real
  external anchoring.

Query it directly from the CLI — see the [CLI Reference](/reference/cli) for
`knotrust audit list` / `tail` / `query` / `verify`.
