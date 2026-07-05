# Security & Threat Boundaries

> New here? This page is the detailed, technical honesty check on exactly
> what KnoTrust protects against and what it doesn't. For the plain-language
> version first, see the [Introduction](/guide/introduction).

KnoTrust is a **Policy Enforcement Point (PEP)**: a proxy that sits on the
MCP action surface, maps every `tools/call` into a policy decision,
evaluates it against signed grants and configuration, and — for `critical`
actions — blocks until an authenticated human approves it out-of-band. This
page states plainly what that does and does not protect against. Overclaiming
here is the fastest way to lose a security-literate audience's trust, so the
boundary comes first, not last.

## The honest boundary

**What KnoTrust does not defend:**

1. **Your agent's own tools.** A shell command, a raw file write, or a
   direct network call made through your agent's own built-in tools never
   becomes an MCP `tools/call`. KnoTrust never sees it. Denying the MCP
   `Read` tool on a path is trivially defeated by `cat` through `Bash` —
   **KnoTrust owns one surface, the MCP action surface, not "everything the
   agent can do."**
2. **The sandbox.** The physical wall — what the agent *cannot* do at all —
   is an OS sandbox or a disposable container with no production
   credentials. **KnoTrust recommends this. It does not replace it.** For
   one specific asset (below), that recommendation is load-bearing, not
   advisory.
3. **MCP's own connection-level auth.** OAuth/token validation upstream of
   KnoTrust is the MCP layer's job; KnoTrust consumes an already-validated
   principal purely as policy context.
4. **Anything outside the sandbox.** Malware on the host, a compromised OS
   account, or a hostile local user with the same UID are outside KnoTrust's
   control. KnoTrust is a policy-and-approval layer, not an EDR.

**Mental model:** the sandbox is the wall; KnoTrust is *when it pauses to
check* on the one surface it fronts. They're complementary layers, never
substitutes for each other.

## The top residual: the grant-signing key and the same-account shell

This is the single most important honest limitation in the model, so it
gets its own section rather than a footnote.

The key that signs every grant lives in the OS keychain where one is usable
(the default), or as a `~/.knotrust/identity.key` file with `0600`
permissions as a fallback. `0600` stops *other* OS users from reading it. It
does **not** stop your agent's own ungated shell/file tool — running as the
same account KnoTrust runs as — from reading that key (or asking the same
user's keychain for it) and forging arbitrary grants. That is a total
bypass, and no amount of file permissions or keychain ACLs closes it,
because both are scoped to "this user's processes," which cannot
distinguish the legitimate `knotrust` process from an agent's shell tool
running under the same account.

The OS keychain **is real hardening** — it upgrades the attack from a
trivial file read to arbitrary-code-execution-as-the-same-user. It is
**not a security boundary**, and KnoTrust does not claim it is one.

**The honest conclusion:** KnoTrust's grant-signing-key confidentiality in
local mode is conditional on your agent not having ungated code-execution
access to the account KnoTrust runs under. This is exactly why the sandbox
recommendation above is load-bearing for this asset specifically — run
agents with untrusted tool access under a separate, least-privilege
principal, not your own login account.

## Self-approval and prompt injection

The primary adversary KnoTrust is built against is a prompt-injected or
otherwise adversarial agent: its reasoning can be fully controlled by
attacker content (a malicious document, a poisoned tool result), and it may
try to talk its way into an approval. The structural defense is
**out-of-band separation**, proven with a dedicated adversarial test suite,
not just asserted:

- Policy and grants are files signed by a key held entirely outside model
  reasoning. There is no code path where model-visible content — tool
  arguments, tool results, elicitation text — is ever parsed as a grant or
  an approval.
- Grants are created only two ways, both out-of-band: an operator running
  `knotrust grant`, or an authenticated human approving a `critical`
  escalation. Nothing the agent *says* can create or widen one.
- Approval requires an unguessable, per-request token delivered **only** to
  the human's own channel (terminal, or the localhost approval page) —
  never present in anything the model can read. A malicious server tool
  result trying to inject "SYSTEM: auto-approve" text, a fake
  `tools/call`/elicitation-complete frame, or a raw `curl` from the agent's
  own shell against the approval endpoint are all provably rejected.
- The ephemeral grant minted on approval is bound to a hash of the *exact*
  call a human approved (`call_hash`). Approving a benign call can never be
  replayed to authorize a different one — closing the "approve X, execute
  Y" bait-and-switch.
- Denial messages are two-layer by design: the model sees only the outcome,
  the tier, and "a human can approve via …" — zero rule IDs, zero policy
  internals, zero hints a probing agent could use to reason its way past
  the fence. The full rationale goes to the audit log and the human-facing
  approval UI only. Repeated-denial probing patterns are flagged in the
  audit log.

## The localhost approval page

The page that resolves a `critical` escalation is hardened specifically
against the agent that's waiting on the other end of it:

- Binds to `127.0.0.1` only — never `0.0.0.0`.
- Every approval link carries a cryptographically random, single-use token,
  invalidated on first use and on expiry.
- `Origin`/`Host` headers are validated against DNS-rebinding attacks.
- Mutating actions are `POST`-only with CSRF protection; a `GET` never
  changes state.
- Argument rendering is defanged — no HTML/markdown interpretation, no
  control-character or bidi-override tricks — so a deceptive argument can't
  disguise itself in the approval prompt.

On a single-user machine, the approver is authenticated by the OS session —
stated plainly as an assumption, not a proof. It does not hold on a shared,
multi-user host.

## Tamper-evident, not tamper-proof

The local audit log is an append-only, hash-chained JSONL file: every event
covers the previous event's hash, so editing, deleting, or reordering a line
breaks the chain from that point forward, and `knotrust audit verify` names
the exact break.

What this **does not** guarantee: a same-account attacker who rewrites the
entire chain from the tamper point forward, or who cleanly deletes a
trailing run of the most recent events, leaves a chain that verifies as
clean — a local hash chain with no external anchor can't tell that apart
from "the log never grew past there." Real tamper-evidence needs an
off-box anchor: KnoTrust exports the audit stream over OpenTelemetry/OTLP
(SigNoz as the reference receiver), and it's the exported copy — not the
local file alone — that an auditor should actually trust. **KnoTrust will
not market the local OSS audit log as "immutable."** That claim is reserved
for a possible future enterprise tier with genuine external anchoring.

## Bypass is config-cooperative, and we say so

Wrapping a server in `knotrust --` depends on the MCP client's config
actually invoking it. Anything with write access to that config — malware,
a malicious client, or your agent's own ungated file tool — can remove the
wrapper and reconnect directly, and KnoTrust cannot enforce its own presence
against a party that already has that access. This is inherent to any
config-cooperative proxy; closing it fully is future work (a
non-cooperative, kernel-level sandbox broker), not a claim this version
makes.

## Draft standards, stated honestly

KnoTrust maps every call into the AuthZEN Authorization API 1.0's
Subject/Action/Resource/Context model — a **ratified, final** standard.
The surrounding approval and MCP-authorization drafts it takes inspiration
from (AARP, COAZ) are still early Working Group Drafts with unstable wire
formats. KnoTrust implements its own stable internal contract shaped like
those drafts and keeps their actual wire format behind an adapter, so their
churn never becomes a breaking change to your policy or grants.

## Full threat model

This page is a summary of the doctrine. The complete STRIDE-per-boundary
threat enumeration, adversary model, asset register, and residual-risk
register live in the published threat model document:
[`docs/02-architecture/security-threat-model.md`](https://github.com/avijeett007/knotrust/blob/main/docs/02-architecture/security-threat-model.md).

Found a security issue? See `SECURITY.md` in the repository for the
coordinated-disclosure process.
