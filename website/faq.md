# FAQ

### Is KnoTrust a sandbox?

No. KnoTrust governs the MCP action surface only — the tool calls that flow
through `tools/call`. Anything your agent does through its own shell, file,
or network tools never becomes an MCP call, so KnoTrust never sees it and
can't gate it. We recommend running agents in a sandbox (a disposable
container, or a least-privilege account with no production credentials) as
a complementary layer, not something KnoTrust replaces. See
[Security](/security) for the full doctrine.

### Does KnoTrust require an account, a cloud service, or a backend?

No. The core is local-first and zero-backend: `npx knotrust -- <server>`
runs entirely on your machine, with grants, config, and the audit log all
stored under `~/.knotrust/`. A team/organization control plane is planned as
an *optional* addition later — never required, and never part of the
open-source first-run experience.

### Does it slow my agent down?

For the common case, barely. A `routine` call that's already in the
decision cache adds well under a millisecond — JSON parsing dominates that
path, not policy evaluation. `sensitive` calls that need a grant lookup and
signature verification add a few milliseconds. Only `critical` calls without
a matching grant have real latency, because they wait on an actual human —
by design, since that's the one case KnoTrust exists to slow down.

### What happens if I don't configure anything?

`knotrust -- <server>` still runs with no `knotrust.config` present. It
captures the server's `tools/list` and audits any drift in what the server
advertises, but `tools/call` stays a pure passthrough — nothing is enforced
until you run `knotrust init` or hand-write a config. KnoTrust tells you
this explicitly on startup; it never silently claims to be protecting you
when it isn't.

### What's the difference between routine, sensitive, and critical?

They're the three risk tiers every tool call is classified into, and they
drive everything else: whether a durable grant can satisfy the call,
whether it's cached (and for how long), and whether it's ever allowed to
fail open. See [Core Concepts](/guide/core-concepts#risk-tiers) for the full
breakdown and the precedence rules that decide a tool's final tier.

### Which MCP clients does KnoTrust work with?

Any MCP-native client, via the direct `knotrust -- <server>` wrap — it's
client-agnostic by construction, since it operates at the stdio transport
level, not inside any one client's config format. `knotrust init` currently
automates the config rewrite specifically for Claude Desktop and Codex CLI;
other clients work the same way with a manual wrap.

### What if my client doesn't support MCP elicitation?

That's exactly why approval is channel-plural. KnoTrust tries richer
channels first (in-client elicitation, the localhost approval page) but
always falls back to **block-and-wait**: holding the call open, printing a
prompt to the terminal, and waiting. That floor works on every MCP client
regardless of what interactive features it supports.

### Is the audit log immutable / tamper-proof?

No, and we're specific about that distinction on purpose. The local log is
hash-chained and **tamper-evident** — it reliably catches accidental
corruption and naive edits, and `knotrust audit verify` will tell you
exactly where a chain breaks. It does **not** catch a same-account attacker
who rewrites the whole chain forward from the tamper point. Real
tamper-evidence comes from exporting the log off-box over
OpenTelemetry/OTLP; the local OSS log is never marketed as "immutable." See
[Security](/security#tamper-evident-not-tamper-proof).

### Can a grant be widened by something my agent says?

No. Grants are created only two ways, both out-of-band: an operator running
`knotrust grant`, or an authenticated human approving a `critical`
escalation on a separate channel. Nothing in a tool call's arguments, a tool
result, or the model's own reasoning can create or expand a grant — that
separation is enforced structurally, not by convention, and is covered by a
dedicated adversarial test suite. See
[Security](/security#self-approval-and-prompt-injection).

### How is this different from a client's built-in "always allow" / OAuth scope?

A client-side allowlist is per-client, per-call, and it's the first thing
that gets bypassed the moment someone runs their agent in an unattended or
"skip all permission checks" mode. A coarse OAuth scope granted once at
connect time can't distinguish a routine call from a catastrophic one. A
KnoTrust grant is signed, durable, portable across whichever agent/client is
making the call, enforced at the protocol seam regardless of the client's
own approval mode, and everything it does — allow or deny — is recorded in
an audit trail a client dialog never gives you.

### What language/runtime does KnoTrust need?

Node.js ≥ 22. It ships as a single `knotrust` npm package (a CLI with
subcommands), run through `npx` — there's no separate install step and no
constellation of packages to reason about.

### Is a Python version planned?

Yes — a Python SDK (a real port, not an FFI wrapper around the TypeScript
core) is on the roadmap, sharing golden cross-language test vectors with the
TypeScript implementation so grant verification and decision logic stay in
lockstep across both.

### What license is KnoTrust under?

Apache 2.0 for the core, with a Contributor License Agreement. The license
stays permissive and forkable deliberately — a security-relevant dependency
maintained by a small team is a real trust question, and Apache 2.0 means
nobody is stranded if it ever needs forking.

### Where do I report a security issue?

See `SECURITY.md` in the repository for the coordinated-disclosure process
and response expectations.
