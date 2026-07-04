# Security Policy

KnoTrust sits in front of real MCP tool calls — GitHub, Stripe, deploy servers, databases — so security issues here can have real consequences. We take reports seriously and ask that you report privately rather than through a public GitHub issue.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email **security@kno2gether.com** with:

- a description of the issue and its potential impact,
- steps to reproduce (a minimal repro is enormously helpful — see `test/adversarial` for the shape of scenario this project already tests against),
- which component is affected (`packages/core`, `packages/grants`, `packages/proxy-stdio`, `packages/approval`, `packages/pdp`, `packages/store`, or `packages/cli`),
- whether you believe it's already being exploited.

> **Placeholder — owner to confirm:** `security@kno2gether.com` is the intended disclosure address for this project; please verify it is live and monitored before this policy is treated as final, and replace it with a dedicated security alias or a GitHub Security Advisory contact if preferred.

We'll acknowledge your report, work with you to understand and reproduce the issue, and aim to keep you informed as a fix is developed. We ask that you give us a reasonable window to ship a fix before any public disclosure. Coordinated disclosure credit is welcome if you'd like it, and none if you'd rather stay anonymous.

If you prefer, you can also use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) on this repository once it's enabled, which routes to the same maintainers.

## Supported versions

KnoTrust is pre-1.0 (`0.0.0` as of this writing). Only the latest release of the published `knotrust` package receives security fixes; there is no long-term-support branch yet.

## The honest threat-model boundary

Read this section before filing a report that assumes KnoTrust is a sandbox — it isn't, and the distinction matters for triage.

**KnoTrust is a Policy Enforcement Point (PEP) at the MCP protocol seam.** It intercepts `tools/call` requests to an MCP server, evaluates them against signed grants and risk-tiered policy, and — for actions that need one — blocks for an authenticated human approval. This is a real, meaningful control on the MCP action surface. It is **not**:

- **A sandbox.** An agent that can execute arbitrary code as the same OS user KnoTrust runs as can defeat local controls entirely — a shell tool, a file tool, or a raw network call never becomes an MCP `tools/call`, so KnoTrust never sees it and cannot gate it. `Read(.env)` denied by KnoTrust is trivially bypassed by `cat .env` over an ungated Bash tool. **Running the agent inside a real OS-level sandbox or disposable container, with no standing production credentials on unattended runs, is a load-bearing recommendation, not a nice-to-have** — see `docs/02-architecture/security-threat-model.md` §1 for the full trust-boundary diagram (KnoTrust's proxy is the trusted computing base; the OS sandbox around it is a separate, complementary layer we recommend but do not provide).
- **A guarantee against a compromised or malicious MCP server.** Tool annotations (`readOnlyHint`/`destructiveHint`) advertised by a server are seeds for suggested risk tiers, never trusted — but a server that lies about what a tool does, or performs a rug-pull after initial trust is established, is a named threat scenario (see the threat model's tool-poisoning section), not something eliminated by this project alone.
- **A silver bullet against prompt injection.** Denial messages shown to the model are deliberately terse (status, tier, "a human can approve via ...") specifically so an injected instruction riding in tool output can't learn the shape of the policy well enough to talk its way past it — but this narrows the attack surface, it does not close it entirely, and repeated-probing patterns are flagged in the audit log for a human to notice, not silently blocked.

## Audit log: tamper-evident, not tamper-proof

Every decision KnoTrust makes — allow, deny, cache hit, or escalation — is appended to a local, append-only JSONL log at `~/.knotrust/audit/`, where each event carries a hash of the previous event. Run `knotrust audit verify` to check the chain is intact. This makes tampering **detectable after the fact** (a broken chain is visible immediately). It does **not** make the log **tamper-proof**: an attacker with the same local filesystem access as the KnoTrust process (i.e., the same OS account) can, in principle, rewrite the entire chain consistently, or delete it outright, exactly as they could with any other local file. The hash chain's guarantee is integrity detection, not an unforgeable ledger — for that, sync audit events out via the optional OpenTelemetry exporter (`packages/otel`) to a store the local attacker doesn't also control.

## Key handling

Grants are signed with Ed25519. The signing key is stored in the OS keychain by default (via `@napi-rs/keyring`) where available, falling back to `~/.knotrust/identity.key` (mode `0600`) otherwise. This is hardening against casual disclosure, not a hard security boundary: an agent executing arbitrary code as the same OS user can also reach the keychain or read the key file. The threat model's OS-sandbox recommendation above applies here too.

## Full threat model

For the complete scope, trust boundaries, and per-scenario (T1–T10) analysis — prompt-injection/self-approval attempts, tool-poisoning/rug-pull, key theft, bypass routes, and more — see [`docs/02-architecture/security-threat-model.md`](docs/02-architecture/security-threat-model.md).
