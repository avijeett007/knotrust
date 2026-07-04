<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-wordmark-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-wordmark.svg">
    <img alt="KnoTrust" src="assets/logo-wordmark.svg" width="360">
  </picture>
</p>

<p align="center">
  <b>The portable, YOLO-proof, fully-audited control layer for what your agents can do through MCP.</b>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <a href="package.json"><img alt="Node >= 22" src="https://img.shields.io/badge/node-%3E%3D22-339933?logo=node.js&logoColor=white"></a>
  <a href="https://avijeett007.github.io/knotrust/"><img alt="Docs" src="https://img.shields.io/badge/docs-website-E7A93A"></a>
  <a href="CONTRIBUTING.md"><img alt="PRs Welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"></a>
</p>

---

**KnoTrust** is an open-source, local-first, zero-backend policy-and-approval layer for [MCP](https://modelcontextprotocol.io) tool calls. It runs as a **stdio proxy** — `knotrust -- your-mcp-server` — that sits between an MCP client (Claude Desktop, Codex CLI, or any MCP-native agent) and the real server, intercepting every `tools/call`. Each call is evaluated against **signed grants**, a **risk tier**, and (when neither is enough) a **human approval**, and resolved to one of four outcomes: `allow`, `deny`, `pending_approval`, or `deferred_not_eligible`. Enforcement happens **inside the proxy process, server-side of the client** — so it holds even when the client itself is running in a YOLO / auto-approve / `--dangerously-skip-permissions` mode, because the client's own approval UI was never in the loop to begin with.

## What KnoTrust is

No single piece of this is unclaimed territory — policy engines, approval bots, and MCP gateways all exist. What we haven't found assembled together anywhere else is the **combination**:

1. **Cross-agent portable** — one signed grant, one config, works the same in front of Claude Desktop, Codex CLI, or any other MCP client, instead of a per-client allowlist.
2. **Enforced at the protocol seam, not a client setting** — the proxy parses the JSON-RPC body of every `tools/call` itself; it doesn't depend on, or get bypassed by, the client's own approval/YOLO configuration.
3. **Signed, durable grants on an AuthZEN-shaped decision model** — the SARC (Subject/Action/Resource/Context) request shape and PEP/PDP split follow the AuthZEN Authorization API; grants are Ed25519-signed and verified fully offline.
4. **Local-first and zero-backend** — no account, no server to stand up, no telemetry by default. State lives in `~/.knotrust/` on your machine; OpenTelemetry export is opt-in.

### What KnoTrust is NOT

- **Not a sandbox.** KnoTrust governs the MCP action surface only. An agent's own shell, file, or network tools (`Bash`, `Read`, a raw `curl`) never become an MCP call, so a KnoTrust proxy in front of one MCP server never sees or gates them — `Read(.env)` denied is trivially defeated by `cat .env` over Bash if the agent has both. Run agents that have broad local tool access inside a real OS sandbox or disposable container; KnoTrust does not replace that layer.
- **Not full visibility into everything an agent does** — only into the MCP servers it's put in front of.
- **Not a silver bullet.** It is a policy-and-human-approval checkpoint at one real seam (MCP tool calls), with an audit trail that survives even when a client's own "always allow" mode is on. Treat it as one layer of a broader defense, not the whole defense.

## 60-second quickstart

Requires **Node ≥ 22**.

```sh
# Point knotrust at your MCP client's config and wrap the servers you choose
npx knotrust init claude          # or: npx knotrust init codex
```

`knotrust init` auto-detects your client's MCP config, lets you pick which servers to route through KnoTrust (or pass `--yes` to wrap all of them, `--server <name>` to target one, `--dry-run`/`--diff` to preview without writing), rewrites the client config to launch each server via `knotrust --`, and best-effort generates a `knotrust.config.yaml` with suggested risk tiers seeded from the server's advertised tool annotations.

You can also wrap any server directly, without touching a client config:

```sh
knotrust -- npx -y @modelcontextprotocol/server-filesystem /path/to/project
```

With a `knotrust.config.*` present, enforcement is on. Here's what the three outcomes look like in practice (`knotrust.config.yaml` tiers a **routine** read, a **sensitive** write, and a **critical** delete on the same server):

**Routine — cache-hit allow, sub-millisecond, transparent:**

```
$ # agent calls github.create_issue (tiered: routine)
$ # → allowed, forwarded to the real server unchanged. Nothing to approve.
```

**Sensitive — no covering grant yet → a Requestable Denial**, a structured tool result the model can read and act on (not a raw protocol error):

```json
{
  "knotrust": {
    "outcome": "deny",
    "reasonCode": "no_grant_sensitive",
    "tier": "sensitive",
    "requestable": { "how": "knotrust grant --tool github.create_issue --server github-mcp" }
  }
}
```

Run the suggested command once, and every future matching call allows without asking again:

```sh
knotrust grant --tool github.create_issue --server github-mcp --tier-cap sensitive
```

**Critical — no grant covers it, so the call blocks for a human, in-terminal:**

```
knotrust: approval required — "stripe.create_refund" on server "stripe-mcp" (critical tier).
  code:    7F3KQD
  approve: http://127.0.0.1:8787/approve?id=apr_01JZ8Q6&token=tok_...
  this call is held until approved, denied, or it times out.
```

Approve from the printed localhost page (or deny it), and the call resumes with a single-use, call-bound grant minted just for that one approved request — never a standing "critical" pre-authorization.

## How it works

```
MCP client                knotrust proxy                          real MCP server
    │  tools/call               │                                        │
    ├──────────────────────────▶│ parse JSON-RPC body (never trust       │
    │                           │ headers) → tier + grant + policy       │
    │                           │                                        │
    │                           ├─ allow ─────────────────────────────▶  │
    │                           │                          result ◀──────┤
    │◀──────────────────────────┤                                        │
    │                           │                                        │
    │                           ├─ deny / deferred → synthesize result   │
    │◀── Requestable Denial ────┤   (same JSON-RPC id, never forwarded)  │
    │                           │                                        │
    │                           ├─ critical, no grant → block-and-wait   │
    │                           │   → human approves on localhost page   │
    │                           │   → mint single-use, call-bound grant  │
    │                           │   → re-evaluate → allow ─────────────▶ │
    │◀──────────────────────────┤                          result ◀──────┤
```

- **Three risk tiers — `routine | sensitive | critical`.** Seeded (never blindly trusted) from a server's own `tools/list` annotations, overridable by your config or a signed policy pack. Unknown/unannotated destructive-looking tools default to `sensitive` or higher.
- **Signed grants.** A grant is `{principal, agent, tool, resource scope, conditions, tier, expiry}`, signed Ed25519 (JWS Compact) and verified fully offline. **Durable** grants (`knotrust grant ...`) are long-lived pre-authorizations; **ephemeral** grants are single-use, short-lived, and bound to the exact call a human approved (`callHash`) — so approving one refund never becomes a blanket license for refunds. List and revoke with `knotrust grant list` / `knotrust revoke <jti>|--tool <pattern>|--all`.
- **Block-and-wait approval.** The universal fallback that works on every MCP client regardless of elicitation support: the proxy holds the call, prints an approval code and URL to the terminal, and serves a localhost approval page (bound to `127.0.0.1`, token-gated, CSRF-protected) for the human to accept or reject. Timeout resolves to deny — fail-closed by default.
- **Hash-chained audit log.** Every decision — allow, deny, cache hit, or escalation — appends to `~/.knotrust/audit/*.jsonl`, each event carrying the previous event's hash: a tamper-*evident* (not tamper-proof) chain. Inspect it with `knotrust audit list` / `knotrust audit tail` / `knotrust audit query --tool <pattern> --outcome deny --since 1h`, and check chain integrity with `knotrust audit verify`.
- **Policy packs.** `knotrust add pack <path>` applies a local, signed-in-spirit YAML pack that seeds tiers for a specific server (GitHub, Stripe, filesystem, …), always previewed as a diff before it's written.

See `docs/02-architecture/system-architecture.md` for the full contract (the `DecisionRequest`/`DecisionResponse` shapes, the precedence engine, and every sequence diagram this summary compresses).

## Links

- **Docs:** https://avijeett007.github.io/knotrust/
- **Architecture:** [`docs/02-architecture/system-architecture.md`](docs/02-architecture/system-architecture.md)
- **Threat model:** [`docs/02-architecture/security-threat-model.md`](docs/02-architecture/security-threat-model.md)
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Security policy:** [`SECURITY.md`](SECURITY.md)
- **License:** [`LICENSE`](LICENSE) (Apache-2.0)

---

<p align="center">
  Licensed under <a href="LICENSE">Apache-2.0</a> · Built by <b>Kno2gether Labs</b><br>
  <a href="CONTRIBUTING.md">Contributing</a> · <a href="SECURITY.md">Security</a> · <a href="CODE_OF_CONDUCT.md">Code of Conduct</a>
</p>
