<p align="center">
  <img alt="KnoTrust" src="https://avijeett007.github.io/knotrust/social-preview.png" width="640">
</p>

<p align="center">
  <b>Stop trusting your AI agents blindly. Take back control of what they can do.</b>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/knotrust"><img alt="npm" src="https://img.shields.io/npm/v/knotrust?color=E7A93A"></a>
  <a href="https://github.com/avijeett007/knotrust/blob/main/LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <img alt="Node >= 22" src="https://img.shields.io/badge/node-%3E%3D22-339933?logo=node.js&logoColor=white">
  <a href="https://avijeett007.github.io/knotrust/"><img alt="Docs" src="https://img.shields.io/badge/docs-website-E7A93A"></a>
</p>

---

AI agents don't just chat anymore — they *do* things: send emails, move money, deploy code, delete files, post messages, often on their own. That's genuinely useful, and a little nerve-wracking. **KnoTrust** puts a human back in the loop for the actions that matter: safe actions run instantly, risky ones wait for your approval, and every attempt is written to a tamper-evident log. Think of it as a spending limit and an approval step for your AI agent — plus a receipt for everything it does.

It's **open-source, local-first, and zero-backend**: a small `knotrust` CLI that runs as a stdio proxy between an MCP client (Claude Desktop, Codex CLI, or any MCP-native agent) and the real MCP server, deciding every `tools/call` against signed grants, a risk tier, and — when needed — a human approval.

## Quickstart

Requires **Node ≥ 22**.

```sh
# Point knotrust at your MCP client's existing servers and wrap the ones you choose
npx knotrust init claude          # or: npx knotrust init codex
```

`knotrust init` auto-detects your client's MCP config, lets you pick which servers to route through KnoTrust, rewrites the config to launch each behind `knotrust --`, and seeds a `knotrust.config.yaml` with suggested risk tiers. You can also wrap any server directly:

```sh
knotrust -- npx -y @modelcontextprotocol/server-filesystem /path/to/project
```

With a `knotrust.config` present, enforcement is on: **routine** calls pass straight through, **sensitive** calls need a signed grant, and **critical** calls block until an authenticated human approves them — every decision appended to a hash-chained audit log you can read with `knotrust audit tail` / `verify`.

Full walkthrough, CLI reference, security model, and architecture: **[the documentation site](https://avijeett007.github.io/knotrust/)**.

## What KnoTrust is *not*

- **Not a sandbox.** It governs the MCP action surface only — your agent's own shell, file, and network tools (`Bash`, a raw `curl`) never become MCP calls, so KnoTrust never sees or gates them. Run agents that have broad local access inside a real OS sandbox or disposable container; KnoTrust is the policy-and-approval layer on top of that wall, not the wall itself.
- **Not tamper-proof.** The local audit log is hash-chained and tamper-*evident*, not tamper-*proof* — a same-account attacker can still rewrite it. Real tamper-evidence needs an off-box export (KnoTrust exports over OpenTelemetry/OTLP). The local OSS log is never called "immutable."
- **Not a silver bullet.** It's a policy-and-human-approval checkpoint at one real seam (MCP tool calls). Treat it as one layer of a broader defense.

## Links

- 📖 **Docs:** https://avijeett007.github.io/knotrust/
- 💻 **Source:** https://github.com/avijeett007/knotrust
- 🔒 **Security policy:** [SECURITY.md](https://github.com/avijeett007/knotrust/blob/main/SECURITY.md)
- 📄 **License:** Apache-2.0
