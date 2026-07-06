---
layout: home

hero:
  image:
    light: /logo-wordmark.svg
    dark: /logo-wordmark-dark.svg
    alt: KnoTrust
  text: "Stop trusting your AI agents blindly."
  tagline: KnoTrust puts you back in charge of what your AI agents can actually do — the safe actions run instantly, the risky ones wait for your approval, and every attempt is logged. Works with Claude, Codex, and any MCP agent. Nothing to host, no account.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/introduction
    - theme: alt
      text: View on GitHub
      link: https://github.com/avijeett007/knotrust

features:
  - title: Runs on your machine
    details: Nothing to host, no account, no cloud. `npx knotrust -- <server>` and you're going. Your policy and history stay in `~/.knotrust/` on your computer.
  - title: Approve once, not every time
    details: Pre-approve a safe action with a signed grant, and KnoTrust stops asking you about it in every new session.
  - title: A human checks the risky stuff
    details: Critical actions stop and wait for a real person to approve them — from a terminal prompt or a local approval page — on every client.
  - title: Everything is on the record
    details: Every decision — allowed, denied, or held — is appended to a tamper-evident log. Nothing your agent tried goes unrecorded.
  - title: Works with all your agents
    details: One policy, one grant — the same in front of Claude Desktop, Codex CLI, or any MCP agent. Not locked to one app's settings.
  - title: Built on open standards
    details: Uses the AuthZEN authorization model and the MCP protocol — not a bespoke, lock-in policy language.
---

## Get started in under a minute

::: tip Not on npm yet — build from source
`knotrust` isn't published to npm yet, so `npx knotrust …` won't resolve.
[Install from source](/guide/installation#install-from-source) — a few minutes,
and you get the same `knotrust` command on your PATH. Then use `knotrust …` in
place of `npx knotrust …` in the examples below.
:::

```sh [Terminal]
# Point KnoTrust at Claude Desktop's existing MCP servers
npx knotrust init claude

# ...or wrap any MCP server directly, client-agnostic
npx knotrust -- node server.js
```

`knotrust init` finds your AI client's tool configuration, rewires each tool
server to run behind `knotrust --`, and sets up a starting policy with
suggested risk tiers based on what each tool says about itself. From there,
every action your agent tries is decided by its risk tier: routine actions
pass straight through, sensitive actions need a one-time approval (a
"grant"), and critical actions stop and wait for you to say yes.
See the [installation & quickstart guide](/guide/installation) for the full
walkthrough.

<div class="not-strip">
<span class="not-strip-label">Honest boundaries</span>
<h3>What KnoTrust is <em>not</em></h3>
<ul>
<li><strong>Not a sandbox.</strong> KnoTrust governs the MCP action surface only. A shell command, a file write, or a raw network call from your agent's own tools never becomes an MCP call — KnoTrust never sees it, and never blocks it.</li>
<li><strong>Not a replacement for running agents in a sandbox.</strong> We recommend a disposable container or a least-privilege account with no production credentials. KnoTrust is the policy-and-approval layer on top of that wall, not the wall itself.</li>
<li><strong>Not tamper-proof.</strong> The local audit log is hash-chained and tamper-<em>evident</em>, not tamper-proof — a same-account attacker can still rewrite it. Real tamper-evidence needs an off-box export. We will never call the local OSS log "immutable."</li>
</ul>
</div>

Read the full doctrine in [Security &amp; threat boundaries](/security).
