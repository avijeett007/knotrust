---
layout: home

hero:
  image:
    light: /logo-wordmark.svg
    dark: /logo-wordmark-dark.svg
    alt: KnoTrust
  text: "Stop re-approving safe calls. Stop the catastrophic ones cold."
  tagline: The local-first policy and approval layer for what your agents can do through MCP — signed grants, human-in-the-loop approval, and a tamper-evident audit trail. Portable across Claude, Codex, and any MCP-native agent.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/introduction
    - theme: alt
      text: View on GitHub
      link: https://github.com/avijeett007/knotrust

features:
  - title: Local-first & zero-backend
    details: Runs entirely on your machine. "npx knotrust -- <server>" and go — no account, no cloud, and nothing to stand up.
  - title: Signed durable grants
    details: Pre-authorize a tool once with an Ed25519-signed grant. Stop re-approving the same safe call in every new session.
  - title: Human-in-the-loop approval
    details: Critical actions block and wait for an authenticated human — a terminal prompt or the localhost approval page, on every client.
  - title: Fully audited & tamper-evident
    details: Every decision — allow, deny, or hold — appends to a hash-chained log. Nothing your agent attempted goes unrecorded.
  - title: Cross-agent portable
    details: One grant, one policy — works across Claude Desktop, Codex CLI, and any MCP-native agent, not locked to a single client's config.
  - title: Standards-conformant
    details: Built on the AuthZEN Authorization API's Subject/Action/Resource/Context model and the MCP protocol, not a bespoke policy language.
---

## Get started in under a minute

```sh [Terminal]
# Point KnoTrust at Claude Desktop's existing MCP servers
npx knotrust init claude

# ...or wrap any MCP server directly, client-agnostic
npx knotrust -- node server.js
```

`knotrust init` finds your client's MCP config, rewires each server to run
behind `knotrust --`, and seeds a `knotrust.config` with suggested risk tiers
drawn from the server's own tool annotations. From there, every `tools/call`
is decided: routine calls pass straight through, sensitive calls need a
grant, and critical calls block until an authenticated human approves them.
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
