# Installation & Quickstart

## Requirements

- Node.js ≥ 22.
- An MCP client that already talks to at least one MCP server — Claude
  Desktop or Codex CLI are the two `knotrust init` currently understands. Any
  other MCP-native client works too, via the manual wrap in
  [Wrapping a server directly](#wrapping-a-server-directly).

## Install from source

> **KnoTrust isn't on npm yet.** The published `npx knotrust …` one-liner is
> the intended experience, but until the first release lands you run it from a
> local build. It only takes a few minutes, and you end up with the same
> `knotrust` command on your PATH — so every example in these docs works, just
> drop the `npx`.

You'll need **Node ≥ 22** and **pnpm** (via Corepack, which ships with Node).

```sh [Terminal]
# Enable pnpm (bundled with Node via Corepack)
corepack enable

# 1. Clone and enter the repo
git clone https://github.com/avijeett007/knotrust.git
cd knotrust

# 2. Install workspace dependencies
pnpm install

# 3. Build the knotrust CLI and its packages
pnpm build

# 4. Put the `knotrust` command on your PATH
cd packages/cli && npm link && cd ../..
```

Step 4 uses `npm link` because npm's global bin directory is already on your
PATH on a standard Node install. Prefer pnpm? Run `pnpm setup` once (to add
pnpm's global bin to your PATH), then `pnpm link --global` from `packages/cli`.

Confirm it's wired up:

```sh [Terminal]
knotrust -- echo hi
```

You should see KnoTrust's startup line — *"no knotrust.config found … tool
inventory capture and drift detection are ACTIVE … tools/call is NOT gated"* —
which means the proxy is running. Press Ctrl-C to stop.

From here, **use `knotrust …` wherever these docs show `npx knotrust …`**. The
bare command is your local build; `npx knotrust` would try to fetch the
not-yet-published package.

**Keeping it current:** the global link points at your checkout, so
`git pull && pnpm build` updates your `knotrust` in place — no need to re-link.
To remove it later: `npm rm -g knotrust`.

## Wrapping an existing client with `knotrust init`

If you already have MCP servers configured in Claude Desktop or Codex CLI,
point `knotrust init` at that client and it does the rest:

```sh [Terminal]
npx knotrust init claude
# or
npx knotrust init codex
```

This:

1. Auto-detects and reads the client's MCP config. A missing or malformed
   config aborts here, before anything is written.
2. Lets you choose which configured servers to wrap — pass `--server <name>`
   for exactly one, `--yes` to wrap all of them non-interactively, or answer
   the interactive prompt.
3. Rewrites the client config so each chosen server's command runs behind
   `knotrust --` instead of running directly, and prints the exact diff
   before writing anything.
4. Best-effort captures each newly-wrapped server's `tools/list` and writes a
   `knotrust.config` seeded with **suggested** risk tiers derived from the
   server's own tool annotations.

Useful flags:

| Flag | Effect |
|---|---|
| `--yes` / `-y` | Wrap every wrappable server, no prompts. |
| `--dry-run` / `--diff` | Print the exact diff(s) that would be written; write nothing. |
| `--server <name>` | Target exactly one server by name, no prompts. |
| `--config-format <yaml\|json\|ts>` | Format for the generated `knotrust.config` (default `yaml`). |

Running `knotrust init` again is idempotent — a server that's already
wrapped produces no diff and nothing is rewritten.

## Wrapping a server directly

`knotrust init` is a convenience over the one thing that actually matters:
running the real MCP server behind KnoTrust's proxy. You can always do that
by hand, for any client or none at all:

```sh [Terminal]
knotrust -- node my-mcp-server.js
```

Everything after the first `--` is the real server command; everything
before it is a `knotrust` subcommand. With **no** `knotrust.config` present,
KnoTrust still captures the server's `tools/list` and audits tool-definition
drift, but `tools/call` stays a pure passthrough — enabling enforcement is
`knotrust init`'s job (or hand-writing a config), never a silent zero-config
default. KnoTrust tells you this on startup so the behavior is never a
surprise:

```
knotrust: no knotrust.config found — tool inventory capture and drift
detection are ACTIVE and audited (server "my-mcp-server.js"); tools/call is
NOT gated or enforced (pure passthrough). Run `knotrust init` to enable
enforcement.
```

## Walking the three risk tiers end to end

Once a server is wrapped and a `knotrust.config` exists, every call resolves
to one of three tiers. Here's what each looks like in practice.

### <span class="tier tier-routine">routine</span> — passes straight through

A read-only, low-stakes call (listing repos, reading a file) matches the
`routine` tier and is allowed on the fast path — a cache lookup, typically
under a millisecond of added latency. Nothing to configure; this is the
common case KnoTrust is built to get out of your way for.

### <span class="tier tier-sensitive">sensitive</span> — needs a matching grant

A `sensitive` call (say, opening a GitHub issue) needs a **durable grant**
before it can be allowed. Mint one with `knotrust grant`:

```sh [Terminal]
knotrust grant \
  --tool github.create_issue \
  --server github-mcp \
  --tier-cap sensitive \
  --expires 30d
```

From then on, matching calls from that server are allowed automatically —
you've pre-authorized this exact shape of call, once, instead of clicking
"allow" on every session. Check what's currently granted with
`knotrust grant list`, and pull a grant at any time with `knotrust revoke`.

### <span class="tier tier-critical">critical</span> — blocks for a human

A `critical` call (a Stripe refund, a production database write) has no
fast path. Without a matching grant, KnoTrust **holds the call** and prints
an approval prompt to the terminal (or, where the client supports it,
opens the localhost approval page) and waits:

```
knotrust: awaiting approval — stripe.create_refund on ch_3PabcXYZ (amount:
$420.00). Approve? [y/N]
```

Approve it, and KnoTrust mints a short-lived, single-use grant bound to that
*exact* call, re-evaluates, and lets it through — deny or let it time out
(default 300s) and the call is refused. Minting a **durable** `critical`
grant ahead of time is possible but deliberately harder:

```sh [Terminal]
knotrust grant \
  --tool stripe.create_refund \
  --server stripe-mcp \
  --tier-cap critical \
  --i-understand-critical
```

`--i-understand-critical` is required friction, on purpose — a standing
pre-authorization for the most dangerous tier shouldn't be one flag away by
accident.

### Reading back what happened

Every decision on every tier — allow, deny, or hold — is appended to the
local, hash-chained audit log:

```sh [Terminal]
knotrust audit tail          # the most recent decisions
knotrust audit verify        # confirm the chain hasn't been tampered with
```

See [Core Concepts](/guide/core-concepts#the-audit-trail) for the full audit
model, and the [CLI Reference](/reference/cli) for every flag on every
command above.
