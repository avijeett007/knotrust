# CLI Reference

Everything after the first standalone `--` is the real MCP server command;
everything before it is a `knotrust` subcommand. Every subcommand below is
invoked **without** a trailing `--`.

## `knotrust -- <server command> [args...]`

The runner — KnoTrust's flagship surface. Spawns `<server command>` as a
child process and proxies stdio between it and the MCP client, intercepting
every `tools/call` for a decision.

```sh [Terminal]
knotrust -- node server.js
knotrust -- npx -y @modelcontextprotocol/server-filesystem /path
```

- If a `knotrust.config` is found in the current directory, full enforcement
  is wired up: `tools/call` is gated by the decision core.
- If no config is found, KnoTrust still captures `tools/list` and audits
  tool-definition drift, but `tools/call` stays a pure passthrough — this is
  stated explicitly on startup, never a silent default.
- The proxy is fail-closed: if the wrapped server crashes, an in-flight call
  resolves to `deny` rather than silently allowing it, and the proxy exits
  non-zero.

## `knotrust init <claude|codex>`

```
usage: knotrust init <claude|codex> [--yes] [--dry-run|--diff] [--server <name>] [--config-format <yaml|json|ts>]
```

Detects the named client's MCP config, rewires the servers you choose to run
behind `knotrust --`, and best-effort generates a `knotrust.config` seeded
with suggested tiers.

| Flag | Description |
|---|---|
| `--yes`, `-y` | Wrap every wrappable server; no interactive prompt. |
| `--dry-run`, `--diff` | Print the exact diff(s) that would be written; write nothing. |
| `--server <name>` | Target exactly one server by name; no prompt. |
| `--config-format <yaml\|json\|ts>` | Format for the generated `knotrust.config` (default `yaml`). |

An already-wrapped server produces no diff and no write — running `init`
again is a safe no-op.

## `knotrust grant`

```
usage: knotrust grant --tool <pattern> --server <name> [--agent <pattern>]
  [--tier-cap routine|sensitive|critical] [--expires <duration>]
  [--resource <type:idPattern|idPattern>] [--yes] [--i-understand-critical]
```

Mints a durable, signed grant.

| Flag | Description | Default |
|---|---|---|
| `--tool <pattern>` | Tool name or glob, e.g. `stripe.create_refund` or `github.*`. **Required.** | — |
| `--server <name>` | The logical server this grant applies to. **Required.** | — |
| `--agent <pattern>` | Restrict the grant to a specific agent identity. | `*` (any agent) |
| `--tier-cap <tier>` | `routine`, `sensitive`, or `critical` — the tier this grant satisfies. | `sensitive` |
| `--expires <duration>` | One or more `<digits><unit>` tokens back to back — `w`(eek), `d`(ay), `h`(our), `m`(inute), `s`(econd) — e.g. `30d`, `12h`, `1d12h`. | `30d` |
| `--resource <type:idPattern\|idPattern>` | Scope the grant to a resource type/id pattern. | — (any resource) |
| `--yes`, `-y` | Skip the interactive confirmation. | — |
| `--i-understand-critical` | **Required** to mint a durable `--tier-cap critical` grant — deliberate friction for the most dangerous tier. | — |

```sh [Terminal]
knotrust grant --tool github.create_issue --server github-mcp \
  --tier-cap sensitive --expires 30d

knotrust grant --tool stripe.create_refund --server stripe-mcp \
  --tier-cap critical --i-understand-critical
```

## `knotrust grant list`

```
usage: knotrust grant list [--json]
```

Lists every durable grant currently on record — `--json` for machine-readable
output.

## `knotrust revoke`

```
usage: knotrust revoke <jti> | --tool <pattern> | --all [--yes]
```

Revokes one or more grants. Exactly one selector is accepted:

| Selector | Effect |
|---|---|
| `<jti>` | Revoke the single grant with this id. |
| `--tool <pattern>` | Revoke every grant matching this tool name/glob. |
| `--all` | Revoke every grant. |

`--yes`/`-y` skips the interactive confirmation. Revocation writes a
tombstone immediately — in local mode, the store *is* the cache, so the
change takes effect on the very next decision.

```sh [Terminal]
knotrust revoke 01JZ8QAGRANT001
knotrust revoke --tool "github.*"
knotrust revoke --all --yes
```

## `knotrust add pack <path>`

```
usage: knotrust add pack <path> [--server <name>] [--yes] [--dry-run]
```

Applies a local YAML policy pack into `knotrust.config`, after printing a
human-readable tier diff — packs are executable security policy, so they
are never silently applied.

| Flag | Description |
|---|---|
| `--server <name>` | Override the target `servers.<name>` config key (defaults to the pack's own `server` field, if set). |
| `--yes`, `-y` | Skip the interactive confirmation (the diff is still always printed). |
| `--dry-run`, `--diff` | Print the diff only; write nothing. |

```sh [Terminal]
knotrust add pack ./packs/stripe.yaml --yes
```

Only `pack` is implemented today; a GitHub-fetched, signed pack registry
(`knotrust add pack <name>`) and an opt-in Cedar policy engine
(`knotrust add pdp cedar`) are the next `<kind>` targets planned for this
same command.

## `knotrust audit list` / `knotrust audit tail`

```
usage: knotrust audit list [-n <count>] [--json]
usage: knotrust audit tail [-n <count>] [--json]
```

`list` and `tail` are deliberate aliases — same output, same flags. Shows
the most recent audit events.

| Flag | Description | Default |
|---|---|---|
| `-n <count>`, `--limit <count>` | Number of events to show. | `50` |
| `--json` | Machine-readable output. | — |

## `knotrust audit query`

```
usage: knotrust audit query [--tool <pattern>]
  [--outcome allow|deny|pending_approval|deferred_not_eligible]
  [--tier routine|sensitive|critical] [--since <duration|timestamp>]
  [--agent <pattern>] [--server <name>] [--json]
```

Filters the audit log.

| Flag | Description |
|---|---|
| `--tool <pattern>` | Filter by tool name/glob. |
| `--outcome <outcome>` | One of <span class="outcome outcome-allow">allow</span>, <span class="outcome">deny</span>, <span class="outcome">pending_approval</span>, <span class="outcome">deferred_not_eligible</span>. |
| `--tier <tier>` | One of <span class="tier tier-routine">routine</span>, <span class="tier tier-sensitive">sensitive</span>, <span class="tier tier-critical">critical</span>. |
| `--since <duration\|timestamp>` | A duration (`1h`, `30d`, `1d12h`) resolved relative to now, or an absolute ISO 8601 timestamp. |
| `--agent <pattern>` | Filter by agent identity. |
| `--server <name>` | Filter by server name. |
| `--json` | Machine-readable output. |

```sh [Terminal]
knotrust audit query --outcome deny --since 1h
knotrust audit query --tier critical --since 7d --json
```

## `knotrust audit verify`

```
usage: knotrust audit verify
```

Walks the entire hash-chained audit log and confirms its integrity. Exits
`0` on a clean chain; on a break, exits non-zero and names the exact
location — file, line, sequence number, and the kind of break detected
(`hash_mismatch`, `seq_gap`, `prevhash_mismatch`, or `torn_line`).

```sh [Terminal]
knotrust audit verify
```

See [the audit trail](/guide/core-concepts#the-audit-trail) for what
"tamper-evident" does and doesn't guarantee, and
[Security](/security) for the full threat model.
