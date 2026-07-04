# Configuration

## Where config lives

KnoTrust looks for `knotrust.config.ts`, `.yaml`, or `.json` in the current
working directory (via [`c12`](https://github.com/unjs/c12), so TypeScript
configs are resolved natively, with YAML/JSON supported equally). `knotrust
init` generates one for you the first time it wraps a server; hand-editing
it — or writing one from scratch — works exactly the same way.

If no config is found, `knotrust -- <server>` still runs, but purely as a
passthrough with tool-inventory capture — see
[Installation & Quickstart](/guide/installation#wrapping-a-server-directly).

## Anatomy of `knotrust.config`

```yaml
apiVersion: knotrust/v1
kind: PolicyBundle
scope: personal            # personal | org (org is a future, multi-user scope)
metadata:
  id: my-personal-policy
  version: 3

tiers:
  defaults:
    unknownTool: sensitive        # unannotated tools default here, not routine
    destructiveLooking: critical
  overrides:
    "stripe.create_refund": critical
    "github.*": sensitive
    "filesystem.read_*": routine

failOpen:                  # per-class only, explicit, always audited
  - class: routine
    tools: ["weather.*"]

approval:
  channelOrder: [elicitation_url, block_and_wait]
  timeoutSeconds: 300

pdp:
  engine: L0               # L0 | cedar | authzen_http | opa

adminEnvelope:              # org scope only — caps what personal grants can do
  forceApproval: [critical]
```

| Field | Meaning |
|---|---|
| `scope` | `personal` (default) or `org`. The field exists from the very first schema version even though only `personal` ships today, so a future team/org mode needs no migration. |
| `tiers.defaults.unknownTool` | The tier an unannotated tool falls back to. Deliberately **not** `routine` — an unknown tool is treated as at least `sensitive` until you say otherwise. |
| `tiers.overrides` | Explicit tool-name or glob-pattern tier assignments. These always win over anything a policy pack or a server's own annotations suggest. |
| `failOpen` | An explicit, per-class allowlist of tools that may proceed if the store or policy engine is unreachable. Only ever applies to `routine`; `sensitive`/`critical` never fail open, and every fail-open firing is still written to the audit log. |
| `approval.channelOrder` | Which approval channels to try, in order, for an escalation. `block_and_wait` should generally stay last — it's the universal fallback. |
| `approval.timeoutSeconds` | How long a block-and-wait hold waits before resolving to `deny` (default 300). |
| `pdp.engine` | Which policy-decision engine evaluates anything the tier/grant layer doesn't resolve on its own: the built-in zero-dependency `L0` evaluator (the default), an opt-in Cedar-WASM engine, or an external AuthZEN-HTTP / OPA adapter. |
| `adminEnvelope` | The outer ceiling a personal grant can never exceed — `org` scope only. |

## Risk tiers, in config

Tiers resolve in this order, most authoritative first:

1. An explicit `tiers.overrides` entry in **your own config**.
2. A **signed policy pack**'s tier assignment.
3. A **suggested tier seeded from the server's own tool annotations** —
   never trusted outright.
4. `tiers.defaults.unknownTool` / `destructiveLooking`.

A policy pack may *raise* a tool's tier above what its annotations suggest;
it can never lower a tool below whatever the admin envelope has floored it
at. That clamp exists specifically so a community-contributed pack can never
become a silent downgrade path.

## Policy packs

A **pack** is a declarative YAML bundle of tier assignments for a specific
MCP server (GitHub, Slack, filesystem, Stripe, …), applied with:

```sh [Terminal]
knotrust add pack ./packs/stripe.yaml
```

```yaml
apiVersion: knotrust/v1
kind: PolicyPack
metadata:
  id: stripe
  version: 2
tiers:
  "stripe.create_refund": critical
  "stripe.create_payment": critical
  "stripe.list_charges": routine
seededFromAnnotations: true
```

`knotrust add pack <path>` always prints a human-readable tier diff and asks
for confirmation before merging a pack into your config — pass `--yes` to
skip the prompt, or `--dry-run`/`--diff` to preview without writing
anything, and `--server <name>` to target a server other than the one the
pack names. This mirrors the lesson Homebrew's tap ecosystem learned the
hard way: a policy pack is executable security policy, not a UI snippet, so
it is never silently applied.

Today, `knotrust add pack <path>` loads a **local** file. A signed,
content-hashed pack fetched from a community GitHub registry
(`knotrust add pack <name>`), and an opt-in Cedar-WASM engine
(`knotrust add pdp cedar`), are on the roadmap as new `<kind>` targets for
the same `add` command — see [Architecture](/architecture) for where they
fit.

## Where tiers, packs, and grants meet

Config sets what a *tool* is allowed to need; a [grant](/guide/core-concepts#signed-grants)
is what actually lets a specific caller skip the check. Think of it as:
config decides the risk tier and the fallback behavior for a tool, while a
grant is a standing "yes" a human already gave for a specific
principal/agent/tool/resource combination, within whatever the tier and the
admin envelope allow.
