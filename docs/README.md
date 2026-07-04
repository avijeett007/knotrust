# KnoTrust Docs

**Looking for how to install, configure, or use KnoTrust?** Start at the docs website:

**https://avijeett007.github.io/knotrust/**

Getting-started guides, configuration, policy packs, and the full CLI reference all live there — that's the primary, user-facing documentation.

This `docs/` tree is the deeper technical and design reference underneath it: the system architecture, the threat model, the standards research it's built on, and the record of *why* KnoTrust is built the way it is. It's aimed at contributors and anyone who wants to understand the internals, not the first stop if you just want to run the CLI.

## Directory layout

```
docs/
├── 00-overview/        entry point — what KnoTrust is, in one document
├── 01-research/        standards & protocol research behind the design
│                       (AuthZEN/AARP/COAZ, the MCP spec, PDP + crypto choices)
├── 02-architecture/    system design, threat model, tech stack
├── 02-product/         product-level specs (e.g. the revocation-claims language contract)
├── 03-engineering/     build, release, and operational docs
└── 05-decisions/
    └── adr/            one file per fine-grained architecture decision
```

## Design record

This public tree doesn't carry a separate product-requirements document or roadmap. The design record lives in two places:

1. **`docs/02-architecture/`** — the current, authoritative description of how KnoTrust works and why: `system-architecture.md` (surfaces → `DecisionRequest` contract → core → PDP layer → approval orchestrator → audit pipeline, with sequence/component diagrams and an invariant-conformance checklist), `security-threat-model.md` (the proxy-as-high-value-target analysis, threat scenarios from prompt-injection/self-approval through tool-poisoning and key theft), and `tech-stack.md` (the ratified stack, with rationale, for every major dependency choice).
2. **`docs/05-decisions/adr/`** — one Architecture Decision Record per decision, in `context / decision / consequences` form (ADR-0001 through ADR-0021 today: runtime, package shape, PDP layering, grant signing, stores, spec baseline, approval channels, header/body policy, annotations trust, approval app, revocation claims, AARP scope, monorepo tooling, positioning, module format, bundling, timestamp profile, PDP adapter boundary, transport relay, decision composition, fail-open recovery). When you want to know *why* something is built a specific way, the ADR for that decision is the source — don't relitigate a decision without writing a new one.

`docs/01-research/` is the supporting evidence behind those decisions — standards and protocol research, not a decision record in its own right. It's dated and some of it will drift over time (standards maturity in particular): treat claims about spec/finalization status as a snapshot, and check the primary source before relying on them for anything time-sensitive.

## Docs-repo map

### `00-overview/`
The entry point. One document, read first by everyone.
- `executive-summary.md` — what KnoTrust is, the problem/wedge, scope boundary, standards maturity, architecture, decision model, competitive position, roadmap, and current status.

### `01-research/`
Standards and protocol research behind the architecture.
- `authzen-aarp-coaz.md` — verifies the AuthZEN/AARP/COAZ claims against primary OIDF sources; the maturity distinction between "AuthZEN 1.0 Final" and "AARP/COAZ Working Group Draft 1" comes from here.
- `mcp-protocol-and-spec.md` — the MCP spec timeline (2024-11-05 through the 2026-07-28 Release Candidate), transports, header-routing constraints, elicitation, and the SEPs behind the stateless rewrite.
- `pdp-and-crypto.md` — policy-engine (Cedar/OPA/Cerbos) and grant-signing (Ed25519/JWS) research behind the tech-stack decisions.

### `02-architecture/`
Technical design.
- `system-architecture.md` — the surfaces → `DecisionRequest` contract → core → PDP layer → approval orchestrator → audit pipeline, in full; sequence/component diagrams; grant schema (incl. the `ch` call-hash binding); invariant-conformance checklist.
- `security-threat-model.md` — the proxy-as-high-value-target analysis: threat scenarios spanning prompt-injection/self-approval, tool-poisoning/rug-pull, key theft, and bypass routes.
- `tech-stack.md` — the ratified stack (TypeScript/Node ≥22, pnpm+Turborepo, Cedar-WASM/OPA/AuthZEN-HTTP adapters, Ed25519/JWS, Hono, etc.) with rationale and a version-pins/re-verify list.

### `02-product/`
- `revocation-claims.md` — the single source for KnoTrust's revocation-freshness claim language, per mode. Every other artifact (README, website copy, CLI help text, other docs) must link to it rather than restate the claim — restated claims drift, and a drifted revocation claim is exactly the kind of overclaim that doesn't survive scrutiny.

### `03-engineering/`
Build, release, and operational reference.
- `releasing.md` — how the published `knotrust` CLI package is versioned and released (release-please, Conventional Commits).
- `latency-budgets.md` — the proxy's added-latency-over-passthrough benchmark harness and results against the ratified budget table.
- `failure-modes.md` — the stdio proxy's fail-closed doctrine: every failure mode it names, what the proxy does about it, and what the calling agent sees.
- `local-store-layout.md` — the `~/.knotrust/` local store layout, override behavior, and the key-protection doctrine.
- `spike-http-findings.md` — spike findings on stateless HTTP resumption via `requestState` (exploratory, not production).
- `dashboards/README.md` — the reference SigNoz dashboards for dogfooding KnoTrust's own audit/decision telemetry.

### `05-decisions/`
- `adr/` — ADRs 0001–0021, one decision per numbered file (`context / decision / consequences` shape): runtime, package shape, PDP layering, grant signing, stores, spec baseline, approval channels, header/body policy, annotations trust, approval app, revocation claims, AARP scope, monorepo tooling, positioning, module format, CLI bundling, timestamp profile, PDP adapter boundary, transport relay, decision composition, fail-open recovery.

## Reading order

**A new contributor:**
`00-overview/executive-summary.md` → `02-architecture/system-architecture.md` + `tech-stack.md` → `02-architecture/security-threat-model.md` (read before touching `packages/core`, `packages/grants`, `packages/pdp`, or `packages/approval`) → relevant `05-decisions/adr/` entries for rationale on the specific area you're changing → `03-engineering/` docs for build/release/ops mechanics (`releasing.md`, `local-store-layout.md`, `latency-budgets.md`, `failure-modes.md`).

**Someone evaluating the standards foundation:**
`01-research/authzen-aarp-coaz.md` + `01-research/mcp-protocol-and-spec.md` + `01-research/pdp-and-crypto.md` for the primary-source research, then `02-architecture/tech-stack.md` to see how that research became ratified decisions.

## Conventions

- **Markdown-only.** No wiki, no Notion, no separate docs site for this tree — every doc is a `.md` file, reviewed in the same PRs as the code it describes. (The docs *website* linked above is generated separately and covers user-facing guides, not this design reference.)
- **ADR process for new decisions.** A decision not already covered by the architecture docs gets a new sequentially-numbered file in `05-decisions/adr/` (`0001-*.md`, `0002-*.md`, ...). ADRs are the permanent, fine-grained record — don't relitigate a past decision without writing one.
- **Docs are versioned with the code repo.** No separate docs repository. Docs changes land in the same commit history as the code they describe, so a `git blame` on either always finds the other's context.
