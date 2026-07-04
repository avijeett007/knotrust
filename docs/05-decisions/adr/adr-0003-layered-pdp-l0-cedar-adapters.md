# ADR-0003: Layered PDP — built-in L0, opt-in Cedar-WASM L1, AuthZEN/OPA adapters

**Status:** Accepted (2026-07-03)

## Context

PRD §21 posed an open question: default PDP — Cedar, OPA, or both? Research found Cedar's Node/WASM path (`@cedar-policy/cedar-wasm`) is official, Node-targeted, actively released (v4.11.2, 2026-06-23), Apache-2.0, and structurally near-identical to AuthZEN's SARC model — but adds ~4.27 MB uncompressed WASM to any install that bundles it, in direct tension with the "npx and go" pitch. OPA's own Node/WASM path (`@open-policy-agent/opa-wasm`) is explicitly OPA's least-invested integration surface — the README self-describes as "Work in Progress," with an ~8-month gap between source activity and the last npm release; OPA's flagship embedding target is Go, not Node. OPA/Styra also explicitly declined native AuthZEN protocol support. Casbin is the only other genuinely embeddable, zero-daemon, pure-TS engine surveyed, but has zero AuthZEN alignment. AuthZEN Authorization API 1.0 reaching Final status (OIDF vote, 2026-01-12) makes a single generic AuthZEN-HTTP adapter viable against the full interop PDP list.

## Decision

Ship a layered PDP model with distinct roles, not a single default engine:
- **L0** — a small, dependency-free, hand-rolled TypeScript risk-tier evaluator: the true zero-config default `npx knotrust` runs on first invocation. Not a general policy language; never marketed as one.
- **L1** — `@cedar-policy/cedar-wasm`, opt-in and lazily installed via `knotrust add pdp cedar`, not bundled. The recommended path once a user writes real policies.
- **Adapters** — a generic AuthZEN HTTP adapter (works with any AuthZEN-interop PDP: Cerbos, Topaz, PlainID, SGNL, …), with a named Cerbos quickstart on top of it; and an OPA REST adapter that performs explicit SARC→Rego `input`-document translation against a user-operated `opa run --server` daemon.

KnoTrust *fronts* PDPs; the PDP interface is the architectural boundary. Cedar being embeddable is an implementation detail of one adapter; OPA/Cerbos being remote is a detail of others. External messaging stays "enforcement + approval layer, PDP-agnostic" and must never claim "OPA speaks AuthZEN."

## Consequences

- First run has zero added dependency weight and zero external-project risk (L0 only).
- Users who need real policy authoring get a formally-verified (Lean-proven), schema-typed, AuthZEN-shaped engine (Cedar) without it costing anything on the default install path.
- Enterprises already running OPA or an AuthZEN-compliant PDP are met where they are, without KnoTrust re-implementing OPA's under-maintained Node/WASM path.
- Docs must carry the positioning note explicitly: embedding Cedar as an opt-in must never read as "KnoTrust is a policy engine" or "OPA speaks AuthZEN."
- Cedar's CNCF Sandbox status (not yet Incubating/Graduated, unlike OPA's CNCF Graduated status) is a smaller-community, earlier-governance dependency accepted in exchange for a clearly superior current Node-embedding story.

## Alternatives considered

- **Bundling Cedar-WASM in the default install** — rejected: ~4.3 MB directly contradicts "npx and go" minimalism.
- **Casbin as the bundled default** — rejected: the strongest genuinely-embeddable pure-TS alternative surveyed, but zero AuthZEN alignment; would require a custom SARC-translation shim with no standards pull to show for it.
- **Oso (Polar)** — rejected from consideration entirely: OSS library frozen/bug-fixes-only since December 2023 (stalled at v0.27.3); the company's surviving product (Oso Cloud) is a different, hosted, non-AuthZEN, proprietary offering.
- **Cerbos or OpenFGA as embedded/bundled options** — rejected: both are client-only architectures (Cerbos's embedded mode needs the commercial Cerbos Hub; OpenFGA embeds only in Go), so both are adapter-only by construction.
- **OPA as an embedded default** — rejected: its Node/WASM path is WIP-labeled and stale-released; an adapter against a user-run daemon is the honest integration shape.

## References

- Brief §B1 (full layered-PDP resolution and positioning note); §D (PDP interface row); §G (Cedar bundling, Casbin, Oso rejections).
- Research: `docs/01-research/pdp-and-crypto.md` §2 (Cedar), §3 (OPA), §4 (Cerbos/OpenFGA/Oso/SpiceDB/Casbin comparison table), §6 (recommendation framing).
