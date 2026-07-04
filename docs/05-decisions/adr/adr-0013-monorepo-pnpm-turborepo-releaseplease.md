# ADR-0013: pnpm workspaces + Turborepo monorepo; release-please for multi-language releases

**Status:** Accepted (2026-07-03)

## Context

KnoTrust's codebase spans a core library, CLI, HTTP proxy, and TS SDK today, with a Python SDK planned for Phase 3 (PRD roadmap). The monorepo tooling and release-automation choice need to support this multi-package, eventually-multi-language shape without over-engineering for a package count KnoTrust does not yet have. Research compared pnpm+Turborepo against Nx, and release-please against Changesets, specifically through the lens of the planned Python future.

## Decision

Use pnpm workspaces (with `catalogs` for centralized shared dependency-version ranges) for the monorepo, and Turborepo for task orchestration/caching. Use release-please, plus npm and PyPI OIDC trusted publishing (configured as two independent jobs off one release-please manifest run), for releases — chosen specifically because of the planned Python SDK.

## Consequences

- Turborepo's free Remote Cache on all plans removes what used to be the main cost objection to it versus self-hosting a cache.
- release-please's native, first-class multi-language manifest support (Python `pyproject.toml`/`setup.py` alongside Java/Ruby/PHP/Go/Rust) means the Phase 3 Python package bump is a first-class citizen from day one, not a bolt-on hand-rolled sync layer.
- Provenance and attestation via OIDC trusted publishing (no stored long-lived `NPM_TOKEN`/`PYPI_API_TOKEN`) matters disproportionately for a security tool whose pitch depends on supply-chain trust.
- No single blessed "dual-publish" recipe exists in current tooling for coordinating npm + PyPI off one manifest — the glue coordinating both jobs must be hand-written and maintained.
- The Python SDK's version number is deliberately allowed to drift from the TS packages' version number (per the DeepEval dual-language-monorepo precedent) — lockstep versioning across ecosystems is treated as artificial coupling, not a virtue, so this is not a defect to fix later.
- `uv` (not Poetry) is the Python build/publish tool for the eventual Python SDK, since `uv build`/`uv publish` (since uv 0.4) close Poetry's former publishing-workflow advantage while being substantially faster on cold installs.

## Alternatives considered

- **Nx** — rejected for now: its differentiators (codegen, module-boundary enforcement, deep polyglot build orchestration) are overkill at KnoTrust's current 4-package count; revisit only if package count/team size grows substantially or genuine polyglot *build* (not just versioning) orchestration becomes necessary.
- **Changesets** — rejected in favor of release-please specifically because of the Python future: Changesets would require a hand-rolled custom-sync layer to cover Python (a documented pain point in the one polyglot-Changesets case researched). Changesets' advantage — richer, contributor-authored changelogs — matters more when the primary audience reads detailed hand-written release notes, which is secondary here.
- **Poetry** for the Python SDK — superseded by `uv`, the converging 2025–2026 default (10–100x faster than pip, ~10x faster than Poetry on cold installs).
- **Forcing lockstep version numbers across TS and Python packages** — rejected: treated as artificial coupling per the DeepEval precedent; a second language allowed to drift in version number is not itself a problem.

## References

- Brief §D (Monorepo row: "pnpm workspaces + Turborepo"; Release row: "release-please + npm/PyPI OIDC trusted publishing... chosen over changesets for the Python future"); §G ("changesets (rejected in favor of release-please: Python)").
- Research: `docs/01-research/competitive-and-packaging.md` §6 ("Monorepo tooling" and "Release/publish automation" subsections, including the pnpm catalogs, Turborepo Remote Cache, Trusted Publishing GA dates, `uv` comparison, and DeepEval structural precedent).
