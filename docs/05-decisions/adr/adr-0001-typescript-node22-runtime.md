# ADR-0001: TypeScript on Node ≥ 22 as the core runtime

**Status:** Accepted (2026-07-03)

## Context

KnoTrust ships as an `npx`-distributed CLI/proxy that must interoperate directly with the official MCP SDK ecosystem, which is overwhelmingly TypeScript/Node-first. The decision core, CLI, and both proxies (stdio and future HTTP) need to share one language so that the surface-agnostic core (PRD §8) is not fragmented by a language boundary between "speaks MCP" and "evaluates policy." Node 20 reaches end-of-life in April 2026, before KnoTrust's Phase 1 launch, so any runtime floor set below Node 22 would ship against an already-sunsetting line. A Python SDK is planned for Phase 3 but is explicitly a later, separate port — it does not change the Phase 0–2 runtime choice.

## Decision

Build KnoTrust's core, CLI, and proxies in TypeScript, targeting Node ≥ 22 (the current LTS at ratification time) as the minimum supported runtime.

## Consequences

- One language spans core/CLI/proxies; no FFI or cross-process boundary is needed between the decision core and the MCP-facing surfaces.
- Node ≥ 22 unlocks stable WebCrypto `SubtleCrypto` Ed25519 support (from Node v22.13.0), giving the crypto layer (ADR-0004) an optional native fast-path later without a second runtime-floor bump.
- The Python SDK (Phase 3) is additive, not blocking — it is a real port of the L0 evaluator and JWS grant verification via Python's `cryptography` library, not an FFI or daemon dependency on the TS core.
- Committing to Node ≥ 22 means dropping Node 20 support immediately; this is intentional given Node 20's EOL timing relative to launch.

## Alternatives considered

- **Bun/Deno single-binary distribution** — rejected for v1: the `npx`-first distribution path and guaranteed compatibility with the official `@modelcontextprotocol/sdk` outweigh Bun/Deno's faster cold start and single-binary packaging today. Revisited specifically for the future F1 desktop app (PRD §19), where a compiled binary matters more than `npx` ergonomics.
- **Node ≥ 20 floor** — implicitly rejected by the EOL timing: Node 20 EOLs in April 2026, before Phase 1 launch, making Node ≥ 22 the only LTS line consistent with a stable launch runtime.

## References

- Brief §D (Language / runtime row); §G ("Bun/Deno single-binary distribution (rejected for v1: npx path + official SDK compatibility wins; revisit for the desktop app F1)"); §H.4 ("Node ≥ 22 floor — approve").
- Research: `docs/01-research/pdp-and-crypto.md` §7.1 (WebCrypto Ed25519 stable since Node v22.13.0).
