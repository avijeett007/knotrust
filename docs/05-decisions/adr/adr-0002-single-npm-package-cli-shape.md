# ADR-0002: Single `knotrust` npm package as the distribution shape

**Status:** Accepted (2026-07-03)

## Context

KnoTrust's flagship first-run experience is `npx knotrust -- your-server` working with zero prior install and zero config. That promise only holds if there is exactly one package name a first-time user has to type and reason about. The closest comparables in the MCP ecosystem — `mcp-remote` and `supergateway` — both validate a "one command, zero config, first value in under a minute" shape as achievable and expected in this space. A fresh, uncached `npx` run installs the full dependency tree before running, so the actual lever on cold-start latency is dependency-tree size, not packaging cleverness.

## Decision

Ship KnoTrust as a single `knotrust` npm package: a CLI with subcommands (`knotrust`, `knotrust init`, `knotrust add pack <x>`, `knotrust -- <server>`), with internal workspace libraries (core, CLI, adapters) bundled into the published package rather than published as separate installable packages.

## Consequences

- First-run friction is minimized: one package name, one `npx` invocation, mode selected by flag/subcommand.
- Internal workspace boundaries (`@knotrust/core`, adapters, etc.) still exist for engineering and testability reasons inside the monorepo (ADR-0013) — they are just not separately published to npm.
- Keeping the dependency tree minimal becomes an explicit, ongoing engineering constraint (e.g., preferring `@clack/prompts` at ~4KB over a heavier prompt library for any interactive UX), since it is the real lever on `npx` cold-start latency.
- A compiled single-binary distribution is deliberately not pursued yet; if an enterprise customer later demands an offline/no-Node installer, Bun `--compile` is the pragmatic choice (a confirmed cross-compile matrix from one CI job: linux x64/arm64 + musl, windows x64/arm64, darwin x64/arm64) over Node's built-in SEA (cannot cross-compile, must build per-target) or `@yao-pkg/pkg` (useful mainly if bytecode obfuscation specifically matters).
- The packaging plan must avoid depending on a `postinstall` lifecycle script, since npm is expected to disable install-lifecycle scripts by default in npm v12 (~mid-2026); any future platform-specific binary distribution should lean on `optionalDependencies` resolution alone.

## Alternatives considered

- **Splitting CLI/proxy/core into separately-installable packages** — rejected: no comparable MCP-ecosystem CLI (`mcp-remote`, `supergateway`, `smithery`) ships this way, and it adds install-order/discovery burden with no offsetting benefit at KnoTrust's current scale.
- **Compiled single-binary distribution (Bun `--compile`, Node SEA, `@yao-pkg/pkg`)** — rejected for v1: none of the closest comparables ship one; revisit only on explicit enterprise demand for an offline installer.

## References

- Brief §D (Package shape row); §G (bundling Cedar rejected as a separate matter, but the same npx-and-go minimalism principle applies here).
- Research: `docs/01-research/competitive-and-packaging.md` §6 ("CLI distribution" — supergateway shape, dependency-tree minimalism, npm v12 install-script disabling, cross-platform binary patterns).
