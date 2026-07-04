# ADR-0015: ESM-only module format

**Status:** Accepted (2026-07-03)

## Context

The monorepo scaffold (P0-E1-T1) needs a module-format decision before any package accumulates source: dual CJS+ESM publishing (the common library-author default), CJS-only, or ESM-only. Two facts already ratified elsewhere change the usual calculus for this choice. First, the Node ≥ 22 floor (brief §D; ADR-0001) means any future CJS consumer can `require()` an ESM package directly — Node's `require(esm)` interop, unconditionally available from Node 22 onward, removes the historical reason a Node library defaults to dual-publishing. Second, the single published artifact is the `knotrust` CLI (ADR-0002), invoked as `npx knotrust` / `knotrust -- <server cmd>`; nobody is expected to `require('knotrust')`/`import knotrust from 'knotrust'` into their own application bundle the way a library consumer would. On top of that, the official `@modelcontextprotocol/sdk`, which `packages/proxy-stdio` and transitively `packages/cli` depend on, is itself ESM-first.

## Decision

All KnoTrust workspace packages are **ESM-only**: `"type": "module"` in every `package.json`, an `"exports"` map pointing at compiled `dist/` output (no top-level CJS `main` fallback, no `.cjs` build artifact), and `tsconfig.json` compiles with `"module": "NodeNext"` / `"moduleResolution": "NodeNext"`. This applies uniformly to every internal `@knotrust/*` package and to the published `knotrust` CLI package.

## Consequences

- Simpler build: one `tsc` output per package, one module setting across the monorepo — no dual-emit step (e.g. `tsup` with two targets) and no `.cjs`/`.mjs` file-extension juggling or twin `.d.ts`/`.d.cts` type declarations.
- A future CJS consumer that needs `require('knotrust')` (or `require('@knotrust/core')` if a library-surface ships later) is not blocked outright: Node ≥ 22's `require(esm)` support lets a CJS caller `require()` an ESM package directly, which is the interop path this decision relies on instead of dual publishing.
- The CLI's `bin` entry point (`packages/cli/src/bin.ts` → `dist/bin.js`) is a plain ESM script with a preserved shebang; `npx knotrust` invocation does not depend on the package's module format being CJS.
- This is a default that is revisited, not assumed permanent: if a future consumer surfaces a hard requirement that genuinely cannot use `require(esm)` interop (a bundler/runtime target with no Node ≥ 22 semantics, for instance), or if the Phase-3 SDK work (a TS/JS library surface distinct from the CLI) turns up a real CJS-only consumer, this ADR is revisited then. The planned Python SDK does not create this pressure — it is a separate ecosystem with its own packaging (`uv`, per ADR-0013) and is out of scope for this decision.

## Alternatives considered

- **Dual CJS+ESM publish** (e.g. via `tsup` with two build targets) — rejected: the added complexity (dual build step, conditional `exports` maps, twin type declarations, the well-documented dual-package-hazard footguns of shared module state) is not justified when the only published artifact is a CLI, not a library consumers `import`/`require` into their own bundles.
- **CJS-only** — rejected: the official MCP SDK and its dependency tree are ESM-first; a CJS-only package would need to carry interop shims KnoTrust does not otherwise need, for no compensating benefit now that Node ≥ 22's `require(esm)` already covers the CJS-consumer case.
- **Defer the decision to P0-E1-T2** — rejected: the module format is load-bearing for every `package.json`, `tsconfig.json`, and import statement written starting with the first package stub in P0-E1-T1; deciding it later would mean rewriting scaffolding already in place rather than adding to it.

## References

- Task brief P0-E1-T1, orchestrator resolution #2 (ESM-only module format; rationale: Node ≥ 22 floor and `require(esm)` interop, `npx knotrust` as the primary consumption path rather than a library import, the MCP SDK being ESM-first, dual-format publishing complexity not being justified; revisit only if the Phase-3 SDK surfaces a hard CJS consumer requirement).
- ADR-0001 (`docs/05-decisions/adr/adr-0001-typescript-node22-runtime.md`) — the Node ≥ 22 floor this decision's interop argument depends on.
- ADR-0002 (`docs/05-decisions/adr/adr-0002-single-npm-package-cli-shape.md`) — the single-published-CLI shape that makes dual-publishing unnecessary.
- ADR-0013 (`docs/05-decisions/adr/adr-0013-monorepo-pnpm-turborepo-releaseplease.md`) — the monorepo tooling this format decision builds on.
- `docs/05-decisions/2026-07-03-decisions-brief.md` §D (Node ≥ 22 floor; monorepo tooling row).
