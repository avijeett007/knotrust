# ADR-0016: tsup for bundling the published `knotrust` CLI

**Status:** Accepted (2026-07-03)

## Context

The single artifact KnoTrust publishes to npm is the `knotrust` CLI (ADR-0002); the eight `@knotrust/*` workspace packages are `private: true` and are meant to be **inlined into the CLI at publish time**, not published individually. The whole monorepo is ESM-only (ADR-0015). Release automation (P0-E1-T3) adds a hard acceptance bar for the published tarball: it must (a) carry **no** `workspace:` specifiers in its installable dependency surface, (b) contain **no** compiled test artifacts (`*.test.js`, `*.d.ts`, sourcemaps), (c) preserve the `#!/usr/bin/env node` shebang on the `bin` entry, and (d) actually inline the internal workspace libraries so a consumer's `npm install knotrust` pulls zero `@knotrust/*` runtime deps.

Plain `tsc` — the build tool for the private packages — does none of this: it emits one `.js` + `.d.ts` per source file (including test files) into `dist/` and does not bundle or inline dependencies. A CLI built with `tsc` would therefore either ship unresolvable `workspace:` runtime dependencies or leak test artifacts (both were live defects: `tsc` was emitting `index.test.js`/`index.test.d.ts` into `packages/cli/dist/`, and the package had no `files` allowlist). A bundler is required for the CLI specifically.

## Decision

Use **tsup** (esbuild-based) as the build tool for `packages/cli` only. The `build` script becomes `tsup`, configured (`packages/cli/tsup.config.ts`) to bundle `src/bin.ts` + `src/index.ts` as **ESM**, `target: node22`, `noExternal: [/^@knotrust\//]` to inline every internal workspace package, `clean: true`, and `dts: false`. `tsup` preserves the shebang and marks the bin executable. `typecheck` stays `tsc --noEmit`, and the eight private `@knotrust/*` packages keep their plain `tsc` builds. tsup is pinned through the pnpm `catalog`.

This does **not** contradict ADR-0015. ADR-0015 rejected tsup as a means of **dual CJS+ESM emit**; here tsup produces a **single ESM output**. Single-format bundling to inline workspace libraries is a different use and is consistent with the ESM-only decision.

## Consequences

- The published tarball inlines `@knotrust/core` (and any future `@knotrust/*` lib) directly into `dist/bin.js` / `dist/index.js`; the tarball's runtime `dependencies` field is empty/absent, so **no `workspace:` specifier ever reaches a consumer**. The CI dry-run job mechanically asserts this (P0-E1-T3).
- `clean: true` plus the two-entry allowlist means `dist/` holds only `bin.js` + `index.js` — no compiled test files, no `.d.ts`, no maps — and a `files: ["dist"]` allowlist on `packages/cli` backs the guarantee at pack time.
- The CLI ships **no** type declarations. This is acceptable: `knotrust` is invoked as a binary, not imported as a typed library (ADR-0002 / ADR-0015), so the `exports` map drops its `types` condition.
- esbuild (tsup's engine) is a new transitive dependency with a `postinstall` build script. It is kept **outside the trust boundary** (`allowBuilds: esbuild: false` in `pnpm-workspace.yaml`): the postinstall never runs, and esbuild's native binary is taken from the `@esbuild/<platform>` optional dependency instead. The default-deny supply-chain posture — load-bearing for a security product — is preserved.
- The monorepo now runs two build tools (tsc for libraries, tsup for the CLI). The cost is small and contained; `typecheck` remains uniform (`tsc --noEmit`) across every package.

## Alternatives considered

- **Raw esbuild** — rejected: more hand-rolled glue (shebang preservation, bin `chmod`, entry/format/`.d.ts` wiring) that tsup provides out of the box, for no offsetting benefit at this scale.
- **rollup** — rejected: slower and configuration-heavy for what is a two-entry ESM bundle with workspace inlining.
- **unbuild** — rejected: a heavier, less direct fit than tsup for a single-CLI bundle; tsup is the ecosystem default for TS CLIs.
- **Keep plain `tsc` for the CLI** — rejected: `tsc` neither bundles/inlines workspace dependencies nor omits test artifacts, so it would ship either unresolvable `workspace:` runtime deps or compiled test files — exactly the defects this task must close.
- **Publish every workspace package unbundled** — rejected: contradicts the single-published-package decision (ADR-0002) and would force publishing the eight `private` packages.

## References

- Task brief P0-E1-T3, orchestrator resolution #1 (bundler = tsup; rationale: esbuild speed, first-class TS + ESM + shebang/bin handling, `noExternal` inlining of `@knotrust/*`, ecosystem default; alternatives to record).
- ADR-0002 (`docs/05-decisions/adr/adr-0002-single-npm-package-cli-shape.md`) — the single-published-CLI shape that makes inlining the requirement.
- ADR-0013 (`docs/05-decisions/adr/adr-0013-monorepo-pnpm-turborepo-releaseplease.md`) — the release-please automation this bundling feeds.
- ADR-0015 (`docs/05-decisions/adr/adr-0015-esm-only-module-format.md`) — ESM-only; tsup used here for single-format bundling, not the dual-emit that ADR rejected.
- `docs/03-engineering/releasing.md` — how the bundled tarball is verified in CI and how the gated publish works.
