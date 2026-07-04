# Contributing to KnoTrust

Thanks for your interest in KnoTrust. This document covers the practical mechanics of contributing: dev setup, conventions, tests, and where to start.

## Licensing

KnoTrust is licensed under [Apache-2.0](LICENSE). By submitting a contribution (a pull request, patch, or any other content intended for inclusion in this project), you agree it is licensed under the same Apache-2.0 terms as the rest of the repository. There is no separate Contributor License Agreement to sign as of this writing — if a formal CLA process is introduced later, it will be announced here and in the PR template.

## Development setup

**Requirements:**

- Node.js **≥ 22**
- pnpm **11.9.0**, pinned via the root `package.json`'s `packageManager` field. `.npmrc` sets `engine-strict=true`, so a mismatched Node/pnpm version fails fast rather than producing a subtly broken install.

```sh
git clone https://github.com/avijeett007/knotrust.git
cd knotrust
pnpm install
pnpm turbo build test lint typecheck
```

That last command runs `build`, `test`, `lint`, and `typecheck` across every workspace package via [Turborepo](https://turbo.build/), respecting each package's dependency graph. You can also run any one of them alone (`pnpm turbo test`, `pnpm turbo lint`, ...), or scope to a single package with `pnpm --filter <package-name> <script>` (e.g. `pnpm --filter @knotrust/core test`).

Formatting and linting use [Biome](https://biomejs.dev/) (`biome.json` at the repo root); `pnpm format` writes fixes, `pnpm turbo lint` checks without writing (`--error-on-warnings`, so warnings fail CI the same as errors).

## Monorepo layout

pnpm + Turborepo workspace. The packages that matter for almost any change:

| Package | Purpose |
|---|---|
| `packages/core` (`@knotrust/core`) | Surface-agnostic decision core: the `DecisionRequest`/`DecisionResponse` contract, the risk-tier evaluator, the precedence engine, the decision cache. No MCP imports — this boundary is load-bearing and checked. |
| `packages/grants` (`@knotrust/grants`) | Ed25519 identity + signed grant mint/verify (JWS Compact), durable vs. ephemeral grant lifecycle, revocation. |
| `packages/store` (`@knotrust/store`) | Local file-based state: the grants directory store, config loading (`knotrust.config.*`), the hash-chained append-only audit log. |
| `packages/proxy-stdio` (`@knotrust/proxy-stdio`) | The MCP stdio proxy: child process spawn/passthrough, `tools/list` interception, `tools/call` enforcement hook. |
| `packages/pdp` (`@knotrust/pdp`) | The PDP adapter interface + registry, with the built-in L0 evaluator as the default. |
| `packages/approval` (`@knotrust/approval`) | The approval orchestrator: lifecycle state machine, the block-and-wait channel, the localhost approval page. |
| `packages/otel` (`@knotrust/otel`) | Optional OpenTelemetry OTLP exporter for decision spans and audit events. Off by default. |
| `packages/cli` (published as `knotrust`) | The CLI: the `knotrust -- <server>` runner, `init`, `grant`/`grant list`/`revoke`, `add pack`, `audit list|tail|query|verify`. Bundles every other workspace package at publish time — it's the only package that actually ships to npm. |

Supporting workspaces:

- `test/harness` (`@knotrust/test-harness`, private) — a fake MCP server/client used across integration tests.
- `test/adversarial` (`@knotrust/adversarial-tests`, private) — end-to-end adversarial suites (prompt-injection/self-approval attempts, grant replay, store tampering, approval-page CSRF/DNS-rebinding, TOCTOU bait-and-switch, ...). Run with `pnpm --filter @knotrust/adversarial-tests test`.
- `test/bench` (`@knotrust/bench`, private) — latency-budget benchmarks for the proxy's added-overhead-over-passthrough claims. Build then run with `pnpm --filter @knotrust/bench build && pnpm --filter @knotrust/bench bench`.
- `golden-vectors/` — language-neutral JSON fixtures (decision outcomes, grant verification cases, SARC normal-form, schema validation) that any language implementation of the core must agree with. If you touch `packages/core` or `packages/grants`, check whether a golden vector needs a new case or an update.

## Commit conventions

Commits to `main` follow [Conventional Commits](https://www.conventionalcommits.org/) (`type(scope): subject`, e.g. `fix(proxy-stdio): ...`, `feat(cli): ...`, `docs(threat-model): ...`, `test(adversarial): ...`). This isn't just style: [release-please](https://github.com/googleapis/release-please) reads these to decide version bumps for the published `knotrust` package (`feat:` → minor, `fix:` → patch) and to generate its changelog. See `docs/03-engineering/releasing.md` for the full release pipeline.

## Running tests

```sh
pnpm turbo test                          # everything, respecting the build graph
pnpm --filter @knotrust/core test        # one package
pnpm --filter @knotrust/adversarial-tests test   # the adversarial suite
pnpm --filter @knotrust/bench bench      # the latency benchmark (after building)
```

Tests run on [Vitest](https://vitest.dev/) via the shared root `vitest.config.ts`, split into per-package projects.

## Where to start

- Browse [GitHub issues](https://github.com/avijeett007/knotrust/issues) for well-scoped work; issues labeled `good first issue` are scoped to a single package and don't require deep familiarity with the decision core. For design context on a given area, see `docs/02-architecture/system-architecture.md` and the relevant `docs/05-decisions/adr/` entry.
- Community **policy packs** (`knotrust add pack <path>`, see `docs/02-architecture/system-architecture.md` §8.2) for popular MCP servers are one of the most approachable contributions: a YAML file mapping a server's tools to risk tiers, with a human-readable diff preview before it's ever applied.
- Read `docs/02-architecture/system-architecture.md` and `docs/02-architecture/security-threat-model.md` before touching `packages/core`, `packages/grants`, `packages/pdp`, or `packages/approval` — these are the security-relevant packages, and changes there are held to a higher bar (see `SECURITY.md`).

## Pull requests

- Keep PRs scoped to one logical change; large refactors are easier to review split up.
- Add or update tests for behavior changes — this is a security-relevant tool, and untested behavior in the decision path is a bug waiting to happen.
- `pnpm turbo build test lint typecheck` should pass locally before you open a PR; CI runs the same checks.
