# Releasing `knotrust`

How the single published package — the `knotrust` CLI (`packages/cli`) — is versioned, verified, and (eventually) published. Only `packages/cli` is publishable; the eight `@knotrust/*` packages are `private` and are **bundled into the CLI** at build time (ADR-0016), not published.

Automation lives in [`.github/workflows/release.yml`](../../.github/workflows/release.yml), with config in [`release-please-config.json`](../../release-please-config.json) and [`.release-please-manifest.json`](../../.release-please-manifest.json).

> Status (Phase 0): the pipeline is built and locally verified, but the **real publish has never fired and must not** until Phase 1. The `knotrust` npm name/trademark check is a Phase-1 gate — Phase 0 must neither squat nor publish. Everything below the "Publish" heading is therefore dormant by design.

## 1. Versioning — release-please

We use [release-please](https://github.com/googleapis/release-please) in **manifest mode** (chosen over Changesets for first-class Python support later — ADR-0013). The flow:

1. You merge [Conventional Commits](https://www.conventionalcommits.org/) to `main` (`feat:` → minor, `fix:` → patch; pre-1.0 bumps stay in the `0.x` range).
2. On each push to `main`, the `release-please` job opens **or updates a release PR** that bumps `packages/cli` version, updates its `CHANGELOG.md`, and rolls `.release-please-manifest.json`.
3. When you merge that release PR, release-please tags the release (`knotrust-v<version>`) and creates the GitHub Release.

The component is `knotrust`, release-type `node`, current version `0.0.0`.

## 2. Verification — automatic dry-run (safe)

The `dry-run-verify` job runs on **every push to `main`** and on every manual dispatch. It builds the CLI (`pnpm turbo build --filter=knotrust`, which bundles `@knotrust/*` via tsup) and then **mechanically asserts** on the packed tarball (`npm pack` — never publishes, never authenticates):

- `dist/bin.js` is present (the bundled bin).
- **No** compiled test artifacts / sourcemaps / type declarations (`*.test.*`, `*.spec.*`, `*.map`, `*.d.ts`).
- The installable dependency surface (`dependencies` / `optionalDependencies` / `peerDependencies`) has **no** `workspace:` or `catalog:` specifier. (`devDependencies` are excluded on purpose — they are never installed by a consumer of a published package, so a `workspace:`/`catalog:` there is inert.)
- `@knotrust/core` is **inlined** into the bundle (no external `@knotrust/*` import remains).

Any failed assertion fails the job. This proves pipeline correctness without claiming the npm name.

## 3. Publish — manual, gated, OIDC (dormant in Phase 0)

The `publish` job performs the real npm publish. It is **hard-gated** and cannot fire from a `push`, `pull_request`, `schedule`, or a release-please release. It runs **only** when you manually dispatch the workflow and type the exact confirmation phrase:

```
publish = I-UNDERSTAND-THIS-CLAIMS-THE-NPM-NAME
```

When (and only when) that holds, and after `dry-run-verify` passes, it:

- upgrades npm to **≥ 11.5.1** (Node 22 ships npm 10.x; OIDC Trusted Publishing needs 11.5.1+),
- runs `npm publish --provenance --access public` via **OIDC trusted publishing** — `permissions: id-token: write`, **no stored token anywhere** (no `NODE_AUTH_TOKEN`, no secrets, no registry auth in `.npmrc`).

### Preconditions before the first real publish (Phase 1)

1. **npm name/trademark check passes** — the Phase-1 gate. Do not run this job before then.
2. **Trusted Publishing is configured on npmjs.com** for the `knotrust` package — link this GitHub repo + the `release.yml` workflow as a trusted publisher (brief §H5). Provenance/OIDC publish will fail until this launch-time step is done.
3. If your org disallows "Actions creating pull requests," give the `release-please` job a PAT or GitHub App token (see the comment in `release.yml`).

## Deferred to first push (no remote in Phase 0)

release-please opening an actual release PR, tag creation, and CI provenance attestation can only be exercised once a GitHub remote exists and `main` receives commits. They are verified by design/schema locally; end-to-end confirmation happens on first push.

## References

- ADR-0013 — monorepo tooling + release-please (and the npm/PyPI OIDC trusted-publishing direction).
- ADR-0016 — tsup bundling of the published CLI (why the tarball inlines `@knotrust/*`).
