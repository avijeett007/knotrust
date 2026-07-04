import { defineConfig } from "tsup";

/**
 * Bundling config for the published `knotrust` CLI (ADR-0016).
 *
 * The CLI is the single published artifact (ADR-0002). Every internal
 * `@knotrust/*` workspace library is inlined INTO this bundle via `noExternal`,
 * so the published tarball carries no `workspace:` runtime dependencies. Output
 * is ESM-only (ADR-0015); the `#!/usr/bin/env node` shebang on `src/bin.ts` is
 * preserved by tsup, which also marks the bin executable.
 *
 * `@modelcontextprotocol/sdk` is the one genuine third-party RUNTIME dependency
 * (P0-E5-T1, R61): the bundled `@knotrust/proxy-stdio` relay imports it. It is
 * left EXTERNAL (declared in the CLI's real `dependencies` with a concrete
 * semver, never `catalog:`) so the consumer's package manager resolves it and
 * its own transitive tree (cross-spawn, zod, …) rather than inlining that whole
 * subtree — and so `npm pack` stays clean of any `workspace:`/`catalog:`
 * specifier (E1-T3 manifest discipline; ADR-0019).
 *
 * `c12` gets the exact same treatment, and for a load-bearing reason
 * (P0-E5-T5): the bundled `@knotrust/store` calls `loadConfig` from `c12` to
 * read `knotrust.config.*`, wired into the CLI's run path at E5-T3. c12's own
 * transitive deps — `dotenv`, `jiti`, `rc9`, `giget`, … — do CJS
 * `require("fs")` at module-eval time. esbuild's ESM output (ADR-0015/ADR-0016)
 * cannot satisfy a runtime `require`, so INLINING that subtree ships a binary
 * that crashes on the very first `node dist/bin.js` with `Error: Dynamic
 * require of "fs" is not supported` (the flagship never even reaches argv
 * parsing). Leaving `c12` EXTERNAL stops esbuild at the c12 boundary — its
 * whole subtree stays out of the bundle and is resolved by the consumer's
 * package manager from c12's own `dependencies` (so listing only `c12` in the
 * CLI's real `dependencies` pulls `dotenv`/`jiti`/… along, mirroring how the
 * SDK pulls `cross-spawn`/`zod`). The unit suite never caught this because it
 * runs `runCli` in-process via vitest and never executes the shipped bundle;
 * `run.built-bin.test.ts` now exercises the real `dist/bin.js` as a child
 * process so a regression can't return silently.
 *
 * `@clack/prompts` (P0-E7-T1, R110 — `knotrust init`'s interactive server
 * selection) needs NO entry in `noExternal`/`external` below: it is listed in
 * `package.json`'s `devDependencies` (mirroring the `@knotrust/*` workspace
 * packages' own placement), and tsup's default is to bundle/inline anything
 * NOT found in real `dependencies`/`peerDependencies` — only `dependencies`
 * are auto-externalized (see the comment on `external` below). It is pure
 * ESM with no native addon, so it inlines cleanly; verified empirically by
 * building and grepping `dist/bin.js` for the bare string `"@clack/prompts"`
 * (none found — confirming no external import/require survived) and by
 * `run.built-bin.test.ts`'s existing `--help`/end-to-end assertions, which
 * would fail loudly (a `Cannot find module` crash) if this ever regressed to
 * an external, unresolvable-by-a-real-consumer import.
 *
 * `zod` (P0-E7-T3, R117 — `add pack`'s pack-file schema) gets the identical
 * `devDependencies` treatment for the identical reason: pure ESM/TS, no
 * native addon, safely inlined rather than added as a new external runtime
 * dependency of the published package. It was ALREADY being bundled
 * transitively before this task (`@knotrust/store`'s `config.ts` uses it,
 * resolved from `packages/store/node_modules` since esbuild resolution is
 * path-based off the importing file) — this `devDependencies` entry only
 * makes it resolvable from `packages/cli`'s own tree too, since
 * `add/pack-schema.ts` imports it directly rather than through
 * `@knotrust/store`'s re-exports.
 *
 * The four `@opentelemetry/*` packages (P0-E8-T1, R127/R128 — the OPTIONAL,
 * off-by-default OTLP exporter `@knotrust/otel` wires in) get the SAME
 * treatment as `c12`, and for the IDENTICAL failure mode, empirically
 * confirmed by literally building both ways and running the result:
 * `@opentelemetry/sdk-trace-node` pulls in
 * `@opentelemetry/context-async-hooks`, which does CJS `require("async_hooks")`
 * at module-eval time. INLINING that subtree (tested by temporarily adding
 * `/^@opentelemetry\//` to `noExternal` below) ships a binary that crashes on
 * the very first `node dist/bin.js` — even `--help` — with `Error: Dynamic
 * require of "async_hooks" is not supported`, the exact same class of failure
 * c12's own comment above documents, just a different built-in module. This
 * is therefore NOT a discretionary bundle-size call: inlining would BREAK the
 * CLI outright for every user, not just the ones who never configure
 * `telemetryExport`. Leaving these four EXTERNAL (declared in the CLI's real
 * `dependencies` with concrete semver, resolved by the consumer's package
 * manager, mirroring `c12`/the SDK) avoids the crash AND keeps a real,
 * measured bundle-size benefit: `dist/bin.js` measured 873.81 KB with these
 * external vs. 1.07 MB inlined (a ~23% smaller bundle for every install,
 * including the overwhelming majority of users who never enable OTel
 * export) — a genuine "a user who doesn't export shouldn't pay the bundle
 * cost" win on top of the correctness requirement.
 * `enforcement.otel.test.ts` (in-process) and this file's own
 * `run.built-bin.test.ts` OTel case (the BUILT binary) both exercise the real
 * wiring so a regression on either axis (crash, or silently becoming
 * unresolvable) can't return silently.
 */
export default defineConfig({
  entry: ["src/bin.ts", "src/index.ts"],
  format: ["esm"],
  target: "node22",
  platform: "node",
  outDir: "dist",
  // Wipe dist before each build so no stale `tsc` output (e.g. compiled
  // *.test.js / *.d.ts) can leak into the published tarball.
  clean: true,
  // The CLI ships no type declarations — it is invoked as `knotrust`, not
  // imported as a typed library (ADR-0015 / ADR-0002).
  dts: false,
  sourcemap: false,
  splitting: false,
  treeshake: true,
  // Inline internal workspace packages; leave real third-party npm deps
  // external for the consumer's package manager to resolve.
  noExternal: [/^@knotrust\//],
  // Explicit (tsup already externalizes `dependencies` by default): the MCP SDK
  // is a real runtime dep, resolved by the consumer, not bundled.
  //
  // `@napi-rs/keyring` is the Rust-backed OS-keychain native module the bundled
  // `@knotrust/grants` loads LAZILY (`keys.ts`'s `import("@napi-rs/keyring")`,
  // only on the keychain-backend path — never on the CLI's resolver-only
  // enforcement path). It is a platform-specific native addon esbuild cannot
  // bundle across platforms' `.node` files, so it stays EXTERNAL and is declared
  // as a concrete-version optionalDependency (mirroring the SDK's real-dep
  // treatment); if it is ever missing at runtime, `keys.ts` already downgrades
  // to the 0600-file backend (R22), so a keychain call is never fatal.
  //
  // `@opentelemetry/*` (four packages) — see the module header above for the
  // empirically-confirmed "inlining crashes the binary" finding (P0-E8-T1).
  external: [
    "@modelcontextprotocol/sdk",
    "@napi-rs/keyring",
    "c12",
    "@opentelemetry/api",
    "@opentelemetry/sdk-trace-node",
    "@opentelemetry/resources",
    "@opentelemetry/exporter-trace-otlp-http",
  ],
});
