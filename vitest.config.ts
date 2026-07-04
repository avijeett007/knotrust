import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// One root-level Vitest config enumerating every workspace package as a
// project. Vitest 3.2 deprecated the standalone `vitest.workspace.ts` file in
// favor of `test.projects` here, and Vitest 4 (the major installed by this
// task) carries that forward — see report for the filename-deviation note.
//
// Each package's own `test` script invokes this config with
// `--config ../../vitest.config.ts`, which pnpm/turbo runs with the package
// directory as the working directory. Project `root` values are therefore
// resolved as absolute paths from this file's own location (not from
// `process.cwd()`), so the same config behaves identically whether it is
// invoked from the repo root or from within a single package directory.
const repoRoot = path.dirname(fileURLToPath(import.meta.url));

// `tsc` (the `build` script) compiles every file under a package's `src`,
// including colocated `*.test.ts` files, into `dist/`. Exclude `dist` from
// test discovery so a package's tests never run twice (once from source,
// once from the compiled build output).
const sharedExclude = ["**/dist/**", "**/node_modules/**"];

const packageProjects = [
  "approval",
  "cli",
  "core",
  "grants",
  "otel",
  "pdp",
  "proxy-stdio",
  "store",
].map((name) => ({
  extends: true,
  test: {
    name,
    root: path.join(repoRoot, "packages", name),
    exclude: sharedExclude,
  },
}));

export default defineConfig({
  test: {
    projects: [
      ...packageProjects,
      {
        extends: true,
        test: {
          name: "harness",
          root: path.join(repoRoot, "test", "harness"),
          exclude: sharedExclude,
        },
      },
      {
        extends: true,
        test: {
          name: "adversarial",
          root: path.join(repoRoot, "test", "adversarial"),
          exclude: sharedExclude,
        },
      },
      {
        extends: true,
        test: {
          name: "bench",
          root: path.join(repoRoot, "test", "bench"),
          exclude: sharedExclude,
        },
      },
    ],
  },
});
