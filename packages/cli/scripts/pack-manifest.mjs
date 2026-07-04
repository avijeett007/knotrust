#!/usr/bin/env node
/**
 * prepack/postpack helper for the published `knotrust` package (P0-E1-T3).
 *
 * The published tarball must carry no pnpm-protocol specifiers
 * (`workspace:*`, `catalog:`) anywhere in package.json, including
 * `devDependencies`. devDependencies are never installed by a consumer of a
 * published package, so a `workspace:`/`catalog:` there is install-inert —
 * but this is a supply-chain-trust product whose published artifact gets
 * audited on a *whole-manifest* reading, and the plan's acceptance
 * criterion ("no workspace-internal `workspace:` specifiers") reads the
 * whole file, not just the installable-deps subset.
 *
 * `npm pack` / `npm publish` run the `prepack` script before building the
 * tarball and `postpack` after. This script strips `devDependencies` from
 * the *working-tree* package.json for the duration of packing ("strip",
 * wired to prepack) and restores the original byte-for-byte afterward
 * ("restore", wired to postpack). The bundled CLI needs no devDependencies
 * at runtime; the working tree keeps them for local development — this
 * never touches git history, only the on-disk file for the packing window.
 *
 * Crash safety: the backup lives next to package.json as `package.json.bak`
 * (gitignored — see .gitignore). Both modes are idempotent:
 *   - "strip": if a backup already exists, a previous run crashed before
 *     restoring. Restore from it first, so a stale *stripped* manifest is
 *     never backed up over the real one, then proceed with a fresh strip.
 *   - "restore": if there's no backup, it's a no-op (e.g. prepack never
 *     ran, or a prior run already restored).
 *
 * Residual risk: if `npm pack` crashes hard enough that postpack never
 * runs at all (npm does not guarantee postpack fires on every failure mode
 * of the underlying tar step), `package.json.bak` is left on disk and the
 * working-tree package.json stays stripped. Recover by hand with:
 *   node scripts/pack-manifest.mjs restore
 * CI's `git diff` / `git status` check on the working tree after packing
 * would also surface this as a dirty tree rather than silently shipping it.
 *
 * Logging note: `npm pack`/`npm publish` inherit lifecycle-script stdout
 * into their own stdout, which lands in `npm pack --json`'s output stream.
 * If this script logged to stdout, `npm pack --json > pack.json` (as used
 * in CI) would get non-JSON lines prepended and fail to parse. All
 * diagnostics below therefore go to stderr.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { copyFile, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.resolve(here, "..");
const manifestPath = path.join(pkgDir, "package.json");
const backupPath = path.join(pkgDir, "package.json.bak");

/** @returns {Promise<boolean>} whether a backup existed and was restored */
async function restoreIfBackupExists() {
  if (!existsSync(backupPath)) return false;
  await copyFile(backupPath, manifestPath);
  await rm(backupPath);
  return true;
}

async function strip() {
  if (await restoreIfBackupExists()) {
    console.error(
      "[pack-manifest] found a stale package.json.bak from a previous run; " +
        "restored it before re-stripping.",
    );
  }

  const original = readFileSync(manifestPath, "utf8");
  const manifest = JSON.parse(original);

  if (!("devDependencies" in manifest)) {
    console.error(
      "[pack-manifest] no devDependencies in package.json; nothing to strip.",
    );
    return;
  }

  // Byte-identical backup so "restore" can put the working tree back exactly
  // as it was (verified in CI with `git diff`).
  await copyFile(manifestPath, backupPath);

  delete manifest.devDependencies;
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  console.error(
    "[pack-manifest] stripped devDependencies from package.json for packing.",
  );
}

async function restore() {
  const restored = await restoreIfBackupExists();
  console.error(
    restored
      ? "[pack-manifest] restored package.json from package.json.bak."
      : "[pack-manifest] no package.json.bak found; nothing to restore.",
  );
}

const mode = process.argv[2];
if (mode === "strip") {
  await strip();
} else if (mode === "restore") {
  await restore();
} else {
  console.error(
    `[pack-manifest] unknown mode "${mode}". Usage: pack-manifest.mjs <strip|restore>`,
  );
  process.exit(1);
}
