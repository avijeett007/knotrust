#!/usr/bin/env node
// packages/core/scripts/check-boundaries.mjs
//
// Package-local half of the MCP-import ban (invariant §4.1, ratified brief
// §E1 / architecture §12): `@knotrust/core` must never import
// `@modelcontextprotocol/*` or anything under a `packages/proxy-*` package.
// Standing in for a dependency-cruiser config, per the task's explicit
// "or an equivalent dedicated script" allowance (P0-E2-T1 ruling 5a) — this
// keeps the check dependency-free beyond the `typescript` devDependency this
// package already has, instead of pulling in a new tool solely to express
// one static rule.
//
// P0-E2-T5 (ruling R18) extends the banned list with `@knotrust/pdp`: the
// `PdpAdapter` port TYPES live in `@knotrust/core` (`pdp-port.ts`) precisely
// so `@knotrust/pdp` can depend on `@knotrust/core` (for these types, and
// for `evaluatePrecedence` in the built-in L0 adapter) without a cycle. That
// direction only holds if core never imports pdp back — this gate makes the
// port direction mechanical, not just documented. See ADR-0018
// (`docs/05-decisions/adr/adr-0018-pdp-adapter-boundary.md`).
//
// Wired as this package's `lint:boundaries` script, and folded into `lint`
// (see package.json) so `turbo run lint` exercises it for `@knotrust/core`
// automatically. The independent repo-level check — `scripts/check-core-
// boundary.sh` — is a plain grep and is the one wired into CI (ruling 5b).
//
// The two gates are NOT mirrors of each other, and neither is required to
// "agree" with the other before either is trusted — they are two
// overlapping gates with different blind spots, and the design property
// that matters is that their UNION covers every realistic accidental
// import. This AST-based gate parses real import/export/dynamic-import/
// require module specifiers, so it has zero false positives from comments
// or string literals that merely mention the banned names — but it only
// sees the file set and specifier forms it is taught to walk. The grep-
// based gate has the complementary blind spot: no syntax awareness (so a
// mention of a banned name in a *quoted* comment could in principle read as
// a hit — see that script's own header for how it narrows this), but no
// dependency on TypeScript parsing succeeding, so it still runs over
// non-parseable or generated files. Only deliberate obfuscation of the
// specifier (e.g. building the string at runtime, or otherwise hiding it
// from both static parsing and a quoted-substring grep) could evade both;
// that is out of scope for a static import-boundary lint.
//
// Method: walk packages/core/src, parse each .ts file with the TypeScript
// compiler API (already a devDependency), collect every static
// import/export/dynamic-import/require module specifier, and fail on any
// specifier matching a banned pattern. Using the compiler's AST (rather
// than a blind grep) avoids false positives from comments or string
// literals that merely mention the banned names.

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.resolve(here, "..", "src");

const BANNED = [
  { pattern: /^@modelcontextprotocol(\/|$)/, label: "@modelcontextprotocol/*" },
  {
    pattern: /(^|\/)@knotrust\/proxy-/,
    label: "any packages/proxy-* package (@knotrust/proxy-*)",
  },
  { pattern: /(^|\/)packages\/proxy-/, label: "any packages/proxy-* path" },
  {
    pattern: /^@knotrust\/pdp(\/|$)/,
    label:
      "@knotrust/pdp (R18: the PdpAdapter port lives in core; implementations/registry live in pdp, never the reverse)",
  },
];

/** @param {string} dir */
function walkTsFiles(dir) {
  /** @type {string[]} */
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      out.push(...walkTsFiles(full));
    } else if (/\.tsx?$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

/** @param {string} file */
function moduleSpecifiersOf(file) {
  const text = readFileSync(file, "utf8");
  const source = ts.createSourceFile(
    file,
    text,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    ts.ScriptKind.TS,
  );

  /** @type {string[]} */
  const specifiers = [];

  /** @param {ts.Node} node */
  const visit = (node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      specifiers.push(node.moduleSpecifier.text);
    } else if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length > 0 &&
      ts.isStringLiteral(node.arguments[0])
    ) {
      // Dynamic import: `import("...")`.
      specifiers.push(node.arguments[0].text);
    } else if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "require" &&
      node.arguments.length > 0 &&
      ts.isStringLiteral(node.arguments[0])
    ) {
      // CJS-style `require("...")` call expression. This repo is ESM-only
      // (ADR-0015), but `require()` is still valid TypeScript/JavaScript
      // syntax (e.g. via `createRequire`, as packages/core/src/contract.test.ts
      // itself does for `ajv-formats`) and was previously invisible to this
      // gate — only import/export/dynamic-import specifiers were collected.
      // Any bare `require("@modelcontextprotocol/...")` or
      // `require("@knotrust/proxy-...")` must be caught exactly like a
      // static import.
      specifiers.push(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  };

  visit(source);
  return specifiers;
}

const files = walkTsFiles(srcDir);
/** @type {Array<{ file: string; specifier: string; label: string }>} */
const violations = [];

for (const file of files) {
  for (const specifier of moduleSpecifiersOf(file)) {
    for (const { pattern, label } of BANNED) {
      if (pattern.test(specifier)) {
        violations.push({
          file: path.relative(process.cwd(), file),
          specifier,
          label,
        });
      }
    }
  }
}

if (violations.length > 0) {
  console.error(
    "lint:boundaries — @knotrust/core boundary violations found:\n",
  );
  for (const v of violations) {
    console.error(`  ${v.file}: imports "${v.specifier}" (banned: ${v.label})`);
  }
  console.error(
    "\n@knotrust/core must not import @modelcontextprotocol/* or any packages/proxy-* path " +
      "(invariant §4.1). MCP specifics belong in an enforcement-surface package, never in core.",
  );
  process.exit(1);
}

console.log(
  `lint:boundaries — OK (${files.length} file(s) scanned under packages/core/src, 0 violations).`,
);
