/**
 * @knotrust/grants — golden-vectors MCP-reference guard (P0-E3-T5, ruling 6).
 *
 * Acceptance requires the entire golden-vectors corpus to contain NO
 * references to MCP types: the vectors exercise core + grants only, never
 * `@modelcontextprotocol/*`, so a future Python (or any other language) port
 * never has to depend on an MCP SDK to reproduce them.
 *
 * This walks the ENTIRE `golden-vectors/` tree (schemas, decisions, grants,
 * sarc-normal-form, schema-validation, test-keys, and every README) — a
 * broader sweep than any single directory this package owns.
 *
 * ## Why this guard lives in `@knotrust/grants`, not `@knotrust/core`
 *
 * `packages/core` carries its OWN, narrower MCP-import boundary: core's
 * source may never *import* an MCP SDK package (invariant §4.1), enforced
 * by two independent gates — `packages/core/scripts/check-boundaries.mjs`
 * (AST-based, package-local) and the repo-level `scripts/check-core-
 * boundary.sh` (a plain grep over `packages/core/src` for any QUOTED
 * occurrence of the banned npm scope, wired into CI). That repo-level grep
 * has no syntax awareness — it cannot distinguish "this file imports the
 * banned package" from "this file contains the banned string as DATA to
 * check other files for it," so a guard test like this one, if placed under
 * `packages/core/src`, would trip that gate on its own `BANNED` constant —
 * a false positive on a test that imports nothing, but a real one on
 * `packages/core`'s narrower "never import MCP" invariant. This directory-
 * spanning corpus guard is a DIFFERENT, broader check (no vector file
 * anywhere references MCP types) and belongs in `@knotrust/grants`, which
 * carries no such repo-level grep gate, to avoid that collision entirely.
 *
 * ## The one deliberate exception (documented, not a false negative)
 *
 * `DecisionRequest.action.properties.mcpMethod` (e.g. `"mcpMethod":
 * "tools/call"`) appears in several fixtures (the architecture §2 examples).
 * This is **core's own contract** (`packages/core/src/contract.ts`'s
 * `Action.properties.mcpMethod?: string`) — an optional, untyped string field
 * that happens to be conventionally populated with an MCP method name by
 * surfaces that front MCP servers. It is NOT an MCP *type* reference: nothing
 * here imports, names, or structurally depends on `@modelcontextprotocol/sdk`
 * types. The guard below asserts the literal absence of the npm scope string,
 * which `"mcpMethod"` does not contain — so this guard and that field
 * coexist without conflict, and this comment exists so a future reader
 * doesn't "fix" the guard to also ban `mcpMethod`.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const goldenVectorsDir = path.resolve(here, "..", "..", "..", "golden-vectors");

// Not obfuscated — see the module header on why a literal here is safe:
// this file lives under packages/grants/src, which the repo-level grep gate
// (scripts/check-core-boundary.sh) never scans (it targets packages/core/src
// only), so this quoted literal cannot collide with that gate.
const BANNED = "@modelcontextprotocol";

function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      out.push(...walkFiles(full));
    } else if (stat.isFile()) {
      out.push(full);
    }
  }
  return out;
}

const files = walkFiles(goldenVectorsDir);

describe("golden-vectors/** — MCP-reference guard (ruling 6)", () => {
  it("finds a non-trivial number of files under golden-vectors/ (sanity check on the walk itself)", () => {
    expect(files.length).toBeGreaterThan(20);
  });

  it.each(
    files.map((f) => [path.relative(goldenVectorsDir, f), f] as const),
  )("%s does not mention the banned MCP SDK npm scope", (_relative, file) => {
    const text = readFileSync(file, "utf8");
    expect(text).not.toContain(BANNED);
  });

  it("mcpMethod (core's own contract field) is present in the corpus and is NOT confused with an MCP-type reference", () => {
    // Sanity-checks the documented exception itself: mcpMethod legitimately
    // appears (proving the guard above isn't vacuously passing because the
    // corpus never touches MCP-adjacent vocabulary at all), while the banned
    // npm-scope string never does.
    const anyMcpMethod = files.some((f) =>
      readFileSync(f, "utf8").includes("mcpMethod"),
    );
    expect(anyMcpMethod).toBe(true);
    const anyBannedScope = files.some((f) =>
      readFileSync(f, "utf8").includes(BANNED),
    );
    expect(anyBannedScope).toBe(false);
  });
});
