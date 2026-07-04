#!/usr/bin/env node
// packages/store/scripts/generate-config-schema.mjs
//
// Regenerates golden-vectors/schemas/config.v1.schema.json FROM
// `KnotrustConfigSchema` (packages/store/src/config.ts) via zod v4's native
// `z.toJSONSchema` — the source of truth is the zod schema, this script (and
// its committed output) is a derived artifact (P0-E4-T2, R47).
//
// Requires a fresh `tsc` build first (this package's `generate:schema` npm
// script chains `tsc && node scripts/generate-config-schema.mjs`) — this
// plain Node script imports the COMPILED `dist/config.js`, not the TS
// source, so it needs no TypeScript loader of its own. `config.test.ts`'s
// sync test is the fast, CI-enforced check (it imports the live TS source
// directly via Vitest and asserts deep-equal against the committed file);
// this script is the human-run "regenerate on schema change, then commit"
// tool the sync test's own failure message points at.
//
// Run: `pnpm --filter @knotrust/store run generate:schema`

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildConfigJsonSchema } from "../dist/config.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const outPath = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "schemas",
  "config.v1.schema.json",
);

const schema = buildConfigJsonSchema();
writeFileSync(outPath, `${JSON.stringify(schema, null, 2)}\n`);
console.log(`generate-config-schema: wrote ${outPath}`);
