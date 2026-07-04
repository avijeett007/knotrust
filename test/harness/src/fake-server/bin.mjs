#!/usr/bin/env node
// @knotrust/test-harness — fake MCP server, child-process entry (P0-E11-T1, R53).
//
// This file is committed as-is (plain ESM, NOT compiled by tsc — it is
// intentionally outside tsc's `include`, so it is never touched by the
// `build` script) and spawned directly: `node bin.mjs --config <path>`.
// `start.ts`'s `startFakeServer({ prepareChildCommand: true })` returns
// exactly that argv (with `process.execPath` in place of the literal
// string "node"). It stays a thin bootstrap on purpose: all real behavior
// lives in `process-entry.ts` (compiled to `dist/fake-server/process-entry.js`),
// so this script and the in-process path (`start.ts`) share the exact same
// `buildFakeServer` core — see the "shared-core factoring" note in
// `core.ts` and `start.ts`.
//
// Requires `dist/` to be built first (`pnpm --filter @knotrust/test-harness
// build`, or just running `test` — the package's `pretest` script runs
// `tsc` before vitest starts, precisely so this is always true when this
// harness's own tests spawn it).

import { runFakeServerProcess } from "../../dist/fake-server/process-entry.js";

await runFakeServerProcess(process.argv.slice(2));
