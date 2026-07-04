/**
 * @knotrust/store — child-process fixture for the real multi-process
 * concurrency acceptance test (P0-E4-T1 ruling 5). NOT a test file (no
 * `describe`/`it`, filename doesn't match `*.test.ts`), so Vitest never
 * collects it directly — mirrors `packages/grants/src/grant-test-kit.ts`'s
 * "shared test infra colocated in src/" precedent. Otherwise a completely
 * normal source file (built and typechecked like any other under `src/`).
 *
 * `grant-store.concurrent.test.ts` spawns this file — transpiled to plain
 * `.js` via the TypeScript compiler API at test time (`ts.transpileModule`;
 * `typescript` is already a devDependency, so this adds nothing beyond
 * node builtins) and run as TWO REAL, separate `node` processes (via
 * `node:child_process`) — against the SAME temp `home`. Each process:
 *
 *   1. `put()`s `grantCount` grants with jtis unique to its own `role`
 *      (`<role>-grant-<i>`) — the "distinct grants" half of ruling 5.
 *   2. Races `consumeOnce()` against the OTHER process over the exact SAME
 *      shared jti list (`sharedJtis`, identical argv on both sides) — the
 *      "racing consumeOnce on the SAME jti set" half.
 *
 * Results are printed to stdout as one JSON line so the parent test can
 * `JSON.parse` them after both processes exit — no shared temp file, no
 * IPC, nothing beyond what two independent OS processes talking to the
 * same directory tree would do in production.
 */

import {
  createGrantStore,
  type DecodeIndexEntry,
  type GrantIndexEntry,
} from "./grant-store.js";

const [, , home, role, grantCountRaw, sharedJtisCsv] = process.argv;

if (
  home === undefined ||
  role === undefined ||
  grantCountRaw === undefined ||
  sharedJtisCsv === undefined
) {
  throw new Error(
    "usage: node --experimental-strip-types grant-store.concurrent-fixture.ts <home> <role> <grantCount> <sharedJtisCsv>",
  );
}

const grantCount = Number(grantCountRaw);
const sharedJtis = sharedJtisCsv.length > 0 ? sharedJtisCsv.split(",") : [];

// Same self-contained JSON-based fake token codec as grant-store.test.ts —
// the store never parses JWS (R29), so a real signer isn't needed here.
interface FakeClaims {
  jti: string;
  tool: string;
  agentId: string | null;
}

function makeToken(claims: FakeClaims): string {
  return JSON.stringify(claims);
}

const decodeIndexEntry: DecodeIndexEntry = (token) => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(token);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.jti !== "string" || obj.jti.length === 0) return null;
  if (typeof obj.tool !== "string" || obj.tool.length === 0) return null;
  if (obj.agentId !== null && typeof obj.agentId !== "string") return null;
  const entry: GrantIndexEntry = {
    jti: obj.jti,
    tool: obj.tool,
    agentId: obj.agentId === null ? null : (obj.agentId as string),
  };
  return entry;
};

const store = createGrantStore({ home, decodeIndexEntry });

const putFailures: string[] = [];
for (let i = 0; i < grantCount; i++) {
  const jti = `${role}-grant-${i}`;
  const token = makeToken({ jti, tool: "demo.tool", agentId: null });
  const result = store.put(token);
  if (!result.ok) {
    putFailures.push(jti);
  }
}

const consumeResults: Record<string, string> = {};
for (const jti of sharedJtis) {
  consumeResults[jti] = store.consumeOnce(jti);
}

process.stdout.write(JSON.stringify({ role, putFailures, consumeResults }));
