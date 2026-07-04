/**
 * @knotrust/store — the multi-process concurrency acceptance test (P0-E4-T1
 * ruling 5), the actual proof for the consumed-jti ledger's
 * replay-protection claim: the `"wx"` (`O_CREAT | O_EXCL`) create in
 * `consumeOnce()` is POSIX-atomic across independent OS processes, not just
 * "safe under a single Node event loop."
 *
 * Two REAL `node` child processes (not workers, not in-process async
 * interleaving) run `grant-store.concurrent-fixture.ts` against the SAME
 * temp `home`:
 *
 *   - each `put()`s 50 grants with jtis unique to its own role (100 files
 *     total) — proving `put()`'s atomic write-then-rename never produces a
 *     torn file even when two processes are writing into the same
 *     directory at the same time;
 *   - both race `consumeOnce()` over the exact same 50 shared jtis — for
 *     every one of those jtis, EXACTLY ONE of the two processes' attempts
 *     may return `"consumed"`; the sum of `"consumed"` results per jti,
 *     across both processes, must be exactly 1.
 *
 * The fixture is executed as plain compiled `.js` (via `ts.transpileModule`
 * — `typescript` is already a devDependency of this package, so this adds
 * no new dependency) rather than via `node --experimental-strip-types`,
 * specifically to sidestep the TypeScript `NodeNext` resolver's
 * "`.ts` import specifiers require `allowImportingTsExtensions`" rule,
 * which is incompatible with this package's normal `tsc`-emits-real-`.js`
 * build — this way the fixture stays a completely ordinary, fully
 * typechecked/built source file with no `tsconfig` carve-out.
 */

import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import ts from "typescript";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest";
import { createGrantStore, type DecodeIndexEntry } from "./grant-store.js";

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));

function transpileTsFile(srcPath: string): string {
  const source = readFileSync(srcPath, "utf8");
  return ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: srcPath,
  }).outputText;
}

// ---------------------------------------------------------------------------
// Build the fixture (and the grant-store module it imports) to plain .js in
// a scratch directory once for the whole file — the fixture has exactly one
// relative import ("./grant-store.js"), so both outputs land in the same
// directory under matching names and Node's normal ESM resolution does the
// rest, no bundler needed.
// ---------------------------------------------------------------------------

let scratchDir: string;
let fixtureJsPath: string;

beforeAll(() => {
  scratchDir = mkdtempSync(
    path.join(tmpdir(), "knotrust-store-concurrent-build-"),
  );
  writeFileSync(
    path.join(scratchDir, "grant-store.js"),
    transpileTsFile(path.join(here, "grant-store.ts")),
  );
  fixtureJsPath = path.join(scratchDir, "grant-store.concurrent-fixture.js");
  writeFileSync(
    fixtureJsPath,
    transpileTsFile(path.join(here, "grant-store.concurrent-fixture.ts")),
  );
});

afterAll(() => {
  rmSync(scratchDir, { recursive: true, force: true });
});

let tempHome: string;

beforeEach(() => {
  tempHome = mkdtempSync(
    path.join(tmpdir(), "knotrust-store-concurrent-home-"),
  );
});

afterEach(() => {
  rmSync(tempHome, { recursive: true, force: true });
});

// Same self-contained JSON-based fake token codec as grant-store.test.ts and
// the fixture itself — the store never parses JWS (R29).
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
  return {
    jti: obj.jti,
    tool: obj.tool,
    agentId: obj.agentId === null ? null : (obj.agentId as string),
  };
};

interface FixtureResult {
  role: string;
  putFailures: string[];
  consumeResults: Record<string, string>;
}

async function runFixture(
  role: string,
  grantCount: number,
  sharedJtis: string[],
): Promise<FixtureResult> {
  const { stdout } = await execFileAsync(
    process.execPath,
    [fixtureJsPath, tempHome, role, String(grantCount), sharedJtis.join(",")],
    { timeout: 60_000 },
  );
  return JSON.parse(stdout) as FixtureResult;
}

describe("createGrantStore — real two-process concurrency (P0-E4-T1 ruling 5)", () => {
  it("100 distinct grants across two real processes parse cleanly, and every raced jti has exactly one consumeOnce winner", async () => {
    const grantCount = 50;
    const sharedJtis = Array.from({ length: 50 }, (_, i) => `shared-${i}`);

    // Kick off both child processes WITHOUT awaiting individually first —
    // that's what actually makes this a race instead of two sequential
    // runs against the same directory.
    const [resultA, resultB] = await Promise.all([
      runFixture("A", grantCount, sharedJtis),
      runFixture("B", grantCount, sharedJtis),
    ]);

    expect(resultA.putFailures).toEqual([]);
    expect(resultB.putFailures).toEqual([]);

    // --- "all 100 grant files parse cleanly (no torn writes)" ---
    const store = createGrantStore({ home: tempHome, decodeIndexEntry });
    const { active, invalid } = store.list();

    expect(invalid).toEqual([]);
    expect(active).toHaveLength(grantCount * 2);

    const activeJtis = new Set(active.map((g) => g.jti));
    for (let i = 0; i < grantCount; i++) {
      expect(activeJtis.has(`A-grant-${i}`)).toBe(true);
      expect(activeJtis.has(`B-grant-${i}`)).toBe(true);
    }
    // Every file's own content parses and matches its filename jti — the
    // direct "no torn writes" assertion (a torn write would either fail
    // JSON.parse or carry a mismatched/truncated jti).
    for (const record of active) {
      const parsed = JSON.parse(record.token) as { jti: string };
      expect(parsed.jti).toBe(record.jti);
    }

    // --- "for every raced jti EXACTLY ONE process won the consume" ---
    for (const jti of sharedJtis) {
      const outcomes = [
        resultA.consumeResults[jti],
        resultB.consumeResults[jti],
      ];
      const consumedCount = outcomes.filter((o) => o === "consumed").length;
      const alreadyConsumedCount = outcomes.filter(
        (o) => o === "already_consumed",
      ).length;

      expect(consumedCount).toBe(1);
      expect(alreadyConsumedCount).toBe(1);
      expect(store.isConsumed(jti)).toBe(true);
    }
  }, 30_000);
});
