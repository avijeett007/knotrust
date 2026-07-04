/**
 * @knotrust/store — grant-store.ts unit tests (P0-E4-T1; rulings R29–R31).
 *
 * Every test gets its own fresh temp `home` (via `mkdtempSync`) passed
 * explicitly through `createGrantStore({ home, ... })` — never the real
 * `~/.knotrust` (brief hygiene requirement). One dedicated test near the
 * bottom exercises the `KNOTRUST_HOME`-env-var default path the same way
 * `packages/grants/src/keys.test.ts` does for `resolveKnotrustHome()`.
 *
 * The store never parses JWS (R29) — these tests use a small self-contained
 * JSON-based fake "token" codec (`decodeIndexEntry`/`makeToken` below)
 * instead of depending on `@knotrust/grants` even at test time, which would
 * violate the store-is-the-lower-layer boundary this task exists to set up.
 *
 * ## `node:fs` interception seam (P0-E4-T1 review round 1)
 *
 * A handful of tests need to inject a real I/O failure — e.g. an `ENOENT`
 * from `readFileSync` mid-scan, to deterministically reproduce "a
 * concurrent remove()/revoke() unlinked the file between this module's
 * existence check and its read" — which cannot be done by racing a second
 * real thread/process (Node is single-threaded within one `get()`/`list()`
 * call) and cannot be done with plain `vi.spyOn` on an ES module namespace
 * object (`node:fs`'s exported bindings are non-configurable — Node throws
 * "Cannot redefine property"). `vi.mock("node:fs", ...)` below is the
 * standard Vitest workaround: it substitutes the WHOLE module at import
 * time with a passthrough wrapper around the real implementation, and each
 * test flips one function's behavior on/off via `fsOverrides` for just the
 * duration of that one assertion (always reset in a `finally`).
 */

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createGrantStore,
  type DecodeIndexEntry,
  type GrantIndexEntry,
} from "./grant-store.js";

// ---------------------------------------------------------------------------
// node:fs interception seam — see module doc comment above.
// ---------------------------------------------------------------------------

const fsOverrides = vi.hoisted(() => ({
  readFileSync: null as ((...args: unknown[]) => unknown) | null,
  renameSync: null as ((...args: unknown[]) => unknown) | null,
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    readFileSync: (...args: unknown[]) =>
      fsOverrides.readFileSync
        ? fsOverrides.readFileSync(...args)
        : // biome-ignore lint/suspicious/noExplicitAny: passthrough to the real overload set
          (actual.readFileSync as any)(...args),
    renameSync: (...args: unknown[]) =>
      fsOverrides.renameSync
        ? fsOverrides.renameSync(...args)
        : // biome-ignore lint/suspicious/noExplicitAny: passthrough to the real overload set
          (actual.renameSync as any)(...args),
  };
});

// ---------------------------------------------------------------------------
// Test-only fake token codec — JSON, not JWS. `decodeIndexEntry` is the ONLY
// seam the store uses to look inside a token; these tests exercise it with
// bespoke pass/fail fixtures instead of a real signer.
// ---------------------------------------------------------------------------

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

function grant(over: Partial<FakeClaims> = {}): FakeClaims {
  return {
    jti: "01JZTESTGRANT001",
    tool: "github.create_issue",
    agentId: null,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Harness — fresh temp home per test.
// ---------------------------------------------------------------------------

let tempHome: string;

beforeEach(() => {
  tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-store-test-"));
});

afterEach(() => {
  rmSync(tempHome, { recursive: true, force: true });
});

function makeStore() {
  return createGrantStore({ home: tempHome, decodeIndexEntry });
}

function grantsDirPath(): string {
  return path.join(tempHome, "grants");
}

function jwsFilePath(jti: string): string {
  return path.join(grantsDirPath(), `${jti}.jws`);
}

function tombstoneFilePath(jti: string): string {
  return path.join(grantsDirPath(), "tombstones", `${jti}.json`);
}

function consumedMarkerFilePath(jti: string): string {
  return path.join(grantsDirPath(), "consumed", jti);
}

// ---------------------------------------------------------------------------
// put()
// ---------------------------------------------------------------------------

describe("put()", () => {
  it("writes grants/<jti>.jws with the token text plus a trailing newline (R30)", () => {
    const store = makeStore();
    const claims = grant();
    const token = makeToken(claims);

    const result = store.put(token);

    expect(result).toEqual({ ok: true, jti: claims.jti });
    expect(readFileSync(jwsFilePath(claims.jti), "utf8")).toBe(`${token}\n`);
  });

  it("returns { ok: false, reason: 'decode_failed' } for an undecodable token, writes nothing", () => {
    const store = makeStore();

    const result = store.put("this is not json at all");

    expect(result).toEqual({ ok: false, reason: "decode_failed" });
    expect(existsSync(grantsDirPath())).toBe(false);
  });

  it("creates the grants directory chain as 0700 (R31)", () => {
    const store = makeStore();
    store.put(makeToken(grant()));

    expect(statSync(tempHome).mode & 0o777).toBe(0o700);
    expect(statSync(grantsDirPath()).mode & 0o777).toBe(0o700);
  });

  it("leaves no .tmp artifacts behind after a normal write (atomic write-then-rename, R31)", () => {
    const store = makeStore();
    store.put(makeToken(grant()));

    const names = readdirSync(grantsDirPath());
    expect(names.some((n) => n.endsWith(".tmp"))).toBe(false);
  });

  it("best-effort-cleans-up the temp file when renameSync fails, and still propagates the original error (P0-E4-T1 review round 1, FIX 4)", () => {
    const store = makeStore();
    const claims = grant();

    fsOverrides.renameSync = () => {
      throw new Error("simulated renameSync failure");
    };

    try {
      expect(() => store.put(makeToken(claims))).toThrow(
        /simulated renameSync failure/,
      );
    } finally {
      fsOverrides.renameSync = null;
    }

    // The write-then-rename left a "<jti>.jws.<random>.tmp" behind only if
    // cleanup didn't run; the real destination file was never created
    // either way (rename never completed).
    expect(existsSync(jwsFilePath(claims.jti))).toBe(false);
    if (existsSync(grantsDirPath())) {
      const names = readdirSync(grantsDirPath());
      expect(names.some((n) => n.endsWith(".tmp"))).toBe(false);
    }
  });

  it("overwrites an existing grant file atomically when put() is called again for the same jti", () => {
    const store = makeStore();
    const jti = "01JZTESTGRANT002";
    store.put(makeToken(grant({ jti, tool: "a.old" })));
    store.put(makeToken(grant({ jti, tool: "a.new" })));

    const onDisk = readFileSync(jwsFilePath(jti), "utf8");
    expect(JSON.parse(onDisk).tool).toBe("a.new");
  });

  it("treats a THROWING decodeIndexEntry the same as a null return (decode_failed), never propagates the throw (P0-E4-T1 review round 1, FIX 3)", () => {
    const throwingDecoder: DecodeIndexEntry = () => {
      throw new Error("decoder bug: exploded instead of returning null");
    };
    const store = createGrantStore({
      home: tempHome,
      decodeIndexEntry: throwingDecoder,
    });

    let result: ReturnType<typeof store.put> | undefined;
    expect(() => {
      result = store.put("irrelevant token");
    }).not.toThrow();
    expect(result).toEqual({ ok: false, reason: "decode_failed" });
    expect(existsSync(grantsDirPath())).toBe(false);
  });

  it("refuses a jti that would escape the grants directory (path traversal defense-in-depth)", () => {
    const evilDecoder: DecodeIndexEntry = () => ({
      jti: "../../evil",
      tool: "x",
      agentId: null,
    });
    const evilStore = createGrantStore({
      home: tempHome,
      decodeIndexEntry: evilDecoder,
    });

    expect(() => evilStore.put("irrelevant")).toThrow(/unsafe jti/i);
  });
});

// ---------------------------------------------------------------------------
// get()
// ---------------------------------------------------------------------------

describe("get()", () => {
  it("returns { status: 'absent' } for an unknown jti", () => {
    const store = makeStore();
    expect(store.get("01JZUNKNOWN0000000")).toEqual({ status: "absent" });
  });

  it("returns { status: 'active', token } for a stored grant, stripping exactly the one trailing newline", () => {
    const store = makeStore();
    const claims = grant();
    const token = makeToken(claims);
    store.put(token);

    expect(store.get(claims.jti)).toEqual({ status: "active", token });
  });

  it("returns { status: 'revoked' } (no token) once revoked, even though the .jws is gone", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));
    store.revoke(claims.jti, "no longer needed");

    expect(store.get(claims.jti)).toEqual({ status: "revoked" });
  });

  it("returns { status: 'absent' } instead of throwing when a concurrent remove()/revoke() unlinks the .jws between the existsSync check and the read (P0-E4-T1 review round 1, FIX 1)", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));

    fsOverrides.readFileSync = () => {
      // Simulate the exact race: some OTHER caller's remove()/revoke()
      // wins the unlink in the window between get()'s existsSync check
      // (already passed by the time we get here) and this readFileSync
      // call.
      rmSync(jwsFilePath(claims.jti), { force: true });
      const err = new Error(
        "ENOENT: no such file or directory, open",
      ) as NodeJS.ErrnoException;
      err.code = "ENOENT";
      throw err;
    };

    try {
      expect(store.get(claims.jti)).toEqual({ status: "absent" });
    } finally {
      fsOverrides.readFileSync = null;
    }
  });

  it("re-throws a non-ENOENT read error instead of tolerating it (only ENOENT is a tolerated race)", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));

    fsOverrides.readFileSync = () => {
      const err = new Error(
        "EACCES: permission denied",
      ) as NodeJS.ErrnoException;
      err.code = "EACCES";
      throw err;
    };

    try {
      expect(() => store.get(claims.jti)).toThrow(/EACCES/);
    } finally {
      fsOverrides.readFileSync = null;
    }
  });

  it("tombstone wins over a LINGERING .jws (simulated unlink failure) — R30's core invariant", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));
    store.revoke(claims.jti);

    // Simulate the "unlink failure tolerated" case: resurrect the .jws file
    // exactly as if revoke()'s best-effort unlink had failed.
    mkdirSync(grantsDirPath(), { recursive: true });
    writeFileSync(jwsFilePath(claims.jti), `${makeToken(claims)}\n`);
    expect(existsSync(jwsFilePath(claims.jti))).toBe(true);

    expect(store.get(claims.jti)).toEqual({ status: "revoked" });
  });
});

// ---------------------------------------------------------------------------
// remove()
// ---------------------------------------------------------------------------

describe("remove()", () => {
  it("deletes the .jws file; get() reports absent afterwards", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));

    store.remove(claims.jti);

    expect(existsSync(jwsFilePath(claims.jti))).toBe(false);
    expect(store.get(claims.jti)).toEqual({ status: "absent" });
  });

  it("is a no-op (never throws) for a jti that was never stored", () => {
    const store = makeStore();
    expect(() => store.remove("01JZNEVERSTORED0000")).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// revoke()
// ---------------------------------------------------------------------------

describe("revoke()", () => {
  it("writes an RFC 3339 tombstone with the given reason and unlinks the .jws", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));

    store.revoke(claims.jti, "compromised");

    const tombstone = JSON.parse(
      readFileSync(tombstoneFilePath(claims.jti), "utf8"),
    );
    expect(tombstone.jti).toBe(claims.jti);
    expect(tombstone.reason).toBe("compromised");
    expect(() => new Date(tombstone.revokedAt).toISOString()).not.toThrow();
    expect(new Date(tombstone.revokedAt).toISOString()).toBe(
      tombstone.revokedAt,
    );
    expect(existsSync(jwsFilePath(claims.jti))).toBe(false);
  });

  it("omits the reason key entirely when no reason is given (exactOptionalPropertyTypes-safe)", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));

    store.revoke(claims.jti);

    const tombstone = JSON.parse(
      readFileSync(tombstoneFilePath(claims.jti), "utf8"),
    );
    expect("reason" in tombstone).toBe(false);
  });

  it("never throws even when the .jws never existed (unlink failure tolerated, R30)", () => {
    const store = makeStore();
    expect(() =>
      store.revoke("01JZNEVERPUT00000000", "preemptive"),
    ).not.toThrow();
    expect(store.get("01JZNEVERPUT00000000")).toEqual({ status: "revoked" });
  });

  it("is idempotent — revoking twice does not throw and stays revoked", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));
    store.revoke(claims.jti, "first");
    expect(() => store.revoke(claims.jti, "second")).not.toThrow();
    expect(store.get(claims.jti)).toEqual({ status: "revoked" });
  });

  it("stamps the tombstone's revokedAt from the injected nowEpochMs clock, not the real wall clock (P0-E4-T2 preliminary item)", () => {
    const fixedEpochMs = Date.parse("2020-01-01T00:00:00.000Z");
    const store = createGrantStore({
      home: tempHome,
      decodeIndexEntry,
      nowEpochMs: () => fixedEpochMs,
    });
    const claims = grant();
    store.put(makeToken(claims));

    store.revoke(claims.jti, "clock-injection test");

    const tombstone = JSON.parse(
      readFileSync(tombstoneFilePath(claims.jti), "utf8"),
    );
    expect(tombstone.revokedAt).toBe(new Date(fixedEpochMs).toISOString());
  });

  it("defaults nowEpochMs to Date.now when omitted (behavior-neutral default)", () => {
    const before = Date.now();
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));

    store.revoke(claims.jti);
    const after = Date.now();

    const tombstone = JSON.parse(
      readFileSync(tombstoneFilePath(claims.jti), "utf8"),
    );
    const revokedAtMs = new Date(tombstone.revokedAt).getTime();
    expect(revokedAtMs).toBeGreaterThanOrEqual(before);
    expect(revokedAtMs).toBeLessThanOrEqual(after);
  });
});

// ---------------------------------------------------------------------------
// list() / listBy()
// ---------------------------------------------------------------------------

describe("list()", () => {
  it("returns every active grant as { jti, token }, invalid empty when nothing is tampered", () => {
    const store = makeStore();
    const a = grant({ jti: "01JZLISTA00000000001", tool: "github.*" });
    const b = grant({
      jti: "01JZLISTB00000000002",
      tool: "stripe.create_refund",
    });
    store.put(makeToken(a));
    store.put(makeToken(b));

    const { active, invalid } = store.list();

    expect(invalid).toEqual([]);
    expect(active).toHaveLength(2);
    expect(new Set(active.map((g) => g.jti))).toEqual(new Set([a.jti, b.jti]));
  });

  it("skips a grant unlinked by a concurrent remove()/revoke() between readdir and read, instead of throwing (P0-E4-T1 review round 1, FIX 1)", () => {
    const store = makeStore();
    const survivor = grant({ jti: "01JZSURVIVOR0000001", tool: "a.tool" });
    const raced = grant({ jti: "01JZRACEDAWAY0000002", tool: "b.tool" });
    store.put(makeToken(survivor));
    store.put(makeToken(raced));

    // decodeIndexEntry is scanActiveGrants' only hook back into test code,
    // so it doubles as the injection point for the race: on whichever
    // grant readdirSync happens to hand the scan FIRST (directory order is
    // filesystem-dependent, so this doesn't assume which), delete the
    // OTHER grant's .jws file as a side effect of decoding — exactly
    // reproducing "unlinked between readdirSync and this file's
    // readFileSync" for whichever grant the scan reaches second.
    const jtis = [survivor.jti, raced.jti];
    let racedOnce = false;
    const racingDecoder: DecodeIndexEntry = (token) => {
      const decoded = decodeIndexEntry(token);
      if (!racedOnce && decoded !== null) {
        racedOnce = true;
        const otherJti = jtis.find((jti) => jti !== decoded.jti);
        if (otherJti !== undefined) {
          rmSync(jwsFilePath(otherJti), { force: true });
        }
      }
      return decoded;
    };
    const racingStore = createGrantStore({
      home: tempHome,
      decodeIndexEntry: racingDecoder,
    });

    let result: ReturnType<typeof store.list> | undefined;
    expect(() => {
      result = racingStore.list();
    }).not.toThrow();

    // Exactly one of the two survives (whichever the scan reached first);
    // the other is silently skipped — NOT reported as invalid, since being
    // unlinked mid-scan is not the same as being tampered/garbage.
    expect(result?.invalid).toEqual([]);
    expect(result?.active).toHaveLength(1);
    expect([survivor.jti, raced.jti]).toContain(result?.active[0]?.jti);
  });

  it("excludes a revoked grant even when its .jws lingers on disk (tombstone wins, R30)", () => {
    const store = makeStore();
    const claims = grant();
    store.put(makeToken(claims));
    store.revoke(claims.jti);
    mkdirSync(grantsDirPath(), { recursive: true });
    writeFileSync(jwsFilePath(claims.jti), `${makeToken(claims)}\n`);

    const { active, invalid } = store.list();

    expect(active).toEqual([]);
    expect(invalid).toEqual([]);
  });
});

describe("listBy()", () => {
  function seedThree(store: ReturnType<typeof makeStore>) {
    const wildcard = grant({
      jti: "01JZAGENTWILD000001",
      tool: "github.*",
      agentId: null,
    });
    const claude = grant({
      jti: "01JZAGENTCLAUDE00002",
      tool: "github.*",
      agentId: "claude-desktop",
    });
    const other = grant({
      jti: "01JZAGENTOTHER00003",
      tool: "stripe.create_refund",
      agentId: "codex-cli",
    });
    store.put(makeToken(wildcard));
    store.put(makeToken(claude));
    store.put(makeToken(other));
    return { wildcard, claude, other };
  }

  it("filters by exact tool match", () => {
    const store = makeStore();
    const { wildcard, claude, other } = seedThree(store);

    const { active } = store.listBy({ tool: "github.*" });

    expect(new Set(active.map((g) => g.jti))).toEqual(
      new Set([wildcard.jti, claude.jti]),
    );
    expect(active.some((g) => g.jti === other.jti)).toBe(false);
  });

  it("filters by agentId, matching both an exact agent AND a wildcard ('*') grant", () => {
    const store = makeStore();
    const { wildcard, claude, other } = seedThree(store);

    const { active } = store.listBy({ agentId: "claude-desktop" });

    expect(new Set(active.map((g) => g.jti))).toEqual(
      new Set([wildcard.jti, claude.jti]),
    );
    expect(active.some((g) => g.jti === other.jti)).toBe(false);
  });

  it("combines tool and agentId filters (AND semantics)", () => {
    const store = makeStore();
    const { wildcard, claude } = seedThree(store);

    const { active } = store.listBy({
      tool: "github.*",
      agentId: "claude-desktop",
    });

    expect(new Set(active.map((g) => g.jti))).toEqual(
      new Set([wildcard.jti, claude.jti]),
    );
  });

  it("with no filter fields returns everything active, same as list()", () => {
    const store = makeStore();
    seedThree(store);

    expect(store.listBy({}).active).toHaveLength(3);
  });

  it("documents the exact-match footgun (P0-E4-T1 review round 1, FIX 2): a glob-pattern grant is NOT returned when filtering by a concrete tool name, but IS returned when filtering by the literal stored pattern string", () => {
    const store = makeStore();
    const globGrant = grant({
      jti: "01JZGLOBGRANT0000001",
      tool: "github.*",
      agentId: null,
    });
    store.put(makeToken(globGrant));

    // filter.tool is EXACT-STRING match, not glob evaluation — a concrete
    // call name never matches a stored glob pattern here. A caller in
    // packages/grants (E3-T3) that filtered by the concrete tool it's
    // about to authorize would silently see NO candidates for this grant.
    expect(store.listBy({ tool: "github.create_issue" }).active).toEqual([]);

    // The literal stored pattern string, on the other hand, matches fine —
    // this is a plain index lookup, not policy evaluation (see
    // ListByFilter.tool's doc comment).
    expect(store.listBy({ tool: "github.*" }).active).toEqual([
      { jti: globGrant.jti, token: makeToken(globGrant) },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Tampered-file acceptance test (ruling 6) — hand-written garbage bytes.
// ---------------------------------------------------------------------------

describe("tampered grant files", () => {
  it("surfaces non-JSON garbage under invalid: grant_invalid, other grants unaffected, never throws", () => {
    const store = makeStore();
    const good = grant({ jti: "01JZGOODGRANT000001" });
    store.put(makeToken(good));

    mkdirSync(grantsDirPath(), { recursive: true });
    const tamperedJti = "01JZTAMPERED00000002";
    writeFileSync(
      jwsFilePath(tamperedJti),
      "not a valid jws or json at all §§§\n",
    );

    let result: ReturnType<typeof store.list> | undefined;
    expect(() => {
      result = store.list();
    }).not.toThrow();

    expect(result?.invalid).toEqual([
      { jti: tamperedJti, reason: "grant_invalid" },
    ]);
    expect(result?.active).toEqual([{ jti: good.jti, token: makeToken(good) }]);
  });

  it("also surfaces well-formed-JSON-but-schema-invalid content as grant_invalid", () => {
    const store = makeStore();
    mkdirSync(grantsDirPath(), { recursive: true });
    const jti = "01JZSCHEMAINVALID0003";
    writeFileSync(
      jwsFilePath(jti),
      `${JSON.stringify({ nope: "no jti or tool here" })}\n`,
    );

    const { active, invalid } = store.list();

    expect(active).toEqual([]);
    expect(invalid).toEqual([{ jti, reason: "grant_invalid" }]);
  });

  it("surfaces a jti mismatch between filename and decoded content as grant_invalid (misplaced-file defense)", () => {
    const store = makeStore();
    mkdirSync(grantsDirPath(), { recursive: true });
    const filenameJti = "01JZFILENAMEJTI00004";
    const innerClaims = grant({ jti: "01JZDIFFERENTJTI0005" });
    writeFileSync(jwsFilePath(filenameJti), `${makeToken(innerClaims)}\n`);

    const { active, invalid } = store.list();

    expect(active).toEqual([]);
    expect(invalid).toEqual([{ jti: filenameJti, reason: "grant_invalid" }]);
  });

  it("listBy() also surfaces tampered files under invalid, independent of the filter", () => {
    const store = makeStore();
    mkdirSync(grantsDirPath(), { recursive: true });
    const jti = "01JZTAMPEREDLISTBY006";
    writeFileSync(jwsFilePath(jti), "garbage\n");

    const { invalid } = store.listBy({ tool: "anything.at.all" });

    expect(invalid).toEqual([{ jti, reason: "grant_invalid" }]);
  });

  it("treats a THROWING decodeIndexEntry the same as a null return during a scan — file lands in invalid[], nothing crashes (P0-E4-T1 review round 1, FIX 3)", () => {
    const jti = "01JZTHROWINGDECODE007";
    const throwingDecoder: DecodeIndexEntry = () => {
      throw new Error("decoder bug: exploded instead of returning null");
    };
    const store = createGrantStore({
      home: tempHome,
      decodeIndexEntry: throwingDecoder,
    });
    mkdirSync(grantsDirPath(), { recursive: true });
    writeFileSync(
      jwsFilePath(jti),
      "anything, the decoder never gets to look\n",
    );

    let result: ReturnType<typeof store.list> | undefined;
    expect(() => {
      result = store.list();
    }).not.toThrow();

    expect(result?.active).toEqual([]);
    expect(result?.invalid).toEqual([{ jti, reason: "grant_invalid" }]);
  });
});

// ---------------------------------------------------------------------------
// consumeOnce() / isConsumed() — the replay-protection primitive.
// ---------------------------------------------------------------------------

describe("consumeOnce() / isConsumed()", () => {
  it("returns 'consumed' the first time, 'already_consumed' every time after", () => {
    const store = makeStore();
    const jti = "01JZCONSUMEONCE00001";

    expect(store.consumeOnce(jti)).toBe("consumed");
    expect(store.consumeOnce(jti)).toBe("already_consumed");
    expect(store.consumeOnce(jti)).toBe("already_consumed");
  });

  it("creates an empty marker file at grants/consumed/<jti> (R30)", () => {
    const store = makeStore();
    const jti = "01JZCONSUMEMARKER0002";
    store.consumeOnce(jti);

    expect(existsSync(consumedMarkerFilePath(jti))).toBe(true);
    expect(readFileSync(consumedMarkerFilePath(jti), "utf8")).toBe("");
  });

  it("isConsumed() is false before consumeOnce(), true after", () => {
    const store = makeStore();
    const jti = "01JZISCONSUMED000003";

    expect(store.isConsumed(jti)).toBe(false);
    store.consumeOnce(jti);
    expect(store.isConsumed(jti)).toBe(true);
  });

  it("consumeOnce is independent per jti", () => {
    const store = makeStore();
    store.consumeOnce("01JZINDEPENDENTA0001");
    expect(store.isConsumed("01JZINDEPENDENTB0002")).toBe(false);
  });

  it("self-heals if grants/consumed/ is deleted mid-process: the next consumeOnce() recreates it and still succeeds, exactly-once semantics intact", () => {
    const store = makeStore();
    const jtiA = "01JZSELFHEALDELETED01";
    // Populates ensureConsumedDir's per-home memo, so the deletion below
    // exercises the case where the cheap memoized early-return would
    // otherwise skip re-creating a directory that's actually gone.
    expect(store.consumeOnce(jtiA)).toBe("consumed");

    rmSync(path.join(grantsDirPath(), "consumed"), {
      recursive: true,
      force: true,
    });
    expect(existsSync(path.join(grantsDirPath(), "consumed"))).toBe(false);

    const jtiB = "01JZSELFHEALDELETED02";
    expect(store.consumeOnce(jtiB)).toBe("consumed");
    expect(existsSync(consumedMarkerFilePath(jtiB))).toBe(true);

    // Exactly-once semantics still hold post-heal — the retry is still a
    // single "wx" open, not a loop.
    expect(store.consumeOnce(jtiB)).toBe("already_consumed");
  });
});

// ---------------------------------------------------------------------------
// stats()
// ---------------------------------------------------------------------------

describe("stats()", () => {
  it("counts active, revoked, consumed, and invalid independently", () => {
    const store = makeStore();
    store.put(makeToken(grant({ jti: "01JZSTATSACTIVE00001" })));
    store.put(makeToken(grant({ jti: "01JZSTATSREVOKED0002" })));
    store.revoke("01JZSTATSREVOKED0002");
    store.consumeOnce("01JZSTATSCONSUMED0003");
    store.consumeOnce("01JZSTATSCONSUMED0004");
    mkdirSync(grantsDirPath(), { recursive: true });
    writeFileSync(jwsFilePath("01JZSTATSINVALID00005"), "garbage\n");

    expect(store.stats()).toEqual({
      active: 1,
      revoked: 1,
      consumed: 2,
      invalid: 1,
    });
  });

  it("is all zeroes for a fresh, never-written home", () => {
    const store = makeStore();
    expect(store.stats()).toEqual({
      active: 0,
      revoked: 0,
      consumed: 0,
      invalid: 0,
    });
  });
});

// ---------------------------------------------------------------------------
// jti safety — path-traversal defense-in-depth on the public API too.
// ---------------------------------------------------------------------------

describe("unsafe jti rejection", () => {
  it("get(), remove(), revoke(), consumeOnce(), isConsumed() all reject a path-traversal jti", () => {
    const store = makeStore();
    const evil = "../../etc/passwd";

    expect(() => store.get(evil)).toThrow(/unsafe jti/i);
    expect(() => store.remove(evil)).toThrow(/unsafe jti/i);
    expect(() => store.revoke(evil)).toThrow(/unsafe jti/i);
    expect(() => store.consumeOnce(evil)).toThrow(/unsafe jti/i);
    expect(() => store.isConsumed(evil)).toThrow(/unsafe jti/i);
  });
});

// ---------------------------------------------------------------------------
// KNOTRUST_HOME default resolution (opts.home omitted).
// ---------------------------------------------------------------------------

describe("default home resolution via KNOTRUST_HOME", () => {
  const ORIGINAL_KNOTRUST_HOME = process.env.KNOTRUST_HOME;

  afterEach(() => {
    if (ORIGINAL_KNOTRUST_HOME === undefined) {
      delete process.env.KNOTRUST_HOME;
    } else {
      process.env.KNOTRUST_HOME = ORIGINAL_KNOTRUST_HOME;
    }
  });

  it("uses KNOTRUST_HOME when opts.home is omitted", () => {
    process.env.KNOTRUST_HOME = tempHome;
    const store = createGrantStore({ decodeIndexEntry });
    const claims = grant();

    store.put(makeToken(claims));

    expect(existsSync(path.join(tempHome, "grants", `${claims.jti}.jws`))).toBe(
      true,
    );
  });
});
