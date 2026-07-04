/**
 * P0-E7-T2 — `knotrust grant list` acceptance (R113, R116): tabulates
 * active grants (tombstoned excluded), `--json` for scripting, a clean
 * empty-store message, and never dumps the raw signed token.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  createKeyStore,
  decodeGrantIndexEntry,
  mintDurableGrant,
} from "@knotrust/grants";
import { createGrantStore } from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type GrantListRow, runGrantList } from "./list-command.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

let home: string;
let priorHome: string | undefined;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "knotrust-grant-list-home-"));
  // `createKeyStore` (used by `seedGrant` below to mint real fixture grants)
  // resolves its home via `KNOTRUST_HOME`, not an injectable option — point
  // it at this test's throwaway temp dir, NEVER the developer's real
  // `~/.knotrust`.
  priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;
});

afterEach(() => {
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;
  rmSync(home, { recursive: true, force: true });
});

async function seedGrant(over: {
  tool?: string;
  jti?: string;
  iat?: number;
  ttlSeconds?: number;
}): Promise<{ jti: string; token: string }> {
  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  // NEVER the real OS keychain — force the file backend against this test's
  // own throwaway temp `home`, mirroring this suite's discipline elsewhere.
  const keyStore = await createKeyStore({ backend: "file" });
  const iat = over.iat ?? 1_000_000;
  const result = await mintDurableGrant(
    {
      principal: { type: "user", id: "local-user" },
      agent: "*",
      tool: over.tool ?? "github.create_issue",
      scope: {},
      tier: "sensitive",
      envelopeScope: "personal",
      ttlSeconds: over.ttlSeconds ?? 2_592_000,
    },
    {
      store,
      keyStore,
      nowEpochSeconds: iat,
      generateId: over.jti
        ? () => over.jti as string
        : () => `01JZ${Math.random().toString(36).slice(2, 10).toUpperCase()}`,
    },
  );
  return { jti: result.jti, token: result.token };
}

describe("runGrantList (R113)", () => {
  it("reports a clean message for an empty store", () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = runGrantList(
      { stdout, stderr: new PassThrough() },
      { json: false },
      { home },
    );
    expect(code).toBe(0);
    expect(getOut()).toContain("No active grants.");
  });

  it("tabulates an active grant with tool/server/agent/tier-cap/kind/expiry/single-use", async () => {
    await seedGrant({
      tool: "github.create_issue",
      iat: 1_000_000,
      ttlSeconds: 2_592_000,
    });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    runGrantList(
      { stdout, stderr: new PassThrough() },
      { json: false },
      { home, nowEpochSeconds: () => 1_000_000 + 86_400 }, // 1 day after mint
    );
    const out = getOut();
    expect(out).toContain("github.create_issue");
    expect(out).toContain("github"); // derived server label
    expect(out).toContain("*"); // agent wildcard
    expect(out).toContain("sensitive");
    expect(out).toContain("durable");
    expect(out).toContain("no"); // single-use: no
    expect(out).toMatch(/in 29d/); // 30d ttl minus 1d elapsed
  });

  it("excludes tombstoned (revoked) grants", async () => {
    const seeded = await seedGrant({ tool: "github.create_issue" });
    const store = createGrantStore({
      home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    store.revoke(seeded.jti, "test-revoke");

    const stdout = new PassThrough();
    const getOut = collect(stdout);
    runGrantList(
      { stdout, stderr: new PassThrough() },
      { json: false },
      { home },
    );
    expect(getOut()).toContain("No active grants.");
  });

  it("--json emits decoded claims-derived fields, never the raw token", async () => {
    const seeded = await seedGrant({
      tool: "stripe.create_refund",
      iat: 1_000_000,
      ttlSeconds: 43_200,
    });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    runGrantList(
      { stdout, stderr: new PassThrough() },
      { json: true },
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    const parsed = JSON.parse(getOut()) as { active: GrantListRow[] };
    expect(parsed.active).toHaveLength(1);
    expect(parsed.active[0]).toMatchObject({
      jti: seeded.jti,
      tool: "stripe.create_refund",
      server: "stripe",
      agent: "*",
      tierCap: "sensitive",
      kind: "durable",
      singleUse: false,
      iat: 1_000_000,
      exp: 1_000_000 + 43_200,
    });
    expect(getOut()).not.toContain(seeded.token);
  });

  it("never dumps the raw signed token in table mode either (R116)", async () => {
    const seeded = await seedGrant({});
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    runGrantList(
      { stdout, stderr: new PassThrough() },
      { json: false },
      { home },
    );
    expect(getOut()).not.toContain(seeded.token);
  });

  it("lists multiple active grants", async () => {
    await seedGrant({ tool: "github.create_issue" });
    await seedGrant({ tool: "stripe.create_refund" });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    runGrantList(
      { stdout, stderr: new PassThrough() },
      { json: true },
      { home },
    );
    const parsed = JSON.parse(getOut()) as { active: GrantListRow[] };
    expect(parsed.active).toHaveLength(2);
  });

  it("table mode: the namespace column is headed NAMESPACE, never SERVER (FIX 3)", async () => {
    await seedGrant({ tool: "github.create_issue" });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    runGrantList(
      { stdout, stderr: new PassThrough() },
      { json: false },
      { home },
    );
    const [header] = getOut().split("\n");
    expect(header).toContain("NAMESPACE");
    expect(header).not.toContain("SERVER");
  });

  describe("invalid grant files are surfaced, never silently dropped (FIX 2)", () => {
    function corruptAGrantFile(): string {
      // A hand-corrupted `.jws`: garbage content that cannot decode, but a
      // real, discoverable file under `grants/` — exactly what a
      // tampered/corrupt grant looks like on disk (R29's `grant_invalid`).
      const jti = "01JZCORRUPTGRANTFILE0000";
      writeFileSync(
        path.join(home, "grants", `${jti}.jws`),
        "not-a-real-jws-token\n",
      );
      return jti;
    }

    beforeEach(() => {
      mkdirSync(path.join(home, "grants"), { recursive: true });
    });

    it("table mode: prints a one-line invalid-count notice to stderr", async () => {
      await seedGrant({ tool: "github.create_issue" });
      corruptAGrantFile();
      const stdout = new PassThrough();
      const stderr = new PassThrough();
      const getOut = collect(stdout);
      const getErr = collect(stderr);
      runGrantList(
        { stdout, stderr },
        { json: false },
        { home, nowEpochSeconds: () => 1_000_000 },
      );
      // The active grant is still listed normally...
      expect(getOut()).toContain("github.create_issue");
      // ...and the corrupt file is surfaced, not silently dropped.
      expect(getErr()).toContain("1 invalid grant file(s) skipped");
      expect(getErr()).toContain("grants");
    });

    it("--json mode: includes a structured invalid count/array field", async () => {
      const corruptJti = corruptAGrantFile();
      const stdout = new PassThrough();
      const stderr = new PassThrough();
      const getOut = collect(stdout);
      const getErr = collect(stderr);
      runGrantList({ stdout, stderr }, { json: true }, { home });
      const parsed = JSON.parse(getOut()) as {
        active: GrantListRow[];
        invalid: { count: number; jtis: string[] };
      };
      expect(parsed.active).toHaveLength(0);
      expect(parsed.invalid).toEqual({ count: 1, jtis: [corruptJti] });
      // The stderr notice fires in --json mode too — never only in table mode.
      expect(getErr()).toContain("1 invalid grant file(s) skipped");
    });

    it("no notice at all when every grant file is valid", async () => {
      await seedGrant({ tool: "github.create_issue" });
      const stderr = new PassThrough();
      const getErr = collect(stderr);
      runGrantList(
        { stdout: new PassThrough(), stderr },
        { json: false },
        { home },
      );
      expect(getErr()).toBe("");
    });
  });
});
