/**
 * P0-E7-T2 — `knotrust revoke` acceptance (R114/R116): revoke by jti/tool/
 * all, confirmation gate (skipped by `--yes`), clean "nothing to revoke"
 * message, and the `grant_revoked` audit trail — composing the REAL store +
 * audit log against a temp `$KNOTRUST_HOME`.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  createKeyStore,
  decodeGrantIndexEntry,
  mintDurableGrant,
} from "@knotrust/grants";
import type { AuditEvent } from "@knotrust/store";
import { createGrantStore } from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runRevoke } from "./revoke-command.js";

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
  home = mkdtempSync(path.join(tmpdir(), "knotrust-revoke-home-"));
  priorHome = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = home;
});

afterEach(() => {
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;
  rmSync(home, { recursive: true, force: true });
});

async function seedGrant(tool = "github.create_issue"): Promise<string> {
  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const keyStore = await createKeyStore({ backend: "file" });
  const result = await mintDurableGrant(
    {
      principal: { type: "user", id: "local-user" },
      agent: "*",
      tool,
      scope: {},
      tier: "sensitive",
      envelopeScope: "personal",
      ttlSeconds: 2_592_000,
    },
    {
      store,
      keyStore,
      nowEpochSeconds: 1_000_000,
      generateId: () =>
        `01JZ${Math.random().toString(36).slice(2, 10).toUpperCase()}`,
    },
  );
  return result.jti;
}

function readAuditEvents(): AuditEvent[] {
  const dir = path.join(home, "audit");
  const events: AuditEvent[] = [];
  for (const f of readdirSync(dir)
    .filter((n) => /^\d{6}\.jsonl$/.test(n))
    .sort()) {
    for (const line of readFileSync(path.join(dir, f), "utf8").split("\n")) {
      if (line.length > 0) events.push(JSON.parse(line) as AuditEvent);
    }
  }
  return events;
}

describe("runRevoke (R114)", () => {
  it("reports cleanly when nothing matches", async () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runRevoke(
      { stdout, stderr: new PassThrough() },
      { selector: { jti: "01JZNOSUCHGRANT" }, yes: true },
      { home },
    );
    expect(code).toBe(0);
    expect(getOut()).toContain("nothing to revoke");
  });

  it("revokes by jti with --yes (no prompt)", async () => {
    const jti = await seedGrant();
    let confirmCalled = false;
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runRevoke(
      { stdout, stderr: new PassThrough() },
      { selector: { jti }, yes: true },
      {
        home,
        confirm: async () => {
          confirmCalled = true;
          return true;
        },
      },
    );
    expect(code).toBe(0);
    expect(confirmCalled).toBe(false);
    expect(getOut()).toContain(jti);

    const store = createGrantStore({
      home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    expect(store.get(jti).status).toBe("revoked");
  });

  it("revokes by --tool (exact stored-pattern match)", async () => {
    const jti1 = await seedGrant("github.*");
    const jti2 = await seedGrant("stripe.create_refund");
    const code = await runRevoke(
      { stdout: new PassThrough(), stderr: new PassThrough() },
      { selector: { tool: "github.*" }, yes: true },
      { home },
    );
    expect(code).toBe(0);
    const store = createGrantStore({
      home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    expect(store.get(jti1).status).toBe("revoked");
    expect(store.get(jti2).status).toBe("active");
  });

  it("revokes --all", async () => {
    const jti1 = await seedGrant("github.*");
    const jti2 = await seedGrant("stripe.create_refund");
    await runRevoke(
      { stdout: new PassThrough(), stderr: new PassThrough() },
      { selector: { all: true }, yes: true },
      { home },
    );
    const store = createGrantStore({
      home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    expect(store.get(jti1).status).toBe("revoked");
    expect(store.get(jti2).status).toBe("revoked");
  });

  it("without --yes, a declined confirm revokes nothing", async () => {
    const jti = await seedGrant();
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runRevoke(
      { stdout, stderr: new PassThrough() },
      { selector: { jti }, yes: false },
      { home, confirm: async () => false },
    );
    expect(code).toBe(0);
    expect(getOut()).toContain("Cancelled");
    const store = createGrantStore({
      home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    expect(store.get(jti).status).toBe("active");
  });

  it("without --yes, an approved confirm revokes", async () => {
    const jti = await seedGrant();
    const code = await runRevoke(
      { stdout: new PassThrough(), stderr: new PassThrough() },
      { selector: { jti }, yes: false },
      { home, confirm: async () => true },
    );
    expect(code).toBe(0);
    const store = createGrantStore({
      home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    expect(store.get(jti).status).toBe("revoked");
  });

  it("appends a grant_revoked audit event", async () => {
    const jti = await seedGrant();
    await runRevoke(
      { stdout: new PassThrough(), stderr: new PassThrough() },
      { selector: { jti }, yes: true },
      { home },
    );
    const events = readAuditEvents();
    const revoked = events.find((e) => e.type === "grant_revoked");
    expect(revoked).toBeDefined();
    expect(revoked?.grantRefs).toEqual([jti]);
  });

  it("the confirmation preview names the selector and candidates before revoking", async () => {
    const jti = await seedGrant("github.create_issue");
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    await runRevoke(
      { stdout, stderr: new PassThrough() },
      { selector: { jti }, yes: true },
      { home },
    );
    expect(getOut()).toContain("github.create_issue");
  });
});
