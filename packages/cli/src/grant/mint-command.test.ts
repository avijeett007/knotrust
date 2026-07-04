/**
 * P0-E7-T2 — `knotrust grant` mint-command acceptance (R111/R112/R116),
 * composing the REAL grant store + file keystore + audit log against a
 * temp `$KNOTRUST_HOME` (NEVER the real keychain/home — `KNOTRUST_KEY_BACKEND`
 * is forced to `"file"` for every test in this suite).
 *
 * The named acceptances proven here:
 *   - `--expires` parses to the EXACT `exp` (iat + duration) epoch (R112).
 *   - the confirmation text for a `destructiveHint` tool includes the word
 *     "destructive" (R111), through the real command (not just the pure
 *     `format.ts` helper already covered in `format.test.ts`).
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  decodeGrantIndexEntry,
  decodeGrantPayload,
  parseWireClaims,
} from "@knotrust/grants";
import { saveToolInventory } from "@knotrust/proxy-stdio";
import { createGrantStore } from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GrantMintArgs } from "./argv.js";
import { runGrantMint } from "./mint-command.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

function baseArgs(over: Partial<GrantMintArgs> = {}): GrantMintArgs {
  return {
    tool: "github.create_issue",
    server: "github-mcp",
    agent: "*",
    tierCap: "sensitive",
    ttlSeconds: 2_592_000,
    yes: true,
    ...over,
  };
}

let home: string;
let cwd: string;
let priorBackend: string | undefined;

beforeEach(() => {
  home = mkdtempSync(path.join(tmpdir(), "knotrust-grant-mint-home-"));
  cwd = mkdtempSync(path.join(tmpdir(), "knotrust-grant-mint-cwd-"));
  priorBackend = process.env.KNOTRUST_KEY_BACKEND;
  // NEVER the real OS keychain — force the 0600-file backend, mirroring
  // `run.enforce.test.ts`'s own discipline for any test that may construct
  // a real `KeyStore`.
  process.env.KNOTRUST_KEY_BACKEND = "file";
});

afterEach(() => {
  if (priorBackend === undefined) delete process.env.KNOTRUST_KEY_BACKEND;
  else process.env.KNOTRUST_KEY_BACKEND = priorBackend;
  rmSync(home, { recursive: true, force: true });
  rmSync(cwd, { recursive: true, force: true });
});

function readOnlyGrantToken(): string {
  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const { active } = store.list();
  expect(active).toHaveLength(1);
  return (active[0] as { token: string }).token;
}

describe("runGrantMint (R111, R116)", () => {
  it("mints and persists a durable grant into the real store", async () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runGrantMint(
      { stdout, stderr: new PassThrough(), cwd },
      baseArgs(),
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    expect(code).toBe(0);
    expect(getOut()).toContain("Minted durable grant");

    const token = readOnlyGrantToken();
    const claims = parseWireClaims(decodeGrantPayload(token));
    expect(claims).toMatchObject({
      kind: "durable",
      singleUse: false,
      tool: "github.create_issue",
      tier: "sensitive",
      agent: "*",
      principal: { type: "user", id: "local-user" },
    });
  });

  it("--expires parses to the EXACT exp = iat + duration epoch (R112)", async () => {
    const code = await runGrantMint(
      { stdout: new PassThrough(), stderr: new PassThrough(), cwd },
      baseArgs({ ttlSeconds: 2_592_000 }), // 30d, already parsed by argv
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    expect(code).toBe(0);

    const token = readOnlyGrantToken();
    const claims = parseWireClaims(decodeGrantPayload(token));
    expect(claims?.iat).toBe(1_000_000);
    expect(claims?.exp).toBe(1_000_000 + 2_592_000);
  });

  it("uses knotrust.config's identity/scope as principal/envelopeScope when present", async () => {
    const { writeFileSync } = await import("node:fs");
    writeFileSync(
      path.join(cwd, "knotrust.config.json"),
      JSON.stringify({
        version: 1,
        scope: "personal",
        identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
      }),
    );
    await runGrantMint(
      { stdout: new PassThrough(), stderr: new PassThrough(), cwd },
      baseArgs(),
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    const token = readOnlyGrantToken();
    const claims = parseWireClaims(decodeGrantPayload(token));
    expect(claims?.principal).toEqual({
      type: "user",
      id: "avijeett007@gmail.com",
    });
    expect(claims?.envelopeScope).toBe("personal");
  });

  it("maps a concrete --agent to {id, type: ai_agent}", async () => {
    await runGrantMint(
      { stdout: new PassThrough(), stderr: new PassThrough(), cwd },
      baseArgs({ agent: "codex-cli" }),
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    const token = readOnlyGrantToken();
    const claims = parseWireClaims(decodeGrantPayload(token));
    expect(claims?.agent).toEqual({ id: "codex-cli", type: "ai_agent" });
  });

  it("parses --resource into scope.resourceType/idPattern", async () => {
    await runGrantMint(
      { stdout: new PassThrough(), stderr: new PassThrough(), cwd },
      baseArgs({ resource: "github_repo:kno2gether/*" }),
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    const token = readOnlyGrantToken();
    const claims = parseWireClaims(decodeGrantPayload(token));
    expect(claims?.scope).toEqual({
      resourceType: "github_repo",
      idPattern: "kno2gether/*",
    });
  });

  it("--yes mints without ever invoking the confirm gate", async () => {
    let called = false;
    const code = await runGrantMint(
      { stdout: new PassThrough(), stderr: new PassThrough(), cwd },
      baseArgs({ yes: true }),
      {
        home,
        nowEpochSeconds: () => 1_000_000,
        confirm: async () => {
          called = true;
          return true;
        },
      },
    );
    expect(code).toBe(0);
    expect(called).toBe(false);
    readOnlyGrantToken(); // throws (via the length assertion) if not persisted
  });

  it("without --yes, a declined confirm mints nothing", async () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    const code = await runGrantMint(
      { stdout, stderr: new PassThrough(), cwd },
      baseArgs({ yes: false }),
      { home, nowEpochSeconds: () => 1_000_000, confirm: async () => false },
    );
    expect(code).toBe(0);
    expect(getOut()).toContain("Cancelled");
    const store = createGrantStore({
      home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    expect(store.list().active).toHaveLength(0);
  });

  it("without --yes, an approved confirm mints", async () => {
    const code = await runGrantMint(
      { stdout: new PassThrough(), stderr: new PassThrough(), cwd },
      baseArgs({ yes: false }),
      { home, nowEpochSeconds: () => 1_000_000, confirm: async () => true },
    );
    expect(code).toBe(0);
    readOnlyGrantToken();
  });

  it("prints the plain-words confirmation text UNCONDITIONALLY, even under --yes (R116)", async () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    await runGrantMint(
      { stdout, stderr: new PassThrough(), cwd },
      baseArgs({
        yes: true,
        tool: "github.create_issue",
        server: "github-mcp",
      }),
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    const out = getOut();
    expect(out).toContain("github.create_issue");
    expect(out).toContain("github-mcp");
    expect(out).toContain("sensitive");
  });

  // --- the named acceptance: destructive-word-in-confirmation (R111) ---
  it("includes the word 'destructive' when the tool-inventory marks the tool destructiveHint:true", async () => {
    saveToolInventory(home, "github-mcp", {
      "github.delete_repo": {
        annotations: {
          trusted: false,
          source: "server_advertised",
          destructiveHint: true,
        },
        inputSchemaHash: "sha256:x",
      },
    });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    await runGrantMint(
      { stdout, stderr: new PassThrough(), cwd },
      baseArgs({ tool: "github.delete_repo", server: "github-mcp" }),
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    expect(getOut().toLowerCase()).toContain("destructive");
  });

  it("does NOT claim destructive when the tool-inventory marks it non-destructive", async () => {
    saveToolInventory(home, "github-mcp", {
      "github.create_issue": {
        annotations: {
          trusted: false,
          source: "server_advertised",
          destructiveHint: false,
        },
        inputSchemaHash: "sha256:x",
      },
    });
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    await runGrantMint(
      { stdout, stderr: new PassThrough(), cwd },
      baseArgs({ tool: "github.create_issue", server: "github-mcp" }),
      { home, nowEpochSeconds: () => 1_000_000 },
    );
    expect(getOut().toLowerCase()).not.toContain("destructive");
  });

  it("never prints the raw signed token/JWS (R116 — no secrets/raw grant text dumped)", async () => {
    const stdout = new PassThrough();
    const getOut = collect(stdout);
    await runGrantMint({ stdout, stderr: new PassThrough(), cwd }, baseArgs(), {
      home,
      nowEpochSeconds: () => 1_000_000,
    });
    const token = readOnlyGrantToken();
    expect(getOut()).not.toContain(token);
  });
});
