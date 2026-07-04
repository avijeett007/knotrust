/**
 * knotrust CLI — R115, the P0-E7-T2 headline scripted e2e acceptance:
 *
 *   mint (knotrust grant) -> list (knotrust grant list, shows it) ->
 *   a matching call decides ALLOW -> revoke (knotrust revoke) ->
 *   the same call decides DENY
 *
 * composing the REAL grant store + file keystore + audit log (via the real
 * `knotrust grant`/`knotrust revoke` CLI commands) and the REAL unified
 * decider (`@knotrust/grants`' `createDecider`, the exact E5/E6 substrate
 * the proxy itself uses) — never a fake/mocked store or decider.
 *
 * ## Why the second `decide()` needs the clock advanced (R114's documented
 * cross-process gap)
 *
 * `knotrust revoke` runs in a SEPARATE process from any live
 * `knotrust -- <server>` proxy (or, here, from this test's own decider
 * object) — it tombstones the grant in the on-disk store but has no
 * in-process decision cache to bump (see `grant/revoke-command.ts`'s module
 * header). So the SAME decider instance used for the pre-revoke ALLOW would,
 * absent a cache expiry, still serve that ALLOW from its warm cache after
 * the CLI revoke — not because the revoke didn't work, but because nothing
 * told THIS cache to forget. This is exactly the documented, honest local-
 * mode mechanism (`docs/02-product/revocation-claims.md`'s "staleness
 * backstop": sensitive-tier cache entries carry a hard **≤ 60 s** TTL,
 * enforced by `@knotrust/core`'s `decision-cache.ts` and never raisable by
 * config). This test advances its injected clock past that bound before the
 * second `decide()`, proving the REAL cross-process revocation guarantee —
 * "at most one TTL window stale, never longer" — rather than relying on an
 * in-process cache-bump this CLI invocation never performs.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import type { DecisionRequest, TierPolicy } from "@knotrust/core";
import { createDecisionCache, createUlidGenerator } from "@knotrust/core";
import {
  createDecider,
  createDiskPublicKeyResolver,
  decodeGrantIndexEntry,
} from "@knotrust/grants";
import { createAuditLog, createGrantStore } from "@knotrust/store";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "./run.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

function io(
  overrides: { stdout?: PassThrough; stderr?: PassThrough; cwd?: string } = {},
) {
  return {
    stdin: new PassThrough(),
    stdout: overrides.stdout ?? new PassThrough(),
    stderr: overrides.stderr ?? new PassThrough(),
    installSignalHandlers: false,
    ...(overrides.cwd !== undefined ? { cwd: overrides.cwd } : {}),
  };
}

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) cleanups.pop()?.();
});

describe("R115 — the scripted e2e acceptance: mint -> list -> allow -> revoke -> deny", () => {
  it("composes the real store + decider: a real CLI mint unlocks a real decide(), a real CLI revoke locks it again", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-grant-e2e-home-"));
    const cwd = mkdtempSync(path.join(tmpdir(), "knotrust-grant-e2e-cwd-"));
    const priorHome = process.env.KNOTRUST_HOME;
    const priorBackend = process.env.KNOTRUST_KEY_BACKEND;
    process.env.KNOTRUST_HOME = home;
    // NEVER the real OS keychain — `knotrust grant` legitimately builds a
    // real KeyStore to sign; force the file backend against this throwaway
    // temp home.
    process.env.KNOTRUST_KEY_BACKEND = "file";
    cleanups.push(() => {
      if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = priorHome;
      if (priorBackend === undefined) delete process.env.KNOTRUST_KEY_BACKEND;
      else process.env.KNOTRUST_KEY_BACKEND = priorBackend;
      rmSync(home, { recursive: true, force: true });
      rmSync(cwd, { recursive: true, force: true });
    });

    // --- 1. mint (knotrust grant), via the real CLI command ---
    const mintStdout = new PassThrough();
    const getMintOut = collect(mintStdout);
    const mintCode = await runCli(
      [
        "grant",
        "--tool",
        "github.create_issue",
        "--server",
        "github-mcp",
        "--agent",
        "*",
        "--tier-cap",
        "sensitive",
        "--expires",
        "30d",
        "--yes",
      ],
      io({ stdout: mintStdout, cwd }),
    );
    expect(mintCode).toBe(0);
    expect(getMintOut()).toContain("Minted durable grant");

    // --- 2. list (knotrust grant list) shows it ---
    const listStdout = new PassThrough();
    const getListOut = collect(listStdout);
    const listCode = await runCli(
      ["grant", "list", "--json"],
      io({ stdout: listStdout }),
    );
    expect(listCode).toBe(0);
    const parsedList = JSON.parse(getListOut()) as {
      active: Array<{
        jti: string;
        tool: string;
        tierCap: string;
        kind: string;
      }>;
    };
    expect(parsedList.active).toHaveLength(1);
    const grant = parsedList.active[0] as {
      jti: string;
      tool: string;
      tierCap: string;
      kind: string;
    };
    expect(grant.tool).toBe("github.create_issue");
    expect(grant.tierCap).toBe("sensitive");
    expect(grant.kind).toBe("durable");
    const jti = grant.jti;

    // A human-table `grant list` also shows it (non-JSON path).
    const tableStdout = new PassThrough();
    const getTableOut = collect(tableStdout);
    await runCli(["grant", "list"], io({ stdout: tableStdout }));
    expect(getTableOut()).toContain("github.create_issue");

    // --- 3. a matching call decides ALLOW — the REAL unified decider ---
    // (`@knotrust/grants`' `createDecider`, the exact substrate
    // `packages/cli/src/enforcement.ts` composes for a live proxy run),
    // over the SAME on-disk store the CLI just wrote to.
    let clockSec = 1_000_000;
    const store = createGrantStore({
      home,
      decodeIndexEntry: decodeGrantIndexEntry,
    });
    const cache = createDecisionCache({ nowEpochSeconds: () => clockSec });
    const resolvePublicKey = createDiskPublicKeyResolver(home);
    const tierPolicy: TierPolicy = {
      tools: { "github.create_issue": { tier: "sensitive", source: "user" } },
      unknownToolTier: "sensitive",
    };
    const generateId = createUlidGenerator(() => clockSec * 1000);

    const request: DecisionRequest = {
      contractVersion: "1.0",
      requestId: "01JZE2EREQ00000000000001",
      timestamp: "2026-07-03T12:00:00Z",
      subject: { type: "user", id: "local-user" },
      action: { name: "github.create_issue" },
      resource: { type: "github_repo", id: "kno2gether/openclaw" },
      context: {
        agent: { id: "claude-desktop", type: "ai_agent" },
        env: { time: "2026-07-03T12:00:00Z", surfaceLocal: true },
      },
      surface: {
        kind: "stdio_proxy",
        instanceId: "e2e-1",
        server: "github-mcp",
      },
    };

    const auditForAllow = createAuditLog({
      home,
      nowEpochMs: () => clockSec * 1_000,
    });
    const deciderForAllow = createDecider({
      cache,
      tierPolicy,
      policyVersion: "e2e-test-policy-v1",
      store,
      audit: auditForAllow,
      resolvePublicKey,
      nowEpochSeconds: () => clockSec,
      nowMs: () => clockSec * 1_000,
      generateId,
    });
    const allowed = await deciderForAllow.decide(request);
    expect(allowed.outcome).toBe("allow");
    expect(allowed.evaluatedBy).toBe("grant");
    // Releases the audit writer lock before the CLI's own revoke opens it.
    auditForAllow.close();

    // --- 4. revoke (knotrust revoke), via the real CLI command ---
    const revokeStdout = new PassThrough();
    const getRevokeOut = collect(revokeStdout);
    const revokeCode = await runCli(
      ["revoke", jti, "--yes"],
      io({ stdout: revokeStdout }),
    );
    expect(revokeCode).toBe(0);
    expect(getRevokeOut()).toContain("Revoked");
    expect(getRevokeOut()).toContain(jti);

    // --- 5. the same call decides DENY ---
    // Advance the clock past the sensitive-tier cache TTL (see module
    // header) so this SECOND decision naturally re-reads the (now
    // tombstoned) store rather than serving a stale ALLOW from the first
    // decider's warm cache.
    clockSec += 61;
    const auditForDeny = createAuditLog({
      home,
      nowEpochMs: () => clockSec * 1_000,
    });
    const deciderForDeny = createDecider({
      cache,
      tierPolicy,
      policyVersion: "e2e-test-policy-v1",
      store,
      audit: auditForDeny,
      resolvePublicKey,
      nowEpochSeconds: () => clockSec,
      nowMs: () => clockSec * 1_000,
      generateId,
    });
    const denied = await deciderForDeny.decide(request);
    expect(denied.outcome).toBe("deny");
    auditForDeny.close();

    // `grant list` now shows it gone too.
    const listStdout2 = new PassThrough();
    const getListOut2 = collect(listStdout2);
    await runCli(["grant", "list"], io({ stdout: listStdout2 }));
    expect(getListOut2()).toContain("No active grants.");
  });
});
