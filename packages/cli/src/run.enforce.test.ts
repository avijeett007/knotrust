/**
 * knotrust CLI — config-gated enforcement wiring acceptance (P0-E5-T3, R73;
 * fix round 1, Must-fix 1).
 *
 * `knotrust -- <server>` with a `knotrust.config.*` present spins up the FULL
 * enforcement stack (config → decider → proxy) and denies a sensitive tool
 * with no grant while forwarding a routine one; with NO config, `tools/call`
 * stays in transparent passthrough (the P0-E5-T1 behavior, preserved) BUT —
 * as of fix round 1 — the E5-T2 tool-inventory observer and a real audit
 * sink are now actually wired (`packages/cli/src/run.ts`'s
 * `buildZeroConfigObserver`), so the printed notice is no longer a lie about
 * "observe-only" mode with nothing observing.
 */

import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  FakeClient,
  type FakeServerConfig,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "./run.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

const SERVER_CONFIG: FakeServerConfig = {
  serverInfo: { name: "knotrust-fake-cli-enforce", version: "1.0.0" },
  tools: [
    { name: "routine_tool", inputSchema: { type: "object", properties: {} } },
    { name: "blocked_tool", inputSchema: { type: "object", properties: {} } },
  ],
};

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) await Promise.resolve(fn()).catch(() => {});
  }
});

function knotrustMeta(result: CallToolResult): Record<string, unknown> {
  const sc = (
    result as { structuredContent?: { knotrust?: Record<string, unknown> } }
  ).structuredContent;
  return sc?.knotrust ?? {};
}

describe("knotrust CLI — config-gated enforcement (R73)", () => {
  it("with a knotrust.config present, denies a sensitive tool (no grant) and forwards a routine one", async () => {
    const configDir = mkdtempSync(path.join(tmpdir(), "knotrust-cli-cfg-"));
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-cli-home-"));
    const priorHome = process.env.KNOTRUST_HOME;
    const priorKeyBackend = process.env.KNOTRUST_KEY_BACKEND;
    process.env.KNOTRUST_HOME = home;
    // Fix round 1, Minor 3: force the file backend so this enforced run's
    // `buildEnforcement` (which may construct a real `KeyStore` on approval)
    // never touches the developer's real OS keychain — matching the
    // integration tests' `createKeyStore({ backend: "file" })` discipline
    // (`packages/proxy-stdio/src/*.integration.test.ts`), applied here via
    // the env var since the CLI constructs its own `KeyStore` internally.
    process.env.KNOTRUST_KEY_BACKEND = "file";
    writeFileSync(
      path.join(configDir, "knotrust.config.json"),
      JSON.stringify({
        version: 1,
        identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
        servers: {
          testsrv: {
            tools: {
              routine_tool: { tier: "routine", source: "user" },
              blocked_tool: { tier: "sensitive", source: "user" },
            },
          },
        },
      }),
    );

    const started = await startFakeServer(SERVER_CONFIG, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const stderr = new PassThrough();
    const getErr = collect(stderr);

    const cliDone = runCli(["--", ...childCommand], {
      stdin: clientToProxy,
      stdout: proxyToClient,
      stderr,
      installSignalHandlers: false,
      cwd: configDir,
    });

    const client = new FakeClient(
      new StdioServerTransport(proxyToClient, clientToProxy),
    );

    cleanups.push(async () => {
      await client.close().catch(() => {});
      clientToProxy.end();
      await cliDone.catch(() => {});
      await started.close().catch(() => {});
      if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = priorHome;
      if (priorKeyBackend === undefined) {
        delete process.env.KNOTRUST_KEY_BACKEND;
      } else {
        process.env.KNOTRUST_KEY_BACKEND = priorKeyBackend;
      }
      rmSync(configDir, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    });

    await client.connect();

    const routine = await client.callTool("routine_tool", { ping: "pong" });
    expect(routine.isError).toBeFalsy();
    expect(routine.content).toEqual([
      { type: "text", text: JSON.stringify({ ping: "pong" }) },
    ]);

    const blocked = await client.callTool("blocked_tool", { x: 1 });
    expect(blocked.isError).toBe(true);
    // reasonCode is the R75 SAFE code (P0-E5-T4's two-layer denial envelope)
    // — never the internal "no_grant_sensitive".
    expect(knotrustMeta(blocked)).toMatchObject({
      outcome: "deny",
      reasonCode: "blocked_needs_grant",
    });

    expect(getErr()).toContain("enforcement enabled");
  }, 40_000);

  it("P0-E6-T2: a critical tool call is genuinely HELD by the real block-and-wait channel (not resolved instantly with a placeholder), and stderr shows the fixed-template approval prompt with a tok_ token", async () => {
    const configDir = mkdtempSync(path.join(tmpdir(), "knotrust-cli-baw-cfg-"));
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-cli-baw-home-"));
    const priorHome = process.env.KNOTRUST_HOME;
    const priorKeyBackend = process.env.KNOTRUST_KEY_BACKEND;
    process.env.KNOTRUST_HOME = home;
    // Fix round 1, Minor 3 — see the sibling test above for the rationale.
    process.env.KNOTRUST_KEY_BACKEND = "file";
    writeFileSync(
      path.join(configDir, "knotrust.config.json"),
      JSON.stringify({
        version: 1,
        identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
        servers: {
          testsrv: {
            tools: {
              critical_tool: { tier: "critical", source: "user" },
            },
          },
        },
      }),
    );

    const criticalConfig: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-cli-baw", version: "1.0.0" },
      tools: [
        {
          name: "critical_tool",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    };
    const started = await startFakeServer(criticalConfig, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const stderr = new PassThrough();
    const getErr = collect(stderr);

    const cliDone = runCli(["--", ...childCommand], {
      stdin: clientToProxy,
      stdout: proxyToClient,
      stderr,
      installSignalHandlers: false,
      cwd: configDir,
    });

    const client = new FakeClient(
      new StdioServerTransport(proxyToClient, clientToProxy),
    );

    const cleanupBaw = async () => {
      clientToProxy.end();
      await client.close().catch(() => {});
      await cliDone.catch(() => {});
      await started.close().catch(() => {});
      if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = priorHome;
      if (priorKeyBackend === undefined) {
        delete process.env.KNOTRUST_KEY_BACKEND;
      } else {
        process.env.KNOTRUST_KEY_BACKEND = priorKeyBackend;
      }
      rmSync(configDir, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    };
    cleanups.push(cleanupBaw);

    await client.connect();

    // A short client-side deadline: the OLD E5-T3 placeholder would have
    // answered a pending_approval INSTANTLY (the cannot-hold envelope) —
    // proving a genuine timeout here proves the real hold is wired in.
    const raced = await client.callToolWithTimeout(
      "critical_tool",
      { amount: 500 },
      { deadlineMs: 500 },
    );
    expect(raced.status).toBe("timedOut");

    // The human-facing prompt (R91a) landed on stderr — tool, tier, and a
    // correctly-shaped tok_ token (R92) — while nothing on the WIRE (the
    // client never received a response at all yet) could possibly carry it.
    const err = getErr();
    expect(err).toContain("approval required");
    expect(err).toContain("critical_tool");
    expect(err).toContain("critical");
    expect(err).toMatch(/tok_[A-Za-z0-9_-]{22,}/);

    // The pending-record file exists under $KNOTRUST_HOME/pending/, carrying
    // the same token — the human/audit-side channel (E7's future
    // `knotrust approvals` reads this).
    const pendingDir = path.join(home, "pending");
    expect(existsSync(pendingDir)).toBe(true);
    const [pendingFile] = readdirSync(pendingDir);
    expect(pendingFile).toBeDefined();
    const record = JSON.parse(
      readFileSync(path.join(pendingDir, pendingFile ?? ""), "utf8"),
    ) as { token: string; tool: string; tier: string };
    expect(record.tool).toBe("critical_tool");
    expect(record.tier).toBe("critical");
    expect(err).toContain(record.token);
  }, 40_000);

  it("with NO config, runs transparent passthrough (echo works), and — fix round 1 — actually wires the tool-inventory observer + audit sink with an honest notice", async () => {
    const emptyDir = mkdtempSync(path.join(tmpdir(), "knotrust-cli-noconfig-"));
    const home = mkdtempSync(
      path.join(tmpdir(), "knotrust-cli-noconfig-home-"),
    );
    const priorHome = process.env.KNOTRUST_HOME;
    process.env.KNOTRUST_HOME = home;

    const started = await startFakeServer(SERVER_CONFIG, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const stderr = new PassThrough();
    const getErr = collect(stderr);

    const cliDone = runCli(["--", ...childCommand], {
      stdin: clientToProxy,
      stdout: proxyToClient,
      stderr,
      installSignalHandlers: false,
      cwd: emptyDir,
    });

    const client = new FakeClient(
      new StdioServerTransport(proxyToClient, clientToProxy),
    );

    cleanups.push(async () => {
      await client.close().catch(() => {});
      clientToProxy.end();
      await cliDone.catch(() => {});
      await started.close().catch(() => {});
      if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = priorHome;
      rmSync(emptyDir, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    });

    await client.connect();

    // tools/list is OBSERVED (fix round 1): drives the E5-T2 capture so the
    // baseline actually gets persisted below — proving the wiring is real,
    // not just present-but-inert.
    const listed = await client.listAllTools();
    expect(listed.tools.map((t) => t.name).sort()).toEqual(
      ["blocked_tool", "routine_tool"].sort(),
    );

    // A sensitive-looking tool is NOT denied — enforcement is off (passthrough).
    const blocked = await client.callTool("blocked_tool", { x: 1 });
    expect(blocked.isError).toBeFalsy();
    expect(blocked.content).toEqual([
      { type: "text", text: JSON.stringify({ x: 1 }) },
    ]);

    // The audit sink is real: `$KNOTRUST_HOME/audit/` exists (createAuditLog
    // creates it eagerly at construction, before any event is appended).
    expect(existsSync(path.join(home, "audit"))).toBe(true);

    // The tool-inventory observer is real: SOME server directory under
    // `$KNOTRUST_HOME/servers/` holds a `tool-inventory.json` capturing both
    // tools this run's `tools/list` observed (not asserting the EXACT
    // derived server name here — that is `deriveZeroConfigServerName`'s own
    // concern — only that observation genuinely happened and was persisted).
    const serversDir = path.join(home, "servers");
    expect(existsSync(serversDir)).toBe(true);
    const serverDirs = readdirSync(serversDir);
    expect(serverDirs.length).toBeGreaterThan(0);
    const inventoryPath = path.join(
      serversDir,
      serverDirs[0] as string,
      "tool-inventory.json",
    );
    expect(existsSync(inventoryPath)).toBe(true);
    const inventory = JSON.parse(readFileSync(inventoryPath, "utf8")) as Record<
      string,
      unknown
    >;
    expect(Object.keys(inventory).sort()).toEqual(
      ["blocked_tool", "routine_tool"].sort(),
    );

    // The notice is now HONEST (fix round 1): it must say observation/audit
    // ARE active, and must NOT claim enforcement or the old false
    // "observe-only" wording that described a wire nothing was listening on.
    const err = getErr();
    expect(err).toContain("no knotrust.config found");
    expect(err).toMatch(/active and audited/i);
    expect(err).toMatch(/not gated or enforced/i);
    expect(err).not.toMatch(/observe-only/i);
    expect(err).not.toContain("enforcement enabled");
  }, 40_000);
});
