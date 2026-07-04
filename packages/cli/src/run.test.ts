/**
 * P0-E5-T1 CLI runner acceptance (R61): argv splitting on `--`, the P0-E7
 * subcommand stub, and a real end-to-end `knotrust -- <server>` run that spawns
 * the @knotrust/test-harness fake server as a child and proxies a full
 * conversation through it.
 *
 * `init`'s own dispatch/argv-parse wiring (P0-E7-T1) is covered separately in
 * `run.init.test.ts`; `grant`/`grant list`/`revoke`'s own dispatch/argv-parse
 * wiring (P0-E7-T2) is covered separately in `run.grant.test.ts` (usage
 * errors) and `run.grant-e2e.test.ts` (the mint->list->allow->revoke->deny
 * acceptance). `add pack`'s own dispatch/argv-parse wiring (P0-E7-T3) is
 * covered separately in `run.add.test.ts`. `audit`'s own dispatch/argv-parse
 * wiring (P0-E4-T4) is covered separately in `run.audit.test.ts`.
 * `approvals` remains stubbed here (its own later P0-E7-Tx task).
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  FakeClient,
  type FakeServerConfig,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { describe, expect, it } from "vitest";
import { parseArgs, runCli } from "./run.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

describe("knotrust CLI — argv parsing (R61)", () => {
  it("splits on the first `--`: before is subcommand, after is the server command", () => {
    expect(parseArgs(["--", "node", "server.js"])).toEqual({
      subcommand: [],
      serverCommand: ["node", "server.js"],
    });
    expect(parseArgs(["init", "--", "node", "server.js", "--flag"])).toEqual({
      subcommand: ["init"],
      serverCommand: ["node", "server.js", "--flag"],
    });
    expect(parseArgs(["init"])).toEqual({
      subcommand: ["init"],
      serverCommand: undefined,
    });
    expect(parseArgs([])).toEqual({ subcommand: [], serverCommand: undefined });
  });
});

describe("knotrust CLI — subcommand stub (P0-E7 not yet implemented)", () => {
  it("errors with a non-zero code and a P0-E7 message for a still-stubbed subcommand", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    // "approvals" (not "init"/"grant"/"revoke"/"audit" — those are
    // implemented as of P0-E7-T1/T2/T3/P0-E4-T4, see
    // `run.init.test.ts`/`run.grant.test.ts`/`run.audit.test.ts`) proves the
    // generic stub still fires for every subcommand that hasn't landed yet.
    const code = await runCli(["approvals"], {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr,
      installSignalHandlers: false,
    });
    expect(code).toBe(2);
    expect(getErr()).toContain("P0-E7");
  });

  it("errors when nothing follows `--`", async () => {
    const stderr = new PassThrough();
    const getErr = collect(stderr);
    const code = await runCli(["--"], {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr,
      installSignalHandlers: false,
    });
    expect(code).toBe(2);
    expect(getErr()).toContain("nothing after");
  });
});

describe("knotrust CLI — `knotrust -- <server>` runs the proxy end-to-end (R61)", () => {
  it("spawns the fake server as a child and proxies initialize->tools/list->tools/call, then exits 0 on client EOF", async () => {
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-cli", version: "1.0.0" },
      tools: [
        { name: "echo", inputSchema: { type: "object", properties: {} } },
      ],
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const stderr = new PassThrough();

    // This is a zero-config run (no `knotrust.config.*` on `io.cwd`), which —
    // since P0-E5-T3 fix round 1 — wires a REAL audit sink at
    // `$KNOTRUST_HOME/audit` (see `run.ts`'s `buildZeroConfigObserver`).
    // Point that at a throwaway temp dir rather than the real
    // `~/.knotrust`, so this test run never touches the developer's/CI
    // machine's actual home directory — restored in `finally` even if an
    // assertion below throws.
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-cli-run-home-"));
    const priorHome = process.env.KNOTRUST_HOME;
    process.env.KNOTRUST_HOME = home;

    try {
      // Run the CLI exactly as `knotrust -- <server command>` would, but on
      // injected streams instead of the real process stdio.
      const cliDone = runCli(["--", ...childCommand], {
        stdin: clientToProxy,
        stdout: proxyToClient,
        stderr,
        installSignalHandlers: false,
      });

      const client = new FakeClient(
        new StdioServerTransport(proxyToClient, clientToProxy),
      );
      const init = (await client.connect()) as {
        serverInfo?: { name?: string };
      };
      expect(init.serverInfo?.name).toBe("knotrust-fake-cli");

      const listed = await client.listAllTools();
      expect(listed.tools.map((t) => t.name)).toEqual(["echo"]);

      const call = await client.callTool("echo", { ping: "pong" });
      expect(call.content).toEqual([
        { type: "text", text: JSON.stringify({ ping: "pong" }) },
      ]);

      // Client closes its end → proxy sees stdin EOF → graceful child
      // shutdown → runCli resolves with exit code 0.
      await client.close();
      clientToProxy.end();

      const code = await cliDone;
      expect(code).toBe(0);

      await started.close();
    } finally {
      if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = priorHome;
      rmSync(home, { recursive: true, force: true });
    }
  }, 30_000);
});
