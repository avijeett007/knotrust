/**
 * knotrust CLI — P0-E5-T5 fail-closed crash & error behavior, driven through
 * the REAL `knotrust -- <server>` runner end to end (rulings R82, R83).
 *
 * - R82: a wrapped-server crash mid-call (harness `crash:exit` — a real
 *   spawned child self-directing `process.exit(1)`) surfaces a client-visible
 *   error (never a hang) and the CLI process exits NON-ZERO.
 * - R83: a real OS SIGTERM to the running proxy, and a simulated
 *   `uncaughtException`/`unhandledRejection`, all terminate the wrapped
 *   child within the same run — proven against the REAL, production signal
 *   wiring (`installSignalHandlers` at its default, not disabled), not just
 *   `proxy.stop()` called directly.
 */

import { execFileSync } from "node:child_process";
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
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "./run.js";

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

/** Finds real OS pids whose full command line contains `substr` (e.g. the fake server's unique temp config-file path) — `ps`-based, so it works whether the matching process is a direct child of THIS test process or several levels down. */
function findPidsByCommandSubstring(substr: string): number[] {
  let out: string;
  try {
    out = execFileSync("ps", ["-eo", "pid,command"], { encoding: "utf8" });
  } catch {
    return [];
  }
  const pids: number[] = [];
  for (const line of out.split("\n")) {
    if (line.includes(substr)) {
      const match = /^\s*(\d+)/.exec(line);
      if (match?.[1] !== undefined) pids.push(Number(match[1]));
    }
  }
  return pids;
}

async function waitUntil(
  predicate: () => boolean,
  timeoutMs: number,
): Promise<boolean> {
  const deadline = performance.now() + timeoutMs;
  while (!predicate()) {
    if (performance.now() > deadline) return predicate();
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
  return true;
}

const cleanups: Array<() => void | Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) {
    const fn = cleanups.pop();
    if (fn) await Promise.resolve(fn()).catch(() => {});
  }
});

/** A fresh $KNOTRUST_HOME temp dir per test (the zero-config path still wires a real audit sink there) — restored/removed in `afterEach`. */
function tempHome(): void {
  const dir = mkdtempSync(path.join(tmpdir(), "knotrust-cli-crash-home-"));
  const prior = process.env.KNOTRUST_HOME;
  process.env.KNOTRUST_HOME = dir;
  cleanups.push(() => {
    if (prior === undefined) delete process.env.KNOTRUST_HOME;
    else process.env.KNOTRUST_HOME = prior;
    rmSync(dir, { recursive: true, force: true });
  });
}

describe("knotrust CLI — R82: wrapped-server crash surfaces a client error and a non-zero exit", () => {
  it("crash:exit mid-call (a real spawned child self-exiting) → the fake client's pending call errors, not hangs, and `knotrust -- <server>` exits NON-ZERO", async () => {
    tempHome();
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-crash-cli", version: "1.0.0" },
      tools: [
        { name: "crashy", inputSchema: { type: "object", properties: {} } },
      ],
      toolBehaviors: { crashy: { respond: { type: "crash", via: "exit" } } },
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const stderr = new PassThrough();

    const cliDone = runCli(["--", ...childCommand], {
      stdin: clientToProxy,
      stdout: proxyToClient,
      stderr,
      installSignalHandlers: false,
    });

    const client = new FakeClient(
      new StdioServerTransport(proxyToClient, clientToProxy),
    );
    cleanups.push(async () => {
      await client.close().catch(() => {});
      await cliDone.catch(() => {});
      await started.close().catch(() => {});
    });

    await client.connect();

    const callOutcome = client.callTool("crashy", {}).then(
      (result) => ({ kind: "resolved" as const, result }),
      (error) => ({ kind: "rejected" as const, error }),
    );
    const raced = await Promise.race([
      callOutcome,
      new Promise<{ kind: "timeout" }>((resolve) =>
        setTimeout(() => resolve({ kind: "timeout" }), 5_000),
      ),
    ]);
    expect(raced.kind).toBe("rejected"); // an ERROR, not a hang.

    const code = await cliDone;
    expect(code).not.toBe(0);
  }, 30_000);
});

describe("knotrust CLI — R83: proxy fatal error/signal termination", () => {
  it("a real SIGTERM to the running process is propagated to the wrapped child, which is gone within 5s (ps-verified) — the production signal wiring, not proxy.stop() called directly", async () => {
    tempHome();
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-sigterm-cli", version: "1.0.0" },
      tools: [
        { name: "echo", inputSchema: { type: "object", properties: {} } },
      ],
      toolBehaviors: { echo: { respond: { type: "echo" } } },
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");
    const configFilePath = childCommand[3];
    if (configFilePath === undefined) {
      throw new Error("test setup: no config file path in childCommand");
    }

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const stderr = new PassThrough();

    // `installSignalHandlers` is left at its DEFAULT (true) here on purpose:
    // this exercises the REAL `process.on("SIGTERM", ...)` wiring `run.ts`
    // installs in production, not a bypass. Sending the signal to THIS
    // process's own pid is a faithful proxy for "an external `kill` to a
    // real `knotrust` process" — Node's signal delivery and handler
    // dispatch mechanics are identical either way; what's under test is our
    // handler code, not the OS's signal-delivery plumbing (already reliable
    // and out of scope here).
    const cliDone = runCli(["--", ...childCommand], {
      stdin: clientToProxy,
      stdout: proxyToClient,
      stderr,
    });

    const client = new FakeClient(
      new StdioServerTransport(proxyToClient, clientToProxy),
    );
    cleanups.push(async () => {
      await client.close().catch(() => {});
      await cliDone.catch(() => {});
      await started.close().catch(() => {});
    });

    await client.connect();
    await client.callTool("echo", {});

    const spawned = await waitUntil(
      () => findPidsByCommandSubstring(configFilePath).length > 0,
      5_000,
    );
    expect(spawned).toBe(true);

    process.kill(process.pid, "SIGTERM");

    const dead = await waitUntil(
      () => findPidsByCommandSubstring(configFilePath).length === 0,
      5_000,
    );
    expect(dead).toBe(true);

    // The run itself must actually finish (not hang) once the child is gone.
    const code = await cliDone;
    expect(typeof code).toBe("number");
  }, 30_000);

  it("an uncaught exception in the proxy terminates the wrapped child and exits non-zero", async () => {
    tempHome();
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-uncaught-cli", version: "1.0.0" },
      tools: [
        { name: "echo", inputSchema: { type: "object", properties: {} } },
      ],
      toolBehaviors: { echo: { respond: { type: "echo" } } },
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");
    const configFilePath = childCommand[3];
    if (configFilePath === undefined) {
      throw new Error("test setup: no config file path in childCommand");
    }

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const stderr = new PassThrough();
    const getErr = collect(stderr);

    const cliDone = runCli(["--", ...childCommand], {
      stdin: clientToProxy,
      stdout: proxyToClient,
      stderr,
    });

    const client = new FakeClient(
      new StdioServerTransport(proxyToClient, clientToProxy),
    );
    cleanups.push(async () => {
      await client.close().catch(() => {});
      await cliDone.catch(() => {});
      await started.close().catch(() => {});
    });

    await client.connect();
    await client.callTool("echo", {});

    const spawned = await waitUntil(
      () => findPidsByCommandSubstring(configFilePath).length > 0,
      5_000,
    );
    expect(spawned).toBe(true);

    // Simulates a genuinely uncaught exception WITHOUT actually crashing the
    // test runner — `process.emit` fires every registered listener exactly
    // as Node's own internals do when an error truly escapes.
    process.emit("uncaughtException", new Error("simulated fatal error"));

    const dead = await waitUntil(
      () => findPidsByCommandSubstring(configFilePath).length === 0,
      5_000,
    );
    expect(dead).toBe(true);

    const code = await cliDone;
    expect(code).toBe(1);
    expect(getErr()).toContain("uncaught exception");
  }, 30_000);

  it("an unhandled rejection in the proxy terminates the wrapped child and exits non-zero", async () => {
    tempHome();
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-unhandled-cli", version: "1.0.0" },
      tools: [
        { name: "echo", inputSchema: { type: "object", properties: {} } },
      ],
      toolBehaviors: { echo: { respond: { type: "echo" } } },
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");
    const configFilePath = childCommand[3];
    if (configFilePath === undefined) {
      throw new Error("test setup: no config file path in childCommand");
    }

    const clientToProxy = new PassThrough();
    const proxyToClient = new PassThrough();
    const stderr = new PassThrough();
    const getErr = collect(stderr);

    const cliDone = runCli(["--", ...childCommand], {
      stdin: clientToProxy,
      stdout: proxyToClient,
      stderr,
    });

    const client = new FakeClient(
      new StdioServerTransport(proxyToClient, clientToProxy),
    );
    cleanups.push(async () => {
      await client.close().catch(() => {});
      await cliDone.catch(() => {});
      await started.close().catch(() => {});
    });

    await client.connect();
    await client.callTool("echo", {});

    const spawned = await waitUntil(
      () => findPidsByCommandSubstring(configFilePath).length > 0,
      5_000,
    );
    expect(spawned).toBe(true);

    const reason = new Error("simulated unhandled rejection");
    const rejected = Promise.reject(reason);
    // Attach our own catch immediately so this deliberately-created promise
    // never ALSO trips a genuine unhandledRejection in this test process —
    // `process.emit` below is what exercises the handler, not this promise
    // settling on its own.
    rejected.catch(() => {});
    process.emit("unhandledRejection", reason, rejected);

    const dead = await waitUntil(
      () => findPidsByCommandSubstring(configFilePath).length === 0,
      5_000,
    );
    expect(dead).toBe(true);

    const code = await cliDone;
    expect(code).toBe(1);
    expect(getErr()).toContain("unhandled rejection");
  }, 30_000);
});
