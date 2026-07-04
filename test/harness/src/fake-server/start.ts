/**
 * @knotrust/test-harness — `startFakeServer` (P0-E11-T1, R53).
 *
 * R53's shape: `startFakeServer(config) → { childCommand?: string[],
 * inProcess?: {...}, ... }`. This module is the "one config, two transports"
 * seam:
 *
 * - **in-process** (always provided): an `InMemoryTransport.createLinkedPair()`
 *   pair — one end connected to a real, fully-configured
 *   `@modelcontextprotocol/sdk` `Server` (via `buildFakeServer`), the other
 *   end (`inProcess.clientTransport`) handed back for a `FakeClient` (or
 *   anything else speaking the `Transport` interface) to connect to
 *   directly. No subprocess, no disk I/O — this is the fast path R56
 *   requires for the 100-iteration chaos run.
 * - **child-process** (opt-in via `prepareChildCommand`): writes the config
 *   to a temp JSON file and returns `childCommand`, an argv the CALLER
 *   spawns itself (e.g. `child_process.spawn(childCommand[0],
 *   childCommand.slice(1))`, or the SDK's own `StdioClientTransport({command,
 *   args})`). `startFakeServer` never spawns this itself — R53 says the
 *   proxy under test (P0-E5) must be the one doing the spawning, so its own
 *   child-spawn logic is what's under test, not ours. Opt-in (rather than
 *   always-on) specifically so the chaos loop's 100 in-process iterations
 *   don't pay for a temp-file write they never use.
 *
 * A single `FakeServerConfig` therefore drives two *separate* running server
 * instances when both forms are used together (one in-process, one — if and
 * when spawned — a child process), not one process wearing two hats. They
 * are configured identically and behave identically from the outside; nobody
 * downstream needs them to be the literal same OS process, and requiring
 * that would rule out testing the real, production-shaped child-spawn path
 * at all.
 */

import { randomUUID } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { createSeededPrng } from "../prng.js";
import { buildFakeServer } from "./core.js";
import {
  type CallLogEntry,
  type FakeServerConfig,
  type FakeToolDef,
  isChildProcessCompatible,
} from "./types.js";

// `bin.mjs` is a committed, hand-written (not tsc-compiled) entry script
// that lives beside its TypeScript siblings at `src/fake-server/bin.mjs`
// (never copied into `dist/`). Both `src/fake-server/start.ts` and its
// compiled `dist/fake-server/start.js` counterpart sit exactly two
// directory levels below the package root, so this relative URL resolves
// to the one canonical `bin.mjs` regardless of whether THIS module is
// running as TS source (vitest) or compiled JS (dist) — no dist-copy build
// step required.
const BIN_PATH = fileURLToPath(
  new URL("../../src/fake-server/bin.mjs", import.meta.url),
);

export interface StartFakeServerOptions {
  /**
   * When true, also prepares a spawnable child-process command (writes a
   * temp JSON config file next to it). Defaults to false: preparing the
   * child command costs a disk write, which the in-process-only chaos
   * acceptance loop (R56) should not pay for on every one of its 100
   * iterations.
   */
  prepareChildCommand?: boolean;
}

export interface StartedFakeServer {
  /**
   * argv to spawn the fake server as a real child process, e.g.
   * `child_process.spawn(childCommand[0], childCommand.slice(1))` or
   * `new StdioClientTransport({ command: childCommand[0], args:
   * childCommand.slice(1) })`. Present only when `prepareChildCommand` was
   * requested AND the config contains no `"custom"` tool-behavior handler
   * (see `isChildProcessCompatible`).
   */
  childCommand?: string[];
  inProcess: {
    /** Hand this to a `FakeClient` (or any `Transport` consumer) to talk to the in-process server directly. */
    clientTransport: Transport;
    /** Live reference — mutated in place as calls arrive. */
    callLog: CallLogEntry[];
    /** Current (possibly drift-patched) served tool definitions. */
    getServedTools(): FakeToolDef[];
  };
  /** The chaos seed actually in effect (`config.chaos?.seed ?? 0`) — log this on chaos-test failure (R54). */
  seed: number;
  /** Closes the in-process server's transport and removes the temp child config file, if one was written. Does NOT touch a child process the caller spawned from `childCommand` — that process is the caller's own to manage. */
  close(): Promise<void>;
}

export async function startFakeServer(
  config: FakeServerConfig,
  options: StartFakeServerOptions = {},
): Promise<StartedFakeServer> {
  const seed = config.chaos?.seed ?? 0;
  const prng = createSeededPrng(seed);
  const handle = buildFakeServer(config, prng, { isChildProcess: false });

  const [serverTransport, clientTransport] =
    InMemoryTransport.createLinkedPair();
  await handle.server.connect(serverTransport);

  let childCommand: string[] | undefined;
  let configFilePath: string | undefined;
  if (options.prepareChildCommand) {
    if (!isChildProcessCompatible(config)) {
      throw new Error(
        "startFakeServer: prepareChildCommand was requested but this config contains a " +
          "'custom' tool-behavior handler, which cannot run in child-process mode " +
          "(a JS closure cannot cross the process boundary) — use in-process mode instead.",
      );
    }
    const dir = path.join(tmpdir(), "knotrust-test-harness");
    await mkdir(dir, { recursive: true });
    configFilePath = path.join(dir, `fake-server-${randomUUID()}.json`);
    await writeFile(configFilePath, JSON.stringify(config), "utf8");
    childCommand = [process.execPath, BIN_PATH, "--config", configFilePath];
  }

  return {
    // `exactOptionalPropertyTypes` treats `childCommand: undefined` as
    // distinct from an absent property, so the key is only present at all
    // when a child command was actually prepared.
    ...(childCommand !== undefined ? { childCommand } : {}),
    inProcess: {
      clientTransport,
      callLog: handle.callLog,
      getServedTools: handle.getServedTools,
    },
    seed,
    async close() {
      await handle.server.close().catch(() => {
        /* already closed (e.g. a configured crash already closed it) */
      });
      if (configFilePath !== undefined) {
        await rm(configFilePath, { force: true });
      }
    },
  };
}
