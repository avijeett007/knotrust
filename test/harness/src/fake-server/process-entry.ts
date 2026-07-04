/**
 * @knotrust/test-harness — child-process entry point (P0-E11-T1, R53).
 *
 * `runFakeServerProcess` is what `bin.mjs` invokes. It reads a
 * `FakeServerConfig` back from the temp JSON file `start.ts` wrote,
 * rebuilds the exact same fake server core `start.ts`'s in-process path
 * uses (`buildFakeServer` — the shared-core factoring), and connects it to
 * a REAL `StdioServerTransport` (this process's own stdin/stdout) instead
 * of an in-memory pair. This is the process the proxy under test (P0-E5)
 * spawns as `knotrust -- node bin.mjs --config <path>` — a real OS
 * subprocess speaking real, line-framed JSON-RPC over real pipes.
 */

import { readFile } from "node:fs/promises";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createSeededPrng } from "../prng.js";
import { buildFakeServer } from "./core.js";
import { type FakeServerConfig, isChildProcessCompatible } from "./types.js";

function parseConfigPath(argv: string[]): string {
  const flagIndex = argv.indexOf("--config");
  const value = flagIndex === -1 ? undefined : argv[flagIndex + 1];
  if (value === undefined) {
    throw new Error(
      "knotrust-fake-server: missing required --config <path> argument",
    );
  }
  return value;
}

export async function runFakeServerProcess(argv: string[]): Promise<void> {
  const configPath = parseConfigPath(argv);
  const raw = await readFile(configPath, "utf8");
  const config = JSON.parse(raw) as FakeServerConfig;

  if (!isChildProcessCompatible(config)) {
    throw new Error(
      "knotrust-fake-server: config contains a 'custom' tool-behavior handler, which is not " +
        "representable in a JSON config file and cannot run in child-process mode.",
    );
  }

  const seed = config.chaos?.seed ?? 0;
  const prng = createSeededPrng(seed);
  const handle = buildFakeServer(config, prng, { isChildProcess: true });

  const transport = new StdioServerTransport();
  await handle.server.connect(transport);
}
