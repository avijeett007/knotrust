/**
 * @knotrust/bench — Path 5: proxy ready-to-serve after spawn (excl. `npx`
 * install). Budget: ≤750ms (R150 bullet 5).
 *
 * ## Why this is an ABSOLUTE measurement, not a delta
 *
 * Like path 4, there is no meaningful "proxy-off" baseline for "how long
 * does it take a proxy to become ready" — with no proxy there is nothing to
 * spawn. This times, per iteration, EXACTLY the span from calling
 * `proxy.start()` (child spawn begins) to the client's `initialize`
 * handshake resolving (the first request the proxy actually serves) —
 * per-iteration setup (building the fake-server config) and teardown
 * (closing the client/proxy/child) happen OUTSIDE the timed span, via
 * `measureAsyncSelfTimed` (`iterate.ts`).
 *
 * "excl. `npx` install" (R150): `serverCommand` here is a direct
 * `[process.execPath, bin.mjs, ...]` invocation (`startFakeServer`'s
 * `childCommand`, `@knotrust/test-harness`) — a real `node` process spawn,
 * never routed through `npx`'s own package-resolution/download overhead, so
 * this number is exactly "spawn a already-resolved server binary," never
 * conflated with a first-run package-manager fetch.
 */
import { PassThrough } from "node:stream";
import { createStdioProxy } from "@knotrust/proxy-stdio";
import { FakeClient, startFakeServer } from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { FAKE_SERVER_CONFIG } from "../fixtures/policy.js";
import { type MeasureOptions, measureAsyncSelfTimed } from "../iterate.js";
import { summarize } from "../stats.js";
import type { AbsolutePathResult } from "../types.js";

const BUDGET_MS_P95 = 750;

/** Sets up ONE fresh fake-server + proxy + client, times spawn→first-response, then tears everything down. Setup/teardown are NOT part of the returned duration. */
async function oneSpawnToReadyCycle(): Promise<number> {
  const started = await startFakeServer(FAKE_SERVER_CONFIG, {
    prepareChildCommand: true,
  });
  const childCommand = started.childCommand;
  if (childCommand === undefined) {
    throw new Error("bench: startFakeServer did not produce a childCommand");
  }

  const clientToProxy = new PassThrough();
  const proxyToClient = new PassThrough();
  const stderrSink = new PassThrough();
  stderrSink.resume();

  const proxy = createStdioProxy({
    serverCommand: childCommand,
    stdin: clientToProxy,
    stdout: proxyToClient,
    stderr: stderrSink,
  });
  const clientTransport = new StdioServerTransport(
    proxyToClient,
    clientToProxy,
  );
  const client = new FakeClient(clientTransport);

  try {
    const startMs = performance.now();
    await proxy.start();
    await client.connect();
    return performance.now() - startMs;
  } finally {
    await client.close().catch(() => {});
    await proxy.stop().catch(() => {});
    await started.close().catch(() => {});
  }
}

export async function benchProxyReadyToServe(
  opts: MeasureOptions,
): Promise<AbsolutePathResult> {
  const durations = await measureAsyncSelfTimed(oneSpawnToReadyCycle, opts);
  return {
    path: "proxy-ready-to-serve-after-spawn",
    budgetMsP95: BUDGET_MS_P95,
    measured: summarize(durations),
    warmupIterations: opts.warmupIterations,
    measuredIterations: opts.measuredIterations,
  };
}
