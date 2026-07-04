/**
 * @knotrust/bench — the PROXY-OFF (baseline) harness (P0-E9-T3, R150/R151).
 *
 * "round-trip DIRECT to the fake server, no proxy" (R151) — a `FakeClient`
 * connected via a real `StdioClientTransport` straight to a spawned fake-
 * server child process, exactly `test/harness/src/acceptance/baseline.test.ts`'s
 * own R56 proxy-free baseline. This is the ONE real spawned-child stdio hop
 * that also appears (unchanged) as the proxy-ON harness's child-facing hop —
 * see `proxy-on.ts`'s module header for why that shared hop is what makes
 * the ON-minus-OFF subtraction isolate the proxy's own added work.
 */

import {
  FakeClient,
  type StartedFakeServer,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { FAKE_SERVER_CONFIG } from "./policy.js";

export interface ProxyOffHarness {
  client: FakeClient;
  teardown(): Promise<void>;
}

export async function setupProxyOff(): Promise<ProxyOffHarness> {
  const started: StartedFakeServer = await startFakeServer(FAKE_SERVER_CONFIG, {
    prepareChildCommand: true,
  });
  const childCommand = started.childCommand;
  if (childCommand === undefined) {
    throw new Error("bench: startFakeServer did not produce a childCommand");
  }
  const [command, ...args] = childCommand;
  if (command === undefined) {
    throw new Error("bench: empty childCommand");
  }

  const transport = new StdioClientTransport({
    command,
    args,
    stderr: "ignore",
  });
  const client = new FakeClient(transport);
  await client.connect();

  return {
    client,
    async teardown() {
      await client.close().catch(() => {});
      await started.close().catch(() => {});
    },
  };
}
