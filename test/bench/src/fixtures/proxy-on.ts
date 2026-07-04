/**
 * @knotrust/bench — the PROXY-ON harness (P0-E9-T3, R150/R151).
 *
 * The REAL substrate, composed exactly like
 * `packages/proxy-stdio/src/enforce.integration.test.ts`'s `setupEnforced`
 * (P0-E5-T3's own acceptance harness) — not the CLI's `buildEnforcement`
 * (`packages/cli/src/enforcement.ts`), which additionally wires the approval
 * orchestrator/localhost page server/OTel exporter. Those are real product
 * surfaces, but they are irrelevant to (and would only add startup-time
 * confounds to) what this bench measures: the decision path itself —
 * `createStdioProxy` (P0-E5-T1/T3) relaying through `createEnforcer`
 * (P0-E5-T3) over the UNIFIED `createDecider` (P0-E5-T3, `@knotrust/grants`),
 * a REAL `createDecisionCache` (P0-E2-T4), a REAL file-backed `GrantStore` +
 * hash-chained `AuditLog` (P0-E4-T1/T3), and a REAL Ed25519 file `KeyStore`
 * (P0-E3-T1, forced `backend: "file"` so a benchmark run never touches the
 * developer's real OS keychain).
 *
 * ## Topology (why the client-facing hop is an in-memory `PassThrough` pair)
 *
 * `createStdioProxy`'s CHILD-facing hop is always a real spawned OS process
 * (`StdioClientTransport` — baked into `proxy.ts`, not something this bench
 * can swap out, and it shouldn't: that's the real spawn cost a production
 * `knotrust -- <server>` run pays too). The CLIENT-facing hop here is an
 * in-memory `PassThrough` pair rather than a second real spawned process —
 * see the doc's methodology section for why this is the fairer comparison,
 * not a shortcut that flatters the numbers: the proxy-OFF baseline
 * (`proxy-off.ts`) also talks to its fake-server child over exactly ONE real
 * spawned-child stdio hop (the same cost the proxy-ON child-facing hop
 * pays), so subtracting isolates the proxy's OWN added work (classify +
 * async enforcement + the in-memory hop, which costs microseconds) rather
 * than also charging the proxy for a SECOND real OS pipe that a symmetric
 * "spawn the proxy as a child too" design would double-count against a
 * single-hop baseline.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import {
  createDecisionCache,
  createUlidGenerator,
  type DecisionCache,
} from "@knotrust/core";
import {
  createDecider,
  createDiskPublicKeyResolver,
  createKeyStore,
  decodeGrantIndexEntry,
  mintDurableGrant,
} from "@knotrust/grants";
import {
  createEnforcer,
  createStdioProxy,
  type EnforcementHook,
  type StdioProxy,
} from "@knotrust/proxy-stdio";
import {
  type AuditSink,
  createAuditLog,
  createGrantStore,
} from "@knotrust/store";
import {
  FakeClient,
  type StartedFakeServer,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  benchMapping,
  FAKE_SERVER_CONFIG,
  FIXED_NOW_EPOCH_SECONDS,
  FIXED_NOW_MS,
  SENSITIVE_TOOL,
  SERVER_NAME,
  TIER_POLICY,
} from "./policy.js";

export interface ProxyOnHarness {
  client: FakeClient;
  cache: DecisionCache;
  audit: AuditSink;
  teardown(): Promise<void>;
}

/** Grant scope `idPattern: "call-*"` — matches every `SENSITIVE_TOOL` call the cache-miss path mints a fresh `arguments.callId` for (see `paths/cache-miss-grant-verify.ts`), so exactly one durable grant is a covering candidate and `verifyGrant` runs its one real Ed25519 signature check per call. */
const GRANT_ID_PATTERN = "call-*";

export async function setupProxyOn(): Promise<ProxyOnHarness> {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-bench-on-"));
  const priorHome = process.env.KNOTRUST_HOME;
  // `createKeyStore` resolves its home via `resolveKnotrustHome()` (the
  // `KNOTRUST_HOME` env override), not a constructor param — mirroring every
  // existing integration test's discipline (see e.g.
  // `enforce.integration.test.ts`'s `setupEnforced`).
  process.env.KNOTRUST_HOME = home;

  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const audit = createAuditLog({ home, nowEpochMs: () => FIXED_NOW_MS });
  const cache = createDecisionCache({
    nowEpochSeconds: () => FIXED_NOW_EPOCH_SECONDS,
  });
  const keyStore = await createKeyStore({ backend: "file" });
  await keyStore.ensureIdentity();
  const resolvePublicKey = createDiskPublicKeyResolver(home);
  const generateId = createUlidGenerator(() => FIXED_NOW_MS);

  await mintDurableGrant(
    {
      principal: { type: "user", id: "bench-user" },
      agent: "*",
      tool: SENSITIVE_TOOL,
      scope: { resourceType: SERVER_NAME, idPattern: GRANT_ID_PATTERN },
      tier: "sensitive",
      envelopeScope: "personal",
      ttlSeconds: 2_592_000,
    },
    {
      store,
      keyStore,
      nowEpochSeconds: FIXED_NOW_EPOCH_SECONDS,
      generateId,
      audit,
    },
  );

  const decider = createDecider({
    cache,
    tierPolicy: TIER_POLICY,
    policyVersion: "bench-pv1",
    store,
    audit,
    resolvePublicKey,
    nowEpochSeconds: () => FIXED_NOW_EPOCH_SECONDS,
    nowMs: () => FIXED_NOW_MS,
    generateId,
  });

  const enforcer = createEnforcer({
    decider,
    requestContext: {
      identity: { subjectType: "user", subjectId: "bench-user" },
      agent: { id: "bench-agent" },
      surface: { instanceId: "px-bench", server: SERVER_NAME },
      nowMs: () => FIXED_NOW_MS,
      generateId,
    },
    getMapping: benchMapping,
  });
  const enforce: EnforcementHook = (message) => enforcer.handle(message);

  const started: StartedFakeServer = await startFakeServer(FAKE_SERVER_CONFIG, {
    prepareChildCommand: true,
  });
  const childCommand = started.childCommand;
  if (childCommand === undefined) {
    throw new Error("bench: startFakeServer did not produce a childCommand");
  }

  const clientToProxy = new PassThrough();
  const proxyToClient = new PassThrough();
  const stderrSink = new PassThrough();
  stderrSink.resume(); // drain and discard — diagnostics are not part of this bench.

  const proxy: StdioProxy = createStdioProxy({
    serverCommand: childCommand,
    stdin: clientToProxy,
    stdout: proxyToClient,
    stderr: stderrSink,
    enforce,
  });
  await proxy.start();

  const clientTransport = new StdioServerTransport(
    proxyToClient,
    clientToProxy,
  );
  const client = new FakeClient(clientTransport);
  await client.connect();

  return {
    client,
    cache,
    audit,
    async teardown() {
      await client.close().catch(() => {});
      await proxy.stop().catch(() => {});
      await started.close().catch(() => {});
      try {
        audit.close();
      } catch {
        // best-effort — releasing the writer lock is the goal.
      }
      if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
      else process.env.KNOTRUST_HOME = priorHome;
      rmSync(home, { recursive: true, force: true });
    },
  };
}
