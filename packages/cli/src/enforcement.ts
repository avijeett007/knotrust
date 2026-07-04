/**
 * knotrust CLI — enforcement wiring (P0-E5-T3, R73; P0-E5-T4 wires the same
 * real audit sink through for probing detection; P0-E5-T5 wires
 * `config.failOpen` through to `createEnforcer`'s narrow fail-open recovery
 * seam, rulings R81/R84; P0-E6-T2 wires the REAL block-and-wait approval
 * channel in place of E5-T3's cannot-hold placeholder, rulings R91–R95;
 * P0-E6-T4 consolidates that wiring behind the formal `ApprovalChannel` +
 * `MultiChannelDispatcher` interface and adds client-cancellation, rulings
 * R101–R105; P0-E8-T1 wires the OPTIONAL OTel exporter, rulings R127/R128).
 *
 * ## P0-E8-T1 — the OTel exporter subscriber (R127/R128)
 *
 * `attachOtelExporter` (`@knotrust/otel`) is called UNCONDITIONALLY, right
 * after `audit` is constructed — but it is a pure SUBSCRIBER on that same
 * sink's `onAppend` hook (`@knotrust/store`, R127), never a decision-path
 * dependency: `createDecider`/`createEnforcer` below are byte-identical to
 * before this task, and neither knows or cares whether anything is
 * listening on the audit stream. The function itself decides — from
 * `config.telemetryExport` alone — whether to build and subscribe anything
 * at all; absent/disabled (R128's default) it returns `undefined` having
 * constructed NOTHING. See `@knotrust/otel`'s own module header for the
 * full "this is telemetry-export, never product telemetry" doctrine.
 *
 * ## P0-E6-T4 — the dispatcher-based approval seam (R101/R102)
 *
 * `createEnforcer`'s `orchestrator` option is now satisfied by
 * `@knotrust/approval`'s `createDispatchingApprovalOrchestrator`, wired over
 * a `createMultiChannelDispatcher` registering the REAL block-and-wait
 * channel as its one floor channel — a clean, one-for-one replacement of
 * E6-T2's direct `orchestrator: blockAndWaitChannel` wiring (that channel no
 * longer implements `requestApproval` itself; see `channel.ts`'s and
 * `block-and-wait.ts`'s own module headers for the full reshape). A future
 * Phase-1 elicitation channel is an ADDITIONAL entry in that SAME array —
 * zero change to this module's `createEnforcer`/`createDecider` wiring, or
 * to `enforce.ts` itself.
 *
 * ## P0-E6-T4 — client-cancellation (R105)
 *
 * `buildEnforcement` now also returns an `onClassify` hook
 * (`@knotrust/proxy-stdio`'s `createCancellationClassifier`), wired to the
 * SAME `approvalAdapter` instance's `cancel(jsonRpcRequestId)` method —
 * `run.ts` threads it into `createStdioProxy`'s existing (previously unused
 * by any CLI path) `onClassify` option, so a client's
 * `notifications/cancelled` for a held critical call also cancels the
 * pending approval, resolving the hold to `deny`/`approval_cancelled`
 * instead of dangling until its timeout.
 *
 * Composes the whole enforcement stack for a `knotrust -- <server>` run when a
 * `knotrust.config.*` is present: the REAL grant store + hash-chained audit log
 * (`@knotrust/store`), the REAL decision cache (`@knotrust/core`), the disk
 * public-key resolver (`@knotrust/grants`), and the UNIFIED decider
 * (`@knotrust/grants` `createDecider`) — handed to `@knotrust/proxy-stdio`'s
 * `createEnforcer` as the async `enforce` hook the proxy awaits for every
 * `tools/call`. The same `audit` sink is also passed as `createEnforcer`'s
 * `audit` option (P0-E5-T4, R78), so a real `denial_probing_suspected` event
 * is appended when repeated denials for the same tool/agent cross the
 * threshold — not just in tests.
 *
 * Enforcement is CONFIG-GATED (see `run.ts`): a real config file enables it; a
 * zero-config run stays transparent passthrough (T1/T2) with a notice — safer
 * for adoption than silently denying every tool on a first run, and the one
 * behavior that keeps the P0-E5-T1 passthrough acceptance intact. The full
 * "zero-config → default L0 enforcement" story is a deliberate follow-on toggle
 * (see the task report), not a silent default here.
 *
 * `createEnforcer`'s `failOpen` option is handed the EXACT SAME `tierPolicy`/
 * `envelope` values this module already builds for `createDecider` (`const
 * tierPolicy`/`const envelope` below, computed once and shared) — this is
 * deliberate, not incidental: when the real decider throws, the enforcer
 * needs an INDEPENDENT way to resolve the throwing call's tier (the decider
 * itself cannot be asked; it's what's broken), and reusing the identical
 * values the decider was constructed with is what keeps that independent
 * resolution consistent with what the decider would have produced. See
 * `enforce.ts`'s own module header for the full R81/R84 doctrine.
 *
 * ## The real approval orchestrator + block-and-wait channel (P0-E6-T2)
 *
 * `createEnforcer`'s `orchestrator` option (E5-T3's seam) is now wired to
 * `@knotrust/approval`'s REAL `createBlockAndWaitChannel`, driving a REAL
 * `createApprovalOrchestrator` (E6-T1) with:
 *
 *   - `mintEphemeralGrant` → `@knotrust/grants`' `mintEphemeralGrant` over
 *     the SAME `store`/`audit` this module already built, plus a REAL
 *     `KeyStore` (`createKeyStore()` — OS keychain default-on, file
 *     fallback, R22) this module constructs for exactly this purpose (no
 *     other CLI path needed a signing key before this). **LAZY** (fix round
 *     1, Important 1): `createKeyStore({})` auto-detects with a real
 *     keychain probe (a disposable set/delete round-trip) at construction —
 *     fine when a human is present to dismiss a first-run OS prompt, fatal
 *     when the proxy is launched non-interactively by an agent host (Claude
 *     Desktop/Codex), where that prompt has no one to answer it and
 *     `buildEnforcement` would hang before the child is even spawned. So the
 *     KeyStore is built (memoized, a lazy singleton promise) only inside
 *     this `mintEphemeralGrant` closure, on the FIRST approval — a
 *     routine-only run, or a deny/pending run that never mints, never
 *     touches the keychain at all.
 *   - `decide` → the SAME `decider.decide` used for the primary enforcement
 *     path (R87b: "the exact composition the proxy uses").
 *   - `revokeGrant` → `@knotrust/grants`' `revokeGrants({jti}, …)`, bumping
 *     the SAME decision cache's grant-set version on invalidation. **This
 *     closes the E6-T1 optional-revoke pin**: without it, a mid-flight
 *     admin-envelope deny during `resolve("approved")` would leave the
 *     just-minted ephemeral grant active and unconsumed for its full TTL
 *     (lifecycle.ts's own "FIX 3" doc-comment) — the CLI is the one place
 *     that gap can actually be closed for a real run, since only it can
 *     construct the real store + real cache to revoke against.
 *
 * ## Breaking the sendNotification chicken-and-egg (`bindProxySender`)
 *
 * The block-and-wait channel needs to push `notifications/progress`
 * heartbeats to the CLIENT while a call is held — i.e. it needs the PROXY's
 * client-facing transport. But the proxy (`createStdioProxy`, `run.ts`) is
 * constructed FROM this module's `enforce` hook, which is itself built from
 * the channel — the proxy does not exist yet when the channel does. A tiny
 * mutable box (`createDeferredClientSender` below) breaks the cycle: the
 * channel is handed a `sendNotification` that forwards to whatever this box
 * currently points at (a safe no-op until bound), and `run.ts` calls the
 * returned `bindProxySender` exactly once, immediately after constructing
 * the real proxy — well before any `tools/call` could arrive.
 */

import {
  createApprovalOrchestrator,
  createApprovalPageServer,
  createBlockAndWaitChannel,
  createDispatchingApprovalOrchestrator,
  createMultiChannelDispatcher,
  generateApprovalCode,
  generateApprovalToken,
  withApprovalRequestRegistry,
} from "@knotrust/approval";
import { createDecisionCache, createUlidGenerator } from "@knotrust/core";
import {
  createDecider,
  createDiskPublicKeyResolver,
  createKeyStore,
  decodeGrantIndexEntry,
  type KeyStore,
  mintDurableGrant,
  mintEphemeralGrant,
  resolveKnotrustHome,
  revokeGrants,
} from "@knotrust/grants";
import { attachOtelExporter } from "@knotrust/otel";
import {
  type ClassifierHook,
  createCancellationClassifier,
  createEnforcer,
  type EnforcementHook,
} from "@knotrust/proxy-stdio";
import {
  createAuditLog,
  createGrantStore,
  type KnotrustConfig,
  policyVersion,
  toAdminEnvelope,
  toTierPolicy,
} from "@knotrust/store";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

// ---------------------------------------------------------------------------
// The sendNotification chicken-and-egg (see module header).
// ---------------------------------------------------------------------------

interface DeferredClientSender {
  /** What the channel calls — forwards to whatever `bind` most recently set. Defaults to a safe no-op. */
  send(message: JSONRPCMessage): Promise<void>;
  /** `run.ts` calls this once, right after constructing the real proxy. */
  bind(send: (message: JSONRPCMessage) => Promise<void>): void;
}

function createDeferredClientSender(): DeferredClientSender {
  let impl: (message: JSONRPCMessage) => Promise<void> = async () => {};
  return {
    send: (message) => impl(message),
    bind: (send) => {
      impl = send;
    },
  };
}

export interface EnforcementBundle {
  /** The async hook the proxy awaits for every `tools/call`. */
  enforce: EnforcementHook;
  /**
   * Wires the real proxy's client-facing send into the block-and-wait
   * channel's heartbeat seam (P0-E6-T2 — see module header). `run.ts` calls
   * this exactly once, immediately after constructing the proxy and before
   * `proxy.start()`.
   */
  bindProxySender(send: (message: JSONRPCMessage) => Promise<void>): void;
  /**
   * The R105 cancellation classifier (P0-E6-T4) — `run.ts` passes this
   * straight through as `createStdioProxy`'s `onClassify` option. A client's
   * `notifications/cancelled` for a held critical call cancels the matching
   * pending approval via the SAME dispatching adapter `enforce` uses.
   */
  onClassify: ClassifierHook;
  /**
   * Releases the audit writer lock — called on proxy teardown. ASYNC (P0-E8-T1):
   * when `telemetryExport` is enabled, this AWAITS the OTel exporter's bounded
   * shutdown (`@knotrust/otel`'s `SHUTDOWN_TIMEOUT_MS`, ≤5s) before resolving,
   * so `run.ts` can await it and give a real collector a genuine chance to
   * receive the run's last spans before `process.exit()` — see `@knotrust/otel`'s
   * `exporter.ts` module header, "Bounded shutdown," for why this can't just be
   * fire-and-forget the way `pageServer.stop()`/`audit.close()` still are. When
   * `telemetryExport` was never enabled (the default), this resolves just as
   * fast as the old synchronous `close()` did — there is nothing new to await.
   */
  close(): Promise<void>;
}

const nowMs = (): number => Date.now();
const nowEpochSeconds = (): number => Math.floor(Date.now() / 1000);

/**
 * Which logical MCP server this proxy instance fronts — the key into
 * `config.servers` used to resolve the tier policy + per-tool mappings.
 * Resolution order: `KNOTRUST_SERVER` env override → the sole configured server
 * (when exactly one) → the literal `"default"` (an unconfigured server yields an
 * empty tier policy, so every tool falls to `unknownToolTier`). Documented,
 * deliberately simple P0 heuristic — a first-class per-invocation server name is
 * an E7 CLI concern.
 */
function resolveServerName(config: KnotrustConfig): string {
  const override = process.env.KNOTRUST_SERVER;
  if (override !== undefined && override.trim() !== "") return override;
  const keys = Object.keys(config.servers ?? {});
  const [only] = keys;
  if (keys.length === 1 && only !== undefined) return only;
  return "default";
}

export interface BuildEnforcementOptions {
  /**
   * Where the block-and-wait channel's human-facing approval prompt is
   * written (P0-E6-T2, R91a — "the proxy's stderr"). Defaults to
   * `process.stderr.write`. `run.ts` passes the SAME injected `io.stderr`
   * the rest of a run already uses (`process.stderr` in the real `bin.ts`
   * entry point — see that module's header — so this is behavior-neutral in
   * production and only matters for tests that inject their own stream).
   */
  stderrWrite?: (chunk: string) => void;
}

export async function buildEnforcement(
  config: KnotrustConfig,
  options: BuildEnforcementOptions = {},
): Promise<EnforcementBundle> {
  const home = resolveKnotrustHome();
  const serverName = resolveServerName(config);

  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const audit = createAuditLog({ home, nowEpochMs: nowMs });
  // P0-E8-T1 (R127/R128): a PURELY ADDITIVE subscriber on the SAME `audit`
  // sink every decision already writes to — never a decision-path hook.
  // `attachOtelExporter` is called UNCONDITIONALLY on every run (enforced or
  // not); it is the one place that decides, from `config.telemetryExport`
  // alone, whether to construct anything at all — absent/disabled (the
  // default) returns `undefined` having built and subscribed NOTHING. See
  // `@knotrust/otel`'s own module header for the full off-by-default
  // contract and the verbatim "no product telemetry, ever" statement.
  // AWAITED (fix round 1, Minor — perf/privacy-story): `attachOtelExporter`
  // is now `async` because it lazy-`import()`s its four `@opentelemetry/*`
  // deps only on the `enabled === true` path (never at this module's own
  // top level) — `buildEnforcement` was already `async`, so this is a
  // zero-cost `await` on the disabled path (the default) and unblocks the
  // dynamic import resolving on the enabled path.
  const otelExporter = await attachOtelExporter({
    config: config.telemetryExport,
    audit,
    serverName,
  });
  const cache = createDecisionCache({ nowEpochSeconds });
  // The disk public-key resolver alone is enough to VERIFY grants (absent
  // identity ⇒ resolver returns null ⇒ no grant verifies, fail closed, never
  // a crash) — but as of P0-E6-T2 this run ALSO needs to MINT (the approval
  // orchestrator's approve path mints a call-hash-bound ephemeral grant),
  // which needs a real signing KeyStore too (below).
  const resolvePublicKey = createDiskPublicKeyResolver(home);
  const generateId = createUlidGenerator(nowMs);
  // OS keychain default-on, file fallback (R22) — the one CLI path that
  // needs to SIGN rather than merely verify, so this is the first place a
  // real KeyStore is constructed outside `knotrust grant` (E7, not yet
  // implemented) and this task's own approve path. LAZY (fix round 1,
  // Important 1): `createKeyStore({})` runs a real keychain probe at
  // construction — deferred to the FIRST approval (see `getKeyStore` below
  // and the module header) so a routine-only or deny/pending run never
  // touches the keychain, and a non-interactive agent host never hangs on a
  // first-run OS prompt before the child is even spawned. Memoized so
  // repeated approvals within one run build the keystore exactly once.
  // `ensureIdentity()` is deliberately NOT called here — `mintEphemeralGrant`
  // (`@knotrust/grants`' `mintGrant`, mint.ts:150) already calls it itself,
  // so an eager call here would be redundant work on every run for a benefit
  // only mint-time needs.
  let keyStorePromise: Promise<KeyStore> | undefined;
  function getKeyStore(): Promise<KeyStore> {
    keyStorePromise ??= createKeyStore({});
    return keyStorePromise;
  }

  // Computed ONCE, shared between `createDecider` (the real decision path)
  // and `createEnforcer`'s `failOpen` option (the INDEPENDENT tier
  // resolution R84 needs when that real path throws) — see this module's
  // own header for why sharing the identical values matters.
  const tierPolicy = toTierPolicy(config, serverName);
  const envelope = toAdminEnvelope(config);

  const decider = createDecider({
    cache,
    tierPolicy,
    envelope,
    policyVersion: policyVersion(config),
    store,
    audit,
    resolvePublicKey,
    nowEpochSeconds,
    nowMs,
    generateId,
  });

  // P0-E6-T2 — the real approval lifecycle orchestrator (E6-T1) + the real
  // block-and-wait channel, replacing E5-T3's cannot-hold placeholder. See
  // module header for the full rationale (mint/decide/revoke wiring, and
  // the `bindProxySender` chicken-and-egg fix).
  const clientSender = createDeferredClientSender();
  const approvalOrchestrator = createApprovalOrchestrator({
    // `mintEphemeralGrant`'s OWN deps take `nowEpochSeconds` as a SNAPSHOT
    // number (`@knotrust/grants`' `MintGrantDeps`/`LifecycleMintDeps` shape)
    // — unlike this orchestrator's own `nowEpochSeconds` (a function) — so
    // it is called fresh on every mint, inside this closure. The FIRST
    // approval is also where the lazy `keyStore` singleton actually gets
    // constructed (see `getKeyStore` above) — every approval after the first
    // in this run reuses the same memoized instance.
    mintEphemeralGrant: async (input) => {
      const keyStore = await getKeyStore();
      return mintEphemeralGrant(input, {
        store,
        keyStore,
        nowEpochSeconds: nowEpochSeconds(),
        generateId,
        audit,
      });
    },
    // The exact same composition the primary enforcement path uses (R87b).
    decide: (request) => decider.decide(request),
    // Closes the E6-T1 optional-revoke pin: a mid-flight envelope-deny
    // during `resolve("approved")` (lifecycle.ts's own "FIX 3") leaves the
    // just-minted ephemeral grant active/unconsumed for its full TTL unless
    // this is wired — best-effort, never changes the terminal deny already
    // written (see that module's own doc-comment).
    revokeGrant: (jti) => {
      revokeGrants(
        { jti },
        { store, audit, onInvalidate: () => cache.bumpGrantSetVersion() },
      );
    },
    audit,
    nowEpochSeconds,
    generateId,
  });

  // P0-E6-T3 — the localhost approval page. `withApprovalRequestRegistry`
  // (minimal wiring, `@knotrust/approval`'s `registry.ts`) wraps the
  // lifecycle orchestrator so the page can render tool/server/tier/argument
  // summary from the SAME frozen `ApprovalRequest` E6-T1 captured, without
  // any change to `lifecycle.ts`'s or `block-and-wait.ts`'s own contracts —
  // both the block-and-wait channel below and the page server share this
  // ONE wrapped orchestrator instance. The page is started EAGERLY (unlike
  // the lazy `KeyStore` above): binding a loopback ephemeral port is a
  // silent, instant `listen(0, "127.0.0.1")` with no OS-keychain-style
  // first-run prompt to hang a non-interactive agent host on, so there is no
  // reason to defer it — every enforced run is ready to serve the page the
  // FIRST time an approval actually needs it.
  const approvalRegistry = withApprovalRequestRegistry(approvalOrchestrator);
  const pageServer = createApprovalPageServer({
    orchestrator: approvalRegistry.orchestrator,
    getApprovalRequest: approvalRegistry.getApprovalRequest,
    // Mirrors `mintEphemeralGrant`'s own lazy-KeyStore closure above — the
    // durable-grant mint only ever runs on an "Always allow" click, so this
    // is not an additional eager keychain touch.
    mintDurableGrant: async (input) => {
      const keyStore = await getKeyStore();
      return mintDurableGrant(input, {
        store,
        keyStore,
        nowEpochSeconds: nowEpochSeconds(),
        generateId,
        audit,
      });
    },
    audit,
    nowEpochSeconds,
  });
  await pageServer.start();

  const blockAndWaitChannel = createBlockAndWaitChannel({
    orchestrator: approvalRegistry.orchestrator,
    sendNotification: (message) =>
      clientSender.send(message as unknown as JSONRPCMessage),
    nowEpochSeconds,
    home,
    // The block-and-wait channel's presented URL now points at THIS page
    // (R100) — reusing the SAME `tok_` token generator E6-T2 shipped with
    // (`generateApprovalCode`/`generateApprovalToken`, exported for exactly
    // this reuse), minted here and registered with the page via `url()`.
    mintApproval: (approvalId) => {
      const token = generateApprovalToken();
      const code = generateApprovalCode();
      const url = pageServer.url(approvalId, token);
      return { token, url, code };
    },
    ...(options.stderrWrite !== undefined
      ? { stderrWrite: options.stderrWrite }
      : {}),
  });

  // P0-E6-T4 (R101/R102): block-and-wait registered as the dispatcher's one
  // floor channel — a future Phase-1 elicitation channel is an ADDITIONAL
  // entry in this array, with zero further change here. The dispatching
  // adapter satisfies `createEnforcer`'s `orchestrator` seam by running
  // `request -> present -> onResolved -> map` over the SAME
  // `approvalRegistry.orchestrator` the page server also shares, and exposes
  // `cancel(jsonRpcRequestId)` for the R105 cancellation classifier below.
  const dispatcher = createMultiChannelDispatcher([blockAndWaitChannel], {
    ...(options.stderrWrite !== undefined
      ? { logger: options.stderrWrite }
      : {}),
  });
  const approvalAdapter = createDispatchingApprovalOrchestrator({
    orchestrator: approvalRegistry.orchestrator,
    dispatcher,
    ...(options.stderrWrite !== undefined
      ? { logger: options.stderrWrite }
      : {}),
  });

  // P0-E6-T4 (R105): a client's `notifications/cancelled` for a held
  // critical call cancels the matching pending approval — best-effort, a
  // no-op if none is pending for that JSON-RPC id (already resolved, or
  // never a pending_approval call at all). Threaded to `createStdioProxy`'s
  // `onClassify` option by `run.ts`.
  const onClassify = createCancellationClassifier((jsonRpcRequestId) => {
    void approvalAdapter.cancel(jsonRpcRequestId);
  });

  const agentId = process.env.KNOTRUST_AGENT;
  const enforcer = createEnforcer({
    decider,
    requestContext: {
      ...(config.identity !== undefined ? { identity: config.identity } : {}),
      ...(agentId !== undefined && agentId.trim() !== ""
        ? { agent: { id: agentId } }
        : {}),
      surface: { instanceId: generateId(), server: serverName },
      nowMs,
      generateId,
    },
    // The same real hash-chained audit sink the decider already writes
    // decision events to — wiring it here too is what makes R78's
    // `denial_probing_suspected` detection live in the real product, not
    // just in tests (P0-E5-T4). It is ALSO the mandatory sink R84's
    // `fail_open_fired` event appends to — the same "audit-of-fail-open is
    // not optional" contract applies here as in every unit test.
    audit,
    getMapping: (toolName) =>
      config.servers?.[serverName]?.tools?.[toolName]?.mapping,
    // P0-E6-T4 — the dispatching adapter (block-and-wait registered as the
    // dispatcher's floor channel; see module header). A `pending_approval`
    // decision now HOLDS and resolves terminally instead of falling through
    // to E5-T3's honest-but-inert cannot-hold envelope.
    orchestrator: approvalAdapter,
    // P0-E5-T5 (R84): consumes `config.failOpen.routine`, structurally
    // routine-only (`FailOpenConfigSchema`, `@knotrust/store`) — absent
    // entirely when the config never declared it, so fail-open stays off
    // by default (opt-in, never implicit).
    failOpen: {
      ...(config.failOpen?.routine !== undefined
        ? { routine: config.failOpen.routine }
        : {}),
      tierPolicy,
      envelope,
    },
  });

  return {
    enforce: (message) => enforcer.handle(message),
    bindProxySender: clientSender.bind,
    onClassify,
    close: async () => {
      // `pageServer.stop()` stays fire-and-forget, unchanged: a stuck
      // `server.close()` must never delay process exit, and `bin.ts`'s own
      // `process.exit(code)` tears down any still-open listener regardless
      // of whether this promise ever settles.
      pageServer.stop().catch(() => {
        // best-effort — see above.
      });
      // UNLIKE pageServer.stop(), this IS awaited (P0-E8-T1): `undefined`
      // when `telemetryExport` was never enabled (the default) — resolves
      // immediately, same as before this task. When enabled, awaiting gives
      // the configured collector a real chance to receive this run's last
      // spans before the process exits, bounded by `@knotrust/otel`'s own
      // `SHUTDOWN_TIMEOUT_MS` (≤5s) so a slow/unreachable collector still
      // can't hang shutdown indefinitely — see that package's `exporter.ts`
      // module header, "Bounded shutdown," and this interface's own
      // `close()` doc-comment for the full rationale.
      try {
        await otelExporter?.close();
      } catch {
        // best-effort — a failed flush must never block/fail shutdown.
      }
      try {
        audit.close();
      } catch {
        // best-effort on shutdown — releasing the writer lock is the goal.
      }
    },
  };
}
