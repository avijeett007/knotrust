/**
 * knotrust CLI — `buildEnforcement`'s lazy KeyStore acceptance (P0-E6-T2, fix
 * round 1, Important 1).
 *
 * Before this fix, `buildEnforcement` constructed a real `KeyStore` (`await
 * createKeyStore({})` + `await keyStore.ensureIdentity()`) UNCONDITIONALLY on
 * every enforced run. `createKeyStore({})` auto-detects the OS keychain via a
 * real probe (a disposable set/delete round-trip) at construction time — a
 * blocking GUI prompt on a first-run machine with no human present when the
 * proxy is launched non-interactively by an agent host (Claude Desktop/Codex).
 * That hung `buildEnforcement` (and therefore the whole proxy startup) before
 * the child was ever spawned, even for a routine-only run that never
 * approves anything.
 *
 * These tests prove the KeyStore is now LAZY: constructed (memoized, a lazy
 * singleton promise) only inside the `mintEphemeralGrant` closure the real
 * approval orchestrator calls on the FIRST approval — never at
 * `buildEnforcement` construction time, never for a routine-only run.
 *
 * Two module mocks make this observable without driving a full
 * hold/resolve/approve flow (there is no `knotrust approvals approve` yet —
 * E7):
 *
 *   - `@knotrust/grants`' `createKeyStore` is wrapped with a call counter,
 *     still forwarding to the REAL implementation (forced `backend: "file"`
 *     so this suite can never trigger a real OS keychain probe even if the
 *     lazy fix regressed) — this is the "does the keychain get touched"
 *     signal.
 *   - `@knotrust/approval`'s `createApprovalOrchestrator` is wrapped to
 *     CAPTURE the `deps` object `enforcement.ts` builds (still forwarding to
 *     the real factory, so `buildEnforcement`'s own behavior is completely
 *     unchanged) — this exposes the exact `mintEphemeralGrant` closure under
 *     test, the same one a real approval would invoke, so it can be called
 *     directly to simulate "N approvals happened in this run" without
 *     needing the full block-and-wait hold/resolve machinery.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { CreateApprovalOrchestratorDeps } from "@knotrust/approval";
import type { DecisionRequest } from "@knotrust/core";
import { type KnotrustConfig, KnotrustConfigSchema } from "@knotrust/store";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildEnforcement } from "./enforcement.js";

// ---------------------------------------------------------------------------
// Mocks — see module header for what each one observes. `vi.mock` calls are
// hoisted above every import in this file by Vitest's transform regardless
// of source position, so `buildEnforcement` above still resolves against the
// mocked `@knotrust/grants`/`@knotrust/approval` modules below.
// ---------------------------------------------------------------------------

const keyStoreState = vi.hoisted(() => ({ calls: 0 }));

vi.mock("@knotrust/grants", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@knotrust/grants")>();
  return {
    ...actual,
    createKeyStore: (
      ...args: Parameters<typeof actual.createKeyStore>
    ): ReturnType<typeof actual.createKeyStore> => {
      keyStoreState.calls += 1;
      // Force the file backend regardless of what enforcement.ts passes —
      // this suite must never risk a real OS keychain probe even if the
      // lazy fix under test regressed. The per-test temp KNOTRUST_HOME
      // keeps the file backend fully isolated from the developer's real
      // ~/.knotrust.
      return actual.createKeyStore({ ...args[0], backend: "file" });
    },
  };
});

const orchestratorState = vi.hoisted(() => ({
  captured: undefined as CreateApprovalOrchestratorDeps | undefined,
}));

vi.mock("@knotrust/approval", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@knotrust/approval")>();
  return {
    ...actual,
    createApprovalOrchestrator: (
      deps: CreateApprovalOrchestratorDeps,
    ): ReturnType<typeof actual.createApprovalOrchestrator> => {
      orchestratorState.captured = deps;
      return actual.createApprovalOrchestrator(deps);
    },
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// `KnotrustConfigSchema.parse` (rather than a hand-built object) fills the
// same zod defaults (`scope`, `unknownToolTier`, `approvalTimeoutSeconds`,
// ...) `loadKnotrustConfig` fills for a real on-disk config — `policyVersion`
// content-hashes the whole normalized shape and throws on an undefined
// field, so this is not optional scaffolding.
function makeConfig(): KnotrustConfig {
  return KnotrustConfigSchema.parse({
    version: 1,
    identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
    servers: {
      testsrv: {
        tools: {
          routine_tool: { tier: "routine", source: "user" },
        },
      },
    },
  });
}

function toolsCall(id: number, name: string): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name, arguments: {} },
  } as JSONRPCMessage;
}

function makeMintInput(requestId: string): {
  request: DecisionRequest;
  tier: "critical";
} {
  return {
    request: {
      contractVersion: "1.0",
      requestId,
      timestamp: "2026-07-04T12:00:00Z",
      subject: { type: "user", id: "avijeett007@gmail.com" },
      action: { name: "critical_tool" },
      resource: { type: "unknown", id: "n/a" },
      context: {
        agent: { id: "codex-cli", type: "ai_agent" },
        env: { time: "2026-07-04T12:00:00Z", surfaceLocal: true },
        arguments: {},
      },
      surface: {
        kind: "stdio_proxy",
        instanceId: "px-enforcement-test-1",
        server: "testsrv",
      },
    },
    tier: "critical",
  };
}

const dirsToClean: string[] = [];
const priorHome = process.env.KNOTRUST_HOME;

afterEach(() => {
  keyStoreState.calls = 0;
  orchestratorState.captured = undefined;
  if (priorHome === undefined) delete process.env.KNOTRUST_HOME;
  else process.env.KNOTRUST_HOME = priorHome;
  while (dirsToClean.length > 0) {
    const dir = dirsToClean.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

function useTempHome(): void {
  const home = mkdtempSync(path.join(tmpdir(), "knotrust-enforcement-test-"));
  dirsToClean.push(home);
  process.env.KNOTRUST_HOME = home;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("buildEnforcement — lazy KeyStore (P0-E6-T2 fix round 1, Important 1)", () => {
  it("a routine-only enforced run never constructs a KeyStore (zero keychain touches)", async () => {
    useTempHome();
    const bundle = await buildEnforcement(makeConfig());
    try {
      const result = await bundle.enforce(toolsCall(1, "routine_tool"));
      expect(result).toEqual({ action: "forward" });
      expect(keyStoreState.calls).toBe(0);
    } finally {
      bundle.close();
    }
  });

  it("buildEnforcement itself never constructs a KeyStore — proxy startup does not await keychain access", async () => {
    useTempHome();
    // No tool call at all — construction alone must never touch the
    // keychain, regression-proofing the exact bug: a first-run keychain
    // probe blocking `buildEnforcement` (and therefore the whole proxy
    // startup) before the child process is even spawned.
    const bundle = await buildEnforcement(makeConfig());
    try {
      expect(keyStoreState.calls).toBe(0);
    } finally {
      bundle.close();
    }
  });

  it("an approval lazily constructs the KeyStore exactly once, even across two approvals in the same run", async () => {
    useTempHome();
    const bundle = await buildEnforcement(makeConfig());
    try {
      expect(keyStoreState.calls).toBe(0);

      const deps = orchestratorState.captured;
      expect(deps).toBeDefined();
      if (!deps)
        throw new Error("createApprovalOrchestrator deps not captured");

      // Two DIFFERENT approvals within the same buildEnforcement() run — the
      // exact `mintEphemeralGrant` closure a real approve resolution invokes.
      const first = await deps.mintEphemeralGrant(
        makeMintInput("01ENFORCEMENTTEST0000001"),
      );
      const second = await deps.mintEphemeralGrant(
        makeMintInput("01ENFORCEMENTTEST0000002"),
      );

      expect(first.jti).not.toBe(second.jti);
      // The lazy singleton: TWO approvals, ONE KeyStore construction.
      expect(keyStoreState.calls).toBe(1);
    } finally {
      bundle.close();
    }
  });
});
