/**
 * @knotrust/bench — shared tool/tier/server constants for the ON/OFF
 * harnesses (P0-E9-T3). ONE definition so the proxy-on and proxy-off setups
 * (and every path benchmark) agree on tool names/tiers without duplicating
 * literals.
 */
import type { TierPolicy } from "@knotrust/core";
import type { FakeServerConfig } from "@knotrust/test-harness";

/** The logical server name the bench's decision requests carry (`resource.type` falls back to this when a tool has no `mapping.resourceType`). */
export const SERVER_NAME = "bench-srv";

/** Routine tier — cacheable, no grant required. Used by the cache-hit-allow path. */
export const ROUTINE_TOOL = "routine_tool";

/** Sensitive tier, gated by a durable grant scoped `idPattern: "call-*"`. Used by the cache-miss + grant-verify path — `resource.id` is mapped from `arguments.callId` so every call with a distinct `callId` is a distinct cache key (guaranteed miss) while still matching the grant's wildcard scope (guaranteed exactly one real Ed25519 grant verify). */
export const SENSITIVE_TOOL = "sensitive_tool";

export const TIER_POLICY: TierPolicy = {
  tools: {
    [ROUTINE_TOOL]: { tier: "routine", source: "pack" },
    [SENSITIVE_TOOL]: { tier: "sensitive", source: "pack" },
  },
  unknownToolTier: "sensitive",
};

/** `getMapping` for `createEnforcer` — only `SENSITIVE_TOOL` needs a mapping (its `resource.id` must vary per call); `ROUTINE_TOOL` uses the default (static `resource.id === toolName`), which is exactly what the cache-hit path wants (a STABLE key across repeated calls). */
export function benchMapping(
  toolName: string,
): { resourceId: string } | undefined {
  return toolName === SENSITIVE_TOOL
    ? { resourceId: "arguments.callId" }
    : undefined;
}

export const FAKE_SERVER_CONFIG: FakeServerConfig = {
  serverInfo: { name: "knotrust-bench-fake-server", version: "1.0.0" },
  tools: [
    { name: ROUTINE_TOOL, inputSchema: { type: "object", properties: {} } },
    { name: SENSITIVE_TOOL, inputSchema: { type: "object", properties: {} } },
  ],
};

/** Fixed injected clock (epoch seconds/ms) for every grant/decision/audit timestamp in the bench — deterministic business logic; wall-clock LATENCY is measured independently via `performance.now()` in `iterate.ts`, so a frozen clock here has no bearing on the numbers this bench reports. */
export const FIXED_NOW_EPOCH_SECONDS = 1_800_000_000;
export const FIXED_NOW_MS = FIXED_NOW_EPOCH_SECONDS * 1000;
