/**
 * @knotrust/pdp — the `PdpAdapter` registry, plus the built-in L0 adapter's
 * default registration (P0-E2-T5, ruling R18).
 *
 * ## Package split (see `@knotrust/core`'s `pdp-port.ts` for the full
 * cycle-rationale write-up)
 *
 * The `PdpAdapter`/`PdpCapabilities`/`PdpDecision`/`PdpEvaluationContext`
 * TYPES live in `@knotrust/core` (`pdp-port.ts`) — core's own composed
 * decision pipeline (`pipeline.ts`) needs them to declare its dependency,
 * and a port a consumer depends on must live where the consumer lives.
 * IMPLEMENTATIONS and the REGISTRY live here, in `@knotrust/pdp`, which
 * depends on `@knotrust/core` and never the reverse — mechanically enforced
 * by `packages/core/scripts/check-boundaries.mjs` and
 * `scripts/check-core-boundary.sh`, both extended by this task to ban any
 * `@knotrust/pdp` import from `packages/core/src`.
 *
 * This module re-exports the core port types so nothing outside
 * `@knotrust/core` needs to import from core directly just to name
 * `PdpAdapter` — `@knotrust/pdp` is the intended integration surface for
 * anything that registers or looks up an adapter (the proxy, the CLI, a
 * future config loader).
 *
 * ## The no-core-changes test (this task's real acceptance bar)
 *
 * Phase 1 plugs a Cedar-WASM, AuthZEN-HTTP, or OPA adapter into this exact
 * registry by adding a new `*.ts` file here (mirroring `l0.ts`'s shape) and
 * a `registerAdapter(createXAdapter())` call — with ZERO changes to
 * `@knotrust/core`'s `pdp-port.ts` or `pipeline.ts`. `adapter.test.ts`'s
 * "no-core-changes conformance" case proves this today with a stub adapter
 * that is not L0, registered and retrieved exactly like the built-in one.
 *
 * ## Conformance-tracking discipline (architecture §10, invariant §E6)
 *
 * Every external draft-standard concern a Phase-1 adapter speaks stays
 * behind THAT adapter's own file, never leaking into this registry or into
 * `@knotrust/core`:
 *
 *   - **AuthZEN 1.0 Authorization API `[STANDARD]`** (Final, 2026-01-12
 *     OIDF vote) — the generic AuthZEN-HTTP adapter speaks
 *     `/access/v1/evaluation` directly; stable, safe to depend on.
 *   - **AARP/ARAP "Requestable Denial" `[DRAFT]`** and **COAZ
 *     `context.agent` mapping `[DRAFT]`** — both WG Draft 1, actively being
 *     rewritten. Any adapter translating to/from these shapes does so
 *     entirely within its own file; `PdpDecision.requestable` and this
 *     registry's public API never name an AARP/COAZ field directly.
 *
 * See ADR-0018 (`docs/05-decisions/adr/adr-0018-pdp-adapter-boundary.md`)
 * for the full ruling this file and `pdp-port.ts` implement.
 */

import type { PdpAdapter } from "@knotrust/core";
import { createL0Adapter } from "./l0.js";

export type {
  PdpAdapter,
  PdpCapabilities,
  PdpDecision,
  PdpEvaluationContext,
} from "@knotrust/core";

const registry = new Map<string, PdpAdapter>();

/** Registers (or overwrites, if the name is already taken) an adapter under its own `capabilities.name`. */
export function registerAdapter(adapter: PdpAdapter): void {
  registry.set(adapter.capabilities.name, adapter);
}

/** Looks up a registered adapter by name. `undefined` if nothing is registered under that name. */
export function getAdapter(name: string): PdpAdapter | undefined {
  return registry.get(name);
}

/** Every currently-registered adapter, in registration order. */
export function listAdapters(): readonly PdpAdapter[] {
  return Array.from(registry.values());
}

// The default adapter: always pre-registered so `getAdapter("l0")` resolves
// with zero configuration (brief §B1 — "the true default `npx knotrust`
// runs with zero config").
registerAdapter(createL0Adapter());
