/**
 * @knotrust/core — internal tier-policy input shapes for the L0 evaluator (P0-E2-T2).
 *
 * These are the shapes `@knotrust/core`'s evaluator(s) consume. They are
 * NOT the on-disk config format — `packages/config` (E4-T2, not yet built)
 * will parse `knotrust.policy.yaml`/`knotrust.config.ts` (architecture §8.1)
 * plus preset packs into exactly this shape before calling the evaluator.
 * Keeping the parse step (E4-T2) and the evaluation step (this task)
 * strictly separate is what keeps the evaluator dependency-free and pure.
 */

import type { DecisionResponse } from "./contract.js";

/** Reuses the contract's tier union — never a parallel definition. */
export type Tier = DecisionResponse["tier"];

/**
 * Where a tool's tier entry came from:
 * - "user" — explicit entry in the user's own config (highest precedence;
 *   the only source `explicitAllow` is honored under, brief §B1/ruling 2).
 * - "pack" — explicit entry contributed by a preset pack (brief §C5, §8.2).
 * - "annotation" — a server-advertised annotation *seed* that was already
 *   recorded into generated config by a prior run (brief §C5: annotations
 *   seed *suggested* tiers in generated config; they never override policy
 *   at evaluation time — by the time an "annotation" entry reaches the
 *   evaluator it is just a recorded config value like any other).
 */
export type TierSource = "user" | "pack" | "annotation";

export interface ToolTierEntry {
  tier: Tier;
  source: TierSource;
  /**
   * Models the plan's "explicit config allow" for `sensitive`-tier tools
   * (brief §B1: sensitive allow iff covered by a durable grant OR explicit
   * config allow). Only meaningful when `source === "user"` — a pack or a
   * recorded annotation seed can never grant a standing allow this way.
   * This is enforced in the evaluator's logic, not at the type level
   * (ruling 2): the type permits `explicitAllow` on any source so a
   * generated-config writer never has to special-case serialization, but
   * `evaluateTierDefault` ignores it unless `source === "user"`.
   */
  explicitAllow?: boolean;
  /**
   * Models the precedence engine's (P0-E2-T3) layer (2) "explicit config
   * deny" (architecture §5.5, ruling R12): a decisive deny that wins over
   * any covering grant and skips straight past the tier default. Only
   * meaningful when `source === "user"` — exactly the same restriction as
   * `explicitAllow`, and for the same reason: a pack or a recorded
   * annotation seed can never mint a standing policy decision this way, only
   * the user's own config can. Enforced in `@knotrust/core`'s precedence
   * engine (`precedence.ts`), not at the type level, mirroring
   * `explicitAllow`'s own enforcement note above.
   */
  explicitDeny?: boolean;
}

export interface TierPolicy {
  /** Key = fully-qualified action name (`DecisionRequest["action"]["name"]`, e.g. "stripe.create_refund"). */
  tools: Record<string, ToolTierEntry>;
  /**
   * Tier assigned to a tool with no entry in `tools` (brief §C5: unknown/
   * unannotated destructive-looking tools default to `sensitive` or
   * higher). Type-level guarantee: this can never be "routine" — an
   * unlisted tool is never silently trusted.
   */
  unknownToolTier: "sensitive" | "critical";
}
