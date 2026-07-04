/**
 * @knotrust/core — golden decision fixture runner (P0-E2-T3, ruling 5;
 * extended at P0-E3-T5, THE FREEZE — pinned ledger obligations 2/3, R52).
 *
 * Loads EVERY `*.json` file in the repo-root `golden-vectors/decisions/`
 * directory and runs `evaluatePrecedence` against it. This is the "start of
 * the golden decision corpus" hook E3-T5 freezes: dropping a new fixture
 * file into that directory is picked up automatically, no test-file edits
 * required. `README.md` in that directory is a stub, not a fixture, and is
 * filtered out by the `.json` extension check below.
 *
 * Resolves the fixtures directory relative to this file (not
 * `process.cwd()`), matching `contract.test.ts`'s schema-loading convention,
 * so the suite behaves identically whether invoked from the repo root or
 * from within `packages/core`.
 *
 * P0-E3-T5 additions (the freeze-time completion the corpus anticipated, not
 * a post-freeze mutation — see `golden-vectors/decisions/README.md`'s
 * changelog):
 * - `expected.grantRef` / `expected.wantsApproval` / `expected.requestable`
 *   are now asserted against the decision's actual optional fields wherever
 *   they are set (not just for the specific reason codes the pinned
 *   obligation named — a fixture that omits one of these MUST decide with
 *   that field absent too, or the fixture is wrong).
 * - `expected.cacheEligible` (mandatory on every fixture) is asserted
 *   against `DecisionCache.set`'s REAL cacheability rules (a fresh cache per
 *   fixture; `stats.size` after `set()` is 1 iff eligible, 0 iff not) —
 *   never a hand-computed predicate that could drift from the cache's own
 *   `isCacheableTier`/`isCacheableOutcome` guards.
 * - A machine-checked reason-code completeness test (R52): the required
 *   code set is read directly off `L0ReasonCode`/`PrecedenceReasonCode`'s
 *   own exported const objects, not hand-retyped, so it can never silently
 *   drift out of sync with the engine's real reason-code vocabulary.
 */

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { DecisionRequest } from "./contract.js";
import { createDecisionCache } from "./decision-cache.js";
import type { CoveringGrant } from "./l0-evaluator.js";
import { L0ReasonCode } from "./l0-evaluator.js";
import type { AdminEnvelope, PrecedenceDecision } from "./precedence.js";
import { evaluatePrecedence, PrecedenceReasonCode } from "./precedence.js";
import type { Tier, TierPolicy } from "./tier-policy.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const decisionsDir = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "decisions",
);

interface DecisionFixture {
  name: string;
  description: string;
  input: {
    request: DecisionRequest;
    tierPolicy: TierPolicy;
    envelope?: AdminEnvelope;
    coveringGrants: CoveringGrant[];
    nowEpochSeconds: number;
  };
  expected: {
    outcome: PrecedenceDecision["outcome"];
    reasonCode: PrecedenceDecision["reasonCode"];
    tier: Tier;
    precedenceLayer: PrecedenceDecision["precedenceLayer"];
    clamped?: { from: Tier; to: Tier };
    /** Asserted whenever a grant decided the outcome (e.g. `grant_allow` fixtures). */
    grantRef?: string;
    /** Asserted whenever the decision escalates to the approval orchestrator (`wantsApproval: true` on the decision). */
    wantsApproval?: true;
    /** Asserted whenever the deny is a Requestable Denial (e.g. `no_grant_sensitive` fixtures). */
    requestable?: { how: string };
    /** Mandatory: true iff outcome ∈ {allow, deny} AND tier ≠ critical (frozen at P0-E3-T5). */
    cacheEligible: boolean;
  };
}

function loadFixtures(): Array<[string, DecisionFixture]> {
  const files = readdirSync(decisionsDir).filter((f) => f.endsWith(".json"));
  return files
    .sort()
    .map((file) => [
      file,
      JSON.parse(
        readFileSync(path.join(decisionsDir, file), "utf8"),
      ) as DecisionFixture,
    ]);
}

const fixtures = loadFixtures();

describe("golden decision fixtures (golden-vectors/decisions)", () => {
  it("enumerates the fixture directory dynamically and finds at least the plan-mandated minimum set", () => {
    // Minimum set per ruling 5: one per precedence layer/rule (envelope
    // deny, envelope force-approval, explicit config deny, grant allow,
    // self-escalation cap violation, pack-clamp floor, routine/sensitive/
    // critical tier defaults, grant-exceeds-envelope) = 10 fixtures.
    expect(fixtures.length).toBeGreaterThanOrEqual(10);
  });

  it.each(fixtures)("%s", (_file, fixture) => {
    const decision = evaluatePrecedence(fixture.input);

    // Every fixture asserts the reason code, not just the outcome (task
    // acceptance) — outcome alone can't distinguish e.g. tier_cap_violation
    // from grant_exceeds_envelope (both "deny" at the same tier).
    expect(decision.reasonCode).toBe(fixture.expected.reasonCode);
    expect(decision.outcome).toBe(fixture.expected.outcome);
    expect(decision.tier).toBe(fixture.expected.tier);
    expect(decision.precedenceLayer).toBe(fixture.expected.precedenceLayer);

    if (fixture.expected.clamped) {
      expect(decision.clamped).toEqual(fixture.expected.clamped);
    } else {
      expect(decision.clamped).toBeUndefined();
    }

    if (fixture.expected.grantRef !== undefined) {
      expect(decision.grantRef).toBe(fixture.expected.grantRef);
    } else {
      expect(decision.grantRef).toBeUndefined();
    }

    if (fixture.expected.wantsApproval === true) {
      expect(decision.wantsApproval).toBe(true);
    } else {
      expect(decision.wantsApproval).toBeUndefined();
    }

    if (fixture.expected.requestable !== undefined) {
      expect(decision.requestable).toEqual(fixture.expected.requestable);
    } else {
      expect(decision.requestable).toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// Cache-eligibility flags (pinned ledger obligation 3, P0-E3-T5) — asserted
// against DecisionCache.set's REAL cacheability rules, not a hand-computed
// predicate.
// ---------------------------------------------------------------------------

describe("golden decision fixtures — cache-eligibility flags (frozen at P0-E3-T5)", () => {
  it.each(
    fixtures,
  )("%s — expected.cacheEligible matches DecisionCache.set's real cacheability rules", (_file, fixture) => {
    const decision = evaluatePrecedence(fixture.input);
    const cache = createDecisionCache({
      nowEpochSeconds: () => fixture.input.nowEpochSeconds,
    });
    cache.set(
      fixture.input.request,
      decision,
      "golden-vector-fixture-policy-v1",
    );
    expect(cache.stats.size).toBe(fixture.expected.cacheEligible ? 1 : 0);
  });
});

// ---------------------------------------------------------------------------
// Reason-code coverage completeness (R52, machine-checked) — the required
// set is read directly off the engines' own exported const objects, so this
// test can never silently drift out of sync with a newly-added reason code.
// ---------------------------------------------------------------------------

describe("golden decision fixtures — reason-code coverage completeness (R52)", () => {
  const ALL_PRECEDENCE_TERMINATING_REASON_CODES = new Set<string>([
    ...Object.values(L0ReasonCode),
    ...Object.values(PrecedenceReasonCode),
  ]);

  it("the required set is exactly the plan-mandated 10 codes (sanity check on the derivation itself)", () => {
    expect(ALL_PRECEDENCE_TERMINATING_REASON_CODES).toEqual(
      new Set([
        "envelope_deny",
        "envelope_force_approval",
        "explicit_config_deny",
        "grant_allow",
        "tier_cap_violation",
        "grant_exceeds_envelope",
        "explicit_config_allow",
        "routine_default_allow",
        "no_grant_sensitive",
        "no_grant_critical",
      ]),
    );
  });

  it("every precedence-terminating reason code has at least one golden vector — fails if a code is added to the union without a fixture", () => {
    const covered = new Set<string>(
      fixtures.map(([, f]) => f.expected.reasonCode),
    );
    const missing = [...ALL_PRECEDENCE_TERMINATING_REASON_CODES].filter(
      (code) => !covered.has(code),
    );
    expect(missing).toEqual([]);
  });

  it("every fixture's reasonCode is a member of the known union (no stray or typo'd codes)", () => {
    for (const [file, fixture] of fixtures) {
      expect(
        ALL_PRECEDENCE_TERMINATING_REASON_CODES.has(
          fixture.expected.reasonCode,
        ),
        `${file}: reasonCode ${fixture.expected.reasonCode} is not in the known union`,
      ).toBe(true);
    }
  });
});
