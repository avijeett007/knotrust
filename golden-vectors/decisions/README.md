# golden-vectors/decisions

Decision fixtures. Consumed by packages/core precedence tests; frozen at P0-E3-T5 (additive-only after).

Corpus now also includes the two R15 ratification locks added 2026-07-03 (`grant-exceeds-envelope-critical.json`, `tier-cap-violation-over-explicit-allow.json`) — see `packages/core/src/precedence.test.ts` for the paired contrast tests.

## Changelog

- **2026-07-04 (P0-E3-T5, the freeze):** this is the freeze-time completion
  the corpus anticipated, not a post-freeze mutation — every existing
  fixture's `expected` gained a `cacheEligible: boolean` flag (true iff
  `outcome ∈ {allow, deny}` and `tier ≠ critical`, asserted against
  `DecisionCache.set`'s real cacheability rules, not hand-computed); the
  `grant_allow` fixture (`grant-allow-within-envelope.json`) gained an
  asserted `grantRef`; the two `no_grant_critical`/`envelope_force_approval`
  pending-approval fixtures gained an asserted `wantsApproval: true`; the two
  `no_grant_sensitive` fixtures gained an asserted `requestable.how`; and
  `explicit-config-allow.json` was added — the corpus previously had no
  positive vector for that reason code, and R52's machine-checked
  completeness test would otherwise fail. After this commit, v1 is frozen:
  changing any byte of any vector here is a contract break (see
  `golden-vectors/README.md`).
