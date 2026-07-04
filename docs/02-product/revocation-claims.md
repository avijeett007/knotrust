# Revocation claims — the single source of truth

This document is the **only** place KnoTrust's revocation-freshness claim language lives (P0-E3-T4, ruling R42; decisions brief §B2; [ADR-0011](../05-decisions/adr/adr-0011-revocation-claims-per-mode.md)). Every other artifact — README, website copy, launch posts, CLI help text, other docs — must **link to the paragraph below for the relevant mode** rather than restate the claim in its own words. Restated claims drift; a drifted revocation claim is exactly the kind of overclaim ("instant revocation") that does not survive technical scrutiny, because no mechanism beats the bound of new information reaching the verifier (ADR-0011's structural conclusion).

## How to link here

Link the mode-specific anchor, never paraphrase: `docs/02-product/revocation-claims.md#local-mode` or `docs/02-product/revocation-claims.md#control-plane-mode-phase-2`. If a sentence about revocation freshness cannot be expressed as "see the revocation claim for <mode>", the sentence is making a new claim and needs a ruling here first.

## Local mode

> **Revocation takes effect on the next decision.**

This is effectively immediate — **for this mode only** — and KnoTrust may say so *only* with that mode qualifier attached (brief §B2; ADR-0011). The mechanism is why the claim is honest: in local mode the store *is* the cache. `knotrust revoke` (library path: `revokeGrants`, `packages/grants/src/revoke.ts`) writes a revocation **tombstone** for each matched grant — a tombstone always wins over any lingering grant file, crash-safely — and then **bumps the decision-cache grant-set version** (the implementation plan's `configEpoch`, realized as `DecisionCache.bumpGrantSetVersion`, P0-E2-T4), which makes every previously-cached decision unreachable *and* purges it. The very next decision re-evaluates against a store that no longer serves the revoked grant. **No process restart is involved, ever** — the acceptance test for this task proves grant → allow → revoke → deny over the same live objects with zero restarts.

Never shorten this to "instant revocation" without the mode qualifier: unqualified "instant" is precisely the claim ADR-0011 rejects.

## Control-plane mode (Phase 2+)

> **Revocation propagates within the configured sync interval (default 30 s), or on push invalidation when connected.**

TTL-bounded, **never "instant."** Edges sync signed policy/grant bundles (TUF-style versioned metadata); a revocation lands at an edge via the next bundle sync or a push invalidation. An edge that stays offline past the sync interval degrades gracefully to the TTL-bounded guarantee below — the grant's own expiry and the decision-cache TTL are the backstop, and that is the honest claim for the offline-edge case (brief §B2; ADR-0011; architecture §5.6).

## The staleness backstop, regardless of mode

Decision-cache entries for `sensitive` and `critical` tiers carry short TTLs — **≤ 60 s for `sensitive`, and `critical` is never cached at all** (brief §B2; architecture §7.2; enforced as hard caps in `packages/core/src/decision-cache.ts`, which config can lower but never raise). This is a concrete, load-bearing mechanism, not a claims-discipline flourish: even in a stale-bundle window, a cached decision can never outlive a revocation by more than one TTL window.

## References

- Decisions brief §B2 (`docs/05-decisions/2026-07-03-decisions-brief.md`) — the ratified mode-scoped decision text.
- [ADR-0011: Mode-dependent revocation-freshness claims; never "instant" unqualified](../05-decisions/adr/adr-0011-revocation-claims-per-mode.md).
- Architecture §5.6 (revocation semantics per mode) and §7.2 (tiered TTLs) — `docs/02-architecture/system-architecture.md`.
