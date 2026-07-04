# ADR-0011: Mode-dependent revocation-freshness claims; never "instant" unqualified

**Status:** Accepted (2026-07-03)

## Context

PRD §21 posed an open question: grant-cache revocation freshness — what security claim can KnoTrust honestly make? Research surveyed short-TTL-plus-refresh, CRL-style signed bundles, OCSP/stapling, and Macaroons/Biscuit-style caveat tokens, and found a structural conclusion: in a pure local, zero-network mode, no mechanism — CRL, OCSP, or otherwise — beats the bound of the grant's own TTL, because revocation-freshness fundamentally requires new information reaching the verifier. RFC 5280 itself acknowledges CRL-style revocation "will not be reliably notified... until all currently issued CRLs are scheduled to be updated." TUF is the strongest offline-verifiable precedent for a "fetch-when-online, cache-otherwise, versioned bundle" model. The CA industry itself is moving away from always-on-responder models (OCSP) toward CRL-style approaches, reinforcing that an always-reachable revocation check is disfavored even where the infrastructure exists.

## Decision

State revocation-freshness claims precisely, scoped by mode:
- **Local mode (single machine):** the store *is* the cache — `knotrust revoke` deletes the grant and takes effect on the next decision. This is effectively immediate, and KnoTrust may say so, *but only for this mode*.
- **Control-plane mode (Phase 2+):** edges sync signed policy/grant bundles; the honest claim is "revocation propagates within the configured sync interval (default 30s) or on push invalidation when connected" — TTL-bounded, never "instant."
- Decision-cache entries for `sensitive` and `critical` tiers carry short TTLs (≤ 60s), so even a stale-bundle window is bounded regardless of mode.
- All marketing and documentation language about revocation must route through this mode-scoped framing.

## Consequences

- KnoTrust never makes an unqualified "instant revocation" claim, which would not survive technical scrutiny given the structural limits research established.
- Local-mode users get an honest and genuinely strong claim (next-decision revocation), since the store-is-the-cache architecture makes this true without overclaiming.
- Control-plane mode's claim is explicitly TTL-bounded by the sync interval, with graceful degradation back to the local TTL-bound guarantee if an edge stays offline longer than the sync interval.
- The `sensitive`/`critical` short-TTL cache policy is a concrete, load-bearing mechanism (not just a claims-discipline exercise) — it bounds the actual staleness window that any marketing claim describes.

## Alternatives considered

- **Claiming "instant" revocation unconditionally** — rejected: no mechanism beats the TTL bound in pure local mode without new information reaching the verifier; an unqualified claim would misrepresent this structural limit.
- **OCSP-style always-reachable responder checking** — rejected as an architectural approach: assumes an always-reachable responder by design, a poor fit for a zero-backend, local-first product, and disfavored industry-wide (Let's Encrypt, Mozilla CRLite moving away from OCSP).
- **Macaroons/Biscuit caveat-based revocation** — not adopted now: a cheaper local revocation *check* mechanism, but the revoked-ID list's own freshness still reduces to the same CRL/bundle-sync problem: it is flagged as a plausible future grant-format enhancement (caveat-based attenuation), not a way to avoid the connectivity requirement.

## References

- Brief §B2 (full mode-scoped decision text, including the 30s default sync interval and ≤60s tier-specific cache TTLs); PRD §21 (the original open question).
- Research: `docs/01-research/pdp-and-crypto.md` §8 (revocation-freshness pattern comparison and the "honest security claims by mode" table).
