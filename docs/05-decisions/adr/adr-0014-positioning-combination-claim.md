# ADR-0014: Positioning rests on the combination claim, not category novelty

**Status:** Accepted (2026-07-03)

## Context

PRD §5 claimed "no portable, standards-based, cross-agent layer exists" for action-level governance. Competitive research found this literal claim will not survive scrutiny in mid-2026: Microsoft's Agent Governance Toolkit (OSS, MIT, shipped, cross-framework, MCP-aware, policy + trust-scoring + quorum approval + audit), Runlayer ($42M raised, commercial cross-client governance), Preloop (Apache-2.0 config-rewrite proxy across 9 clients, CEL policies), Peta (approval console across 4 clients), and IBM's mcp-context-forge (approval workflows at scale, 160K+ users via IBM Consulting Advantage despite community/beta labeling) all exist and converge on close variants of this niche today. None of these, however, combines all of: true cross-agent portability, enforcement that survives YOLO/auto-approve mode via more than a routing/config-rewrite trick, AuthZEN-standards conformance with signed durable grants, and local-first zero-backend OSS distribution — each has at most two of these four properties. The standards body itself (AuthZEN/AARP/COAZ) is independently converging on the primitives KnoTrust needs, with no reference implementation yet shipped by anyone, which is real but time-boxed whitespace rather than a permanent moat.

## Decision

Retire the "no portable layer exists" claim. The external positioning claim becomes the **combination**: cross-agent portable + YOLO-proof at the protocol seam (not a config/routing trick) + AuthZEN-standards-conformant with signed durable grants + local-first zero-backend OSS. No competitor has all four simultaneously; each competitor surveyed has at most two. All external messaging derives from this combination claim, not from a claim of category exclusivity. As a consequence, risk R6 (vendor/competitor absorption) is upgraded from "accepted risk" to "active competitive pressure — product-level, not spec-level," and speed-to-flagship becomes a strategy input on par with the PRD's own "own the niche fast" framing.

## Consequences

- Marketing and docs must never imply KnoTrust is alone in this space; the defensible claim is always the four-property combination, argued on specifics (depth of native MCP/elicitation integration; standards-conformance vs. proprietary policy models; local-first/zero-backend/Apache-2.0 openness vs. enterprise-only or unsupported-beta competitor models; and a genuine architectural argument for surviving YOLO mode vs. approximated-via-routing-tricks).
- Microsoft's Agent Governance Toolkit is treated as the primary tracked competitor — the closest full-stack match to KnoTrust's target feature set — warranting recurring (quarterly) monitoring of its repo activity, any foundation-donation status change, and any pivot from self-hosted toolkit toward a managed/portable product.
- The claims-discipline table (PRD §3/§4) needs an explicit "don't claim we're the only ones" entry, since the absolute uniqueness claim is now known to fail under a single technical reader's search.
- Because the standards-conformance door (AuthZEN/SARC-conformant *and* full human-approval-lifecycle product with signed durable grants) is real but time-boxed — several well-capitalized players (Okta, Cerbos, Axiomatics, SailPoint, Keycard, plus Runlayer and Microsoft) could walk through it once the standard matures — shipping the flagship sooner is a competitive necessity, not just a nice-to-have.
- This decision does not change any technical architecture — it changes only the external claim and the internal urgency/prioritization signal derived from it.

## Alternatives considered

- **Retaining the "no portable layer exists" claim as-is** — rejected: directly falsifiable by a single search turning up Runlayer's funding or Microsoft's Agent Governance Toolkit; would invite teardown by the exact technical audience KnoTrust is courting.
- **Downplaying R6 as a low-priority accepted risk** — rejected: research reclassifies it as active, product-level competitive pressure today (not a hypothetical future vendor-absorption scenario), which changes prioritization even though it changes no architecture.
- **Competing on category novelty alone ("first mover")** — rejected in favor of competing on the specific four-property combination, since novelty alone is not a defensible or durable claim given the crowded adjacent-competitor landscape research surfaced.

## References

- Brief §C1 (full decision text, competitor list, four-property combination framing, R6 upgrade); §A (verdict acknowledging "the niche is no longer empty"); PRD §5 (the original claim), §20-R6 (the original risk framing).
- Research: `docs/01-research/competitive-and-packaging.md` §0 (headline finding), §2 (master competitor table), §3 (whitespace/differentiation — the four-property analysis), §5 (absorption-risk read, Microsoft Agent Governance Toolkit detail), §8 (implications for positioning & build plan).
