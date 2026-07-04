# ADR-0012: AARP v1 scope is approval-only, behind an internal orchestrator interface

**Status:** Accepted (2026-07-03)

## Context

PRD §21 posed an open question: should AARP v1 scope be approval-only, or the full prerequisite taxonomy (step-up auth, attestations)? AARP ("AuthZEN Access Request and Approval Profile") and COAZ ("Compatible with OpenID AuthZen") are real, publicly-announced (2026-06-15) OpenID Foundation artifacts, but both remain at Working Group Draft status, not Implementer's Draft, as of the brief's date — with an open PR against AARP still actively rewriting it as of 2026-07-02. Notably, the AARP draft's own front matter abbreviates the profile "ARAP," not "AARP" — an inconsistency between the OpenID Foundation's press materials and the spec text itself, worth citing both terms rather than propagating only one uncorrected. The AARP mechanism is termed **Requestable Denial** (`context.access_request`) in the spec — the PRD's own "deny-with-prerequisite" phrasing is not the spec's literal term and should be used only as an explanatory gloss, not as primary terminology. COAZ separately supplies the SARC mapping rule (human principal = `subject`; agent identity = `context.agent`, never merged) and an `x-coaz-mapping` extension on tool `inputSchema` for argument-to-resource mapping.

## Decision

Implement the approval lifecycle (`requested → pending → approved | denied | expired | cancelled`) behind an internal orchestrator interface shaped like AARP's Requestable Denial flow (access request → task handle → status → re-evaluate). Do not implement the full prerequisite taxonomy (step-up auth, attestations) in v1. Wire-format conformance with published AARP drafts is tracked as a compatibility task, not treated as a foundation the architecture depends on. Adopt COAZ's SARC mapping rule (`subject`/`context.agent` split, never merged) and the `x-coaz-mapping` extension now, while keeping the wire format itself behind an adapter as the draft continues to move. Documentation uses the spec's own terms — "Requestable Denial," and both "AARP"/"ARAP" — with PRD phrasing retained only as an explanatory gloss.

## Consequences

- KnoTrust's approval lifecycle is real and usable today, without betting the architecture on a still-churning draft's exact wire format.
- If AARP's wire format changes materially before reaching Implementer's Draft, only the adapter needs updating — the internal orchestrator interface and the decision core (`pending_approval` outcome, approval handle) are insulated from that churn, per the same adapter-isolation invariant applied to MCP RC features (ADR-0006).
- The human-principal/agent-identity split (`subject` vs. `context.agent`, never merged) is load-bearing in the SARC mapping from day one, since retrofitting it later would be a breaking change to the `DecisionRequest` contract.
- The PRD's own §16 enterprise-GA gate ("COAZ/AARP at ≥ Implementer's Draft") is correctly anticipated as currently unmet — this is expected and appropriate for Phases 4–5, not a gap needing a workaround now.
- Docs must use "Requestable Denial" as the primary term, citing both "AARP" and "ARAP" where the spec's own naming inconsistency is relevant, rather than silently picking one.

## Alternatives considered

- **Implementing the full prerequisite taxonomy (step-up auth, attestations) in v1** — rejected: AARP is Draft 1 and actively being rewritten; committing to the full taxonomy now risks building against a wire format that changes before stabilizing.
- **Treating "deny-with-prerequisite" as the primary term** — rejected: this phrase appears in no primary source; the spec's own term is Requestable Denial, and using spec-correct terminology matters for credibility with the AuthZEN working-group audience KnoTrust is trying to court.
- **Waiting for AARP/COAZ to reach Implementer's Draft before building any approval lifecycle** — rejected: would delay the flagship indefinitely against an external, uncontrolled timeline; conflicts with the competitive-speed pressure in brief §C1.

## References

- Brief §B5 (full decision text); §C4 (standards maturity detail: AARP/ARAP naming, COAZ SARC mapping rule, Requestable Denial terminology, PIP/PAP non-normativity); §E2 (`pending_approval` outcome mapping to AARP task handle); §E6 (adapter isolation for external draft standards); PRD §21 (original open question), §16 (spec-maturity gate).
- Research: `docs/01-research/pdp-and-crypto.md` §4.1 (AuthZEN/AARP/COAZ maturity detail, WG co-chairs, interop PDP list).
