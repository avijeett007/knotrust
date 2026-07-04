# ADR-0006: Baseline on MCP 2025-11-25, isolate 2026-07-28 behind a SpecAdapter

**Status:** Accepted (2026-07-03)

## Context

The MCP 2026-07-28 spec revision is a real Release Candidate, locked 2026-05-21: sessions are removed, and `requestState`-based Multi Round-Trip Requests (SEP-2322, Final) enable stateless resumption — exactly the mechanism the PRD hoped to use for encoding pending-approval handles. But it is not yet the spec in production use, finalizing roughly 3.5 weeks after this brief's date. Separately, SEP-2243's `Mcp-Method`/`Mcp-Name` headers do not exist in the current stable spec, and the SEP itself forbids intermediaries from treating headers as trusted for security-sensitive decisions (servers MUST reject header/body mismatches) — ruling out a header-only fast path for allow/deny decisions regardless of which spec version is targeted (see ADR-0008). Competitive pressure (brief §C1) makes shipping the flagship demo sooner a live strategic input, so the flagship cannot wait for RC finalization.

## Decision

Build on the official `@modelcontextprotocol/sdk` (1.x). Ship the stdio flagship on the stable **2025-11-25** spec. Isolate all 2026-07-28-specific adaptations (statelessness, `requestState` resumption, header routing) behind an internal `SpecAdapter`/transport interface, so the RC's eventual finalization is absorbed without decision-core rework. The HTTP-proxy spike (Phase 0, per PRD) tracks the 2026-07-28 RC in parallel but does not gate the stdio flagship's ship date.

## Consequences

- The flagship demo ships on stable, production-proven spec semantics, not against a still-finalizing RC.
- When 2026-07-28 finalizes, the `SpecAdapter` boundary is what absorbs the change — this operationalizes the PRD's own §12 isolation requirement as a concrete architectural boundary rather than an aspiration.
- `pending_approval`'s approval handle is designed from the start to encode into `requestState` on stateless HTTP, so the decision core does not need to be redesigned when the HTTP proxy adopts the finalized spec.
- Every external draft standard or RC feature (MCP RC features here; AARP/COAZ wire formats in ADR-0012) sits behind an adapter with a conformance-tracking note — this is a repeated architecture invariant, not unique to MCP.
- Docs and implementation must re-verify the 2026-07-28 spec's *final* (not RC) content against `modelcontextprotocol.io` before treating any RC-specific feature as settled, since finalization occurs after this brief's date.

## Alternatives considered

- **Building directly against the 2026-07-28 RC for the flagship** — implicitly rejected by the sequencing decision: the RC "doesn't gate" the stdio flagship, which ships on 2025-11-25 semantics instead, precisely so competitive speed-to-flagship is not held hostage to RC finalization timing.
- **Header-routed fast-path evaluation** (deciding allow/deny from `Mcp-Method`/`Mcp-Name` headers alone) — rejected regardless of spec version targeted; see ADR-0008 for the full rationale (headers are routing/telemetry only, never a decision input).

## References

- Brief §D (MCP layer row); §C2 (header-routing re-scope, SEP-2243 detail); §F (sequencing: "HTTP-proxy spike... tracks the RC but doesn't gate the stdio flagship, which ships on 2025-11-25 semantics"); §E6 (adapters for every external draft standard).
- Research: `docs/01-research/competitive-and-packaging.md` §5.1 (2026-07-28 spec content verification, tool-annotation advisory-only language).
