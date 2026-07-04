# ADR-0009: Tool annotations seed suggested risk tiers; never a trust decision

**Status:** Accepted (2026-07-03)

## Context

PRD §7 and §12 had proposed seeding risk tiers (`routine`/`sensitive`/`critical`) from MCP tool annotations (`readOnlyHint`/`destructiveHint`/etc.). The MCP spec itself explicitly warns clients never to make trust decisions from annotations on untrusted servers — annotations are advisory metadata, self-declared by the tool/server author, and a malicious or careless server can simply mislabel a destructive tool as read-only. Treating annotations as authoritative would make KnoTrust's own risk-tiering trivially foolable by any server that either lies about its annotations or omits them. (Notably, Codex CLI is one of the only native clients to enforce the `destructiveHint` annotation as a real approval trigger today — a real-world data point that annotations carry some practical weight in the ecosystem already, which is exactly why KnoTrust must be deliberate about the boundary between "useful seed" and "trusted signal" rather than either ignoring or blindly trusting them.)

## Decision

Tool annotations seed *suggested* risk tiers in generated config only. Policy packs and explicit config always override the annotation-derived suggestion. Unknown or unannotated destructive-looking tools default to `sensitive` or higher, never to `routine`. The security documentation states this trust boundary plainly, so integrators understand annotations are a starting point for config generation, not a runtime trust signal.

## Consequences

- KnoTrust's risk-tiering cannot be silently subverted by a server that mislabels its own tool annotations, because annotations never directly drive a live enforcement decision — only the one-time generation of a suggested config that a human or policy pack can then override.
- The preset-pack registry becomes more strategic, not less: because annotations alone are not trustworthy, community-curated, reviewed preset packs (per-server risk-tier presets, signed and content-hashed — see the tech-stack document's config/packs section) become the credible source of accurate tiering, not raw server self-declaration.
- Unknown/unannotated tools defaulting to `sensitive`-or-higher is a fail-closed-by-default posture applied specifically to the tiering-seed step, consistent with the broader fail-closed architecture invariant.
- Documentation must state the annotation trust boundary explicitly and cannot imply annotations are verified or authoritative.

## Alternatives considered

- **Trusting annotations directly as the live risk-tier signal** (the PRD §7/§12 original framing) — rejected: directly contradicts the MCP spec's own guidance that clients must not make trust decisions from annotations on untrusted servers; would make KnoTrust's core security mechanism foolable by tool-poisoning or careless annotation.
- **Ignoring annotations entirely** — not adopted: annotations remain useful as a low-cost seed for generating a starting config (faster onboarding), as long as they are never load-bearing for a live decision.

## References

- Brief §C5 (full decision text: "annotations seed *suggested* tiers in generated config; policy packs and explicit config override; unknown/unannotated destructive-looking tools default to `sensitive` or higher; the security docs state the trust boundary plainly... This makes the preset-pack registry *more* strategic, not less"); PRD §7, §12 (the amended original framing).
