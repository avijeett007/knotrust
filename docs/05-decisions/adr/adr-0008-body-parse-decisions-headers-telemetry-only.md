# ADR-0008: Every allow/deny decision parses the JSON-RPC body; headers are routing/telemetry only

**Status:** Accepted (2026-07-03)

## Context

PRD §9 and §13 had proposed a "header-routed fast path" using MCP's `Mcp-Method`/`Mcp-Name` headers (SEP-2243) to achieve a sub-millisecond common case by evaluating policy from headers alone, avoiding a body parse. Research established two facts that make this unsafe as a security decision mechanism: (a) these headers do not exist at all in the current stable 2025-11-25 spec — they are only real in the 2026-07-28 RC; and (b) the SEP itself explicitly forbids intermediaries from treating headers as trusted for security-sensitive decisions, requiring servers to reject any header/body mismatch. Building the actual allow/deny gate on an input the spec itself says must not be trusted for this purpose would be a foundational security defect, not a performance optimization.

## Decision

Every allow/deny decision parses the JSON-RPC body. Headers (`Mcp-Method`/`Mcp-Name`, once available in 2026-07-28) are a routing/telemetry optimization only — they may be used to route traffic or annotate observability data, but never as an input to a policy decision. The "sub-ms common case" the PRD wanted is instead achieved via the local decision cache (part of `@knotrust/core`), not via header-only evaluation.

## Consequences

- KnoTrust's enforcement gate cannot be fooled or bypassed by a header/body mismatch, because headers never carry decision weight.
- The PRD §9 transport-strategy sentence describing header-routed fast-path evaluation is amended: fast-path latency comes from caching, not from skipping the body parse.
- This decision is spec-version-independent: it holds whether KnoTrust is running against 2025-11-25 (where the headers don't exist yet) or 2026-07-28 (where they exist but are untrusted for this purpose) — see ADR-0006.
- Any future transport or spec revision that introduces new routing metadata must be evaluated against the same rule: metadata may route or annotate, but the decision core only ever sees the parsed body via the `DecisionRequest` contract.
- Headers remain legitimately useful for non-decisional purposes — e.g., routing a call to the correct adapter/tenant shard, or tagging telemetry/observability events — this decision restricts them from decision *logic* specifically, not from all use in the proxy.

## Alternatives considered

- **Header-only fast-path evaluation** (the PRD §9/§13 original proposal) — rejected outright: forbidden by the SEP's own trust model for security-sensitive decisions, and unavailable at all in the spec version the flagship ships against.
- **Hybrid: headers as a first-pass filter, body as confirmation** — not adopted as a formal mechanism; the decision as ratified treats headers as strictly non-decisional (routing/telemetry), not as even a provisional filter, to avoid a partial-trust model that could regress into a shortcut over time.

## References

- Brief §C2 (full rationale: SEP-2243 real only in 2026-07-28 RC, SEP forbids trusting headers for security-sensitive decisions, servers MUST reject header/body mismatches; "every allow/deny decision parses the JSON-RPC body. Headers are a routing/telemetry optimization only"); PRD §9, §13 (the amended original claim).
