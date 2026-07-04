# ADR-0017: RFC 3339 timestamp profile for contract/schema timestamps

**Status:** Accepted (2026-07-03)

## Context

`packages/core/src/contract.ts` and its language-neutral mirrors at
`golden-vectors/schemas/decision-request.v1.schema.json` and
`golden-vectors/schemas/decision.v1.schema.json` (P0-E2-T1) carry four
timestamp fields: `DecisionRequest.timestamp`, `DecisionContext.env.time`,
`UntrustedToolAnnotations.capturedAt`, and `ApprovalHandleRef.expiresAt`. The
TS doc-comments on all four said "ISO-8601" while the JSON Schemas asserted
`format: "date-time"` — which ajv (via `ajv-formats`, already wired in
`packages/core/src/contract.test.ts`) validates against **RFC 3339**, not the
full breadth of ISO 8601. ISO 8601 permits offset-less local date-times
(`2026-07-03T14:32:10`), week-dates, ordinal dates, and reduced precision;
RFC 3339 is a strict profile of it that always carries a UTC offset (`Z` or
`±hh:mm`) and forbids the rest. The doc-comment and the schema's `format`
keyword were describing two different things without saying so.

Every timestamp this system actually generates is produced via
`new Date().toISOString()`, whose output (`...Z` suffix) is already valid
RFC 3339. Nothing in the codebase, the architecture doc's worked examples
(§2), or the planned Python port emits offset-less ISO 8601. The mismatch was
purely a labeling gap, not a behavior gap — but for an audit/security
product, an ambiguous or offset-less timestamp in a `DecisionRequest`,
`context.env.time`, a tool-annotation capture time, or an approval
`expiresAt` deadline is a real correctness hazard: a hash-chained audit log
(ADR-0005) and a revocation/expiry check (§5.6) that don't have an
unambiguous instant to reason about can silently misorder or miscompute
against local-time or offset-less input.

## Decision

Contract/schema timestamps are **RFC 3339-profiled** — a strict subset of
ISO 8601 that always includes a UTC offset. This is a labeling fix, not a
behavior change:

- The JSON Schemas keep `format: "date-time"` (already correct; ajv-formats
  already asserts RFC 3339 date-time, not bare ISO 8601, so no schema
  behavior changes).
- The four TS doc-comments in `packages/core/src/contract.ts` (and their
  mirrors in `docs/02-architecture/system-architecture.md` §2/§3) are
  corrected from "ISO-8601" to "RFC 3339 (profiled subset of ISO 8601,
  ADR-0017)".
- Validators in **every** language MUST assert the `date-time` format, not
  just accept the `type: "string"` shape:
  - TypeScript: `ajv-formats` is already wired into
    `packages/core/src/contract.test.ts`'s ajv instance and MUST stay wired.
  - The Phase-3 Python port MUST wire an explicit format checker.
    `python-jsonschema` does **not** assert `format` keywords by default
    (`FormatChecker` must be constructed and passed explicitly, or format
    validation is silently skipped) — this is exactly the kind of
    silent-divergence trap this ADR exists to close before a second-language
    port can fall into it.
- `golden-vectors/` will include a negative timestamp vector — a timestamp
  that is valid ISO 8601 but not valid RFC 3339 (no UTC offset) — so that any
  validator in any language that fails to assert `format: date-time` fails
  the shared golden-vector suite instead of silently accepting the input.
  `packages/core/src/contract.test.ts` carries the first instance of this
  fixture for the TypeScript side.
- Both schema files carry a top-level `$comment` stating the profile and the
  validator obligation, so a reader of the schema alone (without this ADR)
  still gets the rule.

## Consequences

- No runtime behavior changes: every timestamp already produced by the
  system (`toISOString()`) was already RFC 3339-valid and continues to
  validate.
- Any future validator implementation (a new language port, a new tool that
  consumes `golden-vectors/schemas/`) is on notice, both in the schema
  `$comment` and in this ADR, that accepting the bare `string` type without
  asserting `format: date-time` is a compliance gap, not a style choice.
- The Phase-3 Python port's schema-validation setup has an explicit,
  pre-recorded requirement (wire a `FormatChecker`) instead of discovering
  the `python-jsonschema` default-off behavior the hard way after vectors
  start silently passing malformed timestamps.
- The negative timestamp golden vector becomes a permanent regression guard:
  any validator, in any language, that stops asserting `format` will fail
  the suite immediately rather than degrading silently.

## Alternatives considered

- **Loosen the schema to plain `string`, mirroring the TS doc-comment
  exactly** — rejected: this widens the accepted input to admit ambiguous,
  offset-less, or otherwise under-specified timestamps into audit-relevant
  records (`DecisionRequest`, the hash-chained audit log, approval
  `expiresAt` deadlines) purely to match a doc-comment that was itself
  imprecise. The schema was right; the comment was wrong.
- **Accept full ISO 8601 breadth** (implement or select a validator that
  accepts week-dates, ordinal dates, reduced precision, and offset-less
  local time) — rejected: no generator in this system, nor any planned
  client, ever produces those forms; supporting them buys nothing and adds
  interoperability risk (an offset-less timestamp from one component being
  silently misinterpreted as another component's local time by another).

## References

- Task brief P0-E2-T1, orchestrator ruling (Important): keep
  `format: date-time`, make the RFC 3339 narrowing explicit rather than
  loosen the schema or leave the doc-comments mismatched.
- `packages/core/src/contract.ts` — the four corrected doc-comments.
- `golden-vectors/schemas/decision-request.v1.schema.json` /
  `golden-vectors/schemas/decision.v1.schema.json` — the `format: date-time`
  assertions and the new top-level `$comment`.
- `packages/core/src/contract.test.ts` — the negative RFC 3339 round-trip
  fixture proving a non-asserting validator would fail the suite.
- ADR-0005 (`docs/05-decisions/adr/adr-0005-file-stores-jsonl-hashchain-audit.md`)
  — the hash-chained audit log this timestamp precision protects.
- `docs/02-architecture/system-architecture.md` §5.6 — revocation/expiry
  semantics that depend on unambiguous instants.
