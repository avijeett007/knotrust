# ADR-0005: File-based local stores — JWS grant files and hash-chained JSONL audit

**Status:** Accepted (2026-07-03)

## Context

KnoTrust's local mode is zero-backend: the store *is* the cache (brief §B2), and Phase 0–1 must have zero native dependencies in the `npx` install path to keep cold-start reliable across platforms. The audit trail must record every decision — including denials and cache hits, not just executions (brief §E5) — and be tamper-evident and exportable, without requiring a database engine on day one. A later escalation path is needed for when query needs (e.g., ad hoc audit queries) outgrow simple file streaming.

## Decision

Store signed grants as JWS files in `~/.knotrust/grants/`. Store the audit trail as an append-only JSONL file with hash chaining, queryable via a `knotrust audit` CLI command. Add a SQLite index later — using `node:sqlite` (ships with Node, no native dependency) rather than `better-sqlite3` — only once query needs genuinely outgrow streaming.

## Consequences

- Zero native dependencies exist anywhere in the default `npx` install/runtime path, preserving install-matrix simplicity and cold-start reliability.
- The audit trail is tamper-evident-lite from day one via hash chaining, without needing a database engine.
- Every decision — allow, deny, `pending_approval`, `deferred_not_eligible`, and cache hits — must append an audit event; this is an architecture invariant, not an optional feature.
- The audit trail is exportable via OpenTelemetry (see the tech-stack document's audit-export section) independent of how it is stored locally.
- If/when a SQLite index is added, `node:sqlite` is the default choice specifically because it introduces no native dependency, preserving the same npx-path guarantee that ruled out `better-sqlite3` initially.

## Alternatives considered

- **`better-sqlite3` from day one** — rejected for v1: it is a native module, reintroducing exactly the native-dependency risk the `npx` path is designed to avoid. Deferred to a later point where `node:sqlite` alone may no longer suffice for query needs.
- **A database engine as the primary store from day one** — rejected: unnecessary complexity and dependency weight for what Phase 0–1 needs; JSONL with hash chaining is sufficient and simpler to audit itself (the audit format being human-readable is a feature for a security tool).

## References

- Brief §D (Local store row: "Files: signed grants as JWS in `~/.knotrust/grants/`; audit as append-only JSONL with hash chaining; `knotrust audit` CLI for querying; SQLite index later (`node:sqlite`, no native deps) only when query needs outgrow streaming"); §E5 (audit records attempts, not just executions); §G ("better-sqlite3 (rejected v1: native-dep risk in npx flows)").
