# ADR-0004: Ed25519 signatures in JWS Compact Serialization for grants

**Status:** Accepted (2026-07-03)

## Context

Authorization grants (PRD §7: `{principal, agent, tool, resource scope, conditions, risk tier, granted_by, expiry, single_use}`) must be signed so that policy and grants stay out-of-band from agent reasoning (PRD §13) and are offline-verifiable in a zero-backend, local-first product. The signing scheme and serialization format need mature tooling on both the TypeScript side (now) and the Python side (Phase 3), with no canonicalization ambiguity and no native-binary complications for an `npx`-distributed CLI. Research compared JWS, COSE (CBOR-based, RFC 9052), and a custom compact binary format, and compared `@noble/curves`, libsodium, native WebCrypto, and `jose` for the signing layer itself.

## Decision

Sign grants with Ed25519, using `@noble/curves`'s Ed25519 module on the TypeScript/browser side and Python's `cryptography` library (`Ed25519PrivateKey`/`Ed25519PublicKey`) on the Python side. Serialize as JWS Compact Serialization with `alg: EdDSA`, using short claim names to control size. Golden cross-language test vectors (grant JWS + decision fixtures) are established from Phase 0 to anchor parity between the two languages.

## Consequences

- Grants are offline-verifiable with no dependency on a reachable issuer at verification time.
- `@noble/curves` is pure JS/TS with no WASM or native-binary step, avoiding a native-dependency risk in the `npx` install/build matrix; it is independently audited (Trail of Bits 2023, Kudelski 2023, Cure53 August 2024), unlike the narrower `@noble/ed25519` package's un-audited v2/v3 rewrite.
- JWS signs the base64url string directly rather than re-parsed JSON, so there is no canonicalization ambiguity in practice, and the format gets a mature, ubiquitous cross-language ecosystem (`jose`, `PyJWT`/`Authlib`) essentially for free, while staying human-debuggable via jwt.io.
- The cost is accepted deliberately: roughly 33% base64 expansion plus JSON key verbosity, mitigated by short claim names, rather than paying a three-language codec-maintenance tax for a leaner format now.
- Native WebCrypto Ed25519 remains an optional future fast-path (stable in Node ≥ 22.13.0 per ADR-0001) but is not the default today, since universal browser support only arrived in May 2025 (Chrome/Edge was the last holdout) — too recent to be the sole path for the browser-based approval app.

## Alternatives considered

- **COSE (RFC 9052, CBOR-based)** — rejected for now: more compact and the format WebAuthn/mdoc use, but dedicated JS COSE *envelope* libraries are thin and stale (`cose-js` last touched 2023, `@auth0/cose` April 2024); would require hand-rolling the COSE envelope on otherwise-healthy CBOR codecs. Reserved as a later size optimization only if measured grant size becomes an actual problem (e.g., URL-embedding in MCP's URL-mode elicitation, or QR-code offline transfer).
- **Custom compact binary format** (fixed struct + raw 64-byte Ed25519 signature) — rejected for the same reason: smallest option, avoids canonicalization questions by construction (precedent: Solana's compact transaction structs, WireGuard's fixed binary handshake), but requires a hand-written codec maintained in sync across TS, browser JS, and Python.
- **libsodium** — not chosen over `@noble/curves`: requires WASM via Emscripten with async `sodium.ready` initialization, versus `@noble/curves`'s pure-JS, no-init-step profile, for comparable audit credibility.

## References

- Brief §D (Grant signing row); §G ("custom binary grant format / COSE (deferred: JWS tooling maturity wins now)").
- Research: `docs/01-research/pdp-and-crypto.md` §7.1 (signature scheme comparison), §7.2 (serialization recommendation).
