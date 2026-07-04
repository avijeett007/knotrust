# KnoTrust — Tech Stack

**Status:** Ratified (derived mechanically from `docs/05-decisions/2026-07-03-decisions-brief.md` §D, §G; owner countersign per brief §H)
**Date:** 2026-07-03
**Scope:** This document expands the brief's ratified stack table into full rationale, alternatives-rejected, maturity/license notes, and risk/watch-items, per layer. It is not a new decision surface — where this document and the brief disagree, the brief wins.

---

## 1. Runtime & language

**Choice:** TypeScript, Node ≥ 22 (LTS).

**Why:** MCP's own SDK ecosystem is overwhelmingly TypeScript/Node-first, so building KnoTrust in the same language keeps the core, CLI, and proxies in one toolchain with no FFI or cross-process boundary between "the thing that speaks MCP" and "the thing that evaluates policy." Node 20 reaches end-of-life in April 2026, so a Node ≥ 22 floor is simply choosing the currently-supported LTS rather than shipping against a line already sunsetting. Node ≥ 22 also has a concrete technical payoff for the crypto layer: WebCrypto `SubtleCrypto` Ed25519 support is stable from Node v22.13.0, giving KnoTrust an optional native fast-path later without raising the floor again. A Python SDK is explicitly deferred to Phase 3, so the runtime choice does not block the multi-language future — it is additive.

**Alternatives considered & why rejected:**
- **Bun/Deno single-binary distribution** — rejected for v1. The `npx`-first distribution path and guaranteed compatibility with the official `@modelcontextprotocol/sdk` outweigh Bun/Deno's faster cold-start and single-binary story today. Revisit specifically for the F1 desktop app, where a compiled binary matters more than `npx` ergonomics (brief §G).

**Maturity/license notes:** Node.js is an OpenJS Foundation project; no license risk. TypeScript is Microsoft-stewarded, Apache-2.0 (well, MIT for the compiler) — mature, no concerns.

**Risk/watch-item:** None material. Node LTS cadence is a routine, well-understood upgrade path, not a project risk.

---

## 2. Package / distribution shape

**Choice:** Single `knotrust` npm package (a CLI with subcommands); internal workspace libraries are bundled in rather than published as separate installable packages.

**Why:** The flagship experience is `npx knotrust -- your-server` working with zero prior install and zero config — that only holds if there is exactly one package name to type. This mirrors the proven shape of `supergateway` and `mcp-remote` in the same MCP ecosystem: one package, mode selected by subcommand/flag (`knotrust`, `knotrust init`, `knotrust add pack <x>`, `knotrust -- <server>`), rather than a constellation of `@knotrust/cli`, `@knotrust/proxy`, `@knotrust/core` packages a first-time user has to reason about. Avoiding package sprawl also keeps the actual lever on `npx` cold-start latency — the dependency tree an uncached `npx` run has to fetch and install — as small as possible.

**Alternatives considered & why rejected:**
- **Split CLI/proxy/core into separately-installable packages** — rejected: no closest comparable in the MCP ecosystem (`mcp-remote`, `supergateway`, `smithery`) ships this way, and it adds a discovery/install-order burden with no offsetting benefit at this stage. Internal workspace boundaries (see §3, §4) still exist for engineering reasons — they are just not separately published.
- **Compiled single-binary distribution (Bun `--compile`, Node SEA, `@yao-pkg/pkg`)** — rejected for now: no current comparable ships this way either. If an offline/no-Node installer is ever demanded by an enterprise customer, Bun `--compile` is the pragmatic choice (confirmed cross-compile matrix from one CI job: linux x64/arm64 + musl, windows x64/arm64, darwin x64/arm64) over Node's SEA (cannot cross-compile, must build per-target) or `@yao-pkg/pkg` (useful mainly if bytecode obfuscation specifically matters).

**Maturity/license notes:** Not applicable (packaging pattern, not a dependency).

**Risk/watch-item:** npm is expected to disable install-lifecycle scripts by default in npm v12 (~mid-2026, a response to supply-chain-worm incidents). KnoTrust's packaging plan must not grow a dependency on a `postinstall` step; lean on `optionalDependencies` resolution alone if/when platform-specific binaries are ever needed (e.g., for a future compiled distribution).

---

## 3. Monorepo & release tooling

**Choice:** pnpm workspaces + Turborepo for the monorepo; release-please + npm/PyPI OIDC trusted publishing for releases.

**Why:** pnpm workspaces + Turborepo is the standard, fast combination for a multi-package TypeScript monorepo and is "80% of the value for 20% of the complexity" relative to Nx at KnoTrust's current package count (core, CLI, HTTP proxy, TS SDK, plus a future Python directory). Turborepo's Remote Cache is now free on all plans, removing what used to be the main cost objection to it versus self-hosting. release-please is chosen over Changesets specifically because of the planned Python SDK (Phase 3): release-please ships native, first-class multi-language manifest support (Python `pyproject.toml`/`setup.py` alongside Java/Ruby/PHP/Go/Rust), so a Python version bump is a first-class citizen from day one rather than a hand-rolled sync layer bolted onto Changesets. Provenance and attestation (via OIDC trusted publishing on both npm and PyPI, no stored long-lived tokens) matter disproportionately for a security tool whose entire pitch depends on supply-chain trust.

**Alternatives considered & why rejected:**
- **Nx** — rejected for now: its differentiators (codegen, module-boundary enforcement, deep polyglot build orchestration) are overkill at a 4-package count; revisit only if package count or team size grows substantially, or genuine polyglot *build* (not just versioning) orchestration becomes necessary.
- **Changesets** — rejected in favor of release-please specifically because of the Python future: Changesets would require a hand-rolled custom-sync layer to cover Python (a documented pain point in the one polyglot-Changesets case researched). Changesets' real advantage — richer, contributor-authored changelogs — matters more for projects whose primary audience reads detailed hand-written release notes, which is secondary here to the multi-language requirement.
- **A single dual-publish recipe** — none exists off-the-shelf; expect to hand-write the glue coordinating two independent OIDC-authenticated jobs (npm, PyPI) off one release-please manifest run.
- **Poetry (Python side)** — implicitly superseded by `uv`, the converging 2025–2026 default (10–100x faster than pip, ~10x faster than Poetry on cold installs), with `uv build`/`uv publish` closing Poetry's former publishing-workflow advantage. The Python SDK's version number is deliberately allowed to drift from the TS packages' version number (per the DeepEval dual-language-monorepo precedent) — lockstep versioning across ecosystems is treated as artificial coupling, not a virtue.

**Maturity/license notes:** pnpm, Turborepo, release-please are all OSS and actively maintained (Turborepo is Vercel-stewarded; release-please is a `googleapis` project). No license concerns — all permissive.

**Risk/watch-item:** No single blessed "dual npm+PyPI OIDC publish" recipe exists yet in current tooling; this glue must be hand-written and will need to be revisited if either registry's trusted-publishing requirements change.

---

## 4. MCP layer & spec strategy

**Choice:** Official `@modelcontextprotocol/sdk` (1.x); baseline the stable **2025-11-25** spec, with 2026-07-28 adaptations absorbed behind an internal `SpecAdapter`/transport interface.

**Why:** The 2026-07-28 revision is a real Release Candidate (locked 2026-05-21) — sessions removed, `requestState` multi-round-trip resumption (SEP-2322, Final) — but it is not yet the spec production traffic runs on, and the flagship stdio demo does not need it: it ships on 2025-11-25 semantics and the HTTP-proxy spike tracks the RC in parallel without gating the flagship (brief §F). Isolating both the current and the incoming spec behind an internal adapter interface means the RC's eventual finalization is absorbed without a rework of the decision core — this operationalizes the PRD's own surface-isolation requirement (§12) rather than merely hoping for it.

**Alternatives considered & why rejected:** None recorded as seriously contended — using the official SDK, on the current stable spec, is the only option consistent with "ship the flagship now, absorb the RC later" (brief §F). The alternative of building directly against the 2026-07-28 RC was implicitly rejected by the sequencing decision in brief §F ("doesn't gate the stdio flagship").

**Maturity/license notes:** `@modelcontextprotocol/sdk` is the reference implementation maintained by the MCP project (now under the Agentic AI Foundation / Linux Foundation umbrella per PRD §5), Apache-licensed, actively released.

**Risk/watch-item:** The 2026-07-28 spec finalizes roughly 3.5 weeks after the brief's date — re-verify its final (not RC) content against `modelcontextprotocol.io` before treating any 2026-07-28-specific feature as load-bearing in shipped docs or code (see §11 re-verify list below).

---

## 5. Decision core

**Choice:** Pure TypeScript `@knotrust/core` package: a versioned internal **DecisionRequest contract** (SARC + surface metadata), tier evaluator, grant verifier, precedence engine, and decision cache.

**Why:** This is the direct enforcement mechanism for the PRD's surface-agnostic principle (§8): MCP specifics must never leak into the core, or the future client-native-hooks (F2) and OS-sandbox-broker (F3) surfaces would require core rework instead of just a new adapter feeding the same `DecisionRequest` contract. The brief promotes this from a stated principle to an architecture invariant (§E1): the MCP adapter is "surface #1," and other surfaces must be provably implementable without core changes — checked in review, not assumed. The four decision outcomes (`allow | deny | pending_approval | deferred_not_eligible`) live here, with `pending_approval` carrying an approval handle that maps to AARP's task handle and encodes into `requestState` on stateless HTTP (brief §E2).

**Alternatives considered & why rejected:** No alternative architecture is recorded — this is a foundational invariant carried forward from the PRD (§8) and hardened by the brief (§E), not a build-vs-buy choice with rejected options.

**Maturity/license notes:** In-house code; no external dependency risk. Golden cross-language test vectors (grant JWS + decision fixtures) are added as a Phase 0 deliverable specifically to anchor this core against future refactors and the eventual Python port (brief §F).

**Risk/watch-item:** None beyond ordinary engineering discipline — the invariant is only as good as review enforcement of it (brief §E1 explicitly says this is "checked in review, not assumed").

---

## 6. PDP layers & adapters (L0 / Cedar-WASM / AuthZEN-HTTP / OPA)

**Choice:** Layered PDP — **L0** built-in evaluator (the true zero-config default) · **L1** `@cedar-policy/cedar-wasm` opt-in (installed lazily via `knotrust add pdp cedar`, not bundled) · **generic AuthZEN HTTP adapter** (any AuthZEN-interop PDP: Cerbos, Topaz, PlainID, SGNL, …) · **OPA REST adapter** (SARC→Rego `input` translation against a running `opa run --server`).

**Why (L0):** A small, dependency-free TypeScript evaluator over KnoTrust's native primitives (risk tiers, signed grants, precedence rules) is what `npx knotrust` runs with zero added bytes and zero external-project risk on the very first run — matching the "zero-backend, npx-and-go" pitch exactly and giving KnoTrust full control over its own correctness with no exposure to any external project's release cadence. It is explicitly not a general policy language and is never marketed as one (brief §B1).

**Why (Cedar-WASM, opt-in not bundled):** `@cedar-policy/cedar-wasm` is the official, Node-targeted, actively-released (v4.11.2, 2026-06-23) Apache-2.0 package, and Cedar's request model (PARC — principal/action/resource/context) is a near-exact structural match for the AuthZEN SARC model KnoTrust already speaks. Cedar is also formally verified: AWS maintains parallel Lean proofs of the evaluator/authorizer/validator, cross-checked against the production Rust implementation by differential testing on every release — a genuine differentiator for a security-relevant proxy. The reason it is *not* bundled by default is concrete and measured: the WASM binary is ~4.27 MB uncompressed, which would materially betray the "npx and go" pitch as a one-time install cost on every first run, even though it costs nothing per-invocation once installed. It is recommended as the path once users write real policies, and it stays lazy-installed via `knotrust add pdp cedar`.

**Why (generic AuthZEN HTTP adapter):** AuthZEN Authorization API 1.0 being Final (OIDF vote, 2026-01-12) means one adapter speaking the AuthZEN wire format works against the entire interop list (Cerbos, Topaz/Aserto, PlainID, SGNL, and others) — this single adapter is what makes the "PDP-agnostic" claim real rather than aspirational. Cerbos specifically gets a named quickstart on top of this generic adapter because it has a first-class `/access/v1/evaluation` endpoint and its co-founder co-chairs the AuthZEN working group.

**Why (OPA REST adapter, not embedded):** OPA/Styra explicitly declined native AuthZEN support, so KnoTrust's adapter does SARC→Rego `input`-document translation itself over OPA's REST API — the docs must never claim "OPA speaks AuthZEN." OPA is treated as an external adapter rather than an embedded option because its own Node/WASM path (`@open-policy-agent/opa-wasm`) is explicitly OPA's least-invested integration surface: the README self-describes as "Work in Progress," the last release was November 2024 despite later source commits, and Go embedding — not Node/WASM — is OPA's flagship target. Talking to a daemon a user already runs (`opa run --server`) meets enterprises where they already are without KnoTrust re-implementing an under-maintained path.

**Positioning note (brief §B1, carried forward verbatim in spirit):** KnoTrust *fronts* PDPs; the PDP interface is the architectural boundary, not any one engine. Cedar being embeddable is an implementation detail of one adapter (L1); OPA and Cerbos being remote is a detail of others. The external claim stays "enforcement + approval layer, PDP-agnostic" — docs must say exactly this and never let embedding Cedar read as "KnoTrust is a policy engine."

**Alternatives considered & why rejected:**
- **Bundling Cedar-WASM in the default install** — rejected: ~4.3 MB directly contradicts "npx and go" minimalism; shipped instead as a lazy opt-in.
- **Casbin as the L0/bundled default** — rejected: it is architecturally the strongest genuinely-embeddable, zero-daemon, pure-TS alternative surveyed, but it has zero AuthZEN alignment and no interop presence, so adopting it would require building and maintaining a custom SARC-translation shim for an engine with no standards pull. The hand-rolled L0 evaluator plus Cedar-WASM already covers the embeddable-default need without that translation tax.
- **Oso (Polar)** — rejected outright from consideration: the OSS library has been frozen/bug-fixes-only since December 2023, stalled at v0.27.3; the company's surviving product (Oso Cloud) is a different, hosted, non-AuthZEN, proprietary offering. Continuing to name Oso alongside Cedar/OPA/Cerbos in KnoTrust's own comparative docs is flagged as stale positioning (research open question, unresolved — see final report).
- **Cerbos or OpenFGA as an embedded/bundled option** — rejected: both are client-only architectures (Cerbos's embedded mode requires the commercial Cerbos Hub; OpenFGA's engine embeds only in Go), so both are adapter-only by construction, not a bundled-default candidate.
- **SpiceDB** — rejected as any kind of default or adapter priority: client-only (gRPC + datastore required), and its own co-founder confirmed no official AuthZEN WG support.

**Maturity/license notes:** Cedar is Apache-2.0, CNCF Sandbox (accepted 2025-10-08, monthly release cadence, 1,586 GitHub stars — much smaller community than OPA's but growing CNCF-neutral governance). OPA is Apache-2.0, CNCF Graduated (2021, the highest CNCF maturity tier), 11,929 stars, ubiquitous outside this specific embedding use case (Gatekeeper/Envoy/Istio/Kong/Terraform). Note the August 2025 OPA leadership move (original creators moved to Apple) — OPA's own blog states no governance/licensing change resulted, but it is a leadership-continuity data point worth knowing.

**Risk/watch-item:** Re-verify `@cedar-policy/cedar-wasm`'s current version at Phase-1 launch (see §11). Also watch a known packaging rough edge: GitHub issue cedar-policy/cedar#1226, where the `nodejs` subpackage's `package.json` `exports` initially broke ESM `import()` of the CJS build — fixed via PR #1256, but worth re-testing inside KnoTrust's own bundling pipeline given it signals Node isn't Cedar's most-dogfooded target (Rust/AWS-service embedding is).

---

## 7. Crypto & key management

**Choice:** Ed25519 signatures, serialized as **JWS Compact Serialization with `alg: EdDSA`**, via the audited `@noble/curves` on the TypeScript side and Python's `cryptography` library (`Ed25519PrivateKey`/`Ed25519PublicKey`) on the Python side, with golden cross-language test vectors from day one. Keys live at `~/.knotrust/identity.key` with `0600` permissions, with optional OS-keychain mirroring via `@napi-rs/keyring`.

**Why (Ed25519 + `@noble/curves`):** `@noble/curves` is pure TypeScript/JS with no WASM or native-binary complications — a meaningful property for an `npx`-distributed CLI where a native dependency adds build-matrix and install-failure risk. It is independently audited (Trail of Bits 2023, Kudelski 2023, Cure53 August 2024), unlike the current v2/v3 rewrite of the narrower `@noble/ed25519` package, which is not independently audited. Native WebCrypto Ed25519 support only became universal across major browsers in May 2025 (Chrome/Edge was the last holdout), so a pure-JS implementation is still the safer default for the companion browser approval app; WebCrypto remains an optional future fast-path once Node ≥ 22's stable WebCrypto Ed25519 support (from v22.13.0) is broadly relied upon.

**Why (JWS Compact Serialization over COSE or a custom binary format):** JWS signs the base64url string directly rather than re-parsed JSON, so it has no canonicalization ambiguity in practice, and it gets a mature, ubiquitous cross-language ecosystem essentially for free (`jose` on the TS side, `PyJWT`/`Authlib` on the Python side), while staying human-debuggable (jwt.io). The cost — roughly 33% base64 expansion plus JSON key verbosity — is deliberately paid now in exchange for zero cross-language codec-maintenance tax; short claim names (e.g., `p`/`a`/`t`/`s`/`c`/`r`/`g`/`e`/`su` for principal/action/tool/scope/conditions/risk-tier/granted-by/expiry/single-use) control size without abandoning the format.

**Why (keys at `~/.knotrust/identity.key`, `0600`, optional keychain):** For a local-first, no-backend Phase 0–1 posture, a single Ed25519 identity key written with strict `0600` permissions from the start is already stricter than well-known prior art (the AWS CLI's `~/.aws/credentials` notoriously does not default to `600`; OpenSSH enforces and refuses insecurely-permissioned keys, which is the bar KnoTrust matches). `@napi-rs/keyring` is chosen over the alternative of no keychain option at all because it is Rust-backed, works headless, has no libsecret/dbus dependency, and is already adopted by Microsoft's MSAL/Azure Identity libraries — evidence of production-readiness. `keytar` is explicitly excluded: its repository was archived in December 2022 following Atom's sunset, and known prior consumers (Joplin, Element, Azure SDK, Gemini CLI) have already migrated off it.

**Alternatives considered & why rejected:**
- **COSE (RFC 9052, CBOR-based)** — rejected for now: more compact than JWS and the format WebAuthn/mdoc use, but dedicated JS COSE *envelope* libraries are thin and stale (`cose-js` last touched 2023, `@auth0/cose` April 2024); KnoTrust would effectively hand-roll the COSE envelope on top of otherwise-healthy CBOR codecs. Deferred as a later size optimization only if measured grant size becomes an actual problem (e.g., URL-embedding in MCP's URL-mode elicitation, or QR-code offline transfer).
- **Custom compact binary format (fixed struct + raw 64-byte Ed25519 signature)** — rejected for the same reason: smallest option and avoids canonicalization questions by construction (precedent: Solana's compact transaction structs, WireGuard's fixed binary handshake), but requires maintaining a hand-written codec in sync across TS, browser JS, and Python — an ongoing tax not justified pre-emptively.
- **`keytar`** — rejected: dead upstream (archived Dec 2022).
- **libsodium (`libsodium-wrappers`/`-sumo`)** — implicitly not chosen over `@noble/curves`: it requires WASM via Emscripten with async `sodium.ready` initialization, whereas `@noble/curves` is pure JS with no init step, for comparable long-standing review credibility.

**Maturity/license notes:** `@noble/curves` and Python's `cryptography` are both mature, widely-used, permissively-licensed libraries. `@napi-rs/keyring` is newer but already load-bearing in Microsoft's identity tooling.

**Risk/watch-item:** None material for Phase 0–1 beyond the general note that Ed25519 WebCrypto support in browsers is young (~14 months old as of the brief's date) — this is exactly why the pure-JS path is the default rather than a stopgap.

---

## 8. Local stores & audit

**Choice:** Signed grants stored as JWS files in `~/.knotrust/grants/`; audit as an append-only **JSONL file with hash chaining**; `knotrust audit` CLI for querying; a SQLite index (`node:sqlite`, no native deps) added later only once query needs outgrow simple streaming.

**Why:** Zero native dependencies in the `npx` path is a hard constraint for cold-start reliability and install-matrix simplicity, and JSONL with hash chaining gets tamper-evident-lite behavior from day one without needing a database engine at all. Deferring a SQLite index until query needs genuinely outgrow streaming (and using `node:sqlite`, which ships with Node itself and adds no native dependency, rather than `better-sqlite3`) keeps the same zero-native-dependency property even as the store grows.

**Alternatives considered & why rejected:**
- **`better-sqlite3` from day one** — rejected for v1: it is a native module, which is exactly the native-dependency risk the `npx` path is designed to avoid; deferred to a later point where `node:sqlite` (no native deps) may no longer suffice, at which point it is a reasonable escalation, not before.
- **Custom binary grant format / COSE** — see §7; deferred for the same codec-maintenance-tax reasoning.

**Maturity/license notes:** JSONL and hash-chaining are simple, in-house patterns with no dependency risk. `node:sqlite` is a Node core module (stable, no external license).

**Risk/watch-item:** None material; the escalation trigger ("when query needs outgrow streaming") is intentionally left as an engineering judgment call rather than a fixed threshold, since the brief does not specify one.

---

## 9. Audit export

**Choice:** OpenTelemetry (OTLP) exporter, with SigNoz as the reference receiver.

**Why:** OpenTelemetry is the vendor-neutral standard for exportable telemetry, satisfying the PRD's audit/observability requirement (§12) without coupling KnoTrust's audit trail to any one backend. SigNoz is specifically named as the reference receiver because KnoTrust already runs SigNoz internally — dogfooding the export path on infrastructure the team already operates.

**Alternatives considered & why rejected:** None recorded — OTLP as a vendor-neutral export format was not weighed against a proprietary alternative in the brief or research; it is the natural fit for an audit trail meant to be "exportable," not backend-locked.

**Maturity/license notes:** OpenTelemetry is a CNCF Graduated project; mature, Apache-2.0, broad ecosystem support.

**Risk/watch-item:** None material.

---

## 10. Config & packs

**Choice:** `c12` + `jiti` for config resolution — `knotrust.config.ts` or YAML/JSON, equally supported. Preset packs are declarative YAML, distributed via a **shadcn-style GitHub registry** (`knotrust add pack github`), signed and content-hashed, with a review gate for community submissions.

**Why (`c12` + `jiti` over `cosmiconfig`):** `c12` is purpose-built for typed `knotrust.config.ts` resolution — native `import()` of a TypeScript config file with `jiti` as the transpiling fallback — which is exactly KnoTrust's target format. `cosmiconfig`'s core strength, broad legacy config-format compatibility, is not the problem KnoTrust needs solved; typed config for integrators plus YAML for ops/community packs is.

**Why (shadcn-style GitHub registry for packs, with a trust gate):** Modeling the pack registry directly on shadcn/ui's `registry.json`/`registry-item.json` + GitHub-registry pattern means no server is required for v1 — packs resolve straight from a GitHub repo path (`owner/repo/item#tag`), versioned by tag/SHA, with `registryDependencies` for composability. Critically, a preset pack is *executable security policy*, not a UI snippet, so KnoTrust deliberately does not copy shadcn's fully-silent-apply UX. Instead it bakes in the lesson Homebrew's ecosystem learned the hard way in 2026 — shipping "tap trust" in Homebrew 6.0.0 specifically to stop silent execution of untrusted third-party tap content — by requiring explicit trust/approval before a community pack is silently applied, plus signing and content-hashing every pack.

**Alternatives considered & why rejected:**
- **`cosmiconfig`** — rejected: its strength (legacy-format compatibility) is not the relevant axis; `c12`'s native TS-config resolution is the better fit for a purpose-built, typed config target.
- **Fully-silent pack application (shadcn's default UX)** — rejected specifically for the packs case, because packs are security policy, not UI code; the review-gate/signing requirement is an explicit, deliberate deviation from the shadcn precedent this pattern is otherwise modeled on.

**Maturity/license notes:** `c12` and `jiti` are `unjs`-maintained, actively developed, permissively licensed. The shadcn registry pattern is a well-established, widely-copied convention, not a dependency with its own maturity risk.

**Risk/watch-item:** The signing/content-hashing/review-gate mechanics for community pack submissions are a real, non-trivial subsystem to build correctly — this is the area most directly analogous to a past ecosystem security failure (Homebrew taps pre-6.0.0), so it should not be treated as a routine CRUD feature.

---

## 11. HTTP proxy & approval UI (Phase 2, marked)

> Everything in this section is Phase 2 scope. It is documented here for completeness of the ratified stack, not as something Phase 0/1 builds.

**Choice:** Hono on Node for the streamable HTTP proxy. Approval UI: Phase 1 ships a localhost page served by the proxy itself (vanilla/tiny Vite app, also the URL-mode elicitation target); **Phase 2** upgrades to a **PWA with Web Push**.

**Why (Hono):** Hono is light, standards-based (built on the Fetch API), and portable to edge runtimes if that is ever needed — a reasonable hedge given KnoTrust's local-first architecture may eventually want to run proxy logic somewhere other than a long-lived Node process.

**Why (PWA-first approval app, not native):** Phase 1 needs zero backend and zero push infrastructure — a terminal prompt plus a localhost web approval page (the same page also serves as the URL-mode elicitation target) is sufficient and keeps the flagship demo's "zero backend" claim true. Phase 2's PWA + Web Push is deliberately coupled to the optional control-plane foundation Phase 2 builds anyway, because push inherently requires a reachable push endpoint — this is an honest architectural pairing, not an arbitrary bundling. Both iOS (≥ 16.4) and Android/desktop support Web Push as of 2026, so a PWA is not a compromise relative to native on reachability grounds. SMS via a pluggable notifier (Twilio) covers the voice-approval path. Native apps are deferred indefinitely and revisited only if PWA push proves unreliable on iOS in practice.

**Alternatives considered & why rejected:**
- **Native mobile approval app** — deferred (not rejected outright): PWA push is judged adequate for Phase 2's needs; native is a fallback if PWA push proves unreliable on iOS specifically.

**Maturity/license notes:** Hono is MIT-licensed, actively maintained. Web Push is a mature W3C standard with broad current support.

**Risk/watch-item:** Re-verify the elicitation client support matrix at Phase-1 launch (see §12) — client support for MCP elicitation itself (distinct from the approval app) is uneven today (solid in Claude Code; broken in Claude Desktop at brief-writing time; in-progress in Codex CLI; form-only in Cursor), which is exactly why the approval subsystem is channel-plural (form-mode elicitation, URL-mode elicitation, and a block-and-wait fallback that works on every client regardless of elicitation support) rather than elicitation-only.

---

## 12. Lint / test

**Choice:** Biome + Vitest; TypeScript `strict` mode.

**Why:** A single fast toolchain (Biome covers both linting and formatting in one Rust-based tool) reduces tool-count overhead in a monorepo that will also need to onboard a Python SDK later — keeping the TS-side tooling as consolidated as possible pays off when total tooling surface area grows.

**Alternatives considered & why rejected:** None recorded as seriously contended in the source material — this line item in the brief's table carries no counter-option analysis; it is a straightforward "fast, consolidated toolchain" pick.

**Maturity/license notes:** Biome and Vitest are both actively developed, MIT-licensed, and increasingly the default choice in modern TS projects.

**Risk/watch-item:** None material.

---

## 13. License / CLA

**Choice:** Apache 2.0 core, plus a Contributor License Agreement (CLA), per PRD §14 — unchanged by the brief.

**Why:** Apache 2.0 (rather than a more restrictive core license) plus closed enterprise modules is the chosen defense against cloud resale, per the PRD's open-core boundary (§14): the license itself stays permissive and forkable — an explicit bus-factor/credibility mitigation for a security-relevant dependency owned by a small company (PRD §17: "never stranded — fork it") — while commercial differentiation lives in separately-licensed enterprise modules, not in core-license restrictions. The CLA preserves KnoTrust's (Kno2gether Labs Ltd's) ability to dual-license those enterprise modules later.

**Alternatives considered & why rejected:** Not re-litigated by the brief — PRD §14 is carried forward unchanged ("Unchanged" is the brief's own annotation).

**Maturity/license notes:** Apache 2.0 is a mature, OSI-approved, widely-understood permissive license with an explicit patent grant — a meaningful property for a project positioned partly on standards-conformance (AuthZEN) where patent ambiguity would be a credibility risk.

**Risk/watch-item:** IP/licensing provenance (repo ownership, any license/assignment for code derived from prior Knotie MCP work, contributor CLA language) is flagged in the PRD (§22) as needing a short solicitor review at inception — not a technology risk, but a real pre-launch action item.

---

## Stack at a glance

| Layer | Choice | Status |
|---|---|---|
| Language / runtime | TypeScript, Node ≥ 22 (LTS) | Ratified |
| Package shape | Single `knotrust` npm package, subcommand CLI | Ratified |
| Monorepo | pnpm workspaces + Turborepo | Ratified |
| Release | release-please + npm/PyPI OIDC trusted publishing | Ratified |
| MCP layer | Official `@modelcontextprotocol/sdk` (1.x); baseline 2025-11-25; 2026-07-28 behind `SpecAdapter` | Ratified |
| Decision core | Pure TS `@knotrust/core`: DecisionRequest contract, tier evaluator, grant verifier, precedence engine, decision cache | Ratified |
| PDP — L0 | Built-in dependency-free TS risk-tier evaluator (bundled default) | Ratified |
| PDP — L1 | `@cedar-policy/cedar-wasm`, opt-in lazy install (`knotrust add pdp cedar`) | Ratified |
| PDP — adapters | Generic AuthZEN HTTP adapter (Cerbos, Topaz, PlainID, SGNL, …); OPA REST adapter (SARC→Rego translation) | Ratified |
| Grant signing | Ed25519 → JWS Compact (`alg: EdDSA`) via `@noble/curves` (TS) / `cryptography` (Python) | Ratified |
| Keys | `~/.knotrust/identity.key` (0600); optional `@napi-rs/keyring` | Ratified |
| Local store | Signed grants as JWS files; audit as hash-chained JSONL; `node:sqlite` index later if needed | Ratified |
| Audit export | OpenTelemetry (OTLP); SigNoz as reference receiver | Ratified |
| HTTP proxy | Hono on Node | Ratified (Phase 2) |
| Approval UI | Localhost page (Ph 1) → PWA + Web Push (Ph 2) | Ratified (phased) |
| Config | `c12` + `jiti`; TS config or YAML/JSON | Ratified |
| Preset packs | shadcn-style GitHub registry; signed + content-hashed; review gate | Ratified |
| Lint/format/test | Biome + Vitest; TS `strict` | Ratified |
| License | Apache 2.0 + CLA | Ratified (unchanged from PRD §14) |
| Python SDK | Real port (not FFI/daemon) of L0 evaluator + JWS verification via `cryptography`; FastMCP `on_call_tool` middleware as likely integration surface | Ratified (Phase 3) |

---

## Version pins & re-verify list

These are things whose currency is time-sensitive and must be re-checked close to Phase-1 launch, not assumed to still hold from this document's date (2026-07-03):

1. **`knotrust` npm package name availability + trademark scan** — brief §H flags this as an action item before Phase 1 launch specifically (not before Phase 0 code).
2. **`@cedar-policy/cedar-wasm` current version** — this document cites v4.11.2 (published 2026-06-23) as current; Cedar releases roughly monthly, so re-check the version, the ~4.27 MB uncompressed WASM size, and whether GitHub issue cedar-policy/cedar#1226's packaging edge case (ESM `import()` of the CJS build) remains fixed in KnoTrust's own bundling pipeline.
3. **Elicitation client support matrix** — re-verify Claude Desktop's elicitation gaps specifically (broken at brief-writing time), plus Codex CLI's in-progress status and Cursor's form-only support, before finalizing Phase 1 launch docs; the block-and-wait fallback must remain correct as the universal baseline regardless of how this matrix shifts.
4. **MCP 2026-07-28 finalization** — the spec was a locked RC as of 2026-05-21, finalizing roughly 3.5 weeks after this document's date; re-check its final (not RC) content against `modelcontextprotocol.io` before treating any 2026-07-28-specific feature (e.g., `requestState` resumption, `Mcp-Method`/`Mcp-Name` headers) as settled in shipped docs or code.
5. **AARP/COAZ maturity stage** — re-check against `openid.net/wg/authzen/specifications` before any external claim about spec maturity; both are Working Group Draft as of this document's date, not Implementer's Draft, and the PRD's own §16 enterprise-GA gate depends on this changing.
6. **Microsoft Agent Governance Toolkit status** — not a version pin but a recommended quarterly tracked item per the competitive research (foundation-donation status, any pivot from self-hosted toolkit to managed/portable product) — material to positioning claims, not to the tech stack itself, but worth carrying on the same re-verify cadence.
