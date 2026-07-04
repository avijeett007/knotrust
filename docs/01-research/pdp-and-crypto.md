# PDP & Cryptography Research — Policy Engine and Grant-Signing Choices for KnoTrust

**Status:** Research (Phase 0 input). Not a decision record — see [Open decisions for the orchestrator](#open-decisions-for-the-orchestrator).
**Date compiled:** 2026-07-03 (verified live against primary sources; version numbers and spec statuses are as of this date).
**Scope:** PDP-agnostic policy engine choice (default + adapters) and grant-signing crypto for KnoTrust, an Apache-2.0, local-first, zero-backend MCP action-governance proxy, built on OpenID AuthZEN (Authorization API 1.0 Final; AARP + COAZ profiles), distributed as a Node/TypeScript CLI via `npx` with no daemon in first-run.

---

## 1. Executive summary

- **Default PDP:** recommend a two-tier default — (L0) a tiny hand-rolled, dependency-free risk-tier evaluator that is what `npx knotrust` runs with zero extra bytes on day one, plus (L1) **Cedar compiled to WASM** (`@cedar-policy/cedar-wasm`, official, Apache-2.0, actively maintained, Node-targeted) as the bundled "real" default PDP that activates once a user writes actual policies/schema. **OPA** is a strong **external adapter** (its Node/WASM path is officially work-in-progress and under-maintained relative to Cedar's); **Cedar can also be offered as a standalone external adapter** for teams already running Cedar/AVP elsewhere.
- **Grant signing:** **Ed25519** signatures via **`@noble/curves`** (audited, pure TS/JS, no WASM) on the TypeScript/browser side and Python's **`cryptography`** library (`Ed25519PrivateKey`/`Ed25519PublicKey`) on the Python side, serialized as **JWS Compact Serialization with `alg: EdDSA`** using short claim names. Reserve a custom compact-binary or COSE format as a later size optimization only if measured token size becomes a problem.
- **Top risks/uncertainties:** (1) AuthZEN's **AARP and COAZ profiles are still Working Group Draft**, not Implementer's Draft, as of 2026-07-03 — and the spec text itself abbreviates AARP as "ARAP," a naming inconsistency KnoTrust's own docs should not propagate uncorrected; (2) bundling Cedar-WASM (~4.27 MB uncompressed wasm) inside the default `npx` package is in tension with KnoTrust's "zero-backend, npx-and-go" positioning and with PRD §2's framing that KnoTrust is "not a policy engine competing with Cedar/OPA/Cerbos" — embedding Cedar blurs that line; (3) revocation freshness in pure local (zero-network) mode is fundamentally bounded by grant TTL — no mechanism beats that without new information reaching the verifier, so the honest claim must be TTL-scoped, not "instant."

---

## 2. Cedar (cedarpolicy.com / cedar-policy)

### 2.1 Language, engine, license
Cedar is a purpose-built authorization policy language and evaluation engine. A request asks "can this **principal** take this **action** on this **resource** in this **context**?" (the **PARC** model) — structurally identical to AuthZEN's **Subject-Action-Resource-Context (SARC)** model that KnoTrust already speaks. The engine (`cedar-policy` crate + `cedar-policy-core`/`cedar-policy-validator`) is Rust, in the `cedar-policy/cedar` GitHub repo, **Apache-2.0** licensed (confirmed via GitHub API `license.spdx_id`).

Sources: [docs.cedarpolicy.com](https://docs.cedarpolicy.com/), [auth model](https://docs.cedarpolicy.com/auth/authorization.html), [github.com/cedar-policy/cedar](https://github.com/cedar-policy/cedar).

### 2.2 JS/TS/WASM bindings — official and Node-targeted
**Yes, an official package exists: `@cedar-policy/cedar-wasm`**, built from the `cedar-wasm/` subdirectory of the main `cedar-policy/cedar` monorepo (not a community fork).

- Current version **4.11.2**, published **2026-06-23**, versioned 1:1 with the Rust crate (crates.io `cedar-policy` also at 4.11.2, Apache-2.0).
- ~98.5K downloads in the week of 2026-06-26–07-02 per the npm downloads API (an older cached figure of ~20K/week corresponds to a stale prior version — treat the higher figure as current).
- Three distribution targets: `@cedar-policy/cedar-wasm` (ESM default), `.../nodejs` (CommonJS, synchronous `fs`-based load), `.../web` (custom loader with `initSync`) — i.e., it's built to be consumed directly inside Node, not just a browser demo.
- API surface (from `cedar-wasm/src/lib.rs`): `is_authorized`, `is_authorized_partial`, `validate`, `format` (policy formatter), `check_parse_policy_set`/`check_parse_schema`/`check_parse_context`/`check_parse_entities`, `policy_to_json`/`policy_to_text`, `schema_to_json`/`schema_to_text`, `get_lang_version`/`get_sdk_version`.
- WASM binary is **~4.27 MB uncompressed** (per unpkg's file listing for v4.11.2); a gzip figure could not be confirmed (BundlePhobia lookup failed).
- One packaging rough edge found: [GitHub issue #1226](https://github.com/cedar-policy/cedar/issues/1226) — the `nodejs` subpackage's `package.json` `exports` initially broke ESM `import()` of the CJS build; fixed via PR #1256, but signals Node packaging wasn't fully shaken out pre-release and is worth re-testing in KnoTrust's own bundling pipeline.

Sources: [npm registry](https://registry.npmjs.org/@cedar-policy/cedar-wasm), [npmjs.com](https://www.npmjs.com/package/@cedar-policy/cedar-wasm), [cedar-wasm README](https://github.com/cedar-policy/cedar/blob/main/cedar-wasm/README.md), [lib.rs](https://raw.githubusercontent.com/cedar-policy/cedar/main/cedar-wasm/src/lib.rs), [issue #1226](https://github.com/cedar-policy/cedar/issues/1226).

### 2.3 Policy/schema model and validation
Cedar schemas declare namespaces of entity types (attributes, required/optional, parent/child hierarchy) and actions (with `memberOf` groups and applicable principal/resource types + context shape). The **validator** performs strict, schema-typed static checking of policies ahead of runtime evaluation — catching type errors before they hit production. This gives KnoTrust's OSS users a real typed-authoring experience if they choose to write Cedar policies directly, beyond the built-in risk-tier presets.

Sources: [schema docs](https://docs.cedarpolicy.com/schema/schema.html), [validation docs](https://docs.cedarpolicy.com/policies/validation.html).

### 2.4 Performance and correctness story
Cedar is built with a **verification-guided development process**: AWS maintains parallel formal models of the evaluator/authorizer/validator in **Lean**, proves correctness properties, and cross-checks against the production Rust implementation via differential random testing on every release; a companion **`cedar-policy-symcc`** symbolic compiler formally verifies properties like "policy never errors" or policy-set equivalence/disjointness. AWS's own migration blog (Nov 2025) claims Cedar is **42–60x faster than Rego** on their benchmark — a vendor-authored, relative figure, not an independent absolute-latency benchmark (no independently published p50/p99 numbers were found — flagged as unconfirmed). Evaluation is stateless/local per request, the right shape for a hot path.

Sources: [Lean use case](https://lean-lang.org/use-cases/cedar/), [arXiv 2407.01688](https://arxiv.org/pdf/2407.01688), [cedar-policy-symcc](https://crates.io/crates/cedar-policy-symcc), [AWS Security Blog](https://aws.amazon.com/blogs/security/migrating-from-open-policy-agent-to-amazon-verified-permissions/).

### 2.5 Maturity and governance
Cedar was **accepted into CNCF as a Sandbox project on 2025-10-08** — a governance shift from pure-AWS stewardship toward vendor-neutral CNCF governance, with a stated roadmap toward Incubation. Release cadence in 2025–2026 is roughly monthly (v4.9.0 → v4.11.2 over Feb–Jun 2026). 1,586 GitHub stars (much smaller than OPA's, see below). Named adopters beyond AWS (Verified Permissions, Bedrock AgentCore Policy): **Cloudflare, MongoDB Atlas, StrongDM, Cloudinary**. Governance/RFC process is public at `cedar-policy/rfcs` with a defined Pending→FCP→Unstable→Stable pipeline.

Sources: [CNCF project page](https://www.cncf.io/projects/cedar/), [AWS OSS blog](https://aws.amazon.com/blogs/opensource/cedar-joins-cncf-as-a-sandbox-project/), [CNCF onboarding issue](https://github.com/cncf/sandbox/issues/410), [releases](https://github.com/cedar-policy/cedar/releases), [RFC repo](https://github.com/cedar-policy/rfcs).

### 2.6 Suitability as embeddable default PDP
Realistic. It's a self-contained `.wasm` binary — no network, no daemon — exposing exactly the functions (`is_authorized`, `validate`) a Node CLI needs, and its request model (PARC) maps directly onto AuthZEN's SARC, which KnoTrust already speaks. Concrete costs to validate empirically before committing: **~4.27 MB added to the installed package** (one-time install cost, not a per-invocation fetch, but still non-trivial for an "npx and go" pitch), WASM instantiation cold-start (not independently benchmarked here), and re-verifying the ESM/CJS packaging edge case (#1226) inside KnoTrust's own build/test matrix.

---

## 3. OPA / Rego (openpolicyagent.org)

### 3.1 License and governance
**Apache-2.0**, confirmed in the repo LICENSE. OPA joined CNCF in 2018 and **Graduated 2021-01-29** — CNCF's highest maturity tier. **Notable 2025 event:** in August 2025, OPA's original creators (Teemu Koponen, Tim Hinrichs, Torin Sandall) and much of the Styra engineering team moved employer to Apple; OPA's own blog states explicitly there are **no changes to project governance or licensing**, and Styra is simultaneously open-sourcing more of its commercial stack (EOPA, OPA Control Plane, Regal linter) into the CNCF-owned org. Net: stable license/governance, but a leadership/employer shift worth flagging as context.

Sources: [LICENSE](https://github.com/open-policy-agent/opa/blob/main/LICENSE), [CNCF graduation announcement](https://www.cncf.io/announcements/2021/02/04/cloud-native-computing-foundation-announces-open-policy-agent-graduation/), [maintainer blog post](https://blog.openpolicyagent.org/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371).

### 3.2 Deployment models
Three documented modes: **(a) sidecar/daemon** — `opa run --server` exposes a REST API (`/v1/data`, `/v1/policies`); **(b) Go library embedding** — `github.com/open-policy-agent/opa/rego` lets a Go program build/evaluate prepared queries in-process ("less overhead than the REST API because all communication happens in the same OS process" per OPA's own docs) — this is OPA's flagship embedding target, and it's **Go-only**; **(c) WASM compilation** — `opa build -t wasm` compiles Rego to a `policy.wasm` module runnable in any WASM host, independent of the Go runtime.

Sources: [integration docs](https://www.openpolicyagent.org/docs/integration), [REST API docs](https://www.openpolicyagent.org/docs/rest-api), [rego package docs](https://pkg.go.dev/github.com/open-policy-agent/opa/rego), [wasm docs](https://www.openpolicyagent.org/docs/wasm).

### 3.3 Node/WASM specifically — the honest maturity picture
Official npm package: **`@open-policy-agent/opa-wasm`** (`open-policy-agent/npm-opa-wasm` repo). Latest **v1.10.0, published 2024-11-08**; the README itself still reads **"Work in Progress -- Contributions welcome!!"**. The repo saw a commit as recently as 2025-09-02 but **no npm release has followed** — an ~8-month release lag behind source activity. OPA's current docs do not mark WASM deprecated and list ~7 community WASM-integration projects, and the repo ships a working `examples/nodejs-app` that loads a `.wasm` bundle and calls `policy.evaluate(input)` directly in a plain Node process with **no server** — confirming the zero-daemon pattern is technically real. Known limitation: builtins like `http.send` are explicitly "not, and probably won't be natively supported in WASM," requiring host-side JS reimplementation if a policy needs them.

**Verdict: technically feasible, but this is OPA's least-invested integration surface** (Go embedding is the flagship; WASM/Node is secondary and self-described as WIP).

Sources: [npm-opa-wasm repo](https://github.com/open-policy-agent/npm-opa-wasm), [npm package](https://www.npmjs.com/package/@open-policy-agent/opa-wasm), [commit history](https://github.com/open-policy-agent/npm-opa-wasm/commits/main), [wasm ecosystem list](https://www.openpolicyagent.org/ecosystem/by-feature/wasm-integration), [nodejs-app example](https://github.com/open-policy-agent/npm-opa-wasm/tree/main/examples/nodejs-app).

### 3.4 Enterprise ubiquity
OPA's `ADOPTERS.md` lists Netflix, Goldman Sachs, Google Cloud (built into GKE Policy Automation), Capital One, Intuit (~50 clusters/1,000 namespaces), T-Mobile, Pinterest (OPA+Envoy/Kafka/Jenkins at up to 8.5M QPS). Gatekeeper (OPA-based K8s admission control) is used by BNY Mellon, bol.com, Cloudflare, Marsh McLennan. **11,929 GitHub stars** vs Cedar's 1,586 — a decade of cross-ecosystem reach (Gatekeeper/Envoy/Istio/Kong/Terraform/conftest) that Cedar's newer, more narrowly-scoped, AWS-centric footprint hasn't matched. No specific quantified 2025/2026 CNCF-survey adoption statistic for OPA specifically could be confirmed — flagged as unconfirmed rather than invented.

Sources: [ADOPTERS.md](https://github.com/open-policy-agent/opa/blob/main/ADOPTERS.md).

### 3.5 Tradeoffs vs Cedar for Node-CLI embedding
Both Apache-2.0. Cedar is purpose-built and narrower (schema-typed, formally-verified authorization DSL); Rego is a general Datalog-derived language spanning admission control, CI/CD gating, and app authorization — broader but less amenable to the kind of static analysis Cedar's validator/symcc provide. **Node/WASM tooling maturity clearly favors Cedar**: an actively-released, Node-targeted official package (v4.11.2, 2026-06-23) vs opa-wasm's Nov-2024, WIP-labeled release. **Community size/ubiquity favors OPA** by a wide margin. For KnoTrust's specific job — embedding in-process in a Node CLI with no daemon — Cedar is the better-supported path today; OPA remains the better choice when the user already runs an OPA server/sidecar and just wants KnoTrust to talk to it (external adapter).

---

## 4. Other authorization engines (Cerbos, OpenFGA, Oso, SpiceDB, Casbin)

| Engine | License | Embeddable in Node (in-process, no daemon) | AuthZEN support | Bundled-default fit? | Current version (as of 2026-07-03) |
|---|---|---|---|---|---|
| **Cerbos** | Apache-2.0 | No — `@cerbos/grpc`/`@cerbos/http` are pure clients to a running PDP; `@cerbos/embedded-client` exists but needs bundles generated by **Cerbos Hub** (commercial SaaS) | **Deep, official.** PDP v0.48 added `/access/v1/evaluation`; co-founder is an AuthZEN WG co-chair and co-author of the COAZ profile | External adapter | v0.53.0 (2026-05-05), 4,300+ stars |
| **OpenFGA** | Apache-2.0 | No — `@openfga/sdk` is a generated REST/gRPC client; the Go engine embeds only in Go services | Official but **experimental/flag-gated**; maintains `openfga/authzen-interop` | External adapter | v1.18.1 (2026-06-29); CNCF Incubating (2025-10-28) |
| **Oso (Polar)** | Apache-2.0 (core lib) | Formerly yes (Rust core, native Node bindings) — but the OSS library is **frozen/bug-fixes-only since Dec 2023**, stalled at v0.27.3 (Jan 2024). Living product (Oso Cloud / "Oso for Agents") is a hosted, proprietary API | None found; absent from AuthZEN interop list | **Not recommended for either role** — abandonment risk on the embeddable side, proprietary/non-standard on the surviving side | `oso` 0.27.3 (frozen); `oso-cloud` SDK 2.6.0 (Mar 2026, different product) |
| **SpiceDB** | Apache-2.0 (core); proprietary "Enterprise" add-on separate | No — `@authzed/authzed-node` is a pure gRPC client requiring a running server + datastore | **None.** Cofounder confirmed (May 2025) no official AuthZEN WG support | External adapter | v1.54.0 (2026-06-18) |
| **Casbin** | Apache-2.0 | **Yes — genuinely in-process.** `node-casbin`'s `Enforcer` loads model+policy files directly in pure TS, no daemon; a separate Casbin Server is optional | None; absent from AuthZEN's interop list; only unofficial community bridges exist | Architecturally the strongest **bundled-default** candidate among these five — but needs a custom SARC-translation shim since it's model/policy-file-first, not AuthZEN-native | v5.51.1 (2026-06-25); entered **Apache Software Foundation Incubation** 2026-02-07 |

**Bottom line:** of these five, only **Casbin** is a true zero-process, pure-TS embeddable option today, but it has zero AuthZEN alignment. **Cerbos and OpenFGA** have the best current AuthZEN protocol support (Cerbos deepest, including WG leadership) but are both server/sidecar architectures — external adapters, not bundled defaults. **Oso** should likely be dropped from KnoTrust's own comparative docs/marketing given the OSS library's stalled state and the company's pivot to a different, non-AuthZEN product.

Sources: [Cerbos LICENSE](https://github.com/cerbos/cerbos/blob/main/LICENSE), [Cerbos JS SDK](https://github.com/cerbos/cerbos-sdk-javascript/blob/main/README.md), [Cerbos AuthZEN blog](https://www.cerbos.dev/blog/cerbos-pdp-v0-48-open-id-auth-zen-support-improved-query-plans-faster-bundle-loading), [Cerbos releases](https://github.com/cerbos/cerbos/releases); [OpenFGA LICENSE](https://github.com/openfga/openfga/blob/main/LICENSE), [CNCF OpenFGA](https://www.cncf.io/projects/openfga/), [OpenFGA AuthZEN docs](https://openfga.dev/docs/interacting/authzen), [authzen-interop](https://github.com/openfga/authzen-interop); [Oso repo](https://github.com/osohq/oso), [Oso changelog notice (archived)](https://web.archive.org/web/20250919072838/https://www.osohq.com/docs/oss/project/changelogs/2023-12-18.html), [Oso Cloud architecture](https://www.osohq.com/docs/oso-cloud-overview/oso-cloud-architecture); [SpiceDB LICENSE](https://github.com/authzed/spicedb/blob/main/LICENSE), [authzed-node](https://www.npmjs.com/package/@authzed/authzed-node), [cofounder AuthZEN statement](https://github.com/orgs/authzed/discussions/2320), [SpiceDB releases](https://github.com/authzed/spicedb/releases); [Casbin LICENSE](https://github.com/casbin/node-casbin/blob/master/LICENSE), [node-casbin](https://github.com/casbin/node-casbin), [Apache Incubator page](https://incubator.apache.org/projects/casbin.html).

### 4.1 The AuthZEN standard itself

- **Authorization API 1.0 reached Final Specification status** via OpenID Foundation membership vote on **2026-01-12** (81 approve / 1 object / 25 abstain). Canonical text at `openid.net/specs/authorization-api-1_0.html`; a living editor's draft at [openid.github.io/authzen](https://openid.github.io/authzen/).
- **AARP and COAZ are real, named, publicly-announced artifacts (2026-06-15) — but both are still at Working Group Draft status, not Implementer's Draft or Final:**
  - **AARP** = "AuthZEN Access Request and Approval Profile" (author Karl McGuinness). **Flag:** the draft's own front matter abbreviates it **"ARAP,"** not "AARP" — an inconsistency between the OpenID Foundation's press release and the spec text. The mechanism is a "requestable denial" (`context.access_request`), which maps to KnoTrust's `deny-with-prerequisite` concept but isn't literally named that in the spec.
  - **COAZ** = "Compatible with OpenID AuthZen" (authors Atul Tulshibagwale/SGNL and Alex Olivier/Cerbos); defines `x-coaz-mapping` for mapping MCP tools onto AuthZEN's SARC model. **SARC itself is confirmed real and accurately used in KnoTrust's PRD.**
  - **Consequence:** KnoTrust's own PRD gate (§16: "enterprise GA additionally requires COAZ/AARP at ≥ Implementer's Draft") is **currently unmet by the specs themselves** as of 2026-07-03 — this is already correctly anticipated in the PRD's own phrasing, but worth keeping front-of-mind as a live tracking item, not a settled fact.
- **Vendor participation:** WG co-chairs are Axiomatics, Cerbos, SGNL, IndyKite, Bloomberg. The interop PDP list includes Aserto/Topaz, AWS Verified Permissions, Axiomatics, Cerbos, EmpowerID, Hexa, IndyKite, Kogito, **OPA**, **OpenFGA**, Permit.io, PingAuthorize, PlainID, Rock Solid Knowledge, SGNL, WSO2. Okta is quoted supportively but **not** on the interop list. **Not found** in any AuthZEN materials: Microsoft, Osohq, SpiceDB/AuthZed, Casbin, Veza, Authress, Saviynt.

Sources: [Final spec announcement](https://openid.net/authorization-api-1-0-final-specification-approved/), [spec text](https://openid.net/specs/authorization-api-1_0.html), [authzen GitHub](https://github.com/openid/authzen), [AARP/ARAP draft](https://github.com/openid/authzen/blob/main/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md), [COAZ/MCP profile draft](https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md), [WG drafts announcement](https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/), [interop pdps.json](https://github.com/openid/authzen/blob/main/interop/authzen-todo-backend/src/pdps.json), [WG home](https://openid.net/wg/authzen/).

---

## 5. Comparison table — engine × {license, embeddable-in-Node, WASM, AuthZEN, maturity}

| Engine | License | Embeddable in-process in Node | WASM path | AuthZEN support | Maturity / governance |
|---|---|---|---|---|---|
| **Cedar** | Apache-2.0 | **Yes** — official `@cedar-policy/cedar-wasm`, Node-targeted (ESM+CJS), actively released | Native (it *is* the embedding mechanism) | Model (PARC) is structurally SARC-compatible; not a named AuthZEN interop PDP itself, but AWS Verified Permissions (Cedar-based) **is** on the interop list | CNCF Sandbox (2025-10-08); monthly releases; 1,586 stars; formally verified (Lean) |
| **OPA/Rego** | Apache-2.0 | Technically yes via `@open-policy-agent/opa-wasm`, but package is WIP-labeled, last release Nov 2024 | Yes, official but secondary/under-invested integration surface | **Yes** — on the AuthZEN interop PDP list | CNCF Graduated (2021); 11,929 stars; ubiquitous (K8s/Envoy/Istio/Terraform) |
| **Cerbos** | Apache-2.0 | No (client-only; embedded mode needs commercial Cerbos Hub) | No general-purpose package | **Deep, official** (PDP-native `/access/v1/evaluation`; WG co-chair) | v0.53.0; 4,300+ stars |
| **OpenFGA** | Apache-2.0 | No (client-only; Go-only embedding) | No | Official but experimental/flag-gated | CNCF Incubating (2025-10-28); v1.18.1 |
| **Oso (Polar)** | Apache-2.0 (frozen lib) | Formerly yes; abandoned in practice since Dec 2023 | N/A | None found | Stalled/frozen; company pivoted product |
| **SpiceDB** | Apache-2.0 (core) | No (client-only, gRPC + datastore required) | Browser-only Playground build, not a reusable package | **None** (cofounder-confirmed) | v1.54.0; strong adopter base (Netflix) |
| **Casbin** | Apache-2.0 | **Yes** — genuine pure-TS in-process `Enforcer` | N/A (not needed; pure TS) | None; no interop presence | Apache Incubation (2026-02-07); v5.51.1; broad industrial adoption |

---

## 6. Recommendation framing — default PDP

### (a) Tiny hand-rolled risk-tier evaluator as the true default
**Pros:** zero dependencies, zero added bytes, trivially auditable, fastest possible cold start, no exposure to any external project's release/governance risk, matches the "zero-backend, npx-and-go" pitch exactly, and is enough to implement KnoTrust's own `routine|sensitive|critical` risk-tier model (PRD §7) with admin-envelope precedence (PRD §7) out of the box.
**Cons:** it is not a general policy language — it can't express the kind of fine-grained, schema-typed conditions power users will eventually want; risks organically growing into an unofficial bespoke DSL anyway if pushed too far; doesn't inherit any of Cedar's formal-verification or validator guarantees.

### (b) Cedar-WASM as the embeddable "real" default PDP
**Pros:** official, Node-targeted, Apache-2.0, actively released package; request model (PARC) is a near-exact match for the SARC model KnoTrust already speaks; schema + validator give real typed policy authoring; runs fully in-process with no daemon; CNCF Sandbox governance trend is moving the project away from single-vendor (AWS) control; formally-verified semantics is a genuine differentiator for a security-relevant proxy.
**Cons:** ~4.27 MB (uncompressed) of WASM added to the default install — real tension with "npx and go" minimalism; one recent Node-packaging bug (fixed, but shows Node isn't Cedar's most-dogfooded target — Rust/AWS-service embedding is); Cedar's own policy language is a new thing for OSS users to learn versus just editing a risk-tier config; embedding one of the very engines KnoTrust's own positioning (PRD §2) says it doesn't compete with is a messaging tension that needs to be resolved explicitly, not left implicit.

### (c) OPA and Cedar as external adapters
**Pros:** meets teams and enterprises exactly where they already are (OPA is the de facto enterprise policy-as-code standard; Cedar is growing via AWS Verified Permissions). An adapter model requires no change to KnoTrust's own bundle size and cleanly upholds the "PDP-agnostic, not a policy-engine competitor" positioning.
**Cons:** OPA's own in-process Node/WASM path is under-invested (WIP-labeled, stale release) — so an "adapter" in practice likely means talking to a running `opa run --server` daemon over REST, which reintroduces exactly the kind of resident-process dependency KnoTrust's OSS-first, zero-backend story is designed to avoid unless the user opts in. Cedar-as-adapter (a separately-run Cedar/AVP service) is viable but redundant with option (b) if Cedar is already embedded.

### Recommended stance
Ship a layered default: **L0** — the hand-rolled risk-tier evaluator, so `npx knotrust -- your-server` works with zero extra dependency weight and zero external-project risk on the very first run (this is the literal "bundled default PDP" for the demo/launch moment). **L1** — bundle **Cedar-WASM** as the "grows-up" default that activates the moment a user supplies a real schema/policy set, since it is genuinely embeddable, Apache-2.0, AuthZEN-shaped, and Node-native today, unlike every other engine surveyed except Casbin (which has zero AuthZEN alignment). Keep **OPA as the primary external adapter** for the many enterprises that already run it (via its REST API against a daemon they operate — not via KnoTrust re-implementing OPA's under-maintained Node/WASM path), and offer **Cedar as an external-adapter mode too** (for teams centralizing on AWS Verified Permissions or a shared Cedar service) so the embedded L1 story and the external-adapter story use the *same* policy language without forcing a choice. This directly informs PRD §12 ("bundled default PDP; OPA + Cedar adapters at launch") — but flags that Cedar's role should likely be **both** embedded-default-candidate *and* adapter, not adapter-only, which is a decision the orchestrator needs to make explicitly (see below).

---

## 7. Grant signing / cryptography

### 7.1 Signature scheme comparison

| Option | Pure JS/TS (no native/WASM) | Audited | Node support | Browser support | Python equivalent |
|---|---|---|---|---|---|
| **`@noble/curves`** (v2.2.0) / **`@noble/ed25519`** (v3.1.0) | Yes | `noble-curves`: Trail of Bits (2023), Kudelski (2023), Cure53 (Aug 2024). `noble-ed25519`'s current v2/v3 rewrite is **not** independently audited (only the older v1 code was) | Any Node version | Any evergreen browser | — (use `cryptography` directly) |
| **libsodium** (`libsodium-wrappers`/`-sumo`) | No — WASM via Emscripten, requires async `sodium.ready` init | Long-standing C library, widely reviewed over years | Yes | Yes | `PyNaCl` (Apache-2.0, prebuilt wheels for all major OS/arch) |
| **Node `crypto`/WebCrypto** | N/A (native) | N/A (Node internals) | Ed25519 in `crypto.sign`/`generateKeyPair` since Node 12; **WebCrypto `SubtleCrypto` Ed25519 stable since Node v22.13.0**; Node 24 LTS fully supports it | Firefox 129 (Aug 2024), Safari 17.0, **Chrome/Edge 137 (May 2025 — the last major holdout)**; ~81% global coverage per caniuse | N/A |
| **`jose`** (panva, v6.2.3) | Yes, zero deps | Relies on underlying WebCrypto/Node crypto, not separately audited as a crypto implementation | Node, browser, CF Workers, Deno, Bun uniformly | Same | `PyJWT` (EdDSA via `cryptography` backend), `Authlib` (v1.7.2, most actively maintained), `python-jose` (14 months no release — maintenance risk, avoid) |

**Recommendation:** use **`@noble/curves`'s Ed25519 module** as the shared TypeScript/browser signing core (it's independently audited and has no WASM/native-binary complications for an `npx`-distributed CLI), and Python's **`cryptography`** library (`Ed25519PrivateKey`/`Ed25519PublicKey`) on the Python side. Treat native WebCrypto as an optional fast-path later — Chrome's Ed25519 support is only ~14 months old as of this writing, so a JS fallback is still warranted for the companion browser approval app for a while yet.

### 7.2 Serialization recommendation
Compared JWS/JWT compact serialization, COSE (RFC 9052, CBOR-based), and a custom compact binary format with a detached raw Ed25519 signature:

- **JWS Compact Serialization signs the base64url string directly, not re-parsed JSON — so it has no canonicalization ambiguity in practice**, gets a mature, ubiquitous cross-language ecosystem for free (`jose` + `PyJWT`/`Authlib`), and stays human-debuggable (jwt.io). Cost: ~33% base64 expansion plus JSON key verbosity.
- **COSE** is CBOR-native and more compact, and is the format WebAuthn/mdoc use — but dedicated JS COSE *envelope* libraries are thin and stale (`cose-js` 2023, `@auth0/cose` April 2024); CBOR codecs themselves (`cbor2` in Python, `cbor-x`/`cborg` in JS) are healthy, but you'd effectively hand-roll the COSE envelope on top.
- **Custom compact binary** (fixed struct + raw 64-byte Ed25519 signature) is the smallest and avoids any canonicalization question by construction (precedent: Solana's compact transaction structs, WireGuard's fixed binary handshake), but requires maintaining a hand-written codec in sync across TS, browser JS, and Python — a real ongoing tax.

**Recommendation: JWS Compact Serialization with `alg: EdDSA`, using short claim names** (e.g. `p`, `a`, `t`, `s`, `c`, `r`, `g`, `e`, `su` for principal/action/tool/scope/conditions/risk-tier/granted-by/expiry/single-use) to control size. This gets cross-language interoperability essentially for free and sidesteps canonicalization risk entirely. Reserve a custom binary or COSE "compact mode" as a **later** optimization only if measured grant size becomes an actual problem (e.g., for URL-embedding in MCP's URL-mode elicitation, or QR-code-based offline transfer) — don't pay the three-language codec-maintenance tax preemptively.

### 7.3 Key management for local-first, no-backend
- **`keytar` is dead** — the repo was archived in Dec 2022 following Atom's sunset; multiple prior consumers (Joplin, Element, Azure SDK, Gemini CLI) have migrated off it. A more current successor is **`@napi-rs/keyring`** (Rust-backed, no libsecret/dbus dependency, works headless, already adopted by Microsoft's MSAL/Azure Identity libraries).
- Versus a plain file: OpenSSH enforces `600` permissions on private keys and refuses to use insecurely-permissioned ones; by contrast, `age` only warns, and the AWS CLI's `~/.aws/credentials` notoriously does **not** default to `600` — so KnoTrust enforcing `0600` by default from day one is already stricter than some well-known prior art.
- **Root + delegated/derived keys for a later team/control-plane mode:** the cleanest precedent is SSH certificates (a CA key signs a short-lived certificate over a member's public key, with identity + validity window baked in), and the strongest modern analog is **Sigstore's keyless model** — Fulcio issues short-lived (10-minute) OIDC-bound certificates, Rekor logs every signature to a public transparency ledger, and `cosign` orchestrates both. WebAuthn Level 3 explicitly supports Ed25519 (COSE algorithm -8) as an authenticator option alongside the more common ES256, though real-world hardware-key adoption of Ed25519 specifically could not be confirmed.

**Recommendation:** Phase 0–1 (solo user): a single Ed25519 identity key at `~/.knotrust/identity.key`, written with `0600` permissions from the start, optionally mirrored into the OS keychain via `@napi-rs/keyring` (skip `keytar` entirely — it's unmaintained). Team/control-plane mode later: a root/org key signs short-lived per-device or per-session member keys (SSH-certificate-style, or a Sigstore/Fulcio-style short-lived-cert pattern), optionally with a Rekor-style append-only transparency log for auditability — this maps cleanly onto KnoTrust's existing "personal vs org scope" policy-bundle model (PRD §8).

---

## 8. Revocation freshness without an always-on backend

Patterns compared: short TTL + refresh (RFC 6749 §1.5/§10.4), CRL-style signed policy bundles (RFC 5280), OCSP/OCSP-stapling (RFC 6960/6066), and Macaroons/Biscuit-style caveat tokens.

- **Short TTL + refresh** bounds exposure to a single TTL window; refresh-token rotation can detect reuse of a stolen token, but detecting it still fundamentally requires periodic connectivity to compare notes with an issuer.
- **CRL-style signed bundles**: RFC 5280 itself acknowledges revocation "will not be reliably notified... until all currently issued CRLs are scheduled to be updated" — freshness is bounded by the issue/refresh period, not instantaneous by design. **The strongest offline-verifiable precedent is TUF** (The Update Framework): versioned, signed `timestamp`/`snapshot`/`root` metadata with explicit expirations, designed to bound freeze attacks — structurally close to what KnoTrust's "fetch-when-online, cache-otherwise, versioned bundle" model should mirror.
- **OCSP/stapling** assumes an always-reachable responder by design — a poor architectural fit for a zero-backend tool. Notably, the CA industry itself is moving *away* from OCSP toward CRL-based approaches (Let's Encrypt's 2022 CRL post; Mozilla's CRLite, 2025) — further evidence that "always-on responder" checking is disfavored even where the infrastructure to support it exists.
- **Macaroons / Biscuit** (now **Eclipse Biscuit** as of its Feb 2025 move to the Eclipse Foundation) add caveats/attenuation without contacting the issuer at grant-creation time; Biscuit's revocation mechanism gives each token block an auto-derived `revocation_id`, and the verifying app supplies a locally-known revoked-ID list as external facts at check time — a cheap local-match check. **This is a cheaper revocation *check*, not a way to avoid the connectivity requirement**: the revoked-ID list's own freshness still depends on whatever distribution channel populates it (i.e., it still reduces to the CRL/bundle-sync problem above). Biscuit's Rust core with bindings for Python, Java, Go, Swift, Haskell, and WASM/JS (and Ed25519-by-default per-block signatures) makes it a plausible longer-term grant format if KnoTrust wants caveat-based attenuation beyond flat JWT claims — but it's an additive/future consideration, not a blocker for the JWS recommendation above.

### Honest security claims by mode
| Mode | Honest revocation-latency claim |
|---|---|
| **(a) Pure local, zero network** | Bounded only by the grant's TTL. No mechanism — CRL, OCSP, or otherwise — beats this without new information reaching the verifier. Do not claim "instant" revocation in this mode. |
| **(b) Periodic control-plane bundle sync** | Latency ≈ configured sync interval + propagation delay; degrades gracefully back to (a)'s TTL-bound guarantee if the edge stays offline longer than that interval. |
| **(c) Always-reachable control plane** | Near-instant revocation is achievable, but this requires exactly the always-on backend that KnoTrust's default local-first mode explicitly rejects — only relevant to the optional team/enterprise control-plane mode. |

This gives a direct, defensible answer to PRD §21's open question ("Grant-cache revocation freshness — what security claim can we make?"): **the claim must be scoped by mode** — "revocation is TTL-bounded in local mode; in control-plane mode, revocation propagates within your configured sync interval" — never an unqualified "instant."

---

## 9. Sources

**Cedar / CNCF / Lean:**
- https://docs.cedarpolicy.com/
- https://docs.cedarpolicy.com/auth/authorization.html
- https://docs.cedarpolicy.com/schema/schema.html
- https://docs.cedarpolicy.com/policies/validation.html
- https://github.com/cedar-policy/cedar
- https://github.com/cedar-policy/cedar/blob/main/cedar-wasm/README.md
- https://raw.githubusercontent.com/cedar-policy/cedar/main/cedar-wasm/src/lib.rs
- https://github.com/cedar-policy/cedar/issues/1226
- https://github.com/cedar-policy/cedar/releases
- https://registry.npmjs.org/@cedar-policy/cedar-wasm
- https://www.npmjs.com/package/@cedar-policy/cedar-wasm
- https://app.unpkg.com/@cedar-policy/cedar-wasm@4.11.2/files/nodejs
- https://crates.io/api/v1/crates/cedar-policy
- https://crates.io/crates/cedar-policy-symcc
- https://lean-lang.org/use-cases/cedar/
- https://arxiv.org/pdf/2407.01688
- https://aws.amazon.com/blogs/security/migrating-from-open-policy-agent-to-amazon-verified-permissions/
- https://aws.amazon.com/blogs/opensource/cedar-joins-cncf-as-a-sandbox-project/
- https://www.cncf.io/projects/cedar/
- https://github.com/cncf/sandbox/issues/410
- https://github.com/cedar-policy/rfcs

**OPA / Rego:**
- https://github.com/open-policy-agent/opa/blob/main/LICENSE
- https://github.com/open-policy-agent/opa
- https://www.cncf.io/projects/open-policy-agent-opa/
- https://www.cncf.io/announcements/2021/02/04/cloud-native-computing-foundation-announces-open-policy-agent-graduation/
- https://blog.openpolicyagent.org/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371
- https://www.openpolicyagent.org/docs/integration
- https://www.openpolicyagent.org/docs/rest-api
- https://pkg.go.dev/github.com/open-policy-agent/opa/rego
- https://www.openpolicyagent.org/docs/wasm
- https://github.com/open-policy-agent/npm-opa-wasm
- https://www.npmjs.com/package/@open-policy-agent/opa-wasm
- https://github.com/open-policy-agent/npm-opa-wasm/commits/main
- https://www.openpolicyagent.org/ecosystem/by-feature/wasm-integration
- https://github.com/open-policy-agent/npm-opa-wasm/tree/main/examples/nodejs-app
- https://github.com/open-policy-agent/opa/blob/main/ADOPTERS.md

**Other engines:**
- https://github.com/cerbos/cerbos/blob/main/LICENSE
- https://github.com/cerbos/cerbos-sdk-javascript/blob/main/README.md
- https://www.cerbos.dev/blog/cerbos-pdp-v0-48-open-id-auth-zen-support-improved-query-plans-faster-bundle-loading
- https://www.cerbos.dev/blog/openid-authzen-is-official-cerbos-is-ready
- https://github.com/cerbos/cerbos/releases
- https://www.cerbos.dev/customers
- https://github.com/openfga/openfga/blob/main/LICENSE
- https://www.cncf.io/projects/openfga/
- https://github.com/openfga/js-sdk
- https://openfga.dev/docs/interacting/authzen
- https://github.com/openfga/authzen-interop
- https://auth0.com/blog/auth0s-openfga-open-source-fine-grained-authorization-system/
- https://github.com/openfga/community/blob/main/ADOPTERS.md
- https://github.com/osohq/oso
- https://web.archive.org/web/20250919072838/https://www.osohq.com/docs/oss/project/changelogs/2023-12-18.html
- https://web.archive.org/web/20260604044523/https://www.osohq.com/
- https://www.osohq.com/docs/oso-cloud-overview/oso-cloud-architecture
- https://github.com/authzed/spicedb/blob/main/LICENSE
- https://authzed.com/products/spicedb-enterprise
- https://www.npmjs.com/package/@authzed/authzed-node
- https://authzed.com/blog/some-assembly-required
- https://github.com/orgs/authzed/discussions/2320
- https://github.com/authzed/spicedb/releases
- https://authzed.com/customers/netflix
- https://github.com/casbin/node-casbin/blob/master/LICENSE
- https://github.com/casbin/node-casbin
- https://github.com/casbin/casbin-server
- https://incubator.apache.org/projects/casbin.html
- https://casbin.apache.org/users/

**AuthZEN:**
- https://openid.net/authorization-api-1-0-final-specification-approved/
- https://openid.net/specs/authorization-api-1_0.html
- https://github.com/openid/authzen/blob/main/api/authorization-api-1_0.md
- https://openid.github.io/authzen/
- https://openid.net/wg/authzen/specifications/
- https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/
- https://github.com/openid/authzen/blob/main/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md
- https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md
- https://github.com/openid/authzen/blob/main/interop/authzen-todo-backend/src/pdps.json
- https://openid.net/wg/authzen/

**Crypto — Part A (signing):**
- https://registry.npmjs.org/@noble/curves/latest
- https://registry.npmjs.org/@noble/ed25519/latest
- https://github.com/paulmillr/noble-curves
- https://github.com/paulmillr/noble-ed25519
- https://cure53.de/audit-report_noble-crypto-libs.pdf
- https://cure53.de/pentest-report_ed25519.pdf
- https://paulmillr.com/noble/
- https://registry.npmjs.org/libsodium-wrappers
- https://github.com/jedisct1/libsodium.js/
- https://pypi.org/project/PyNaCl/
- https://github.com/nodejs/node/pull/26554
- https://github.com/nodejs/node/pull/26611
- https://nodejs.org/docs/latest-v24.x/api/webcrypto.html
- https://caniuse.com/mdn-api_subtlecrypto_sign_ed25519
- https://blogs.igalia.com/jfernandez/2025/08/25/ed25519-support-lands-in-chrome-what-it-means-for-developers-and-the-web/
- https://registry.npmjs.org/jose/latest
- https://github.com/panva/jose
- https://pyjwt.readthedocs.io/en/stable/algorithms.html
- https://github.com/mpdavis/python-jose/issues/340
- https://pypi.org/project/Authlib/

**Crypto — Part B (serialization):**
- https://www.rfc-editor.org/rfc/rfc7515
- https://www.rfc-editor.org/rfc/rfc7519
- https://www.rfc-editor.org/rfc/rfc8785
- https://www.rfc-editor.org/rfc/rfc9052
- https://www.rfc-editor.org/rfc/rfc8032.html
- https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier
- https://pypi.org/project/cbor2/
- https://github.com/kriszyp/cbor-x
- https://www.npmjs.com/package/cborg
- https://www.npmjs.com/package/cose-js
- https://www.npmjs.com/package/@auth0/cose
- https://solana.com/docs/core/transactions/transaction-structure
- https://www.wireguard.com/protocol/

**Crypto — Part C (key management):**
- https://github.com/atom/node-keytar
- https://www.npmjs.com/package/@github/keytar
- https://github.com/Brooooooklyn/keyring-node
- https://man7.org/linux/man-pages/man1/ssh-keygen.1.html
- https://github.com/FiloSottile/age/issues/149
- https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html
- https://github.com/aws/aws-cli/issues/7369
- https://jedisct1.github.io/minisign/
- https://github.com/sigstore/cosign
- https://github.com/sigstore/fulcio
- https://github.com/sigstore/rekor
- https://www.w3.org/TR/webauthn-3/

**Crypto — Part D (revocation):**
- https://www.rfc-editor.org/rfc/rfc6749
- https://www.rfc-editor.org/rfc/rfc5280
- https://www.rfc-editor.org/rfc/rfc6960
- https://www.rfc-editor.org/rfc/rfc6066
- https://github.com/theupdateframework/specification/blob/master/tuf-spec.md
- https://theupdateframework.io/
- https://letsencrypt.org/2022/09/07/new-life-for-crls
- https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/
- https://research.google/pubs/pub41892/ (Macaroons paper)
- https://github.com/eclipse-biscuit/biscuit
- https://www.biscuitsec.org/docs/guides/revocation/
- https://www.biscuitsec.org/blog/joining-eclipse/

---

## 10. Open decisions for the orchestrator

1. **Does "bundled default PDP" mean the hand-rolled risk-tier evaluator only, or does Cedar-WASM ship inside the default `npx` package** (adding ~4.27 MB uncompressed WASM to the install)? This is the single biggest tension between the recommendation above and the "npx and go" minimalism the PRD emphasizes — needs an explicit call, ideally validated against a real measured install-size/cold-start budget.
2. **Positioning conflict:** PRD §2 states KnoTrust is "not a policy engine competing with Cerbos/Cedar/OPA/Oso." Embedding Cedar-WASM as a bundled default literally embeds one of those named engines. Does the messaging change to "ships with Cedar built in, plus adapters to OPA/Cerbos/others," or does Cedar stay adapter-only to preserve the current positioning, with the L0 hand-rolled evaluator remaining the *only* truly bundled default?
3. **AARP naming inconsistency:** the AuthZEN spec text itself abbreviates the profile "ARAP," not "AARP." KnoTrust's PRD and any public docs using "AARP" should be reconciled with the spec's own naming before this becomes a credibility issue with the AuthZEN working group audience the project is trying to court.
4. **AARP/COAZ are still Working Group Draft**, not Implementer's Draft, as of 2026-07-03. PRD §16 already gates enterprise GA on this — but is worth an explicit "last checked" tracking note somewhere in the repo, since this is exactly the kind of external dependency likely to change status during KnoTrust's own roadmap.
5. **Casbin as a second bundled-default candidate?** It's the only other engine surveyed that's genuinely embeddable pure-TS with no daemon — but has zero AuthZEN alignment. Worth a build/buy call: invest in a SARC-to-Casbin translation shim as an alternative path, or drop it from consideration in favor of Cedar-WASM alone?
6. **Should Oso be removed from KnoTrust's own comparative docs/marketing** (PRD §2's "Cerbos/Cedar/OPA/Oso" list)? Its OSS library is stalled/frozen and the company's surviving product is a different, non-AuthZEN, proprietary cloud offering — continuing to name it alongside Cedar/OPA/Cerbos may already be stale positioning.
7. **Pure-JS (`@noble/curves`) vs native WebCrypto for signing:** WebCrypto Ed25519 support only became universal across major browsers in May 2025 (Chrome/Edge). Standardize on pure-JS for maximum portability/auditability now, with WebCrypto as a later fast-path — or commit to a higher minimum Node/browser version and lean on native crypto sooner? Affects the minimum supported runtime versions KnoTrust commits to publicly.
8. **Grant size budget:** is the ~33% overhead of JWS/base64 acceptable given KnoTrust's own URL-mode elicitation pattern (which may embed grant/request state in a URL) and any future QR-code/offline-transfer use cases — or does a leaner custom-binary/COSE format need to be pulled forward from "later optimization" to "launch requirement"?
9. **Key storage default:** plain `0600` file at `~/.knotrust/identity.key` (zero extra native dependency, simpler cross-platform build matrix for `npx`) vs OS-keychain-by-default via `@napi-rs/keyring` (stronger at-rest protection, but adds a native/Rust-backed module to the dependency and build/release matrix of an `npx`-distributed CLI). Which does Phase 0 ship with?
10. **Revocation UX commitment:** what specific default bundle-sync interval (e.g., 5 minutes) should ship as KnoTrust's advertised "control-plane mode" revocation-latency claim, and how is the pure-local (TTL-bound only, no "instant revocation") case communicated so it can't be read as overclaiming under PRD §4's claims discipline?
11. **Cedar's CNCF Sandbox status (not yet Incubating/Graduated) vs OPA's CNCF Graduated status:** given KnoTrust's own R5 bus-factor/credibility concern (PRD §17) about depending on external projects, how much weight should Cedar's earlier-stage governance carry against its clearly superior Node-embedding story today? Worth revisiting as Cedar's CNCF status evolves.
