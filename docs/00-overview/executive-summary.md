# KnoTrust — Executive Summary

**Owner:** Avijit Sarkar · **Entity:** Kno2gether Labs Ltd (UK)
**Status:** Planning complete 2026-07-03 · Phase 0 ready to start pending owner countersign (see §9)
**Source of truth:** `knotrust_prd_v5.md` (product intent) + `docs/05-decisions/2026-07-03-decisions-brief.md` (ratified decisions — overrides the PRD where the two conflict). This summary distills both. If anything here appears to disagree with either, those two documents win, not this one.

---

## 1. What it is

KnoTrust is the portable, YOLO-proof, fully-audited control layer for what agents can actually do through MCP — hand agents real power on the action surface without flying blind.

It ships as three pieces around one shared decision core:

- an agentic **PEP** (policy enforcement point) — proxy + SDK — that intercepts MCP tool calls,
- an **AARP approval orchestrator** for the cases that need a human, and
- an **optional control plane** for teams (never required, never part of the OSS first-run).

Its claim is not that this space is empty — it isn't (§7). The claim is the **combination**: no existing product assembles all four of —

1. **cross-agent portability** (one artifact works across Claude, Codex, and any MCP-native agent),
2. **YOLO-survival enforced at the protocol seam** — not a client config-rewrite trick,
3. **AuthZEN-standards conformance with signed, durable grants**, and
4. a **local-first, zero-backend OSS core**.

Every competitor found in research has at most two of the four. That combination — not any single capability — is the product.

## 2. The problem & the wedge

- Agents now act, not just answer, and increasingly they act through MCP: Stripe, database servers, deploy servers, payment rails.
- People hand agents this power — often via `--dangerously-skip-permissions` / YOLO mode — and get burned: surprise bills, drained accounts, a dropped production table.
- Today's only two options are both bad:
  - a coarse OAuth scope granted once at connect time, or
  - a client that nags for approval on every call — which trains people to click "allow" blindly, then disable prompts entirely.
- Neither is zero trust and neither is portable: native client allowlists are per-client, per-call, un-auditable, and bypassed the moment YOLO mode is enabled.

**The wedge leads with capability unlock, not control:**

> "Stop re-approving the same safe calls. Stop the catastrophic ones cold. See everything your agent did — even in YOLO mode."

KnoTrust encodes a durable, risk-tiered, portable grant **once**, enforced server-side regardless of client approval mode, with an audit trail a client dialog never gives you. Security is the byproduct we deliver; the "unleash your agent safely" story is the headline. We never market "approve your agent's actions" — that reads as more friction, not less.

## 3. What it is NOT

- **Not a shell/file sandbox.** KnoTrust governs the MCP action surface only. A `psql DROP`, an `rm -rf`, or a runaway `curl` loop never becomes an MCP call, so an MCP proxy never sees it. A broadly-permissioned agent can also route around any gate — `Read(.env)` denied, then defeated by `cat .env` via Bash — because KnoTrust owns one surface, not "everything the agent can do."
- **Not a replacement for the OS sandbox.** The physical containment layer — Seatbelt/bubblewrap, disposable containers, no real credentials on unattended runs — is not KnoTrust's job. We recommend it; we do not pretend to replace it.
  - Mental model: the **sandbox is the wall** (what the agent *cannot* do); **KnoTrust is the policy-and-approval layer** on the MCP surface (when it pauses to check, tiers risk, requires a human, and records everything). Complementary layers, not substitutes.
- **MCP-surface-only at launch.** Shell-surface gating (client-native hooks, then a KnoTrust-managed OS sandbox broker) is a staged future on the same decision core — never a launch claim (§8, F1–F3).
- **Not marketed beyond what survives scrutiny.** The claim that ships: *"policy + human approval for MCP actions, enforced even in YOLO mode, portable across agents, fully audited."* Claims that die to one technical reply and must never ship: "run `--dangerously-skip-permissions` safely," "stops your agent deleting prod," "full power, zero risk," "replaces the sandbox," or anything containing "all."

## 4. Standards foundation (honest maturity)

| Standard | Maturity | What it means for us |
|---|---|---|
| **AuthZEN Authorization API 1.0** | **Final.** OpenID Foundation membership vote, published 2026-01-12. | The ratified core: the Subject/Action/Resource/Context (SARC) model every tool call maps into. Safe to build on without a fallback plan. |
| **AARP** (approval profile) | **Working Group Draft 1** — still actively edited (open PR as of 2026-07-02). Spec's own front matter self-abbreviates it "ARAP," an unresolved inconsistency in OIDF's own publishing, not ours. | We implement the approval lifecycle behind an internal orchestrator interface shaped like AARP's flow. Wire-format conformance is a tracked compatibility task, not a foundation — the draft can move without touching our core. |
| **COAZ** (MCP tool-authorization profile) | **Working Group Draft 1**, same immaturity tier as AARP. | Gives us the SARC mapping rule (human principal = `subject`, agent identity = `context.agent`, never merged) and the `x-coaz-mapping` extension. Adopted now, kept behind an adapter. |
| **MCP protocol** | Stable baseline **2025-11-25** (current spec, official SDK). The **2026-07-28 revision is a Release Candidate, not final** — stateless core, header-based routing, Multi Round-Trip Requests. | We build the flagship on 2025-11-25 semantics and absorb the RC behind an internal `SpecAdapter`/transport interface as it finalizes. The RC never gates the launch. |

Neither AARP nor COAZ is at Implementer's Draft yet, so the PRD's own enterprise spec-maturity gate (AARP/COAZ ≥ Implementer's Draft, MCP 2026-07-28 shipped, plus a third-party security audit) is **not currently met** — which is correct and expected, since enterprise is Phases 4–5.

## 5. Architecture in 10 lines

1. **Surfaces** are plugins into one shared core: stdio proxy (flagship, ship first), streamable HTTP proxy, TypeScript then Python SDK, sidecar (on demand).
2. Every surface emits a **DecisionRequest** — a versioned internal contract (SARC + surface metadata) — the *only* way any surface reaches the core.
3. The **core** (`@knotrust/core`, pure TypeScript) holds the risk-tier evaluator, grant verifier, precedence engine, and decision cache.
4. The core consults a **PDP layer**: a built-in L0 evaluator by default, Cedar-WASM opt-in, or an external adapter (generic AuthZEN HTTP, or OPA REST).
5. Escalations reach the **AARP-shaped approval orchestrator**: `requested → pending → approved | denied | expired | cancelled`.
6. Approval is **channel-plural**: form-mode elicitation, URL-mode elicitation to a localhost approval page, or a block-and-wait fallback that works on every client regardless of elicitation support.
7. Every decision — allow, deny, cache hit, or escalation — appends to a hash-chained **audit log**, exportable via OpenTelemetry (SigNoz as the reference receiver).
8. **Local mode:** the cache *is* the store, no backend. **Team/enterprise mode:** an optional control plane syncs signed policy/grant bundles, approvals, and audit to edges — by `personal` or `org` scope, from the schema on day one.
9. Only cache misses and escalations consult policy; only `critical` escalations reach a human — the thin edge resolves the common case fast.
10. **Fail-closed by default**; fail-open is per-class, explicit, and audited every time it fires.

## 6. Decision outcomes, the grant primitive, risk tiers

**Four decision outcomes:** `allow` | `deny` | `pending_approval` | `deferred_not_eligible`.
- `pending_approval` carries an approval handle that maps to the AARP task handle (encoded into `requestState` on stateless HTTP).
- `deferred_not_eligible` covers cases like a critical action attempted mid-voice-call, where synchronous approval would degrade the call — making "this isn't eligible right now" a first-class outcome, not a failure.
- Denials return a structured tool result (`isError: true`), not a raw JSON-RPC protocol error, so the agent can adapt conversationally; protocol errors are reserved for malformed traffic.

**The grant** is the core primitive: `{principal, agent, tool, resource scope, conditions, risk tier, granted_by, expiry, single_use}`, signed (Ed25519 → JWS Compact).
- Pre-authorization = a durable grant. Runtime approval = an ephemeral single-use grant. A grant is a pre-satisfied prerequisite.
- Grants cannot self-escalate; the admin policy envelope is always the outer bound, regardless of what a user pre-authorized.

**Risk tiers:** `routine | sensitive | critical` drive the decision path and fail-open/closed behavior.
- Tiers are *seeded* from MCP tool annotations (`readOnly`/`destructive`) but never trusted blindly — the MCP spec itself warns against trusting annotations from untrusted servers.
- Annotations produce *suggested* tiers in generated config; policy packs and explicit config override; unannotated destructive-looking tools default to `sensitive` or higher.

## 7. Competitive position

The niche is contested, not empty — this is the honest correction to the PRD's original "no portable layer exists" framing (retired; see the decisions brief §C1).

| Product | Category | Closest overlap | The gap we differentiate on |
|---|---|---|---|
| **Microsoft Agent Governance Toolkit** | OSS (MIT), cross-framework governance toolkit | Broadest feature-set match: policy + trust-scoring + quorum approval + audit, MCP-aware | Proprietary policy/risk model, no confirmed AuthZEN/SARC conformance; Microsoft-controlled repo, not yet foundation-neutral |
| **Runlayer** | Commercial, $42M raised, cross-client gateway | Named enterprise customers, genuine cross-client positioning | Approval-workflow mechanics ambiguous in public materials; no OSS/self-host path; no confirmed standards conformance |
| **Preloop** | OSS (Apache 2.0), config-rewrite proxy across 9 clients | Architecturally the closest analog to KnoTrust's design | Bypass-resistance depends on the client not reverting its own config rewrite — not a protocol-level guarantee; proprietary CEL/YAML policy, no signed grants |
| **Peta** | HITL desktop approval console | The closest existing product to our approval-app UX | OSS/licensing status unverified; no AuthZEN/SARC or interoperability standard |
| **IBM mcp-context-forge** | OSS (Apache 2.0), gateway + registry | Real, shipped human-approval workflow at 160K+-user scale (IBM Consulting Advantage) | IBM explicitly disclaims it as "not officially supported for production"; no standards conformance or signed-grant model |

None of the five combines standards conformance, signed durable grants, protocol-seam YOLO-survival, and a local-first OSS core. Full dossier: `docs/01-research/product-profiles/` (28 profiles, including PDPs, frameworks, and native clients surveyed as context, not just direct competitors). Market-level analysis: `docs/01-research/competitive-and-packaging.md`.

## 8. Roadmap at a glance

| Phase | Focus |
|---|---|
| **0 — Dogfood** | Core + signed grant model + stdio proxy; protect OpenClaw and a local Knotie MCP path end-to-end; HTTP-proxy spike against the 2026-07-28 RC in parallel; golden test vectors for cross-language parity. |
| **1 — OSS launch (flagship)** | Claude Desktop stdio proxy; block-and-wait approval with elicitation as progressive enhancement; local mode; default PDP + OPA/Cedar adapters; first preset packs; killer README + launch video with an explicit "what KnoTrust is not" section. |
| **2 — HTTP + voice** | Stateless HTTP proxy in Knotie/Knova; async push/SMS approval; the `deferred_not_eligible` outcome; foundation for the multi-tenant control plane. |
| **3 — SDK + widen** | TypeScript then Python SDK; published adapter interface; first Tier-2 framework adapters; community preset packs. |
| **4 — Commercial** | Managed multi-tenant control plane; hosted approval app; SLA. |
| **5 — Enterprise** | SSO/SCIM, immutable audit + SOC 2/ISO, policy GUI, delegation/break-glass, AI decision engine — behind the spec-maturity gate and a third-party security audit. |
| **F1 — Desktop app** (staged, MCP-surface still) | Policy manager + approval UI + local grant cache + agent launcher; syncs personal-scope policy across a user's machines. |
| **F2 — Shell gating via client-native hooks** (staged, soft) | Wires Claude Code / Codex approval hooks into the same decision core; per-client, application-level, not a hard wall. |
| **F3 — OS sandbox broker** (staged, hard) | A KnoTrust-managed sandbox brokering file/exec/network decisions to the policy core — the boundary the agent can't route around; requires elevated privileges and raises threat-model stakes accordingly. |

F1–F3 are deliberately staged on the surface-agnostic core, never implied at launch — see §3.

## 9. Current status

Planning is complete as of 2026-07-03: PRD v5 is cleared for Phase 0, and the decisions brief has resolved every PRD open question and recorded every research-forced deviation.

**Phase 0 is ready to start pending the owner's countersign of the decisions brief's §H items:**
1. the C1 rewording of external positioning (the combination claim),
2. the "Requestable Denial" terminology shift in docs,
3. the Node ≥ 22 floor, and
4. the B4 pricing lean (non-binding, noted only).

None of these block writing Phase 0 code. The one true action item — a `knotrust` npm-name and trademark check — is due before Phase 1 launch, not before Phase 0.

## 10. Governance & the bus-factor question

A security-relevant dependency owned by a small company is a first-class trust problem, not a footnote. Our mitigations: Apache 2.0 core + self-host, so nobody is stranded — fork it; standards-based replaceability, so any AuthZEN PEP can be swapped in; a public roadmap and open governance rather than a black box; and honesty about the §3 boundary, which is itself a credibility asset with the developer and CISO audiences we're courting. Vendor absorption (R6 in the PRD) is an accepted, watched risk, not a solved one — see §7 for why the niche stays defensible even as MCP vendors harden their own connection-level auth.

## 11. Related documents

- `knotrust_prd_v5.md` — full product requirements (v5), the intent behind every decision here.
- `docs/05-decisions/2026-07-03-decisions-brief.md` — every ratified decision and every PRD deviation, with rationale.
- `docs/README.md` — the docs-repo map, source-of-truth chain, and reading order for other audiences.
- `docs/01-research/` — the four standards/market research reports and the 28-profile competitive dossier this summary draws from.
