# AuthZEN, AARP, and COAZ — Standards Research

**Purpose:** Verify (and correct where needed) the AuthZEN-related claims in `knotrust_prd_v5.md` against primary sources, and give KnoTrust engineering a precise, cited picture of what is safe to build against today vs. what is still moving.

**Research date:** 2026-07-03. **Method:** Five independent research passes fetched primary sources directly (openid.net, github.com/openid/authzen raw files, openid.github.io/authzen, IETF datatracker) rather than relying on search-engine summaries; findings were cross-checked across passes. Every claim below is followed by its source URL. Where a claim could not be verified against a primary source, that is stated explicitly rather than inferred.

---

## Executive summary — corrections to the PRD's claims

The PRD (`knotrust_prd_v5.md:6`) states: *"Built on: OpenID AuthZEN (Authorization API 1.0 final; AARP + COAZ profiles)"* — bundling three artifacts together under one maturity implication. This is **partially accurate and partially misleading**:

| PRD claim | Verdict | Correction |
|---|---|---|
| "Authorization API 1.0 final" | **Correct.** | Confirmed OpenID Foundation Final Specification, approved by membership vote, published 11 Jan 2026. |
| "AARP ... profiles" bundled as if same maturity as 1.0 | **Materially overstated.** | AARP is a **Working Group Draft, "Draft 1"**, published/merged 2 June 2026 — two tiers below Final (Draft → Implementer's Draft → Final), and still under active, unsettled editing (open PR as of 2 Jul 2026). It is **not** part of "Authorization API 1.0" — it's a separate profile document. |
| "COAZ ... profiles" bundled as if same maturity as 1.0 | **Materially overstated.** | COAZ is also a **Working Group Draft, "Draft 1"**, published 13 Feb 2026 — same immature tier as AARP, not yet cross-listed on the WG's own specifications index page. |
| "AARP" as the profile's name | **Naming inconsistency found in the primary sources themselves.** | The spec file's own front matter self-declares `abbrev: "ARAP"` ("AuthZEN Access Request and Approval Profile"), not "AARP." The OpenID Foundation's own blog post and WG specifications page use "AARP." Both names trace to the same OIDF-linked material — this is an unresolved inconsistency in OIDF's own publishing, not an invented term. See §3 below. |
| "`deny-with-prerequisite`" as an AuthZEN term | **Not a spec term.** | This exact phrase appears nowhere in any AuthZEN primary source. The spec's own term for the equivalent concept is **"Requestable Denial."** Fine as KnoTrust's internal/product vocabulary, just don't present it as spec-native. |

The PRD's own §14 ("Enterprise tier is gated on spec stabilization... AuthZEN Authorization API 1.0 is final (✅); enterprise GA additionally requires COAZ/AARP at ≥ Implementer's Draft") already reflects awareness that COAZ/AARP are pre-Implementer's-Draft — that gating logic is **correct and should be kept**; it's the top-line PRD summary line (`:6`) that overstates maturity by bundling all three together.

---

## 1. AuthZEN Authorization API 1.0 — status and core model

### 1.1 Standardization status: **Final Specification** (confirmed)

The OpenID Foundation announced Final Specification approval on **12 January 2026**:

> "The OpenID Foundation membership has approved the following as an OpenID Final Specification: Authorization API 1.0 ... A Final Specification provides intellectual property protections to implementers of the specification and is not subject to further revision. ... The voting results were: Approve – 81 votes, Object -- 1 vote, Abstain – 25 votes. Total votes: 107 (out of 378 members = 28.3% > 20% quorum requirement)"
> — https://openid.net/authorization-api-1-0-final-specification-approved/

The spec document itself (fetched directly) carries this metadata in lieu of a classic "Status of This Document" boilerplate section:

> "Workgroup: OpenID AuthZEN / Published: 11 January 2026 / Status: Final / Authors: O. Gazitt, Ed. (Aserto), D. Brossard, Ed. (Axiomatics), A. Tulshibagwale, Ed. (SGNL)"
> — https://openid.net/specs/authorization-api-1_0.html

**Version/maturity history** (all URLs confirmed live on the WG specifications index, https://openid.net/wg/authzen/specifications/):

| Draft | Maturity | URL |
|---|---|---|
| draft 00 | Superseded draft (Identiverse 2024 interop target) | `/specs/authorization-api-1_0-00.html` |
| draft 01 | **Implementer's Draft** (approved 15 Nov 2024) | `/specs/authorization-api-1_0-01.html` |
| draft 02 | Draft — adds `/evaluations` (boxcarred/batch) | `/specs/authorization-api-1_0-02.html` |
| draft 03 | Draft — adds subject/resource/action search APIs | `/specs/authorization-api-1_0-03.html` |
| draft 05 | Public-review draft (23 Oct – 22 Dec 2025) | `/specs/authorization-api-1_0-05.html` |
| (un-suffixed) | **Final Specification** (11 Jan 2026) | `/specs/authorization-api-1_0.html` |
| current | Living/editor's draft (textually identical to Final as of this research, only date/status differ) | https://openid.github.io/authzen |

The Implementer's Draft milestone (Nov 2024) is itself independently confirmed:

> "Published November 15, 2024. The OpenID Foundation membership has approved the following AuthZEN specifications as an OpenID Implementer's Draft: Authorization API 1.0 Implementer's Draft ... Approve – 82 votes, Object - 2 votes, Abstain – 22 votes."
> — https://openid.net/authzen-authorization-api-1-0-implementers-draft-approved/

An **archived, unpublished 1.1 draft** exists in the repo (`archive/authorization-api-1_1_01.md`) but has no `openid.net/specs` URL and is not referenced from the WG page — its standing could not be verified beyond "exists in the repo's archive directory." (https://github.com/openid/authzen/blob/main/archive/authorization-api-1_1_01.md)

**Verdict: the PRD's claim that "Authorization API 1.0 is final" is correct and well-supported.**

### 1.2 Core model: Subject / Action / Resource / Context

**Note on terminology:** the spec itself never uses the acronym "SARC." It defines an "Information Model" of five entities — Subject, Action, Resource, Context, and Decision:

> "5. Information Model — The information model for requests and responses include the following entities: Subject, Action, Resource, Context, and Decision."
> — https://openid.net/specs/authorization-api-1_0.html §5

"SARC" is downstream shorthand (also used by the AuthZEN community itself in the COAZ spec text, see §4) for Subject-Action-Resource-Context — safe to use as KnoTrust's internal name for the model, just note it isn't the spec's own defined term.

**Field definitions, verbatim:**

> "**Subject**: A Subject is the user or machine principal about whom the Authorization API is being invoked... A Subject is an object that contains two REQUIRED keys, `type` and `id`, which have a string value, and an OPTIONAL key, `properties`, with a value of an object."
>
> "**Resource**: A Resource is the target of an access request. It is an object that is constructed similar to a Subject entity." (REQUIRED `type`, `id`; OPTIONAL `properties`)
>
> "**Action**: An Action is the type of access that the requester intends to perform. Action is an object that contains a REQUIRED `name` key with a string value, and an OPTIONAL `properties` key with an object value."
>
> "**Context**: The Context represents the environment of the access evaluation request. Context is an object which can be used to express attributes of the environment."
>
> "**Decision**: A Decision is the result of the evaluation of an access request... Decision is an object that contains a REQUIRED `decision` key with a boolean value, and an OPTIONAL `context` key with an object value."
> — https://openid.net/specs/authorization-api-1_0.html §5.1–5.5

### 1.3 Endpoints — single vs. batch vs. search

Exact endpoint table from the spec:

> Table 1: API Endpoint Overview
> | API Endpoint | Default Path | Metadata Parameter |
> |---|---|---|
> | Access Evaluation | `/access/v1/evaluation` | `access_evaluation_endpoint` |
> | Access Evaluations | `/access/v1/evaluations` | `access_evaluations_endpoint` |
> | Subject Search | `/access/v1/search/subject` | `search_subject_endpoint` |
> | Resource Search | `/access/v1/search/resource` | `search_resource_endpoint` |
> | Action Search | `/access/v1/search/action` | `search_action_endpoint` |
> — https://openid.net/specs/authorization-api-1_0.html §10.1 (Table 1)

There is genuinely a single-evaluation endpoint **and** a separate batch endpoint:

> "6. Access Evaluation API — ...defines the message exchange pattern between a PEP and a PDP for executing a **single** access evaluation."
>
> "7. Access Evaluations API — ...defines the message exchange pattern between a PEP and a PDP for evaluating **multiple** access evaluations within the scope of a single message exchange (also known as 'boxcarring' requests)."
> — https://openid.net/specs/authorization-api-1_0.html §6, §7

Batch semantics are controlled by `options.evaluations_semantic` ∈ `{execute_all, deny_on_first_deny, permit_on_first_permit}` (§7.1.2.1). There are also three distinct **search** endpoints (subject/resource/action) that return lists, not decisions — a third category beyond single/batch evaluation.

### 1.4 JSON schemas (verbatim, from the repo's schema files)

`api/schemas/evaluation-request.schema.json` (https://github.com/openid/authzen/blob/main/api/schemas/evaluation-request.schema.json):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "authzen-evaluation-request",
  "title": "Access Evaluation API Request",
  "type": "object",
  "required": ["subject", "resource", "action"],
  "properties": {
    "subject": { "type": "object", "required": ["type", "id"], "properties": {"type": {"type": "string"}, "id": {"type": "string"}, "properties": {"type": "object"}} },
    "resource": { "type": "object", "required": ["type", "id"], "properties": {"type": {"type": "string"}, "id": {"type": "string"}, "properties": {"type": "object"}} },
    "action": { "type": "object", "required": ["name"], "properties": {"name": {"type": "string"}, "properties": {"type": "object"}} },
    "context": { "type": "object" }
  },
  "additionalProperties": false,
  "examples": [
    {
      "subject": {"type": "user", "id": "alice@acmecorp.com"},
      "resource": {"type": "account", "id": "123"},
      "action": {"name": "can_read", "properties": {"method": "GET"}},
      "context": {"time": "1985-10-26T01:22-07:00"}
    }
  ]
}
```

`api/schemas/evaluation-response.schema.json` (https://github.com/openid/authzen/blob/main/api/schemas/evaluation-response.schema.json):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "authzen-evaluation-response",
  "title": "Access Evaluation API Response",
  "type": "object",
  "required": ["decision"],
  "properties": {
    "decision": { "description": "A boolean value that specifies whether the Decision is to allow or deny the operation.", "type": "boolean" },
    "context": {
      "type": "object",
      "required": ["id"],
      "properties": {
        "id": {"type": "string"},
        "reason_admin": {"type": "object"},
        "reason_user": {"type": "object"}
      },
      "additionalProperties": false
    }
  }
}
```

**Exact wire example** from the spec (non-normative, §10.1.4):

```
POST /access/v1/evaluation HTTP/1.1
Host: pdp.example.com
Content-Type: application/json
Authorization: Bearer <myoauthtoken>
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{
  "subject": { "type": "user", "id": "alice@example.com" },
  "resource": { "type": "todo", "id": "1" },
  "action": { "name": "can_read" },
  "context": { "time": "1985-10-26T01:22-07:00" }
}
```
```
HTTP/1.1 OK
Content-Type: application/json
X-Request-ID: bfe9eb29-ab87-4ca3-be83-a1d5d8305716

{ "decision": true }
```
— https://openid.net/specs/authorization-api-1_0.html §10.1.4

**The decision is a bare boolean**, not an object — with an optional sibling `context` for anything else:

> "In this specification, assuming the evaluation was successful, there are only two possible values for the `decision`: `true`: The access request is permitted to go forward... `false`: The access request is denied and MUST NOT be permitted to go forward."
> — https://openid.net/specs/authorization-api-1_0.html §5.5

> "A successful request that results in a 'deny' is indicated by a 200 OK status code with a `{ "decision": false }` payload."
> — https://openid.net/specs/authorization-api-1_0.html §10.1.2 (i.e., denial is not an HTTP error — it's a 200 with `decision: false`)

Deny-with-reason example (§5.5.2.1):
```json
{
  "decision": false,
  "context": {
    "reason_admin": { "403": "Request failed policy C076E82F" },
    "reason_user": { "403": "Insufficient privileges. Contact your administrator" }
  }
}
```

Batch (`/access/v1/evaluations`) response shape (§7.2):
```json
{
  "evaluations": [
    { "decision": true },
    { "decision": false, "context": { "error": {"status": 404, "message": "Resource not found"} } },
    { "decision": false, "context": { "reason": "Subject is a viewer of the resource" } }
  ]
}
```

A real interop test fixture from the repo confirms this shape is exercised in practice, not just documented (https://github.com/openid/authzen/blob/main/interop/authzen-todo-backend/test/decisions.json):

```json
{
  "request": {
    "subject": { "type": "user", "id": "rick@the-citadel.com" },
    "action": { "name": "can_read_user" },
    "resource": { "type": "user", "id": "beth@the-smiths.com" }
  },
  "expected": true
}
```

**Maturity: Final Specification. Confidence: High** (all quotes independently pulled from the raw spec file and cross-checked against the rendered HTML).

---

## 2. PEP / PDP / PIP / PAP roles

AuthZEN's own Terminology appendix defines **only PDP and PEP** — it does not define PIP or PAP anywhere in the spec body (confirmed by full-text search of the document; zero matches).

> "**PDP**: Policy Decision Point. The component or system that provides authorization decisions over the network interface defined here as the Authorization API.
>
> **PEP**: Policy Enforcement Point. The component or system that acts as a client to the PDP. The most common use case for a PEP is to request decisions and enforce access based on the decisions obtained from the PDP. It can also request decisions or search results for other purposes, such as determining which resources a subject may have access to."
> — https://openid.net/specs/authorization-api-1_0.html, Appendix A ("Terminology")

The spec's Model section (§2) gives the operative definitions used throughout the document, and is explicit that PDP internals (policy language, architecture, state) are **out of scope**:

> "By convention, we refer to a service that implements this API as a Policy Decision Point, or PDP. The policy language, architecture, and state management aspects of a PDP are beyond the scope of this specification. ... By convention, we refer to a client of the Authorization API as a Policy Enforcement Point, or PEP."
> — https://openid.net/specs/authorization-api-1_0.html §2

The Introduction explicitly grounds PDP/PEP in XACML and NIST ABAC:

> "Computational services often implement access control within their components by separating Policy Decision Points (PDPs) from Policy Enforcement Points (PEPs). PDPs and PEPs are defined in XACML ([XACML]) and NIST's ABAC SP 800-162 ([NIST.SP.800-162])."
> — https://openid.net/specs/authorization-api-1_0.html §1

**PIP and PAP are absent from the Authorization API 1.0 spec entirely** — this is a deliberate scoping choice (the spec explicitly disclaims PDP-internal architecture as out of scope), not an oversight. The WG's own **charter**, however, does name all four XACML roles as an *aspiration* for the WG's broader mission (not as something the 1.0 API spec itself defines):

> "'Be the OAuth2/OIDC/SAML of authZ' by: ... Define and formalize interoperable communication patterns between major authZ components, for example PAP, PDP, PEP, and PIP."
> — https://openid.net/wg/authzen/charter/

**Mapping onto KnoTrust:**

| Role | AuthZEN definition | KnoTrust mapping |
|---|---|---|
| **PEP** | "Policy Enforcement Point... acts as a client to the PDP... requests decisions and enforces access." | KnoTrust's proxy/SDK. It intercepts each MCP `tools/call`, maps it to a SARC request, calls the evaluation endpoint, and enforces the returned decision (block/allow the tool call). This is squarely and exactly what the spec defines a PEP to be — no interpretive stretch needed. |
| **PDP** | "Provides authorization decisions... policy language, architecture, and state management... beyond the scope of this specification." | Explicitly pluggable per the spec's own design intent — Cedar-based, OPA, a bundled default engine, or any third-party AuthZEN-conformant PDP. The spec's deliberate PDP-internals-agnosticism is *why* KnoTrust's "PDP-agnostic, rip-and-replace with any AuthZEN PEP/PDP" positioning is standards-accurate, not just marketing. |
| **PIP** | Not defined by AuthZEN. | Not a spec-defined role KnoTrust needs to satisfy an interface for. Conceptually, KnoTrust's context-enrichment logic (pulling session/JWT claims, tool metadata, risk-tier annotations into the `context` object before evaluation) plays a PIP-like role, but there is no AuthZEN wire contract for it — this is entirely internal to KnoTrust/the chosen PDP. |
| **PAP** | Not defined by AuthZEN. | Not a spec-defined role. KnoTrust's policy-authoring UI/config (for the bundled default PDP) or the third-party PDP's own admin console plays this role, again with no AuthZEN wire contract governing it. |

**Maturity: Final Specification (for PDP/PEP definitions). PIP/PAP: not defined by AuthZEN at all — sourced only from the WG charter's aspirational language, not the ratified spec.**

---

## 3. AARP — "Authorization API Approvals" / deny-with-prerequisite

### 3.1 Does it exist, and under what name?

**Yes — a real, dated, WG-endorsed artifact exists for this exact concept, but there is a genuine, unresolved naming discrepancy in OIDF's own material.**

The OpenID Foundation's blog post (published 2026-06-15) announces:

> "AuthZEN Working Group approves AARP and COAZ - new standards defining how applications, agents, and governance platforms coordinate authorization prerequisites... the AuthZEN Access Request and Approval Profile (AARP) and ... Model Context Protocol Tool Authorization (COAZ) official Working Group Drafts."
> "The AARP draft addresses a challenge that is becoming central as applications, services, and AI systems grow more autonomous: what should happen when policy cannot authorize an action yet, because a prerequisite must first be satisfied."
> "This is to authorization prerequisites what Client-Initiated Backchannel Authentication (CIBA) is to authentication approval."
> — https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/

**However, the normative spec document itself self-declares a different abbreviation.** Its RFC-style front matter (`profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md`), verified from the file's first commit through the current `main` branch:

```
title: "AuthZEN Access Request and Approval Profile - Draft 1"
abbrev: "ARAP"
```
— https://github.com/openid/authzen/blob/main/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md

A full-text grep of the ~2,098-line spec body found **zero occurrences of "AARP"** anywhere in the document — the spec calls itself ARAP throughout. This is corroborated by a live community GitHub issue (opened 2026-06-10, five days *before* the OIDF blog post) that already uses "ARAP":

> Issue #520, "ARAP does too many things" — "Although I definitively see the value of a protocol for requesting access dynamically, the proposed ARAP profile does too much..."
> — https://github.com/openid/authzen/issues/520

No commit, PR, or issue documenting an intentional rename (in either direction) was found. **Conclusion: "AARP" (used by the OIDF blog post and the WG specifications page) and "ARAP" (used by the spec's own front matter, its author, and the community issue thread) refer to the same single document — this is an internal OIDF naming inconsistency, not two different artifacts, and not a case of "AARP doesn't exist."** KnoTrust should keep using "AARP" for external/product communication (matching the OIDF blog and WG page, which is what most readers will search for) but should internally note the spec file itself says "ARAP," in case future tooling, citations, or spec URLs use that string instead.

**Authorship/provenance:** authored by Karl McGuinness, added via PR #508 ("Add AuthZEN Access Request and Approval Profile 1.0 (WG draft)," merged 2026-06-02), with a metadata fix in PR #515 (merged 2026-06-03) marking it as an official OIDF-stream Working Group Draft (not an IETF submission). As of 2026-07-02 an open PR (#541) was still actively reworking the document — direct evidence this is genuinely unsettled, in-motion work, not a stable draft.

### 3.2 The actual mechanics (not "deny-with-prerequisite" — "Requestable Denial")

The literal phrase **"deny-with-prerequisite" does not appear anywhere** in the spec, the OIDF blog post, or the GitHub issue thread — verified by full-text search of all three. The spec's own decision model is **explicitly still boolean, not three-valued**:

> "The profile preserves the AuthZEN Authorization API decision model: a denied decision remains a denial and MUST NOT be treated as access."
> — https://github.com/openid/authzen/blob/main/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md

The spec's own term for the mechanism is **"Requestable Denial"**:

> "**Requestable Denial**: An AuthZEN Authorization API Decision with `decision` set to `false` and a Decision Context indicating that the denied access can be requested through an Access Request Endpoint."
> "The presence of `context.access_request` is the signal that the denial is requestable."
> — same source

**Lifecycle of a prerequisite** (from the spec's Task Status Values / State Transitions sections):

1. PEP evaluates access via the normal `/access/v1/evaluation` call.
2. PDP returns `{"decision": false, "context": {"access_request": {...}}}` — a Requestable Denial.
3. PEP submits a request to a dedicated **Access Request Endpoint**, receiving an opaque **Task Handle** for the asynchronous workflow.
4. The Task resolves via polling or callback, tracked through a defined status enum:

> "**Task Status Values**: `pending`: The request has been accepted and is awaiting processing or approval. `approved`: The request was approved. Approval does not by itself grant access unless accompanied by a result that can be enforced under [completion semantics]. `denied`: The request was denied by the approval workflow. `expired`: The request expired before completion. `cancelled`: The request was cancelled by the requester, approver, administrator, or system. `failed`: The request could not be completed due to an error. `partial`: All items in a bulk task... reached terminal status, but with mixed outcomes... Implementations MAY define additional status values."
> — same source

5. Once resolved, the PEP re-evaluates via a fresh, ordinary AuthZEN call — the PDP remains authoritative; approval alone does not bypass re-evaluation.

The spec explicitly frames both human and automated evaluators as valid resolvers:

> "A gateway acting as a PEP for an internal API encounters a user attempting an operation that requires elevated authority their standing role does not grant. The deployment expects the gateway to route the request to an owner for approval rather than refuse the call outright."
> "...whether that evaluator is human (an owner, approver, or delegate), automated (a policy engine, risk engine, or rule-based evaluator), or a combination of the two."
> — same source

**Delegation/actor fields relevant to KnoTrust's grant model** are also defined in this same document (§10.1):

> "`client.actor`: OPTIONAL. Object identifying the immediate actor on whose behalf the PEP submits the Access Request, when that actor differs from the Subject... `type`: OPTIONAL. String. Actor category, such as `user`, `service`, `workload`, or `ai_agent`."
> "`act`: OPTIONAL. Object. Nested actor representing the next link in a delegation chain, following the conventions in [I-D.mcguinness-oauth-actor-profile]."
> — https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html §10.1

That referenced delegation-chain convention is itself deferred to a *separate, non-AuthZEN* individual OAuth WG Internet-Draft, `draft-mcguinness-oauth-actor-profile-00` (dated 2026-04-30, expires 2026-11-01) — https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/ — i.e., AARP does not itself define delegation semantics; it points at unratified OAuth work-in-progress for that piece.

**"Step-up authorization"** appears only in the spec's front-matter keyword list, not elaborated as a distinct mechanism in the body text reviewed.

### 3.3 Maturity

**Working Group Draft, "Draft 1."** Published/merged 2 June 2026, still under active editing as of 2 July 2026 (open PR #541). Not yet an Implementer's Draft, not yet Final, and **not yet cross-listed on the WG's canonical specifications index page** (`openid.net/wg/authzen/specifications/`, confirmed via direct fetch to be missing any AARP/ARAP reference at time of research) — it currently exists only as a GitHub-hosted rendered page (openid.github.io) and the OIDF blog announcement.

**Verdict on the PRD's "deny-with-prerequisite (AARP)" terminology (`knotrust_prd_v5.md:68`):** the underlying concept is real and closely matches the spec's "Requestable Denial" mechanism — this is a legitimate design to build toward — but (a) it is very early-stage (WG Draft, actively being rewritten), (b) the exact PRD phrase isn't the spec's own term, and (c) the spec's own abbreviation is ARAP, creating a citation risk if OIDF's blog naming and the spec's self-declared naming diverge further or get reconciled in a future revision.

---

## 4. COAZ

### 4.1 Identification: confirmed

**COAZ = "Compatible with OpenID AuthZen"** (pronounced "cozy"), the informal name of the **"AuthZEN Profile for Model Context Protocol Tool Authorization"** — a Working Group Draft that defines how an MCP tool server maps a `tools/call`'s arguments/session token into the AuthZEN SARC model. This is confirmed across three independent sources:

1. **Origin proposal**, `modelcontextprotocol/ext-auth` issue #15 (opened 2026-02-06 by Atul Tulshibagwale, SGNL):
   > "COAZ (pronounced "cozy") stands for "Compatible with OpenID AuthZen". This SEP introduces `coazMapping`, an extension to the MCP `Tool` definition's `inputSchema`... to map tool arguments and session tokens to the OpenID AuthZEN Subject-Action-Resource-Context (SARC) model."
   > — https://github.com/modelcontextprotocol/ext-auth/issues/15

2. **The adopted spec text** (`profiles/authzen-mcp-profile-1_0.md`, front matter `abbrev: "coaz"`, dated 2026-02-13, authors A. Tulshibagwale (SGNL) and A. Olivier (Cerbos)):
   > "This specification defines a profile of the OpenID AuthZen Authorization API for use with the Model Context Protocol (MCP). It introduces COAZ (Compatible [with OpenID AuthZen])..."
   > "For COAZ tools, the `inputSchema` object MUST include an `x-coaz-mapping` field..."
   > — https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md

3. **OpenID Foundation's official announcement** (2026-06-15):
   > "COAZ draft adds a profile for standardizing the mapping from different source information models into the AuthZEN Subject-Action-Resource-Context (SARC) structure... to enable Model Context Protocol tools to expose the authorization checks required to call a tool to bring a control to agentic workflows."
   > — https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/

**Note of caution:** there were at least two distinct, independently-authored proposals converging on this problem space — the `ext-auth` #15 COAZ design (tool-schema-level `x-coaz-mapping`), and a separate `openid/authzen` issue #429, "AuthZEN MCP Profile Proposal" (M. Besozzi, opened 2026-02-04), which never uses the term "COAZ" and covers a differently-scoped gateway/JSON-RPC-level mapping. The shipped WG Draft's title matches #429's phrasing but its technical content (`coaz` field, `x-coaz-mapping`) matches #15's design. No explicit source documents how these two threads merged — **this convergence is inferred from the documents, not confirmed by an explicit statement**, though the end artifact and its "COAZ" name/content are solidly confirmed.

### 4.2 Mapping MCP tool calls → SARC per COAZ

The profile requires the MCP tool's `inputSchema` to carry an `x-coaz-mapping` object whose values are [CEL (Common Expression Language)](https://cel.dev) expressions that derive `subject`/`action`/`resource`/`context` from the tool call's arguments and the session/bearer token. Example (agent-reconstructed field placement, verbatim field values as fetched from the spec):

```json
{
  "context": {
    "agent": "http://agentprovider.com/agent-app-id",
    "case": "case-67890"
  }
}
```

— where the `agent` value is derived from `token.client_id` via a CEL mapping expression (https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md).

Critically, COAZ makes an explicit human-vs-agent separation a design principle:

> "MCP Client: An AI agent or application that connects to MCP servers and invokes tools. The MCP Client acts as the caller in MCP."
> "A critical security consideration for MCP deployments is the distinction between the human user (represented as the AuthZen Subject) and the AI agent (represented in the AuthZen Context). This separation enables policies that can independently evaluate the trust level of both the user and the agent, supporting zero-trust architectures for AI agent interactions."
> — same source

This directly matches KnoTrust's stated grant model shape (principal + agent + tool + resource scope): the human/end-user goes in `subject`, the tool name/verb goes in `action`, the target object goes in `resource`, and the **acting AI agent's identity goes in `context.agent`**, not in `subject` — this is a load-bearing design decision KnoTrust should mirror if it wants to stay COAZ-compatible, since a competing WG-internal debate (see §6) has not settled whether agent identity belongs in `Subject` or `Context` at all.

### 4.3 Maturity

**Working Group Draft, "Draft 1."** Published 13 Feb 2026. Like AARP, **not yet cross-listed on the WG's canonical specifications index page** as of this research (confirmed via direct fetch) — exists only via GitHub Pages and the June 2026 blog announcement. A live reference-implementation demo occurred at IIW XLII (28–30 April 2026): Cerbos's Alex Olivier and SGNL's Atul Tulshibagwale demoed tool-call authorization using the AuthZEN MCP Profile (per https://www.technometria.com/p/internet-identity-workshop-xlii-report) — real-world traction exists, but standards-track maturity remains at the earliest WG Draft tier.

---

## 5. Obligations, advice, and context in responses — and mapping to "deferred"/"pending"

Primary source throughout: https://github.com/openid/authzen/blob/main/api/authorization-api-1_0.md (core 1.0 spec).

**"Obligations" and "advice" are NOT normatively-defined fields.** They appear exactly once, as *illustrative, non-normative examples* of what a deployment might put inside the generic `context` object:

> "In addition to a `decision`, a response MAY contain a `context` field which contains an object. This context can convey additional information that can be used by the PEP as part of the decision enforcement process. Examples include, but are not limited to: Reason(s) a decision was made, "Advices" and/or "Obligations" tied to the access decision, Hints for rendering UI state, Instructions for step-up authentication, Environmental information, etc."
> "The actual semantics and format of the `context` object are an implementation concern and outside the scope of this specification."
> — https://github.com/openid/authzen/blob/main/api/authorization-api-1_0.md

There is no schema, no required member names, and no enforcement semantics for "obligations" or "advice" — these are naming suggestions (explicitly analogous to XACML's Obligations/Advice) that a deployment can put under a self-chosen key, with **zero interoperability guarantee** between two independently-built PDPs/PEPs.

**Is there a decision outcome besides boolean permit/deny?** No — not in AuthZEN 1.0 core:

> "In this specification, assuming the evaluation was successful, there are only two possible values for the `decision`: `true`... `false`..."
> — same source

There is no XACML-style `Indeterminate` or `NotApplicable` at the core `decision` field level. This is a deliberate design choice, not an omission.

**Where a third state does exist:** in AARP's separate Task resource (see §3.2), whose `status` field genuinely carries multiple values (`pending`, `approved`, `denied`, `expired`, `cancelled`, `failed`, `partial`). This is architecturally a **side-channel workflow bolted onto a `false` core decision** — not a richer `decision` value itself. The core `decision` boolean never becomes anything other than `true`/`false`; the multi-state richness lives entirely in the AARP-defined Task object.

**Mapping to KnoTrust's "deferred"/"pending" outcomes:**

- **Under vanilla AuthZEN 1.0 core alone**, a PEP wanting to express "this requires further approval before being permitted" has no standardized way to do so — it would have to improvise inside `context` (e.g., a custom `context.needs_approval` key), with the spec's own text confirming this is exactly the kind of ad hoc use `context` is meant to allow, but with **zero cross-implementation interoperability guarantee** ("the actual semantics and format of the `context` object are ... outside the scope of this specification").
- **As of the June 2026 WG Draft approval**, this gap now has a real, purpose-built extension: AARP's Requestable Denial + Access Request Endpoint + Task Handle + Task Status state machine (§3.2). This is the technically-correct target for KnoTrust's "deferred"/"pending" outcomes going forward, but it inherits AARP's own immaturity (WG Draft, actively being rewritten).

**Practical implication:** KnoTrust's "deny-with-prerequisite" / "deferred — not eligible in this context" outcomes (`knotrust_prd_v5.md:68`) are not expressible as first-class values of AuthZEN's core `decision` field under any version of the spec — they must be layered on via `context` (freeform, no interop guarantee) today, or via AARP's Task/Requestable-Denial mechanism once that profile stabilizes. KnoTrust should **not** wire its outcome enum directly onto AARP's wire format yet; it should keep its own internal outcome model and translate to/from AARP's shape at the boundary (see §"Implications" below).

---

## 6. Agent/AI-specific authorization and delegated-authority standards

### 6.1 AuthZEN WG's own position

The WG's **charter** (dated 19 Oct 2023, https://openid.net/wg/authzen/charter/) predates the "agentic AI" framing and contains no AI/agent language (the only occurrence of "agent" is inside the product name "Open Policy Agent"). The **ratified Final spec** (Jan 2026) likewise contains zero occurrences of "agent," "agentic," "delegation," or "on_behalf_of" — `Subject` is a flat `{type, id, properties}` object with no reserved delegation vocabulary. Agent-specific language exists **only** in the two 2026 Working Group Drafts, AARP and COAZ (see §3–4), which is itself evidence of how new this concern is to the WG.

Co-chair statements (promotional, not normative, but useful context) accompanying the June 2026 announcement:

> David Brossard (Axiomatics): "Authorization has been overlooked for too long... AI is compounding the challenge at an unprecedented scale."
> Alex Olivier (Cerbos): "Modern systems, especially AI agents, often need approvals, attestations, delegated authority, or other prerequisites before a decision can be made."
> — https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/

**Live, unresolved internal debate** (github.com/openid/authzen), confirming agent identity placement (`Subject` vs. `Context` vs. a new `Actor` object) is genuinely unsettled WG-wide, not just within AARP/COAZ specifically:

> Issue #416 (29 Dec 2025): a proposed `delegation_chain` field aligned to RFC 8693 was rejected by a WG collaborator: "I don't think the AuthZEN spec should make an architectural decision as to how to convey delegation chains."
> Issues #481–#494 (April 2026): live, unresolved debate on `subject.type = "agent"` vs. context-carried agent identity.
> PR #541 (open as of 2 Jul 2026): "nothing here is settled."

**Do not conflate with a separate, lower-tier OIDF body:** the **Artificial Intelligence Identity Management (AIIM) Community Group** works on AI-agent identity but explicitly disclaims standards authority ("Any such protocol work will be deferred to an OIDF or liaison working group" — https://openid.net/cg/artificial-intelligence-identity-management-community-group/); OIDF Community Groups cannot ratify protocols. Its whitepaper ("Identity Management for Agentic AI," 7 Oct 2025) is not itself standards-track and does not name AuthZEN.

### 6.2 OAuth/IETF delegated-authority mechanisms

**RFC 8693 (OAuth 2.0 Token Exchange) — RFC/Final, Feb 2020** — the foundational, ratified delegation primitive:

> §1.1: "With delegation semantics, principal A still has its own identity separate from B, and it is explicitly understood that while B may have delegated some of its rights to A, any actions taken are being taken by A representing B. In a sense, A is an agent for B."
> §4.1, `act` (Actor) Claim: "...express that delegation has occurred and identify the acting party to whom authority has been delegated... For the purpose of applying access control policy, the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor by the `act` claim. Prior actors identified by any nested `act` claims are informational only and are not to be considered in access control decisions."
> §4.4, `may_act` (Authorized Actor) Claim: "...makes a statement that one party is authorized to become the actor and act on behalf of another party."
> — https://www.rfc-editor.org/rfc/rfc8693

The IANA JWT Claims Registry confirms only `act` and `may_act` are registered delegation claims (https://www.iana.org/assignments/jwt/jwt.xhtml) — there is no registered `delegate`, `authorized_actor`, or `on_behalf_of` claim.

**Adjacent IETF drafts building on RFC 8693 for AI agents (all pre-RFC, individual or recently-WG-adopted):**

| Draft | Concept | Maturity |
|---|---|---|
| `draft-ietf-oauth-identity-assertion-authz-grant` ("ID-JAG," underlies Okta Cross App Access) | Cites RFC 8693's `act` claim; has an appendix "AI Agent using External Tools" | **Internet-Draft-active, WG-adopted** (strongest WG-level link between RFC 8693 and AI agents found) |
| `draft-oauth-ai-agents-on-behalf-of-user` | `requested_actor`, `actor_token` params, reusing `act` | Internet-Draft (individual; version status varies) |
| `draft-oauth-transaction-tokens-for-agents` | Transaction tokens for agent call chains | Internet-Draft-active (individual) |
| `draft-mw-spice-actor-chain` | Cryptographically-verifiable actor chains (patches RFC 8693's "informational only" nested-act limitation) | Internet-Draft-active (individual) |
| `draft-mcguinness-oauth-actor-profile` | Delegation-chain convention referenced by AARP (§3.2) | Internet-Draft-active (individual, dated 30 Apr 2026, expires 1 Nov 2026) |

No `draft-ietf-oauth-*-agent-*` has been formally adopted as of this research (ID-JAG is the closest, and it's general cross-app delegation, not agent-specific by charter).

**"Identity Query Language" (IDQL):** real, but **not** an IETF/W3C/OpenID standard and **not** AI-agent-specific — it's a Strata-Identity-originated open-source project (reference implementation "Hexa," submitted to CNCF for stewardship, https://hexaorchestration.org/). CNCF hosting is open-source project governance, not a ratified standard. No connection to AI-agent delegation semantics was found. **Do not cite IDQL as AI-agent-authorization prior art.**

**IETF WIMSE (Workload Identity in Multi-System Environments)** — a real, active WG whose charter is agent-silent, but whose adopted architecture document explicitly addresses AI agents:

> "AI intermediaries [are] a special case of delegated workloads... SHOULD propagate the upstream security context, unless explicitly authorized to translate or reduce its scope... Because AI intermediaries may chain requests across multiple services, there is an elevated risk of privilege escalation if security context is propagated beyond the intended trust domain. Each hop MUST explicitly scope and re-bind the security context."
> — `draft-ietf-wimse-arch`, https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/ (Working-Group-Draft, adopted, active)

**Genuine RFC-level delegation vocabulary across the broader ecosystem** (not AuthZEN-specific, for completeness/precision):

| Field/claim | Spec | Maturity |
|---|---|---|
| `act`, `may_act` | RFC 8693 | RFC/Final |
| `OnBehalfOf`, `ActAs` (XML elements) | WS-Trust 1.4 | OASIS Standard (Final-equivalent) |
| `user` (with `sub_ids`) | RFC 9635 (GNAP) | RFC/Final |
| `existing_access_token` | RFC 9767 (GNAP RS extension) | RFC/Final |
| `client.actor`, `act` (chain) | AuthZEN AARP §10.1 | Working Group Draft |
| `context.agent` | AuthZEN COAZ | Working Group Draft |

**Terms that do NOT exist as literal spec fields, despite plausible sound:** `authorized_actor` (a paraphrase of RFC 8693's `may_act`, not its literal key), `acting_party`, `on_behalf_of` as a literal OAuth parameter (Microsoft's "On-Behalf-Of flow" is a marketing name for a JWT-bearer grant type, not a parameter literally named this).

### 6.3 MCP's own authorization model is moving *away* from an explicit human/agent distinction

Current MCP spec (2025-11-25, https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) uses a plain OAuth 2.1 client/AS/RS pattern with no agent-specific identity primitive. Notably, the earlier 2025-03-26 version *did* distinguish "acting on behalf of a (human) end user" (Authorization Code) from autonomous agents (Client Credentials) — this framing and a "Third-Party Authorization Flow" section were **removed** in the 2025-06-18 revision and remain absent from the current spec. This reinforces that KnoTrust's PEP-level mapping of MCP tool calls into an AuthZEN-style principal/agent/tool/scope model is filling a gap that MCP itself has explicitly declined to formalize — not duplicating existing MCP-native machinery.

**Synthesis for KnoTrust's grant model:** there is no single, converged, ratified field name for "agent acting on behalf of principal" anywhere in this landscape. KnoTrust's principal+agent+tool+resource-scope model should be built as an internal abstraction that can be projected onto whichever externalization wins — RFC 8693's `act`/`may_act` (ratified, general-purpose), AARP's `client.actor`/`act` (AuthZEN-native, WG Draft), or COAZ's `context.agent` (AuthZEN-native, WG Draft, sibling-to-Subject placement) — since the WG itself has not settled which of these AuthZEN should standardize on.

---

## 7. Interop / vendor implementations

### 7.1 Confirmed implementers (vendor's own primary source or WG source)

| Vendor/Project | Evidence | Source |
|---|---|---|
| **Cerbos** | Vendor's own page + WG source | https://www.cerbos.dev/authzen |
| **Axiomatics** | Vendor's own page + WG source (CTO is spec co-editor/WG co-chair) | https://axiomatics.com/resources/reference-library/openid-authzen |
| **SGNL** | WG source (co-founder is WG co-chair, contributed initial draft) | https://openid.net/wg/authzen/ |
| **Aserto** (company defunct; OSS successor **Topaz** active) | Vendor's own page (historical); lead spec editor was Aserto's Omri Gazitt | https://www.aserto.com/lp/authzen; https://www.aserto.com/blog/the-final-chapter-for-aserto |
| **Amazon Verified Permissions (Cedar)** | Vendor's own blog — but as a translation-layer adapter, not native protocol support | https://aws.amazon.com/blogs/security/how-to-support-openid-authzen-requests-with-amazon-verified-permissions/ (15 Apr 2025) |
| **OpenFGA** | Vendor's own repo, flagged **experimental** | https://github.com/openfga/authzen-interop (behind `--experimentals=enable_authzen`; repo notes OpenFGA "will not pass the search interop tests" due to actions-vs-relations modeling mismatch) |
| **Permit.io** | Vendor's own repo | https://github.com/permitio/permit-authzen-interop |
| **Hexa** (CNCF Sandbox, Cedar/IDQL-adjacent) | WG source (interop results) | https://authzen-interop.net; https://www.cncf.io/projects/hexa/ |
| **IndyKite** | Vendor's own page + WG (co-chair company) | https://www.indykite.ai/glossary/what-is-authzen |
| PlainID, EmpowerID, WSO2, Rock Solid Knowledge, 3Edges, Strata Identity, Thales, Kogito | WG source only (interop results pages) | https://openid.net/authorization-interop-results/; https://authzen-interop.net |
| **PingAuthorize** | WG source, but tested implementation was a **third-party adapter** ("ID Partners adapter for PingAuthorize"), not built by Ping itself | https://authzen-interop.net/docs/scenarios/todo-1.0-id/results/pingid/ |

### 7.2 Could NOT confirm (no primary-source evidence found)

- **Styra / OPA core** — a GitHub feature request for native AuthZEN support was **explicitly closed as "not planned"**: https://github.com/open-policy-agent/opa/issues/8449. A Styra-maintained Spring Boot SDK uses an AuthZEN-*like* shape per Styra's own docs, but this is not a compliance claim.
- **Okta / Auth0 FGA** — Auth0's own blog (https://auth0.com/blog/implementing-authzen-guide-openid-authorization-api/, 6 Feb 2026) is an educational walkthrough only; it does not claim Auth0 FGA/Okta FGA implements the wire protocol.
- **Microsoft (Entra)** — no Microsoft-authored source found claiming support; Microsoft does not appear in the spec's contributor list, WG chair list, or interop results. A third-party technical blog explicitly states Entra ID/M365 "do not expose a native AuthZEN PEP interface." Any claim that Microsoft is an AuthZEN contributor should be treated as an error.
- **Radiant Logic, Cedar-agent (standalone OSS project), Oso** (stated future intent only, per Oso's own "Aserto alternatives" page: "as soon as it is in DRAFT mode" — not confirmed shipped) — no direct evidence of implementation.

### 7.3 Interop program cadence (WG source: https://authzen-interop.net, https://openid.net/authorization-interop-results/)

Formal interop demos have run at: Identiverse 2024 (9 conformant vendors, announced 29 May 2024), Authenticate 2024 (11 implementations passed), EIC 2024, Gartner IAM US/London 2024–2025, Identiverse 2025, and Gartner IAM Summit Dec 2025 (8 live implementer demos: Axiomatics, Cerbos, EmpowerID, SGNL, WSO2, Topaz as PDPs; Curity, EmpowerID, Gluu, Thales as IdPs). At IIW XLII (28–30 Apr 2026), Cerbos and SGNL jointly demoed a reference implementation of the AuthZEN MCP Profile (COAZ) for tool-call authorization.

### 7.4 Reference/conformance implementation status

**No finished, WG-published reference PDP or formal conformance test suite currently exists.** The official repo's `interop/` directory contains a reference **PEP** only (the Todo app), used to test third-party PDPs. A certification-profile spec was opened as GitHub Issue #433 (12 Feb 2026), defining certification levels (Basic, Batch, Search, Discovery), but its build/deployment status could not be confirmed — treat as planned/in-progress, not delivered. The OpenID Foundation's general conformance suite does not yet list AuthZEN.

---

## Maturity summary table

| Item | Status | Evidence / URL | Confidence |
|---|---|---|---|
| AuthZEN Authorization API 1.0 (core: SARC model, single evaluation, batch evaluation, search endpoints) | **Final Specification** (approved 12 Jan 2026, published 11 Jan 2026) | https://openid.net/authorization-api-1-0-final-specification-approved/ ; https://openid.net/specs/authorization-api-1_0.html | High |
| PDP/PEP role definitions | **Final Specification** (defined in spec's Terminology + Model sections) | https://openid.net/specs/authorization-api-1_0.html §2, Appendix A | High |
| PIP/PAP role definitions | **Not defined by AuthZEN at all** — only named aspirationally in the WG charter | https://openid.net/wg/authzen/charter/ | High (negative finding) |
| AARP / ARAP ("Access Request and Approval Profile," Requestable Denial / prerequisite mechanism) | **Working Group Draft, "Draft 1"** — actively being edited (open PR as of 2 Jul 2026); **not** Implementer's Draft, **not** Final; spec's own abbrev is "ARAP," OIDF blog/WG page say "AARP" (unresolved naming inconsistency) | https://github.com/openid/authzen/blob/main/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md ; https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/ | High on existence/mechanics; flagged inconsistency on naming |
| "deny-with-prerequisite" (as a literal term) | **Not found in any AuthZEN primary source.** Closest real spec term: "Requestable Denial." | (absence confirmed via full-text search of spec, blog, and issue thread) | High (negative finding) |
| COAZ ("AuthZEN Profile for Model Context Protocol Tool Authorization," Compatible with OpenID AuthZen) | **Working Group Draft, "Draft 1"** (published 13 Feb 2026); not yet Implementer's Draft/Final; not yet on WG's canonical specs index | https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md ; https://github.com/modelcontextprotocol/ext-auth/issues/15 | High on identification; Medium on exact #429/#15 convergence mechanics |
| Obligations / advice (as normative response fields) | **Not normatively defined** — non-normative examples only, inside a freeform `context` object | https://github.com/openid/authzen/blob/main/api/authorization-api-1_0.md | High |
| Three-valued decision (indeterminate/pending in core `decision` field) | **Does not exist in AuthZEN 1.0 core.** A `status` state machine exists, but only inside AARP's separate Task resource (a WG Draft), not the core boolean `decision`. | Same as above + AARP source | High |
| AuthZEN WG explicit AI-agent charter/scope | **Not present** — charter (2023) and Final spec (Jan 2026) are agent-silent; agent language exists only in the 2026 AARP/COAZ WG Drafts | https://openid.net/wg/authzen/charter/ | High (negative finding) |
| RFC 8693 (OAuth Token Exchange, `act`/`may_act`) | **RFC/Final** (Feb 2020) — foundational, ratified, general-purpose delegation primitive, not AI-agent-specific | https://www.rfc-editor.org/rfc/rfc8693 | High |
| `draft-ietf-oauth-identity-assertion-authz-grant` (ID-JAG) | **Internet-Draft-active, WG-adopted** — includes an AI-agent appendix | https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/ | High |
| `draft-mcguinness-oauth-actor-profile` (delegation chain, referenced by AARP) | **Internet-Draft-active** (individual submission) | https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/ | High |
| IETF WIMSE architecture (AI intermediaries as delegated workloads) | **Working Group Draft, adopted, active** | https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/ | High |
| "Identity Query Language" (IDQL) | **Not an IETF/W3C/OpenID standard** — CNCF-hosted open-source project (Strata Identity origin), not AI-agent-specific | https://hexaorchestration.org/ | High (negative finding) |
| Vendor AuthZEN support: Cerbos, Axiomatics, SGNL, OpenFGA (experimental), Permit.io, IndyKite, Hexa | **Confirmed** (vendor's own primary source or WG source) | See §7.1 | High |
| Vendor AuthZEN support: Styra/OPA (native), Okta/Auth0 FGA, Microsoft/Entra, Radiant Logic, Oso | **Not confirmed / explicitly declined (OPA) or contradicted (Microsoft)** | See §7.2 | High (negative finding) |
| AuthZEN reference PDP / conformance suite | **Does not yet exist** — only a reference PEP and a planned (not confirmed built) certification harness | https://github.com/openid/authzen/issues/433 | Medium-High |

---

## Sources

**OpenID Foundation / AuthZEN primary sources:**
- https://openid.net/wg/authzen/ — WG home
- https://openid.net/wg/authzen/charter/ — WG charter (2023-10-19)
- https://openid.net/wg/authzen/specifications/ — canonical specifications index
- https://openid.net/specs/authorization-api-1_0.html — Final Specification (11 Jan 2026)
- https://openid.net/specs/authorization-api-1_0-00.html / `-01.html` / `-02.html` / `-03.html` / `-05.html` — draft history
- https://openid.net/authorization-api-1-0-final-specification-approved/ — Final Specification approval announcement (12 Jan 2026)
- https://openid.net/authzen-authorization-api-1-0-implementers-draft-approved/ — Implementer's Draft approval (15 Nov 2024)
- https://openid.net/public-review-period-for-proposed-authorization-api-1-final-specification/ — public review timeline (23 Oct 2025)
- https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/ — AARP + COAZ WG Draft announcement (15 Jun 2026)
- https://openid.net/authorization-interop-results/ — Identiverse 2024 interop results
- https://openid.net/authzen-shared-signals-in-the-gartner-iam-2025-spotlight/ — Gartner IAM 2025 recap
- https://openid.net/authzen-shows-enterprise-readiness-at-gartner-iam-summit/ — Gartner IAM Summit Dec 2025 recap
- https://openid.net/cg/artificial-intelligence-identity-management-community-group/ — AIIM Community Group (distinct from AuthZEN)
- https://openid.github.io/authzen — living/editor's draft
- https://openid.github.io/authzen/authzen-access-request-approval-profile-1_0.html — AARP/ARAP rendered
- https://openid.github.io/authzen/authzen-mcp-profile-1_0.html — COAZ rendered
- https://authzen-interop.net — interop program site

**GitHub (github.com/openid/authzen):**
- https://github.com/openid/authzen/blob/main/api/authorization-api-1_0.md
- https://github.com/openid/authzen/blob/main/api/schemas/evaluation-request.schema.json
- https://github.com/openid/authzen/blob/main/api/schemas/evaluation-response.schema.json
- https://github.com/openid/authzen/blob/main/interop/authzen-todo-backend/test/decisions.json
- https://github.com/openid/authzen/blob/main/patterns/AuthorizationDesignPatterns.md
- https://github.com/openid/authzen/blob/main/archive/authorization-api-1_1_01.md
- https://github.com/openid/authzen/blob/main/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md
- https://github.com/openid/authzen/blob/main/profiles/authzen-mcp-profile-1_0.md
- https://github.com/openid/authzen/issues/416, /429, /433, /481–494, /520
- https://github.com/openid/authzen/pull/508, /515, /541

**MCP (modelcontextprotocol.io / github.com/modelcontextprotocol):**
- https://github.com/modelcontextprotocol/ext-auth/issues/15 — COAZ origin proposal
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization — current MCP authorization spec

**IETF / OAuth:**
- https://www.rfc-editor.org/rfc/rfc8693 — OAuth 2.0 Token Exchange (`act`, `may_act`)
- https://www.rfc-editor.org/rfc/rfc9635.html — GNAP core (RFC 9635)
- https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/ — ID-JAG
- https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/
- https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/05/
- https://datatracker.ietf.org/doc/draft-mw-spice-actor-chain/
- https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/
- https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/
- https://datatracker.ietf.org/doc/charter-ietf-wimse/
- https://datatracker.ietf.org/doc/charter-ietf-spice/
- https://www.iana.org/assignments/jwt/jwt.xhtml — JWT Claims Registry

**Other standards bodies:**
- https://hexaorchestration.org/ — IDQL/Hexa (CNCF-hosted, not an SDO standard)
- https://www.cncf.io/projects/hexa/
- https://www.w3.org/community/agent-identity/ — nascent W3C Community Group (pre-launch)
- https://www.linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project — A2A protocol
- https://docs.agntcy.org/ — AGNTCY / Internet of Agents

**Vendor primary sources (implementers):**
- https://www.cerbos.dev/authzen
- https://axiomatics.com/resources/reference-library/openid-authzen
- https://www.aserto.com/lp/authzen ; https://www.aserto.com/blog/the-final-chapter-for-aserto
- https://aws.amazon.com/blogs/security/how-to-support-openid-authzen-requests-with-amazon-verified-permissions/
- https://github.com/openfga/authzen-interop
- https://github.com/permitio/permit-authzen-interop
- https://www.indykite.ai/glossary/what-is-authzen
- https://github.com/open-policy-agent/opa/issues/8449 — OPA native support declined
- https://auth0.com/blog/implementing-authzen-guide-openid-authorization-api/
- https://www.osohq.com/learn/aserto-alternatives

**Secondary/corroborating (used only for cross-checking, not as sole evidence for any load-bearing claim):**
- https://www.technometria.com/p/internet-identity-workshop-xlii-report — IIW XLII COAZ demo recap
- https://andrewdoering.org/blog/2026/authzen-shared-signals-framework-part-3-microsoft/ — Microsoft non-support note

---

## Implications for KnoTrust design

1. **Build directly against AuthZEN 1.0 core today — it's genuinely safe.** The Final Specification's SARC model, the `/access/v1/evaluation` and `/access/v1/evaluations` endpoints, and the boolean `decision` + optional `context` response shape are ratified, stable, and will not change ("not subject to further revision," per OIDF's own Final-Specification language). KnoTrust's PEP, its request-mapping layer, and its "PDP-agnostic, rip-and-replace with any AuthZEN PEP" positioning can all be built on this with confidence — this part of the PRD's claims is fully vindicated.

2. **Isolate AARP and COAZ behind internal interfaces — they are pre-Implementer's-Draft and one is still being rewritten.** Both are "Working Group Draft, Draft 1," a full two maturity tiers below Final, and AARP had an open, actively-editing PR as of 2 July 2026. Concretely:
   - Define KnoTrust's own internal decision-outcome enum (e.g., `allow` / `deny` / `needs_approval` / `deferred`) and its own internal grant-request shape (principal + agent + tool + resource scope) as the **stable core contract** the rest of KnoTrust's code depends on.
   - Write a thin **AARP adapter** that translates KnoTrust's `needs_approval`/`deferred` outcomes to and from AARP's Requestable-Denial / Access-Request-Endpoint / Task-Handle / Task-Status vocabulary, so that when AARP's wire format inevitably changes en route to Implementer's Draft, only the adapter — not the decision core — needs to change. Given the open PR on 2 Jul 2026, do not assume the current field names (`client.actor`, `context.access_request`, the Task Status enum) are final.
   - Write a thin **COAZ adapter** for the `x-coaz-mapping` / `context.agent` tool-schema convention, rather than hard-wiring KnoTrust's MCP-tool-to-SARC mapping logic to COAZ's exact current shape. Note the still-unresolved WG debate (issues #481–494) over whether agent identity belongs in `Subject` or `Context` — COAZ's current choice (context, sibling to Subject) could still shift.
   - Do not present AARP/COAZ as "final" or bundle their maturity with the core API's in any external-facing material (correcting `knotrust_prd_v5.md:6`); the PRD's own gating logic in §14 (enterprise GA requires COAZ/AARP at ≥ Implementer's Draft) is the right instinct and should be the template for how these are described elsewhere in the doc.

3. **Correct the vocabulary, keep the product concept.** "Deny-with-prerequisite" is a reasonable product-facing term for KnoTrust's own outcome model, but it isn't AuthZEN's term — the spec calls the underlying mechanic "Requestable Denial." Where the PRD or docs cite AuthZEN directly, use "Requestable Denial" (AARP) to avoid inventing spec vocabulary; keep "deny-with-prerequisite" purely as KnoTrust's internal/marketing name if useful, clearly distinguished from spec terminology.

4. **Resolve (or explicitly caveat) the AARP/ARAP naming inconsistency in KnoTrust's own docs.** Since even the OpenID Foundation's own blog post and the spec's own front matter disagree ("AARP" vs. "ARAP"), KnoTrust should pick one primary term for its docs (recommend "AARP," matching OIDF's external-facing blog/WG-page usage, since that's what most readers will search for) but add a one-line footnote noting the spec file itself uses "ARAP" — this avoids KnoTrust looking wrong if a reader checks the primary spec directly and sees a different abbreviation.

5. **The PDP-agnostic pitch is standards-accurate, but interop evidence is currently thin outside a handful of vendors.** Cerbos, Axiomatics, SGNL, IndyKite, Permit.io, and Hexa have confirmed AuthZEN support; OpenFGA's is explicitly experimental; and — notably — Styra/OPA (arguably the most-deployed general policy engine) has **declined** native AuthZEN support as "not planned." KnoTrust's bundled-default-PDP and OPA/Cedar-adapter plan (`knotrust_prd_v5.md:119`) should account for the fact that an OPA adapter will need to be KnoTrust-built and maintained rather than relying on upstream OPA ever speaking AuthZEN natively.

6. **Delegation/agent-identity field shape is genuinely unsettled industry-wide, not just within AuthZEN.** RFC 8693's `act`/`may_act` (ratified) is the only delegation vocabulary with real standards-track weight; everything AI-agent-specific (AARP's `client.actor`, COAZ's `context.agent`, the referenced-but-unratified `draft-mcguinness-oauth-actor-profile`) is still in motion. KnoTrust's internal grant model (principal + agent + tool + resource scope) should be designed to be projectable onto whichever of these wins, rather than committing to one now — this is the same "isolate behind an internal interface" principle as point 2, applied one layer up at the identity/delegation-claim level.

7. **No reference/conformance PDP exists yet from the WG.** KnoTrust cannot currently validate its PEP against an official AuthZEN conformance suite (only a certification-profile GitHub issue exists, status unclear) or a WG reference PDP (only a reference PEP — the Todo app — exists). Plan for KnoTrust to build its own conformance fixtures against the published JSON schemas and the Todo-app interop test fixtures in the interim, and revisit once/if OIDF ships the certification harness described in issue #433.
