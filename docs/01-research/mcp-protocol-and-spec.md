# MCP Protocol & Spec Research for KnoTrust

**Compiled:** 2026-07-03
**Purpose:** Ground KnoTrust's design (an action-governance proxy / PEP sitting in front of MCP servers, gating `tools/call`) in the actual, verified state of the Model Context Protocol — both the current stable spec and the in-progress "stateless" revision KnoTrust is targeting.

**Methodology note:** This report combines (a) four parallel research passes across the eight questions below, and (b) direct, independent primary-source verification by the report author of the highest-stakes and most novel claims — especially everything touching the 2026-07-28 revision, which did not exist as of the assistant's January 2026 knowledge cutoff. Where a claim was independently re-fetched from a primary source (modelcontextprotocol.io, a GitHub PR, an SEP page, a raw schema file, or a package registry), it is marked **[Verified directly]**. Where it rests only on a delegated research pass, it is marked **[Verified by research agent, not independently re-checked]**. Read the "Maturity & Uncertainty" section before treating anything here as load-bearing for architecture decisions.

---

## 1. Spec Revisions & Timeline

| Revision | Status | Headline changes |
|---|---|---|
| **2024-11-05** | Initial public release | Baseline protocol: JSON-RPC 2.0 messages, stdio + HTTP+SSE transports, tools/resources/prompts primitives. (Not independently re-fetched; consistently cited as the baseline by every later changelog.) |
| **2025-03-26** | Superseded | Added the OAuth 2.1-based **authorization framework** (PR #133); replaced HTTP+SSE with **Streamable HTTP** (PR #206); added JSON-RPC batching (PR #228, later removed); added **tool annotations** (PR #185, `readOnlyHint`/`destructiveHint`/etc.). |
| **2025-06-18** | Superseded | Removed JSON-RPC batching; added **structured tool output** (`structuredContent`, PR #371); classified MCP servers as **OAuth 2.1 resource servers** with Protected Resource Metadata discovery (PR #338); required **RFC 8707 Resource Indicators** for token audience binding (PR #734); added **elicitation** (`elicitation/create`, PR #382, form mode only); added resource links in tool results (PR #603); made `MCP-Protocol-Version` header mandatory (PR #548). |
| **2025-11-25** | **Current stable spec** as of this report's date | OpenID Connect Discovery as an AS-metadata option (PR #797); **icons metadata** (SEP-973); **incremental scope consent** via `WWW-Authenticate` (SEP-835); tool-naming guidance (SEP-986); enhanced enum schemas for elicitation (SEP-1330); **URL-mode elicitation** (SEP-1036); tool-calling inside sampling (SEP-1577); OAuth Client ID Metadata Documents (SEP-991); **experimental Tasks primitive** (SEP-1686, a call-now/fetch-later pattern for long-running requests); reclassified input-validation errors from Protocol Errors to Tool Execution Errors (SEP-1303, to enable model self-correction). **[Verified directly against `modelcontextprotocol.io/specification/2025-11-25/changelog`.]** |
| **2026-07-28** | **Release Candidate — NOT YET FINAL.** Locked 2026-05-21; final publication targeted 2026-07-28, i.e. ~3.5 weeks after this report's compilation date. | Four pillars, per the RC blog post: (1) a **stateless protocol core** (removes `initialize`/`initialized` handshake and `Mcp-Session-Id`); (2) an **Extensions framework** (MCP Apps and the 2025-11-25 experimental Tasks primitive both "graduate" out of core into governed extensions); (3) **authorization hardening** (six SEPs — `iss` validation, OIDC `application_type` declarations, clearer refresh-token handling); (4) a **formal deprecation policy** (Roots, Sampling, Logging deprecated with a ≥12-month compatibility window). **[Verified directly — see below.]** |

### The 2026-07-28 revision — what was directly confirmed

Fetched directly from `blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/` (published 2026-05-21) **[Verified directly]**:

> "any MCP request can land on any server instance, and the sticky routing and shared session stores that horizontal deployments needed before are no longer required at the protocol layer."

The post confirms: removal of `initialize`/`initialized` and `Mcp-Session-Id`; new required `Mcp-Method`/`Mcp-Name` headers for routing; `ttlMs`/`cacheScope` for list caching; W3C Trace Context propagation; the Extensions framework; the six authorization SEPs; and the Roots/Sampling/Logging deprecation with a 12-month window. It also states a **10-week SDK validation window** before final publication.

Four SEPs (Specification Enhancement Proposals) underpin this, each confirmed by directly fetching its page on `modelcontextprotocol.io/seps/...` or its GitHub PR:

- **SEP-2575, "Make MCP Stateless"** — PR [#2575](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575), author `kurtisvg`, created 2026-04-14, **merged 2026-05-11**. Removes the mandatory `initialize` handshake; protocol version, client info, and capabilities move to per-request metadata; adds an optional `server/discover` RPC and a `messages/listen` RPC (replacing the GET/SSE stream). **[Verified directly.]**
- **SEP-2567, "Sessionless MCP via Explicit State Handles"** — PR [#2567](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2567), author Peter Alexander (`@pja-ant`), created 2026-03-11, **Status: Final**. Removes the `Mcp-Session-Id` header and the session concept entirely; stateful workflows move to server-minted opaque handles threaded through tool arguments (a documented tool-design pattern, not a new wire construct); makes `tools/list`/`resources/list`/`prompts/list` session-independent and therefore cacheable. Cites a 1000-repo survey: ~90% of OSS MCP servers have zero application-level reliance on session ID; ~2.5% use session-keyed state; ~0.7% do sticky-routing gateways; ~0.5% bind auth artifacts to session ID. **[Verified directly — full text fetched.]**
- **SEP-2322, "Multi Round-Trip Requests" (MRTR)** — PR [#2322](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2322), authors Mark D. Roth and Caitie McCaffrey, created 2026-02-03, **Status: Final**. See §6 below. **[Verified directly.]**
- **SEP-2243, "HTTP Header Standardization for Streamable HTTP Transport"** — PR [#2243](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2243), author "MCP Transports Working Group," created 2026-02-04, **Status: Final**. See §2 below. **[Verified directly — full text fetched, including conformance test tables.]**

**Nothing found dated between 2025-11-25 and 2026-07-28 as a separate named revision, and nothing found dated after 2026-07-28.** A December 2025 working-group post, "Exploring the Future of MCP Transports" (2025-12-19), reportedly foreshadowed this direction with the framing "agentic applications are stateful, but the protocol itself doesn't need to be" (reported by research agent, not independently re-fetched).

---

## 2. Transports

### stdio (spec 2025-11-25, `.../basic/transports`)

Client launches the server as a subprocess. Server reads JSON-RPC from stdin, writes JSON-RPC to stdout, one message per line, **MUST NOT** embed newlines inside a message. Server **MAY** write arbitrary logging to stderr (not just errors). No headers, no sessions; lifecycle ends when the client closes stdin and terminates the process. Unchanged in the 2026-07-28 RC.

### Streamable HTTP — current stable model (2025-11-25)

Single MCP endpoint supporting `POST` and optional `GET`. Every client message is its own `POST` with `Accept: application/json, text/event-stream`. For a request (not a notification), the server **MUST** respond with either `Content-Type: text/event-stream` (SSE) or `Content-Type: application/json` (single object) — the client must support both; there's no separate signaling header, the `Content-Type` on the response *is* the signal. `GET` is optional, for an unsolicited server→client SSE stream.

**`Mcp-Session-Id`**: server **MAY** assign one on the HTTP response carrying `InitializeResult`. If issued, the client **MUST** echo it on every subsequent request; if a server requires sessions it **SHOULD** 400 requests missing it, and 404 once the session is terminated (client sends `DELETE` to end one explicitly). **Critically, nothing requires a server to issue a session ID at all** — omitting it is already a legitimate, spec-compliant way to run statelessly today. This is corroborated by both official SDKs already shipping a stateless mode: the Python SDK's `FastMCP(stateless_http=True)` / `StreamableHTTPSessionManager`, and the TypeScript SDK's `sessionIdGenerator: undefined` mode.

**`Mcp-Protocol-Version`**: client **MUST** send it on all requests after negotiation; server 400s on unsupported values; if absent, server **SHOULD** assume `2025-03-26` for backward compatibility.

**Resumability**: server **MAY** tag SSE events with an `id`; on reconnect the client **SHOULD** re-`GET` with `Last-Event-ID`, and the server **MAY** replay only same-stream messages.

### Streamable HTTP — the 2026-07-28 RC rewrite

The draft transports page removes `Mcp-Session-Id`, removes the GET/SSE-resumability/`Last-Event-ID` mechanism, and removes the `initialize` handshake (protocol version/client info move to per-request `_meta`, per SEP-2575). This is the mechanism behind the RC blog's claim that servers can "run behind a plain round-robin load balancer."

### Header-based routing without parsing the JSON-RPC body — the exact answer to your question

**Today, against the current stable spec (2025-11-25), there is no such header. A proxy MUST parse `method` and `params.name` out of the JSON-RPC body to know what's being called.** This is a real gap, not something previously overlooked — it's exactly what SEP-2243 was written to close.

**SEP-2243 (Final, incorporated into the 2026-07-28 RC)** defines, verbatim **[Verified directly against the full SEP text]**:

- **`Mcp-Method`** — mirrors `method`. Required on every request/notification.
- **`Mcp-Name`** — mirrors `params.name` (tools/prompts) or `params.uri` (resources). Required for `tools/call`, `resources/read`, `prompts/get`.
- **`Mcp-Param-{Name}`** — optional, opt-in per parameter via an `x-mcp-header` JSON Schema extension keyword on a primitive-typed property in `inputSchema` (e.g., a `region` or `tenant_id` argument), with a `=?base64?...?=` sentinel encoding for non-ASCII/whitespace/control-char values. Example use case cited in the SEP: a Cloud Spanner-style tool with a `region` argument, letting a load balancer route to the correct regional cluster from the header alone, without terminating TLS and parsing the body.
- **Server-side enforcement**: any server (or intermediary) that processes the body **MUST reject** header/body mismatches — HTTP `400`, JSON-RPC error code **`-32001` `HeaderMismatch`**.
- **Explicit security warning, quoted verbatim**: *"Header values originate from tool call arguments, which may be influenced by an LLM or a malicious client. Intermediaries and servers **MUST NOT** treat these values as trusted input for security-sensitive decisions... Header values that imply access to specific resources (e.g., tenant IDs, region names) **MUST be independently verified** against the authenticated user's permissions before granting access to those resources."*

So the precise, careful answer for KnoTrust: **once 2026-07-28 ships**, `Mcp-Method`/`Mcp-Name` let a proxy do fast-path routing/observability without deserializing the body — but the SEP itself forbids using them as the basis for a policy/privilege decision. A proxy can use headers to *route* (which backend, which policy bucket to look up) but must still inspect the actual body (or trust the server's own header/body validation) before making an allow/deny call on the arguments. This maps cleanly onto defense-in-depth: headers for performance, body for truth.

### tools/list (2025-11-25, schema at `.../server/tools`)

```json
// Request
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"optional-cursor-value"}}

// Response
{"jsonrpc":"2.0","id":1,"result":{
  "tools":[{
    "name":"get_weather","title":"Weather Information Provider",
    "description":"Get current weather information for a location",
    "inputSchema":{"type":"object","properties":{"location":{"type":"string"}},"required":["location"]},
    "outputSchema":{"...":"optional"},
    "annotations":{"...":"optional, see §5"},
    "execution":{"taskSupport":"optional"}
  }],
  "nextCursor":"next-page-cursor"
}}
```

### tools/call (2025-11-25)

```json
// Request
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
  "name":"get_weather","arguments":{"location":"New York"}
}}

// Success response
{"jsonrpc":"2.0","id":2,"result":{
  "content":[{"type":"text","text":"Current weather in New York: 72°F, partly cloudy"}],
  "structuredContent":{"temperature":22.2,"conditions":"Partly cloudy"},
  "isError":false
}}
```

`params._meta.progressToken` (string|number) carries progress-notification correlation. `result.content` is a union of `TextContent | ImageContent | AudioContent | ResourceLink | EmbeddedResource`.

### Two distinct error channels — get this exactly right

1. **Protocol Errors** — standard JSON-RPC `{jsonrpc, id, error:{code, message, data?}}`. Used for unknown tool name, malformed request, server errors. Example: `-32602 "Unknown tool: invalid_tool_name"`.
2. **Tool Execution Errors** — `result.isError: true`, with the failure explained in `content`. Used for API failures, input-validation errors, business-logic errors.

The spec's own guidance (verbatim): *"Tool Execution Errors contain actionable feedback that language models can use to self-correct and retry with adjusted parameters. Protocol Errors indicate issues with the request structure itself that models are less likely to be able to fix. Clients SHOULD provide tool execution errors to language models... Clients MAY provide protocol errors."* Note the 2025-11-25 changelog explicitly reclassified input-validation errors from channel (1) to channel (2) specifically to enable model self-correction (SEP-1303).

### What a transparent proxy must do

- `tools/list`: pass through unmodified (or annotate), but preserve `nextCursor` pagination semantics exactly.
- Every `tools/call` must be intercepted: parse `method` + `params.name`/`params.arguments` from the body (today); optionally fast-path on `Mcp-Method`/`Mcp-Name` headers once 2026-07-28 ships, but always re-validate against the body for any policy decision.
- **Forward unchanged** — simple pass-through.
- **Short-circuit / deny** — synthesize a JSON-RPC response reusing the **same `id`** as the client's request (JSON-RPC correlation is purely by `id`; losing this breaks the client). Model a policy "denial" as a **Tool Execution Error** (`isError:true` + explanatory `content`), not a protocol error, so the calling LLM can see and react to the denial in-context.
- **Modify then forward** — rewrite `params.arguments` before forwarding; if/when adopting SEP-2243 headers, keep `Mcp-Param-*`/`Mcp-Name` in sync with any rewritten body or the real server will reject with `HeaderMismatch`.
- **Streaming/SSE** — since the server may interleave `notifications/progress` before the terminal response, and chooses per-request whether to answer with plain JSON or SSE, a proxy that wants to inspect-before-releasing either buffers until the terminal frame (breaking true streaming) or passes progress notifications through in real time while only gating the final response frame. `notifications/cancelled` should pass through untouched. If KnoTrust terminates/restarts connections, it must faithfully relay SSE event IDs or it will break client `Last-Event-ID` reconnection.
- **No first-class "pending human approval" primitive exists in the current stable spec.** Today KnoTrust must either hold the HTTP request open until a human approves/denies, or return a protocol error and have the client re-poll/retry. The 2026-07-28 RC's MRTR mechanism (§6) is the sanctioned future primitive for exactly this — worth designing toward, not assuming as available today.

---

## 3. tools/call Interception — see §2 above

(Merged into §2 for coherence — the request/response shapes, error channels, and proxy design guidance all live there.)

---

## 4. Elicitation

### `elicitation/create` — introduced 2025-06-18

```json
// Request (server → client)
{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{
  "message":"Please provide your GitHub username",
  "requestedSchema":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}
}}

// Response (client → server)
{"jsonrpc":"2.0","id":1,"result":{"action":"accept","content":{"name":"octocat"}}}
```

`requestedSchema` is deliberately restricted to a **flat object with only primitive-typed properties** — string, number/integer, boolean, enum (single- or multi-select, titled or untitled). The spec states: *"complex nested structures, arrays of objects (beyond enums), and other advanced JSON Schema features are intentionally not supported to simplify client user experience."* The 2025-06-18 page originally carried a note that the feature "is newly introduced in this version... and its design may evolve" — which it then did.

### Evolution in 2025-11-25 — URL-mode elicitation (confirmed, currently shipped)

**[Verified directly against `modelcontextprotocol.io/specification/2025-11-25/client/elicitation` — full page fetched.]** Elicitation now has a `mode` field: `"form"` (the original, defaults if omitted for backward compatibility) or `"url"`.

- **Form mode** is unchanged in shape from 2025-06-18, plus default values on primitives (SEP-1034) and richer enum support (SEP-1330).
- **URL mode**: request carries `mode:"url"`, `url`, `elicitationId`. Client shows the user the URL, gets consent, opens it (in an isolated browser view that the client/LLM cannot inspect, e.g. `SFSafariViewController` not `WKWebView`), and returns `{"action":"accept"}` — which means only *"consent to open the URL,"* not completion. Verbatim: *"It does not mean that the interaction is complete. The interaction occurs out of band and the client is not aware of the outcome until and unless the server sends a notification indicating completion"* (`notifications/elicitation/complete`). A new error code `-32042 URLElicitationRequiredError` lets a server tell the client mid-`tools/call` that a URL-mode elicitation must complete first, with a designed retry flow. This whole mechanism has an unusually long, careful security section covering an "Alice tricks Bob into completing her OAuth grant" phishing scenario, and mandates the server bind the elicitation to a verified user identity (e.g. via session cookie / `sub` claim) before accepting the callback.

**Explicit sensitivity rule, verbatim**: *"Servers MUST NOT use form mode elicitation to request sensitive information such as passwords, API keys, access tokens, or payment credentials. Servers MUST use URL mode for interactions involving such sensitive information."*

**Statefulness rule, verbatim**: *"State MUST NOT be associated with session IDs alone... user identification MUST be derived from credentials acquired via MCP authorization when possible (e.g. `sub` claim)"* — notably, this is written to survive the removal of sessions in the 2026-07-28 direction.

### The "only during active request processing" constraint

In the ratified 2025-06-18/2025-11-25 text this is a **soft, descriptive** property, not a structurally-enforced MUST: elicitation is framed as occurring "nested inside other MCP server features" — i.e., in practice a server sends `elicitation/create` while it's in the middle of handling a `tools/call` (or similar) and hasn't yet responded to it, but nothing in the wire format *forces* this.

**This becomes structurally enforced in the 2026-07-28 RC.** Per MRTR (§6), `elicitation/create` is no longer a free-standing request sent over a held-open connection — it's delivered as an `inputRequests` entry inside an `InputRequiredResult`, which is literally the *response* to the original in-flight request. The constraint is enforced by the message shape itself, because there's no other way to send one. **This is proposed/draft, not yet final** — treat the "hard MUST" framing as forthcoming, not current.

### Client support matrix

| Client | Status | Source |
|---|---|---|
| **Claude Code (CLI)** | **Confirmed shipped.** | GitHub release notes v2.1.76: "Added MCP elicitation support — MCP servers can now request structured input mid-task via an interactive dialog (form fields or browser URL)," plus `Elicitation`/`ElicitationResult` hooks. **Caveat:** the fetched release timestamp read "14 Mar 01:23" without an unambiguous year in the snippet retrieved; given the v2.1.x version number this is almost certainly March 2026, not March 2025, but the exact year was not conclusively pinned down in this pass. |
| **Claude Desktop / "Claude Cowork"** (Anthropic's newer agentic desktop product, distinct from the classic chat app) | **Not confirmed working — likely broken.** | GitHub issue anthropics/claude-code#56243 reportedly documents Cowork auto-declining `elicitation/create` instead of surfacing UI ("works correctly in Claude Code CLI"). No public confirmation of elicitation support in the classic Claude Desktop chat app either. **[Verified by research agent only, not independently re-checked.]** |
| **OpenAI Codex CLI** | **In progress / unconfirmed as a client.** | The official docs page (developers.openai.com/codex/mcp) doesn't mention elicitation. Open PR `openai/codex#17043` ("Support server-driven elicitations") and issues #6992, #13405 requesting it; bug #11816 describes Codex hanging when an approval requires elicitation it can't answer. Codex can reportedly use elicitation when acting as an MCP *server*, but Codex-as-client support for third-party elicitation is unconfirmed as fully working. |
| **Cursor** | **Confirmed for form mode only.** | Cursor 1.5 changelog, dated 2025-08-21: "Cursor now supports MCP elicitation... string, number, boolean, and enum" schema types. Predates the 2025-11-25 URL-mode addition, so URL-mode support is unconfirmed. |

**[This whole matrix: Verified by research agent, not independently re-checked by the report author.]**

---

## 5. Tool Annotations

**[Verified directly against `raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-06-18/schema.ts` and the rendered 2025-11-25 tools spec page.]**

| Annotation | Meaning | Default |
|---|---|---|
| `readOnlyHint` | "If true, the tool does not modify its environment." | `false` |
| `destructiveHint` | "If true, the tool may perform destructive updates to its environment. If false, the tool performs only additive updates." (meaningful only when `readOnlyHint == false`) | `true` |
| `idempotentHint` | "If true, calling the tool repeatedly with the same arguments will have no additional effect on the environment." (meaningful only when `readOnlyHint == false`) | `false` |
| `openWorldHint` | "If true, this tool may interact with an 'open world' of external entities" (e.g. web search vs. a closed memory tool). | `true` |

**The load-bearing caveat for KnoTrust, quoted verbatim from `schema.ts`:**

> "NOTE: all properties in ToolAnnotations are **hints**. They are not guaranteed to provide a faithful description of tool behavior (including descriptive properties like `title`). Clients should never make tool use decisions based on ToolAnnotations received from untrusted servers."

And normatively, on the rendered spec page:

> "For trust & safety and security, clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers."

**Implication:** these hints are self-declared by the tool/server author, are not verified or enforced by the protocol in any way, and the spec itself forbids treating them as a security signal for untrusted servers. For KnoTrust, this means annotations can seed a *default* risk-tier suggestion (e.g., a UX nudge, a starting point an operator can review) — but they must never be the sole basis for an automated allow decision on a server KnoTrust hasn't independently vetted, and even for vetted/trusted servers they're better treated as author intent than as ground truth about actual behavior.

---

## 6. Stateless Resumption / "Multi Round-Trip Requests"

**Real, not speculative — confirmed via direct fetch of SEP-2322, Status: Final** (though still part of the 2026-07-28 RC, so not finalized as the current spec until that date).

SEP-2322 introduces a new `Result.resultType` value, `"input_required"`, and an `InputRequiredResult` object that `tools/call`, `prompts/get`, `resources/read`, or `tasks/result` can return **instead of** their normal result. It carries:

- `inputRequests` — an optional map of keyed server-initiated requests (e.g. an `elicitation/create` or `sampling/createMessage`) the server needs answered before it can finish.
- `requestState` — an **opaque string the client must echo back verbatim and never inspect or modify.**

The client answers with a **fresh, independent request** carrying `inputResponses` (keyed identically to `inputRequests`) plus the echoed `requestState`. Because `requestState` is opaque and round-trips through the client, **any stateless server replica** can reconstruct exactly where processing left off — no held-open SSE stream, no shared session store. Servers are required to cryptographically validate/bind `requestState` since it's untrusted, client-carried data (it must not be a forgeable capability). For longer-running "persistent" tools, this integrates with the Tasks extension (`input_required` task status → `tasks/result` → `tasks/input_response`). The SEP includes a worked example: an Azure DevOps `update_work_item` tool doing two rounds of elicitation with zero server-side storage.

**This directly answers your hypothesis about a `requestState`/`inputRequired` mechanism for resuming a paused request statelessly behind a load balancer — it is real, and it is essentially the design you described.** The caveat is purely about timing: it's part of a Release Candidate, locked 2026-05-21, not finalized until 2026-07-28. SEPs marked "Final" within an RC are the ones the working group considers settled for that release, but until the RC itself ships, treat it as high-confidence-but-not-yet-authoritative.

---

## 7. Official SDKs

### TypeScript SDK (`@modelcontextprotocol/sdk`)

Current published version: **1.29.0** on npm **[Verified directly via `registry.npmjs.org/@modelcontextprotocol/sdk/latest`]**. A v2 beta targeting the 2026-07-28 spec exists on the repo's main branch; v1.x remains the supported line during the transition.

Exposes a **low-level `Server` class** with `server.setRequestHandler(SomeRequestSchema, handler)` per JSON-RPC method (`CallToolRequestSchema`, `ListToolsRequestSchema`, etc.) — full control to inspect/modify/reject before delegating — plus a **`Client` class** for connecting onward to a real server, and stdio/Streamable-HTTP transport classes. **No built-in proxy example or interceptor/middleware hook system is documented in the official README** — building a proxy means composing `Server` + `Client` + transports yourself. A community proof of this pattern: **`punkpeye/mcp-proxy`**, a stdio↔HTTP/SSE bridge built on exactly these SDK primitives — but it's a pure transport bridge with no gating/approval logic.

### Python SDK (`mcp` package)

Current stable version reported as **1.28.1** (per research agent; not independently re-verified by the report author). FastMCP 1.0 was folded into the official SDK in 2024 as `mcp.server.fastmcp.FastMCP`.

The **standalone `fastmcp`** package (PrefectHQ/jlowin) has the more mature proxy/middleware story and is the closest existing prior art to KnoTrust's shape:

- A genuine **Middleware system** — subclass `Middleware`, override async hooks `on_message` (broadest) → `on_request` → `on_call_tool` (most specific); each can inspect/modify/reject a JSON-RPC request before it proceeds, with the response flowing back through the chain in reverse.
- **`FastMCP.as_proxy()`** — an async classmethod that connects to a backend MCP server, discovers its capabilities, and builds a local proxy forwarding tool calls, resource reads, sampling, elicitation, logging, and progress, explicitly documented as a transport-bridging ("stdio-in/SSE-out") pattern.

**[SDK version numbers and the FastMCP middleware/proxy claims: verified by research agent, not independently re-checked by the report author, aside from the TS SDK npm version above.]**

### Existing MCP gateway / proxy / governance projects (competitive landscape)

Reported as a moderately active, named category rather than an empty field — a curated list exists at `github.com/e2b-dev/awesome-mcp-gateways`. Named examples surfaced: **Preloop** (OSS, CEL-based policy + Slack/Teams HITL approvals), **Helio** (OSS proxy, declarative policy + Slack/email/dashboard approval + audit log), **Lunar.dev / MCPX** (OSS gateway, tool-level access control + audit trails), **Assay** ("firewall for MCP tool calls," OWASP MCP Top 10 coverage), **AgentJail** (OPA/Rego-based policy daemon), **Microsoft MCP Gateway** (Kubernetes reverse proxy, session-aware routing, Entra ID), **Obot**, and **AWS MCP Gateway & Registry**. **[Verified by research agent only — treat names/URLs as leads to re-check before citing in any public KnoTrust materials, not as confirmed facts.]**

---

## 8. Auth in MCP (Access Control — Distinct from KnoTrust's Action Governance)

**[Verified directly against `modelcontextprotocol.io/specification/2025-11-25/basic/authorization`.]**

- MCP servers act as **OAuth 2.1 resource servers**; clients act as OAuth 2.1 clients.
- Servers **MUST** implement **Protected Resource Metadata (RFC 9728)**; clients **MUST** use it for authorization-server discovery.
- Clients **MUST** implement **PKCE** (S256) per OAuth 2.1 §7.5.2.
- Clients **MUST** implement **Resource Indicators (RFC 8707)**; servers **MUST** validate that a token's audience is specifically them, and **MUST NOT** accept or transit tokens issued for anyone else — explicitly framed as preventing token-passthrough/confused-deputy attacks. Directly relevant to a proxy operator: *"MCP proxy servers using static client IDs MUST obtain user consent for each dynamically registered client before forwarding..."*
- **Dynamic Client Registration (RFC 7591)** is now only a **MAY**, kept for backward compatibility; **Client ID Metadata Documents** are the newer, preferred (SHOULD-level) mechanism.
- **stdio is explicitly exempt**, verbatim: *"Implementations using an STDIO transport SHOULD NOT follow this specification, and instead retrieve credentials from the environment."* The entire authorization framework is optional and scoped to HTTP-based transports.

### The boundary, stated precisely

MCP's OAuth-based authorization answers exactly one question: *is this bearer token, bound to this audience, valid for opening a connection to this MCP server at all?* It's a connection/session-level gate, evaluated via coarse, server-declared scopes (e.g. `files:write`) — not evaluated per tool call and not evaluated against argument values. A direct search of the authorization spec found **no language anywhere about per-call or per-argument authorization, policy, or human approval.** Whether an already-authorized, already-scoped call — `delete_file(path="/prod/db.sql")` vs. `delete_file(path="/tmp/scratch.txt")` — should actually be allowed to execute is a question the spec never addresses. That gap is precisely KnoTrust's domain: action governance operates *after* MCP-level authorization has already succeeded, evaluating the specific call and its arguments, optionally gating on human approval, on a per-invocation basis.

---

## Maturity & Uncertainty

| Area | Confidence | Notes |
|---|---|---|
| 2025-11-25 stable spec (transports, tools, elicitation, annotations, auth) | **High.** | Directly fetched from `modelcontextprotocol.io` and the raw `schema.ts`; verbatim quotes extracted from actual page content, cross-checked in two independent passes (research agent + report author). |
| 2026-07-28 RC's existence and headline content (stateless core, four SEPs, RC/final dates) | **Medium-high, but explicitly provisional.** | Directly verified across 7 independent primary-source fetches (the RC blog + SEP-2575, 2567, 2322, 2243 pages), all internally consistent and extremely detailed (specific error codes, RFC citations, conformance test tables, rationale sections weighing rejected alternatives) — a level of detail that is hard to attribute to coincidental hallucination across independent fetches. **However**, this is by definition a Release Candidate: it was locked 2026-05-21 and is not the current spec until 2026-07-28. Content could still shift before finalization. Additionally, the `WebFetch` tool used for verification processes pages through an intermediate model rather than returning raw bytes, which carries a small residual risk of subtle transcription error even when the underlying source is genuine — mitigated here by cross-checking specific facts (header names, error codes, SEP statuses) across multiple independent fetches. |
| Header-based routing (`Mcp-Method`/`Mcp-Name`/`Mcp-Param-*`, SEP-2243) | **Medium-high for the mechanism's existence and shape; not yet real for today's stable spec.** | Directly verified in full detail (including the explicit "MUST NOT treat as trusted for security decisions" language KnoTrust needs). Does not exist in 2025-11-25 or earlier — a proxy today has no choice but to parse the JSON-RPC body. |
| Stateless resumption / MRTR (`InputRequiredResult`, `requestState`) | **Medium-high.** | Directly verified, SEP marked Final, matches the requesting user's own hypothesis closely enough to have been independently invented rather than fabricated to please the prompt — but still gated on the same RC-not-final caveat above. |
| Client support matrix for elicitation (Claude Desktop/Cowork, Codex CLI, Cursor) | **Lower — not independently re-verified.** | Sourced from one delegated research pass; the Claude Code v2.1.76 release date has an unresolved year ambiguity in the fetched snippet (almost certainly 2026, not conclusively confirmed). Re-verify directly before relying on this for a client-compatibility matrix in KnoTrust's own docs. |
| SDK versions/maturity, FastMCP middleware details, gateway/proxy competitive landscape | **Medium — partially independently checked.** | TypeScript SDK npm version (1.29.0) independently confirmed by the report author; Python SDK version, FastMCP internals, and the named competitor list were not re-checked beyond the original research pass. Treat competitor names as leads, not settled facts, until re-confirmed. |
| Auth spec (OAuth 2.1, PRM, PKCE, Resource Indicators) | **High.** | Directly fetched and quoted from the current stable authorization spec page. |

**Overall framing:** this report necessarily researches a spec revision that is still in Release Candidate status and is scheduled to finalize only ~3.5 weeks after this report's compilation date. Even with unusually thorough direct verification (this is one of the few areas where a full primary-source page, not just a search snippet, was fetched and cross-checked repeatedly), **KnoTrust's team should re-verify against `modelcontextprotocol.io` directly, close to or after 2026-07-28**, before hard-coding any of the stateless-transport, header-routing, or MRTR assumptions into shipped architecture. Everything under the 2025-11-25 stable spec is on much firmer ground and can be treated as a solid baseline today.

---

## Sources

**Primary — directly fetched by the report author:**
- https://modelcontextprotocol.io/specification/2025-11-25/changelog
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation
- https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575 (SEP-2575, Make MCP Stateless)
- https://modelcontextprotocol.io/seps/2567-sessionless-mcp (SEP-2567, Sessionless MCP via Explicit State Handles)
- https://modelcontextprotocol.io/seps/2322-MRTR (SEP-2322, Multi Round-Trip Requests)
- https://modelcontextprotocol.io/seps/2243-http-standardization (SEP-2243, HTTP Header Standardization)
- https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-06-18/schema.ts (ToolAnnotations)
- https://registry.npmjs.org/@modelcontextprotocol/sdk/latest
- https://github.com/anthropics/claude-code/releases/tag/v2.1.76

**Secondary — surfaced by delegated research passes, not independently re-fetched by the report author:**
- https://modelcontextprotocol.io/specification/2025-03-26/changelog and .../2025-06-18/changelog
- https://modelcontextprotocol.io/specification/versioning
- blog.modelcontextprotocol.io/posts/2025-11-25-first-mcp-anniversary/
- blog.modelcontextprotocol.io/posts/sdk-betas-2026-07-28/
- blog.modelcontextprotocol.io "Exploring the Future of MCP Transports" (2025-12-19)
- github.com/modelcontextprotocol/modelcontextprotocol issues #1442, #932, #994, #1302, #1730, #1439, #670, #797, #973, #835, #1603, #1330, #887, #1577, #991/#1296, #1686, #1303, #1699, #1847, #985, #1034, #1613
- github.com/modelcontextprotocol/typescript-sdk (README, Server/Client classes)
- github.com/modelcontextprotocol/python-sdk (README)
- pypi.org/project/mcp/, pypi.org/project/fastmcp/
- gofastmcp.com/servers/middleware, gofastmcp.com/servers/providers/proxy
- github.com/punkpeye/mcp-proxy
- github.com/e2b-dev/awesome-mcp-gateways
- github.com/preloop/preloop, helio.so, lunar.dev, github.com/LuD1161/agentjail, obot.ai, aws.amazon.com/blogs/opensource (MCP Gateway)
- anthropics/claude-code GitHub issue #56243 (Cowork elicitation bug, reported)
- developers.openai.com/codex/mcp; openai/codex PR #17043, issues #6992, #13405, #11816
- cursor.com/changelog/1-5

---

## Implications for KnoTrust Design

1. **Design against the 2025-11-25 stable spec as the shipping baseline today**; treat every 2026-07-28 RC detail as a forward-looking target to architect *toward*, not something to assume is deployed in the wild yet. Build the abstraction layer so protocol-version negotiation can pick either path.

2. **Never trust routing headers (`Mcp-Method`/`Mcp-Name`/`Mcp-Param-*`) as the basis for a policy decision, even once they ship.** The spec that defines them says so explicitly. Use them as a fast-path/observability optimization once available; always derive the actual allow/deny decision from the JSON-RPC body (or from a server that has already validated header/body consistency per SEP-2243's `HeaderMismatch` mechanism).

3. **Model a KnoTrust "denial" as a Tool Execution Error (`isError:true`) with an explanatory message, correlated by the original request `id`**, so the calling LLM sees and can react to the denial in-context — this is consistent with how the spec already wants input-validation-style failures surfaced. For "pending human approval," today's only real options are holding the HTTP request open or forcing a client-side retry via a protocol error; **track MRTR/`InputRequiredResult`** (2026-07-28 RC) as the sanctioned future primitive for a genuinely stateless pending-approval flow, and design KnoTrust's own approval-correlation state so it can migrate onto that mechanism once final.

4. **Do not seed automated risk tiers from tool annotations for any server KnoTrust hasn't independently vetted.** The spec's own MUST-level language forbids using annotations for trust decisions on untrusted servers. Use them, at most, as a default UX suggestion an operator reviews and can override — and even for trusted/allow-listed servers, treat them as author intent rather than verified behavior.

5. **Treat MCP's OAuth/authorization layer as strictly out of scope and orthogonal** — KnoTrust sits downstream of it. Don't duplicate PRM/PKCE/token-audience logic; consume whatever authenticated-principal information is available (e.g., a validated `sub` claim) purely as policy *context* (who is this call attributed to), never as the thing being gated.

6. **Build on existing SDK primitives rather than a from-scratch transport implementation.** The official SDKs' low-level `Server`/`Client` classes (TypeScript) and FastMCP's `Middleware` hook chain + `as_proxy()` (Python) are the closest existing patterns to "sit in front of a real MCP server and gate calls" — FastMCP in particular already has `on_call_tool`-level interception, which is nearly the exact shape KnoTrust needs for a Python-side implementation.

7. **Anticipate the session-removal direction (SEP-2567) when designing KnoTrust's own cross-call state** (e.g., correlating a pending approval across the request that triggered it and the eventual approve/deny signal). Rather than keying anything off `Mcp-Session-Id` — which the protocol is actively removing — follow the same "explicit opaque handle threaded through calls" pattern the spec itself is standardizing on.

8. **Plan a non-elicitation fallback for human approval from day one.** Elicitation support across clients is inconsistent today (solid in Claude Code; broken in Claude Desktop/Cowork; in-progress in Codex CLI; form-only, unconfirmed-for-URL-mode in Cursor). KnoTrust's approval mechanism should not assume elicitation is available — an out-of-band channel (Slack/email/dashboard, matching what Preloop, Helio, and similar existing gateways already do) should be the default, with in-band elicitation as an enhancement where the client supports it.
