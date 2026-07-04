# Spike findings: stateless HTTP resumption via `requestState` (P0-E10-T1)

**Status: SPIKE, not production.** This document is the real deliverable
of P0-E10-T1; the code that produced it lives in `spikes/http-proxy/`
(throwaway, non-production, never wired into any `@knotrust/*` package,
never published — see that directory's own `README.md`). Nothing here
changes any product package. If anything below reveals a real gap in a
shipped shape (it does, once — §6), it is **noted, not fixed**, per R164.

**Timebox honored (R161):** minimal Hono two-replica demo, run once
end-to-end, findings written up. No tests, no error-handling polish, no
retry logic, no persistence.

## 0. The question this de-risks

The MCP 2026-07-28 Release Candidate (locked 2026-05-21, targeting final
publication ~2026-07-28 — see `docs/01-research/mcp-protocol-and-spec.md`
§6/§Streamable-HTTP) removes sessions from the protocol core and
introduces **SEP-2322 (Multi Round-Trip Requests / MRTR)**: a `tools/call`
(or `prompts/get`/`resources/read`/`tasks/result`) can return an
`InputRequiredResult` instead of its normal result, carrying an **opaque**
`requestState` string the client must echo back verbatim on a follow-up
request, together with `inputResponses`. Because `requestState` round-trips
through the client, *any* stateless server replica can pick up exactly
where processing left off — no held-open connection, no shared session
store.

That is precisely the mechanism ADR-0006 already named as the thing the
`SpecAdapter` boundary exists to absorb, and precisely the mechanism
`docs/04-roadmap/implementation-plan.md`'s Phase-2 DoD cites verbatim:
*"two-replica `requestState` pending-approval resumption green on final
spec."* This spike builds the smallest possible version of that resumption
and answers the four questions R163 requires.

## 1. requestState encoding scheme

**Exact scheme (`spikes/http-proxy/src/request-state.mjs`):**

- **Primitive:** AES-256-GCM — a single authenticated-encryption primitive,
  not "encrypt, then separately compute an HMAC." GCM's authentication tag
  *is* the MAC here.
- **AAD (associated-authenticated-data) input:** `` `${principal}|${callHash}` ``
  — this is the literal implementation of the §I2.4 ruling ("the MAC input
  binds principal + call hash"). `callHash` is this spike's simplified
  stand-in for `@knotrust/grants`'s real `computeCallHash` (P0-E3-T3, SARC
  v1 normal form) — same idea (a digest of "which call was approved"),
  deliberately reimplemented small and local rather than imported, per
  R164.
- **Plaintext (encrypted):** `{ approvalId, call }` — the full
  reconstructable pending call (the tool name + arguments + resource), not
  just an ID. This is what makes resumption stateless: replica B never
  looked this up anywhere; it decrypted it.
- **Wire format:** `base64url(JSON.stringify({ v:1, callHash, iv, ct, tag }))`.
  `callHash` travels in cleartext alongside the ciphertext (it's a one-way
  digest, not secret) so the verifier can reconstruct the same AAD bytes
  the minting replica used; `iv`/`ct`/`tag` are each base64url.
- **Key management (spike):** a single hardcoded 32-byte hex key, passed to
  both replica processes via the `SHARED_SECRET_HEX` env var —
  `spikes/http-proxy/src/run-demo.mjs` generates one value and hands it to
  both. Documented everywhere in the code as **not a production pattern**.

**What it guarantees:** decryption succeeds **only** if the verifier
reconstructs byte-identical AAD to what the minter used. The verifier
builds its half of the AAD (`currentPrincipal`) from the **current
request's own independently-authenticated identity** — never from anything
inside the `requestState` the client echoes. Concretely, that means:

- **Unforgeable:** without the shared key, no attacker can produce a
  `requestState` that decrypts under any AAD (standard AEAD property).
- **Non-replayable across principal:** the *same, byte-for-byte-unmodified*
  `requestState` that decrypts cleanly for `alice` **fails GCM tag
  verification** when replayed under `bob`'s identity — proven directly in
  the captured run below (Step 5), and it fails through the **identical
  error path** as outright ciphertext tampering (Step 4). That collapse
  into one failure mode is the single most important design property this
  spike surfaces: there is no separate "does principal match" string
  comparison sitting downstream of decryption for a future engineer to
  forget to write, or to write with a subtle bug (e.g., a non-constant-time
  compare, or a check that's reachable-but-skippable on some code path).
  The binding **is** the decryption.
- **Non-replayable across call:** tampering with the embedded call
  (arguments, tool name) — the only way to redirect a `requestState` at a
  *different* call than the one actually approved — breaks the ciphertext
  and is caught the same way. This spike also re-derives `callHash` from
  the decrypted call and compares it to the AAD-bound value as a redundant,
  defense-in-depth check (mirroring the pattern `packages/grants/src/verify.ts`
  already uses for grant `call_hash` re-derivation) — in principle
  unreachable if the GCM tag already passed, but cheap insurance against a
  bug in this file specifically.

**Size overhead:** the captured run's `requestState` for a small
`stripe.refund_payment` call (charge id + amount) was **568 bytes**
base64url — i.e., roughly 3-4x the ~150-200 byte JSON plaintext it encodes,
which is the expected AES-GCM-plus-base64url-plus-JSON-envelope overhead
(12-byte IV + 16-byte tag + base64 ~33% expansion + the `{v,callHash,iv,ct,tag}`
JSON scaffolding, where `callHash` itself is a 71-character hex-prefixed
string). This is small in absolute terms but is **not free** — see §3 for
what happens to it if the RC's MRTR wire shape changes.

**Recommended Phase-2 production scheme:**

1. **KMS-backed key, not a hardcoded/env value.** The shared secret both
   replicas need must come from a real KMS (AWS KMS, GCP KMS, HashiCorp
   Vault, or the self-hosted OSS equivalent already implied by
   `docs/04-roadmap/implementation-plan.md`'s P2-E5 control-plane
   foundation) — every replica fetches the *current* key at boot/refresh,
   never bakes it into an image or env var.
2. **Key rotation with a short grace window.** Since a `requestState` can
   legitimately outlive a few minutes (human approval latency), Phase 2
   needs a key **id** embedded in cleartext next to `callHash` (this spike
   has exactly one key, so there was nothing to select) so a verifier can
   look up "key epoch N" even after "key epoch N+1" is now the mint key —
   otherwise rotation silently invalidates every in-flight approval at the
   moment of rotation, which is a real (if narrow) availability regression
   to design against, not just a security nicety.
2b. **A short server-side TTL embedded in and checked from the plaintext**
    (`exp` field) so a `requestState` can't be replayed arbitrarily far in
    the future even with a valid key — this spike has none (see §4, "left
    open").
3. **Real SARC v1 `computeCallHash`** (`@knotrust/grants`, JCS-canonical,
   frozen, golden-vector-tested), not this spike's local
   `JSON.stringify`-based stand-in.
4. Keep the **AAD-as-the-binding** design (§1 above) — it is simple, has no
   separate forgettable check, and this spike found no reason to deviate
   from it for Phase 2.

## 2. Tenant-isolation implications

The AAD binding (`principal|callHash`) is doing real tenant-isolation work
today, in miniature: Step 5 of the captured run is literally "tenant A's
(here, `alice`'s) genuine, unmodified approval state, replayed by a
different identity (`bob`)" — and it fails identically to a forged token.
If `principal` in a Phase-2 build is (or includes) a validated tenant/org
identifier — matching `docs/04-roadmap/implementation-plan.md`'s
P2-E2 "tenant keying from validated auth context" and brief §E7's
`scope: personal|org` schema field already present since P0-E4-T2 — then
this exact mechanism is what stops tenant B's proxy replica (or a
compromised client, or a leaked log line) from redeeming tenant A's pending
approval, **even against a replica that has never served tenant A's traffic
before**, without any cross-tenant lookup table at all.

What the real HTTP proxy needs on top of what this spike proved, for full
tenant isolation (P2-E2's own stated exit criterion: "cross-tenant leakage
adversarial tests"):

- **`principal` must be an independently-authenticated identity from the
  auth layer, never a client-supplied header** — this spike's
  `X-Principal` header is a stand-in for "whatever the real OAuth
  2.1/token-introspection layer already resolved," and is explicitly
  documented as such in `spikes/http-proxy/src/replica.mjs`'s comments; a
  literal port of this trust model to production (trusting a raw header)
  would be a real vulnerability, not a simplification.
- **The AAD should probably include the tenant/org id as a distinct field
  from the human principal** (`tenantId|principal|callHash`), so a
  same-username collision across two different orgs (unlikely with a real
  identity system, but not structurally impossible depending on how
  `subject.id` is sourced) can't accidentally satisfy the binding. This
  spike used a single flat `principal` string; Phase 2 should not assume
  global uniqueness of that string across tenants without checking.
- **Per-tenant key material is a stronger posture than one global shared
  key** (this spike's one hardcoded key is deliberately the weakest
  possible baseline) — worth evaluating against the added key-management
  complexity in P2-E5's control-plane design, not assumed here.
- **Audit/observability must record `requestState` mint and resume as
  distinct, correlated events** (mint→approvalId, resume→approvalId) so a
  cross-tenant replay *attempt* (Step 5's scenario, but against a real
  attacker) shows up in the audit trail even though it's cryptographically
  rejected — this spike only logs to stderr, not to any audit sink.

## 3. What breaks if the RC shifts (re-verify list for post-final-spec)

The 2026-07-28 spec is a **Release Candidate**, not final, as of this
writing. `docs/01-research/mcp-protocol-and-spec.md` rates SEP-2322 itself
"Status: Final" within the RC (i.e., the working group considers *that*
SEP settled for this release) but the RC as a whole is not authoritative
until publication. Re-verify every item below against
`modelcontextprotocol.io` **directly at or after 2026-07-28**, before
hardening any of this into the real `SpecAdapter`:

1. **The exact `InputRequiredResult`/`requestState` field names and
   nesting.** This spike invented its own JSON-RPC envelope shape
   (`result.resultType`, `result.inputRequests`, `result.requestState`)
   from the research doc's prose description — it was **not** validated
   against a real schema file or SDK type (the `@modelcontextprotocol/sdk`
   version pinned in this repo, 1.29.0, predates the RC; a v2 beta
   targeting 2026-07-28 exists but is not what's installed here). If the
   final field names/nesting differ even slightly, every place this spike
   assumed a shape needs a matching update — but that update is entirely
   inside the (not-yet-built) `SpecAdapter`, per ADR-0006's whole reason
   for existing.
2. **Whether the "resume" request is really a bare `inputResponses` +
   `requestState` payload, or is itself wrapped in a specific new JSON-RPC
   method** (the research doc mentions `tasks/input_response` as the
   mechanism for the *Tasks extension*'s persistent-tool integration, which
   may or may not be the same shape MRTR uses for a plain `tools/call`).
   This spike invented a bespoke `POST /mcp/resume` HTTP route rather than
   modeling a specific JSON-RPC method name — re-verify what the real
   method is called and whether it round-trips the original `id`.
3. **Whether `requestState` is expected to be bounded in size.** This
   spike's 568-byte figure was for a small call; a call with large
   `arguments` (e.g., a big JSON blob tool input) could produce a
   `requestState` in the kilobytes, and if the final spec (or a given
   transport/CDN/gateway in front of the real deployment) caps
   header/body/URL sizes, that's a real constraint this spike didn't hit
   only because its demo payload was small. Re-check whether the final
   spec says anything about a size ceiling.
4. **Whether servers are required (not just permitted) to validate
   `requestState` cryptographically.** The research doc's summary says
   "Servers are required to cryptographically validate/bind `requestState`
   since it's untrusted, client-carried data" — re-verify the exact MUST/
   SHOULD language in the final spec text, since that phrasing determines
   whether an unbound/unsigned `requestState` implementation would be
   spec-non-conformant (today, in the RC text) or merely
   unwise-but-permitted.
5. **`Mcp-Method`/`Mcp-Name` header requirements** (SEP-2243) — this spike
   demonstrated the header/body mismatch rejection (Step 6) using
   invented header names/casing (`mcp-method`, `mcp-name`, lowercased by
   Hono's header accessor) and an invented `-32001 HeaderMismatch` error
   code copied from `docs/02-architecture/system-architecture.md`'s own
   citation — re-verify the actual required header names, casing
   sensitivity, and error code against the final SEP-2243 text.
6. **Whether MRTR interacts with the Tasks extension for long-running
   tools at all**, and if so how — the research doc notes this
   integration exists for "persistent" tools but this spike did not model
   it (single-round approval only).

## 4. Phase-2 design recommendations

**What this spike validated (with reasonable confidence, modulo §3):**

- The core statelessness claim is real and mechanically simple: an AEAD
  primitive with the right AAD input is *sufficient* to make "replica B,
  which never saw the original call, resolves it correctly and rejects
  everyone else" work, with no shared store, no sticky sessions, no
  cross-replica RPC.
- The "tamper" and "wrong principal" failure modes are cryptographically
  identical under this design (§1) — a genuinely good property to carry
  into Phase 2 as a design constraint, not just an implementation detail.
- Headers-as-routing-only (brief §C2) composes cleanly with this: nothing
  about the resumption mechanism needed to trust a header for anything
  beyond the pre-decision HeaderMismatch check.

**What this spike left open (explicitly, per R162's "not required" list —
these are real gaps for Phase 2 to close, not oversights of this task):**

- **No replay/single-use tracking.** Nothing in this design stops the
  *same* valid `requestState`, from the *correct* principal, being
  replayed to execute the approved call **twice** (or N times). Real MRTR
  statelessness and single-use enforcement are in genuine tension: full
  statelessness means no shared "already consumed" record exists anywhere,
  but single-use approval is a real product requirement (an approved
  refund should fire once, not on every retry). Phase 2 needs *some* durable,
  shared-but-narrow state for this specifically — e.g., a short-TTL
  consumed-`approvalId` cache (which reintroduces a small amount of shared
  state, but far less than the full pending-approval record this spike
  proved doesn't need to be shared) — this is a real design decision for
  Phase 2, not a gap in this spike's crypto.
- **No error handling, no retries, no timeouts** on the upstream fetch or
  on malformed input generally (R161's explicit non-goal).
- **No real transport-level auth** — `X-Principal` is a stand-in for a
  validated identity (see §2).
- **Replica coordination for non-approval state** (e.g., rate limiting,
  circuit breaking) is untouched — this spike only proves the *approval*
  path is replica-agnostic, not that everything a real proxy needs is.
- **The `SpecAdapter` boundary itself doesn't exist yet** (ADR-0006 names
  it as the future absorption point but P0 doesn't build it) — this spike
  is evidence for what that adapter's HTTP-surface implementation will
  need to do, not a preview of its actual interface.

**What the real HTTP proxy (Hono, Phase 2) should do:**

1. Keep the AEAD-with-binding-AAD design from §1, upgraded to a real KMS
   key + rotation (§1) and the real SARC v1 call hash.
2. Add the missing single-use/replay control from the "left open" list
   above — this is the biggest real gap between this spike and a
   shippable Phase-2 mechanism.
3. Build the actual `SpecAdapter` HTTP surface against the **final**
   2026-07-28 schema (re-verified per §3), not this spike's invented
   envelope shapes.
4. Wire tenant/org identity into the AAD per §2, sourced from a real
   authenticated context.

## 5. A real gap this spike surfaced in the shipped approval-handle shape (noted, not fixed — R164)

`packages/approval/src/lifecycle.ts` is explicit and deliberate:
`ApprovalHandle` is `{ id, state }` **only** — "never a token, a URL, or
any [encoded secret]" (see that file's own module comment, line ~185).
That's the right shape for the stdio flagship, where the handle only ever
needs to be looked up in the *same process's* in-memory `ApprovalOrchestrator`.

Building this spike made concrete something the roadmap already gestures
at (`docs/04-roadmap/implementation-plan.md`'s E architecture invariant #2:
"`pending_approval` carrying an approval handle... encodes into
`requestState` on stateless HTTP") but doesn't yet specify a mechanism
for: **the current `ApprovalHandle`/`ApprovalOrchestrator` contract has no
hook for "mint the encrypted state that lets a *different* process
reconstruct this pending approval," nor for "given an inbound
`requestState` and a principal, reconstruct and resolve an
`ApprovalRequest` this process never created."** Those two operations
(`mintRequestState`/`verifyAndDecrypt` in this spike) are genuinely new
surface area, not a variant of anything `lifecycle.ts` exposes today.

This is **not** a defect in the current shape — `{ id, state }` is correct
for a single-process orchestrator, and changing it now would be scope creep
into Phase 2 territory for no P0 benefit. The recommendation is narrow:
**Phase 2 should add this as a new capability behind the `SpecAdapter`
boundary** (a `StatelessResumptionAdapter` or similar, wrapping
`mintRequestState`/`reconstructFromRequestState` around the existing
`ApprovalOrchestrator`), rather than changing `ApprovalHandle` itself or
teaching `lifecycle.ts` about HTTP/crypto concerns it has no business
knowing about.

## 6. Captured terminal output (one end-to-end run)

Produced by `cd spikes/http-proxy && npm install && npm run demo` on the
maintainer's machine, captured verbatim (exit code `0`, no leftover
processes on ports 4300-4302 afterward):

```
==============================================================================
SETUP — starting fake upstream MCP server + two ISOLATED replica processes
==============================================================================
[upstream] fake MCP HTTP server listening on :4300
[replica A] listening on :4301 (upstream=http://localhost:4300)
[replica B] listening on :4302 (upstream=http://localhost:4300)

==============================================================================
STEP 1 — client -> REPLICA A: tools/call stripe.refund_payment (critical) as principal=alice
==============================================================================
[replica A] routing hint headers Mcp-Method=tools/call Mcp-Name=stripe.refund_payment — decision below uses body.params.name=stripe.refund_payment ONLY
[replica A] tier=critical for stripe.refund_payment — minted requestState (approvalId=apr_13a6f182a34e46849c2c699a01788c06, callHash=sha256:c08e89a695d19c5137e97bb7dde4678c0ca97e3338e2892e4ae508a5afb508ab, requestState is 568 bytes base64url) — NOT held in this process's memory
client received: {
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "resultType": "input_required",
    "inputRequests": {
      "approval": {
        "type": "elicitation",
        "message": "Approve stripe.refund_payment? (approvalId=apr_13a6f182a34e46849c2c699a01788c06)"
      }
    },
    "requestState": "eyJ2IjoxLCJjYWxsSGFzaCI6InNoYTI1NjpjMDhlODlhNjk1ZDE5YzUxMzdlOTdiYjdkZGU0Njc4YzBjYTk3ZTMzMzhlMjg5MmU0YWU1MDhhNWFmYjUwOGFiIiwiaXYiOiJXTHk2WWc3YThqNnFkeXd3IiwiY3QiOiJQSzNPNjBQQk81U3ZmVm9FcjRSUDdkWkJ1OXA0NENsTl9tblN2TmhZVkF3VVpZZzBZeENXclZSWktDMXlRcmlNQ0NwUDdsZmNRcGdhamJOU2c2VHdja1JpZ1FvRi1IdmVQX1lxYXpKWmY3SEJ2QkVwdWpNTG54TURjc3Z4NURQaW5ueGRlMmJ6UU43REkyeHY5ckd3eHczRjE1cGc4YVpoQVIyNVFkVjQtOWNJRVgwdmo4eHRSQUVYUS1QdXptLWUwWF8wWlJXSzJpNlVfdVRMeU9EMTNRc2RFbUdVaUVuaTNLUmh5d2IwbGU3cGhxTHRUa1BneEQtRUp1TDE4M3JFODNBeGhFdk5LNUgxMW9RIiwidGFnIjoieUE5cFA3eWc5VUxJdzlvVjk4UG93dyJ9"
  }
}

==============================================================================
STEP 2 — (out of band) a human approves via the elicitation UI
==============================================================================
simulating: human clicks "Approve" -> inputResponses.approval = "approve"

==============================================================================
STEP 3 — client -> REPLICA B (the OTHER process, never saw step 1) resumes with requestState
==============================================================================
[replica B] RESUME OK — reconstructed pending call from requestState alone (approvalId=apr_13a6f182a34e46849c2c699a01788c06, callHash=sha256:c08e89a695d19c5137e97bb7dde4678c0ca97e3338e2892e4ae508a5afb508ab, action=stripe.refund_payment); this process never held it in memory
[upstream] executing tool=stripe.refund_payment arguments={"charge_id":"ch_demo123","amount":4200}
[replica B] executed upstream call for approvalId=apr_13a6f182a34e46849c2c699a01788c06
client received: {
  "jsonrpc": "2.0",
  "id": null,
  "result": {
    "resultType": "success",
    "approvalId": "apr_13a6f182a34e46849c2c699a01788c06",
    "resolvedBy": "B",
    "tool": "stripe.refund_payment",
    "executedAt": "2026-07-04T18:47:13.801Z",
    "echoArguments": {
      "charge_id": "ch_demo123",
      "amount": 4200
    },
    "note": "fake upstream MCP server — not a real Stripe/anything call"
  }
}

>>> PROVED: replica B, holding NO in-memory record of the original call, reconstructed and resolved it purely from requestState. <<<

==============================================================================
STEP 4 — TAMPER TEST: flip one character inside the ciphertext, resume against replica B
==============================================================================
[replica B] RESUME REJECTED (principal=alice): requestState authentication failed (tampered, wrong principal/call binding, or wrong key)
HTTP 403: {
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32002,
    "message": "requestState authentication failed (tampered, wrong principal/call binding, or wrong key)"
  }
}
>>> PROVED: a tampered requestState fails MAC verification (GCM auth tag), rejected before decrypt/reconstruct. <<<

==============================================================================
STEP 5 — WRONG-PRINCIPAL TEST: alice's untouched requestState, resumed as principal=bob
==============================================================================
[replica B] RESUME REJECTED (principal=bob): requestState authentication failed (tampered, wrong principal/call binding, or wrong key)
HTTP 403: {
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32002,
    "message": "requestState authentication failed (tampered, wrong principal/call binding, or wrong key)"
  }
}
>>> PROVED: the SAME unmodified, valid requestState fails when replayed under a different principal — the AAD the verifier reconstructs (bob|callHash) never matches what alice's mint used (alice|callHash), so this fails through the identical code path as tampering, not a separate forgettable check. <<<

==============================================================================
STEP 6 — HEADER/BODY MISMATCH: Mcp-Name header disagrees with body.params.name (brief §C2 / SEP-2243)
==============================================================================
[replica A] REJECT header/body mismatch: Mcp-Name=stripe.list_charges body.params.name=stripe.refund_payment
HTTP 400: {
  "jsonrpc": "2.0",
  "id": 6,
  "error": {
    "code": -32001,
    "message": "HeaderMismatch: Mcp-Name does not match body.params.name"
  }
}
>>> PROVED: header/body mismatch is rejected outright (HeaderMismatch); note from STEP 1's log line that even when headers DO match, the tier decision reads body.params.name only — headers are routing/telemetry, never the decision input. <<<

==============================================================================
STEP 7 — BODY-PARSE COST: JSON.parse over a representative tools/call payload
==============================================================================
payload size: 234 bytes
50000 JSON.parse calls: 30.61ms total, 0.612µs/call average
also for reference — the call-hash computation this spike uses on the same payload's parsed call:
50000 computeCallHash calls: 38.95ms total, 0.779µs/call average

==============================================================================
DEMO COMPLETE — all 7 steps ran end to end
==============================================================================
```

Body-parse cost reading: **~0.6µs per `JSON.parse` call** on a small
(234-byte) representative `tools/call` payload, and ~0.8µs for this
spike's (non-canonical, `JSON.stringify`-based) call-hash computation on
top of that — both negligible next to the ratified latency budgets in
`docs/03-engineering/latency-budgets.md` (the tightest of which is 5ms
p95). This is consistent with that doc's own finding that body-parsing
cost is not the bottleneck anywhere in this system; nothing here suggests
HTTP body parsing specifically becomes a concern for Phase 2 at
representative payload sizes. A large-arguments payload was not measured
(see §3 point 3 on `requestState` size at scale) and would be worth a real
measurement once the actual Phase-2 payload distribution is known.

## 7. Honest spike caveats

- **Throwaway code.** `spikes/http-proxy/` is not held to any product
  code-quality bar — no tests, minimal comments-as-documentation instead of
  real docs, single-file-per-concern only because that was convenient, not
  because of any architectural principle.
- **Hardcoded key.** One 32-byte hex constant, in the demo driver, handed
  to both replica processes via env var. Never do this in production (§1).
- **No error handling beyond the one thing under test.** Malformed input
  outside the specific shapes this demo constructs is not handled
  gracefully — the fake upstream server in particular has none at all.
- **Invented wire shapes.** The exact `InputRequiredResult`/resume JSON
  shapes are this spike's own invention from the research doc's prose
  description, not a validated schema (§3 point 1) — expect these to need
  revision once the final spec (or an SDK release targeting it) exists.
- **Single-process-pair demo, not a real multi-replica deployment.** Two
  child processes on one machine over loopback is enough to prove "no
  shared JS memory," but says nothing about real network partition
  behavior, load-balancer affinity, or clock skew across actual replica
  hosts.
- **No tenant isolation was actually tested against two tenants' real
  data** — §2's tenant-isolation claims follow logically from the
  principal-binding property demonstrated in Step 5, but no adversarial
  multi-tenant test suite was built (that's explicitly P2-E2's job, per
  the roadmap).
