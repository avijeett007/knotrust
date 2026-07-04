# Voice-outcome findings (P0-E9-T2)

This dogfood pass does **not** build voice — brief and task are explicit
that voice wiring is Phase 2 (`P2-E4`). This note is the required deliverable
instead: identify, from actually tiering a Knotie-shaped tool surface and
running it through the real three-tier proof, at least one concrete case
where a **critical** mid-conversation action would want the fourth decision
outcome, `deferred_not_eligible`, rather than the `pending_approval`
block-and-wait this build already implements for a synchronous CLI/desktop
session.

## The concrete trigger case

**`knotie.transfer_funds` (critical, `examples/dogfood/knotie/knotrust.config.yaml`)
invoked mid-voice-call.**

On the stdio/desktop surface this build ships, a `critical` call **blocks**:
the proxy holds the JSON-RPC request open, prints/pushes an approval URL,
and waits (up to `approvalTimeoutSeconds`) for a human to click Approve on
the localhost page — the human and the agent session are, by construction,
on the same machine with a browser available.

None of that holds for a voice call. There is no localhost page a phone
call can render, and — this is the load-bearing distinction —
**block-and-wait itself doesn't make sense on a live voice channel**: a
caller cannot be put on hold indefinitely while a human elsewhere reviews an
approval page, the way an agent's stdout can simply pause. If Knotie's voice
front-end asked "transfer $50 to my roommate" mid-call and the proxy tried
to hold the call open the way it does today, the caller would sit in
silence (or an audio timeout) waiting for a page nobody else is watching.
There is no eligible human-approval channel reachable *synchronously* from
inside the call at all.

That is exactly what `deferred_not_eligible` is for (brief §E2, PRD §10):
the honest answer is not "hold and hope," it's "this cannot be approved
*here*" — the call should get a clean, immediate `deferred_not_eligible`
result (something the voice agent can say out loud: "I can't complete that
right now — I'll need you to approve it later"), and the actual approval
gets deferred to a channel that *is* eligible once the call ends (Phase 2's
SMS/push notifier, `P2-E4`): the human gets a push/SMS after the call,
approves from their phone, and the transfer completes then — post-call, not
mid-call.

## Why this is the right first case (not a hypothetical)

- It's the **most severe** tier (`critical`) paired with the **least
  patient** channel (a live call) — the combination where blocking is most
  obviously wrong, so it's the clearest place to point Phase 2 at first.
- It's already tiered as `critical` by hand-review in this exact dogfood
  config, not invented for this note — the config and the finding are the
  same artifact.
- It generalizes: any `critical` Knotie tool (`knotie.delete_account` is the
  other one in this config) invoked mid-call hits the identical structural
  problem — `transfer_funds` is simply the most concrete, least abstract
  example to lead with.

## What this does NOT claim

This is a design observation from tiering + running the harness proof, not a
tested voice path — no voice surface exists in this repo to test against.
Phase 2's `P2-E4` is where `deferred_not_eligible` actually gets wired for
Knotie's voice path (per `docs/04-roadmap/implementation-plan.md`'s own
exit criterion for that epic, which already names this exact finding).
