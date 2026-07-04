# ADR-0007: Channel-plural approval subsystem with block-and-wait as universal fallback

**Status:** Accepted (2026-07-03)

## Context

PRD §9 had assumed MCP elicitation as *the* approval mechanism. Research found client support for elicitation is uneven: solid in Claude Code, broken in Claude Desktop at the time of writing, in-progress in Codex CLI, and form-only in Cursor. Since the flagship demo (brief §F: "Phase 1's flagship demo must run on the block-and-wait fallback... with elicitation as progressive enhancement") must work on every client regardless of elicitation support, elicitation cannot be the sole approval path without making the demo itself fragile to client-support gaps.

## Decision

The approval subsystem is channel-plural from day one, in priority order: (1) form-mode elicitation where the client supports it, (2) URL-mode elicitation bouncing the user to the localhost approval page, (3) a fallback of block-and-wait — the proxy holds the call, prints the approval URL/code to the terminal and/or notifier, and resolves on approval, deny, or timeout (timeout resolves to deny, and is audited). The block-and-wait fallback is what makes the flagship demo work on every client independent of elicitation support, and is treated as the baseline, not an afterthought.

## Consequences

- The flagship demo (Claude Desktop stdio proxy, calm-down-Claude) is guaranteed to work regardless of a given client's elicitation maturity, because the fallback path never depends on elicitation being implemented correctly by the client.
- Elicitation (form-mode, URL-mode) is progressive enhancement layered on top of a working baseline, not a hard dependency for launch.
- A timeout must resolve to deny, and that resolution is itself an audited event — timeouts are never silently dropped or silently allowed.
- Claude Desktop's elicitation gaps specifically must be re-verified at Phase-1 launch, since client behavior in this space is actively changing.
- This decision directly supports the "critical, voice" path (PRD §10) and the future `deferred_not_eligible` outcome, since block-and-wait's async, out-of-band shape generalizes cleanly to non-interactive contexts.

## Alternatives considered

- **Elicitation-only approval mechanism** (the PRD §9 original assumption) — rejected: client support is too uneven today (broken in Claude Desktop, form-only in Cursor) to be a sole dependency for a launch-critical demo.
- **Requiring a specific client's elicitation support as a launch gate** — rejected: this would make the flagship demo dependent on external client roadmaps outside KnoTrust's control, directly conflicting with the competitive-speed pressure identified in brief §C1.

## References

- Brief §C3 (full channel-plural decision and rationale); §F (Phase 1 sequencing: block-and-wait as the flagship's baseline, elicitation as progressive enhancement); §D (Approval UI row, Phase 1 localhost page as the URL-mode elicitation target).
- Research: `docs/01-research/competitive-and-packaging.md` §1 (native client permission model table showing elicitation/approval-support unevenness across Claude Desktop, Claude Code, Codex CLI, Cursor).
