# ADR-0010: PWA-first approval app; native deferred indefinitely

**Status:** Accepted (2026-07-03)

## Context

PRD §21 posed an open question: approval app — native vs. PWA for push. Phase 1 needs zero backend and zero push infrastructure, since local mode is the store and the cache with no control plane. Phase 2 introduces an optional control-plane foundation for team/enterprise sync, and any push-notification mechanism inherently requires a reachable push endpoint — so push and the Phase 2 control plane are naturally coupled rather than independent builds. Both iOS (≥ 16.4) and Android/desktop support Web Push as of 2026, removing the historical iOS gap that used to be the strongest argument for native.

## Decision

Phase 1: approval is a terminal prompt plus a localhost web approval page served by the proxy itself — this page doubles as the URL-mode elicitation target (see ADR-0007). Zero backend, zero push infrastructure. Phase 2: a PWA with Web Push, deliberately coupled to the optional control-plane foundation that Phase 2 builds anyway, since push requires a reachable endpoint regardless. SMS via a pluggable notifier (Twilio) covers the voice-approval path. Native mobile apps are deferred indefinitely, to be revisited only if PWA push proves unreliable on iOS in practice.

## Consequences

- Phase 1 ships with genuinely zero backend and zero push infrastructure, matching the "local-first, zero-backend free path" commitment (PRD §11).
- The Phase 2 PWA's dependency on the control-plane foundation is an honest architectural coupling, not an arbitrary bundling decision — push cannot exist without a reachable endpoint, and Phase 2 is exactly where that endpoint is being built for other reasons (policy/grant/audit sync).
- Native mobile development is not undertaken unless PWA push specifically fails in practice on iOS — this avoids committing engineering effort to a platform-specific app before there is evidence PWA push is inadequate.
- The localhost approval page's dual role (terminal-adjacent web UI and URL-mode elicitation target) means it is not extra scope — it is the same page brief §C3's channel-plural approval mechanism already requires.

## Alternatives considered

- **Native mobile app for Phase 1 or Phase 2** — deferred, not rejected outright: PWA + Web Push is judged adequate given both iOS ≥ 16.4 and Android/desktop supporting Web Push in 2026; native is the fallback specifically if PWA push proves unreliable on iOS.
- **Building push infrastructure independent of the control-plane foundation** — rejected: push requires a reachable endpoint, so building it separately from Phase 2's control plane would duplicate infrastructure that Phase 2 already needs to build.
- **Shipping Web Push already in Phase 1** — rejected: Phase 1 is explicitly zero-backend, and push cannot exist without a reachable endpoint; pulling push forward would require standing up exactly the control-plane infrastructure Phase 1 is designed to avoid.

## References

- Brief §B3 (full decision text, including the iOS ≥16.4/Android Web Push support claim and the Phase 2 control-plane coupling rationale); §D (Approval UI row); §G ("native mobile approval app (deferred: PWA push adequate)"); PRD §21 (the original open question).
