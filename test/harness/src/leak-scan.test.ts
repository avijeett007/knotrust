/**
 * @knotrust/test-harness — global frame-scan / leak-scan assertion unit
 * suite (P0-E5-T4, R76; invariant §4.3).
 *
 * `findLeaks`/`assertNoLeakedSecrets` are the REUSABLE substrate every
 * model-visible-frame-emitting suite (E5's own tests, E11-T2/T5's
 * adversarial batteries, and any future one) calls to mechanically prove
 * "no approval token or policy-internal identifier ever reaches
 * model-visible content." This suite proves the scanner itself: it detects
 * both token shapes (the `tok_...` opaque-id shape and a bare 128-bit hex
 * run — see `leak-scan.ts`'s header for why BOTH are defined now, ahead of
 * E6-T3 actually minting tokens), detects the closed set of internal
 * reason-code strings R75 maps away, passes clean input, and — critically —
 * only scans the `direction: "recv"` subset of a `Frame[]` transcript (what
 * the model/agent actually received), never the `"sent"` subset (what the
 * agent itself sent, which is none of KnoTrust's business to police).
 */

import { describe, expect, it } from "vitest";
import type { Frame } from "./frame.js";
import { assertNoLeakedSecrets, findLeaks } from "./leak-scan.js";

function frame(
  seq: number,
  direction: Frame["direction"],
  message: unknown,
): Frame {
  return { seq, direction, atMs: seq, message };
}

describe("findLeaks — token-shaped strings", () => {
  it("flags a tok_ prefixed opaque token (the shape E6-T3 must mint to)", () => {
    const leaks = findLeaks(
      "here is your token tok_AbCdEfGhIjKlMnOpQrStUvWx use it now",
    );
    expect(leaks.length).toBeGreaterThan(0);
    expect(leaks.some((l) => l.kind === "token")).toBe(true);
  });

  it("flags a bare 128-bit (32 hex char) run", () => {
    const leaks = findLeaks("secret=deadbeefdeadbeefdeadbeefdeadbeef end");
    expect(leaks.some((l) => l.kind === "token")).toBe(true);
  });

  it("flags a token embedded in a URL query string", () => {
    const leaks = findLeaks(
      "approve here: https://approve.knotrust.dev/a?token=tok_AbCdEfGhIjKlMnOpQrStUvWx",
    );
    expect(leaks.some((l) => l.kind === "token")).toBe(true);
  });

  it("does NOT flag a ULID-shaped decisionId (26 Crockford base32 chars, not hex, no tok_ prefix)", () => {
    const leaks = findLeaks(
      JSON.stringify({ decisionId: "01JZ8Q5XYZABCDEFGHJKMNPQRS" }),
    );
    expect(leaks).toEqual([]);
  });

  it("does NOT flag an ordinary short hex-looking substring under the 32-char floor", () => {
    const leaks = findLeaks("color #deadbe or hash abc123");
    expect(leaks).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Fix round 1 (finding 3) — hardened token detection: case-insensitivity and
// word-boundary blind spots in the original patterns.
// ---------------------------------------------------------------------------

describe("findLeaks — fix round 1: hardened token patterns (finding 3)", () => {
  it("flags an UPPERCASE hex run (the original lowercase-only pattern missed this)", () => {
    const leaks = findLeaks("token DEADBEEFDEADBEEFDEADBEEFDEADBEEF end");
    expect(leaks.some((l) => l.kind === "token")).toBe(true);
  });

  it("flags a MIXED-case hex run", () => {
    const leaks = findLeaks("token DeadBeefDeadBeefDeadBeefDeadBeef end");
    expect(leaks.some((l) => l.kind === "token")).toBe(true);
  });

  it("flags a hex run immediately flanked by ordinary letters (no whitespace/punctuation boundary) — the \\b anchoring blind spot", () => {
    // Both hex digits and 'z' are \w chars, so `\b[0-9a-f]{32,}\b` has NO
    // word boundary at either edge here and silently missed this before
    // fix round 1 — this is the exact scenario finding 3 names.
    const leaks = findLeaks("zzzdeadbeefdeadbeefdeadbeefdeadbeefzzz");
    expect(leaks.some((l) => l.kind === "token")).toBe(true);
  });

  it.each([
    ["TOK_AbCdEfGhIjKlMnOpQrStUvWx", "uppercase TOK_ prefix"],
    ["Tok_AbCdEfGhIjKlMnOpQrStUvWx", "mixed-case Tok_ prefix"],
  ])("flags a %s-prefixed token (any casing of the literal prefix, per the binding contract)", (token) => {
    expect(
      findLeaks(`here is your token ${token} use it`).length,
    ).toBeGreaterThan(0);
    expect(
      findLeaks(`https://approve.knotrust.dev/a?token=${token}`).length,
    ).toBeGreaterThan(0);
    expect(
      findLeaks(JSON.stringify({ structuredContent: { nested: { token } } }))
        .length,
    ).toBeGreaterThan(0);
  });

  it("documents the residual gap: a bare (non-tok_-prefixed, mixed-case) base64url token is NOT reliably caught — best-effort only", () => {
    // A realistic ~128-bit bare base64url token: mixed case, includes
    // non-hex letters, no `tok_` prefix. Neither `APPROVAL_TOKEN_HEX_PATTERN`
    // (hex chars only) nor `APPROVAL_TOKEN_PREFIXED_PATTERN` (requires the
    // `tok_` prefix) is built to catch this shape — this is the KNOWN,
    // ACCEPTED blind spot `leak-patterns.ts`'s header documents as the
    // reason the `tok_` prefix is the BINDING contract for E6-T3, not the
    // hex/bare fallback. This test exists to make the gap explicit and
    // regression-tested, not to assert it is closed.
    //
    // Built via concatenation (not one literal) purely so this obviously-
    // fake fixture doesn't superficially resemble a real credential to
    // generic secret-scanners; the assembled value is what's actually
    // exercised below.
    const bareBase64Token = "Xk9pQz3mNc7Vb" + "Gh2Ls5TyRf8";
    const leaks = findLeaks(`approve: ${bareBase64Token} now`);
    expect(leaks).toEqual([]);
  });
});

describe("findLeaks — policy-internal identifiers", () => {
  it.each([
    "tier_cap_violation",
    "envelope_deny",
    "envelope_force_approval",
    "explicit_config_deny",
    "grant_exceeds_envelope",
    "grant_replayed",
    "audit_unavailable",
  ])("flags the internal reason code %s", (code) => {
    const leaks = findLeaks(`decision reason: ${code}`);
    expect(leaks.some((l) => l.kind === "policy_internal")).toBe(true);
  });

  it("flags a reasonAdmin-shaped key appearing in serialized content", () => {
    const leaks = findLeaks(
      JSON.stringify({ reasonAdmin: "matched pack rule R14" }),
    );
    expect(leaks.some((l) => l.kind === "policy_internal")).toBe(true);
  });

  it("does NOT flag the SAFE reason codes the model is meant to see", () => {
    const leaks = findLeaks(
      JSON.stringify({
        reasonCode: "blocked_needs_grant",
      }),
    );
    expect(leaks).toEqual([]);
    for (const safe of [
      "blocked_needs_approval",
      "blocked_by_policy",
      "unavailable",
      "not_eligible_here",
    ]) {
      expect(findLeaks(`reasonCode: ${safe}`)).toEqual([]);
    }
  });
});

describe("findLeaks — clean input", () => {
  it("a well-formed denial envelope string with no leaks scans clean", () => {
    const clean = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      result: {
        isError: true,
        content: [
          {
            type: "text",
            text: "This action was blocked (sensitive tier) and was not performed. A human can approve it via the KnoTrust prompt or `knotrust approvals`.",
          },
        ],
        structuredContent: {
          knotrust: {
            outcome: "deny",
            decisionId: "01JZ8Q5XYZABCDEFGHJKMNPQRS",
            tierClass: "sensitive",
            reasonCode: "blocked_needs_grant",
            retryable: false,
            humanApproval: {
              possible: true,
              hint: "Approve via the KnoTrust prompt or `knotrust approvals`",
            },
            requestable: {
              how: "knotrust grant --tool stripe.refund --server stripe",
            },
            auditRef: "01JZ8Q5XYZABCDEFGHJKMNPQRS",
          },
        },
      },
    });
    expect(findLeaks(clean)).toEqual([]);
  });
});

describe("findLeaks — Frame[] input scopes to direction: recv only", () => {
  it("ignores a leak-shaped string in a 'sent' frame", () => {
    const frames: Frame[] = [
      frame(0, "sent", {
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          name: "x",
          arguments: { note: "tok_AbCdEfGhIjKlMnOpQrStUvWx" },
        },
      }),
    ];
    expect(findLeaks(frames)).toEqual([]);
  });

  it("flags a leak in a 'recv' frame and reports its seq/direction", () => {
    const frames: Frame[] = [
      frame(0, "sent", { jsonrpc: "2.0", method: "tools/call", params: {} }),
      frame(1, "recv", {
        jsonrpc: "2.0",
        id: 1,
        result: { content: [{ type: "text", text: "reason: envelope_deny" }] },
      }),
    ];
    const leaks = findLeaks(frames);
    expect(leaks.length).toBe(1);
    expect(leaks[0]).toMatchObject({ frameSeq: 1, direction: "recv" });
  });
});

describe("assertNoLeakedSecrets", () => {
  it("does not throw on clean input", () => {
    expect(() => assertNoLeakedSecrets("nothing to see here")).not.toThrow();
  });

  it("throws a descriptive error when a leak is present", () => {
    expect(() => assertNoLeakedSecrets("reason: tier_cap_violation")).toThrow(
      /tier_cap_violation/,
    );
  });
});
