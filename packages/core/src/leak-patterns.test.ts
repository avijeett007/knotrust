/**
 * @knotrust/core — unit coverage for the relocated leak-pattern source
 * (P0-E5-T4 fix round 2, R80).
 *
 * This only proves the patterns/identifiers themselves behave as
 * documented (core's own responsibility now that it hosts them).
 * `@knotrust/test-harness`'s `leak-scan.test.ts` covers the SCANNER built
 * on top of these (`findLeaks`/`assertNoLeakedSecrets`, including the
 * `Frame[]` recv/sent-direction behavior) and is unaffected by this
 * relocation — it imports the very same exports, now from `@knotrust/core`
 * instead of a package-local module.
 */

import { describe, expect, it } from "vitest";
import {
  APPROVAL_TOKEN_HEX_PATTERN,
  APPROVAL_TOKEN_PREFIXED_PATTERN,
  POLICY_INTERNAL_IDENTIFIERS,
  POLICY_INTERNAL_PATTERNS,
} from "./leak-patterns.js";

describe("APPROVAL_TOKEN_PREFIXED_PATTERN", () => {
  it("matches a tok_-prefixed opaque id (>=22 base64url chars)", () => {
    APPROVAL_TOKEN_PREFIXED_PATTERN.lastIndex = 0;
    expect(
      APPROVAL_TOKEN_PREFIXED_PATTERN.test("tok_AbCdEfGhIjKlMnOpQrStUvWx"),
    ).toBe(true);
  });

  it("matches any casing of the tok_ prefix (fix round 1 hardening)", () => {
    APPROVAL_TOKEN_PREFIXED_PATTERN.lastIndex = 0;
    expect(
      APPROVAL_TOKEN_PREFIXED_PATTERN.test("TOK_AbCdEfGhIjKlMnOpQrStUvWx"),
    ).toBe(true);
  });

  it("does not match a tok_ id shorter than the 22-char floor", () => {
    APPROVAL_TOKEN_PREFIXED_PATTERN.lastIndex = 0;
    expect(APPROVAL_TOKEN_PREFIXED_PATTERN.test("tok_short")).toBe(false);
  });
});

describe("APPROVAL_TOKEN_HEX_PATTERN", () => {
  it("matches a bare 32+ char hex run, case-insensitively", () => {
    APPROVAL_TOKEN_HEX_PATTERN.lastIndex = 0;
    expect(
      APPROVAL_TOKEN_HEX_PATTERN.test("DEADBEEFDEADBEEFDEADBEEFDEADBEEF"),
    ).toBe(true);
  });

  it("matches a hex run flanked by letters (no \\b anchors — fix round 1)", () => {
    APPROVAL_TOKEN_HEX_PATTERN.lastIndex = 0;
    expect(
      APPROVAL_TOKEN_HEX_PATTERN.test("zzzdeadbeefdeadbeefdeadbeefdeadbeefzzz"),
    ).toBe(true);
  });

  it("does not match a short hex-looking run under the 32-char floor", () => {
    APPROVAL_TOKEN_HEX_PATTERN.lastIndex = 0;
    expect(APPROVAL_TOKEN_HEX_PATTERN.test("abc123")).toBe(false);
  });
});

describe("POLICY_INTERNAL_IDENTIFIERS", () => {
  it("contains every internal reason code toSafeReasonCode maps away", () => {
    for (const id of [
      "no_grant_sensitive",
      "no_grant_critical",
      "tier_cap_violation",
      "envelope_deny",
      "envelope_force_approval",
      "explicit_config_deny",
      "grant_exceeds_envelope",
      "grant_replayed",
      "audit_unavailable",
      "internal_error",
      "enforcement_error",
    ]) {
      expect(POLICY_INTERNAL_IDENTIFIERS).toContain(id);
    }
  });
});

describe("POLICY_INTERNAL_PATTERNS", () => {
  it("matches rule-id/policy-id/pack-id in hyphen, underscore, and bare forms", () => {
    for (const candidate of [
      "rule-id",
      "rule_id",
      "ruleid",
      "policy-id",
      "pack_id",
    ]) {
      const hit = POLICY_INTERNAL_PATTERNS.some((re) => {
        re.lastIndex = 0;
        return re.test(candidate);
      });
      expect(hit).toBe(true);
    }
  });

  it('matches the "reasonAdmin" JSON key shape', () => {
    const hit = POLICY_INTERNAL_PATTERNS.some((re) => {
      re.lastIndex = 0;
      return re.test('{"reasonAdmin":"x"}');
    });
    expect(hit).toBe(true);
  });
});
