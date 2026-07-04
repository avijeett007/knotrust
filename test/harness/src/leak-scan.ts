/**
 * @knotrust/test-harness — the global frame-scan / leak-scan assertion
 * (P0-E5-T4, R76; invariant §4.3: "no approval token or policy-internal
 * ever reaches model-visible content").
 *
 * This is the ONE reusable substrate every model-visible-content-emitting
 * test suite in this repo is meant to call — `packages/proxy-stdio`'s own
 * denial-envelope suite, and every P0-E11 adversarial battery downstream
 * (self-approval, CSRF/rebind, bait-and-switch, ...). The "every frame in
 * CI" ambition named by the acceptance bar is realized not by one giant
 * suite that sees every frame ever produced, but by this function being
 * trivially cheap to call and getting called everywhere a suite produces
 * model-visible content — see the two exported functions' doc comments for
 * the calling convention, and `test/harness/src/frame.ts`'s own header
 * ("the frame-scan substrate later tasks reuse verbatim") for the `Frame`
 * shape this builds on via `scanFrames`.
 *
 * ## Patterns live in `@knotrust/core` (fix round 1, relocated in round 2)
 *
 * Every pattern/identifier this scanner checks — both token shapes and the
 * policy-internal identifier/pattern lists — is defined in ONE place,
 * `@knotrust/core`'s `leak-patterns.ts`, and re-exported here for backward
 * compatibility. `packages/proxy-stdio/src/denial-envelope.ts`'s redactor
 * imports the SAME module (from `@knotrust/core` directly) so the scanner
 * and the redactor can never silently drift apart — see that module's
 * header for the full rationale (this fixed a real false positive: a tool
 * literally named "rule-id" used to survive the redactor's own hand-copied
 * list and then trip `assertNoLeakedSecrets`).
 *
 * Fix round 2 (R80): this module used to live locally at
 * `./leak-patterns.ts` and forced `@knotrust/proxy-stdio` — a PRODUCTION
 * package — into a real runtime `dependencies` entry on this TEST package
 * so its redactor could reach the same patterns. That direction was wrong
 * (production must never runtime-depend on test code, and the published
 * `knotrust` CLI bundles proxy-stdio wholesale). The shared source now
 * lives in `@knotrust/core` instead — a package this one can depend on
 * cleanly (`@knotrust/core` depends on neither `proxy-stdio` nor
 * `test-harness`) — and this file just re-exports what it imports from
 * there.
 *
 * **`@knotrust/core`'s `leak-patterns.ts` header is also the BINDING
 * token-format contract for E6-T3** (approval-token minting, not yet
 * implemented) — read it before minting the first token.
 */

import {
  APPROVAL_TOKEN_HEX_PATTERN,
  APPROVAL_TOKEN_PREFIXED_PATTERN,
  POLICY_INTERNAL_IDENTIFIERS,
  POLICY_INTERNAL_PATTERNS,
} from "@knotrust/core";
import type { Frame } from "./frame.js";
import { scanFrames } from "./frame.js";

export {
  APPROVAL_TOKEN_HEX_PATTERN,
  APPROVAL_TOKEN_PREFIXED_PATTERN,
  POLICY_INTERNAL_IDENTIFIERS,
  POLICY_INTERNAL_PATTERNS,
};

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type LeakKind = "token" | "policy_internal";

export interface LeakFinding {
  readonly kind: LeakKind;
  /** Human-readable label of what matched (the literal pattern/identifier). */
  readonly pattern: string;
  /** The exact substring found. */
  readonly match: string;
  /** Present only when scanning a `Frame[]` transcript. */
  readonly frameSeq?: number;
  readonly direction?: Frame["direction"];
}

function scanText(
  text: string,
): Array<Omit<LeakFinding, "frameSeq" | "direction">> {
  const findings: Array<Omit<LeakFinding, "frameSeq" | "direction">> = [];

  for (const re of [
    APPROVAL_TOKEN_PREFIXED_PATTERN,
    APPROVAL_TOKEN_HEX_PATTERN,
  ]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: standard exec-loop idiom.
    while ((m = re.exec(text)) !== null) {
      findings.push({ kind: "token", pattern: re.source, match: m[0] });
    }
  }

  for (const identifier of POLICY_INTERNAL_IDENTIFIERS) {
    if (text.includes(identifier)) {
      findings.push({
        kind: "policy_internal",
        pattern: identifier,
        match: identifier,
      });
    }
  }

  for (const re of POLICY_INTERNAL_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: standard exec-loop idiom.
    while ((m = re.exec(text)) !== null) {
      findings.push({
        kind: "policy_internal",
        pattern: re.source,
        match: m[0],
      });
    }
  }

  return findings;
}

/**
 * Scans `input` for approval-token-shaped strings and policy-internal
 * identifiers. Two call shapes:
 *
 * - `findLeaks(text: string)` — scans the raw string directly. Use this for
 *   a `content[].text` string or `JSON.stringify(structuredContent)` you
 *   already have in hand (e.g. a unit test constructing an envelope
 *   directly, with no fake-client transcript involved).
 * - `findLeaks(frames: Frame[])` — scans only the `direction: "recv"`
 *   subset (what the fake client, standing in for the model/agent, actually
 *   RECEIVED — never `"sent"`, which is the agent's own traffic and none of
 *   KnoTrust's business to police), `JSON.stringify`-ing each frame's whole
 *   `message` (the simplest correct superset of "any `content[].text` +
 *   `structuredContent`, serialized" — scanning the whole received message
 *   is strictly more conservative, and every real denial envelope's
 *   `content`/`structuredContent` live inside exactly one such message).
 */
export function findLeaks(input: readonly Frame[] | string): LeakFinding[] {
  if (typeof input === "string") {
    return scanText(input);
  }
  const recvFrames = scanFrames(input, (f) => f.direction === "recv");
  const findings: LeakFinding[] = [];
  for (const frame of recvFrames) {
    const text = JSON.stringify(frame.message);
    for (const finding of scanText(text)) {
      findings.push({
        ...finding,
        frameSeq: frame.seq,
        direction: frame.direction,
      });
    }
  }
  return findings;
}

/**
 * Throws if `findLeaks(input)` finds anything — the actual assertion call
 * sites use. A plain thrown `Error` (not a framework-specific matcher) so
 * this stays test-framework-agnostic: any test runner's `it()` treats a
 * thrown error as a failure, and the message embeds every finding for a
 * fast diagnosis without needing a debugger.
 */
export function assertNoLeakedSecrets(input: readonly Frame[] | string): void {
  const leaks = findLeaks(input);
  if (leaks.length > 0) {
    throw new Error(
      `assertNoLeakedSecrets: found ${leaks.length} leak(s) in model-visible content:\n` +
        JSON.stringify(leaks, null, 2),
    );
  }
}
