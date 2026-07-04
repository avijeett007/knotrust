// SPIKE — simplified stand-in for @knotrust/grants' real computeCallHash
// (P0-E3-T3, packages/grants/src/callhash.ts, R33). Same IDEA — hash a
// canonical projection of "which call was approved" so approve-X-execute-Y
// can't reopen (brief §I2.3) — deliberately NOT importing the real
// implementation so this spike stays fully isolated from product packages
// (R164). The real thing uses RFC 8785 JCS canonicalization over a FROZEN,
// versioned field list with golden cross-language vectors; this uses plain
// JSON.stringify over a fixed key order, which is fine for a throwaway
// same-process demo but is NOT a substitute for the real SARC v1 form in
// Phase 2.

import { createHash } from "node:crypto";

/**
 * @param {{ subject: string, action: string, resource: unknown, agent: string, arguments: unknown }} call
 * @returns {string} "sha256:<hex>"
 */
export function computeCallHash(call) {
  const normalForm = {
    v: 1,
    subject: call.subject,
    action: call.action,
    resource: call.resource ?? null,
    agent: call.agent,
    arguments: call.arguments ?? null,
  };
  // NOT RFC 8785 JCS — a fixed-key-order JSON.stringify is enough to make
  // this deterministic for the spike's single-process demo. Do not treat
  // this as canonical.
  const canonical = JSON.stringify(normalForm);
  const hex = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `sha256:${hex}`;
}
