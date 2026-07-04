/**
 * @knotrust/grants — SARC normal-form `callHash` computation (P0-E3-T3, R33).
 *
 * The call-hash is the mechanism that closes approve-X-execute-Y (TOCTOU,
 * brief §I2.3): an ephemeral grant carries `ch = computeCallHash(approvedCall)`,
 * and at execution the verifier re-derives `computeCallHash(liveCall)` and
 * requires an exact match. A human approves *this* call, not "one free
 * critical call."
 *
 * ## The SARC normal form (FROZEN — v1)
 *
 * The hash is taken over the RFC 8785 (JCS) canonical JSON of a fixed,
 * versioned projection of the DecisionRequest — the SARC normal form:
 *
 * ```
 * { v: 1,
 *   subject:   request.subject.id,
 *   action:    request.action.name,
 *   resource:  { type, id, properties: resource.properties ?? null },
 *   agent:     request.context.agent.id,
 *   arguments: request.context.arguments ?? null }
 * ```
 *
 * Only these fields are hashed. Volatile/provenance fields (`requestId`,
 * `timestamp`, `env`, `surface`, `toolAnnotations`) are excluded — they are
 * not part of "which call was approved." `context.arguments` (R32) is
 * included verbatim so two calls that differ only in an argument the
 * resource-mapping never projected into `resource.properties` still produce
 * different hashes (without it, approve-X-execute-Y reopens).
 *
 * Absent optionals collapse to `null` (`resource.properties`,
 * `context.arguments`): an absent field and an explicit `null` are
 * indistinguishable in the frozen form, by design.
 *
 * This is a FROZEN cross-language artifact. `golden-vectors/schemas/
 * sarc-normal-form.v1.md` is the spec; `golden-vectors/sarc-normal-form/*.json`
 * are the vectors; the Phase-3 Python port must reproduce every byte. Any
 * change to the field list or the JCS profile is a v2 + a vector bump, never
 * an in-place edit (R33 versioning policy).
 *
 * The canonicalizer itself lives in `@knotrust/core` (`canonicalizeJcs`), the
 * layer with no dependencies, so both the enforcement core and this grants
 * layer canonicalize identically.
 */

import { createHash } from "node:crypto";
import { canonicalizeJcs, type DecisionRequest } from "@knotrust/core";

/** The current SARC normal-form schema version. Bump = v2 + a golden-vector bump. */
export const SARC_NORMAL_FORM_VERSION = 1 as const;

/**
 * The FROZEN SARC normal-form value (v1) — the exact object canonicalized to
 * produce the call-hash. Field order here is irrelevant to the output
 * (`canonicalizeJcs` sorts keys); it is written in the R33-specified order for
 * readability only.
 */
export interface SarcNormalForm {
  v: typeof SARC_NORMAL_FORM_VERSION;
  subject: string;
  action: string;
  resource: {
    type: string;
    id: string;
    /** `resource.properties ?? null` — absent properties collapse to null. */
    properties: Record<string, unknown> | null;
  };
  agent: string;
  /** `context.arguments ?? null` (R32) — absent arguments collapse to null. */
  arguments: Record<string, unknown> | null;
}

/**
 * Projects a `DecisionRequest` onto its SARC normal form (v1). Pure — no I/O,
 * no clock. See the module header for the frozen field list and the
 * null-for-absent rule.
 */
export function sarcNormalForm(request: DecisionRequest): SarcNormalForm {
  return {
    v: SARC_NORMAL_FORM_VERSION,
    subject: request.subject.id,
    action: request.action.name,
    resource: {
      type: request.resource.type,
      id: request.resource.id,
      properties: request.resource.properties ?? null,
    },
    agent: request.context.agent.id,
    arguments: request.context.arguments ?? null,
  };
}

/**
 * Computes the call-hash of a request: `"sha256:" + lowercase-hex(SHA-256(
 * utf8(canonicalizeJcs(sarcNormalForm(request)))))`. Matches architecture
 * §5.2's `"ch":"sha256:9f2c1e..."` form.
 */
export function computeCallHash(request: DecisionRequest): string {
  const canonical = canonicalizeJcs(sarcNormalForm(request));
  const hex = createHash("sha256").update(canonical, "utf8").digest("hex");
  return `sha256:${hex}`;
}
