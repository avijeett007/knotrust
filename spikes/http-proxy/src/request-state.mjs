// SPIKE — the requestState encoding scheme (P0-E10-T1, SEP-2322/MRTR,
// §I2.4). See docs/03-engineering/spike-http-findings.md for the write-up;
// this file is the actual implementation the findings doc describes.
//
// Scheme: AES-256-GCM, encrypt-and-authenticate in one primitive. The
// authenticated-associated-data (AAD) input is `${principal}|${callHash}` —
// this is the literal mechanism behind "the MAC input binds principal +
// call hash" (§I2.4 ruling #4). AAD is authenticated but not encrypted, and
// critically it is NOT trusted from data embedded inside the ciphertext —
// the verifier reconstructs it fresh from (a) the CURRENT request's own
// independently-authenticated principal (never from anything the client
// echoes) and (b) the callHash carried in cleartext alongside the
// ciphertext (not secret — it's a one-way digest of the call, not the call
// itself). Decryption only succeeds if the verifier's reconstructed AAD
// bytes are IDENTICAL to what the minting replica used — so "tampered
// ciphertext" and "correct, unmodified ciphertext presented by the wrong
// principal" fail through the exact same code path (GCM auth tag check),
// which is the property the findings doc calls out as the main design win:
// there is no separate, forgettable "does principal match" string-compare
// for a future engineer to omit.
//
// requestState wire format (opaque to the CLIENT, per SEP-2322 — the
// client must echo it verbatim and never inspect/modify it; it is NOT
// opaque to the two replicas, which is the whole point):
//
//   base64url( JSON.stringify({ v: 1, callHash, iv, ct, tag }) )
//
// iv/ct/tag are themselves base64url. See the findings doc for the
// measured size overhead.

import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { computeCallHash } from "./call-hash.mjs";

const ALGO = "aes-256-gcm";
const IV_BYTES = 12;

export class RequestStateError extends Error {}

/**
 * Loads the shared "KMS" key from a 64-hex-char env var. In real life this
 * is a KMS/shared-secret-manager-backed key both replicas fetch (and
 * rotate) independently of any one process's memory — see the findings doc
 * for the recommended Phase-2 key-management story. Here it's a hardcoded
 * demo value, passed to both replica processes via SHARED_SECRET_HEX,
 * documented as a spike simplification, never as a production pattern.
 * @param {string} hex
 * @returns {Buffer}
 */
export function loadSharedKey(hex) {
  const key = Buffer.from(hex, "hex");
  if (key.length !== 32) {
    throw new RequestStateError(
      `SHARED_SECRET_HEX must decode to 32 bytes (AES-256), got ${key.length}`,
    );
  }
  return key;
}

/**
 * Mints a requestState for a pending critical call. Called by whichever
 * replica FIRST sees the call (replica A in the demo). Nothing about the
 * pending call is retained in that replica's memory — everything needed to
 * resume lives inside the returned requestState.
 *
 * @param {{ call: object, principal: string }} input
 * @param {Buffer} key
 */
export function mintRequestState({ call, principal }, key) {
  const callHash = computeCallHash(call);
  const approvalId = `apr_${randomUUID().replace(/-/g, "")}`;
  const plaintext = Buffer.from(JSON.stringify({ approvalId, call }), "utf8");
  const iv = randomBytes(IV_BYTES);
  const aad = Buffer.from(`${principal}|${callHash}`, "utf8");

  const cipher = createCipheriv(ALGO, key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const payload = {
    v: 1,
    callHash,
    iv: iv.toString("base64url"),
    ct: ct.toString("base64url"),
    tag: tag.toString("base64url"),
  };
  const requestState = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url",
  );
  return { requestState, approvalId, callHash, sizeBytes: requestState.length };
}

/**
 * Verifies + decrypts a requestState. `currentPrincipal` MUST come from the
 * CURRENT resume request's own independently-authenticated context (a
 * session/bearer identity resolved by the auth layer) — NEVER from
 * anything the client sends inside the resume body itself. This is what
 * makes the check a binding rather than a suggestion: an attacker who
 * relays someone else's genuine, byte-for-byte-unmodified requestString
 * under a different identity still fails here, because the AAD the
 * verifier reconstructs won't match what was used to mint it.
 *
 * @param {{ requestState: string, currentPrincipal: string }} input
 * @param {Buffer} key
 * @returns {{ approvalId: string, call: object, callHash: string }}
 */
export function verifyAndDecrypt({ requestState, currentPrincipal }, key) {
  let payload;
  try {
    payload = JSON.parse(
      Buffer.from(requestState, "base64url").toString("utf8"),
    );
  } catch {
    throw new RequestStateError("malformed requestState (not valid base64url/JSON)");
  }
  const { callHash, iv, ct, tag } = payload ?? {};
  if (!callHash || !iv || !ct || !tag) {
    throw new RequestStateError("malformed requestState (missing fields)");
  }

  const aad = Buffer.from(`${currentPrincipal}|${callHash}`, "utf8");
  const decipher = createDecipheriv(ALGO, key, Buffer.from(iv, "base64url"));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(tag, "base64url"));

  let plaintext;
  try {
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(ct, "base64url")),
      decipher.final(),
    ]);
  } catch {
    // This is the ONE failure path for both "tampered ciphertext" and
    // "correct ciphertext, wrong principal" — see module header.
    throw new RequestStateError(
      "requestState authentication failed (tampered, wrong principal/call binding, or wrong key)",
    );
  }

  const { approvalId, call } = JSON.parse(plaintext.toString("utf8"));

  // Redundant-by-construction re-derivation, mirroring the pattern
  // packages/grants/src/verify.ts already uses for grant call_hash
  // (re-derive from the live payload, require an exact match) — defense in
  // depth against a future bug in this file, not a gap the GCM tag leaves
  // open by itself.
  const recomputed = computeCallHash(call);
  if (recomputed !== callHash) {
    throw new RequestStateError(
      "call hash mismatch after decrypt (should be unreachable if the GCM tag passed)",
    );
  }

  return { approvalId, call, callHash };
}
