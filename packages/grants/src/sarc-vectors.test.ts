/**
 * @knotrust/grants — SARC normal-form canonicalization vectors (P0-E3-T3, R33).
 *
 * Enumerates every `*.json` fixture in the repo-root
 * `golden-vectors/sarc-normal-form/` directory (dynamic, like the decisions
 * corpus) and locks the FROZEN artifact: `computeCallHash` and the
 * `canonicalizeJcs(sarcNormalForm(...))` pipeline must reproduce each
 * fixture's canonical string and `sha256:` hash byte-for-byte. Dropping a new
 * fixture into that directory is picked up automatically.
 *
 * The fixtures' `hash` fields were produced by an oracle independent of the
 * implementation under test (node:crypto over hand-authored canonical
 * strings, cross-checked against `shasum`/`openssl`); each case here ALSO
 * re-derives `sha256(canonical)` with node:crypto so the fixture's own
 * canonical↔hash relationship is verified without trusting `computeCallHash`.
 */

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { DecisionRequest } from "@knotrust/core";
import { canonicalizeJcs } from "@knotrust/core";
import { describe, expect, it } from "vitest";
import { computeCallHash, sarcNormalForm } from "./callhash.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsDir = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "sarc-normal-form",
);

interface SarcVector {
  name: string;
  description: string;
  request: DecisionRequest;
  canonical: string;
  hash: string;
}

function loadVectors(): Array<[string, SarcVector]> {
  const files = readdirSync(vectorsDir).filter((f) => f.endsWith(".json"));
  return files
    .sort()
    .map((file) => [
      file,
      JSON.parse(
        readFileSync(path.join(vectorsDir, file), "utf8"),
      ) as SarcVector,
    ]);
}

const vectors = loadVectors();

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

describe("SARC normal-form canonicalization vectors (golden-vectors/sarc-normal-form)", () => {
  it("enumerates the directory dynamically and finds at least the R33-mandated minimum set", () => {
    // R33 minimum: the two architecture §2 example requests (arguments added
    // to one), a unicode-key case, a number-forms case, an absent-vs-null
    // arguments case, and a properties-nested-object case = 6 vectors.
    expect(vectors.length).toBeGreaterThanOrEqual(6);
  });

  it.each(
    vectors,
  )("%s — canonicalizeJcs(sarcNormalForm(request))", (_file, vector) => {
    expect(canonicalizeJcs(sarcNormalForm(vector.request))).toBe(
      vector.canonical,
    );
  });

  it.each(
    vectors,
  )("%s — computeCallHash(request) matches frozen hash", (_file, vector) => {
    expect(computeCallHash(vector.request)).toBe(vector.hash);
  });

  it.each(
    vectors,
  )("%s — fixture hash is genuinely sha256 of fixture canonical (independent of computeCallHash)", (_file, vector) => {
    expect(`sha256:${sha256Hex(vector.canonical)}`).toBe(vector.hash);
  });
});

describe("SARC normal form — null-for-absent equivalence (R33)", () => {
  it("absent context.arguments hashes identically to an explicit arguments:null normal form", () => {
    const vector = vectors.find(
      ([, v]) => v.name === "arguments-absent-vs-null",
    );
    if (!vector) throw new Error("missing arguments-absent-vs-null fixture");
    const request = vector[1].request;

    // The normal form the implementation derives for an absent-arguments
    // request must carry arguments: null exactly (not undefined, not omitted).
    const nf = sarcNormalForm(request);
    expect(nf.arguments).toBeNull();
    expect(nf.resource.properties).toBeNull();

    // And re-canonicalizing that exact normal form (arguments explicitly null)
    // reproduces the same string/hash the request produced — proving absent
    // and explicit-null are indistinguishable in the frozen form.
    expect(canonicalizeJcs(nf)).toBe(vector[1].canonical);
    expect(computeCallHash(request)).toBe(vector[1].hash);
  });
});
