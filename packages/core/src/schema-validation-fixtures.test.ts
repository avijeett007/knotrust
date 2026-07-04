/**
 * @knotrust/core — golden schema-validation fixture runner (P0-E3-T5, R50).
 *
 * Materializes the shared, language-neutral schema-validation corpus:
 * `golden-vectors/schema-validation/*.json`, each shaped
 * `{ name, target: "decision-request.v1" | "decision.v1", value, valid }`.
 * These are the SAME cases `contract.test.ts` exercises inline (the four
 * E2-T1 negatives + the ADR-0017 negative timestamp + the two architecture
 * §2 positives) — materialized here as standalone JSON so a Phase-3 Python
 * port (or any other language) can load and assert them without re-deriving
 * the TS literals from that test file. `contract.test.ts` is NOT superseded
 * by this suite: it additionally proves the TS *type* round-trips through
 * `JSON.stringify`/`JSON.parse` before schema-validating, which only makes
 * sense against real `DecisionRequest`/`DecisionResponse`-typed values — this
 * suite is deliberately untyped (raw JSON `value`), matching what a
 * language-neutral consumer actually receives.
 *
 * ajv setup is intentionally duplicated from `contract.test.ts` (own Ajv2020
 * instance, `strict: true`, `ajv-formats` wired) rather than importing a
 * shared helper — same "same strict mode as the round-trip suite" outcome,
 * zero coupling to that file's internals, and this is itself only test
 * infrastructure (not production code), so duplication here carries none of
 * the security-freeze risk a runtime duplication would.
 */

import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { FormatsPlugin } from "ajv-formats";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const addFormats: FormatsPlugin = require("ajv-formats");

const here = path.dirname(fileURLToPath(import.meta.url));
const schemasDir = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "schemas",
);
const schemaValidationDir = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "schema-validation",
);

function loadSchema(fileName: string): object {
  return JSON.parse(
    readFileSync(path.join(schemasDir, fileName), "utf8"),
  ) as object;
}

const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);

const validators = {
  "decision-request.v1": ajv.compile(
    loadSchema("decision-request.v1.schema.json"),
  ),
  "decision.v1": ajv.compile(loadSchema("decision.v1.schema.json")),
} as const;

type Target = keyof typeof validators;

interface SchemaValidationFixture {
  name: string;
  description: string;
  target: Target;
  value: unknown;
  valid: boolean;
}

function loadFixtures(): Array<[string, SchemaValidationFixture]> {
  const files = readdirSync(schemaValidationDir).filter((f) =>
    f.endsWith(".json"),
  );
  return files
    .sort()
    .map((file) => [
      file,
      JSON.parse(
        readFileSync(path.join(schemaValidationDir, file), "utf8"),
      ) as SchemaValidationFixture,
    ]);
}

const fixtures = loadFixtures();

describe("golden schema-validation fixtures (golden-vectors/schema-validation)", () => {
  it("enumerates the directory dynamically and finds the R50-mandated minimum set", () => {
    // R50 minimum: the ADR-0017 negative timestamp + the four E2-T1
    // negatives (subject.type "agent", fifth outcome, trusted:true, missing
    // resource) + two positives (architecture §2 examples) = 7 fixtures.
    expect(fixtures.length).toBeGreaterThanOrEqual(7);
  });

  it.each(fixtures)("%s", (_file, fixture) => {
    const validate = validators[fixture.target];
    const result = validate(fixture.value);
    expect(result).toBe(fixture.valid);
    if (fixture.valid) {
      expect(validate.errors).toBeNull();
    } else {
      expect(validate.errors).not.toBeNull();
    }
  });

  it("covers both targets (decision-request.v1 and decision.v1)", () => {
    const targets = new Set(fixtures.map(([, f]) => f.target));
    expect(targets.has("decision-request.v1")).toBe(true);
    expect(targets.has("decision.v1")).toBe(true);
  });

  it("includes at least one positive (valid:true) and the ADR-0017 negative timestamp case", () => {
    const names = fixtures.map(([, f]) => f.name);
    expect(names).toContain("adr-0017-negative-timestamp");
    expect(fixtures.some(([, f]) => f.valid)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ADR-0017 red-team note (not itself run here — see report/README): this
// suite's `adr-0017-negative-timestamp` case only fails validation because
// `addFormats(ajv)` is wired above. Removing that wiring (or compiling the
// schema against an Ajv instance that never asserts `format`) makes this
// exact fixture wrongly pass as `valid: true` — the manual verification step
// documented in golden-vectors/README.md exercises that regression directly
// against this suite's own ajv setup, then restores it.
// ---------------------------------------------------------------------------
