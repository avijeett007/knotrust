/**
 * @knotrust/otel — index.ts sanity tests, plus the R128 "verbatim" doc check.
 *
 * R128 requires the "this is telemetry-export, not product telemetry"
 * distinction be stated VERBATIM — this file makes that a checkable,
 * CI-enforced property (not just a claim in a task report) by asserting the
 * exact same canonical sentence appears, whitespace-normalized, in all three
 * places it is supposed to live: this package's own module header,
 * `@knotrust/store`'s `TelemetryExportConfigSchema` doc-comment, and
 * `docs/02-architecture/system-architecture.md`.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  attachOtelExporter,
  DECISION_SPAN_NAME,
  mapAuditEventToSpan,
  PKG,
  SECURITY_SPAN_NAME_PREFIX,
} from "./index.js";

describe("@knotrust/otel — public surface", () => {
  it("exports the package name", () => {
    expect(PKG).toBe("@knotrust/otel");
  });

  it("re-exports attachOtelExporter and the span mapper", () => {
    expect(typeof attachOtelExporter).toBe("function");
    expect(typeof mapAuditEventToSpan).toBe("function");
    expect(DECISION_SPAN_NAME).toBe("knotrust.decision");
  });

  it("re-exports SECURITY_SPAN_NAME_PREFIX (R132)", () => {
    expect(SECURITY_SPAN_NAME_PREFIX).toBe("knotrust.security");
  });
});

// ---------------------------------------------------------------------------
// R128 — the verbatim "no product telemetry, ever" statement.
// ---------------------------------------------------------------------------

const CANONICAL_STATEMENT =
  "KnoTrust has NO product telemetry / phone-home / usage analytics — ever " +
  "(PRD §11). `telemetryExport` is a user-controlled export of the USER'S " +
  "OWN audit stream to the USER'S OWN OTLP collector; it is off by default " +
  "and makes no external call unless the user configures an endpoint.";

/** Collapses all whitespace runs (including newlines and JSDoc `* ` line-leads) to single spaces, and strips markdown `**bold**` markers — so a sentence hand-wrapped across comment lines can still be compared against a single-line canonical string. */
function normalizeProse(raw: string): string {
  return raw
    .replace(/\*\*/g, "")
    .replace(/^\s*\*\s?/gm, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");

describe("R128 — the verbatim statement appears, identically, in all three required places", () => {
  it("in this package's own index.ts module header", () => {
    const raw = readFileSync(path.join(here, "index.ts"), "utf8");
    expect(normalizeProse(raw)).toContain(CANONICAL_STATEMENT);
  });

  it("in @knotrust/store's config.ts (TelemetryExportConfigSchema doc-comment)", () => {
    const raw = readFileSync(
      path.join(repoRoot, "packages", "store", "src", "config.ts"),
      "utf8",
    );
    expect(normalizeProse(raw)).toContain(CANONICAL_STATEMENT);
  });

  it("in docs/02-architecture/system-architecture.md", () => {
    const raw = readFileSync(
      path.join(repoRoot, "docs", "02-architecture", "system-architecture.md"),
      "utf8",
    );
    expect(normalizeProse(raw)).toContain(CANONICAL_STATEMENT);
  });
});
