/**
 * @knotrust/store — config.ts unit tests (P0-E4-T2; rulings R44–R47).
 *
 * Pure-function coverage: schema validation (valid/invalid), the
 * normalizers (`toTierPolicy`/`toAdminEnvelope`), `policyVersion`, and the
 * committed JSON Schema sync test. Loader (`loadKnotrustConfig`) tests that
 * touch real files/temp dirs live in the sibling `config.loader.test.ts`.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildConfigJsonSchema,
  CONFIG_JSON_SCHEMA_ID,
  KnotrustConfigSchema,
  policyVersion,
  toAdminEnvelope,
  toTierPolicy,
} from "./config.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "schemas",
  "config.v1.schema.json",
);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const fullExampleRaw = {
  version: 1,
  scope: "personal",
  identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
  servers: {
    "github-mcp": {
      tools: {
        "github.create_issue": { tier: "routine", source: "annotation" },
        "github.close_issue": {
          tier: "sensitive",
          source: "pack",
          mapping: {
            resourceType: "github_issue",
            resourceId: "arguments.issue_number",
            properties: { repo: "arguments.repo" },
          },
        },
        "github.delete_repo": {
          tier: "critical",
          source: "user",
          explicitDeny: true,
        },
      },
    },
  },
  unknownToolTier: "sensitive",
  envelope: { tierFloors: { "github.create_issue": "sensitive" } },
  approvalTimeoutSeconds: 300,
  cacheTtlOverrides: { sensitive: 30 },
};

// ---------------------------------------------------------------------------
// Schema — positive
// ---------------------------------------------------------------------------

describe("KnotrustConfigSchema — valid configs", () => {
  it("parses the full example config unchanged", () => {
    const result = KnotrustConfigSchema.parse(fullExampleRaw);
    expect(result).toEqual(fullExampleRaw);
  });

  it("applies defaults (timeout 300, scope personal, unknownToolTier sensitive) for a minimal config", () => {
    const result = KnotrustConfigSchema.parse({ version: 1 });
    expect(result).toEqual({
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
      approvalTimeoutSeconds: 300,
    });
  });

  it("parses scope: 'org' — accepted, inert (§E7)", () => {
    const result = KnotrustConfigSchema.parse({ version: 1, scope: "org" });
    expect(result.scope).toBe("org");
  });

  it("accepts an explicit failOpen.routine declaration", () => {
    const result = KnotrustConfigSchema.parse({
      version: 1,
      failOpen: { routine: true },
    });
    expect(result.failOpen).toEqual({ routine: true });
  });

  it("accepts telemetryExport absent, applying enabled:false/serviceName:'knotrust' defaults only when the key is itself present", () => {
    const result = KnotrustConfigSchema.parse({
      version: 1,
      telemetryExport: {},
    });
    expect(result.telemetryExport).toEqual({
      enabled: false,
      serviceName: "knotrust",
    });
  });

  it("accepts a real enabled telemetryExport with endpoint/headers/serviceName (P0-E8-T1, R129)", () => {
    const result = KnotrustConfigSchema.parse({
      version: 1,
      telemetryExport: {
        enabled: true,
        endpoint: "https://collector.example.com:4318/v1/traces",
        headers: { "x-api-key": "secret" },
        serviceName: "my-knotrust",
      },
    });
    expect(result.telemetryExport).toEqual({
      enabled: true,
      endpoint: "https://collector.example.com:4318/v1/traces",
      headers: { "x-api-key": "secret" },
      serviceName: "my-knotrust",
    });
  });
});

// ---------------------------------------------------------------------------
// Schema — negative (each must fail, naming its offending key)
// ---------------------------------------------------------------------------

describe("KnotrustConfigSchema — invalid configs fail fast, naming the offending key", () => {
  it("rejects a bad tier value on a nested tool entry", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      servers: {
        "github-mcp": {
          tools: {
            "github.create_issue": { tier: "bogus", source: "user" },
          },
        },
      },
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected failure");
    const paths = result.error.issues.map((i) => i.path.join("."));
    expect(paths).toContain(
      "servers.github-mcp.tools.github.create_issue.tier",
    );
  });

  it("rejects an unrecognized top-level key", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      bogusTopLevelKey: true,
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected failure");
    expect(result.error.issues[0]?.message).toMatch(/bogusTopLevelKey/);
  });

  it("rejects unknownToolTier: 'routine' at runtime", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      unknownToolTier: "routine",
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected failure");
    expect(result.error.issues[0]?.path).toEqual(["unknownToolTier"]);
  });

  it("rejects unknownToolTier: 'routine' at the TYPE level too — the parsed KnotrustConfig's field type is 'sensitive' | 'critical', never 'routine'", () => {
    const config = KnotrustConfigSchema.parse({ version: 1 });
    // @ts-expect-error — "routine" is not assignable to "sensitive" | "critical".
    config.unknownToolTier = "routine";
    expect(true).toBe(true);
  });

  it("rejects failOpen.sensitive structurally (sensitive/critical may never fail open)", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      failOpen: { sensitive: true },
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected failure");
    expect(result.error.issues[0]?.path).toEqual(["failOpen"]);
  });

  it("rejects failOpen.critical structurally", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      failOpen: { critical: true },
    });
    expect(result.success).toBe(false);
  });

  it("rejects a missing version", () => {
    const result = KnotrustConfigSchema.safeParse({});
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected failure");
    expect(result.error.issues[0]?.path).toEqual(["version"]);
  });

  it("rejects a function value assigned to a real field (config must be data)", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      approvalTimeoutSeconds: () => 300,
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected failure");
    expect(result.error.issues[0]?.path).toEqual(["approvalTimeoutSeconds"]);
  });

  // -------------------------------------------------------------------------
  // telemetryExport (P0-E8-T1; R129 — replaces the E4-T2 inert placeholder)
  // -------------------------------------------------------------------------

  it("rejects telemetryExport.enabled: true with no endpoint — a clean ConfigError naming telemetryExport.endpoint", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      telemetryExport: { enabled: true },
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected failure");
    expect(result.error.issues.map((i) => i.path.join("."))).toContain(
      "telemetryExport.endpoint",
    );
  });

  it("rejects telemetryExport.enabled: true with an empty/blank endpoint", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      telemetryExport: { enabled: true, endpoint: "   " },
    });
    expect(result.success).toBe(false);
  });

  it("rejects an unrecognized key under telemetryExport (strict, not the old wide-open placeholder)", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      telemetryExport: { enabled: false, batchSize: 10 },
    });
    expect(result.success).toBe(false);
    if (result.success) throw new Error("expected failure");
    expect(result.error.issues[0]?.message).toMatch(/batchSize/);
  });

  it("accepts telemetryExport.enabled: false even with a stray endpoint present (endpoint is only REQUIRED when enabled)", () => {
    const result = KnotrustConfigSchema.safeParse({
      version: 1,
      telemetryExport: { enabled: false, endpoint: "https://example.com" },
    });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// toTierPolicy
// ---------------------------------------------------------------------------

describe("toTierPolicy", () => {
  const config = KnotrustConfigSchema.parse(fullExampleRaw);

  it("builds a TierPolicy from the named server's tools, dropping `mapping` (core has no slot for it)", () => {
    const policy = toTierPolicy(config, "github-mcp");
    expect(policy).toEqual({
      tools: {
        "github.create_issue": { tier: "routine", source: "annotation" },
        "github.close_issue": { tier: "sensitive", source: "pack" },
        "github.delete_repo": {
          tier: "critical",
          source: "user",
          explicitDeny: true,
        },
      },
      unknownToolTier: "sensitive",
    });
  });

  it("returns an empty (but valid) TierPolicy for an unconfigured server name", () => {
    const policy = toTierPolicy(config, "unknown-server");
    expect(policy).toEqual({ tools: {}, unknownToolTier: "sensitive" });
  });

  it("preserves explicitAllow when present", () => {
    const withAllow = KnotrustConfigSchema.parse({
      version: 1,
      servers: {
        s: {
          tools: {
            "a.tool": {
              tier: "sensitive",
              source: "user",
              explicitAllow: true,
            },
          },
        },
      },
    });
    const policy = toTierPolicy(withAllow, "s");
    expect(policy.tools["a.tool"]).toEqual({
      tier: "sensitive",
      source: "user",
      explicitAllow: true,
    });
  });
});

// ---------------------------------------------------------------------------
// toAdminEnvelope
// ---------------------------------------------------------------------------

describe("toAdminEnvelope", () => {
  it("maps envelope fields 1:1 and joins config.scope in as AdminEnvelope.scope", () => {
    const config = KnotrustConfigSchema.parse(fullExampleRaw);
    const envelope = toAdminEnvelope(config);
    expect(envelope).toEqual({
      scope: "personal",
      tierFloors: { "github.create_issue": "sensitive" },
    });
  });

  it("carries scope: 'org' through inert — no special normalizer behavior", () => {
    const config = KnotrustConfigSchema.parse({
      version: 1,
      scope: "org",
    });
    expect(toAdminEnvelope(config)).toEqual({ scope: "org" });
    expect(toTierPolicy(config, "any-server")).toEqual({
      tools: {},
      unknownToolTier: "sensitive",
    });
  });

  it("maps every envelope field when all are present", () => {
    const config = KnotrustConfigSchema.parse({
      version: 1,
      envelope: {
        denyTools: ["a.tool"],
        forceApprovalTiers: ["critical"],
        forceApprovalTools: ["b.tool"],
        tierFloors: { "a.tool": "sensitive" },
        grantCeiling: "sensitive",
      },
    });
    expect(toAdminEnvelope(config)).toEqual({
      scope: "personal",
      denyTools: ["a.tool"],
      forceApprovalTiers: ["critical"],
      forceApprovalTools: ["b.tool"],
      tierFloors: { "a.tool": "sensitive" },
      grantCeiling: "sensitive",
    });
  });
});

// ---------------------------------------------------------------------------
// R20 — fresh objects, every call
// ---------------------------------------------------------------------------

describe("R20 contract — normalizers return FRESH objects, never memoized/shared mutables", () => {
  const config = KnotrustConfigSchema.parse(fullExampleRaw);

  it("toTierPolicy returns a new object + new tools record on every call", () => {
    const p1 = toTierPolicy(config, "github-mcp");
    const p2 = toTierPolicy(config, "github-mcp");
    expect(p1).toEqual(p2);
    expect(p1).not.toBe(p2);
    expect(p1.tools).not.toBe(p2.tools);
    expect(p1.tools["github.create_issue"]).not.toBe(
      p2.tools["github.create_issue"],
    );
  });

  it("mutating a returned TierPolicy never affects a later fresh call nor the source config", () => {
    const p1 = toTierPolicy(config, "github-mcp");
    delete (p1.tools as Record<string, unknown>)["github.create_issue"];
    const p2 = toTierPolicy(config, "github-mcp");
    expect(p2.tools["github.create_issue"]).toBeDefined();
    expect(
      config.servers?.["github-mcp"]?.tools?.["github.create_issue"],
    ).toBeDefined();
  });

  it("toAdminEnvelope returns a new object + new nested collections on every call", () => {
    const e1 = toAdminEnvelope(config);
    const e2 = toAdminEnvelope(config);
    expect(e1).toEqual(e2);
    expect(e1).not.toBe(e2);
    expect(e1.tierFloors).not.toBe(e2.tierFloors);
  });

  it("mutating a returned AdminEnvelope never affects a later fresh call nor the source config", () => {
    const e1 = toAdminEnvelope(config);
    (e1.tierFloors as Record<string, unknown>)["github.create_issue"] =
      "critical";
    const e2 = toAdminEnvelope(config);
    expect(e2.tierFloors?.["github.create_issue"]).toBe("sensitive");
    expect(config.envelope?.tierFloors?.["github.create_issue"]).toBe(
      "sensitive",
    );
  });
});

// ---------------------------------------------------------------------------
// policyVersion
// ---------------------------------------------------------------------------

describe("policyVersion", () => {
  it("is deterministic and key-insertion-order independent", () => {
    const a = KnotrustConfigSchema.parse({
      version: 1,
      scope: "personal",
      unknownToolTier: "sensitive",
    });
    const b = KnotrustConfigSchema.parse({
      unknownToolTier: "sensitive",
      version: 1,
      scope: "personal",
    });
    expect(policyVersion(a)).toBe(policyVersion(b));
    expect(policyVersion(a)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes whenever a policy-relevant field changes", () => {
    const a = KnotrustConfigSchema.parse({ version: 1 });
    const b = KnotrustConfigSchema.parse({
      version: 1,
      approvalTimeoutSeconds: 60,
    });
    expect(policyVersion(a)).not.toBe(policyVersion(b));
  });

  it("ignores identity — configs differing only in identity hash the SAME", () => {
    const a = KnotrustConfigSchema.parse({
      version: 1,
      identity: { subjectId: "alice@example.com", subjectType: "user" },
    });
    const b = KnotrustConfigSchema.parse({
      version: 1,
      identity: { subjectId: "bob@example.com", subjectType: "service" },
    });
    expect(policyVersion(a)).toBe(policyVersion(b));
  });

  it("ignores telemetryExport — configs differing only in telemetryExport hash the SAME", () => {
    const a = KnotrustConfigSchema.parse({
      version: 1,
      telemetryExport: {
        enabled: true,
        endpoint: "https://a.example.com/v1/traces",
      },
    });
    const b = KnotrustConfigSchema.parse({
      version: 1,
      telemetryExport: {
        enabled: true,
        endpoint: "https://b.example.com/v1/traces",
        serviceName: "other",
      },
    });
    expect(policyVersion(a)).toBe(policyVersion(b));
  });

  it("does not throw when telemetryExport is present (R129's real, now-validated schema, still excluded from the hashed subset)", () => {
    // telemetryExport is no longer the wide-open z.unknown() placeholder
    // (R129 gave it a real, strict schema) — but policyVersion's exclusion
    // of the field is unchanged (see policyRelevantSubset's own doc-comment),
    // so this still must never throw or vary policyVersion's output.
    const config = KnotrustConfigSchema.parse({
      version: 1,
      telemetryExport: {
        enabled: true,
        endpoint: "https://collector.example.com/v1/traces",
        headers: { authorization: "Bearer secret" },
      },
    });
    expect(() => policyVersion(config)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// JSON Schema artifact — sync test (R47)
// ---------------------------------------------------------------------------

describe("golden-vectors/schemas/config.v1.schema.json — sync test (R47)", () => {
  it("matches buildConfigJsonSchema() exactly (regenerate via `pnpm --filter @knotrust/store run generate:schema` and commit on drift)", () => {
    const committed = JSON.parse(readFileSync(schemaPath, "utf8"));
    const generated = buildConfigJsonSchema();
    expect(generated).toEqual(committed);
  });

  it("carries the pinned $id", () => {
    const generated = buildConfigJsonSchema();
    expect(generated.$id).toBe(CONFIG_JSON_SCHEMA_ID);
    expect(generated.$id).toBe(
      "https://knotrust.dev/schemas/config.v1.schema.json",
    );
  });

  it("validates the full example config with a real JSON Schema validator (ajv)", async () => {
    const { Ajv2020 } = await import("ajv/dist/2020.js");
    const ajv = new Ajv2020({ strict: true });
    const validate = ajv.compile(buildConfigJsonSchema());
    const valid = validate(fullExampleRaw);
    expect(validate.errors).toBeNull();
    expect(valid).toBe(true);
  });

  it("rejects an unrecognized key with the same ajv validator", async () => {
    const { Ajv2020 } = await import("ajv/dist/2020.js");
    const ajv = new Ajv2020({ strict: true });
    const validate = ajv.compile(buildConfigJsonSchema());
    expect(validate({ version: 1, bogus: true })).toBe(false);
  });
});
