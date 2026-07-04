import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
// Neither package ships an ESM build or a package.json "exports" map, and
// under this project's real NodeNext/ESM output a default import
// (`import X from "cjsPkg"`) types as the whole CJS module namespace rather
// than its `.default` property, so `new Ajv2020()` / `addFormats(ajv)` don't
// type-check against a plain `import`. `Ajv2020` has a real named class
// export, so it's imported directly by name. `ajv-formats` exports only a
// default (`module.exports = exports.default = formatsPlugin` at runtime —
// verified: they are the same callable value), so it's loaded via
// `createRequire` and typed with its named `FormatsPlugin` type export,
// sidestepping the default-binding ambiguity entirely rather than fighting it.
import { Ajv2020 } from "ajv/dist/2020.js";
import type { FormatsPlugin } from "ajv-formats";
import { describe, expect, it } from "vitest";
import type {
  ApprovalHandleRef,
  DecisionRequest,
  DecisionResponse,
} from "./contract.js";

const require = createRequire(import.meta.url);
const addFormats: FormatsPlugin = require("ajv-formats");

// ---------------------------------------------------------------------------
// Schema loading + ajv setup (draft 2020-12, strict).
//
// Schemas live at the repo-root `golden-vectors/schemas/` (not inside
// packages/core) because they are the language-neutral artifact shared with
// the future Python port — resolve relative to this file, not process.cwd(),
// so the suite behaves the same whether invoked from the repo root or from
// within packages/core.
// ---------------------------------------------------------------------------

const here = path.dirname(fileURLToPath(import.meta.url));
const schemasDir = path.resolve(
  here,
  "..",
  "..",
  "..",
  "golden-vectors",
  "schemas",
);

function loadSchema(fileName: string): object {
  return JSON.parse(
    readFileSync(path.join(schemasDir, fileName), "utf8"),
  ) as object;
}

const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);

const validateDecisionRequest = ajv.compile(
  loadSchema("decision-request.v1.schema.json"),
);
const validateDecisionResponse = ajv.compile(
  loadSchema("decision.v1.schema.json"),
);

/** JSON round-trip: proves the fixture survives serialization losslessly before schema-validating it. */
function roundTrip<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

// ---------------------------------------------------------------------------
// Fixtures — typed against the contract.ts interfaces so the compiler
// enforces the TS side of "round-trips the TS types"; ajv enforces the JSON
// Schema side.
// ---------------------------------------------------------------------------

/** Architecture §2 example — github.create_issue (routine/sensitive, allowed from a durable grant), copied verbatim. */
const githubCreateIssueRequest: DecisionRequest = {
  contractVersion: "1.0",
  requestId: "01JZ8Q3M9X7R2K4V6B0YHTDC1A",
  timestamp: "2026-07-03T14:32:10.221Z",
  subject: {
    type: "user",
    id: "avijeett007@gmail.com",
    properties: { authn: "os_session", tenant: "kno2gether" },
  },
  action: {
    name: "github.create_issue",
    properties: { mcpMethod: "tools/call" },
  },
  resource: {
    type: "github_repo",
    id: "kno2gether/openclaw",
    properties: { title: "Race in proxy shutdown", labels: ["bug"] },
  },
  context: {
    agent: {
      id: "claude-desktop",
      type: "ai_agent",
      clientId: "mcp-client-abc",
      model: "claude-opus-4-x",
    },
    env: { time: "2026-07-03T14:32:10Z", surfaceLocal: true },
  },
  surface: {
    kind: "stdio_proxy",
    instanceId: "px_01JZ8Q3",
    server: "github-mcp",
    specVersion: "2025-11-25",
    transport: "stdio",
  },
  toolAnnotations: {
    trusted: false,
    source: "server_advertised",
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
    capturedAt: "2026-07-03T14:30:00Z",
  },
};

/** Architecture §2 example — stripe.create_refund (critical, escalates to human), copied verbatim. */
const stripeCreateRefundRequest: DecisionRequest = {
  contractVersion: "1.0",
  requestId: "01JZ8Q4T0F5N8P2Q7C3WERKD9B",
  timestamp: "2026-07-03T14:40:02.005Z",
  subject: {
    type: "user",
    id: "avijeett007@gmail.com",
    properties: { authn: "os_session", tenant: "kno2gether" },
  },
  action: {
    name: "stripe.create_refund",
    properties: { mcpMethod: "tools/call" },
  },
  resource: {
    type: "stripe_charge",
    id: "ch_3PabcXYZ",
    properties: {
      amount: 42000,
      currency: "usd",
      reason: "requested_by_customer",
    },
  },
  context: {
    agent: { id: "codex-cli", type: "ai_agent", clientId: "codex-mcp" },
    env: { time: "2026-07-03T14:40:01Z", surfaceLocal: true },
  },
  surface: {
    kind: "stdio_proxy",
    instanceId: "px_01JZ8Q4",
    server: "stripe-mcp",
    specVersion: "2025-11-25",
    transport: "stdio",
  },
  toolAnnotations: {
    trusted: false,
    source: "server_advertised",
    destructiveHint: true,
    readOnlyHint: false,
  },
};

/**
 * Request carrying `context.arguments` (R32, P0-E3-T3): the raw tool-call
 * arguments the surface received, hashed into the SARC normal form for
 * call-hash binding. Proves the additive field round-trips TS ↔ JSON Schema.
 */
const argumentsCarryingRequest: DecisionRequest = {
  contractVersion: "1.0",
  requestId: "01JZ8QARGSREQUEST00000001",
  timestamp: "2026-07-03T14:40:02.005Z",
  subject: { type: "user", id: "avijeett007@gmail.com" },
  action: {
    name: "stripe.create_refund",
    properties: { mcpMethod: "tools/call" },
  },
  resource: {
    type: "stripe_charge",
    id: "ch_3PabcXYZ",
    properties: { amount: 42000, currency: "usd" },
  },
  context: {
    agent: { id: "codex-cli", type: "ai_agent" },
    env: { time: "2026-07-03T14:40:01Z", surfaceLocal: true },
    arguments: {
      charge: "ch_3PabcXYZ",
      amount: 42000,
      reason: "requested_by_customer",
      metadata: { note: "duplicate charge", nested: [1, true, null] },
    },
  },
  surface: {
    kind: "stdio_proxy",
    instanceId: "px_01JZ8QA",
    server: "stripe-mcp",
  },
};

/** Minimal-fields request: every optional field omitted. */
const minimalRequest: DecisionRequest = {
  contractVersion: "1.0",
  requestId: "01JZ8Q0000000000000000000",
  timestamp: "2026-07-03T00:00:00.000Z",
  subject: { type: "service", id: "svc:knotrust-cli" },
  action: { name: "filesystem.read_file" },
  resource: { type: "file", id: "/tmp/example.txt" },
  context: {
    agent: { id: "knotrust-cli", type: "workload" },
    env: { time: "2026-07-03T00:00:00.000Z", surfaceLocal: true },
  },
  surface: { kind: "sdk", instanceId: "sdk_01JZ8Q0" },
};

const pendingApprovalHandle: ApprovalHandleRef = {
  id: "apr_01JZ8Q6",
  state: "pending",
  expiresAt: "2026-07-03T14:45:02Z",
};

/** pending_approval DecisionResponse carrying an ApprovalHandleRef. */
const pendingApprovalResponse: DecisionResponse = {
  contractVersion: "1.0",
  requestId: "01JZ8Q6X0F5N8P2Q7C3WERKD9B",
  decisionId: "01JZ8Q6DECISION0000000001",
  outcome: "pending_approval",
  tier: "critical",
  reasonCode: "awaiting_human_approval",
  approval: pendingApprovalHandle,
  cache: { hit: false },
  evaluatedBy: "L0",
  latencyMs: 2.4,
};

/** deny DecisionResponse with reasonUser + reasonAdmin (two-layer denial message, architecture §3.2). */
const denyResponse: DecisionResponse = {
  contractVersion: "1.0",
  requestId: "01JZ8Q5T0F5N8P2Q7C3WERKD9B",
  decisionId: "01JZ8Q5DECISION0000000001",
  outcome: "deny",
  tier: "critical",
  reasonCode: "no_grant_critical",
  reasonUser:
    "This action was blocked (critical tier) and was not performed. A human can approve it via the KnoTrust approval page or terminal prompt.",
  reasonAdmin:
    "policy=critical-default; no matching grant for principal=avijeett007@gmail.com tool=stripe.create_refund",
  cache: { hit: false },
  evaluatedBy: "L0",
  latencyMs: 1.8,
};

/** deny DecisionResponse carrying `requestable` guidance (sensitive tier, no covering grant — Requestable Denial, R9/P0-E2-T2). */
const denyWithRequestableResponse: DecisionResponse = {
  contractVersion: "1.0",
  requestId: "01JZ8Q9T0F5N8P2Q7C3WERKD9B",
  decisionId: "01JZ8Q9DECISION0000000001",
  outcome: "deny",
  tier: "sensitive",
  reasonCode: "no_grant_sensitive",
  reasonUser:
    "This action was blocked (sensitive tier) and was not performed. A human can grant access to enable it.",
  requestable: {
    how: "knotrust grant --tool github.create_issue --server github-mcp",
  },
  cache: { hit: false },
  evaluatedBy: "L0",
  latencyMs: 1.1,
};

/** deferred_not_eligible DecisionResponse (e.g. a critical action mid-voice-call, PRD §10). */
const deferredNotEligibleResponse: DecisionResponse = {
  contractVersion: "1.0",
  requestId: "01JZ8Q7T0F5N8P2Q7C3WERKD9B",
  decisionId: "01JZ8Q7DECISION0000000001",
  outcome: "deferred_not_eligible",
  tier: "critical",
  reasonCode: "channel_not_eligible",
  cache: { hit: false },
  evaluatedBy: "L0",
  latencyMs: 0.9,
};

/** Minimal-fields DecisionResponse: every optional field omitted. */
const minimalResponse: DecisionResponse = {
  contractVersion: "1.0",
  requestId: "01JZ8Q0000000000000000000",
  decisionId: "01JZ8Q0DECISION0000000001",
  outcome: "allow",
  tier: "routine",
  reasonCode: "cache_hit",
  cache: { hit: true, ttlSeconds: 3600 },
  evaluatedBy: "grant",
  latencyMs: 0.4,
};

// ---------------------------------------------------------------------------
// Positive: round-trip + schema validation.
// ---------------------------------------------------------------------------

describe("DecisionRequest — round-trips the TS type against the JSON Schema", () => {
  const fixtures: Array<[string, DecisionRequest]> = [
    ["architecture §2 example: github.create_issue", githubCreateIssueRequest],
    [
      "architecture §2 example: stripe.create_refund",
      stripeCreateRefundRequest,
    ],
    ["request carrying context.arguments (R32)", argumentsCarryingRequest],
    ["minimal-fields request (no optionals)", minimalRequest],
  ];

  it.each(fixtures)("%s", (_name, fixture) => {
    const serialized = roundTrip(fixture);
    expect(serialized).toEqual(fixture);

    const valid = validateDecisionRequest(serialized);
    expect(validateDecisionRequest.errors).toBeNull();
    expect(valid).toBe(true);
  });
});

describe("DecisionResponse — round-trips the TS type against the JSON Schema", () => {
  const fixtures: Array<[string, DecisionResponse]> = [
    ["pending_approval carrying an ApprovalHandleRef", pendingApprovalResponse],
    ["deny with reasonUser/reasonAdmin", denyResponse],
    [
      "deny with requestable guidance (sensitive, R9)",
      denyWithRequestableResponse,
    ],
    ["deferred_not_eligible", deferredNotEligibleResponse],
    ["minimal-fields response (no optionals)", minimalResponse],
  ];

  it.each(fixtures)("%s", (_name, fixture) => {
    const serialized = roundTrip(fixture);
    expect(serialized).toEqual(fixture);

    const valid = validateDecisionResponse(serialized);
    expect(validateDecisionResponse.errors).toBeNull();
    expect(valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Negative: each of these must FAIL validation (ruling 4c).
// ---------------------------------------------------------------------------

describe("negative validation — each fixture must fail", () => {
  it('rejects subject.type outside the AuthZEN union ("agent" is not "user" | "service")', () => {
    const bad: unknown = {
      ...roundTrip(minimalRequest),
      subject: { type: "agent", id: "not-a-valid-subject-type" },
    };

    expect(validateDecisionRequest(bad)).toBe(false);
    expect(validateDecisionRequest.errors).not.toBeNull();
  });

  it("rejects a fifth outcome value outside the four-outcome union", () => {
    const bad: unknown = {
      ...roundTrip(minimalResponse),
      outcome: "maybe_later",
    };

    expect(validateDecisionResponse(bad)).toBe(false);
    expect(validateDecisionResponse.errors).not.toBeNull();
  });

  it("rejects toolAnnotations.trusted: true (the field is a literal false, never a lie the schema accepts)", () => {
    const bad: unknown = {
      ...roundTrip(githubCreateIssueRequest),
      toolAnnotations: {
        ...githubCreateIssueRequest.toolAnnotations,
        trusted: true,
      },
    };

    expect(validateDecisionRequest(bad)).toBe(false);
    expect(validateDecisionRequest.errors).not.toBeNull();
  });

  it("rejects a DecisionRequest missing a required field (resource)", () => {
    const { resource: _resource, ...bad } = roundTrip(minimalRequest);

    expect(validateDecisionRequest(bad)).toBe(false);
    expect(validateDecisionRequest.errors).not.toBeNull();
  });

  it("rejects an offset-less timestamp: valid ISO-8601 local date-time, but not valid RFC 3339 (ADR-0017)", () => {
    // "2026-07-03T14:32:10" is valid ISO-8601 (a local date-time with no UTC
    // offset) but RFC 3339 §5.6 requires every date-time to carry a
    // time-offset ("Z" or "±hh:mm"). format: date-time in the JSON Schemas
    // is the RFC 3339 profile, not bare ISO-8601 (ADR-0017) — a validator
    // that only checks `type: "string"` and never asserts `format` would
    // wrongly accept this fixture. ajv-formats (wired above) must reject it.
    const bad: unknown = {
      ...roundTrip(minimalRequest),
      timestamp: "2026-07-03T14:32:10",
    };

    expect(validateDecisionRequest(bad)).toBe(false);
    expect(validateDecisionRequest.errors).not.toBeNull();
  });
});
