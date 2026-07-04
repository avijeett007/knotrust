/**
 * @knotrust/store — config loading (c12 + jiti) & schema (P0-E4-T2; rulings
 * R44–R47. `telemetryExport` got its real schema at P0-E8-T1, rulings
 * R127–R131 — see `TelemetryExportConfigSchema`'s own doc-comment below).
 *
 * `knotrust.config.ts` **or** YAML/JSON are all equally first-class (brief
 * §D): loaded uniformly via [c12](https://github.com/unjs/c12)
 * (`name: "knotrust"`), whose bundled `jiti` dependency executes the `.ts`
 * form directly — this module never imports `jiti` itself (R44: "jiti rides
 * inside c12"). Validated by a strict zod schema (`KnotrustConfigSchema`):
 * unknown keys are rejected everywhere, at every level — fail-fast beats
 * silent typo-acceptance in a security config. (Before P0-E8-T1,
 * `telemetryExport` was the one documented exception, a wide-open
 * `z.unknown()` placeholder; R129 gave it a real, equally-strict schema.)
 *
 * ## What this module is NOT
 *
 * `KnotrustConfig` is the ON-DISK config format — a different, richer shape
 * than `@knotrust/core`'s `TierPolicy`/`AdminEnvelope` (the shapes the L0
 * evaluator/precedence engine actually consume). `toTierPolicy`/
 * `toAdminEnvelope` below are the normalizers that bridge the two; nothing
 * in `@knotrust/core` knows this on-disk format exists (see
 * `packages/core/src/tier-policy.ts`'s own header, which names this exact
 * task as the future parser). This keeps the evaluator dependency-free and
 * pure, per that module's own stated design.
 *
 * A `mapping` on a `ToolEntry` (`CoazStyleMapping`) is DEFINED and VALIDATED
 * here only — resolving its dot-path strings against a real tool call's
 * `arguments` to build a `DecisionRequest["resource"]` is P0-E5-T3's job
 * (invariant §E6; see `CoazStyleMapping`'s own doc-comment for the full
 * COAZ-provenance note, R45).
 *
 * ## R20 — normalizers return FRESH objects, always
 *
 * `toTierPolicy`/`toAdminEnvelope` below build a brand-new object graph on
 * EVERY call — never a memoized or shared mutable singleton, and never a
 * value carrying a live reference into `config`'s own nested
 * objects/arrays/records. This is not just tidiness: `@knotrust/core`'s
 * decision pipeline (`packages/core/src/pipeline.ts`, R20 ruling) memoizes
 * its per-request `policyFingerprint` by the OBJECT IDENTITY of the
 * `tierPolicy`/`envelope` it is handed, and that pipeline's own doc-comment
 * is explicit: "Always construct/replace a new `tierPolicy`/`envelope`
 * object when policy content changes; never mutate one that a pipeline has
 * already seen." A normalizer that returned a cached/shared object and then
 * mutated it in place on the next config change would keep the SAME
 * identity while its content silently drifted — exactly the stale-decision
 * hole that pipeline's fingerprint memo exists to close. Returning fresh
 * objects unconditionally makes that failure mode structurally impossible
 * here, rather than relying on this module remembering not to do it.
 *
 * ## Always-fresh on-disk reads (fix round 1, P0-E7-T3 review, FIX 3)
 *
 * A DIFFERENT freshness concern than R20 above, at a different layer — R20
 * is about `toTierPolicy`/`toAdminEnvelope`'s OUTPUT identity given an
 * already-loaded `config` object; this is about `loadKnotrustConfig`'s
 * INPUT: whether a second in-process call for the same on-disk path
 * actually re-reads the file. It did not, for `.json` specifically, until
 * this fix (`bustNativeRequireCache`, defined just above
 * `loadKnotrustConfig` below, carries the full root-cause story) — a latent
 * trap for the upcoming E9 dogfood / any in-process add-then-decide flow /
 * future config-watch loop, not something today's P0 call sites happen to
 * trigger (each process loads its config exactly once). The two fixes are
 * unrelated and this one does not touch R20's memo or its contract.
 *
 * ## Config-epoch semantics — `policyVersion(config)`
 *
 * `policyVersion` is a SHA-256 content-hash of the canonicalized (via
 * `@knotrust/core`'s frozen `canonicalizeJcs`) POLICY-RELEVANT SUBSET of the
 * config — not the whole parsed object (see `policyRelevantSubset`'s own
 * doc-comment for exactly what is hashed and what is excluded, and why).
 * Feeding this into `createDecisionPipeline({ policyVersion, ... })`
 * realizes the implementation plan's "config-epoch" semantics: any
 * POLICY-RELEVANT change changes this hash, which — per
 * `decision-cache.ts`'s versioned invalidation — makes every decision cached
 * under the OLD hash unreachable. Deterministic and canonicalization-stable
 * (key-insertion-order independent), never itself a source of I/O or clock
 * reads.
 */

import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import type { AdminEnvelope, TierPolicy } from "@knotrust/core";
import { canonicalizeJcs } from "@knotrust/core";
import { loadConfig } from "c12";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Schema (R44)
// ---------------------------------------------------------------------------

const TierEnum = z.enum(["routine", "sensitive", "critical"]);

/** Never "routine" — an unlisted tool must never get a silent free pass (mirrors `TierPolicy.unknownToolTier`'s own type-level guarantee, tier-policy.ts). */
const UnknownToolTierEnum = z.enum(["sensitive", "critical"]);

const ToolTierSourceEnum = z.enum(["annotation", "pack", "user"]);

/**
 * Shaped after COAZ's `x-coaz-mapping` extension (AuthZEN/COAZ WG **Draft
 * 1** — an early, unstable spec; brief §C4). KnoTrust's own P0 mapping
 * language is plain, flat DOT-PATH REFERENCES into a tool call's arguments
 * object (e.g. `"arguments.charge_id"`) — **NOT CEL** (Common Expression
 * Language) and **NOT** the COAZ wire shape verbatim. Real CEL expressions
 * and the exact COAZ `x-coaz-mapping` wire format stay behind an adapter
 * boundary with their own conformance note (invariant §E6): this type is
 * KnoTrust's own COAZ-inspired-but-simpler P0 mapping shape, not a COAZ
 * implementation.
 *
 * This task (P0-E4-T2) only DEFINES and VALIDATES this shape — it pins the
 * `{ resourceType?, resourceId?, properties? }` structure and that every
 * string value is a dot-path-shaped reference, nothing more. It does not
 * parse or interpret those dot-path strings, and does not constrain their
 * exact grammar beyond "a string" (that grammar is P0-E5-T3's concern to
 * fix, when it actually resolves a mapping against real arguments to build
 * a `DecisionRequest["resource"]" — deliberately not frozen here).
 */
const CoazStyleMappingSchema = z
  .strictObject({
    resourceType: z.string().optional(),
    resourceId: z.string().optional(),
    properties: z.record(z.string(), z.string()).optional(),
  })
  .describe(
    'Shaped after COAZ\'s "x-coaz-mapping" extension (AuthZEN/COAZ WG Draft 1 — an early, unstable spec). ' +
      "KnoTrust's own P0 mapping language is plain dot-path references into tool-call arguments " +
      '(e.g. "arguments.charge_id"), NOT CEL and NOT the COAZ wire shape verbatim — CEL and the real COAZ ' +
      "wire format stay behind an adapter boundary (invariant §E6). This shape is defined and validated by " +
      "P0-E4-T2 only; resolving it against real arguments to build a DecisionRequest resource is P0-E5-T3's job.",
  );

export type CoazStyleMapping = z.infer<typeof CoazStyleMappingSchema>;

/**
 * `source` is the "annotation | pack | user" provenance marker (mirrors
 * `@knotrust/core`'s `TierSource`, tier-policy.ts): only a `source: "user"`
 * entry's `explicitAllow`/`explicitDeny` is ever honored by the evaluator —
 * enforced in `@knotrust/core`'s logic, not re-validated at this
 * schema/type level (same split `TierSource`'s own doc-comment documents).
 */
const ToolEntrySchema = z.strictObject({
  tier: TierEnum,
  source: ToolTierSourceEnum,
  explicitAllow: z.boolean().optional(),
  explicitDeny: z.boolean().optional(),
  mapping: CoazStyleMappingSchema.optional(),
});

export type ToolEntry = z.infer<typeof ToolEntrySchema>;

const ServerConfigEntrySchema = z.strictObject({
  /** Key = fully-qualified action name (`DecisionRequest["action"]["name"]`, e.g. "github.create_issue"). */
  tools: z.record(z.string(), ToolEntrySchema).optional(),
});

export type ServerConfigEntry = z.infer<typeof ServerConfigEntrySchema>;

/** Proxy subject fallback (E5-T3 seam) — not consumed by any normalizer in this task. */
const IdentityConfigSchema = z.strictObject({
  subjectId: z.string().optional(),
  subjectType: z.enum(["user", "service"]).optional(),
});

export type IdentityConfig = z.infer<typeof IdentityConfigSchema>;

/** Maps 1:1 onto `@knotrust/core`'s `AdminEnvelope` (R12) via `toAdminEnvelope` below — `scope` itself lives at the top-level config, not here. */
const EnvelopeConfigSchema = z.strictObject({
  denyTools: z.array(z.string()).optional(),
  forceApprovalTiers: z.array(TierEnum).optional(),
  forceApprovalTools: z.array(z.string()).optional(),
  tierFloors: z.record(z.string(), TierEnum).optional(),
  grantCeiling: TierEnum.optional(),
});

export type EnvelopeConfig = z.infer<typeof EnvelopeConfigSchema>;

/**
 * STRUCTURALLY routine-only (arch §4.3: sensitive/critical may never fail
 * open) — enforced at BOTH the type level (this shape has no
 * `sensitive`/`critical` key at all) and at runtime (the strict object
 * rejects `{ sensitive: ... }`/`{ critical: ... }` as unrecognized keys,
 * exactly like any other typo). Default absent/off: fail-open is an
 * explicit, opt-in declaration, never an implicit default.
 */
const FailOpenConfigSchema = z.strictObject({
  routine: z.boolean().optional(),
});

export type FailOpenConfig = z.infer<typeof FailOpenConfigSchema>;

/** Cache clamps (`packages/core/src/decision-cache.ts`'s `MAX_ROUTINE_TTL_SECONDS`/`MAX_SENSITIVE_TTL_SECONDS`) enforce their caps regardless of what this config supplies — a value above the cap is accepted here and silently clamped there, by design (R44). */
const CacheTtlOverridesConfigSchema = z.strictObject({
  routine: z.number().nonnegative().optional(),
  sensitive: z.number().nonnegative().optional(),
});

export type CacheTtlOverridesConfig = z.infer<
  typeof CacheTtlOverridesConfigSchema
>;

/**
 * `telemetryExport` (P0-E8-T1; rulings R127–R131) — the REAL schema,
 * replacing the E4-T2 inert `z.unknown()` placeholder (see the field's own
 * comment on `KnotrustConfigSchema` below for that placeholder's history).
 *
 * **KnoTrust has NO product telemetry / phone-home / usage analytics — ever
 * (PRD §11). `telemetryExport` is a user-controlled export of the USER'S OWN
 * audit stream to the USER'S OWN OTLP collector; it is off by default and
 * makes no external call unless the user configures an endpoint.** (R128 —
 * this exact sentence is also stated verbatim in `packages/otel`'s module
 * header and in `docs/02-architecture/system-architecture.md` §9.2.)
 *
 * `enabled` defaults to `false` — an absent `telemetryExport` key, OR an
 * explicit `{}`, both parse to `{enabled: false, serviceName: "knotrust"}`:
 * no endpoint, no exporter construction, no network call, ever, without an
 * explicit opt-in (R128's "off by default" half).
 *
 * `endpoint` (the OTLP/HTTP collector URL) is REQUIRED only when `enabled`
 * is `true` — enforced by the `.superRefine()` below, not by field-level
 * `.optional()` alone, since zod's structural optionality can't express "this
 * field is required only when a SIBLING field is true." `{enabled: true}`
 * alone is therefore a clean `ConfigError` naming `telemetryExport.endpoint`
 * (R129: "enabled without endpoint → clean config error"), never a silent
 * no-op and never a runtime crash inside `@knotrust/otel` reaching for a
 * `undefined` endpoint.
 *
 * `headers` (optional) lets a user attach collector auth (e.g. an API key)
 * — this schema does not interpret or validate header VALUES; whatever the
 * user configures is passed straight through to the OTLP exporter. This is
 * the user's OWN egress credential to their OWN collector, categorically
 * different from anything KnoTrust itself would ever transmit unprompted.
 *
 * `serviceName` (optional, default `"knotrust"`) becomes the OTel `Resource`
 * `service.name` attribute every exported span carries — lets a user
 * distinguish multiple KnoTrust instances in one collector/backend.
 */
const TelemetryExportConfigSchema = z
  .strictObject({
    enabled: z.boolean().default(false),
    endpoint: z.string().optional(),
    headers: z.record(z.string(), z.string()).optional(),
    serviceName: z.string().default("knotrust"),
  })
  .superRefine((value, ctx) => {
    if (
      value.enabled &&
      (value.endpoint === undefined || value.endpoint.trim() === "")
    ) {
      ctx.addIssue({
        code: "custom",
        message:
          "telemetryExport.endpoint is required when telemetryExport.enabled is true",
        path: ["endpoint"],
      });
    }
  });

export type TelemetryExportConfig = z.infer<typeof TelemetryExportConfigSchema>;

/**
 * The on-disk KnoTrust config, v1 (R44). Strict everywhere (unknown keys
 * rejected), including `telemetryExport` (R129 gave it a real schema,
 * replacing the E4-T2 inert placeholder — see `TelemetryExportConfigSchema`'s
 * own doc-comment above).
 * `version`/`scope`/`unknownToolTier`/`approvalTimeoutSeconds` are the
 * fields with ratified defaults (see each field's own comment); every other
 * field is genuinely optional with no default, simply absent when unset.
 */
export const KnotrustConfigSchema = z.strictObject({
  /** Schema/format version. No default — every real config (including generated ones, E7-T1) stamps this explicitly. */
  version: z.literal(1),
  /** Default "personal". "org" parses and is accepted, but Phase 0 gives it no special behavior anywhere (§E7) — schema-forward for Phase 2. */
  scope: z.enum(["personal", "org"]).default("personal"),
  /** Proxy subject fallback (E5-T3 seam). */
  identity: IdentityConfigSchema.optional(),
  /** Key = logical MCP server name (e.g. "github-mcp"). */
  servers: z.record(z.string(), ServerConfigEntrySchema).optional(),
  /** Default "sensitive". NEVER "routine" (type-level AND runtime — see `UnknownToolTierEnum`). */
  unknownToolTier: UnknownToolTierEnum.default("sensitive"),
  envelope: EnvelopeConfigSchema.optional(),
  failOpen: FailOpenConfigSchema.optional(),
  /** Default 300 (arch §6.1: the block-and-wait approval timeout). */
  approvalTimeoutSeconds: z.number().int().positive().default(300),
  cacheTtlOverrides: CacheTtlOverridesConfigSchema.optional(),
  /**
   * Real schema as of P0-E8-T1 (R129) — see `TelemetryExportConfigSchema`'s
   * own doc-comment above (off-by-default, endpoint required iff enabled,
   * the verbatim "no product telemetry, ever" statement). Was an inert,
   * wide-open `z.unknown()` placeholder before this task.
   */
  telemetryExport: TelemetryExportConfigSchema.optional(),
});

export type KnotrustConfig = z.infer<typeof KnotrustConfigSchema>;

// ---------------------------------------------------------------------------
// JSON Schema artifact (R47)
// ---------------------------------------------------------------------------

export const CONFIG_JSON_SCHEMA_ID =
  "https://knotrust.dev/schemas/config.v1.schema.json";

/**
 * Generates the JSON Schema mirror of `KnotrustConfigSchema` via zod v4's
 * native `z.toJSONSchema` (no separate `zod-to-json-schema` dependency).
 *
 * `io: "input"` is deliberate, not the default: this schema's job is to
 * validate the RAW config file an author writes on disk (for editor
 * tooling / CI / `knotrust init`'s generated output), where a defaulted
 * field like `scope`/`unknownToolTier`/`approvalTimeoutSeconds` is
 * genuinely OPTIONAL to author — zod's default `io: "output"` mode marks
 * defaulted fields `required` (true of the PARSED/normalized shape, where
 * the default has already been applied), which would wrongly force every
 * on-disk config to spell out fields this schema's own `default` keyword
 * says are optional.
 *
 * `golden-vectors/schemas/config.v1.schema.json`'s sync test
 * (`config.test.ts`) calls this function and asserts deep-equal against the
 * committed file — regenerate via `pnpm --filter @knotrust/store run
 * generate:schema` after any schema change, then commit the result.
 */
export function buildConfigJsonSchema(): Record<string, unknown> {
  const generated = z.toJSONSchema(KnotrustConfigSchema, {
    target: "draft-2020-12",
    io: "input",
  }) as Record<string, unknown>;
  const { $schema, ...rest } = generated;
  return {
    $schema: $schema ?? "https://json-schema.org/draft/2020-12/schema",
    $id: CONFIG_JSON_SCHEMA_ID,
    title: "KnotrustConfig",
    description:
      "KnoTrust on-disk config v1 (P0-E4-T2, rulings R44-R47). Language-neutral mirror of " +
      "packages/store/src/config.ts's KnotrustConfigSchema (zod). Loaded via c12 (jiti rides inside c12) " +
      "from knotrust.config.ts|yaml|json — all three equally first-class and semantically interchangeable. " +
      '`scope: "org"` parses and is accepted but inert in Phase 0 (personal-only; schema-forward for Phase ' +
      "2). A ToolEntry's `mapping` is shaped after COAZ's `x-coaz-mapping` extension (COAZ WG Draft 1) but " +
      "KnoTrust's own P0 mapping language is plain dot-path argument references, never CEL or the COAZ wire " +
      "form directly (invariant §E6) — see the `mapping` property's own description. This schema reflects " +
      "the INPUT (authoring) shape: fields with a `default` are optional here, exactly as an author may " +
      "omit them from a real config file.",
    ...rest,
  };
}

// ---------------------------------------------------------------------------
// ConfigError (R46)
// ---------------------------------------------------------------------------

/** One zod validation issue, normalized to a dot-joined key path (e.g. `"servers.github-mcp.tools.github.create_issue.tier"`). An empty `path` means a root-level issue (e.g. an unrecognized top-level key — see `message` for the key name(s)). */
export interface ConfigIssue {
  path: string;
  message: string;
}

/**
 * Thrown by `loadKnotrustConfig` when the loaded config fails
 * `KnotrustConfigSchema` validation. Names the offending key path(s) (zod
 * issue path, dot-joined) and the source file it came from (`undefined`
 * only for the zero-config synthetic default — see `loadKnotrustConfig`).
 */
export class ConfigError extends Error {
  readonly issues: readonly ConfigIssue[];
  readonly sourceFile: string | undefined;

  constructor(issues: readonly ConfigIssue[], sourceFile: string | undefined) {
    const summary = issues
      .map(
        (issue) =>
          `${issue.path.length > 0 ? issue.path : "(root)"}: ${issue.message}`,
      )
      .join("; ");
    // NOT self-prefixed with "knotrust: " (fix round 1, P0-E7-T2 review, FIX
    // 1) — every caller that prints this to a human (`run.ts`'s top-level
    // guard, `init/command.ts`) already adds its own single "knotrust: "
    // lead-in; a second one baked in here doubled it to "knotrust: knotrust:".
    super(`invalid config${sourceFile ? ` (${sourceFile})` : ""} — ${summary}`);
    this.name = "ConfigError";
    this.issues = issues;
    this.sourceFile = sourceFile;
  }

  static fromZodError(
    error: z.ZodError,
    sourceFile: string | undefined,
  ): ConfigError {
    const issues: ConfigIssue[] = error.issues.map((issue) => ({
      path: issue.path.map(String).join("."),
      message: issue.message,
    }));
    return new ConfigError(issues, sourceFile);
  }
}

// ---------------------------------------------------------------------------
// Loader (R46) — c12 (`name: "knotrust"`); jiti rides inside c12.
// ---------------------------------------------------------------------------

export interface LoadKnotrustConfigOptions {
  /** Directory c12 searches for `knotrust.config.{ts,yaml,json,...}`. Defaults to `process.cwd()` (c12's own default). */
  cwd?: string;
}

export interface LoadedKnotrustConfig {
  config: KnotrustConfig;
  /** Absolute path to the resolved config file. Absent iff no `knotrust.config.*` file was found at all (the zero-config case below). */
  sourceFile?: string;
}

/**
 * A `require()` bound to this module's own location, used ONLY to reach
 * Node's process-global CJS module cache (`req.cache`, the exact object
 * `require.cache` refers to anywhere in this process) — never to actually
 * require anything through it. `createRequire` is the standard way to get
 * one from an ESM module (this file has no ambient `require`); it needs no
 * real "parent module" semantics for that purpose, just an anchor URL.
 */
const req = createRequire(import.meta.url);

/**
 * Busts Node's OWN CJS module-cache entry for `resolvedConfigFile`, if any
 * (fix round 1, P0-E7-T3 review, FIX 3 — a latent staleness bug this task
 * surfaced in the shared config loader, not introduced by it; see the
 * module header's own note on this fix for the discovery context).
 *
 * WHY THIS EXISTS: `loadConfig` below already disables jiti's own
 * `moduleCache` option, and that alone is enough to keep a `.ts`/`.js`
 * config fresh across repeated in-process loads — jiti transpiles and
 * evaluates those itself, through a fresh jiti instance on every call here
 * (this module never reuses one across calls), so there is nothing stale to
 * serve. A plain `.json` config is different: jiti has a dedicated fast
 * path for it (no TypeScript transform is needed for JSON at all) that
 * calls straight through to Node's OWN `require()` — and `require()`'s
 * module cache (`Module._cache`, the same object `require.cache` exposes)
 * is a PROCESS-GLOBAL singleton entirely outside jiti's `moduleCache`
 * option's reach. Verified empirically while building this fix: NONE of
 * jiti's configurable options (`moduleCache`, `fsCache`, the deprecated
 * `requireCache`, a trimmed `extensions` list) change this — a second
 * in-process `loadKnotrustConfig` call against an evolving `.json` config
 * kept returning the FIRST call's stale parse regardless. Left alone, that
 * is a real correctness trap the moment anything in this process loads the
 * same config path twice (an in-process add-then-decide flow, a future
 * config-watch loop) — silently, with no error and no hint anything was
 * wrong.
 *
 * `require.resolve` (not the raw string) because that is the exact
 * normalization Node's own module system used to key the cache entry in the
 * first place — a byte-different-but-equivalent path string would
 * otherwise silently fail to match and bust nothing. Wrapped in try/catch
 * because `require.resolve` can in principle throw for a path shape Node's
 * CJS resolver rejects; never actually observed for `resolvedConfigFile`
 * here (always a real, already-existing absolute path `loadConfig` itself
 * just reported), so this is belt-and-braces, not load-bearing — a
 * resolution failure means there was nothing cached to bust in the first
 * place, so doing nothing is correct, not a hidden failure.
 *
 * Safe to call for EVERY resolved config path regardless of format: a
 * `.ts`/`.yaml`/etc. file never routes through Node's `require()` in the
 * first place (jiti transpiles-and-evaluates those, or confbox parses YAML
 * directly), so it has no matching cache entry and the `delete` below is a
 * pure no-op for those cases — this function does not need to know which
 * format it was handed.
 */
function bustNativeRequireCache(resolvedConfigFile: string): void {
  try {
    delete req.cache[req.resolve(resolvedConfigFile)];
  } catch {
    // Nothing was cached under this path — see doc comment above.
  }
}

/**
 * Loads and validates `knotrust.config.{ts,yaml,json,...}` from `opts.cwd`
 * via c12. `.ts`/`.yaml`/`.json` are all first-class and equally supported
 * (R44) — c12's bundled jiti executes the `.ts` form directly, no build
 * step required, and this module never imports jiti itself.
 *
 * Every c12 "ambient merge" feature that could pull in config from OUTSIDE
 * the given `cwd` (an `.knotrustrc`, a `package.json#knotrust` key, a
 * `.env` file, a global rc file) is explicitly disabled: this loader's
 * behavior depends ONLY on `knotrust.config.*` inside `cwd`, which is what
 * makes it deterministic under test (fresh temp dirs, no ambient
 * interference from the real environment) and predictable for a real user.
 *
 * **Zero-config**: when NO `knotrust.config.*` file exists anywhere under
 * `cwd` at all, this resolves to the schema's all-defaults config (as if
 * `{ version: 1 }` had been loaded) rather than failing on a missing
 * `version` key — `@knotrust/core`'s L0 evaluator is explicitly "the true
 * default every `npx knotrust` run uses with zero config"
 * (`l0-evaluator.ts`'s own header); config loading must honor that same
 * promise, not undercut the evaluator beneath it. `sourceFile` is absent in
 * this case (there is no real file backing it).
 *
 * **Fails fast** (`ConfigError`) on any `KnotrustConfigSchema` violation —
 * a bad tier value, an unrecognized key, a `.ts` config whose value for a
 * real field evaluates to a function (config must be data — a strict
 * zod schema naturally rejects any non-matching runtime value, function or
 * otherwise, exactly the same way it rejects a plain string typo). A
 * genuine parse/syntax error in the config file itself (malformed YAML/JSON,
 * a `.ts` file that throws while evaluating) is NOT wrapped here — it
 * propagates as c12/jiti's own error, since it has no "offending key path"
 * to name in the first place.
 *
 * **Always a fresh on-disk read, never a stale in-process cache** (fix
 * round 1, P0-E7-T3 review, FIX 3): every call busts the one cache layer
 * that could otherwise serve a prior call's stale parse for an evolving
 * `.json` config (`bustNativeRequireCache`, see its own doc-comment for the
 * full root-cause story) — a second `loadKnotrustConfig` call in the same
 * process, after the file changed on disk, always reflects the change,
 * for every supported format (`.ts`/`.yaml`/`.json`/…) equally.
 */
export async function loadKnotrustConfig(
  opts: LoadKnotrustConfigOptions = {},
): Promise<LoadedKnotrustConfig> {
  const resolved = await loadConfig<Record<string, unknown>>({
    name: "knotrust",
    ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
    rcFile: false,
    packageJson: false,
    dotenv: false,
    globalRc: false,
  });

  const found = (resolved.layers?.length ?? 0) > 0;
  const sourceFile = found ? resolved.configFile : undefined;
  const raw: unknown = found ? resolved.config : { version: 1 };

  // Bust BEFORE returning (success or failure alike) — see
  // `bustNativeRequireCache`'s own doc-comment (fix round 1, FIX 3):
  // guarantees the NEXT load of this same path, from anywhere in this
  // process, re-reads the file fresh rather than silently serving this
  // call's parse forever.
  if (sourceFile !== undefined) {
    bustNativeRequireCache(sourceFile);
  }

  const result = KnotrustConfigSchema.safeParse(raw);
  if (!result.success) {
    throw ConfigError.fromZodError(result.error, sourceFile);
  }

  return sourceFile !== undefined
    ? { config: result.data, sourceFile }
    : { config: result.data };
}

/**
 * Identity helper for authoring `knotrust.config.ts` with type-checking —
 * mirrors c12's own `createDefineConfig` convention. Purely a compile-time
 * ergonomic aid: returns its argument unchanged, no validation happens
 * here (validation is `loadKnotrustConfig`'s job, after loading).
 */
export function defineKnotrustConfig(config: KnotrustConfig): KnotrustConfig {
  return config;
}

// ---------------------------------------------------------------------------
// Normalizers (R46) — `@knotrust/core` shapes, FRESH objects every call (R20)
// ---------------------------------------------------------------------------

/**
 * Builds the `TierPolicy` the L0 evaluator consumes for one server, from
 * `config.servers?.[serverName]?.tools`. A `serverName` absent from
 * `config.servers` yields an EMPTY (but valid) `TierPolicy` — every tool on
 * that server simply falls back to `unknownToolTier` — rather than
 * throwing; an unconfigured server is not an error.
 *
 * `ToolEntry.mapping` is deliberately DROPPED here: `@knotrust/core`'s
 * `ToolTierEntry` (tier-policy.ts) has no slot for it — mapping is a
 * config-level, resource-building concern P0-E5-T3 reads directly off the
 * loaded `KnotrustConfig`, never through this normalizer (see this module's
 * own header).
 *
 * R20 CONTRACT: returns a brand-new `TierPolicy` object (and a brand-new
 * `tools` record, and a brand-new object per tool entry) on every call —
 * never a shared/memoized reference, never a value carrying a live
 * reference into `config`'s own nested objects. See this module's header
 * for why that matters to `@knotrust/core`'s decision pipeline.
 */
export function toTierPolicy(
  config: KnotrustConfig,
  serverName: string,
): TierPolicy {
  const serverTools = config.servers?.[serverName]?.tools ?? {};
  const tools: TierPolicy["tools"] = {};
  for (const [actionName, entry] of Object.entries(serverTools)) {
    tools[actionName] = {
      tier: entry.tier,
      source: entry.source,
      ...(entry.explicitAllow !== undefined
        ? { explicitAllow: entry.explicitAllow }
        : {}),
      ...(entry.explicitDeny !== undefined
        ? { explicitDeny: entry.explicitDeny }
        : {}),
    };
  }
  return { tools, unknownToolTier: config.unknownToolTier };
}

/**
 * Builds the `AdminEnvelope` the precedence engine consumes, from
 * `config.envelope` plus the top-level `config.scope` (`AdminEnvelope.scope`
 * is REQUIRED — `scope` itself lives outside `envelope` in the on-disk
 * config, R44 — this is where the two are joined 1:1).
 *
 * R20 CONTRACT: same as `toTierPolicy` above — a brand-new `AdminEnvelope`
 * object (and brand-new arrays/records for every present field) on every
 * call, never shared/memoized, never aliasing `config`'s own nested values.
 */
export function toAdminEnvelope(config: KnotrustConfig): AdminEnvelope {
  const envelope = config.envelope;
  return {
    scope: config.scope,
    ...(envelope?.denyTools !== undefined
      ? { denyTools: [...envelope.denyTools] }
      : {}),
    ...(envelope?.forceApprovalTiers !== undefined
      ? { forceApprovalTiers: [...envelope.forceApprovalTiers] }
      : {}),
    ...(envelope?.forceApprovalTools !== undefined
      ? { forceApprovalTools: [...envelope.forceApprovalTools] }
      : {}),
    ...(envelope?.tierFloors !== undefined
      ? { tierFloors: { ...envelope.tierFloors } }
      : {}),
    ...(envelope?.grantCeiling !== undefined
      ? { grantCeiling: envelope.grantCeiling }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// policyVersion (R46) — config-epoch content-hash
// ---------------------------------------------------------------------------

/**
 * The fields of `KnotrustConfig` that actually shape a decision, and
 * therefore belong in `policyVersion`'s content-hash. Built as an explicit
 * object (never `{ ...config }` minus a denylist) so that adding a new
 * `KnotrustConfigSchema` field defaults to EXCLUDED until someone
 * deliberately adds it here — the safer failure mode for a hash whose whole
 * job is cache invalidation, not accidental completeness.
 *
 * **Hashed**: `version`, `scope`, `servers` (per-tool `tier`/`source`/
 * `explicitAllow`/`explicitDeny`/`mapping`), `unknownToolTier`, `envelope`,
 * `failOpen`, `approvalTimeoutSeconds`, `cacheTtlOverrides` — every field
 * `toTierPolicy`/`toAdminEnvelope` read, plus `failOpen`/
 * `approvalTimeoutSeconds`/`cacheTtlOverrides`, which shape the pipeline the
 * same way even though no normalizer above touches them yet.
 *
 * **Excluded, deliberately**:
 * - `identity` — a proxy `subject` fallback (E5-T3 seam), not a policy
 *   input. Once wired, the `subject.id` it resolves to is already part of
 *   `computeCacheKey`'s own key material (`decision-cache.ts`'s `s` field);
 *   hashing it here too would be redundant, and would over-invalidate the
 *   cache (and bump the epoch) every time a user's identity changes with no
 *   policy change at all.
 * - `telemetryExport` — excluded for relevance, not for validation: it now
 *   has a real, strict schema (`TelemetryExportConfigSchema`, P0-E8-T1,
 *   R129 — see that schema's own doc-comment), but it configures WHERE
 *   already-made decisions get exported to (an observability/export
 *   destination), not any input the decider itself reads — it carries no
 *   decision semantics at all, so it does not belong in a hash whose whole
 *   job is invalidating cached decisions when POLICY changes. Hashing it
 *   would over-invalidate the cache (and bump the epoch) every time a user
 *   merely points their OTLP collector at a new endpoint, with no policy
 *   change at all — the same category of reason `identity` above is
 *   excluded.
 *
 * This basis freezes once P0-E5 wires `policyVersion` into
 * `createDecisionPipeline` — changing it after that point changes epoch
 * semantics for a live pipeline, not just this module's own tests.
 */
function policyRelevantSubset(config: KnotrustConfig): Record<string, unknown> {
  return {
    version: config.version,
    scope: config.scope,
    ...(config.servers !== undefined ? { servers: config.servers } : {}),
    unknownToolTier: config.unknownToolTier,
    ...(config.envelope !== undefined ? { envelope: config.envelope } : {}),
    ...(config.failOpen !== undefined ? { failOpen: config.failOpen } : {}),
    approvalTimeoutSeconds: config.approvalTimeoutSeconds,
    ...(config.cacheTtlOverrides !== undefined
      ? { cacheTtlOverrides: config.cacheTtlOverrides }
      : {}),
  };
}

/**
 * Identifies which top-level field of a policy-relevant subset failed to
 * canonicalize, for `policyVersion`'s `ConfigError` message. Re-canonicalizes
 * each field individually (cheap: this only runs on the already-rare error
 * path) rather than threading a path out of `canonicalizeJcs` itself, which
 * has no notion of "field name" (its own errors are plain `TypeError`s with
 * no path, R33 — it is a frozen, path-agnostic artifact).
 */
function findFailingPolicyField(subset: Record<string, unknown>): string {
  for (const [field, value] of Object.entries(subset)) {
    try {
      canonicalizeJcs(value);
    } catch {
      return field;
    }
  }
  // Unreachable in practice: canonicalizeJcs(subset) itself just threw, so
  // some field must fail individually too. Falls back to a root-level issue
  // rather than throwing an unrelated error out of this helper.
  return "(root)";
}

/**
 * SHA-256 hex content-hash of the canonicalized (`@knotrust/core`'s frozen
 * `canonicalizeJcs`) POLICY-RELEVANT SUBSET of `config` — see
 * `policyRelevantSubset` for exactly what is hashed and what is deliberately
 * excluded (`identity`, `telemetryExport`) and why. This is the
 * `policyVersion` input `createDecisionPipeline` expects (config-epoch
 * semantics: any policy-relevant config change ⇒ a new hash ⇒ every
 * previously-cached decision becomes unreachable). Deterministic and
 * key-insertion-order independent (inherits `canonicalizeJcs`'s own
 * recursive key sort); pure — no I/O, no clock.
 *
 * Every field `policyRelevantSubset` selects comes from a
 * `KnotrustConfigSchema`-validated field, so every value reaching
 * `canonicalizeJcs` here is always JSON-safe in practice — this holds for
 * `telemetryExport` too (it has its own real, strict schema as of P0-E8-T1,
 * R129), which is EXCLUDED from the subset not because it is unvalidated
 * (it isn't, anymore) but because it carries no decision semantics at all
 * (see `policyRelevantSubset`'s own doc-comment). The try/catch below is
 * therefore belt-and-braces, not load-bearing — but it keeps this module's
 * documented `ConfigError` contract (R46) intact even if that invariant is
 * ever violated (e.g. a future schema change loosens a hashed field), rather
 * than letting a raw `canonicalizeJcs` `TypeError` escape.
 */
export function policyVersion(config: KnotrustConfig): string {
  const subset = policyRelevantSubset(config);
  let canonical: string;
  try {
    canonical = canonicalizeJcs(subset);
  } catch (error) {
    const field = findFailingPolicyField(subset);
    const message = error instanceof Error ? error.message : String(error);
    throw new ConfigError(
      [{ path: field, message: `policyVersion: ${message}` }],
      undefined,
    );
  }
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}
