/**
 * knotrust CLI `add pack` — the local pack file format + loader (P0-E7-T3,
 * ruling R117).
 *
 * A pack is a small, declarative YAML file bundling tier policy for a set of
 * tools (e.g. a `github` pack tiering `github.delete_repo` critical):
 *
 *   name: github-basics
 *   version: 1
 *   description: "Conservative tiers for common github.com MCP tools"
 *   server: github-mcp
 *   tools:
 *     github.delete_repo:
 *       tier: critical
 *     github.create_issue:
 *       tier: sensitive
 *
 * `PackToolEntrySchema` mirrors `@knotrust/store`'s `ToolEntrySchema` MINUS
 * `source` — a pack never declares its own provenance; `knotrust add pack`
 * stamps every entry it applies with `source: "pack"` itself (see
 * `pack-merge.ts`). `tier`/`mapping` are otherwise identical fields, for the
 * identical reason: a pack IS a bundle of `ToolEntry`s, just not-yet-
 * attributed ones — MINUS `explicitAllow`/`explicitDeny` too (fix round 1,
 * P0-E7-T3 review, FIX 1): the evaluator honors those two flags ONLY on a
 * `source: "user"` entry, so a pack's own copy (always stamped `source:
 * "pack"` by `pack-merge.ts`) is never itself read by today's evaluator —
 * but accepting it here would leave a live bypass primitive sitting inside
 * every applied pack, one future evaluator change away from silently going
 * live for content nobody currently checks. A pack expresses TIER POLICY
 * only; explicit allow/deny is USER-only authority, never delegable to a
 * pack file. See `PackToolEntrySchema`'s own doc-comment for the exact
 * rejection.
 *
 * ## P0 packs are UNSIGNED local files (R117 — read before trusting one)
 *
 * This loader performs NO signature verification, NO content-hash pinning,
 * and NO registry lookup — `path` is read directly off the local filesystem,
 * validated against `PackSchema`, and nothing more. `knotrust add pack` is
 * therefore only as trustworthy as the human who chose to point it at a given
 * file — exactly the Homebrew "tap trust" lesson this task's diff-preview UX
 * (R119) exists to mitigate for the ONE thing local-file trust can't fix
 * (content you can't see before it's applied). The GitHub registry, package
 * signing, and content-hash verification arrive in P1-E3 (invariant §E6) —
 * this module is deliberately the reusable, signature-agnostic core P1 will
 * wrap, not a placeholder that pretends to verify anything today.
 *
 * ## Reuses c12 for YAML — no new parser dependency (mirrors `config.ts`)
 *
 * `@knotrust/store`'s `loadKnotrustConfig` already established the pattern
 * this loader follows: c12's bundled `confbox` parses YAML/JSON/`.ts`
 * uniformly, so a pack file gets the exact same "any of `.yaml`/`.yml`/
 * `.json`/`.ts` is fine" flexibility a `knotrust.config.*` does, with zero new
 * runtime dependency (ADR-0002 dependency-tree-minimalism doctrine) — c12 is
 * already a direct `dependencies` entry of this package. `loadConfig`'s
 * `configFile` option (distinct from its `name`-based directory search) loads
 * one EXACT file path directly, which is exactly what `add pack <path>` needs
 * (a specific file the user named, not a `name.config.*` convention search).
 */

import { existsSync } from "node:fs";
import path from "node:path";
import { loadConfig } from "c12";
import { z } from "zod";

const TierEnum = z.enum(["routine", "sensitive", "critical"]);

/** Identical shape to `@knotrust/store`'s (unexported) `CoazStyleMappingSchema` — duplicated here rather than cross-imported, mirroring this repo's established convention for a tiny shared shape with no other consumer to share a package boundary with (see e.g. `run.ts`'s own note on the two independent `resolveKnotrustHome` copies). */
const PackMappingSchema = z.strictObject({
  resourceType: z.string().optional(),
  resourceId: z.string().optional(),
  properties: z.record(z.string(), z.string()).optional(),
});

/**
 * Rejection message for a pack tool entry carrying `explicitAllow` or
 * `explicitDeny` (fix round 1, P0-E7-T3 review, FIX 1) — see
 * `PackToolEntrySchema`'s own doc-comment and this module's header for the
 * full "why". Named per-field (not a single generic sentence) so the
 * composed `PackError` message reads naturally next to the zod issue path
 * it is paired with (e.g. `tools.github.delete_repo.explicitAllow: ...`).
 */
function explicitFlagRejectionMessage(
  field: "explicitAllow" | "explicitDeny",
): string {
  return (
    `packs cannot set "${field}" — explicit allow/deny is USER-only ` +
    'authority (the evaluator only honors it on a source: "user" entry); ' +
    `a pack may declare tier policy only. Remove "${field}" from this pack file.`
  );
}

/**
 * `z.never()` (rather than simply omitting the key, which would fall
 * through to the strict object's generic "unrecognized key" message) so a
 * pack file carrying `explicitAllow`/`explicitDeny` gets a field-specific,
 * load-bearing explanation instead of a plain typo-shaped complaint. Still
 * `.optional()` — a pack that never mentions the field at all is fine; only
 * an ACTUAL value (any value, since `never` accepts none) is rejected.
 */
function rejectedExplicitFlag(field: "explicitAllow" | "explicitDeny") {
  return z
    .never({ error: () => explicitFlagRejectionMessage(field) })
    .optional();
}

/**
 * Mirrors `@knotrust/store`'s `ToolEntrySchema` MINUS `source` (R117) — see
 * this module's header. A pack tool entry is otherwise a plain `ToolEntry`,
 * MINUS `explicitAllow`/`explicitDeny` (fix round 1, P0-E7-T3 review, FIX
 * 1): declared here ONLY to reject them with `rejectedExplicitFlag`'s clear,
 * field-naming message — a pack may carry `tier`/`mapping`, nothing else.
 */
const PackToolEntrySchema = z.strictObject({
  tier: TierEnum,
  explicitAllow: rejectedExplicitFlag("explicitAllow"),
  explicitDeny: rejectedExplicitFlag("explicitDeny"),
  mapping: PackMappingSchema.optional(),
});

export type PackToolEntry = z.infer<typeof PackToolEntrySchema>;

/**
 * `version` is liberal (`string | number`) deliberately: unlike
 * `KnotrustConfigSchema`'s `version` (a schema-format literal gate this
 * loader's own parsing depends on), a pack's `version` is author-facing
 * metadata only — nothing in this task's apply/merge logic branches on its
 * type or value. A human writing `version: 1` or `version: "1.2.0"` in YAML
 * should both validate.
 */
export const PackSchema = z.strictObject({
  name: z.string().min(1),
  version: z.union([z.string(), z.number()]),
  description: z.string().optional(),
  /** Suggested target `servers.<server>` key (config schema shape) — `add pack` uses this as the default `--server` when the flag is omitted (see `pack-command.ts`). */
  server: z.string().optional(),
  tools: z.record(z.string(), PackToolEntrySchema),
});

export type Pack = z.infer<typeof PackSchema>;

/** One zod validation issue, normalized to a dot-joined key path — mirrors `@knotrust/store`'s `ConfigIssue`. */
export interface PackIssue {
  path: string;
  message: string;
}

/** Thrown when a pack file fails `PackSchema` validation. Mirrors `@knotrust/store`'s `ConfigError` shape/contract exactly (same reasoning: name the offending key path(s) and the source file, never a raw zod dump). */
export class PackError extends Error {
  readonly issues: readonly PackIssue[];
  readonly filePath: string;

  constructor(issues: readonly PackIssue[], filePath: string) {
    const summary = issues
      .map(
        (issue) =>
          `${issue.path.length > 0 ? issue.path : "(root)"}: ${issue.message}`,
      )
      .join("; ");
    super(`invalid pack (${filePath}) — ${summary}`);
    this.name = "PackError";
    this.issues = issues;
    this.filePath = filePath;
  }

  static fromZodError(error: z.ZodError, filePath: string): PackError {
    const issues: PackIssue[] = error.issues.map((issue) => ({
      path: issue.path.map(String).join("."),
      message: issue.message,
    }));
    return new PackError(issues, filePath);
  }
}

/** Thrown when `add pack <path>` names a file that does not exist. Named and thrown BEFORE any parse attempt (never a c12 "file not found" surprise several layers down) — mirrors `init/client-config.ts`'s `ClientConfigNotFoundError` convention of naming exactly what was looked for. */
export class PackNotFoundError extends Error {
  constructor(filePath: string) {
    super(`pack file not found: ${filePath}`);
    this.name = "PackNotFoundError";
  }
}

/**
 * Loads and validates a pack file at the exact given `filePath` (absolute or
 * relative to `process.cwd()` — callers resolve against their own `cwd`
 * first; see `pack-command.ts`). Every c12 "ambient merge" feature that could
 * pull in config from OUTSIDE this one file is disabled, mirroring
 * `loadKnotrustConfig`'s own discipline — this loader's result depends ONLY
 * on the named file.
 *
 * Throws {@link PackNotFoundError} if `filePath` does not exist, {@link
 * PackError} if it parses but fails `PackSchema` validation. A genuine
 * parse/syntax error in the file itself (malformed YAML, etc.) is NOT wrapped
 * — it propagates as c12/confbox's own error, exactly as `loadKnotrustConfig`
 * documents for the identical reason (no "offending key path" to name).
 */
export async function loadPackFile(filePath: string): Promise<Pack> {
  if (!existsSync(filePath)) {
    throw new PackNotFoundError(filePath);
  }

  const resolved = await loadConfig<Record<string, unknown>>({
    configFile: filePath,
    cwd: path.dirname(filePath),
    rcFile: false,
    packageJson: false,
    dotenv: false,
    globalRc: false,
  });

  const result = PackSchema.safeParse(resolved.config);
  if (!result.success) {
    throw PackError.fromZodError(result.error, filePath);
  }
  return result.data;
}
