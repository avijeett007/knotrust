/**
 * knotrust CLI `init` — suggested-tier `knotrust.config.*` generation
 * (P0-E7-T1, ruling R109 — closes the P0-E5-T2 `mergeSeededTiers` pin).
 *
 * After wrapping a client's MCP server entries, `init` best-effort captures
 * each wrapped server's `tools/list` (`tool-capture.ts`), seeds SUGGESTED
 * tiers from the captured annotations (`@knotrust/proxy-stdio`'s
 * `seedTierEntriesFromAnnotations`), and folds them into a real
 * `knotrust.config.*` via the SAME `mergeSeededTiers` E5-T2 shipped —
 * without ever overriding a pre-existing pack/user entry (R65). This module
 * is the plumbing between those two packages and `@knotrust/store`'s
 * on-disk `KnotrustConfig` shape, plus the three format serializers R109
 * asks `--config-format` to choose between.
 *
 * ## The E5-T2 pin: `ToolTierEntry` → `ToolEntry`
 *
 * `mergeSeededTiers` targets `@knotrust/core`'s `ToolTierEntry`
 * (`{tier, source, explicitAllow?, explicitDeny?}`) — it has no `mapping`
 * slot (`ToolTierEntry` predates the config-level `CoazStyleMapping`
 * concept, which is a config-authoring feature P0-E4-T2 added, not a
 * decision-pipeline one). `@knotrust/store`'s on-disk `ToolEntry` is a
 * strict superset (adds the optional `mapping`). `toConfigToolEntries`
 * below is the explicit adapter: every annotation-seeded entry this module
 * ever writes has `source: "annotation"` and NO `mapping` (annotations never
 * suggest a resource mapping) — built as a fresh object per field, mirroring
 * `packages/store/src/config.ts`'s own "R20: normalizers return fresh
 * objects" discipline, rather than relying on the two interfaces' silent
 * structural compatibility.
 *
 * ## Best-effort capture failure → the skeleton (R109)
 *
 * When `tool-capture.ts`'s capture fails/times out for a server, this module
 * does NOT invent tier suggestions — it leaves that server's existing
 * `tools` (if any) untouched and records it in `skeletonServers`, so
 * `command.ts` can attach the documented note ("tiers will be seeded next
 * successful `knotrust init` run — until then every unlisted tool falls back
 * to `unknownToolTier`") to the generated file. The top-level
 * `unknownToolTier` field is ALWAYS present in the generated config
 * (defaulting to `"sensitive"`, mirroring the schema's own default) whether
 * or not any server hit the skeleton path.
 *
 * ## Never overwriting without a real merge (R109)
 *
 * `buildGeneratedConfig` takes the EXISTING parsed+validated `KnotrustConfig`
 * (if `command.ts` found one via `loadKnotrustConfig`) as its base and only
 * ever replaces `servers[name].tools` for servers this run actually
 * processed — every other field (`envelope`, `failOpen`,
 * `approvalTimeoutSeconds`, other servers, …) round-trips through
 * unchanged. This is DATA-level preservation (the regenerated file is a
 * fresh, canonical re-serialization of the full `KnotrustConfig` object, not
 * a byte-level patch) — full and exact for every field this schema models,
 * but it does NOT reproduce a hand-authored file's original comments/key
 * order/whitespace. That is an explicit, narrower guarantee than R107's
 * "preserve as faithfully as JSON allows" for the CLIENT config (a
 * third-party file format outside our own schema); see `command.ts`'s
 * module header for why a `knotrust.config.ts` (arbitrary executable TS, not
 * safely re-emittable) is skipped entirely rather than regenerated.
 */

import type { ToolTierEntry } from "@knotrust/core";
import {
  mergeSeededTiers,
  seedTierEntriesFromAnnotations,
  type ToolInventory,
} from "@knotrust/proxy-stdio";
import type {
  KnotrustConfig,
  ServerConfigEntry,
  ToolEntry,
} from "@knotrust/store";

export type ConfigFormat = "yaml" | "json" | "ts";

export const DEFAULT_CONFIG_FORMAT: ConfigFormat = "yaml";

export function configFileName(format: ConfigFormat): string {
  return `knotrust.config.${format}`;
}

// ---------------------------------------------------------------------------
// The E5-T2 pin adapter
// ---------------------------------------------------------------------------

/** Adapts `@knotrust/core`'s `ToolTierEntry` into the config's `ToolEntry` shape — see this module's header. Fresh object per entry; never carries `mapping`. */
export function toConfigToolEntries(
  entries: Record<string, ToolTierEntry>,
): Record<string, ToolEntry> {
  const result: Record<string, ToolEntry> = {};
  for (const [name, entry] of Object.entries(entries)) {
    result[name] = {
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
  return result;
}

/**
 * The inverse adapter, needed going INTO `mergeSeededTiers`: with
 * `exactOptionalPropertyTypes` on, zod's inferred `ToolEntry` (whose optional
 * fields are typed `T | undefined`, not just "possibly absent") is not
 * structurally assignable to the hand-written `ToolTierEntry` interface
 * (whose optional fields are plain `T?`) even though every VALUE either type
 * can hold is identical — so this strips `mapping` and rebuilds each entry
 * explicitly rather than relying on a cast.
 */
function fromConfigToolEntries(
  entries: Record<string, ToolEntry> | undefined,
): Record<string, ToolTierEntry> | undefined {
  if (entries === undefined) return undefined;
  const result: Record<string, ToolTierEntry> = {};
  for (const [name, entry] of Object.entries(entries)) {
    result[name] = {
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
  return result;
}

// ---------------------------------------------------------------------------
// Building the config object (pure)
// ---------------------------------------------------------------------------

export interface CaptureOutcome {
  serverName: string;
  /** `undefined` = best-effort capture failed/timed out this run (R109 skeleton path). */
  inventory: ToolInventory | undefined;
}

export interface BuildGeneratedConfigResult {
  config: KnotrustConfig;
  /** Servers whose capture failed/timed out this run — `command.ts` attaches the documented skeleton note for these. */
  skeletonServers: string[];
}

function freshDefaultConfig(): KnotrustConfig {
  return {
    version: 1,
    scope: "personal",
    unknownToolTier: "sensitive",
    approvalTimeoutSeconds: 300,
  };
}

/**
 * Pure: folds `outcomes` (one per wrapped server this `init` run touched)
 * into `existing` (or a fresh all-defaults config when none was found),
 * seeding suggested tiers via `seedTierEntriesFromAnnotations` +
 * `mergeSeededTiers` for every server whose capture succeeded, and leaving
 * a server's existing `tools` untouched (recording it in `skeletonServers`)
 * when capture failed. Every other top-level field of `existing` (and every
 * OTHER server's config) is carried over verbatim.
 */
export function buildGeneratedConfig(
  existing: KnotrustConfig | undefined,
  outcomes: readonly CaptureOutcome[],
): BuildGeneratedConfigResult {
  const base = existing ?? freshDefaultConfig();
  const unknownToolTier = base.unknownToolTier;
  const servers: Record<string, ServerConfigEntry> = {
    ...(base.servers ?? {}),
  };
  const skeletonServers: string[] = [];

  for (const { serverName, inventory } of outcomes) {
    const existingEntry = base.servers?.[serverName];
    if (inventory === undefined) {
      skeletonServers.push(serverName);
      if (existingEntry !== undefined) {
        servers[serverName] = existingEntry;
      } else if (!(serverName in servers)) {
        servers[serverName] = {};
      }
      continue;
    }
    const seeded = seedTierEntriesFromAnnotations(inventory, {
      unknownToolTier,
    });
    const merged = mergeSeededTiers(
      fromConfigToolEntries(existingEntry?.tools),
      seeded,
    );
    servers[serverName] = { tools: toConfigToolEntries(merged) };
  }

  return {
    config: { ...base, servers },
    skeletonServers,
  };
}

// ---------------------------------------------------------------------------
// Serializers (R109 — `--config-format yaml|json|ts`)
// ---------------------------------------------------------------------------

export interface SerializeOptions {
  /** Attached as a leading comment block when non-empty (never present for a JSON target — JSON has no comment syntax; see `serializeConfigJson`). */
  skeletonNote?: string;
}

const HEADER_LINES = [
  "Generated by `knotrust init` (P0-E7-T1). Validated against",
  "KnotrustConfigSchema (@knotrust/store) on every `knotrust` run — edit",
  "freely.",
];

function commentBlock(prefix: string, opts: SerializeOptions): string[] {
  const lines = HEADER_LINES.map((l) => `${prefix} ${l}`);
  if (opts.skeletonNote !== undefined && opts.skeletonNote.length > 0) {
    lines.push(prefix);
    for (const l of opts.skeletonNote.split("\n")) {
      lines.push(`${prefix} ${l}`);
    }
  }
  return lines;
}

/** JSON has no comment syntax — `opts.skeletonNote` is intentionally dropped here (the CLI still prints it to stderr; see `command.ts`). */
export function serializeConfigJson(
  config: KnotrustConfig,
  _opts: SerializeOptions = {},
): string {
  return `${JSON.stringify(config, null, 2)}\n`;
}

export function serializeConfigTs(
  config: KnotrustConfig,
  opts: SerializeOptions = {},
): string {
  const header = commentBlock("//", opts);
  header.push(
    "//",
    "// Plain data export — deliberately NOT a `defineKnotrustConfig` helper",
    "// imported from the @knotrust/store package. That internal package is",
    "// bundled into the published `knotrust` CLI, never published to npm on",
    "// its own (ADR-0002), so a generated config file cannot depend on it.",
    "// c12's bundled jiti executes this file directly and reads the default export.",
  );
  return `${header.join("\n")}\nexport default ${JSON.stringify(config, null, 2)};\n`;
}

// --- a tiny, deliberately narrow YAML dumper -------------------------------
//
// Covers exactly what `KnotrustConfigSchema` can ever produce: strings,
// finite numbers, booleans, plain objects/records, and arrays of the above
// (nested arbitrarily). Every string scalar is emitted DOUBLE-QUOTED — this
// sidesteps YAML's unquoted-scalar ambiguity (a tool named "true"/"null"/
// "123", a colon or `#` inside a name, …) entirely, at the minor cosmetic
// cost of quoting marks on every key/string value. Not a general-purpose
// YAML writer; see this module's header for why a full YAML dependency was
// deliberately not added (ADR-0002 dependency-tree-minimalism doctrine).

function yamlScalar(value: string | number | boolean): string {
  if (typeof value === "string") return JSON.stringify(value);
  return String(value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function yamlLines(value: unknown, indent: number): string[] {
  const pad = "  ".repeat(indent);

  if (Array.isArray(value)) {
    if (value.length === 0) return [`${pad}[]`];
    const lines: string[] = [];
    for (const item of value) {
      if (isPlainRecord(item)) {
        const nested = yamlLines(item, indent + 1);
        const first = nested[0] ?? "";
        lines.push(`${pad}- ${first.trimStart()}`);
        lines.push(...nested.slice(1));
      } else {
        lines.push(`${pad}- ${yamlScalar(item as string | number | boolean)}`);
      }
    }
    return lines;
  }

  if (isPlainRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) return [`${pad}{}`];
    const lines: string[] = [];
    for (const [key, v] of entries) {
      const keyStr = yamlScalar(key);
      if (isPlainRecord(v) || Array.isArray(v)) {
        const nested = yamlLines(v, indent + 1);
        const onlyLine = nested.length === 1 ? nested[0] : undefined;
        const trimmed = onlyLine?.trim();
        if (trimmed === "[]" || trimmed === "{}") {
          lines.push(`${pad}${keyStr}: ${trimmed}`);
        } else {
          lines.push(`${pad}${keyStr}:`);
          lines.push(...nested);
        }
      } else {
        lines.push(
          `${pad}${keyStr}: ${yamlScalar(v as string | number | boolean)}`,
        );
      }
    }
    return lines;
  }

  return [`${pad}${yamlScalar(value as string | number | boolean)}`];
}

export function serializeConfigYaml(
  config: KnotrustConfig,
  opts: SerializeOptions = {},
): string {
  const header = commentBlock("#", opts);
  const body = yamlLines(config, 0).join("\n");
  return `${header.join("\n")}\n${body}\n`;
}

export function serializeGeneratedConfig(
  config: KnotrustConfig,
  format: ConfigFormat,
  opts: SerializeOptions = {},
): string {
  if (format === "json") return serializeConfigJson(config, opts);
  if (format === "ts") return serializeConfigTs(config, opts);
  return serializeConfigYaml(config, opts);
}
