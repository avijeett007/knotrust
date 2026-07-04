/**
 * knotrust CLI `grant` — mint a durable grant (P0-E7-T2, R111/R112/R116).
 *
 * Composes the REAL substrate — this is the one CLI path (alongside a
 * successful approval's "Always allow") that legitimately needs to SIGN, so
 * it builds a real `KeyStore` (OS keychain default-on, file fallback, R22 —
 * mirroring `enforcement.ts`'s own justification for doing the same on the
 * approval path), the real file-backed grant store (`@knotrust/store`), and
 * the real hash-chained audit sink. `mintDurableGrant` (`@knotrust/grants`)
 * does the actual signing/persisting/auditing; this module is the argv ->
 * plain-words-confirmation -> composed-call glue.
 *
 * ## Subject/principal + envelope scope
 *
 * There is no `--as`/`--subject` flag (not in the ratified flag list, R111)
 * — the principal comes from `knotrust.config`'s `identity` field, read from
 * `io.cwd` via the SAME `loadKnotrustConfig` + default-fallback
 * (`{ type: "user", id: "local-user" }`) the proxy's own `enforce.ts` uses
 * for its subject fallback. This is deliberate: a grant minted with the
 * SAME default identity a zero-config/matching-config proxy run resolves to
 * is what makes "mint a grant, then a matching call allows" actually true
 * without requiring the human to first write a config. `envelopeScope`
 * mirrors `config.scope` the same way. A malformed existing config is fatal
 * here exactly as it is on the enforcement path — this function does not
 * swallow `ConfigError`; it propagates to `run.ts`'s top-level guard (R116:
 * still never a raw stack, just a clean `knotrust: <message>`).
 *
 * ## The "server" flag is real input, but not a grant claim
 *
 * `--server <name>` is used here for the tool-inventory `destructiveHint`
 * lookup (R111) and the confirmation text; it is NOT persisted onto the
 * minted grant (`GrantClaims`, architecture §5.2, carries no server field —
 * see `format.ts`'s `deriveServerLabel` doc-comment for the full rationale).
 */

import type { Writable } from "node:stream";
import { createUlidGenerator } from "@knotrust/core";
import {
  createKeyStore,
  decodeGrantIndexEntry,
  type MintDurableGrantInput,
  mintDurableGrant,
  resolveKnotrustHome,
} from "@knotrust/grants";
import { loadToolInventory } from "@knotrust/proxy-stdio";
import {
  createAuditLog,
  createGrantStore,
  loadKnotrustConfig,
} from "@knotrust/store";
import type { GrantMintArgs } from "./argv.js";
import { type ConfirmFn, confirmInteractively } from "./confirm.js";
import {
  buildGrantConfirmationText,
  formatAbsolute,
  isKnownDestructive,
  parseResourceScope,
} from "./format.js";

export interface GrantMintIo {
  stdout: Writable;
  stderr: Writable;
  /** Directory searched for `knotrust.config.*` (the identity/scope defaults). Defaults to `process.cwd()`. */
  cwd?: string;
}

export interface GrantMintDeps {
  /** Defaults to `resolveKnotrustHome()`; injected in tests to a throwaway temp dir. */
  home?: string;
  /** Injected millisecond clock. Defaults to `Date.now`. */
  nowMs?: () => number;
  /** Injected epoch-seconds clock (mint's `iat`). Defaults to `Math.floor(nowMs() / 1000)`. */
  nowEpochSeconds?: () => number;
  generateId?: () => string;
  /** Injected confirmation gate. Defaults to the real `@clack/prompts` implementation. */
  confirm?: ConfirmFn;
}

/** `runInit`'s convention: returns the process exit code, never calls `process.exit`, never throws for a USER-facing failure it can name cleanly — but DOES propagate genuine construction failures (bad config, unusable keystore, audit lock contention) to the caller's top-level guard (R116), same as `resolveRunBundle` does on the enforcement path. */
export async function runGrantMint(
  io: GrantMintIo,
  args: GrantMintArgs,
  deps: GrantMintDeps = {},
): Promise<number> {
  const cwd = io.cwd ?? process.cwd();
  const home = deps.home ?? resolveKnotrustHome();
  const nowMs = deps.nowMs ?? Date.now;
  const nowEpochSeconds =
    deps.nowEpochSeconds ?? (() => Math.floor(nowMs() / 1000));
  const generateId = deps.generateId ?? createUlidGenerator(nowMs);
  const confirm = deps.confirm ?? confirmInteractively;

  const loaded = await loadKnotrustConfig({ cwd });
  const identity = loaded.config.identity;
  const envelopeScope = loaded.config.scope;

  // FOOTGUN (fix round 1, P0-E7-T2 review, FIX 4 — comment only, no
  // behavior change): a concrete `--agent <id>` is hardcoded here to
  // `type: "ai_agent"` — there is no flag to mint a grant for a `workload`-
  // or `user`-typed agent id. `verify.ts`'s `agentMatches` (packages/grants/
  // src/verify.ts:180) requires BOTH `id` AND `type` to match, so a grant
  // minted this way SILENTLY never matches a same-id request whose agent
  // type is `workload`/`user` — it just falls through to "no covering
  // grant", not a visible error. The `*` default (any agent) sidesteps this
  // entirely and is what today's MCP agents actually need, since every
  // agent this product currently sees on the wire is `ai_agent`-typed — but
  // the moment a non-`ai_agent` concrete `--agent` grant is wanted, this
  // hardcoding is the reason it won't work.
  const agent: MintDurableGrantInput["agent"] =
    args.agent === "*" ? "*" : { id: args.agent, type: "ai_agent" };

  const scope =
    args.resource !== undefined ? parseResourceScope(args.resource) : {};

  const inventory = loadToolInventory(home, args.server);
  const destructive = isKnownDestructive(inventory, args.tool);

  const iat = nowEpochSeconds();
  const expEpochSeconds = iat + args.ttlSeconds;

  // R116: the plain-words text is printed UNCONDITIONALLY — --yes only skips
  // the interactive y/n gate below, never the transparency itself.
  const confirmationText = buildGrantConfirmationText({
    tool: args.tool,
    server: args.server,
    agentPattern: args.agent,
    tierCap: args.tierCap,
    ttlSeconds: args.ttlSeconds,
    expEpochSeconds,
    scope,
    destructive,
  });
  io.stdout.write(`${confirmationText}\n`);

  if (!args.yes) {
    const proceed = await confirm(confirmationText);
    if (!proceed) {
      io.stdout.write("Cancelled — no grant minted.\n");
      return 0;
    }
  }

  const store = createGrantStore({
    home,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  const audit = createAuditLog({ home, nowEpochMs: nowMs });
  try {
    const keyStore = await createKeyStore({});
    const result = await mintDurableGrant(
      {
        principal: {
          type: identity?.subjectType ?? "user",
          id: identity?.subjectId ?? "local-user",
        },
        agent,
        tool: args.tool,
        scope,
        tier: args.tierCap,
        envelopeScope,
        ttlSeconds: args.ttlSeconds,
      },
      { store, keyStore, nowEpochSeconds: iat, generateId, audit },
    );
    io.stdout.write(
      `Minted durable grant ${result.jti} — expires ${formatAbsolute(expEpochSeconds)}.\n`,
    );
    return 0;
  } finally {
    // Releases the audit writer's exclusive lock (R38, single-writer-process
    // discipline) — load-bearing for sequential same-process CLI
    // invocations (mint -> list -> revoke, as the R115 e2e does): a lock
    // left held here would make the NEXT `createAuditLog()` in this process
    // throw.
    audit.close();
  }
}
