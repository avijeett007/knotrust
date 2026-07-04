/**
 * `knotrust add pack` — the headline precedence-integration proof (P0-E7-T3,
 * ruling R120).
 *
 * `pack-merge.test.ts` and `pack-command.test.ts` already prove the merge is
 * CONFIG-SHAPE correct (right `source`/`tier`, right diff lines). This file
 * is the one R120 explicitly asks for on top of that: after applying a pack
 * against a config with (a) an annotation-seeded entry for tool X and (b) a
 * user entry for tool Y, feed the MERGED config through `@knotrust/core`'s
 * REAL `evaluatePrecedence` engine (the same engine the proxy's enforcement
 * path runs every `tools/call` through, via `toTierPolicy`) and confirm:
 *
 *   - X's pack tier ACTUALLY takes effect at decision time (not just present
 *     in the config object) — proven by X producing a DIFFERENT outcome than
 *     its pre-apply annotation tier would have.
 *   - Y's user tier ACTUALLY still governs — proven by Y producing the SAME
 *     outcome its pre-apply user tier always produced, which would have
 *     changed had the pack's (different) suggested tier wrongly taken over.
 *
 * Re-apply is then proven idempotent one more time at this same integration
 * level: applying twice produces byte-identical config content, and the
 * SAME two decisions.
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import type { DecisionRequest } from "@knotrust/core";
import { evaluatePrecedence, L0ReasonCode } from "@knotrust/core";
import { loadKnotrustConfig, toTierPolicy } from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runAddPack } from "./pack-command.js";

let cwd: string;

beforeEach(() => {
  cwd = mkdtempSync(path.join(tmpdir(), "knotrust-add-precedence-cwd-"));
});

afterEach(() => {
  rmSync(cwd, { recursive: true, force: true });
});

function io(stdout?: PassThrough) {
  return {
    stdout: stdout ?? new PassThrough(),
    stderr: new PassThrough(),
    cwd,
  };
}

function makeRequest(actionName: string): DecisionRequest {
  return {
    contractVersion: "1.0",
    requestId: "01TESTPRECEDENCE0000000000",
    timestamp: "2026-07-03T00:00:00.000Z",
    subject: { type: "user", id: "avijeett007@gmail.com" },
    action: { name: actionName },
    resource: { type: "github_repo", id: "kno2gether/openclaw" },
    context: {
      agent: { id: "claude-desktop", type: "ai_agent" },
      env: { time: "2026-07-03T00:00:00Z", surfaceLocal: true },
    },
    surface: {
      kind: "stdio_proxy",
      instanceId: "px_test",
      server: "github-mcp",
    },
  };
}

const PACK_LINES = [
  "name: github-basics",
  "version: 1",
  "server: github-mcp",
  "tools:",
  // X: was annotation-seeded "routine" pre-apply; the pack raises it to
  // "critical". If the override did NOT take effect, this stays "routine"
  // and unconditionally allows (routine_default_allow) — a materially
  // different, and materially WORSE, outcome than the intended critical
  // gate.
  "  github.delete_repo:",
  "    tier: critical",
  // Y: is a "critical", source:user entry pre-apply with no explicitAllow.
  // The pack suggests "routine" for it. If the override WRONGLY took effect,
  // this becomes "routine" and unconditionally allows — exactly the
  // self-escalation-shaped bug R118/R120 exists to prevent.
  "  github.push:",
  "    tier: routine",
];

/**
 * Seeds the existing config as YAML, not JSON — deliberately (a discovered
 * platform gotcha, not a stylistic choice): `@knotrust/store`'s
 * `loadKnotrustConfig` resolves `.json`/`.ts` config files through c12's
 * `jiti.import()`, which caches by resolved file path using Node's own
 * module registry — invisible in real usage (`knotrust add pack` is a fresh
 * process per invocation) but STALE across repeated in-process
 * `loadKnotrustConfig` calls against the same evolving `.json` path within
 * one test run (exactly what this file's tests do: apply, reload to
 * inspect, apply again). `.yaml` is parsed via confbox's `parseYAML` over a
 * fresh `readFile` every call — no such cache — so it is the correct choice
 * for any test that reloads an evolving config more than once in-process
 * (see also `pack-command.test.ts`'s own idempotent-re-apply test, which
 * independently avoids this by writing through the skeleton/yaml path).
 */
function seedExistingConfig(): void {
  writeFileSync(
    path.join(cwd, "knotrust.config.yaml"),
    [
      "version: 1",
      "servers:",
      "  github-mcp:",
      "    tools:",
      "      github.delete_repo:",
      "        tier: routine",
      "        source: annotation",
      "      github.push:",
      "        tier: critical",
      "        source: user",
    ].join("\n"),
  );
}

describe("knotrust add pack — the R120 precedence-integration proof", () => {
  it("baseline (pre-apply): X allows unconditionally (routine), Y escalates to pending_approval (critical, no grant)", async () => {
    seedExistingConfig();
    const loaded = await loadKnotrustConfig({ cwd });
    const tierPolicy = toTierPolicy(loaded.config, "github-mcp");

    const xBefore = evaluatePrecedence({
      request: makeRequest("github.delete_repo"),
      tierPolicy,
      coveringGrants: [],
      nowEpochSeconds: 1_800_000_000,
    });
    expect(xBefore.outcome).toBe("allow");
    expect(xBefore.reasonCode).toBe(L0ReasonCode.RoutineDefaultAllow);

    const yBefore = evaluatePrecedence({
      request: makeRequest("github.push"),
      tierPolicy,
      coveringGrants: [],
      nowEpochSeconds: 1_800_000_000,
    });
    expect(yBefore.outcome).toBe("pending_approval");
    expect(yBefore.reasonCode).toBe(L0ReasonCode.NoGrantCritical);
  });

  it("after apply: X's pack tier TAKES EFFECT (now pending_approval, critical) while Y's user tier STILL GOVERNS (unchanged, still pending_approval/critical) — the headline precedence proof", async () => {
    seedExistingConfig();
    const filePath = path.join(cwd, "github.yaml");
    writeFileSync(filePath, PACK_LINES.join("\n"));

    const stdout = new PassThrough();
    let out = "";
    stdout.on("data", (c: Buffer) => {
      out += c.toString("utf8");
    });

    const code = await runAddPack(io(stdout), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(code).toBe(0);
    // The diff explains BOTH halves of the precedence story (R119).
    expect(out).toContain(
      "CHANGE: github.delete_repo routine → critical (pack)",
    );
    expect(out).toContain(
      "KEPT: github.push → your user setting critical (pack suggested routine)",
    );

    const loaded = await loadKnotrustConfig({ cwd });
    // Config-shape check.
    expect(
      loaded.config.servers?.["github-mcp"]?.tools?.["github.delete_repo"],
    ).toEqual({ tier: "critical", source: "pack" });
    expect(
      loaded.config.servers?.["github-mcp"]?.tools?.["github.push"],
    ).toEqual({ tier: "critical", source: "user" });

    const tierPolicy = toTierPolicy(loaded.config, "github-mcp");

    // X: the pack's "critical" tier ACTUALLY governs the decision now —
    // pending_approval (no_grant_critical), NOT the pre-apply
    // routine_default_allow. This is the "integration proof, not just
    // config-shape" R120 asks for: the override is provably live at the
    // decision engine, not merely present in the serialized config.
    const xAfter = evaluatePrecedence({
      request: makeRequest("github.delete_repo"),
      tierPolicy,
      coveringGrants: [],
      nowEpochSeconds: 1_800_000_000,
    });
    expect(xAfter.outcome).toBe("pending_approval");
    expect(xAfter.reasonCode).toBe(L0ReasonCode.NoGrantCritical);
    expect(xAfter.tier).toBe("critical");

    // Y: the pack's "routine" suggestion NEVER governs — the user's
    // "critical" tier still decides, producing the IDENTICAL outcome as the
    // pre-apply baseline. Had the (buggy) alternative "pack overrides
    // everything" behavior shipped instead, this would have flipped to
    // outcome "allow" / reasonCode "routine_default_allow" — a silent
    // self-escalation of exactly the kind R118 forbids.
    const yAfter = evaluatePrecedence({
      request: makeRequest("github.push"),
      tierPolicy,
      coveringGrants: [],
      nowEpochSeconds: 1_800_000_000,
    });
    expect(yAfter.outcome).toBe("pending_approval");
    expect(yAfter.reasonCode).toBe(L0ReasonCode.NoGrantCritical);
    expect(yAfter.tier).toBe("critical");
  });

  it("re-apply is idempotent at the integration level too: identical config bytes, identical decisions", async () => {
    seedExistingConfig();
    const filePath = path.join(cwd, "github.yaml");
    writeFileSync(filePath, PACK_LINES.join("\n"));

    const first = await runAddPack(io(), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(first).toBe(0);
    const afterFirst = readFileSync(
      path.join(cwd, "knotrust.config.yaml"),
      "utf8",
    );

    const stdout = new PassThrough();
    let out = "";
    stdout.on("data", (c: Buffer) => {
      out += c.toString("utf8");
    });
    const second = await runAddPack(io(stdout), {
      path: filePath,
      yes: true,
      dryRun: false,
    });
    expect(second).toBe(0);
    expect(out).not.toContain("CHANGE:");
    expect(out).not.toContain("NEW:");

    const afterSecond = readFileSync(
      path.join(cwd, "knotrust.config.yaml"),
      "utf8",
    );
    expect(afterSecond).toBe(afterFirst);

    const loaded = await loadKnotrustConfig({ cwd });
    const tierPolicy = toTierPolicy(loaded.config, "github-mcp");
    const x = evaluatePrecedence({
      request: makeRequest("github.delete_repo"),
      tierPolicy,
      coveringGrants: [],
      nowEpochSeconds: 1_800_000_000,
    });
    const y = evaluatePrecedence({
      request: makeRequest("github.push"),
      tierPolicy,
      coveringGrants: [],
      nowEpochSeconds: 1_800_000_000,
    });
    expect(x.outcome).toBe("pending_approval");
    expect(y.outcome).toBe("pending_approval");
    expect(y.tier).toBe("critical");
  });
});
