/**
 * @knotrust/proxy-stdio — tool-inventory.ts unit tests (P0-E5-T2; R63–R67).
 *
 * Covers the building blocks in isolation (hashing, snapshot building,
 * diff/drift, tier seeding, merge precedence, atomic persistence) — the
 * fuller proxy-integration acceptance scenarios (pagination through a real
 * proxy + fake server, drift-across-captures with a real audit sink) live in
 * `proxy.test.ts`.
 */

import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ToolTierEntry } from "@knotrust/core";
import { canonicalizeJcs } from "@knotrust/core";
import type { AuditEvent, AuditSink } from "@knotrust/store";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { JsonRpcMessage } from "./classifier.js";
import {
  buildToolInventorySnapshot,
  computeInputSchemaHash,
  createToolInventoryClassifier,
  diffToolInventory,
  emitToolDefinitionChangeEvent,
  loadToolInventory,
  mergeSeededTiers,
  saveToolInventory,
  seedTierEntriesFromAnnotations,
  type ToolDefinitionChange,
  type ToolInventory,
} from "./tool-inventory.js";

function tool(name: string, overrides: Partial<Tool> = {}): Tool {
  return {
    name,
    inputSchema: { type: "object", properties: {} },
    ...overrides,
  } as Tool;
}

// ---------------------------------------------------------------------------
// computeInputSchemaHash
// ---------------------------------------------------------------------------

describe("computeInputSchemaHash", () => {
  it("is deterministic for the same schema", () => {
    const schema = { type: "object", properties: { a: { type: "string" } } };
    expect(computeInputSchemaHash(schema)).toBe(computeInputSchemaHash(schema));
  });

  it("changes when the schema changes", () => {
    const a = computeInputSchemaHash({ type: "object", properties: {} });
    const b = computeInputSchemaHash({
      type: "object",
      properties: { x: { type: "number" } },
    });
    expect(a).not.toBe(b);
  });

  it("is key-order independent (matches canonicalizeJcs)", () => {
    const a = computeInputSchemaHash({
      type: "object",
      properties: { a: 1, b: 2 },
    });
    const b = computeInputSchemaHash({
      type: "object",
      properties: { b: 2, a: 1 },
    });
    expect(a).toBe(b);
  });

  it("is prefixed sha256: like computeArgsHash's own convention", () => {
    const hash = computeInputSchemaHash({ type: "object" });
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("never throws — returns 'unavailable' for a non-canonicalizable input", () => {
    const cyclic: Record<string, unknown> = { type: "object" };
    cyclic.self = cyclic;
    expect(computeInputSchemaHash(cyclic)).toBe("unavailable");
  });
});

// ---------------------------------------------------------------------------
// buildToolInventorySnapshot
// ---------------------------------------------------------------------------

describe("buildToolInventorySnapshot", () => {
  it("captures annotations (untrusted-shaped) + inputSchemaHash + inputSchema per tool", () => {
    const snapshot = buildToolInventorySnapshot(
      [
        tool("alpha", { annotations: { readOnlyHint: true } }),
        tool("beta", {
          annotations: { destructiveHint: true, openWorldHint: true },
        }),
      ],
      "2026-07-03T00:00:00.000Z",
    );

    expect(Object.keys(snapshot).sort()).toEqual(["alpha", "beta"]);
    expect(snapshot.alpha).toEqual({
      annotations: {
        trusted: false,
        source: "server_advertised",
        readOnlyHint: true,
        capturedAt: "2026-07-03T00:00:00.000Z",
      },
      inputSchemaHash: computeInputSchemaHash({
        type: "object",
        properties: {},
      }),
      inputSchema: { type: "object", properties: {} },
    });
    expect(snapshot.beta?.annotations).toEqual({
      trusted: false,
      source: "server_advertised",
      destructiveHint: true,
      openWorldHint: true,
      capturedAt: "2026-07-03T00:00:00.000Z",
    });
  });

  it("a tool with no annotations at all captures no hint fields (absent, not false)", () => {
    const snapshot = buildToolInventorySnapshot(
      [tool("plain")],
      "2026-01-01T00:00:00.000Z",
    );
    expect(snapshot.plain?.annotations).toEqual({
      trusted: false,
      source: "server_advertised",
      capturedAt: "2026-01-01T00:00:00.000Z",
    });
    expect(snapshot.plain?.annotations).not.toHaveProperty("readOnlyHint");
  });
});

// ---------------------------------------------------------------------------
// diffToolInventory
// ---------------------------------------------------------------------------

describe("diffToolInventory", () => {
  const CAPTURED_AT = "2026-07-03T00:00:00.000Z";

  it("reports NO changes when prior is undefined (first-ever capture)", () => {
    const next = buildToolInventorySnapshot(
      [tool("a"), tool("b")],
      CAPTURED_AT,
    );
    expect(diffToolInventory("srv", undefined, next)).toEqual([]);
  });

  it("reports no findings when nothing changed", () => {
    const inv = buildToolInventorySnapshot(
      [tool("a", { annotations: { readOnlyHint: true } })],
      CAPTURED_AT,
    );
    // A later capture at a different instant, but identical annotations/schema.
    const later = buildToolInventorySnapshot(
      [tool("a", { annotations: { readOnlyHint: true } })],
      "2026-07-04T00:00:00.000Z",
    );
    expect(diffToolInventory("srv", inv, later)).toEqual([]);
  });

  it("detects an annotation hint flip (destructiveHint) with old/new values", () => {
    const prior = buildToolInventorySnapshot(
      [
        tool("deploy", {
          annotations: { readOnlyHint: true, destructiveHint: false },
        }),
      ],
      CAPTURED_AT,
    );
    const next = buildToolInventorySnapshot(
      [
        tool("deploy", {
          annotations: { readOnlyHint: false, destructiveHint: true },
        }),
      ],
      "2026-07-04T00:00:00.000Z",
    );
    const changes = diffToolInventory("srv", prior, next);
    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({
      server: "srv",
      tool: "deploy",
      changeKind: "changed",
    });
    expect(changes[0]?.annotationChanges).toEqual(
      expect.arrayContaining([
        { field: "readOnlyHint", old: true, new: false },
        { field: "destructiveHint", old: false, new: true },
      ]),
    );
    expect(changes[0]?.schemaHashChanged).toBeUndefined();
  });

  it("detects an inputSchema change via schemaHashChanged, without leaking the raw schema", () => {
    const prior = buildToolInventorySnapshot(
      [
        tool("write_file", {
          inputSchema: { type: "object", properties: { path: {} } },
        }),
      ],
      CAPTURED_AT,
    );
    const next = buildToolInventorySnapshot(
      [
        tool("write_file", {
          inputSchema: {
            type: "object",
            properties: { path: {}, contents: {} },
          },
        }),
      ],
      "2026-07-04T00:00:00.000Z",
    );
    const changes = diffToolInventory("srv", prior, next);
    expect(changes).toEqual([
      {
        server: "srv",
        tool: "write_file",
        changeKind: "changed",
        schemaHashChanged: true,
      },
    ]);
  });

  it("detects a newly-added tool as changeKind 'added'", () => {
    const prior = buildToolInventorySnapshot([tool("a")], CAPTURED_AT);
    const next = buildToolInventorySnapshot(
      [tool("a"), tool("b")],
      CAPTURED_AT,
    );
    const changes = diffToolInventory("srv", prior, next);
    expect(changes).toEqual([
      { server: "srv", tool: "b", changeKind: "added" },
    ]);
  });

  it("detects a removed tool as changeKind 'removed'", () => {
    const prior = buildToolInventorySnapshot(
      [tool("a"), tool("b")],
      CAPTURED_AT,
    );
    const next = buildToolInventorySnapshot([tool("a")], CAPTURED_AT);
    const changes = diffToolInventory("srv", prior, next);
    expect(changes).toEqual([
      { server: "srv", tool: "b", changeKind: "removed" },
    ]);
  });
});

// ---------------------------------------------------------------------------
// emitToolDefinitionChangeEvent
// ---------------------------------------------------------------------------

function fakeAuditSink(): { sink: AuditSink; events: AuditEvent[] } {
  const events: AuditEvent[] = [];
  const sink: AuditSink = {
    append(event) {
      const full: AuditEvent = {
        seq: events.length + 1,
        ts: "2026-07-03T00:00:00.000Z",
        prevHash: "0".repeat(64),
        hash: "f".repeat(64),
        ...event,
      };
      events.push(full);
      return full;
    },
    flush() {},
    close() {},
    verify() {
      return { ok: true, events: events.length };
    },
    onAppend() {
      // no-op — no test in this file subscribes; @knotrust/otel's subscriber
      // contract is covered in that package's own suite, not here.
      return () => {};
    },
  };
  return { sink, events };
}

describe("emitToolDefinitionChangeEvent", () => {
  it("appends a tool_definition_changed event with server/changeKind/annotationChanges JSON-encoded in reason, no raw schema", () => {
    const { sink, events } = fakeAuditSink();
    const change: ToolDefinitionChange = {
      server: "github-mcp",
      tool: "deploy",
      changeKind: "changed",
      annotationChanges: [{ field: "destructiveHint", old: false, new: true }],
    };
    emitToolDefinitionChangeEvent(sink, change);

    expect(events).toHaveLength(1);
    const event = events[0];
    expect(event?.type).toBe("tool_definition_changed");
    expect(event?.tool).toBe("deploy");
    expect(event?.surface).toBe("stdio_proxy");
    const detail = JSON.parse(event?.reason ?? "{}");
    expect(detail).toEqual({
      server: "github-mcp",
      changeKind: "changed",
      annotationChanges: [{ field: "destructiveHint", old: false, new: true }],
    });
    expect(event?.reason ?? "").not.toContain("inputSchema");
  });

  it("marks schemaHashChanged without ever including a raw schema field", () => {
    const { sink, events } = fakeAuditSink();
    emitToolDefinitionChangeEvent(sink, {
      server: "srv",
      tool: "write_file",
      changeKind: "changed",
      schemaHashChanged: true,
    });
    const detail = JSON.parse(events[0]?.reason ?? "{}");
    expect(detail).toEqual({
      server: "srv",
      changeKind: "changed",
      schemaHashChanged: true,
    });
  });
});

// ---------------------------------------------------------------------------
// seedTierEntriesFromAnnotations (R65)
// ---------------------------------------------------------------------------

describe("seedTierEntriesFromAnnotations", () => {
  it("destructiveHint=true (not readOnly) -> sensitive", () => {
    const inv = buildToolInventorySnapshot(
      [tool("delete_repo", { annotations: { destructiveHint: true } })],
      "2026-07-03T00:00:00.000Z",
    );
    const seeded = seedTierEntriesFromAnnotations(inv);
    expect(seeded.delete_repo).toEqual({
      tier: "sensitive",
      source: "annotation",
    });
  });

  it("readOnlyHint=true (not destructive) -> routine", () => {
    const inv = buildToolInventorySnapshot(
      [tool("list_repos", { annotations: { readOnlyHint: true } })],
      "2026-07-03T00:00:00.000Z",
    );
    const seeded = seedTierEntriesFromAnnotations(inv);
    expect(seeded.list_repos).toEqual({
      tier: "routine",
      source: "annotation",
    });
  });

  it("neither hint (or only openWorldHint/idempotentHint) -> unknownToolTier default (sensitive)", () => {
    const inv = buildToolInventorySnapshot(
      [
        tool("mystery"),
        tool("open_world_only", { annotations: { openWorldHint: true } }),
      ],
      "2026-07-03T00:00:00.000Z",
    );
    const seeded = seedTierEntriesFromAnnotations(inv);
    expect(seeded.mystery).toEqual({ tier: "sensitive", source: "annotation" });
    expect(seeded.open_world_only).toEqual({
      tier: "sensitive",
      source: "annotation",
    });
  });

  it("respects a configured unknownToolTier of 'critical' for the ambiguous case", () => {
    const inv = buildToolInventorySnapshot(
      [tool("mystery")],
      "2026-07-03T00:00:00.000Z",
    );
    const seeded = seedTierEntriesFromAnnotations(inv, {
      unknownToolTier: "critical",
    });
    expect(seeded.mystery).toEqual({ tier: "critical", source: "annotation" });
  });

  it("annotation-lie (readOnlyHint AND destructiveHint both true) -> seeded sensitive, never routine", () => {
    const inv = buildToolInventorySnapshot(
      [
        tool("lying_tool", {
          annotations: { readOnlyHint: true, destructiveHint: true },
        }),
      ],
      "2026-07-03T00:00:00.000Z",
    );
    const seeded = seedTierEntriesFromAnnotations(inv);
    expect(seeded.lying_tool).toEqual({
      tier: "sensitive",
      source: "annotation",
    });
  });

  it("every seeded entry is marked source: 'annotation'", () => {
    const inv = buildToolInventorySnapshot(
      [tool("a", { annotations: { readOnlyHint: true } }), tool("b")],
      "2026-07-03T00:00:00.000Z",
    );
    const seeded = seedTierEntriesFromAnnotations(inv);
    for (const entry of Object.values(seeded)) {
      expect(entry.source).toBe("annotation");
    }
  });
});

// ---------------------------------------------------------------------------
// mergeSeededTiers (R65) — the explicit "never overrides pack/user" proof.
// ---------------------------------------------------------------------------

describe("mergeSeededTiers", () => {
  it("an annotation-seeded 'routine' suggestion NEVER overrides an existing pack/user 'critical' entry", () => {
    const existing: Record<string, ToolTierEntry> = {
      "stripe.create_refund": {
        tier: "critical",
        source: "user",
        explicitAllow: false,
      },
    };
    const seeded: Record<string, ToolTierEntry> = {
      "stripe.create_refund": { tier: "routine", source: "annotation" },
    };
    const merged = mergeSeededTiers(existing, seeded);
    expect(merged["stripe.create_refund"]).toEqual(
      existing["stripe.create_refund"],
    );
  });

  it("also never overrides a pack-sourced entry", () => {
    const existing: Record<string, ToolTierEntry> = {
      "github.delete_repo": { tier: "sensitive", source: "pack" },
    };
    const seeded: Record<string, ToolTierEntry> = {
      "github.delete_repo": { tier: "routine", source: "annotation" },
    };
    const merged = mergeSeededTiers(existing, seeded);
    expect(merged["github.delete_repo"]).toEqual(
      existing["github.delete_repo"],
    );
  });

  it("adds a seeded entry for a tool with no existing entry at all", () => {
    const merged = mergeSeededTiers(
      { "stripe.create_refund": { tier: "critical", source: "user" } },
      { "stripe.list_charges": { tier: "routine", source: "annotation" } },
    );
    expect(merged["stripe.list_charges"]).toEqual({
      tier: "routine",
      source: "annotation",
    });
    expect(merged["stripe.create_refund"]).toEqual({
      tier: "critical",
      source: "user",
    });
  });

  it("refreshes a STALE annotation-sourced entry (annotation never outranks annotation)", () => {
    const existing: Record<string, ToolTierEntry> = {
      "github.list_issues": { tier: "sensitive", source: "annotation" },
    };
    const seeded: Record<string, ToolTierEntry> = {
      "github.list_issues": { tier: "routine", source: "annotation" },
    };
    const merged = mergeSeededTiers(existing, seeded);
    expect(merged["github.list_issues"]).toEqual({
      tier: "routine",
      source: "annotation",
    });
  });

  it("handles an undefined existing config (fresh install) by taking every seed", () => {
    const merged = mergeSeededTiers(undefined, {
      "a.tool": { tier: "routine", source: "annotation" },
    });
    expect(merged).toEqual({
      "a.tool": { tier: "routine", source: "annotation" },
    });
  });

  it("never mutates the existing input object", () => {
    const existing: Record<string, ToolTierEntry> = {
      "a.tool": { tier: "critical", source: "user" },
    };
    const snapshot = canonicalizeJcs(existing);
    mergeSeededTiers(existing, {
      "b.tool": { tier: "routine", source: "annotation" },
    });
    expect(canonicalizeJcs(existing)).toBe(snapshot);
  });
});

// ---------------------------------------------------------------------------
// Persistence — atomic write, load/save round-trip (R64).
// ---------------------------------------------------------------------------

describe("saveToolInventory / loadToolInventory", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(path.join(tmpdir(), "knotrust-tool-inventory-test-"));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("round-trips exactly what was saved", () => {
    const inventory: ToolInventory = buildToolInventorySnapshot(
      [tool("a", { annotations: { readOnlyHint: true } })],
      "2026-07-03T00:00:00.000Z",
    );
    saveToolInventory(home, "my-server", inventory);
    const loaded = loadToolInventory(home, "my-server");
    expect(loaded).toEqual(inventory);
  });

  it("returns undefined when nothing has been saved yet for this server", () => {
    expect(loadToolInventory(home, "never-seen")).toBeUndefined();
  });

  it("returns undefined (never throws) for a corrupt/garbage inventory file", () => {
    const dir = path.join(home, "servers", "corrupt-server");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "tool-inventory.json"),
      "{ this is not valid json",
    );
    expect(loadToolInventory(home, "corrupt-server")).toBeUndefined();
  });

  it("writes the file under servers/<server>/tool-inventory.json (layout doc path)", () => {
    saveToolInventory(home, "github-mcp", {});
    expect(
      existsSync(
        path.join(home, "servers", "github-mcp", "tool-inventory.json"),
      ),
    ).toBe(true);
  });

  it("creates the server directory as 0700", () => {
    saveToolInventory(home, "perm-server", {});
    const stat = statSync(path.join(home, "servers", "perm-server"));
    expect(stat.mode & 0o777).toBe(0o700);
  });

  it("atomic write survives repeated saves: no torn/lingering .tmp files remain", () => {
    for (let i = 0; i < 20; i++) {
      const snapshot = buildToolInventorySnapshot(
        [tool(`tool-${i}`)],
        "2026-07-03T00:00:00.000Z",
      );
      saveToolInventory(home, "churn-server", snapshot);
    }
    const dir = path.join(home, "servers", "churn-server");
    const entries = readdirSync(dir);
    expect(entries).toEqual(["tool-inventory.json"]);
    expect(entries.some((name) => name.endsWith(".tmp"))).toBe(false);

    // The final file is valid, complete JSON — never a torn partial write.
    const raw = readFileSync(path.join(dir, "tool-inventory.json"), "utf8");
    expect(() => JSON.parse(raw)).not.toThrow();
    expect(JSON.parse(raw)).toHaveProperty("tool-19");
  });

  it("refuses an unsafe server name (path traversal)", () => {
    expect(() => saveToolInventory(home, "../escape", {})).toThrow(
      /unsafe server name/,
    );
    expect(() => loadToolInventory(home, "a/b")).toThrow(/unsafe server name/);
  });

  // -------------------------------------------------------------------------
  // C-1: dot-only server names ("." / "..") — path traversal to
  // $KNOTRUST_HOME itself. The character class alone (`[A-Za-z0-9._-]+`)
  // permits these since dots are otherwise legitimate (`"server.v2"`), so
  // they must be rejected explicitly. Critically, rejection must happen
  // BEFORE any mkdir/chmod/write touches the filesystem — a serverName of
  // ".." resolves `path.join(home, "servers", "..")` to `home` itself, so a
  // guard that runs too late would mkdir+chmod (0700) $KNOTRUST_HOME, or
  // write tool-inventory.json directly into it.
  // -------------------------------------------------------------------------

  it('rejects serverName "." and touches nothing outside servers/', () => {
    const modeBefore = statSync(home).mode & 0o777;
    expect(() => saveToolInventory(home, ".", {})).toThrow(
      /unsafe server name/,
    );
    expect(() => loadToolInventory(home, ".")).toThrow(/unsafe server name/);
    expect(existsSync(path.join(home, "tool-inventory.json"))).toBe(false);
    expect(existsSync(path.join(home, "servers", "."))).toBe(false);
    expect(statSync(home).mode & 0o777).toBe(modeBefore);
  });

  it('rejects serverName ".." (escapes servers/ to $KNOTRUST_HOME) and touches nothing outside servers/', () => {
    const modeBefore = statSync(home).mode & 0o777;
    expect(() => saveToolInventory(home, "..", {})).toThrow(
      /unsafe server name/,
    );
    expect(() => loadToolInventory(home, "..")).toThrow(/unsafe server name/);
    expect(existsSync(path.join(home, "tool-inventory.json"))).toBe(false);
    // Confirm $KNOTRUST_HOME was never (re-)chmod'd/mkdir'd by the guarded
    // call — its mode is exactly what it was before the attempted escape.
    expect(statSync(home).mode & 0o777).toBe(modeBefore);
  });

  it("still accepts legitimate dotted/mixed server names (github-mcp, server.v2, a_b-c.d)", () => {
    for (const name of ["github-mcp", "server.v2", "a_b-c.d"]) {
      const inventory: ToolInventory = buildToolInventorySnapshot(
        [tool("x")],
        "2026-07-03T00:00:00.000Z",
      );
      saveToolInventory(home, name, inventory);
      expect(loadToolInventory(home, name)).toEqual(inventory);
    }
  });
});

// ---------------------------------------------------------------------------
// createToolInventoryClassifier — C-2: audit flush ordering (tripwire
// durability). Drives the returned `ClassifierHook` directly with hand-built
// request/response messages (no full proxy/fake-server needed for this
// unit-level ordering assertion — see `proxy.test.ts` for the fuller
// integration-level drift scenario against a real audit sink).
// ---------------------------------------------------------------------------

describe("createToolInventoryClassifier — C-2 audit flush ordering", () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(
      path.join(tmpdir(), "knotrust-tool-inventory-flush-test-"),
    );
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it("flushes the injected audit sink BEFORE the new baseline overwrites the prior persisted one", () => {
    const serverName = "flush-order-server";
    const priorInventory = buildToolInventorySnapshot(
      [
        tool("deploy", {
          annotations: { readOnlyHint: true, destructiveHint: false },
        }),
      ],
      "2026-07-01T00:00:00.000Z",
    );
    saveToolInventory(home, serverName, priorInventory);

    let flushCallCount = 0;
    let flushObserved: ToolInventory | undefined;
    const sink: AuditSink = {
      append(event) {
        return {
          seq: 1,
          ts: "2026-07-03T00:00:00.000Z",
          prevHash: "0".repeat(64),
          hash: "f".repeat(64),
          ...event,
        };
      },
      flush() {
        flushCallCount += 1;
        // The load below reads whatever is on disk RIGHT NOW. If this
        // still reports the OLD (destructiveHint: false) baseline, flush()
        // ran before saveToolInventory overwrote it — exactly the ordering
        // C-2 requires (the rug-pull signal must be durable before the
        // baseline it's a diff against is gone).
        flushObserved = loadToolInventory(home, serverName);
      },
      close() {},
      verify() {
        return { ok: true, events: 0 };
      },
      onAppend() {
        return () => {};
      },
    };

    const hook = createToolInventoryClassifier({
      serverName,
      home,
      audit: sink,
      nowMs: () => Date.parse("2026-07-03T00:00:00.000Z"),
    });

    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {},
    } as JsonRpcMessage;
    hook(request, "client_to_server");

    const response = {
      jsonrpc: "2.0",
      id: 1,
      result: {
        tools: [
          tool("deploy", {
            annotations: { readOnlyHint: false, destructiveHint: true },
          }),
        ],
      },
    } as JsonRpcMessage;
    const classified = hook(response, "server_to_client");
    classified.observe?.(response);

    expect(flushCallCount).toBe(1);
    expect(flushObserved).toBeDefined();
    expect(flushObserved?.deploy?.annotations.destructiveHint).toBe(false);

    // After finalize() completes, the baseline HAS advanced to the new
    // capture — flush ran before the write, not instead of it.
    const finalInventory = loadToolInventory(home, serverName);
    expect(finalInventory?.deploy?.annotations.destructiveHint).toBe(true);
  });

  it("never calls flush() when no audit sink was supplied (documented seam — R66)", () => {
    const serverName = "no-audit-server";
    const hook = createToolInventoryClassifier({
      serverName,
      home,
      nowMs: () => Date.parse("2026-07-03T00:00:00.000Z"),
    });

    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {},
    } as JsonRpcMessage;
    hook(request, "client_to_server");
    const response = {
      jsonrpc: "2.0",
      id: 1,
      result: { tools: [tool("a")] },
    } as JsonRpcMessage;
    const classified = hook(response, "server_to_client");
    expect(() => classified.observe?.(response)).not.toThrow();
    expect(loadToolInventory(home, serverName)?.a).toBeDefined();
  });
});
