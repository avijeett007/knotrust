/**
 * Best-effort `tools/list` capture tests (P0-E7-T1, R109).
 *
 * Success path spawns the REAL `@knotrust/test-harness` fake MCP server as a
 * child process (never a real user's server) — same substrate the CLI's
 * other end-to-end tests already use. Failure/timeout paths use commands
 * that are guaranteed not to speak MCP.
 */

import type { FakeServerConfig } from "@knotrust/test-harness";
import { startFakeServer } from "@knotrust/test-harness";
import { describe, expect, it } from "vitest";
import { captureToolInventory } from "./tool-capture.js";

describe("captureToolInventory (R109 — best-effort)", () => {
  it("captures a real server's tool inventory, including annotations", async () => {
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-init-capture", version: "1.0.0" },
      tools: [
        {
          name: "read_file",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true },
        },
        {
          name: "delete_file",
          inputSchema: { type: "object", properties: {} },
          annotations: { destructiveHint: true },
        },
      ],
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    try {
      const inventory = await captureToolInventory(childCommand, {
        timeoutMs: 5_000,
      });
      expect(inventory).toBeDefined();
      const names = Object.keys(inventory ?? {}).sort();
      expect(names).toEqual(["delete_file", "read_file"]);
      expect(inventory?.read_file?.annotations.readOnlyHint).toBe(true);
      expect(inventory?.delete_file?.annotations.destructiveHint).toBe(true);
    } finally {
      await started.close();
    }
  }, 15_000);

  it("pages through a multi-page tools/list listing", async () => {
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-init-paginated", version: "1.0.0" },
      tools: [
        { name: "a", inputSchema: { type: "object", properties: {} } },
        { name: "b", inputSchema: { type: "object", properties: {} } },
        { name: "c", inputSchema: { type: "object", properties: {} } },
      ],
      pagination: { pageSize: 1 },
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    try {
      const inventory = await captureToolInventory(childCommand, {
        timeoutMs: 5_000,
      });
      expect(Object.keys(inventory ?? {}).sort()).toEqual(["a", "b", "c"]);
    } finally {
      await started.close();
    }
  }, 15_000);

  it("returns undefined (never throws) when the command doesn't exist", async () => {
    const inventory = await captureToolInventory(
      ["knotrust-init-definitely-does-not-exist-binary"],
      { timeoutMs: 2_000 },
    );
    expect(inventory).toBeUndefined();
  }, 10_000);

  it("returns undefined on timeout against a process that never speaks MCP", async () => {
    const inventory = await captureToolInventory(["sleep", "5"], {
      timeoutMs: 300,
    });
    expect(inventory).toBeUndefined();
  }, 10_000);

  it("returns undefined for an empty server command", async () => {
    const inventory = await captureToolInventory([]);
    expect(inventory).toBeUndefined();
  });
});
