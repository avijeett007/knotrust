/**
 * Interactive server selection — wiring smoke tests (P0-E7-T1, R107/R110).
 *
 * `selectServersInteractively` drives a REAL `@clack/prompts` TTY prompt —
 * per this module's own header, it is deliberately never invoked from an
 * automated test (there is no real terminal to answer it, and doing so would
 * hang a CI run). Every command-level test instead injects a fake
 * `SelectServers` (see `command.test.ts`) or bypasses selection entirely via
 * `--yes`/`--server`. This file only proves the exported shape is what
 * `command.ts` expects.
 */

import { describe, expect, it } from "vitest";
import {
  ServerSelectionCancelledError,
  selectServersInteractively,
} from "./select-servers.js";

describe("select-servers exports", () => {
  it("exports a callable selectServersInteractively", () => {
    expect(typeof selectServersInteractively).toBe("function");
  });

  it("ServerSelectionCancelledError carries a clear, no-write message", () => {
    const error = new ServerSelectionCancelledError();
    expect(error.name).toBe("ServerSelectionCancelledError");
    expect(error.message).toContain("no changes written");
  });
});
