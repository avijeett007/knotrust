#!/usr/bin/env node
/**
 * knotrust CLI entry point (P0-E5-T1, ruling R61).
 *
 * `knotrust -- <server command>` spawns the real MCP server as a child and runs
 * the transparent stdio proxy end-to-end (the FLAGSHIP surface). Invocations
 * without `--` are subcommands, which arrive in P0-E7 and currently error.
 *
 * This file is deliberately thin: all logic lives in `run.ts`'s `runCli`, which
 * is unit-testable with injected streams. Here we only bind it to the real
 * process stdio and translate its return value into the process exit code.
 *
 * `@knotrust/proxy-stdio` (and its transitive `@knotrust/*` graph) is inlined
 * into this bundle at publish time (tsup `noExternal`, ADR-0016); only
 * `@modelcontextprotocol/sdk` stays an external runtime dependency (ADR-0019).
 *
 * The try/catch below is a second, outermost copy of `run.ts`'s own top-level
 * guard (fix round 1, P0-E7-T1 review) — `runCli` should never actually reject
 * given its own catch, but this is the literal last line of defense before
 * whatever `runCli` returns/throws reaches a real user's terminal: NO command
 * this CLI ships may ever print a raw Node stack trace here, only a clean
 * `knotrust: <message>` and a non-zero exit.
 */

import process from "node:process";
import { runCli } from "./run.js";

try {
  const code = await runCli(process.argv.slice(2), {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
  });
  process.exit(code);
} catch (error) {
  process.stderr.write(
    `knotrust: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
}
