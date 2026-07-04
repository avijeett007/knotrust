/**
 * knotrust CLI — BUILT-BUNDLE startup & end-to-end guard (P0-E5-T5, ADR-0016).
 *
 * Every other CLI test runs `runCli` IN-PROCESS via vitest and never executes
 * the shipped tsup bundle. That blind spot let a P0 ship: the ESM bundle
 * inlined `c12` (config loader, wired at E5-T3) whose transitive deps
 * (`dotenv`/`jiti`/…) do CJS `require("fs")`, which esbuild's ESM output cannot
 * satisfy — so `node dist/bin.js` crashed at import time with `Error: Dynamic
 * require of "fs" is not supported` while the entire vitest suite stayed green.
 *
 * This test closes that gap by building the REAL bundle (current source, same
 * `tsup.config.ts` → same externals as production) and exercising it as a child
 * process:
 *   1. `node <bin> --help` reaches argv handling with NO dynamic-require crash.
 *   2. A full `initialize → tools/list → tools/call → EOF` conversation runs
 *      end-to-end THROUGH the built binary against the real fake MCP server,
 *      exits 0, and leaves no orphan child.
 *
 * The durable lesson: "tests green" must include "the bundled binary starts".
 *
 * Build isolation: we build into a throwaway dir UNDER `node_modules` (a) so
 * git never sees it and (b) so ESM external resolution still walks up to
 * `packages/cli/node_modules` and finds `c12`/`@modelcontextprotocol/sdk` at
 * runtime — while NOT racing with turbo's concurrent `build#cli`, which cleans
 * only the real `dist/`. CI runs this under `turbo build test`; the beforeAll
 * build makes the test self-sufficient even when run standalone
 * (`vitest run --project cli`) with no prior build.
 */

import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  AuditEventType,
  computeArgsHash,
  createAuditLog,
} from "@knotrust/store";
import {
  FakeClient,
  type FakeServerConfig,
  startFakeServer,
} from "@knotrust/test-harness";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
// `..` from src/ (test source) OR dist/ (compiled) both land on the package dir.
const pkgDir = path.resolve(here, "..");
const tsupBin = path.join(pkgDir, "node_modules", ".bin", "tsup");

let outDir: string;
let builtBin: string;

beforeAll(() => {
  // Isolated build dir under node_modules (gitignored; externals still resolve).
  outDir = mkdtempSync(path.join(pkgDir, "node_modules", ".e2e-bin-"));
  execFileSync(tsupBin, ["--out-dir", outDir], { cwd: pkgDir, stdio: "pipe" });
  builtBin = path.join(outDir, "bin.js");
}, 60_000);

afterAll(() => {
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

describe("knotrust built bundle — the shipped binary starts (ADR-0016)", () => {
  it("`node dist/bin.js --help` reaches argv handling with no dynamic-require crash", () => {
    const result = spawnSync(process.execPath, [builtBin, "--help"], {
      encoding: "utf8",
    });
    const combined = `${result.stdout}${result.stderr}`;

    // The exact P0 regression: a `require("fs")` inlined from c12's subtree
    // would throw at import time, before argv is ever parsed.
    expect(combined).not.toMatch(/Dynamic require/i);

    // `--help` is an as-yet-unimplemented subcommand (real ones land in P0-E7),
    // so the runner prints usage and exits 2 — the point is it REACHED that
    // code path (module loaded, runCli ran) instead of crashing at import
    // (which would be exit 1 with a Node stack trace, not this usage message).
    expect(result.status).toBe(2);
    expect(combined).toContain("usage: knotrust -- <server command>");
  });

  // ---------------------------------------------------------------------
  // P0-E7-T1 — `knotrust init` from the BUILT bundle (R110). `@clack/prompts`
  // is a new bundled runtime dependency this task adds (inlined — see
  // `tsup.config.ts`'s header note); this is the regression that would catch
  // it ever silently regressing to an external, unresolvable-by-a-real-
  // consumer import. `--yes` keeps this non-interactive (no real TTY prompt
  // reachable from a spawned child process anyway).
  // ---------------------------------------------------------------------

  it("`node dist/bin.js init claude --dry-run` works from the bundle: prints a diff, writes nothing", () => {
    const projectDir = mkdtempSync(
      path.join(pkgDir, "node_modules", ".e2e-init-dryrun-"),
    );
    const mcpJsonPath = path.join(projectDir, ".mcp.json");
    const before = `${JSON.stringify(
      { mcpServers: { echo: { command: "node", args: ["echo.js"] } } },
      null,
      2,
    )}\n`;
    writeFileSync(mcpJsonPath, before);
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-init-bin-home-"));

    try {
      const result = spawnSync(
        process.execPath,
        [builtBin, "init", "claude", "--yes", "--dry-run"],
        {
          encoding: "utf8",
          cwd: projectDir,
          env: { ...process.env, KNOTRUST_HOME: home },
        },
      );
      const combined = `${result.stdout}${result.stderr}`;
      expect(combined).not.toMatch(/Dynamic require/i);
      expect(result.status).toBe(0);
      expect(combined).toContain("claude-code config");
      expect(combined).toContain("dry run — no changes written");
      expect(readFileSync(mcpJsonPath, "utf8")).toBe(before);
    } finally {
      rmSync(projectDir, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    }
  });

  it("`node dist/bin.js init claude --yes` wraps a real server end-to-end from the bundle, seeding a knotrust.config.yaml", () => {
    const projectDir = mkdtempSync(
      path.join(pkgDir, "node_modules", ".e2e-init-wrap-"),
    );
    const mcpJsonPath = path.join(projectDir, ".mcp.json");
    writeFileSync(
      mcpJsonPath,
      `${JSON.stringify(
        { mcpServers: { echo: { command: "node", args: ["echo.js"] } } },
        null,
        2,
      )}\n`,
    );
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-init-bin-home2-"));

    try {
      const result = spawnSync(
        process.execPath,
        [builtBin, "init", "claude", "--yes"],
        {
          encoding: "utf8",
          cwd: projectDir,
          env: { ...process.env, KNOTRUST_HOME: home },
          timeout: 15_000,
        },
      );
      const combined = `${result.stdout}${result.stderr}`;
      expect(combined).not.toMatch(/Dynamic require/i);
      expect(result.status).toBe(0);
      const rewritten = JSON.parse(readFileSync(mcpJsonPath, "utf8")) as {
        mcpServers: Record<string, { command: string; args: string[] }>;
      };
      expect(rewritten.mcpServers.echo).toEqual({
        command: "knotrust",
        args: ["--", "node", "echo.js"],
      });
      // Best-effort capture against a nonexistent `echo.js` fails cleanly —
      // the skeleton path still writes a config with the documented default.
      const generatedConfig = readFileSync(
        path.join(projectDir, "knotrust.config.yaml"),
        "utf8",
      );
      expect(generatedConfig).toContain('"unknownToolTier": "sensitive"');
    } finally {
      rmSync(projectDir, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    }
  }, 20_000);

  // ---------------------------------------------------------------------
  // P0-E7-T3 — `knotrust add pack` from the BUILT bundle (R117-R121). `zod`
  // is a new bundled runtime dependency this task adds (`add/pack-
  // schema.ts`'s pack validation — see `tsup.config.ts`'s header note); this
  // is the regression that would catch it ever silently regressing to an
  // external, unresolvable-by-a-real-consumer import, mirroring the
  // existing `@clack/prompts` regression above.
  // ---------------------------------------------------------------------

  it("`node dist/bin.js add pack <path> --dry-run` works from the bundle: prints the tier diff, writes nothing", () => {
    const projectDir = mkdtempSync(
      path.join(pkgDir, "node_modules", ".e2e-add-dryrun-"),
    );
    const packPath = path.join(projectDir, "github.yaml");
    writeFileSync(
      packPath,
      [
        "name: github-basics",
        "version: 1",
        "server: github-mcp",
        "tools:",
        "  github.delete_repo:",
        "    tier: critical",
      ].join("\n"),
    );

    try {
      const result = spawnSync(
        process.execPath,
        [builtBin, "add", "pack", packPath, "--yes", "--dry-run"],
        { encoding: "utf8", cwd: projectDir },
      );
      const combined = `${result.stdout}${result.stderr}`;
      expect(combined).not.toMatch(/Dynamic require/i);
      expect(result.status).toBe(0);
      expect(combined).toContain(
        "NEW: github.delete_repo → critical (from pack)",
      );
      expect(combined).toContain("dry run — no changes written");
      expect(existsSync(path.join(projectDir, "knotrust.config.yaml"))).toBe(
        false,
      );
    } finally {
      rmSync(projectDir, { recursive: true, force: true });
    }
  });

  it("`node dist/bin.js add pack <path> --yes` applies from the bundle, stamping source: pack", () => {
    const projectDir = mkdtempSync(
      path.join(pkgDir, "node_modules", ".e2e-add-apply-"),
    );
    const packPath = path.join(projectDir, "github.yaml");
    writeFileSync(
      packPath,
      [
        "name: github-basics",
        "version: 1",
        "server: github-mcp",
        "tools:",
        "  github.delete_repo:",
        "    tier: critical",
      ].join("\n"),
    );

    try {
      const result = spawnSync(
        process.execPath,
        [builtBin, "add", "pack", packPath, "--yes"],
        { encoding: "utf8", cwd: projectDir },
      );
      const combined = `${result.stdout}${result.stderr}`;
      expect(combined).not.toMatch(/Dynamic require/i);
      expect(result.status).toBe(0);
      const generatedConfig = readFileSync(
        path.join(projectDir, "knotrust.config.yaml"),
        "utf8",
      );
      expect(generatedConfig).toContain('"github.delete_repo"');
      expect(generatedConfig).toContain('"tier": "critical"');
      expect(generatedConfig).toContain('"source": "pack"');
    } finally {
      rmSync(projectDir, { recursive: true, force: true });
    }
  });

  it("proxies initialize→tools/list→tools/call end-to-end through the built binary, then exits 0 with no orphan", async () => {
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-built-bin", version: "1.0.0" },
      tools: [
        { name: "echo", inputSchema: { type: "object", properties: {} } },
      ],
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");
    // Unique marker (the fake server's temp config path) to detect orphans.
    const configMarker = childCommand[childCommand.length - 1] ?? "";

    // Zero-config run: point KNOTRUST_HOME at a throwaway dir so the real
    // ~/.knotrust is never touched by the audit sink.
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-built-bin-home-"));

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [builtBin, "--", ...childCommand],
      env: { ...process.env, KNOTRUST_HOME: home },
      stderr: "pipe",
    });
    let proxyStderr = "";
    const client = new FakeClient(transport);

    try {
      const init = (await client.connect()) as {
        serverInfo?: { name?: string };
      };
      transport.stderr?.on("data", (c: Buffer) => {
        proxyStderr += c.toString("utf8");
      });
      expect(init.serverInfo?.name).toBe("knotrust-fake-built-bin");

      const listed = await client.listAllTools();
      expect(listed.tools.map((t) => t.name)).toEqual(["echo"]);

      const call = await client.callTool("echo", { ping: "pong" });
      expect(call.content).toEqual([
        { type: "text", text: JSON.stringify({ ping: "pong" }) },
      ]);

      // Client EOF → proxy graceful child shutdown → clean exit.
      await client.close();
    } finally {
      await started.close();
      rmSync(home, { recursive: true, force: true });
    }

    // No dynamic-require crash leaked onto the proxy's own stderr.
    expect(proxyStderr).not.toMatch(/Dynamic require/i);

    // No orphaned fake-server child left behind after the graceful shutdown.
    const ps = spawnSync("ps", ["-eo", "pid,command"], { encoding: "utf8" });
    const orphans = (ps.stdout ?? "")
      .split("\n")
      .filter((line) => configMarker !== "" && line.includes(configMarker));
    expect(orphans).toEqual([]);
  }, 30_000);

  // ---------------------------------------------------------------------
  // P0-E6-T3 — the localhost approval page's embedded HTML/CSS string
  // assets survive tsup bundling (R100): no separate asset file exists for
  // the bundler to lose, or for the published tarball to omit, so the
  // rendered page must work identically when served from the COMPILED
  // `dist/bin.js` as it does from source. This is the built-binary
  // self-containment check the task brief asks for, mirrored on E5-T5's own
  // "tests green must include the bundled binary starts" lesson: a real
  // HTTP GET+POST against the page a REAL child process (running the built
  // bundle) is serving, releasing a REAL held `tools/call` end-to-end.
  // ---------------------------------------------------------------------

  interface RawResponse {
    status: number;
    body: string;
  }

  function rawHttpRequest(options: {
    port: number;
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: string;
  }): Promise<RawResponse> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: options.port,
          method: options.method,
          path: options.path,
          headers: options.headers,
        },
        (res) => {
          let body = "";
          res.on("data", (chunk: Buffer) => {
            body += chunk.toString("utf8");
          });
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
        },
      );
      req.on("error", reject);
      if (options.body !== undefined) req.write(options.body);
      req.end();
    });
  }

  function extractCsrf(html: string): string {
    const m = /name="csrf" value="([^"]*)"/.exec(html);
    if (m?.[1] === undefined)
      throw new Error("csrf token not found in rendered page");
    return m[1];
  }

  /** Polls the accumulating stderr text for the fixed-template prompt's `approve: <url>` line (block-and-wait.ts's `renderApprovalPrompt`). */
  async function waitForApprovalUrl(getStderr: () => string): Promise<string> {
    const deadline = Date.now() + 10_000;
    for (;;) {
      const match = /approve:\s+(\S+)/.exec(getStderr());
      if (match?.[1] !== undefined) return match[1];
      if (Date.now() > deadline) {
        throw new Error(
          `timed out waiting for the approval URL in stderr; got:\n${getStderr()}`,
        );
      }
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  it("P0-E6-T3: the localhost approval page survives tsup bundling — a real HTTP approve through the BUILT binary releases a held critical-tool call", async () => {
    const configDir = mkdtempSync(
      path.join(pkgDir, "node_modules", ".e2e-page-cfg-"),
    );
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-page-bin-home-"));
    writeFileSync(
      path.join(configDir, "knotrust.config.json"),
      JSON.stringify({
        version: 1,
        identity: { subjectId: "avijeett007@gmail.com", subjectType: "user" },
        servers: {
          testsrv: {
            tools: { critical_tool: { tier: "critical", source: "user" } },
          },
        },
      }),
    );

    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-page-bin", version: "1.0.0" },
      tools: [
        {
          name: "critical_tool",
          inputSchema: { type: "object", properties: {} },
        },
      ],
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [builtBin, "--", ...childCommand],
      env: {
        ...process.env,
        KNOTRUST_HOME: home,
        // Never touch the developer's real OS keychain from a test (same
        // discipline as `run.enforce.test.ts`'s block-and-wait suite).
        KNOTRUST_KEY_BACKEND: "file",
      },
      cwd: configDir,
      stderr: "pipe",
    });
    let proxyStderr = "";
    const client = new FakeClient(transport);

    try {
      await client.connect();
      transport.stderr?.on("data", (c: Buffer) => {
        proxyStderr += c.toString("utf8");
      });

      const callPromise = client.callTool("critical_tool", { amount: 777 });

      const url = await waitForApprovalUrl(() => proxyStderr);
      const parsed = new URL(url);
      const port = Number(parsed.port);

      // GET renders the page — proving the embedded HTML/CSS string assets
      // (html.ts) are present and correct in the COMPILED bundle, not just
      // in source: no separate asset file exists for tsup to have dropped.
      const rendered = await rawHttpRequest({
        port,
        method: "GET",
        path: `${parsed.pathname}${parsed.search}`,
      });
      expect(rendered.status).toBe(200);
      expect(rendered.body).toContain("critical_tool");
      const csrf = extractCsrf(rendered.body);

      const params = new URLSearchParams(parsed.search);
      const id = params.get("id");
      const token = params.get("token");
      if (id === null || token === null) {
        throw new Error("missing id/token in the approval URL");
      }

      const body = new URLSearchParams({
        id,
        token,
        csrf,
        action: "approve",
      }).toString();
      const postRes = await rawHttpRequest({
        port,
        method: "POST",
        path: "/approve/action",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": String(Buffer.byteLength(body)),
          Origin: `http://127.0.0.1:${port}`,
        },
        body,
      });
      expect(postRes.status).toBe(200);

      // The held `tools/call` — genuinely blocked on the REAL block-and-wait
      // channel inside the built binary — is now released as an ALLOW.
      const result = await callPromise;
      expect(result.isError).toBeFalsy();

      await client.close();
    } finally {
      await started.close();
      rmSync(configDir, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
    }
  }, 30_000);

  // ---------------------------------------------------------------------
  // P0-E4-T4 — `knotrust audit list|tail|query|verify` from the BUILT
  // bundle: this surface adds no new runtime dependency (no bundling risk
  // like `@clack/prompts`/`zod` above), but every other subcommand gets a
  // built-binary smoke test, and this is the regression that would catch
  // the audit dispatch wiring itself ever silently breaking in the bundled
  // output.
  // ---------------------------------------------------------------------

  it("`node dist/bin.js audit list|query|verify` all work from the bundle against a real seeded log", () => {
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-audit-bin-home-"));
    try {
      const sink = createAuditLog({ home, nowEpochMs: () => Date.now() });
      sink.append({
        type: AuditEventType.DECISION,
        surface: "mcp-stdio",
        subject: "user:local",
        agent: "claude-desktop",
        tool: "github.create_issue",
        argsHash: computeArgsHash(null),
        outcome: "allow",
      });
      sink.append({
        type: AuditEventType.DECISION,
        surface: "mcp-stdio",
        subject: "user:local",
        agent: "claude-desktop",
        tool: "stripe.create_refund",
        argsHash: computeArgsHash(null),
        outcome: "deny",
        reason: "no_grant_sensitive",
      });
      sink.close();

      const env = { ...process.env, KNOTRUST_HOME: home };

      const listResult = spawnSync(
        process.execPath,
        [builtBin, "audit", "list"],
        {
          encoding: "utf8",
          env,
        },
      );
      expect(listResult.status).toBe(0);
      expect(listResult.stdout).toContain("tool=github.create_issue");
      expect(listResult.stdout).toContain("tool=stripe.create_refund");

      const queryResult = spawnSync(
        process.execPath,
        [builtBin, "audit", "query", "--outcome", "deny", "--json"],
        { encoding: "utf8", env },
      );
      expect(queryResult.status).toBe(0);
      const rows = queryResult.stdout
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l) as { tool: string });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.tool).toBe("stripe.create_refund");

      const verifyResult = spawnSync(
        process.execPath,
        [builtBin, "audit", "verify"],
        { encoding: "utf8", env },
      );
      expect(verifyResult.status).toBe(0);
      expect(verifyResult.stdout).toContain("chain intact (2 events)");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  // ---------------------------------------------------------------------
  // P0-E8-T1 — the OTel exporter survives tsup's `external` treatment
  // (R127/R128, tsup.config.ts's own header): four NEW bundled-but-external
  // runtime dependencies (`@opentelemetry/*`) resolved from the CLI's real
  // `dependencies` by the consumer's package manager, never inlined
  // (inlining was empirically proven to crash the binary — see that file's
  // comment). This is the "the shipped binary can actually resolve and use
  // them" regression: a real `tools/call` through the BUILT bundle, with
  // `telemetryExport` pointed at a local collector fixture, must produce a
  // real exported span — not just work when run in-process via vitest
  // (`enforcement.otel.test.ts`), which never executes the shipped bundle.
  // ---------------------------------------------------------------------

  interface OtlpSpanAttr {
    key: string;
    value: { stringValue?: string };
  }
  interface OtlpSpan {
    name: string;
    attributes?: OtlpSpanAttr[];
  }
  interface OtlpBody {
    resourceSpans?: Array<{ scopeSpans?: Array<{ spans?: OtlpSpan[] }> }>;
  }

  function startCollectorFixture(): Promise<{
    port: number;
    bodies: unknown[];
    close(): Promise<void>;
  }> {
    return new Promise((resolve, reject) => {
      const bodies: unknown[] = [];
      const server = http.createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          try {
            bodies.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            bodies.push(undefined);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end("{}");
        });
      });
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (address === null || typeof address === "string") {
          reject(new Error("collector fixture: failed to bind"));
          return;
        }
        resolve({
          port: address.port,
          bodies,
          close: () =>
            new Promise((res, rej) => {
              server.close((err) => (err ? rej(err) : res()));
            }),
        });
      });
    });
  }

  function flattenSpans(bodies: unknown[]): OtlpSpan[] {
    const spans: OtlpSpan[] = [];
    for (const body of bodies) {
      for (const rs of (body as OtlpBody)?.resourceSpans ?? []) {
        for (const ss of rs.scopeSpans ?? []) {
          for (const s of ss.spans ?? []) spans.push(s);
        }
      }
    }
    return spans;
  }

  function spanAttr(span: OtlpSpan, key: string): string | undefined {
    return span.attributes?.find((a) => a.key === key)?.value.stringValue;
  }

  it("a real tools/call through the BUILT binary, with telemetryExport enabled, exports one real span to a local OTLP collector fixture", async () => {
    const fixture = await startCollectorFixture();
    const configDir = mkdtempSync(
      path.join(pkgDir, "node_modules", ".e2e-otel-cfg-"),
    );
    const home = mkdtempSync(path.join(tmpdir(), "knotrust-otel-bin-home-"));
    writeFileSync(
      path.join(configDir, "knotrust.config.json"),
      JSON.stringify({
        version: 1,
        servers: {
          testsrv: { tools: { echo: { tier: "routine", source: "user" } } },
        },
        telemetryExport: {
          enabled: true,
          endpoint: `http://127.0.0.1:${fixture.port}/v1/traces`,
          serviceName: "knotrust-built-bin-otel-test",
        },
      }),
    );

    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-fake-otel-bin", version: "1.0.0" },
      tools: [
        { name: "echo", inputSchema: { type: "object", properties: {} } },
      ],
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [builtBin, "--", ...childCommand],
      env: { ...process.env, KNOTRUST_HOME: home },
      cwd: configDir,
      stderr: "pipe",
    });
    const client = new FakeClient(transport);

    try {
      await client.connect();
      await client.listAllTools();
      const call = await client.callTool("echo", { ping: "pong" });
      expect(call.isError).toBeFalsy();
      await client.close();
    } finally {
      await started.close();
    }

    // Poll — the proxy's graceful shutdown (triggered by client EOF above)
    // flushes the exporter, but that flush is fire-and-forget from the
    // proxy's own perspective (see enforcement.ts's `close()`), so the POST
    // to the fixture can land a short moment after `client.close()` returns.
    const deadline = Date.now() + 5000;
    while (fixture.bodies.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }

    try {
      const spans = flattenSpans(fixture.bodies);
      expect(spans).toHaveLength(1);
      expect(spans[0]?.name).toBe("knotrust.decision");
      expect(spanAttr(spans[0] as OtlpSpan, "knotrust.tool")).toBe("echo");
      expect(spanAttr(spans[0] as OtlpSpan, "knotrust.server")).toBe("testsrv");
      expect(spanAttr(spans[0] as OtlpSpan, "knotrust.outcome")).toBe("allow");
    } finally {
      rmSync(configDir, { recursive: true, force: true });
      rmSync(home, { recursive: true, force: true });
      await fixture.close();
    }
  }, 20_000);
});
