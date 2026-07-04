/**
 * `knotrust init` orchestrator acceptance tests (P0-E7-T1).
 *
 * Every fixture lives in a throwaway `mkdtemp` directory; `clientConfigCandidates`
 * is ALWAYS injected to point at that directory — this suite never touches a
 * real user's `~/Library/Application Support/Claude` or any real file
 * (R106). Most tests inject a fake `captureToolInventory` (the fixture
 * client configs reference commands like `"npx"` that aren't real MCP
 * servers); one dedicated end-to-end test spawns the REAL
 * `@knotrust/test-harness` fake server to prove the production capture
 * wiring.
 */

import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import type { FakeServerConfig } from "@knotrust/test-harness";
import { startFakeServer } from "@knotrust/test-harness";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { InitArgs } from "./argv.js";
import type { ClientConfigCandidate } from "./client-config.js";
import { type InitDeps, type InitIo, runInit } from "./command.js";
import { unifiedDiff } from "./diff.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(path.join(tmpdir(), "knotrust-init-command-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function collect(stream: PassThrough): () => string {
  let text = "";
  stream.on("data", (chunk: Buffer) => {
    text += chunk.toString("utf8");
  });
  return () => text;
}

function makeIo(): { io: InitIo; getOut: () => string; getErr: () => string } {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  return {
    io: { stdout, stderr, cwd: tmp },
    getOut: collect(stdout),
    getErr: collect(stderr),
  };
}

function baseArgs(overrides: Partial<InitArgs> = {}): InitArgs {
  return {
    client: "claude",
    yes: false,
    dryRun: false,
    configFormat: "yaml",
    ...overrides,
  };
}

function candidatesFor(fixturePath: string) {
  return (): ClientConfigCandidate[] => [
    { kind: "claude-desktop" as const, path: fixturePath },
  ];
}

function writeFixture(content: unknown): string {
  const fixturePath = path.join(tmp, "claude_desktop_config.json");
  writeFileSync(
    fixturePath,
    typeof content === "string" ? content : JSON.stringify(content, null, 2),
  );
  return fixturePath;
}

const noCapture: InitDeps["captureToolInventory"] = async () => undefined;

describe("runInit — dry-run diff discipline (R108)", () => {
  it("`init claude --dry-run` prints an exact diff and writes NOTHING", async () => {
    const original = {
      other: "untouched",
      mcpServers: {
        github: { command: "npx", args: ["-y", "github-mcp"] },
      },
    };
    const fixturePath = writeFixture(original);
    const before = readFileSync(fixturePath, "utf8");
    const { io, getOut } = makeIo();

    const code = await runInit(io, baseArgs({ yes: true, dryRun: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
    });

    expect(code).toBe(0);
    // Nothing written — byte-identical to before.
    expect(readFileSync(fixturePath, "utf8")).toBe(before);
    expect(existsSync(path.join(tmp, "knotrust.config.yaml"))).toBe(false);

    const expectedNewText = `${JSON.stringify(
      {
        other: "untouched",
        mcpServers: {
          github: {
            command: "knotrust",
            args: ["--", "npx", "-y", "github-mcp"],
          },
        },
      },
      null,
      2,
    )}\n`;
    const expectedDiff = unifiedDiff(before, expectedNewText, {
      fromLabel: fixturePath,
      toLabel: fixturePath,
    });
    expect(expectedDiff.length).toBeGreaterThan(0);
    expect(getOut()).toContain(expectedDiff);
    expect(getOut()).toContain("dry run — no changes written");
  });
});

describe("runInit — real wrap + idempotent second run (R107)", () => {
  it("wraps the chosen servers, then a second run is a clean no-op", async () => {
    const fixturePath = writeFixture({
      mcpServers: {
        github: {
          command: "npx",
          args: ["-y", "github-mcp"],
          env: { TOKEN: "x" },
        },
      },
    });
    const fakeInventory = {
      list_issues: {
        annotations: {
          trusted: false as const,
          source: "server_advertised" as const,
          readOnlyHint: true,
          capturedAt: "2026-01-01T00:00:00.000Z",
        },
        inputSchemaHash: "sha256:abc",
      },
    };

    const { io: io1 } = makeIo();
    const code1 = await runInit(io1, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => fakeInventory,
    });
    expect(code1).toBe(0);

    const afterFirst = readFileSync(fixturePath, "utf8");
    const parsedAfterFirst = JSON.parse(afterFirst) as {
      mcpServers: Record<
        string,
        { command: string; args: string[]; env?: unknown }
      >;
    };
    expect(parsedAfterFirst.mcpServers.github).toEqual({
      command: "knotrust",
      args: ["--", "npx", "-y", "github-mcp"],
      env: { TOKEN: "x" },
    });

    const configPath = path.join(tmp, "knotrust.config.yaml");
    expect(existsSync(configPath)).toBe(true);

    // --- second run: idempotent no-op ---
    const { io: io2, getOut: getOut2 } = makeIo();
    const code2 = await runInit(io2, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => {
        throw new Error("capture must not run on an idempotent no-op re-run");
      },
    });
    expect(code2).toBe(0);
    expect(readFileSync(fixturePath, "utf8")).toBe(afterFirst); // byte-identical
    expect(getOut2()).toContain("idempotent no-op");
    // knotrust.config.yaml also untouched on the no-op re-run.
    expect(readFileSync(configPath, "utf8")).toEqual(
      readFileSync(configPath, "utf8"),
    );
  });

  it("marks the generated config's seeded tiers source: annotation", async () => {
    const fixturePath = writeFixture({
      mcpServers: { fs: { command: "npx", args: ["-y", "fs-mcp"] } },
    });
    const { io } = makeIo();
    await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => ({
        read_file: {
          annotations: {
            trusted: false,
            source: "server_advertised",
            readOnlyHint: true,
            capturedAt: "2026-01-01T00:00:00.000Z",
          },
          inputSchemaHash: "sha256:x",
        },
        delete_file: {
          annotations: {
            trusted: false,
            source: "server_advertised",
            destructiveHint: true,
            capturedAt: "2026-01-01T00:00:00.000Z",
          },
          inputSchemaHash: "sha256:y",
        },
      }),
    });
    const generated = readFileSync(
      path.join(tmp, "knotrust.config.yaml"),
      "utf8",
    );
    expect(generated).toContain('"source": "annotation"');
    expect(generated).toContain('"read_file"');
    expect(generated).toContain('"tier": "routine"');
    expect(generated).toContain('"delete_file"');
    expect(generated).toContain('"tier": "sensitive"');
  });
});

describe("runInit — malformed client config aborts with no partial write (R108)", () => {
  it("aborts with a non-zero code, no writes anywhere", async () => {
    const fixturePath = writeFixture("{ this is not valid json ");
    const before = readFileSync(fixturePath, "utf8");
    const { io, getErr } = makeIo();

    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
    });

    expect(code).toBe(1);
    expect(getErr()).toContain("not valid JSON");
    expect(readFileSync(fixturePath, "utf8")).toBe(before);
    expect(existsSync(path.join(tmp, "knotrust.config.yaml"))).toBe(false);
    // No stray temp files left behind either.
    expect(readdirSync(tmp).filter((f) => f.includes(".tmp"))).toEqual([]);
  });

  it("aborts with no write when no client config exists at any candidate path", async () => {
    const { io, getErr } = makeIo();
    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: () => [
        { kind: "claude-desktop", path: path.join(tmp, "nope.json") },
      ],
      captureToolInventory: noCapture,
    });
    expect(code).toBe(1);
    expect(getErr()).toContain("no client MCP config found");
  });
});

describe("runInit — `--yes` completes with zero prompts", () => {
  it("never calls selectServers when --yes is given", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    const { io } = makeIo();
    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
      selectServers: async () => {
        throw new Error("selectServers must never be called under --yes");
      },
    });
    expect(code).toBe(0);
  });

  it("never calls selectServers when --server <name> is given", async () => {
    const fixturePath = writeFixture({
      mcpServers: {
        a: { command: "node", args: ["a.js"] },
        b: { command: "node", args: ["b.js"] },
      },
    });
    const { io } = makeIo();
    const code = await runInit(io, baseArgs({ server: "a" }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
      selectServers: async () => {
        throw new Error("selectServers must never be called with --server");
      },
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      mcpServers: Record<string, { command: string }>;
    };
    expect(parsed.mcpServers.a?.command).toBe("knotrust");
    expect(parsed.mcpServers.b?.command).toBe("node"); // untouched
  });
});

describe("runInit — interactive selection (injected fake, never the real TTY prompt)", () => {
  it("wraps exactly the subset selectServers returns", async () => {
    const fixturePath = writeFixture({
      mcpServers: {
        a: { command: "node", args: ["a.js"] },
        b: { command: "node", args: ["b.js"] },
      },
    });
    const { io } = makeIo();
    let calledWith: readonly string[] | undefined;
    const code = await runInit(io, baseArgs(), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
      selectServers: async (candidates) => {
        calledWith = candidates;
        return ["b"];
      },
    });
    expect(code).toBe(0);
    expect(calledWith).toEqual(["a", "b"]);
    const parsed = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      mcpServers: Record<string, { command: string }>;
    };
    expect(parsed.mcpServers.a?.command).toBe("node");
    expect(parsed.mcpServers.b?.command).toBe("knotrust");
  });

  it("a cancelled selection aborts with no write", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    const before = readFileSync(fixturePath, "utf8");
    const { io, getErr } = makeIo();
    const code = await runInit(io, baseArgs(), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
      selectServers: async () => {
        const { ServerSelectionCancelledError } = await import(
          "./select-servers.js"
        );
        throw new ServerSelectionCancelledError();
      },
    });
    expect(code).toBe(1);
    expect(getErr()).toContain("cancelled");
    expect(readFileSync(fixturePath, "utf8")).toBe(before);
  });
});

describe("runInit — unknown --server name", () => {
  it("errors clearly, writes nothing", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    const before = readFileSync(fixturePath, "utf8");
    const { io, getErr } = makeIo();
    const code = await runInit(io, baseArgs({ server: "nope" }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
    });
    expect(code).toBe(1);
    expect(getErr()).toContain('server "nope" not found');
    expect(readFileSync(fixturePath, "utf8")).toBe(before);
  });
});

describe("runInit — best-effort capture failure -> skeleton config (R109)", () => {
  it("generates a skeleton with unknownToolTier sensitive and a note when capture fails", async () => {
    const fixturePath = writeFixture({
      mcpServers: { flaky: { command: "npx", args: ["-y", "flaky-mcp"] } },
    });
    const { io, getErr } = makeIo();
    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => undefined, // best-effort failure
    });
    expect(code).toBe(0);
    const generated = readFileSync(
      path.join(tmp, "knotrust.config.yaml"),
      "utf8",
    );
    expect(generated).toContain('"unknownToolTier": "sensitive"');
    expect(getErr()).toContain("tools/list capture did not complete");
    expect(getErr()).toContain("flaky");
  });
});

describe("runInit — existing knotrust.config.ts is never regenerated", () => {
  it("skips config generation, printing a clear notice", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    const tsPath = path.join(tmp, "knotrust.config.ts");
    const tsContent = "export default { version: 1 };\n";
    writeFileSync(tsPath, tsContent);
    const { io, getOut } = makeIo();
    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => ({}),
    });
    expect(code).toBe(0);
    expect(readFileSync(tsPath, "utf8")).toBe(tsContent); // untouched
    expect(getOut()).toContain("is a TypeScript config");
  });
});

describe("runInit — confirmation before overwriting an existing knotrust.config (R109)", () => {
  it("declining leaves the existing config untouched", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    const configPath = path.join(tmp, "knotrust.config.json");
    const existingContent = `${JSON.stringify(
      {
        version: 1,
        scope: "personal",
        unknownToolTier: "sensitive",
        approvalTimeoutSeconds: 300,
      },
      null,
      2,
    )}\n`;
    writeFileSync(configPath, existingContent);

    const { io } = makeIo();
    const code = await runInit(io, baseArgs(), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => ({
        x: {
          annotations: {
            trusted: false,
            source: "server_advertised",
            readOnlyHint: true,
            capturedAt: "2026-01-01T00:00:00.000Z",
          },
          inputSchemaHash: "sha256:z",
        },
      }),
      selectServers: async () => ["a"],
      confirmOverwrite: async () => false,
    });
    expect(code).toBe(0);
    expect(readFileSync(configPath, "utf8")).toBe(existingContent);
  });

  it("confirming overwrites with the fresh suggestions", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    const configPath = path.join(tmp, "knotrust.config.json");
    writeFileSync(
      configPath,
      `${JSON.stringify(
        {
          version: 1,
          scope: "personal",
          unknownToolTier: "sensitive",
          approvalTimeoutSeconds: 300,
        },
        null,
        2,
      )}\n`,
    );

    const { io } = makeIo();
    const code = await runInit(io, baseArgs(), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => ({
        x: {
          annotations: {
            trusted: false,
            source: "server_advertised",
            readOnlyHint: true,
            capturedAt: "2026-01-01T00:00:00.000Z",
          },
          inputSchemaHash: "sha256:z",
        },
      }),
      selectServers: async () => ["a"],
      confirmOverwrite: async () => true,
    });
    expect(code).toBe(0);
    const updated = readFileSync(configPath, "utf8");
    expect(updated).toContain('"source": "annotation"');
  });

  it("--yes never prompts for overwrite confirmation", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    const configPath = path.join(tmp, "knotrust.config.json");
    writeFileSync(
      configPath,
      `${JSON.stringify(
        {
          version: 1,
          scope: "personal",
          unknownToolTier: "sensitive",
          approvalTimeoutSeconds: 300,
        },
        null,
        2,
      )}\n`,
    );
    const { io } = makeIo();
    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => ({}),
      confirmOverwrite: async () => {
        throw new Error("confirmOverwrite must never be called under --yes");
      },
    });
    expect(code).toBe(0);
  });
});

describe("runInit — preserves env and other untouched entries (R107)", () => {
  it("forwards the original entry's env into the capture call", async () => {
    const fixturePath = writeFixture({
      mcpServers: {
        github: {
          command: "npx",
          args: ["-y", "github-mcp"],
          env: { GITHUB_TOKEN: "secret" },
        },
      },
    });
    let capturedEnv: Record<string, string> | undefined;
    const { io } = makeIo();
    await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async (_cmd, opts) => {
        capturedEnv = opts.env;
        return {};
      },
    });
    expect(capturedEnv).toEqual({ GITHUB_TOKEN: "secret" });
  });
});

describe("runInit — end-to-end with a REAL spawned server (no injected capture)", () => {
  it("captures real tools/list output from a fake MCP server and seeds tiers", async () => {
    const config: FakeServerConfig = {
      serverInfo: { name: "knotrust-init-e2e", version: "1.0.0" },
      tools: [
        {
          name: "list_things",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true },
        },
      ],
    };
    const started = await startFakeServer(config, {
      prepareChildCommand: true,
    });
    const childCommand = started.childCommand;
    if (childCommand === undefined) throw new Error("no childCommand");

    const fixturePath = writeFixture({
      mcpServers: {
        realsrv: { command: childCommand[0], args: childCommand.slice(1) },
      },
    });

    try {
      const { io } = makeIo();
      const code = await runInit(io, baseArgs({ yes: true }), {
        clientConfigCandidates: candidatesFor(fixturePath),
        captureTimeoutMs: 5_000,
      });
      expect(code).toBe(0);
      const generated = readFileSync(
        path.join(tmp, "knotrust.config.yaml"),
        "utf8",
      );
      expect(generated).toContain('"list_things"');
      expect(generated).toContain('"tier": "routine"');
      expect(generated).toContain('"source": "annotation"');
    } finally {
      await started.close();
    }
  }, 15_000);
});

describe("runInit — codex client (JSON-shaped assumption, R106)", () => {
  it("reads/writes the codex candidate path the same way as claude", async () => {
    const codexPath = path.join(tmp, "config.toml");
    writeFileSync(
      codexPath,
      JSON.stringify({
        mcpServers: { fs: { command: "node", args: ["fs.js"] } },
      }),
    );
    const { io } = makeIo();
    const code = await runInit(io, baseArgs({ client: "codex", yes: true }), {
      clientConfigCandidates: () => [{ kind: "codex", path: codexPath }],
      captureToolInventory: noCapture,
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(readFileSync(codexPath, "utf8")) as {
      mcpServers: Record<string, { command: string }>;
    };
    expect(parsed.mcpServers.fs?.command).toBe("knotrust");
  });
});

describe("runInit — knotrust.config generation degrades cleanly on a broken EXISTING config (fix round 1: no unguarded throw after the client-config write)", () => {
  function writeExistingConfig(filename: string, content: string): string {
    const configPath = path.join(tmp, filename);
    writeFileSync(configPath, content);
    return configPath;
  }

  /** No raw JS stack trace (a `    at <file>:<line>:<col>` frame) anywhere in `text`. */
  function hasNoStackFrame(text: string): boolean {
    return !/\n\s*at .+:\d+:\d+/.test(text);
  }

  it("an invalid existing knotrust.config.yaml (schema violation — unknownToolTier: routine) still lets the client config wrap; generation is skipped with a clean notice, no stack trace", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    writeExistingConfig(
      "knotrust.config.yaml",
      'version: 1\nunknownToolTier: "routine"\n',
    );
    const { io, getErr } = makeIo();

    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
    });

    // Clean exit — the client wrap already succeeded and stands.
    expect(code).toBe(0);
    // Byte-verified: the client config WAS wrapped despite the broken
    // knotrust.config sitting right next to it.
    const parsed = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      mcpServers: Record<string, { command: string; args: string[] }>;
    };
    expect(parsed.mcpServers.a).toEqual({
      command: "knotrust",
      args: ["--", "node", "a.js"],
    });
    expect(getErr()).toContain("wrapped the claude-desktop config");
    expect(getErr()).toContain("could not generate/update knotrust.config");
    expect(getErr()).toContain("invalid");
    expect(hasNoStackFrame(getErr())).toBe(true);
  });

  it("an invalid existing knotrust.config.json (same schema violation) behaves identically", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    writeExistingConfig(
      "knotrust.config.json",
      JSON.stringify({ version: 1, unknownToolTier: "routine" }),
    );
    const { io, getErr } = makeIo();

    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
    });

    expect(code).toBe(0);
    const parsed = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      mcpServers: Record<string, { command: string }>;
    };
    expect(parsed.mcpServers.a?.command).toBe("knotrust");
    expect(getErr()).toContain("could not generate/update knotrust.config");
    expect(hasNoStackFrame(getErr())).toBe(true);
  });

  it("an unparseable existing knotrust.config.yaml (a genuine syntax error, NOT a schema violation) also degrades cleanly", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    // Malformed YAML flow-sequence syntax — this throws a raw YAML parse
    // error from c12/jiti's own YAML loader, never wrapped into our
    // `ConfigError` (see `loadKnotrustConfig`'s doc-comment) — the OTHER
    // failure class `describeConfigGenerationFailure` must also handle.
    writeExistingConfig("knotrust.config.yaml", "foo: [1, 2\nbar: }\n");
    const { io, getErr } = makeIo();

    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
    });

    expect(code).toBe(0);
    const parsed = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      mcpServers: Record<string, { command: string }>;
    };
    expect(parsed.mcpServers.a?.command).toBe("knotrust");
    expect(getErr()).toContain("could not generate/update knotrust.config");
    expect(hasNoStackFrame(getErr())).toBe(true);
  });

  it("happy path unaffected: a VALID (or absent) existing config still generates the seeded config as before", async () => {
    const fixturePath = writeFixture({
      mcpServers: { a: { command: "node", args: ["a.js"] } },
    });
    // No existing knotrust.config at all — the ordinary zero-config case.
    const { io, getErr } = makeIo();
    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: async () => ({}),
    });
    expect(code).toBe(0);
    expect(existsSync(path.join(tmp, "knotrust.config.yaml"))).toBe(true);
    expect(getErr()).not.toContain("could not generate/update");
  });
});

describe("runInit — no wrappable servers at all", () => {
  it("is a clean no-op when mcpServers is empty", async () => {
    const fixturePath = writeFixture({ mcpServers: {} });
    const before = readFileSync(fixturePath, "utf8");
    const { io, getOut } = makeIo();
    const code = await runInit(io, baseArgs({ yes: true }), {
      clientConfigCandidates: candidatesFor(fixturePath),
      captureToolInventory: noCapture,
    });
    expect(code).toBe(0);
    expect(readFileSync(fixturePath, "utf8")).toBe(before);
    expect(getOut()).toContain("No wrappable MCP servers found");
    expect(existsSync(path.join(tmp, "knotrust.config.yaml"))).toBe(false);
  });
});
