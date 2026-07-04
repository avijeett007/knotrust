/**
 * Client MCP config read/rewrite/write tests (P0-E7-T1, R106–R108).
 *
 * Every fixture lives in a throwaway `mkdtemp` directory — NEVER the real
 * `~/Library/Application Support/Claude` or any real user file (R106).
 */

import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  atomicWriteFileSync,
  ClientConfigNotFoundError,
  ClientConfigParseError,
  defaultClientConfigCandidates,
  detectIndent,
  findExistingCandidate,
  isWrappedEntry,
  KNOTRUST_COMMAND,
  partitionServers,
  readClientConfig,
  rewriteClientConfig,
  serializeClientConfig,
  wrapEntry,
} from "./client-config.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(path.join(tmpdir(), "knotrust-init-clientcfg-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe("wrapEntry / isWrappedEntry (R107)", () => {
  it("wraps a plain server entry, preserving env and other keys", () => {
    const entry = {
      command: "node",
      args: ["server.js", "--flag"],
      env: { API_KEY: "secret" },
      extra: "kept",
    };
    const wrapped = wrapEntry(entry);
    expect(wrapped).toEqual({
      command: "knotrust",
      args: ["--", "node", "server.js", "--flag"],
      env: { API_KEY: "secret" },
      extra: "kept",
    });
    expect(entry.command).toBe("node"); // never mutates the input
  });

  it("recognizes an already-wrapped entry as wrapped (idempotent detection)", () => {
    const wrapped = wrapEntry({ command: "node", args: ["server.js"] });
    expect(isWrappedEntry(wrapped)).toBe(true);
  });

  it("recognizes a knotrust command referenced by absolute path (basename match)", () => {
    expect(
      isWrappedEntry({
        command: "/usr/local/bin/knotrust",
        args: ["--", "node"],
      }),
    ).toBe(true);
  });

  it("does not treat a bare `knotrust` command with no `--` as wrapped", () => {
    expect(isWrappedEntry({ command: KNOTRUST_COMMAND, args: ["init"] })).toBe(
      false,
    );
  });

  it("does not treat an unrelated command as wrapped", () => {
    expect(isWrappedEntry({ command: "node", args: ["server.js"] })).toBe(
      false,
    );
  });
});

describe("partitionServers", () => {
  it("splits wrappable vs. already-wrapped, ignoring malformed nested entries", () => {
    const parsed = {
      mcpServers: {
        github: { command: "npx", args: ["github-mcp"] },
        already: { command: "knotrust", args: ["--", "npx", "fs-mcp"] },
        odd: "not-an-object",
        noCommand: { args: ["x"] },
      },
    };
    const partition = partitionServers(parsed);
    expect(partition.wrappable).toEqual(["github"]);
    expect(partition.alreadyWrapped).toEqual(["already"]);
  });

  it("returns empty partitions when mcpServers is absent", () => {
    expect(partitionServers({})).toEqual({ wrappable: [], alreadyWrapped: [] });
  });
});

describe("rewriteClientConfig (R107)", () => {
  const twoServerConfig = {
    someOtherKey: "untouched",
    mcpServers: {
      github: { command: "npx", args: ["-y", "github-mcp"] },
      filesystem: {
        command: "npx",
        args: ["-y", "fs-mcp"],
        env: { ROOT: "/tmp" },
      },
    },
  };

  it("mode 'all' wraps every wrappable server and preserves other keys", () => {
    const plan = rewriteClientConfig(twoServerConfig, { mode: "all" });
    expect(plan.changed).toBe(true);
    expect(plan.wrapped.sort()).toEqual(["filesystem", "github"]);
    expect(plan.parsed.someOtherKey).toBe("untouched");
    const servers = plan.parsed.mcpServers as Record<string, unknown>;
    expect(servers.github).toEqual({
      command: "knotrust",
      args: ["--", "npx", "-y", "github-mcp"],
    });
    expect(servers.filesystem).toEqual({
      command: "knotrust",
      args: ["--", "npx", "-y", "fs-mcp"],
      env: { ROOT: "/tmp" },
    });
  });

  it("mode 'one' wraps only the named server", () => {
    const plan = rewriteClientConfig(twoServerConfig, {
      mode: "one",
      server: "github",
    });
    expect(plan.wrapped).toEqual(["github"]);
    expect(plan.notSelected).toEqual(["filesystem"]);
    const servers = plan.parsed.mcpServers as Record<string, unknown>;
    expect(servers.filesystem).toEqual(twoServerConfig.mcpServers.filesystem);
  });

  it("mode 'one' with an unknown server name changes nothing and reports unknownServer", () => {
    const plan = rewriteClientConfig(twoServerConfig, {
      mode: "one",
      server: "nope",
    });
    expect(plan.changed).toBe(false);
    expect(plan.unknownServer).toBe("nope");
  });

  it("mode 'subset' wraps exactly the named subset", () => {
    const three = {
      mcpServers: {
        a: { command: "node", args: ["a.js"] },
        b: { command: "node", args: ["b.js"] },
        c: { command: "node", args: ["c.js"] },
      },
    };
    const plan = rewriteClientConfig(three, {
      mode: "subset",
      servers: ["a", "c"],
    });
    expect(plan.wrapped.sort()).toEqual(["a", "c"]);
    expect(plan.notSelected).toEqual(["b"]);
  });

  it("is idempotent: re-running mode 'all' on an already-wrapped config is a no-op", () => {
    const first = rewriteClientConfig(twoServerConfig, { mode: "all" });
    const second = rewriteClientConfig(first.parsed, { mode: "all" });
    expect(second.changed).toBe(false);
    expect(second.wrapped).toEqual([]);
    expect(second.alreadyWrapped.sort()).toEqual(["filesystem", "github"]);
    expect(second.parsed).toBe(first.parsed); // same reference — genuinely untouched
  });

  it("reports changed:false and leaves parsed untouched when nothing is selected", () => {
    const plan = rewriteClientConfig(twoServerConfig, {
      mode: "subset",
      servers: [],
    });
    expect(plan.changed).toBe(false);
    expect(plan.parsed).toBe(twoServerConfig);
  });

  it("treats a config with no mcpServers key as a clean no-op, not an error", () => {
    const plan = rewriteClientConfig({ foo: "bar" }, { mode: "all" });
    expect(plan.changed).toBe(false);
    expect(plan.wrapped).toEqual([]);
  });
});

describe("readClientConfig / candidate resolution (R106)", () => {
  it("throws ClientConfigNotFoundError naming every candidate when none exist", () => {
    const candidates = [
      {
        kind: "claude-code" as const,
        path: path.join(tmp, "missing1", ".mcp.json"),
      },
      {
        kind: "claude-desktop" as const,
        path: path.join(tmp, "missing2.json"),
      },
    ];
    expect(() => readClientConfig(candidates)).toThrow(
      ClientConfigNotFoundError,
    );
    try {
      readClientConfig(candidates);
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(ClientConfigNotFoundError);
      const message = (error as Error).message;
      expect(message).toContain("missing1");
      expect(message).toContain("missing2.json");
    }
  });

  it("picks the first EXISTING candidate in priority order", () => {
    const desktopPath = path.join(tmp, "desktop.json");
    const codePath = path.join(tmp, ".mcp.json");
    writeFileSync(desktopPath, JSON.stringify({ mcpServers: {} }));
    writeFileSync(
      codePath,
      JSON.stringify({ mcpServers: { x: { command: "y" } } }),
    );
    const found = findExistingCandidate([
      { kind: "claude-code", path: codePath },
      { kind: "claude-desktop", path: desktopPath },
    ]);
    expect(found?.path).toBe(codePath);

    const doc = readClientConfig([
      { kind: "claude-code", path: codePath },
      { kind: "claude-desktop", path: desktopPath },
    ]);
    expect(doc.kind).toBe("claude-code");
    expect(doc.parsed).toEqual({ mcpServers: { x: { command: "y" } } });
  });

  it("throws ClientConfigParseError on malformed JSON, never touching the file", () => {
    const badPath = path.join(tmp, "bad.json");
    writeFileSync(badPath, "{ not: valid json ");
    const before = readFileSync(badPath, "utf8");
    expect(() =>
      readClientConfig([{ kind: "claude-desktop", path: badPath }]),
    ).toThrow(ClientConfigParseError);
    expect(readFileSync(badPath, "utf8")).toBe(before);
  });

  it("throws ClientConfigParseError when the top level isn't a JSON object", () => {
    const arrPath = path.join(tmp, "arr.json");
    writeFileSync(arrPath, "[1, 2, 3]");
    expect(() =>
      readClientConfig([{ kind: "claude-desktop", path: arrPath }]),
    ).toThrow(ClientConfigParseError);
  });
});

describe("defaultClientConfigCandidates (R106)", () => {
  const prior: Record<string, string | undefined> = {};
  const keys = [
    "KNOTRUST_CLAUDE_DESKTOP_CONFIG",
    "KNOTRUST_CLAUDE_CODE_CONFIG",
    "KNOTRUST_CODEX_CONFIG",
  ];

  beforeEach(() => {
    for (const k of keys) {
      prior[k] = process.env[k];
      delete process.env[k];
    }
  });
  afterEach(() => {
    for (const k of keys) {
      if (prior[k] === undefined) delete process.env[k];
      else process.env[k] = prior[k];
    }
  });

  it("orders claude candidates: claude-code (.mcp.json in cwd) first, claude-desktop second", () => {
    const candidates = defaultClientConfigCandidates("claude", "/some/project");
    expect(candidates.map((c) => c.kind)).toEqual([
      "claude-code",
      "claude-desktop",
    ]);
    expect(candidates[0]?.path).toBe(path.join("/some/project", ".mcp.json"));
  });

  it("returns a single codex candidate", () => {
    const candidates = defaultClientConfigCandidates("codex", "/some/project");
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.kind).toBe("codex");
  });

  it("honors env overrides for every candidate path", () => {
    process.env.KNOTRUST_CLAUDE_DESKTOP_CONFIG = "/override/desktop.json";
    process.env.KNOTRUST_CLAUDE_CODE_CONFIG = "/override/mcp.json";
    process.env.KNOTRUST_CODEX_CONFIG = "/override/codex.toml";
    const claude = defaultClientConfigCandidates("claude", "/cwd");
    expect(claude.find((c) => c.kind === "claude-desktop")?.path).toBe(
      "/override/desktop.json",
    );
    expect(claude.find((c) => c.kind === "claude-code")?.path).toBe(
      "/override/mcp.json",
    );
    const codex = defaultClientConfigCandidates("codex", "/cwd");
    expect(codex[0]?.path).toBe("/override/codex.toml");
  });
});

describe("serializeClientConfig / detectIndent", () => {
  it("detects 2-space indent", () => {
    expect(detectIndent('{\n  "a": 1\n}')).toBe(2);
  });

  it("detects 4-space indent", () => {
    expect(detectIndent('{\n    "a": 1\n}')).toBe(4);
  });

  it("detects tab indent", () => {
    expect(detectIndent('{\n\t"a": 1\n}')).toBe("\t");
  });

  it("defaults to 2 spaces when indentation can't be sniffed", () => {
    expect(detectIndent('{"a":1}')).toBe(2);
  });

  it("round-trips: serializing the parsed form of an untouched file reproduces byte-identical text at the same indent", () => {
    const raw = '{\n  "a": 1,\n  "b": [\n    2,\n    3\n  ]\n}\n';
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    expect(serializeClientConfig(parsed, detectIndent(raw))).toBe(raw);
  });
});

describe("atomicWriteFileSync", () => {
  it("writes the file and leaves no leftover temp file", () => {
    const target = path.join(tmp, "out.json");
    atomicWriteFileSync(target, '{"a":1}\n');
    expect(readFileSync(target, "utf8")).toBe('{"a":1}\n');
    const leftovers = readdirSync(tmp).filter((f) => f.includes(".tmp"));
    expect(leftovers).toEqual([]);
  });

  it("overwrites an existing file atomically", () => {
    const target = path.join(tmp, "out.json");
    writeFileSync(target, "old");
    atomicWriteFileSync(target, "new");
    expect(readFileSync(target, "utf8")).toBe("new");
  });
});
