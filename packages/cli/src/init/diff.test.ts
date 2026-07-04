/**
 * Unified-diff formatter tests (P0-E7-T1, R108).
 */

import { describe, expect, it } from "vitest";
import { unifiedDiff } from "./diff.js";

describe("unifiedDiff", () => {
  it("returns empty string for identical text", () => {
    expect(unifiedDiff("a\nb\nc\n", "a\nb\nc\n")).toBe("");
  });

  it("treats a difference only in trailing newline as identical (documented normalization)", () => {
    expect(unifiedDiff("a\nb\nc\n", "a\nb\nc")).toBe("");
  });

  it("produces a single-line-changed hunk with headers and context", () => {
    const oldText = "one\ntwo\nthree\n";
    const newText = "one\nTWO\nthree\n";
    const out = unifiedDiff(oldText, newText);
    expect(out).toBe(
      [
        "--- a",
        "+++ b",
        "@@ -1,3 +1,3 @@",
        " one",
        "-two",
        "+TWO",
        " three",
        "",
      ].join("\n"),
    );
  });

  it("uses custom from/to labels", () => {
    const out = unifiedDiff("a\n", "b\n", {
      fromLabel: "old/config.json",
      toLabel: "new/config.json",
    });
    expect(out.startsWith("--- old/config.json\n+++ new/config.json\n")).toBe(
      true,
    );
  });

  it("handles a pure insertion at the end (zero old-side count, no context)", () => {
    const out = unifiedDiff("a\nb\n", "a\nb\nc\n", { context: 0 });
    expect(out).toBe(
      ["--- a", "+++ b", "@@ -2,0 +3,1 @@", "+c", ""].join("\n"),
    );
  });

  it("handles a pure deletion at the start (zero new-side count, no context)", () => {
    const out = unifiedDiff("x\na\nb\n", "a\nb\n", { context: 0 });
    expect(out).toBe(
      ["--- a", "+++ b", "@@ -1,1 +0,0 @@", "-x", ""].join("\n"),
    );
  });

  it("includes surrounding context around a pure insertion when context > 0", () => {
    const out = unifiedDiff("a\nb\n", "a\nb\nc\n", { context: 3 });
    expect(out).toBe(
      ["--- a", "+++ b", "@@ -1,2 +1,3 @@", " a", " b", "+c", ""].join("\n"),
    );
  });

  it("splits distant changes into separate hunks and merges nearby ones", () => {
    const oldLines = Array.from({ length: 20 }, (_, i) => `line${i}`);
    const newLines = [...oldLines];
    newLines[0] = "CHANGED0";
    newLines[19] = "CHANGED19";
    const oldText = `${oldLines.join("\n")}\n`;
    const newText = `${newLines.join("\n")}\n`;
    const out = unifiedDiff(oldText, newText, { context: 3 });
    const hunkHeaders = out.match(/^@@.*@@$/gm) ?? [];
    expect(hunkHeaders.length).toBe(2);
  });

  it("merges two nearby changes into one hunk when their context windows overlap", () => {
    const oldLines = Array.from({ length: 10 }, (_, i) => `line${i}`);
    const newLines = [...oldLines];
    newLines[2] = "CHANGED2";
    newLines[5] = "CHANGED5";
    const oldText = `${oldLines.join("\n")}\n`;
    const newText = `${newLines.join("\n")}\n`;
    const out = unifiedDiff(oldText, newText, { context: 3 });
    const hunkHeaders = out.match(/^@@.*@@$/gm) ?? [];
    expect(hunkHeaders.length).toBe(1);
  });

  it("handles a diff of an entirely new file (empty old text)", () => {
    const out = unifiedDiff("", "one\ntwo\n");
    expect(out).toBe(
      ["--- a", "+++ b", "@@ -0,0 +1,2 @@", "+one", "+two", ""].join("\n"),
    );
  });
});
