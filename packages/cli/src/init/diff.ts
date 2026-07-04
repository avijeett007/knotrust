/**
 * knotrust CLI `init` — unified-diff formatter (P0-E7-T1, ruling R108).
 *
 * `init claude|codex --dry-run`/`--diff` must print an EXACT diff of the
 * intended client-config change (and the generated `knotrust.config.*`
 * change) before ANY write happens (shadcn init playbook). This repo already
 * runs a strict dependency-tree-minimalism doctrine for the published CLI
 * (ADR-0002); the config files this command ever diffs are small (a handful
 * to a few hundred lines of JSON/YAML), so a hand-rolled diff — rather than
 * pulling in a third-party `diff` package — keeps the published dependency
 * tree exactly as-is (R110 only adds `@clack/prompts`).
 *
 * Algorithm: a straightforward O(n·m) dynamic-programming LCS over lines
 * (config files are small; this is never run against large source trees),
 * then a standard GNU/git-style unified-diff hunk grouping (3 lines of
 * context, adjacent/overlapping change regions merged into one hunk). Line
 * numbering and the `@@ -a,b +c,d @@` header math follow the same convention
 * `diff -u`/`git diff` use, including the `,0` zero-length-side special case
 * for a pure insertion/deletion hunk.
 *
 * Deliberately NOT attempted: a "\ No newline at end of file" marker, or any
 * whitespace/tab-expansion nuance real `diff` implementations carry — this is
 * a PREVIEW tool for a human deciding whether to let `knotrust init` write a
 * file, not a `patch`-compatible patch generator. Trailing-newline presence
 * is normalized away (see `splitLines`) rather than represented, so a file
 * that only differs by a trailing newline diffs as identical (no hunks).
 */

export interface UnifiedDiffOptions {
  /** Lines of unchanged context kept around each change region. Default 3 (matches `diff -u`/git). */
  context?: number;
  /** Label for the `--- ` header line. Default `"a"`. */
  fromLabel?: string;
  /** Label for the `+++ ` header line. Default `"b"`. */
  toLabel?: string;
}

type OpType = "context" | "add" | "remove";

interface DiffOp {
  type: OpType;
  line: string;
}

/**
 * Splits into lines on `\n`/`\r\n`, dropping a single trailing empty element
 * produced when the text ends with a newline — so `"a\nb\n"` and `"a\nb"`
 * both yield `["a", "b"]`. This is a deliberate simplification (see this
 * module's header): a diff PREVIEW does not need to represent "does the file
 * end with a newline" as its own diff-able fact.
 */
function splitLines(text: string): string[] {
  const lines = text.split(/\r\n|\n/);
  if (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

/** Flat (row-major) DP grid — avoids `noUncheckedIndexedAccess` friction from a `number[][]` where every nested read is `| undefined`. */
class Grid {
  private readonly data: number[];
  private readonly cols: number;

  constructor(rows: number, cols: number) {
    this.cols = cols;
    this.data = new Array(rows * cols).fill(0);
  }

  get(row: number, col: number): number {
    return this.data[row * this.cols + col] ?? 0;
  }

  set(row: number, col: number, value: number): void {
    this.data[row * this.cols + col] = value;
  }
}

/** Classic bottom-up LCS length table, then a greedy backtrack that prefers a "remove" over an "add" on ties (matches conventional diff output shape). */
function computeOps(
  oldLines: readonly string[],
  newLines: readonly string[],
): DiffOp[] {
  const n = oldLines.length;
  const m = newLines.length;
  const dp = new Grid(n + 1, m + 1);

  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      if (oldLines[i] === newLines[j]) {
        dp.set(i, j, dp.get(i + 1, j + 1) + 1);
      } else {
        dp.set(i, j, Math.max(dp.get(i + 1, j), dp.get(i, j + 1)));
      }
    }
  }

  const ops: DiffOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    const oldLine = oldLines[i];
    const newLine = newLines[j];
    if (oldLine === newLine) {
      ops.push({ type: "context", line: oldLine ?? "" });
      i++;
      j++;
    } else if (dp.get(i + 1, j) >= dp.get(i, j + 1)) {
      ops.push({ type: "remove", line: oldLine ?? "" });
      i++;
    } else {
      ops.push({ type: "add", line: newLine ?? "" });
      j++;
    }
  }
  while (i < n) {
    ops.push({ type: "remove", line: oldLines[i] ?? "" });
    i++;
  }
  while (j < m) {
    ops.push({ type: "add", line: newLines[j] ?? "" });
    j++;
  }
  return ops;
}

interface AnnotatedOp extends DiffOp {
  /** 1-based old-file line number this op sits AT (see this module's header re: the `,0` convention for a pure add/remove edge). */
  oldPos: number;
  /** 1-based new-file line number this op sits AT. */
  newPos: number;
}

function annotate(ops: readonly DiffOp[]): AnnotatedOp[] {
  let oldPos = 1;
  let newPos = 1;
  const result: AnnotatedOp[] = [];
  for (const op of ops) {
    result.push({ ...op, oldPos, newPos });
    if (op.type === "context") {
      oldPos++;
      newPos++;
    } else if (op.type === "remove") {
      oldPos++;
    } else {
      newPos++;
    }
  }
  return result;
}

interface Hunk {
  ops: AnnotatedOp[];
}

/** Groups changed regions (padded by `context` lines on each side, overlaps merged) into hunks. Returns `[]` when there are no changes at all. */
function groupIntoHunks(ops: readonly AnnotatedOp[], context: number): Hunk[] {
  const changedIndices: number[] = [];
  ops.forEach((op, idx) => {
    if (op.type !== "context") changedIndices.push(idx);
  });
  if (changedIndices.length === 0) return [];

  const ranges: Array<[number, number]> = [];
  for (const idx of changedIndices) {
    const start = Math.max(0, idx - context);
    const end = Math.min(ops.length, idx + context + 1);
    const last = ranges[ranges.length - 1];
    if (last !== undefined && start <= last[1]) {
      last[1] = Math.max(last[1], end);
    } else {
      ranges.push([start, end]);
    }
  }
  return ranges.map(([start, end]) => ({ ops: ops.slice(start, end) }));
}

function formatHunk(hunk: Hunk): string {
  const first = hunk.ops[0];
  if (first === undefined) return "";
  const oldCount = hunk.ops.filter((op) => op.type !== "add").length;
  const newCount = hunk.ops.filter((op) => op.type !== "remove").length;
  const oldStart = oldCount === 0 ? first.oldPos - 1 : first.oldPos;
  const newStart = newCount === 0 ? first.newPos - 1 : first.newPos;

  const header = `@@ -${oldStart},${oldCount} +${newStart},${newCount} @@\n`;
  const body = hunk.ops
    .map((op) => {
      const marker =
        op.type === "context" ? " " : op.type === "add" ? "+" : "-";
      return `${marker}${op.line}`;
    })
    .join("\n");
  return `${header}${body}\n`;
}

/**
 * Produces a unified diff of `oldText` vs `newText`, or `""` when they are
 * line-for-line identical (see `splitLines` for the one normalization:
 * trailing-newline presence is not itself diff-able). The empty-string
 * return is the caller's (`command.ts`) no-diff / no-op signal — do not
 * treat `""` as an error.
 */
export function unifiedDiff(
  oldText: string,
  newText: string,
  opts: UnifiedDiffOptions = {},
): string {
  const oldLines = splitLines(oldText);
  const newLines = splitLines(newText);
  const ops = computeOps(oldLines, newLines);
  const annotated = annotate(ops);
  const hunks = groupIntoHunks(annotated, opts.context ?? 3);
  if (hunks.length === 0) return "";

  const fromLabel = opts.fromLabel ?? "a";
  const toLabel = opts.toLabel ?? "b";
  const header = `--- ${fromLabel}\n+++ ${toLabel}\n`;
  return header + hunks.map(formatHunk).join("");
}
