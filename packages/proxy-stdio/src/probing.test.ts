/**
 * @knotrust/proxy-stdio — repeated-denial probing detector unit suite
 * (P0-E5-T4, R78; fix round 1 adds the "bounded memory" describe block
 * below).
 */

import { describe, expect, it } from "vitest";
import { createProbingDetector, DEFAULT_PROBING_WINDOW_MS } from "./probing.js";

describe("createProbingDetector — R78 sliding-window threshold", () => {
  it("fires exactly once on the Nth (default 5th) denial for a (tool, agent) pair within the window", () => {
    let now = 1_000_000;
    const detector = createProbingDetector({ nowMs: () => now });

    const fired: boolean[] = [];
    for (let i = 0; i < 5; i++) {
      fired.push(detector.recordDenial("stripe.refund", "codex-cli"));
      now += 100; // well within the 60s window
    }
    expect(fired).toEqual([false, false, false, false, true]);
  });

  it("does not spam: a 6th denial right after the fire does not fire again immediately", () => {
    let now = 0;
    const detector = createProbingDetector({ nowMs: () => now });
    for (let i = 0; i < 5; i++) {
      detector.recordDenial("t", "a");
      now += 10;
    }
    // the window reset on fire — the very next denial starts a fresh count.
    expect(detector.recordDenial("t", "a")).toBe(false);
  });

  it("fires again after another full threshold's worth of denials post-reset", () => {
    let now = 0;
    const detector = createProbingDetector({ nowMs: () => now });
    const fired: boolean[] = [];
    for (let i = 0; i < 10; i++) {
      fired.push(detector.recordDenial("t", "a"));
      now += 10;
    }
    // 5th (index 4) fires, resets; 10th (index 9, the 5th since reset) fires again.
    expect(fired[4]).toBe(true);
    expect(fired[9]).toBe(true);
    expect(fired.filter(Boolean).length).toBe(2);
  });

  it("tracks each (tool, agent) pair independently", () => {
    let now = 0;
    const detector = createProbingDetector({ nowMs: () => now });
    for (let i = 0; i < 4; i++) {
      expect(detector.recordDenial("toolA", "agent1")).toBe(false);
      now += 10;
    }
    // A different tool with the same agent has its own independent counter.
    expect(detector.recordDenial("toolB", "agent1")).toBe(false);
    // A different agent with the same tool ALSO has its own independent counter.
    expect(detector.recordDenial("toolA", "agent2")).toBe(false);
    // The original (toolA, agent1) pair's 5th denial fires.
    expect(detector.recordDenial("toolA", "agent1")).toBe(true);
  });

  it("denials outside the window do not accumulate toward the threshold", () => {
    let now = 0;
    const detector = createProbingDetector({
      nowMs: () => now,
      windowMs: 60_000,
    });
    for (let i = 0; i < 4; i++) {
      expect(detector.recordDenial("t", "a")).toBe(false);
      now += 10;
    }
    // Jump well past the window — the earlier 4 should have expired.
    now += 70_000;
    expect(detector.recordDenial("t", "a")).toBe(false); // this is only the 1st within the new window
    for (let i = 0; i < 3; i++) {
      now += 10;
      expect(detector.recordDenial("t", "a")).toBe(false);
    }
    now += 10;
    expect(detector.recordDenial("t", "a")).toBe(true); // 5th within THIS window
  });

  it("honors a custom threshold/windowMs", () => {
    let now = 0;
    const detector = createProbingDetector({
      nowMs: () => now,
      threshold: 3,
      windowMs: 1_000,
    });
    expect(detector.recordDenial("t", "a")).toBe(false);
    now += 10;
    expect(detector.recordDenial("t", "a")).toBe(false);
    now += 10;
    expect(detector.recordDenial("t", "a")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Fix round 1 — bounded memory (probing counter unbounded-memory + evasion
// finding): a pair denied under the threshold must not be tracked forever,
// and a name-varying flood must not grow the Map without bound.
// ---------------------------------------------------------------------------

describe("createProbingDetector — fix round 1: bounded memory", () => {
  it("a pair denied 1-4 times (under threshold) then idle past the window is evicted — tracked-pair count returns to baseline", () => {
    let now = 0;
    const detector = createProbingDetector({ nowMs: () => now });

    expect(detector.trackedPairCount()).toBe(0);

    for (let i = 0; i < 4; i++) {
      expect(detector.recordDenial("stripe.refund", "codex-cli")).toBe(false);
      now += 100;
    }
    expect(detector.trackedPairCount()).toBe(1);

    // Idle well past the 60s window — "stripe.refund"/"codex-cli" is never
    // denied again. Nothing calls recordDenial for THAT pair again; the
    // eviction below must happen as a side effect of a call for an
    // UNRELATED pair (there is no timer in this module).
    now += DEFAULT_PROBING_WINDOW_MS + 1;
    expect(detector.recordDenial("unrelated.tool", "other-agent")).toBe(false);

    // Baseline (0 stale pairs) + the one new pair just recorded above.
    expect(detector.trackedPairCount()).toBe(1);
  });

  it("does not evict a pair whose under-threshold count is still live within the window", () => {
    let now = 0;
    const detector = createProbingDetector({ nowMs: () => now });

    for (let i = 0; i < 3; i++) {
      detector.recordDenial("t", "a");
      now += 100; // well within the window
    }
    expect(detector.trackedPairCount()).toBe(1);

    // A call for an unrelated pair triggers the sweep, but "t"/"a"'s window
    // is still live (only ~200ms old, window is 60s) — must survive.
    detector.recordDenial("other", "b");
    expect(detector.trackedPairCount()).toBe(2);
  });

  it("a flood of distinct tool names (each denied once, never reaching threshold) stays bounded at maxTrackedPairs", () => {
    let now = 0;
    const cap = 50;
    const detector = createProbingDetector({
      nowMs: () => now,
      maxTrackedPairs: cap,
    });

    for (let i = 0; i < cap * 4; i++) {
      // Distinct tool name every call, same agent — the exact evasion
      // shape the finding describes (varying the tool name to stay under
      // the per-pair threshold while flooding the tracker with new keys).
      expect(detector.recordDenial(`x${i}`, "codex-cli")).toBe(false);
      now += 10; // all well within the 60s window — nothing ages out.
      expect(detector.trackedPairCount()).toBeLessThanOrEqual(cap);
    }
    expect(detector.trackedPairCount()).toBe(cap);
  });

  it("cap eviction drops the least-recently-touched pair, not an arbitrary/most-recent one", () => {
    let now = 0;
    const cap = 3;
    const detector = createProbingDetector({
      nowMs: () => now,
      maxTrackedPairs: cap,
    });

    detector.recordDenial("t0", "a"); // oldest-touched
    now += 10;
    detector.recordDenial("t1", "a");
    now += 10;
    detector.recordDenial("t2", "a");
    now += 10;
    expect(detector.trackedPairCount()).toBe(3);

    // Touch t0 again so it is no longer the least-recently-touched.
    detector.recordDenial("t0", "a");
    now += 10;

    // A 4th distinct pair pushes the map over the cap — t1 (now the
    // least-recently-touched) should be evicted, not t0.
    detector.recordDenial("t3", "a");
    expect(detector.trackedPairCount()).toBe(3);

    // Confirm t1 was actually evicted (not just some other pair): denying
    // it again starts a FRESH count from 1, so 4 more denials (5 total
    // counting this one) are needed to fire — if t1 had survived with its
    // prior 1-denial history intact, firing behavior would differ, but
    // either way the count below proves t1 is being tracked as brand new.
    const fired: boolean[] = [];
    for (let i = 0; i < 5; i++) {
      fired.push(detector.recordDenial("t1", "a"));
      now += 10;
    }
    expect(fired).toEqual([false, false, false, false, true]);
  });
});
