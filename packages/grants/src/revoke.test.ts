/**
 * @knotrust/grants — `revokeGrants` unit suite (P0-E3-T4, ruling R39).
 *
 * Locks the library revoke path CLI wiring (P0-E7-T2) will compose:
 *   - selector semantics: `{ jti }`, `{ tool }` (EXACT stored-pattern string,
 *     never glob expansion at revoke time), `{ all: true }`;
 *   - tombstone-first ordering: every matched grant is tombstoned in the
 *     store BEFORE `onInvalidate` fires;
 *   - `onInvalidate` called exactly ONCE per call, regardless of match count,
 *     and NOT called at all on a no-match;
 *   - one `grant_revoked` audit event per revoked grant (hash-chain intact);
 *   - not-found / already-revoked idempotence (`notFound: true`, nothing
 *     re-tombstoned, nothing re-audited).
 *
 * Every test gets a fresh temp `home` shared by the real E4-T1 grant store
 * (`<home>/grants`) and — where audit is exercised — the real E4-T3 audit
 * log (`<home>/audit`). Injected clock/ids; no `Date.now()`, no
 * `~/.knotrust`.
 */

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  type AuditEvent,
  type AuditSink,
  createAuditLog,
  createGrantStore,
  type GrantStore,
} from "@knotrust/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeTestKeyStore } from "./grant-test-kit.js";
import { decodeGrantIndexEntry, mintDurableGrant } from "./lifecycle.js";
import { revokeGrants } from "./revoke.js";

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000;
const keyStore = makeTestKeyStore();

/** Deterministic, store-safe (`/^[A-Za-z0-9_-]+$/`) unique jti generator. */
function makeIdGen(): () => string {
  let n = 0;
  return () => `TESTREVOKE${String(n++).padStart(4, "0")}`;
}

let tempHome: string;
let store: GrantStore;
let sink: AuditSink | undefined;

beforeEach(() => {
  tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-revoke-test-"));
  store = createGrantStore({
    home: tempHome,
    decodeIndexEntry: decodeGrantIndexEntry,
  });
  sink = undefined;
});

afterEach(() => {
  try {
    sink?.close();
  } catch {
    // best-effort — release the audit writer lock
  }
  rmSync(tempHome, { recursive: true, force: true });
});

function makeAudit(): AuditSink {
  sink = createAuditLog({ home: tempHome, nowEpochMs: () => NOW * 1000 });
  return sink;
}

function readAuditEvents(): AuditEvent[] {
  const auditDir = path.join(tempHome, "audit");
  const files = readdirSync(auditDir)
    .filter((name) => /^\d{6}\.jsonl$/.test(name))
    .sort();
  const events: AuditEvent[] = [];
  for (const file of files) {
    const raw = readFileSync(path.join(auditDir, file), "utf8");
    for (const line of raw.split("\n")) {
      if (line.length > 0) events.push(JSON.parse(line) as AuditEvent);
    }
  }
  return events;
}

/** Mints a durable grant with the given tool pattern; returns its jti. */
async function seedGrant(
  tool: string,
  idGen: () => string,
  audit?: AuditSink,
): Promise<string> {
  const { jti } = await mintDurableGrant(
    {
      principal: { type: "user", id: "avijeett007@gmail.com" },
      agent: "*",
      tool,
      scope: {},
      tier: "sensitive",
      envelopeScope: "personal",
      ttlSeconds: 2_592_000,
    },
    {
      store,
      keyStore,
      nowEpochSeconds: NOW,
      generateId: idGen,
      ...(audit !== undefined ? { audit } : {}),
    },
  );
  return jti;
}

// ---------------------------------------------------------------------------
// { jti } selector
// ---------------------------------------------------------------------------

describe("revokeGrants({ jti }) — R39", () => {
  it("tombstones the grant, returns { revoked: [jti], notFound: false }, and calls onInvalidate exactly once", async () => {
    const jti = await seedGrant("github.*", makeIdGen());
    const onInvalidate = vi.fn();

    const result = revokeGrants({ jti }, { store, onInvalidate });

    expect(result).toEqual({ revoked: [jti], notFound: false });
    expect(onInvalidate).toHaveBeenCalledTimes(1);
    expect(store.get(jti).status).toBe("revoked");
    // A revoked grant never comes back from list().
    expect(store.list().active).toHaveLength(0);
  });

  it("fires onInvalidate only AFTER the tombstone has landed (tombstone-first ordering)", async () => {
    const jti = await seedGrant("github.*", makeIdGen());
    const statusAtInvalidate: string[] = [];
    const onInvalidate = vi.fn(() => {
      statusAtInvalidate.push(store.get(jti).status);
    });

    revokeGrants({ jti }, { store, onInvalidate });

    expect(statusAtInvalidate).toEqual(["revoked"]);
  });

  it("an unknown jti → { revoked: [], notFound: true }; onInvalidate NOT called", () => {
    const onInvalidate = vi.fn();
    const result = revokeGrants(
      { jti: "TESTREVOKEUNKNOWN" },
      { store, onInvalidate },
    );

    expect(result).toEqual({ revoked: [], notFound: true });
    expect(onInvalidate).not.toHaveBeenCalled();
  });

  it("an already-revoked jti is idempotent: notFound true, no re-tombstone, no audit event, no invalidate", async () => {
    const audit = makeAudit();
    const jti = await seedGrant("github.*", makeIdGen());
    revokeGrants({ jti }, { store, audit });
    const eventsAfterFirst = readAuditEvents().length;

    const onInvalidate = vi.fn();
    const second = revokeGrants({ jti }, { store, audit, onInvalidate });

    expect(second).toEqual({ revoked: [], notFound: true });
    expect(onInvalidate).not.toHaveBeenCalled();
    audit.flush();
    expect(readAuditEvents()).toHaveLength(eventsAfterFirst);
  });
});

// ---------------------------------------------------------------------------
// { tool } selector — EXACT stored-pattern string (R39)
// ---------------------------------------------------------------------------

describe("revokeGrants({ tool }) — exact stored-pattern string, no glob expansion (R39)", () => {
  it('revokes the grant stored with pattern "github.*" and NOT a sibling stored with the concrete name', async () => {
    const idGen = makeIdGen();
    const patternJti = await seedGrant("github.*", idGen);
    const concreteJti = await seedGrant("github.create_issue", idGen);
    const onInvalidate = vi.fn();

    const result = revokeGrants({ tool: "github.*" }, { store, onInvalidate });

    expect(result.notFound).toBe(false);
    expect(result.revoked).toEqual([patternJti]);
    expect(store.get(patternJti).status).toBe("revoked");
    expect(store.get(concreteJti).status).toBe("active");
    expect(onInvalidate).toHaveBeenCalledTimes(1);
  });

  it('revoking a CONCRETE tool name never reaches a broader glob grant that would MATCH it ("github.create_issue" does not revoke "github.*")', async () => {
    const idGen = makeIdGen();
    const patternJti = await seedGrant("github.*", idGen);
    const concreteJti = await seedGrant("github.create_issue", idGen);

    const result = revokeGrants({ tool: "github.create_issue" }, { store });

    expect(result.revoked).toEqual([concreteJti]);
    expect(store.get(patternJti).status).toBe("active");
  });

  it("a tool string matching no stored grant → notFound true, onInvalidate NOT called", async () => {
    await seedGrant("github.*", makeIdGen());
    const onInvalidate = vi.fn();

    const result = revokeGrants(
      { tool: "stripe.create_refund" },
      { store, onInvalidate },
    );

    expect(result).toEqual({ revoked: [], notFound: true });
    expect(onInvalidate).not.toHaveBeenCalled();
    expect(store.list().active).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// { all: true } selector
// ---------------------------------------------------------------------------

describe("revokeGrants({ all: true }) — R39", () => {
  it("revokes every active grant; onInvalidate exactly ONCE for the whole batch, after ALL tombstones landed", async () => {
    const idGen = makeIdGen();
    const jtis = [
      await seedGrant("github.*", idGen),
      await seedGrant("stripe.create_refund", idGen),
      await seedGrant("slack.*", idGen),
    ];
    const revokedStatusesAtInvalidate: string[][] = [];
    const onInvalidate = vi.fn(() => {
      revokedStatusesAtInvalidate.push(jtis.map((j) => store.get(j).status));
    });

    const result = revokeGrants({ all: true }, { store, onInvalidate });

    expect(result.notFound).toBe(false);
    expect([...result.revoked].sort()).toEqual([...jtis].sort());
    expect(onInvalidate).toHaveBeenCalledTimes(1);
    // At the moment onInvalidate fired, every tombstone was already down.
    expect(revokedStatusesAtInvalidate).toEqual([
      ["revoked", "revoked", "revoked"],
    ]);
    expect(store.list().active).toHaveLength(0);
  });

  it("an empty store → notFound true, nothing revoked, no invalidate", () => {
    const onInvalidate = vi.fn();
    const result = revokeGrants({ all: true }, { store, onInvalidate });

    expect(result).toEqual({ revoked: [], notFound: true });
    expect(onInvalidate).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Invalidate-on-partial-failure (R43) — the fix under test here: onInvalidate
// must fire once whenever AT LEAST ONE tombstone landed, even if a later
// audit append (or a later grant in the batch) throws, so a composed cache
// is never left serving stale cached ALLOWs for tombstones that already
// landed. Zero tombstones landed must still never invalidate (unchanged).
// ---------------------------------------------------------------------------

describe("revokeGrants — invalidate on partial failure (R43)", () => {
  it("audit sink throws on the Nth append during a 3-grant revoke-all: the error propagates, the tombstones already landed stay down, and onInvalidate fires exactly once", async () => {
    const idGen = makeIdGen();
    const jtis = [
      await seedGrant("github.*", idGen),
      await seedGrant("stripe.create_refund", idGen),
      await seedGrant("slack.*", idGen),
    ];
    const onInvalidate = vi.fn();
    const boom = new Error("audit sink is down mid-batch");
    let calls = 0;
    const flakyAudit: AuditSink = {
      append: (event) => {
        calls += 1;
        if (calls === 2) throw boom;
        return {
          ...event,
          seq: calls,
          prevHash: "0".repeat(64),
          hash: "0".repeat(64),
          ts: new Date(NOW * 1000).toISOString(),
        };
      },
      flush: () => {},
      close: () => {},
      verify: () => ({ ok: true, events: calls }),
      onAppend: () => () => {},
    };

    expect(() =>
      revokeGrants({ all: true }, { store, audit: flakyAudit, onInvalidate }),
    ).toThrow(boom);

    // The Nth (2nd) append throw happens right after ITS OWN grant's
    // tombstone already landed (tombstone-first ordering), so exactly two
    // of the three grants are tombstoned by the time the error propagates;
    // the third was never reached.
    const revokedCount = jtis.filter(
      (jti) => store.get(jti).status === "revoked",
    ).length;
    expect(revokedCount).toBe(2);
    expect(store.list().active).toHaveLength(1);

    // The whole point of R43: already-tombstoned grants must not be left
    // being served from a stale cache — onInvalidate still fires, exactly
    // once, despite the batch never finishing.
    expect(onInvalidate).toHaveBeenCalledTimes(1);
  });

  it("zero tombstones landed (no match) never invalidates, even though onInvalidate is wired", () => {
    const onInvalidate = vi.fn();

    const result = revokeGrants({ all: true }, { store, onInvalidate });

    expect(result).toEqual({ revoked: [], notFound: true });
    expect(onInvalidate).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Audit wiring — one grant_revoked event per revoked grant (R39/R40)
// ---------------------------------------------------------------------------

describe("revokeGrants — audit wiring (grant_revoked)", () => {
  it("appends one grant_revoked event carrying grantRefs=[jti] and the grant's subject/agent/tool", async () => {
    const audit = makeAudit();
    const jti = await seedGrant("github.*", makeIdGen());

    revokeGrants({ jti }, { store, audit });
    audit.flush();

    const events = readAuditEvents();
    expect(events).toHaveLength(1);
    const event = events[0];
    expect(event?.type).toBe("grant_revoked");
    expect(event?.grantRefs).toEqual([jti]);
    expect(event?.subject).toBe("avijeett007@gmail.com");
    expect(event?.agent).toBe("*");
    expect(event?.tool).toBe("github.*");
    expect(event?.reason).toContain(jti);
    expect(audit.verify()).toEqual({ ok: true, events: 1 });
  });

  it("revoke-all over N grants appends N grant_revoked events, chain intact", async () => {
    const audit = makeAudit();
    const idGen = makeIdGen();
    const jtis = [
      await seedGrant("github.*", idGen),
      await seedGrant("stripe.*", idGen),
    ];

    revokeGrants({ all: true }, { store, audit });
    audit.flush();

    const events = readAuditEvents();
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.type)).toEqual([
      "grant_revoked",
      "grant_revoked",
    ]);
    expect([...events.flatMap((e) => e.grantRefs ?? [])].sort()).toEqual(
      [...jtis].sort(),
    );
    expect(audit.verify()).toEqual({ ok: true, events: 2 });
  });

  it("without an audit sink, revocation still fully happens (tombstone + invalidate)", async () => {
    const jti = await seedGrant("github.*", makeIdGen());
    const onInvalidate = vi.fn();

    const result = revokeGrants({ jti }, { store, onInvalidate });

    expect(result.revoked).toEqual([jti]);
    expect(store.get(jti).status).toBe("revoked");
    expect(onInvalidate).toHaveBeenCalledTimes(1);
  });
});
