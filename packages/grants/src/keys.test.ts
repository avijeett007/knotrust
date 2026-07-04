import { randomBytes as nodeRandomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createKeyStore,
  DEFAULT_KEYCHAIN_ACCOUNT,
  DEFAULT_KEYCHAIN_SERVICE,
  type KeyringModule,
  resolveKnotrustHome,
} from "./keys.js";

// ---------------------------------------------------------------------------
// Golden vector (cross-validated against node:crypto's independent Ed25519
// implementation — see task report for derivation). This is what makes the
// "noble-only derivation" acceptance case a real assertion instead of just
// "it didn't throw": the seed, its derived public key, its JWK `x`, and its
// `kid` are ALL fixed, known-correct values.
// ---------------------------------------------------------------------------
const GOLDEN_SEED_HEX =
  "4c8a67b53eb24b1197b90d0339594e5d2cdd953c2fabc418f1231235c126ee29";
const GOLDEN_PUBLIC_KEY_HEX =
  "5548dcfab88e8cf7d068210fcac0a9d7c270ece03ab5b3b0e78131a391b72844";
const GOLDEN_PUBLIC_KEY_BASE64URL =
  "VUjc-riOjPfQaCEPysCp18Jw7OA6tbOw54Exo5G3KEQ";
const GOLDEN_KID = "psCF7ZupReLC5Tp8";

// ---------------------------------------------------------------------------
// Test harness — every test gets its own temp KNOTRUST_HOME. NEVER the real
// ~/.knotrust (brief hygiene requirement). `resolveKnotrustHome()`'s only
// override mechanism is the KNOTRUST_HOME env var, so tests drive it that
// way and always restore/delete it in afterEach.
// ---------------------------------------------------------------------------
let tempHome: string;
const ORIGINAL_KNOTRUST_HOME = process.env.KNOTRUST_HOME;
const ORIGINAL_KEY_BACKEND = process.env.KNOTRUST_KEY_BACKEND;

beforeEach(() => {
  tempHome = mkdtempSync(path.join(tmpdir(), "knotrust-keys-test-"));
  process.env.KNOTRUST_HOME = tempHome;
  delete process.env.KNOTRUST_KEY_BACKEND;
});

afterEach(() => {
  rmSync(tempHome, { recursive: true, force: true });
  if (ORIGINAL_KNOTRUST_HOME === undefined) {
    delete process.env.KNOTRUST_HOME;
  } else {
    process.env.KNOTRUST_HOME = ORIGINAL_KNOTRUST_HOME;
  }
  if (ORIGINAL_KEY_BACKEND === undefined) {
    delete process.env.KNOTRUST_KEY_BACKEND;
  } else {
    process.env.KNOTRUST_KEY_BACKEND = ORIGINAL_KEY_BACKEND;
  }
});

function identityKeyPath(home: string): string {
  return path.join(home, "identity.key");
}

function jwkPath(home: string, kid: string): string {
  return path.join(home, "keys", `${kid}.jwk.json`);
}

// ---------------------------------------------------------------------------
// Fake keyring backends — the injectable-loader mechanism (R22) is what
// makes the keychain-less degradation path testable without a real
// container. These never touch the real OS keychain.
// ---------------------------------------------------------------------------

/** A working in-memory fake of the `@napi-rs/keyring` surface this module needs. */
function makeWorkingFakeKeyringModule(): KeyringModule & {
  store: Map<string, Uint8Array>;
} {
  const store = new Map<string, Uint8Array>();
  class FakeAsyncEntry {
    #key: string;
    constructor(service: string, account: string) {
      this.#key = `${service}\0${account}`;
    }
    async setSecret(secret: Uint8Array): Promise<void> {
      store.set(this.#key, secret);
    }
    async getSecret(): Promise<Uint8Array | null> {
      return store.get(this.#key) ?? null;
    }
    async deleteCredential(): Promise<boolean> {
      return store.delete(this.#key);
    }
  }
  return { AsyncEntry: FakeAsyncEntry, store };
}

/** Simulates a loaded native module whose secret service is unusable (e.g. headless Linux, no D-Bus). */
function makeUnusableFakeKeyringModule(
  message = "no secret service found",
): KeyringModule {
  class UnusableAsyncEntry {
    async setSecret(): Promise<void> {
      throw new Error(message);
    }
    async getSecret(): Promise<Uint8Array | null> {
      throw new Error(message);
    }
    async deleteCredential(): Promise<boolean> {
      throw new Error(message);
    }
  }
  return { AsyncEntry: UnusableAsyncEntry };
}

// ---------------------------------------------------------------------------
// resolveKnotrustHome
// ---------------------------------------------------------------------------

describe("resolveKnotrustHome", () => {
  it("honors the KNOTRUST_HOME env override", () => {
    expect(resolveKnotrustHome()).toBe(tempHome);
  });

  it("falls back to ~/.knotrust when KNOTRUST_HOME is unset", () => {
    delete process.env.KNOTRUST_HOME;
    expect(resolveKnotrustHome()).toMatch(/\.knotrust$/);
    expect(resolveKnotrustHome()).not.toBe(tempHome);
    // Restored in afterEach from ORIGINAL_KNOTRUST_HOME; re-set here so this
    // test doesn't leak into others within the same file run.
    process.env.KNOTRUST_HOME = tempHome;
  });
});

// ---------------------------------------------------------------------------
// File backend
// ---------------------------------------------------------------------------

describe("file backend", () => {
  it("backendKind() reports 'file' when forced", async () => {
    const store = await createKeyStore({ backend: "file" });
    expect(store.backendKind()).toBe("file");
  });

  it("ensureIdentity() creates identity.key at exactly 0600, containing the lowercase hex seed + trailing newline", async () => {
    const store = await createKeyStore({ backend: "file" });
    await store.ensureIdentity();

    const keyPath = identityKeyPath(tempHome);
    expect(existsSync(keyPath)).toBe(true);

    const mode = statSync(keyPath).mode & 0o777;
    expect(mode).toBe(0o600);

    const content = readFileSync(keyPath, "utf8");
    expect(content).toMatch(/^[0-9a-f]{64}\n$/);
  });

  it("creates ~/.knotrust as 0700", async () => {
    const store = await createKeyStore({ backend: "file" });
    await store.ensureIdentity();
    const mode = statSync(tempHome).mode & 0o777;
    expect(mode).toBe(0o700);
  });

  it("writes the public key JWK to keys/<kid>.jwk.json (OKP/Ed25519, default perms)", async () => {
    const store = await createKeyStore({ backend: "file" });
    const identity = await store.ensureIdentity();

    const p = jwkPath(tempHome, identity.kid);
    expect(existsSync(p)).toBe(true);
    const jwk = JSON.parse(readFileSync(p, "utf8"));
    expect(jwk).toEqual(identity.publicKeyJwk);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(typeof jwk.x).toBe("string");
  });

  it("ensureIdentity() is idempotent: second call loads the same identity instead of regenerating", async () => {
    const store = await createKeyStore({ backend: "file" });
    const first = await store.ensureIdentity();
    const seedAfterFirst = readFileSync(identityKeyPath(tempHome), "utf8");

    const second = await store.ensureIdentity();
    const seedAfterSecond = readFileSync(identityKeyPath(tempHome), "utf8");

    expect(second).toEqual(first);
    expect(seedAfterSecond).toBe(seedAfterFirst);
  });

  it("getIdentity() returns null before ensureIdentity(), and the identity after", async () => {
    const store = await createKeyStore({ backend: "file" });
    expect(await store.getIdentity()).toBeNull();

    const identity = await store.ensureIdentity();
    expect(await store.getIdentity()).toEqual(identity);
  });

  it("sign() throws before an identity exists, and produces a verifiable Ed25519 signature after", async () => {
    const store = await createKeyStore({ backend: "file" });
    await expect(store.sign(new Uint8Array([1, 2, 3]))).rejects.toThrow();

    const identity = await store.ensureIdentity();
    const data = new TextEncoder().encode("hello knotrust");
    const sig = await store.sign(data);

    const rawPub = Buffer.from(identity.publicKeyJwk.x, "base64url");
    expect(ed25519.verify(sig, data, rawPub)).toBe(true);
  });

  it("refuses a 0644 key file with remediation text naming 'chmod 600'", async () => {
    const store = await createKeyStore({ backend: "file" });
    await store.ensureIdentity();
    chmodSync(identityKeyPath(tempHome), 0o644);

    await expect(store.getIdentity()).rejects.toThrow(/chmod 600/);
    await expect(store.ensureIdentity()).rejects.toThrow(/chmod 600/);
    await expect(store.sign(new Uint8Array([1]))).rejects.toThrow(/chmod 600/);
  });

  it("does not clobber an existing identity.key (no-clobber semantics) — loads the pre-seeded golden vector rather than regenerating", async () => {
    // Pre-seed the file exactly as the file backend itself would write it.
    const { mkdirSync, writeFileSync } = await import("node:fs");
    mkdirSync(tempHome, { recursive: true, mode: 0o700 });
    writeFileSync(identityKeyPath(tempHome), `${GOLDEN_SEED_HEX}\n`, {
      mode: 0o600,
    });

    const store = await createKeyStore({ backend: "file" });
    const identity = await store.ensureIdentity();

    expect(identity.kid).toBe(GOLDEN_KID);
    expect(identity.publicKeyJwk.x).toBe(GOLDEN_PUBLIC_KEY_BASE64URL);
    // The file on disk must be untouched (same seed) — proves no clobber happened.
    expect(readFileSync(identityKeyPath(tempHome), "utf8")).toBe(
      `${GOLDEN_SEED_HEX}\n`,
    );
  });

  it("two fresh homes produce two different keys (keygen is deterministic-free)", async () => {
    const homeA = tempHome;
    const homeB = mkdtempSync(path.join(tmpdir(), "knotrust-keys-test-b-"));
    try {
      process.env.KNOTRUST_HOME = homeA;
      const storeA = await createKeyStore({ backend: "file" });
      const identityA = await storeA.ensureIdentity();

      process.env.KNOTRUST_HOME = homeB;
      const storeB = await createKeyStore({ backend: "file" });
      const identityB = await storeB.ensureIdentity();

      expect(identityA.kid).not.toBe(identityB.kid);
      expect(identityA.publicKeyJwk.x).not.toBe(identityB.publicKeyJwk.x);
    } finally {
      rmSync(homeB, { recursive: true, force: true });
      process.env.KNOTRUST_HOME = homeA;
    }
  });
});

// ---------------------------------------------------------------------------
// noble-only derivation (golden vector + source guard)
// ---------------------------------------------------------------------------

describe("noble-only derivation", () => {
  it("derives kid and JWK x from a known seed exactly as specified (kid = first 16 chars of base64url(SHA-256(pubkey))))", async () => {
    const { mkdirSync, writeFileSync } = await import("node:fs");
    mkdirSync(tempHome, { recursive: true, mode: 0o700 });
    writeFileSync(identityKeyPath(tempHome), `${GOLDEN_SEED_HEX}\n`, {
      mode: 0o600,
    });

    const store = await createKeyStore({ backend: "file" });
    const identity = await store.getIdentity();

    expect(identity).not.toBeNull();
    expect(identity?.kid).toBe(GOLDEN_KID);
    expect(identity?.kid.length).toBe(16);
    expect(identity?.publicKeyJwk).toEqual({
      kty: "OKP",
      crv: "Ed25519",
      x: GOLDEN_PUBLIC_KEY_BASE64URL,
    });
    expect(
      Buffer.from(identity?.publicKeyJwk.x ?? "", "base64url").toString("hex"),
    ).toBe(GOLDEN_PUBLIC_KEY_HEX);
  });

  it("keys.ts never calls node:crypto's own Ed25519 keygen/sign primitives — derivation and signing go through @noble/curves only", async () => {
    const { readFileSync: readSourceFile } = await import("node:fs");
    const source = readSourceFile(
      new URL("./keys.ts", import.meta.url),
      "utf8",
    );
    for (const banned of [
      "generateKeyPairSync",
      "generateKeyPair(",
      "createSign",
      "createVerify",
    ]) {
      expect(source).not.toContain(banned);
    }
    // The seed's entropy source (crypto.randomBytes) IS permitted (ruling
    // R22/brief) — only keygen/derivation/signing must stay noble-only.
    expect(source).toContain("@noble/curves/ed25519.js");
  });
});

// ---------------------------------------------------------------------------
// Keychain backend — injected fakes (never a real container needed)
// ---------------------------------------------------------------------------

describe("keychain backend (injected fake)", () => {
  it("lands the identity in the fake keychain and writes no plaintext key file", async () => {
    const fakeModule = makeWorkingFakeKeyringModule();
    const notify = vi.fn();
    const store = await createKeyStore({
      backend: "keychain",
      keychainService: "knotrust-test-fake",
      loadKeyringModule: async () => fakeModule,
      notify,
    });

    expect(store.backendKind()).toBe("keychain");
    const identity = await store.ensureIdentity();

    expect(existsSync(identityKeyPath(tempHome))).toBe(false);
    expect(notify).not.toHaveBeenCalled();

    // Assert directly against the fake keyring's own storage — not just our wrapper.
    const raw = fakeModule.store.get("knotrust-test-fake\0identity");
    expect(raw).toBeDefined();
    expect(new TextDecoder().decode(raw).trim()).toMatch(/^[0-9a-f]{64}$/);

    // Public JWK still lands on disk (pubkeys are not secret).
    expect(existsSync(jwkPath(tempHome, identity.kid))).toBe(true);
  });

  it("getIdentity()/sign() round-trip through the fake keychain", async () => {
    const fakeModule = makeWorkingFakeKeyringModule();
    const store = await createKeyStore({
      backend: "keychain",
      keychainService: "knotrust-test-fake",
      loadKeyringModule: async () => fakeModule,
    });

    expect(await store.getIdentity()).toBeNull();
    const identity = await store.ensureIdentity();
    expect(await store.getIdentity()).toEqual(identity);

    const data = new TextEncoder().encode("sign me");
    const sig = await store.sign(data);
    const rawPub = Buffer.from(identity.publicKeyJwk.x, "base64url");
    expect(ed25519.verify(sig, data, rawPub)).toBe(true);
  });

  it("falls back to the file backend with a single stderr-style notice when the native module fails to load", async () => {
    const notify = vi.fn();
    const store = await createKeyStore({
      loadKeyringModule: async () => {
        throw new Error("Cannot find native binding");
      },
      notify,
    });

    expect(store.backendKind()).toBe("file");
    expect(notify).toHaveBeenCalledTimes(1);
    const [message] = notify.mock.calls[0] as [string];
    expect(message).toMatch(/keychain/i);
    expect(message).toMatch(/0600/);

    await store.ensureIdentity();
    expect(existsSync(identityKeyPath(tempHome))).toBe(true);
    expect(statSync(identityKeyPath(tempHome)).mode & 0o777).toBe(0o600);
  });

  it("falls back to the file backend with a single notice when the secret service is unusable", async () => {
    const notify = vi.fn();
    const store = await createKeyStore({
      loadKeyringModule: async () => makeUnusableFakeKeyringModule(),
      notify,
    });

    expect(store.backendKind()).toBe("file");
    expect(notify).toHaveBeenCalledTimes(1);

    await store.ensureIdentity();
    expect(existsSync(identityKeyPath(tempHome))).toBe(true);
  });

  it("KNOTRUST_KEY_BACKEND=keychain forced against an unusable keychain is a hard error, not a silent fallback", async () => {
    const notify = vi.fn();
    await expect(
      createKeyStore({
        backend: "keychain",
        loadKeyringModule: async () =>
          makeUnusableFakeKeyringModule("no D-Bus secret service"),
        notify,
      }),
    ).rejects.toThrow(/keychain/i);

    expect(notify).not.toHaveBeenCalled();
    expect(existsSync(identityKeyPath(tempHome))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// KNOTRUST_KEY_BACKEND env var
// ---------------------------------------------------------------------------

describe("KNOTRUST_KEY_BACKEND env var", () => {
  it("'file' forces the file backend and never invokes the keyring loader", async () => {
    process.env.KNOTRUST_KEY_BACKEND = "file";
    const loadKeyringModule = vi.fn(async () => makeWorkingFakeKeyringModule());

    const store = await createKeyStore({ loadKeyringModule });
    expect(store.backendKind()).toBe("file");
    expect(loadKeyringModule).not.toHaveBeenCalled();
  });

  it("'keychain' forces the keychain backend when usable", async () => {
    process.env.KNOTRUST_KEY_BACKEND = "keychain";
    const fakeModule = makeWorkingFakeKeyringModule();

    const store = await createKeyStore({
      loadKeyringModule: async () => fakeModule,
    });
    expect(store.backendKind()).toBe("keychain");
  });

  it("an invalid value throws a clear error", async () => {
    process.env.KNOTRUST_KEY_BACKEND = "totally-invalid";
    await expect(createKeyStore()).rejects.toThrow(/KNOTRUST_KEY_BACKEND/);
  });

  it("an explicit opts.backend overrides the env var", async () => {
    process.env.KNOTRUST_KEY_BACKEND = "keychain";
    const store = await createKeyStore({ backend: "file" });
    expect(store.backendKind()).toBe("file");
  });
});

// ---------------------------------------------------------------------------
// Real OS keychain (macOS) — throwaway service name, cleaned up unconditionally.
// NEVER writes the real "knotrust" service.
// ---------------------------------------------------------------------------

describe.skipIf(process.platform !== "darwin")(
  "real macOS keychain (throwaway service)",
  () => {
    let throwawayService: string;

    beforeEach(() => {
      throwawayService = `knotrust-test-${nodeRandomBytes(8).toString("hex")}`;
      expect(throwawayService).not.toBe(DEFAULT_KEYCHAIN_SERVICE);
    });

    afterEach(async () => {
      const { AsyncEntry } = await import("@napi-rs/keyring");
      for (const account of [
        DEFAULT_KEYCHAIN_ACCOUNT,
        `${DEFAULT_KEYCHAIN_ACCOUNT}:probe`,
      ]) {
        try {
          await new AsyncEntry(throwawayService, account).deleteCredential();
        } catch {
          // best-effort cleanup only
        }
      }
    });

    it("lands the identity in the real OS keychain with no plaintext key file on disk", async () => {
      const store = await createKeyStore({
        backend: "keychain",
        keychainService: throwawayService,
      });

      expect(store.backendKind()).toBe("keychain");
      const identity = await store.ensureIdentity();

      expect(existsSync(identityKeyPath(tempHome))).toBe(false);

      const { AsyncEntry } = await import("@napi-rs/keyring");
      const entry = new AsyncEntry(throwawayService, DEFAULT_KEYCHAIN_ACCOUNT);
      const secret = await entry.getSecret();
      expect(secret).not.toBeNull();

      const rawPub = Buffer.from(identity.publicKeyJwk.x, "base64url");
      const sig = await store.sign(new Uint8Array([9, 9, 9]));
      expect(ed25519.verify(sig, new Uint8Array([9, 9, 9]), rawPub)).toBe(true);
    });
  },
);
