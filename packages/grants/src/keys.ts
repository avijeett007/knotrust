/**
 * @knotrust/grants — Ed25519 identity keygen & key management (P0-E3-T1,
 * rulings R21–R23; architecture §5.1; ratified brief §I2.1).
 *
 * This module owns the ONE Ed25519 identity that signs every grant (E3-T2
 * mints/verifies grants against it via `sign()` here — the private key
 * material never leaves this module; `sign()` is the only operation that
 * touches it).
 *
 * ## Backend architecture (R22) — hardening, not a boundary
 *
 * Two backends behind one `KeyStore` interface:
 *
 * - **keychain** (default where usable) — the 32-byte seed lives as a
 *   secret in the OS keychain via `@napi-rs/keyring` (service `"knotrust"`,
 *   account `"identity"` by default — see `DEFAULT_KEYCHAIN_SERVICE`/
 *   `DEFAULT_KEYCHAIN_ACCOUNT`). `@napi-rs/keyring` is an
 *   `optionalDependency` (prebuilt per-platform binaries, no install
 *   script) loaded via dynamic `import()` inside a try/catch — a missing
 *   native module never hard-fails the `npx` path.
 * - **file** (fallback) — `~/.knotrust/identity.key`, exactly the lowercase
 *   hex seed + trailing newline, created `0600` from the first byte
 *   (`writeFileSync` with `mode` + the `"wx"` flag for `O_EXCL`-style
 *   no-clobber semantics — a losing race just re-reads what the winner
 *   wrote, see `ensureFileSeed`). Read access refuses (does not silently
 *   tighten) any file whose group/other permission bits are set — matching
 *   OpenSSH's stricter-than-AWS-CLI posture, per the task ruling.
 *
 * Backend selection: an explicit `opts.backend` wins; otherwise
 * `KNOTRUST_KEY_BACKEND` (`"file" | "keychain"`); otherwise auto-detect.
 * Auto-detect (and a forced `"keychain"`) both run `probeKeychain` — a
 * real, disposable set/delete round-trip on a distinct `<account>:probe`
 * sub-entry (never the real identity secret) — to find out whether the
 * native module loads AND the OS secret service actually accepts writes
 * (a loaded module on headless Linux without a running secret service
 * still throws on first real use, not at load time). Auto-detect degrades
 * silently to the file backend on either failure, emitting exactly ONE
 * `notify()` call naming the downgrade (default: stderr). A FORCED
 * `"keychain"` that fails the same probe is a hard `Error` instead —
 * "forcing keychain when unusable = hard error, not silent fallback" (R22).
 *
 * Every dependency an auto-detect/probe needs (`loadKeyringModule`,
 * `randomBytes`, `notify`) is injectable via `CreateKeyStoreOptions`
 * specifically so the keychain-less degradation path — and the OS keychain
 * path itself, via a throwaway service name — are both fully testable
 * without a real headless container (R22's testability requirement).
 *
 * ## Key material formats (R21)
 *
 * - Private key: the raw 32-byte Ed25519 seed. Never node:crypto's own
 *   Ed25519 keygen/sign — `generateSeed` only sources RAW ENTROPY from an
 *   injectable `randomBytes` (default `node:crypto`'s, exactly like
 *   `@knotrust/core`'s `ulid.ts` generator), and every derivation/signing
 *   operation on that entropy goes through `@noble/curves/ed25519.js`
 *   (`ed25519.getPublicKey`, `ed25519.sign`) — the audited implementation
 *   architecture §5.1 mandates for grant signing.
 * - Public key: a JWK (`{ kty: "OKP", crv: "Ed25519", x: base64url(raw
 *   pubkey) }`), written to `~/.knotrust/keys/<kid>.jwk.json` with default
 *   permissions — pubkeys are not secret; this is what the verification
 *   flow (architecture §5.4) means by "resolve local pubkey by kid".
 * - `kid`: the first 16 chars of `base64url(SHA-256(raw pubkey))`. This is
 *   an identifier hash, not a keygen/signing operation, so it uses
 *   `node:crypto`'s `createHash("sha256")` — the same "hash, not keygen"
 *   line `@knotrust/core`'s `decision-cache.ts` already draws for its own
 *   unrelated cache-key hash.
 *
 * `~/.knotrust` itself (and its parent, if `KNOTRUST_HOME` points somewhere
 * new) is created/enforced `0700` on every write path, both backends —
 * `~/.knotrust/keys/` is not secret-bearing itself, but the directory that
 * physically contains `identity.key` still needs to keep other local users
 * out. See `docs/03-engineering/local-store-layout.md` for the full tree
 * and — the load-bearing paragraph — why NONE of this is a boundary against
 * the agent process itself.
 */

import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";

// ---------------------------------------------------------------------------
// Public API surface (R23)
// ---------------------------------------------------------------------------

/** OKP/Ed25519 JWK — the public-key wire shape written under `keys/<kid>.jwk.json`. */
export interface Ed25519PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

export interface KnotrustIdentity {
  kid: string;
  publicKeyJwk: Ed25519PublicJwk;
}

export interface KeyStore {
  /** Idempotent: generates the identity on the first call, loads it thereafter. */
  ensureIdentity(): Promise<KnotrustIdentity>;
  getIdentity(): Promise<KnotrustIdentity | null>;
  /** Ed25519 signature with the identity's private key. The key never leaves this module. */
  sign(data: Uint8Array): Promise<Uint8Array>;
  backendKind(): KeyBackendKind;
}

export type KeyBackendKind = "keychain" | "file";

/** Injectable entropy source for seed generation — see module header on why this is the ONLY node:crypto touchpoint for key material. */
export type RandomBytesFn = (byteLength: number) => Uint8Array;

/**
 * The minimal structural shape this module needs from `@napi-rs/keyring`'s
 * `AsyncEntry` (duck-typed rather than importing the upstream `.d.ts`
 * directly, so a fake/injected module in tests satisfies this with zero
 * coupling to the real package's exact declaration shape).
 */
export interface KeyringEntryLike {
  setSecret(secret: Uint8Array): Promise<void>;
  /** Real-world behavior (verified against `@napi-rs/keyring` 1.3.0 on macOS): resolves `null` for a missing entry, never throws NoEntry. */
  getSecret(): Promise<Uint8Array | ReadonlyArray<number> | null | undefined>;
  deleteCredential(): Promise<boolean>;
}

export interface KeyringModule {
  AsyncEntry: new (service: string, account: string) => KeyringEntryLike;
}

export type KeyringModuleLoader = () => Promise<KeyringModule>;

export const DEFAULT_KEYCHAIN_SERVICE = "knotrust";
export const DEFAULT_KEYCHAIN_ACCOUNT = "identity";

export interface CreateKeyStoreOptions {
  /** Forces a backend; overrides `KNOTRUST_KEY_BACKEND`. Forcing `"keychain"` against an unusable keychain is a hard error (R22), never a silent fallback. */
  backend?: KeyBackendKind;
  /** OS keychain service name. Defaults to `"knotrust"`. Tests MUST pass a throwaway name and delete the entry afterwards — never write the real service from a test. */
  keychainService?: string;
  /** OS keychain account name within the service. Defaults to `"identity"`. */
  keychainAccount?: string;
  /** Injectable loader for the native keyring module. Defaults to `import("@napi-rs/keyring")`. Tests use this to simulate load failure or an unusable secret service without a real headless container. */
  loadKeyringModule?: KeyringModuleLoader;
  /** Injectable entropy source. Defaults to `node:crypto`'s `randomBytes`. */
  randomBytes?: RandomBytesFn;
  /** Injectable sink for the single keychain→file downgrade notice. Defaults to `process.stderr.write`. */
  notify?: (message: string) => void;
}

/**
 * `KNOTRUST_HOME` is the one override every path in this module (and,
 * eventually, `@knotrust/store`'s grant/audit files) derives from. Read
 * fresh on every call — never cached — so tests can point it at a fresh
 * temp dir per case without any module-reload gymnastics.
 */
export function resolveKnotrustHome(): string {
  const override = process.env.KNOTRUST_HOME;
  if (override !== undefined && override.trim() !== "") {
    return override;
  }
  return path.join(homedir(), ".knotrust");
}

// ---------------------------------------------------------------------------
// Crypto core — the ONLY place seeds get generated, derived, or signed with.
// ---------------------------------------------------------------------------

const SEED_BYTES = 32;
const KID_CHARS = 16;
const IDENTITY_KEY_FILENAME = "identity.key";
const IDENTITY_KEY_MODE = 0o600;
const KNOTRUST_HOME_MODE = 0o700;

function defaultRandomBytes(byteLength: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(byteLength));
}

function generateSeed(randomBytesFn: RandomBytesFn): Uint8Array {
  const seed = randomBytesFn(SEED_BYTES);
  if (seed.length !== SEED_BYTES) {
    throw new RangeError(
      `knotrust: randomBytes must return exactly ${SEED_BYTES} bytes, got ${seed.length}`,
    );
  }
  return seed;
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(Buffer.from(hex, "hex"));
  if (bytes.length !== SEED_BYTES || bytesToHex(bytes) !== hex.toLowerCase()) {
    throw new Error(
      `knotrust: stored identity seed is corrupt — expected ${SEED_BYTES * 2} lowercase hex chars, got ${hex.length} chars`,
    );
  }
  return bytes;
}

/** `kid` derivation (R21): first 16 chars of base64url(SHA-256(raw pubkey)) — an identifier hash, not keygen; see module header. */
function deriveKid(publicKey: Uint8Array): string {
  const digest = createHash("sha256").update(publicKey).digest();
  return Buffer.from(digest).toString("base64url").slice(0, KID_CHARS);
}

/** The one function that turns a seed into the public `KnotrustIdentity` shape — `@noble/curves/ed25519.js` only. */
function deriveIdentity(seed: Uint8Array): KnotrustIdentity {
  const publicKey = ed25519.getPublicKey(seed);
  return {
    kid: deriveKid(publicKey),
    publicKeyJwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(publicKey).toString("base64url"),
    },
  };
}

function signWithSeed(seed: Uint8Array, data: Uint8Array): Uint8Array {
  return ed25519.sign(data, seed);
}

// ---------------------------------------------------------------------------
// Shared filesystem helpers (both backends write the pubkey JWK here)
// ---------------------------------------------------------------------------

function ensureKnotrustHomeDir(home: string): void {
  mkdirSync(home, { recursive: true, mode: KNOTRUST_HOME_MODE });
  // mkdirSync's `mode` only applies at creation time — enforce it even if
  // `home` pre-existed with looser permissions from something else.
  chmodSync(home, KNOTRUST_HOME_MODE);
}

function writeIdentityJwk(home: string, identity: KnotrustIdentity): void {
  ensureKnotrustHomeDir(home);
  const keysDir = path.join(home, "keys");
  mkdirSync(keysDir, { recursive: true });
  const jwkFilePath = path.join(keysDir, `${identity.kid}.jwk.json`);
  writeFileSync(
    jwkFilePath,
    `${JSON.stringify(identity.publicKeyJwk, null, 2)}\n`,
  );
}

function noIdentityError(): Error {
  return new Error(
    "knotrust: no identity to sign with — call ensureIdentity() first",
  );
}

// ---------------------------------------------------------------------------
// File backend
// ---------------------------------------------------------------------------

function fileKeyPath(home: string): string {
  return path.join(home, IDENTITY_KEY_FILENAME);
}

/**
 * Reads and validates the on-disk seed. Refuses (does not silently accept)
 * any file whose group/other permission bits are set — matching OpenSSH,
 * stricter than the AWS CLI's un-enforced `~/.aws/credentials` default
 * (ruling: "File-mode keys are refused ... if permissions are looser than
 * 0600").
 */
function readFileSeed(home: string): Uint8Array | null {
  const keyPath = fileKeyPath(home);
  if (!existsSync(keyPath)) {
    return null;
  }
  const mode = statSync(keyPath).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `knotrust: refusing to use ${keyPath} — its permissions (${mode.toString(8)}) are ` +
        `looser than 0600 (group/other can read or write it). Fix with: chmod 600 ${keyPath}`,
    );
  }
  const hex = readFileSync(keyPath, "utf8").trim();
  return hexToBytes(hex);
}

/**
 * Generates a seed and writes it with `O_EXCL`-style no-clobber semantics
 * (`flag: "wx"`) if (and only if) nothing is there yet. A losing race
 * (another process/call won the create) re-reads what the winner wrote
 * instead of erroring — `ensureIdentity()` must stay idempotent even under
 * concurrent first calls.
 */
function ensureFileSeed(
  home: string,
  randomBytesFn: RandomBytesFn,
): Uint8Array {
  const existing = readFileSeed(home);
  if (existing) {
    return existing;
  }

  ensureKnotrustHomeDir(home);
  const seed = generateSeed(randomBytesFn);
  const keyPath = fileKeyPath(home);
  try {
    writeFileSync(keyPath, `${bytesToHex(seed)}\n`, {
      mode: IDENTITY_KEY_MODE,
      flag: "wx",
    });
  } catch (err) {
    if (isErrnoException(err) && err.code === "EEXIST") {
      const raced = readFileSeed(home);
      if (raced) {
        return raced;
      }
    }
    throw err;
  }
  return seed;
}

function isErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && "code" in err;
}

function createFileKeyStore(
  home: string,
  randomBytesFn: RandomBytesFn,
): KeyStore {
  return {
    backendKind: () => "file",

    async ensureIdentity() {
      const seed = ensureFileSeed(home, randomBytesFn);
      const identity = deriveIdentity(seed);
      writeIdentityJwk(home, identity);
      return identity;
    },

    async getIdentity() {
      const seed = readFileSeed(home);
      return seed ? deriveIdentity(seed) : null;
    },

    async sign(data: Uint8Array) {
      const seed = readFileSeed(home);
      if (!seed) {
        throw noIdentityError();
      }
      return signWithSeed(seed, data);
    },
  };
}

// ---------------------------------------------------------------------------
// Keychain backend
// ---------------------------------------------------------------------------

function normalizeSecretBytes(
  secret: Uint8Array | ReadonlyArray<number> | null | undefined,
): Uint8Array | null {
  if (secret === null || secret === undefined) {
    return null;
  }
  return secret instanceof Uint8Array ? secret : Uint8Array.from(secret);
}

function createKeychainKeyStore(
  module: KeyringModule,
  service: string,
  account: string,
  home: string,
  randomBytesFn: RandomBytesFn,
): KeyStore {
  const entry = () => new module.AsyncEntry(service, account);

  async function readSeed(): Promise<Uint8Array | null> {
    const secret = normalizeSecretBytes(await entry().getSecret());
    if (!secret) {
      return null;
    }
    const hex = new TextDecoder().decode(secret).trim();
    return hexToBytes(hex);
  }

  return {
    backendKind: () => "keychain",

    async ensureIdentity() {
      let seed = await readSeed();
      if (!seed) {
        seed = generateSeed(randomBytesFn);
        await entry().setSecret(
          new TextEncoder().encode(`${bytesToHex(seed)}\n`),
        );
      }
      const identity = deriveIdentity(seed);
      writeIdentityJwk(home, identity);
      return identity;
    },

    async getIdentity() {
      const seed = await readSeed();
      return seed ? deriveIdentity(seed) : null;
    },

    async sign(data: Uint8Array) {
      const seed = await readSeed();
      if (!seed) {
        throw noIdentityError();
      }
      return signWithSeed(seed, data);
    },
  };
}

// ---------------------------------------------------------------------------
// Backend selection (R22) — probe, auto-detect, forced-backend hard errors.
// ---------------------------------------------------------------------------

async function defaultLoadKeyringModule(): Promise<KeyringModule> {
  const mod = await import("@napi-rs/keyring");
  return mod as unknown as KeyringModule;
}

function defaultNotify(message: string): void {
  process.stderr.write(message.endsWith("\n") ? message : `${message}\n`);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

type ProbeResult =
  | { ok: true; module: KeyringModule }
  | { ok: false; reason: string };

/**
 * A real, disposable set/delete round-trip against `<account>:probe` —
 * never the real identity secret — so we find out whether the native
 * module both LOADS and can actually WRITE to a running secret service.
 * Loading can succeed on headless Linux with no secret service running; the
 * first real write is where that surfaces, so a probe that only reads back
 * an entry (`getSecret()` on a nonexistent entry resolves `null`,
 * not-a-throw — verified against `@napi-rs/keyring` 1.3.0) would miss it.
 */
async function probeKeychain(args: {
  service: string;
  account: string;
  loadKeyringModule: KeyringModuleLoader;
}): Promise<ProbeResult> {
  let mod: KeyringModule;
  try {
    mod = await args.loadKeyringModule();
  } catch (err) {
    return {
      ok: false,
      reason: `native module failed to load (${errorMessage(err)})`,
    };
  }

  try {
    const probeEntry = new mod.AsyncEntry(
      args.service,
      `${args.account}:probe`,
    );
    await probeEntry.setSecret(
      new TextEncoder().encode("knotrust-keychain-probe"),
    );
    try {
      await probeEntry.deleteCredential();
    } catch {
      // Best-effort cleanup only — the write succeeding is what proves usability.
    }
  } catch (err) {
    return {
      ok: false,
      reason: `secret service unusable (${errorMessage(err)})`,
    };
  }

  return { ok: true, module: mod };
}

function formatFallbackNotice(reason: string, keyPath: string): string {
  return (
    `knotrust: OS keychain unavailable (${reason}) — falling back to a 0600 file at ${keyPath}. ` +
    "This is hardening, not a security boundary; see docs/03-engineering/local-store-layout.md.\n"
  );
}

function parseBackendEnv(
  value: string | undefined,
): KeyBackendKind | undefined {
  if (value === undefined || value === "") {
    return undefined;
  }
  if (value === "file" || value === "keychain") {
    return value;
  }
  throw new Error(
    `knotrust: invalid KNOTRUST_KEY_BACKEND=${JSON.stringify(value)} — expected "file" or "keychain"`,
  );
}

/**
 * Resolves the backend and returns a ready `KeyStore`. See module header
 * for the full selection algorithm; this is the only entry point that runs
 * it — every `KeyStore` this function returns already knows its own
 * `backendKind()`, with no further probing on later calls.
 */
export async function createKeyStore(
  opts: CreateKeyStoreOptions = {},
): Promise<KeyStore> {
  const home = resolveKnotrustHome();
  const service = opts.keychainService ?? DEFAULT_KEYCHAIN_SERVICE;
  const account = opts.keychainAccount ?? DEFAULT_KEYCHAIN_ACCOUNT;
  const randomBytesFn = opts.randomBytes ?? defaultRandomBytes;
  const notify = opts.notify ?? defaultNotify;
  const loadKeyringModule = opts.loadKeyringModule ?? defaultLoadKeyringModule;

  const requestedBackend =
    opts.backend ?? parseBackendEnv(process.env.KNOTRUST_KEY_BACKEND);

  if (requestedBackend === "file") {
    return createFileKeyStore(home, randomBytesFn);
  }

  const probe = await probeKeychain({ service, account, loadKeyringModule });

  if (probe.ok) {
    return createKeychainKeyStore(
      probe.module,
      service,
      account,
      home,
      randomBytesFn,
    );
  }

  if (requestedBackend === "keychain") {
    throw new Error(
      `knotrust: KNOTRUST_KEY_BACKEND=keychain was forced but the OS keychain is unusable ` +
        `(${probe.reason}). Unset KNOTRUST_KEY_BACKEND to allow the 0600 file fallback, or fix ` +
        "the OS keychain / secret service.",
    );
  }

  notify(formatFallbackNotice(probe.reason, fileKeyPath(home)));
  return createFileKeyStore(home, randomBytesFn);
}
