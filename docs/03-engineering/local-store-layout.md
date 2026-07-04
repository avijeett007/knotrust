# The `~/.knotrust/` local store

KnoTrust is local-first and zero-backend in Phase 0–1 (architecture §5, §7.3; brief §D): the store *is* the cache, and everything it needs to make and audit a decision lives under one directory tree on the machine `knotrust` runs on. This doc is the map of that tree, the override that redirects it, and — because the tree holds the private key that signs every grant — the honest doctrine about what protecting that key does and does not buy you.

## 1. Root and override

The root is `~/.knotrust` — resolved by `resolveKnotrustHome()` (`packages/grants/src/keys.ts`), the single function every path in this tree derives from:

```
KNOTRUST_HOME env var set and non-empty  →  that path, verbatim (it IS the root; nothing is appended)
otherwise                                →  os.homedir() + "/.knotrust"
```

`KNOTRUST_HOME` exists so tests (and, later, any tooling that wants an isolated store) can point the whole tree at a temp directory — real test suites in this repo **never** touch the real `~/.knotrust`; every `keys.ts` test sets `KNOTRUST_HOME` to a fresh `mkdtemp()` directory in `beforeEach` and removes it in `afterEach`.

The root directory itself is created — and its permissions actively re-enforced on every write, even if it already existed with looser permissions from something else — as **`0700`**: only the owning user can list or enter it at all, independent of what lives inside.

## 2. Tree as of P0

```
~/.knotrust/
├── identity.key           # Ed25519 seed, FILE-BACKEND FALLBACK ONLY (P0-E3-T1, this doc)
├── keys/
│   └── <kid>.jwk.json      # public keys (yours + anyone else's you resolve), by kid (P0-E3-T1)
├── grants/                 # signed grant JWS files + revocation/replay ledgers (P0-E4-T1, this doc)
│   ├── <jti>.jws            # the token text, exactly, plus a trailing newline
│   ├── tombstones/
│   │   └── <jti>.json        # revocation tombstone: { jti, revokedAt, reason? }
│   └── consumed/
│       └── <jti>              # empty marker — the single-use/replay-protection ledger
├── audit/                 # append-only JSONL, hash-chained (P0-E4-T3, this doc)
│   ├── <yyyymm>.jsonl       # one hash-chained event per line, seq/hash CONTINUOUS across files
│   ├── <yyyymm>.jsonl.torn  # quarantined torn tail fragment(s) — only present after a crash mid-append
│   └── .lock                # exclusive "wx" + pid — single-writer-process enforcement
├── servers/               # per-server tool inventories (P0-E5-T2, this doc)
│   └── <server>/
│       └── tool-inventory.json  # captured annotations + inputSchema fingerprint per tool, keyed by tool name
└── pending/               # block-and-wait approval URLs for headless/Desktop clients [arrives with P0-E6-T2]
```

`identity.key`, `keys/`, `grants/`, `audit/`, and `servers/` exist as of this task (P0-E4-T1 landed `grants/`, P0-E4-T3 landed `audit/`, P0-E5-T2 landed `servers/`); `pending/` is named here so this doc is the single place the eventual full tree is documented, tagged with the task that adds it. Nothing about its shape is decided by this task.

### `identity.key` — the file-backend fallback, not the default

**The OS keychain is the default where usable (ratified, brief §I2.1) — `identity.key` only exists when the keychain backend was unavailable or unusable, and a real production run may have no `identity.key` at all.** When it does exist:

- Contents are **exactly** the 32-byte Ed25519 seed as lowercase hex, plus a trailing newline. Nothing else — no JSON envelope, no metadata.
- Permissions are **`0600` from the moment of creation** (`writeFileSync` with `mode: 0o600` and the `"wx"` flag — `O_EXCL`-style, so two racing first-run processes can't clobber each other; the loser just re-reads what the winner wrote). This is already stricter than well-known prior art: the AWS CLI's `~/.aws/credentials` does not default to `600` at all. It matches OpenSSH's posture.
- **Read access is refused, not silently accepted, if group or other has any permission bit set** (`mode & 0o077 !== 0` — so `0640`, `0644`, `0664`, etc. are all refused; `0600` and `0400` are both fine). The error names the fix directly: `chmod 600 <path>`. This refusal — not just a warning — is what "stricter than AWS CLI, matching OpenSSH" means in practice: OpenSSH refuses to *use* an insecurely-permissioned private key rather than trusting it anyway.

### `keys/<kid>.jwk.json` — public keys, not secret

Every identity's public key is written here as a JWK — `{ "kty": "OKP", "crv": "Ed25519", "x": "<base64url raw pubkey>" }` — under a filename derived from its `kid`. This is what the grant verification flow (architecture §5.4) means by "resolve local pubkey by kid, `~/.knotrust/keys/`": a grant's JWS header carries `kid`, and verification is a local file lookup, never a network call.

`kid` is **the first 16 characters of `base64url(SHA-256(raw 32-byte public key)))`** — stable and fully derived from the public key, documented here and in `packages/grants/src/keys.ts` (`deriveKid`). Public keys are not secret: this file is written with default filesystem permissions (no `mode` override), unlike `identity.key`.

**Expected behavior: swapping a `keys/<kid>.jwk.json` file invalidates every grant signed under the original key (P0-E11-T4, `docs/02-architecture/security-threat-model.md` T4/T5).** `verifyGrant` (`packages/grants/src/verify.ts`) resolves a grant's Ed25519 public key purely by reading this file by `kid` — it has no independent memory of "the key that used to be here." If this file's content is overwritten with a *different* key (same `kid` filename — e.g. a same-UID attacker, a corrupted restore, or a manual key-management mistake), every existing grant whose JWS header names that `kid` now fails `verifyGrant`'s signature check (`grant_invalid_signature`) the next time it is evaluated, regardless of how valid it was when minted; if the file is removed instead (a replaced identity with no old `kid` file lingering), resolution itself fails (`grant_unknown_key`). Both are **correct, fail-closed behavior, not a bug**: a rotated or replaced key must never silently continue to honor grants signed under the key it replaced. This is proven against the real store/verify/keystore by the adversarial suite `test/adversarial/src/store-tamper.test.ts` (P0-E11-T4) — see its "(3) pubkey swap" case.

### `grants/` — signed grants, revocation tombstones, and the consumed-jti ledger

`packages/store/src/grant-store.ts` (`createGrantStore`, P0-E4-T1, rulings R29–R31) owns this subtree. It is **codec-agnostic**: it never parses JWS or verifies a signature — every token is an opaque string, and wherever the store needs to look inside one (extracting `jti` on write, filtering by `tool`/`agent` on `listBy`) it calls a `decodeIndexEntry` function injected by the caller. This is deliberate dependency direction (R29): `packages/grants` (arriving in E3-T3) imports `packages/store` for the ledger below, so `packages/store` must never import `packages/grants` back — a store that parsed JWS itself would make that a cycle. `grant_invalid`, wherever this store's API surfaces it, means only "undecodable/garbage bytes" — real signature-level verification is `@knotrust/grants`' job, upstream of this store.

- **`grants/<jti>.jws`** — the token text, exactly, plus a trailing newline. Written via the same write-to-temp-then-`rename` discipline as every other file in this subtree (R31: `<name>.<random>.tmp` in the same directory, then an atomic same-filesystem `rename()`) — a reader always sees either the fully-old or the fully-new file, never a torn one, even when two independent OS processes are writing into `grants/` at the same time.

- **`grants/tombstones/<jti>.json`** — a revocation tombstone: `{ jti, revokedAt, reason? }`, `revokedAt` RFC 3339 (profiled subset of ISO 8601, ADR-0017). `revoke()` writes the tombstone FIRST (atomically), then best-effort-unlinks the `.jws`. **The unlink failure is tolerated and never surfaces as an error: tombstone presence alone is what makes a grant revoked, permanently, regardless of whether its `.jws` is still sitting there.** Every read path (`get()`, `list()`, `listBy()`) checks the tombstone before anything else, so a process that dies between the tombstone write and the unlink has still fully revoked the grant — this is what makes revocation crash-safe.

- **`grants/consumed/<jti>`** — an empty marker file, and the **replay-protection primitive the whole product's single-use/ephemeral grant story depends on**. `consumeOnce(jti)` creates it with the `"wx"` flag (`O_CREAT | O_EXCL`): one `open()` syscall that either creates the file (first-and-only caller: `"consumed"`) or fails `EEXIST` (someone already won: `"already_consumed"`). There is no read-then-write anywhere in this path — the atomicity is POSIX-level, holds across independent OS processes (not just concurrent async calls inside one Node event loop), and needs no lock file. `packages/grants` (E3-T3) wires this into ephemeral/single-use grant decisions; `packages/store`'s own test suite proves the cross-process guarantee by spawning two real `node` child processes racing `consumeOnce()` over the same `jti` set and asserting exactly one winner per `jti`.

As with `~/.knotrust` itself, `grants/`, `grants/tombstones/`, and `grants/consumed/` are created `0700` lazily and re-`chmod`'d on every write path that touches them (mirroring `keys.ts`'s `ensureKnotrustHomeDir`) — defensive against a directory that pre-existed with looser permissions from something else. Unlike `identity.key`, individual `.jws`/tombstone/marker files are written with default file permissions: a grant is bearer-token-shaped secret material in the same rough class as a session cookie, not the signing key itself, and confidentiality here is the directory's `0700`, not a per-file `0600`.

`node:sqlite` indexing over this tree is deliberately deferred (brief §D) until query needs outgrow streaming every `.jws` file in `listBy()` — `grants/` stays plain files, no native dependencies, for as long as that holds.

### `audit/` — the tamper-evident, hash-chained decision log

`packages/store/src/audit-log.ts` (`createAuditLog`, P0-E4-T3, rulings R36–R38) owns this subtree — the spine behind "everything the agent *tried* is hash-chain audited." Every decision — including denials, cache hits, fail-open firings, approval lifecycle transitions, and grant lifecycle events — is meant to append exactly one JSONL line here (brief §E5: attempts, not just executions).

- **Chain definition (R36).** Each line is one JSON object: `{seq, ts, prevHash, hash, type, surface, subject, agent, tool, argsHash, outcome?, reason?, grantRefs?, approvalId?, latencyMs?, cacheHit?}`. `hash = lowercase-hex(SHA-256(utf8(canonicalizeJcs(eventWithoutHash))))`, where the hashed object INCLUDES `prevHash` — an exact, cross-language-reproducible restatement of "`SHA-256(prevHash + canonical-line-bytes)`" that reuses `@knotrust/core`'s FROZEN `canonicalizeJcs` (the same canonicalizer the SARC call-hash pins) rather than a bespoke concatenation scheme. Genesis `prevHash` is 64 zeros (`AUDIT_GENESIS_PREV_HASH`). `seq` starts at 1, is global-monotonic, and is **continuous across month files** — the chain spans files: the last hash of file N is the `prevHash` of file N+1's first event.

- **`audit/<yyyymm>.jsonl`** — one file per calendar month, named from the same injected clock that stamps `ts` (RFC 3339, ADR-0017). Opened append-only (`"a"`) and kept open for the sink's lifetime; a write that crosses a month boundary closes the old fd and opens/creates the new month's file, carrying the in-memory chain state (`seq`/`hash`) across the rotation with no re-derivation from disk needed.

- **Argument hashing, not raw capture (R37).** `argsHash` is `"sha256:" + hex(SHA-256(utf8(canonicalizeJcs(arguments ?? null))))` (the exported `computeArgsHash` helper — never throws; a non-canonicalizable input yields the literal `"unavailable"`). Raw arguments are **never** written to disk by default — the sink only persists a `rawArgs` field when constructed with `captureRawArgs: true`, and strips any caller-supplied `rawArgs` otherwise, regardless of caller behavior (secrets hygiene, defense in depth).

- **Fail-closed on audit-write failure (R38, D6 — ratified).** `append()` is synchronous — the line is written immediately (visible to a concurrent reader right away), with fsync **batched** via a timer capped at 100ms unless the caller passes `{ fsync: "immediate" }` (used for `critical`-tier events), which fsyncs before returning. **Any** failure in this path throws `AuditUnavailableError` (after writing the failure to stderr) carrying the original error as `.cause`; the future proxy composition (P0-E5-T3/T5) treats that throw as `deny` with reason `AUDIT_UNAVAILABLE` — an ungoverned-but-unaudited allow is the worst outcome for a product whose pitch is "fully audited." The **next** `append()` call after a failure retries directory/file bootstrap from scratch; if that succeeds, it first emits an internally-generated `audit_recovered` event (documenting the gap) before writing the caller's originally-intended event.

- **Crash recovery — tail-only, never a full-file scan (R36).** On construction, the sink locates its resume position by reading only the *tail* of the newest `<yyyymm>.jsonl` file (falling back to older files only if the newest is empty), never scanning the whole file. If the tail's final line is torn (no trailing newline — a crash mid-`write()`), that fragment is quarantined to `<file>.torn` (appended, never overwritten, so repeated crash cycles keep full forensic history), the live file is truncated back to its last intact line, a notice goes to stderr, and the chain resumes from that intact line. This is an inherent, documented limitation shared with any hash-chained log: it detects insertion/edit/reorder/tearing within or at the end of the chain, but not wholesale deletion of a clean trailing run of the most-recent events.

- **Tamper-evident, not tamper-proof** (architecture §9.3's "tamper-evident-lite" doctrine; security threat model §5.1, T5 — the same honest-boundary discipline §4 above states for the OS keychain). This chain reliably catches accidental, naive, or partial tampering — a line edited without redoing everything downstream, a middle line deleted, a write torn mid-append — because the next `verify()` finds the first hash/prevHash mismatch at the tamper point. It does **not** catch a privileged local writer (the same OS user this process runs as) who edits a line and recomputes every downstream hash to match: the chain is unkeyed SHA-256, with no signature and no external anchor over the head, so a fully-recomputed chain is indistinguishable from one that was never touched. External anchoring/witnessing — periodic head export via OTel, or signing the head — is the real fix for that case, and is deferred, future work, not shipped in P0.

- **`audit/.lock`** — an exclusive (`"wx"`) create containing this process's pid. P0 does not support multiple processes appending to the same log concurrently (a single proxy process owns it); a second `createAuditLog()` against the same home fails loudly instead of risking a corrupted chain. If the pid the lock names is no longer running (`process.kill(pid, 0)`), the lock is treated as stale and taken over — best-effort, not atomic across two simultaneous takeovers, an accepted gap since P0 explicitly doesn't support concurrent writers.

- **`verify()`** streams every file in seq order with O(chunk) memory (never slurping a whole file) and reports `{ ok: true, events: n }` or `{ ok: false, breakAt: { file, line, seq, kind } }` where `kind` is `"hash_mismatch"`, `"seq_gap"`, `"prevhash_mismatch"`, or `"torn_line"` — editing, deleting, or reordering any line is detected at the exact break position.

As with `~/.knotrust` itself, `audit/` is created `0700` lazily and re-`chmod`'d on every construction (mirroring `grants/`'s and `keys.ts`'s discipline). Individual `.jsonl`/`.torn`/`.lock` files are written with default filesystem permissions — audit content is not secret material in the same class as `identity.key`; confidentiality here is the directory's `0700`.

`node:sqlite` indexing over this tree is deliberately deferred (brief §D, ADR-0005) until query needs (e.g. `knotrust audit --since 1h --outcome deny`) genuinely outgrow streaming — `audit/` stays plain JSONL, no native dependencies, for as long as that holds.

### `servers/<server>/tool-inventory.json` — the per-server tool inventory (rug-pull/annotation-trust surface)

`packages/proxy-stdio/src/tool-inventory.ts` (`createToolInventoryClassifier`, P0-E5-T2, rulings R63–R67) owns this subtree — one JSON file per logical MCP server name (the same `server` string `SurfaceMetadata.server`/`knotrust.config`'s `servers` key uses elsewhere), holding every tool that server has ever advertised, as of the last successful `tools/list` capture.

- **Written when, and by what.** Only when the proxy is started with the (opt-in) `toolInventory` option (`createStdioProxy`'s `toolInventory: { serverName, home?, audit? }` — architecture §4.2 default is untouched otherwise). On every FULLY-accumulated `tools/list` listing (all pages collected, see below), the file is REPLACED with the fresh snapshot — the new capture becomes the baseline the NEXT capture (same server, same or a later session) is diffed against.

- **Shape**: `Record<toolName, { annotations, inputSchemaHash, inputSchema? }>`. `annotations` is `@knotrust/core`'s `UntrustedToolAnnotations` shape (`trusted: false`, `source: "server_advertised"`, `readOnlyHint?`/`destructiveHint?`/`idempotentHint?`/`openWorldHint?`, `capturedAt`) — the SAME shape a live `DecisionRequest.toolAnnotations` carries, so the "these are self-declared and may be a lie" trust boundary (ADR-0009) is visible in the type, not just prose. `inputSchemaHash` is `"sha256:" + hex(SHA-256(utf8(canonicalizeJcs(inputSchema))))` (or the literal `"unavailable"` on a non-canonicalizable input — never throws, mirroring `computeArgsHash`). `inputSchema` itself is kept alongside the hash for regeneration/diff/forensic inspection.

- **Pagination-aware accumulation.** A `tools/list` listing may span multiple pages (`nextCursor`); the capturing hook tracks in-flight requests by JSON-RPC `id` to tell a fresh listing's first page from a continuation, and only finalizes (diffs + persists) once a listing's LAST page (no `nextCursor`) arrives — a tool defined only on page 2 still lands in the inventory.

- **Drift detection (the rug-pull tripwire, threat model PRD §13).** Each finalized capture is diffed against whatever was PREVIOUSLY persisted for this server (`undefined` only on a server's genuine first-ever capture, in which case nothing is reported — see `tool-inventory.ts`'s own header for why flooding the audit log on every fresh install would be noise, not signal). A tool whose `inputSchemaHash` changed, or any annotation hint flipped, or that is newly present/absent versus the prior baseline, produces one `tool_definition_changed` audit event (`packages/store/src/audit-log.ts`'s `AuditEventType.TOOL_DEFINITION_CHANGED` — `tool_added`/`tool_removed` are folded into this ONE type via a `changeKind` field in the JSON-encoded `reason`, rather than minted as separate audit-event types) when an audit sink is supplied. The event never carries the raw schema, only a `schemaHashChanged` boolean plus any per-hint old/new pairs.

- **Tier seeding (NOT persisted here — a pure function of this file's content).** `seedTierEntriesFromAnnotations`/`mergeSeededTiers` (same module) turn a loaded inventory into SUGGESTED `source: "annotation"` tier entries for `knotrust init` (P0-E7-T1) to fold into generated config — conservatively (destructive-looking never suggests `"routine"`; a self-contradicting "annotation lie" takes the higher/`"sensitive"` suggestion), and NEVER overriding an existing `"user"`/`"pack"` config entry. This file itself holds only the captured facts, never a tier decision.

As with the rest of this tree, `servers/<server>/` is created `0700` lazily and re-`chmod`'d on every write (mirroring `grants/`'s and `audit/`'s discipline); the `tool-inventory.json` file itself is written with default filesystem permissions (tool schemas/annotations are not secret material) via the same write-to-temp-then-`rename` atomic discipline as `grants/`'s `.jws` files.

## 3. Backend selection (`KeyStore`, `packages/grants/src/keys.ts`)

One `KeyStore` interface, two backends:

| Backend | Where the seed lives | Default? |
|---|---|---|
| `keychain` | OS keychain via `@napi-rs/keyring` — service `"knotrust"`, account `"identity"` | Yes, wherever usable |
| `file` | `~/.knotrust/identity.key`, `0600` (§2 above) | Fallback only |

Selection order:

1. An explicit `backend` option to `createKeyStore()`, if given.
2. Otherwise the `KNOTRUST_KEY_BACKEND` env var (`"file"` or `"keychain"`; any other value is a startup error naming the bad value).
3. Otherwise **auto-detect**: a real, disposable set-then-delete round-trip against a `<account>:probe` sub-entry (never the real identity secret) checks both that the native module loads *and* that the OS secret service actually accepts a write — a loaded module on headless Linux with no secret service running still throws on first real use, not at load time, so a load-only check would miss it.

Auto-detect degrades **silently to the file backend** on either failure (module load failure, e.g. an unsupported platform or a corrupted `optionalDependencies` install; or a probe write failure, e.g. no secret-service daemon reachable), emitting **exactly one** notice to stderr naming the downgrade and the resulting file path. `@napi-rs/keyring` is loaded via dynamic `import()` inside a try/catch specifically so this degradation is transparent — the `npx` path never hard-fails just because the native module for this platform didn't install.

**Forcing `KNOTRUST_KEY_BACKEND=keychain` against an unusable keychain is a hard error, not a silent fallback** — if you explicitly asked for the keychain, KnoTrust tells you it couldn't deliver instead of quietly writing a file you didn't ask for.

## 4. Keychain storage is hardening, not a boundary

This is the paragraph that matters most in this document, and it is stated in full, not abbreviated, because getting it wrong in either direction — overclaiming the keychain's protection, or dismissing it as pointless — would be dishonest in opposite ways (ratified brief §I2.1; architecture §5.1; security-threat-model §5.1, the model's top stated limitation).

**The OS keychain is real hardening: it upgrades the attack an adversary needs from a trivial file read (`cat ~/.knotrust/identity.key`) to arbitrary-code-execution-as-the-same-user. It is not a security boundary, and KnoTrust does not claim it is one.** An agent that is already executing arbitrary code as the same OS user KnoTrust runs as can ask that user's own keychain for the secret exactly as `keys.ts` does — a keychain ACL scoped to "this user's processes" does not distinguish "the legitimate `knotrust` process" from "an agent's shell tool running under the same account." An ungated same-account shell defeats any local control, keychain included. The `0600` file fallback makes this even more direct — file permissions stop *other* OS users, never the same UID the agent runs as — but the keychain default does not close that gap either, it only raises the cost of exploiting it.

The honest conclusion, and the one this project commits to stating everywhere this topic comes up: **KnoTrust's grant-signing-key confidentiality in local mode is conditional on the agent not having ungated code-execution access to the account `knotrust` runs under.** The sandbox recommendation (PRD §3 — run agents with untrusted tool access under a separate, least-privilege principal, not your own login account) is therefore **load-bearing, not advisory**, for this asset specifically. The real fix — the point where this actually becomes a boundary instead of hardening — is the **F3-era separate-principal sandbox broker**, where the signing operation itself runs under a principal the agent's own process cannot reach, keychain or not.

## 5. References

- `packages/grants/src/keys.ts` — the `KeyStore` implementation this doc describes (P0-E3-T1, rulings R21–R23).
- `packages/store/src/grant-store.ts` — the `grants/` subtree implementation this doc describes (P0-E4-T1, rulings R29–R31), including the `consumeOnce()` replay-protection primitive.
- `packages/store/src/audit-log.ts` — the `audit/` subtree implementation this doc describes (P0-E4-T3, rulings R36–R38), including the hash-chain definition, tail-only crash recovery, the writer lock, and the fail-closed `AuditUnavailableError` contract.
- `packages/proxy-stdio/src/tool-inventory.ts` — the `servers/<server>/tool-inventory.json` subtree implementation this doc describes (P0-E5-T2, rulings R63–R67): `tools/list` pagination-aware capture, drift detection against the persisted baseline, and the `seedTierEntriesFromAnnotations`/`mergeSeededTiers` tier-seeding functions `knotrust init` (P0-E7-T1) reuses.
- `packages/proxy-stdio/src/classifier.ts` — the `observe` seam capability (R63) this task added to the classifier contract, and `composeClassifiers`, which layers the tool-inventory hook under any other classifier.
- `packages/core/src/jcs.ts` — the frozen `canonicalizeJcs` the audit chain hash reuses (P0-E3-T3, ruling R33).
- ADR-0009 (`docs/05-decisions/adr/adr-0009-annotations-seed-only-never-trust.md`) — the "annotations seed suggested tiers, never a trust decision" doctrine this subtree implements.
- Architecture §5.1 (`docs/02-architecture/system-architecture.md`) — grant format and the canonical hardening-not-a-boundary sentence this doc expands on; §9.1 — the audit pipeline's original sketch (superseded in exact field-shape detail by R36–R38, reconciled above).
- ADR-0005 (`docs/05-decisions/adr/adr-0005-file-stores-jsonl-hashchain-audit.md`) — the file-store-vs-database decision this subtree implements.
- Security threat model §5.1 (`docs/02-architecture/security-threat-model.md`) — the residual analysis this doctrine is escalated from.
- Ratified brief §I2.1 (`docs/05-decisions/2026-07-03-decisions-brief.md` and `docs/04-roadmap/implementation-plan.md`'s D9 entry) — the binding ruling superseding the original file-only Phase-0 call.
