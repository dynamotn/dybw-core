# dybw-core

The shared core of bwss (a Rust Secret Service daemon) and the Obsidian
plugin, both backed by Bitwarden. It implements data model 1.6 (M3: history,
rollback and duplicates, `requires`, blob ciphers, signed security state, the
KDF pin). The repository holds the Rust core and the
language-neutral conformance vectors: plaintext scenarios, a deterministic
generator that encrypts them, and the schemas that pin the formats. See
[`vectors/README.md`](vectors/README.md) for the formats.

## Vectors

Regenerate the encrypted scenarios from the sources:

```bash
uv run vectors/gen/gen.py build
```

Check that the committed files match what a build would produce (exit 1 and
a list of stale files otherwise):

```bash
uv run vectors/gen/gen.py check
```

Run the tests with:

```bash
uv run --with jsonschema --with pytest --with cryptography --with argon2-cffi pytest vectors/gen -q
```

## Crates

- `crates/dybw-core`: the core library, native and portable (no I/O crate, no
  `tokio`, `reqwest`, `rsa` or `getrandom` in its normal dependencies; the
  default feature `native` adds `aws-lc-rs` and `argon2`).
  - `ports`: the traits a host implements (HTTP, storage, secrets, clock,
    randomness, KDF, events, prompts, RSA-OAEP).
  - `crypto`: KDF bounds, PBKDF2, Argon2id, legacy and COSE keys, EncString
    types 2, 3, 4 and 7, value marks.
  - `api`: server URLs, the Bitwarden API client, MessagePack, SignalR frames
    and the notification hub.
  - `vault`: namespace rules, scan, duplicates, organizations, write-back and
    create.
  - `sync`: the out-of-date writer, the write queue, the three-way planner,
    device state and passes.
  - `profile`: unlock, device identity, lock.
  - `testing` (feature): fakes and `block_on`.
- `crates/dybw-vectors`: runs the conformance vectors against the core.
  `expected-failures.txt` lists no vector at the end of M3.
- `crates/dybw-core-wasm`: the core for `wasm32-unknown-unknown` (M5), with the
  host ports in JavaScript; every `#[wasm_bindgen]` item is in `src/bindings.rs`.
  The `vectors` feature adds the conformance runner for the harness in `js/`
  (see [WASM](#wasm)).

M4 Part A adds what bwss needs from the core:

- `vault::append_lines` unions lines into a tool field (an ACL), skipping those
  already there, and creates the field when it is missing.
- `profile::unlock_cached` unlocks from a cached sync, without the network.
- `vault::item_meta` reads an item's name, username and URI.
- The write queue holds, stalls and records as bwss expects, and older queue
  files stay readable.
- `profile::accept_security_version` records a security-state version the user
  accepted.
- `SymmetricKey::tag` is the keyed HMAC-SHA256 behind bwss's ACL confirmations,
  with the ADR 0023 known answers in `vectors/crypto/bwss-subkeys.json`.

Its futures are `!Send`: run them on a `current_thread` runtime or a `LocalSet`.

## WASM

Tools, at the versions CI pins: Rust 1.99.1 with the `wasm32-unknown-unknown`
target, `wasm-bindgen-cli` 0.2.129 (it must match the `wasm-bindgen` crate),
binaryen `version_133` (`wasm-opt`), Node 26 and
[dybatpho](https://github.com/dynamotn/dybatpho), which the build script is
written with. The harness's `npm ci` comes first: the build's size report
uses its esbuild.

```bash
(cd crates/dybw-core-wasm/js && npm ci)
WASM_OPT=/path/to/wasm-opt DYBATPHO_DIR=/path/to/dybatpho scripts/build-wasm.sh
WASM_OPT=/path/to/wasm-opt DYBATPHO_DIR=/path/to/dybatpho \
  scripts/build-wasm.sh --features vectors --out crates/dybw-core-wasm/js/pkg
```

The first build, without features, goes to `target-wasm/pkg`: it is the module
the plugin ships and the one the size gate measures. The second adds the
vectors runner for the harness. Each build runs `wasm-opt -Oz`, refuses glue
with Node-only or eval-like code, and prints the size report. It remaps the
repository, the cargo registry sources and the rustc sysroot, so the module
holds no absolute build path.

A panic traps the instance but leaves it callable with its memory, keys
included. On any trap the plugin calls `lock()` on every live `WasmSession`,
each in its own try/catch, which wipes the keys, then reloads itself (or loads
a fresh glue module): the glue caches its instance, so calling its init again
is no recovery. The buffers of the call that trapped are not wiped; they stay
in the dead instance's memory until it is dropped.

Calls the plugin uses (`new WasmSession(ports, namespace)`, after the glue's
`init` and the export `init(ports)`):

```text
unlock(profile: string, clientSecret: string, password: string): Promise<string>
unlockWithKey(profile: string, clientSecret: string, userKeyB64: string): Promise<string>
unlockCached(profile: string, password: string): Promise<string>   // offline unlock; the plugin does not use it in M6
exportUserKey(): string
lock(): void
deviceId(): Promise<string>
acceptKdf(kdf: string, origin: string): Promise<void>
acceptSecurityVersion(version: bigint): Promise<void>
acknowledgeOrigin(origin: string): Promise<void>
forgetOrigin(origin: string): Promise<void>
acknowledgedOrigins(): Promise<string>                 // JSON list of origins
planPass(options: string, ids: string[], values: string[]): Promise<string>
runSync(options: string, ids: string[], values: string[]): Promise<string>
queueUpload(id: string, scope: string): Promise<void>
syncedIds(): string
resetState(): Promise<void>
runHub(onChange: () => void, stop: () => boolean): Promise<void>
```

`options` and the answers are the JSON texts described below; every rejection
is a structured error, described next.

The profile JSON taken by `unlock`, `unlockWithKey` and `unlockCached`
(unknown fields are refused with `invalid`):

```text
{ server: string,                  // required: the Bitwarden server URL
  email: string,                   // required
  deviceName: string,              // required
  deviceType: number,              // required, 0-255
  clientName: string,              // required
  clientVersion: string,           // required
  apiOrigin: string,               // default "": the identity origin the API key was entered for;
                                   //   unlock and unlockWithKey need it, else wrong-origin
  clientId: string,                // default "": the API key's client id (unlock, unlockWithKey)
  organizations: "none" | "all" | { only: [orgId] },   // default "none"
  cachedSync: object,              // default null: unlockCached only, an earlier /sync
  preloginKdf: kdf }               // default none: unlockCached only, the KDF prelogin gave with it
```

The three unlocks answer one summary, JSON text:

```text
{ userKeyId: string,               // stable, non-secret id of the user key
  securityVersion: number,
  orgProblems: [{organization, reason}],
  warnings: [string] }             // sentences for the notice, no secret
```

A KDF, as `acceptKdf` takes it and as `kdf-weakened` carries it (`pinned`,
`offered`), is `{type: "pbkdf2", iterations}` or
`{type: "argon2id", iterations, memory, parallelism}` (`memory` in MiB).

Every `WasmSession` rejection is the JSON text of one object,
`{"code", "message", …fields}`: JS branches on `code` and shows `message`, the
core's own text. No field carries a value, a key or ciphertext. The codes and
their fields are listed in `crates/dybw-core-wasm/src/error.rs`. The profile's
`apiOrigin` is the identity origin the API key was entered for; `unlock` sends
the key nowhere else (`wrong-origin`).

"Remember unlock": `exportUserKey(): string`, synchronous, gives the user key
as base64 while unlocked; otherwise `locked`, or `busy` while another call has
the keys.
It is one of the secrets spec §6.2 lets cross as a JS string, for SecretStorage:
the plugin calls it only when the user turned "remember unlock" on.
`unlockWithKey(profile, clientSecret, userKeyB64): Promise<string>` unlocks with
it instead of the password: the same login (API key, `apiOrigin`, ADR 0018) and
`/sync`, no KDF, so the KDF pin is neither read nor written. The key must open
the account's private key, else `wrong-password` and nothing is saved (the
plugin then forgets the key and asks for the password); then the security state
checks run as for a password. A key that is not base64 or no key is `invalid`,
before any request. It answers the same summary as `unlock`.

A host whose `http` follows redirects (`refusesRedirects()` answers `false`)
gets ADR 0018's rule: the API key and the bearer token go only to Bitwarden
cloud (`identity.bitwarden.com`, `identity.bitwarden.eu`) or to an identity
origin the user acknowledged on this device; anything else is refused with
`origin-not-acknowledged` (field `origin`) before any request. The
acknowledgements live in the host's `Storage` under `acknowledged-origins`
(a JSON list), set with `acknowledgeOrigin(origin)`, withdrawn with
`forgetOrigin(origin)` (from the next unlock: lock the session) and listed by `acknowledgedOrigins()`. Each is bound
to its server: an unlock drops every acknowledgement but its own identity
origin's. A host that refuses redirects, as bwss, is unaffected.

The sync calls take local values as `ids[i]` = `values[i]` and an options
JSON object, every field optional:

```text
{ policy: "ask" | "prefer-remote" | "prefer-local",
  acceptRollback: bool,                           // every rollback (ADR 0019)
  acceptRollbacks: [cipherId],                    // only these: the rollbacks shown and accepted
  overrides: { <id>: { policy, kind } },          // kind: a conflict kind below
  answers: { <id>: { question, answer } },        // question: "first-write-back" | "evicts-foreign-history"
                                                  // answer: "write-to-login" | "keep-separate"
  vaultName: string, uploadFolder: string }
```

A rollback (`rollbacks` below) stays held until the user accepts it: pass the
`cipherId`s shown in `acceptRollbacks`, so one that came back since is not
taken unseen; `acceptRollback: true` accepts every one. An override holds only
while the conflict is still of its `kind`; an answer
covers only the question it was given for (ADR 0016). An item's
`obsidian:scope` applies as the plugin's `scopeApplies`: `global` (or none)
everywhere, `vault:<name>` where `vaultName` is `<name>`, `device:<id>` on the
device whose state has that id; a scope the plugin cannot parse applies
nowhere. An unknown option is refused (`invalid`): a mass clear has no
override, `resetState()` is the way out.

The plugin must always pass `vaultName`: without it every `vault:<name>` item
never applies.

`planPass` answers `{actions: [{kind, id, …}], massClear}`. An action is one of
`{kind: "pull", id}`, `{kind: "push", id, confirmed: bool}`,
`{kind: "create", id}`, `{kind: "adopt", id}`, `{kind: "clear-local", id}`,
`{kind: "forget", id}` and `{kind: "conflict", id, conflict}`, where `conflict`
is a conflict kind below. `massClear` is `null`, or `[clears, base]` (counts) when the pass would clear
half or more of what was synced (`runSync` then refuses with `mass-clear`).

`runSync` answers:

```text
{ pulled, pushed, created, cleared: [id],
  errors: [{id, error}], passes: number, keptChanging: bool,
  conflicts: [{id, kind, label, organization, organizationName}],
  questions: [{id, label, question}],
  rollbacks, held, readOnly: [{id, cipherId}],
  unknownFeatures: [{cipherId, features: [name]}],
  unreadable: [cipherId],
  duplicates: [{id, kept, left: [cipherId], boundKept}],
  skipped: [{cipherId, reason}],
  warnings: [string] }
```

Conflict kinds: `both-changed`, `local-unsynced`, `deleted-remotely`,
`organization-claim`, `organization-push`. `label` is the item's name, or the
id when it has none. `organization` and `organizationName` are `null` for a
personal item; the name is raw, as the organization's owners set it: sanitize
it before showing it. `skipped` reasons are the vectors' codes (`wrong-type`,
`newer-format`, …). `warnings` are the core's sentences for the notice, with
counts only. No field carries a value.

The state calls:

- `queueUpload(id, scope): Promise<void>`, unlocked only. `scope` is
  `"global"`, `"vault:<name>"` or `"device"`, which is always this device. A
  reserved or malformed id, or an unknown scope, is refused with `invalid`. The
  host checks that it holds a value for `id`. A failed save keeps the id queued
  in memory; the next successful save writes it.
- `syncedIds(): string`, synchronous, unlocked only: the JSON text
  `{"base": [id], "pendingCreates": [id]}`.
- `resetState(): Promise<void>` works unlocked (on the session's state) or
  locked (on the saved state). Locked, it first locks again, so an unlock in
  flight answers `locked` rather than loading the state from before the reset,
  and an unlock that ends before the reset saves makes the reset refuse with
  `locked`.

All three answer `busy` while another call has the keys out. `runHub` keeps the
device id, the notifications URL and its own twin of the logged-in client
beside the keys, so it keeps running during a sync; it answers `locked` (never
`busy`) when there are no keys, and `lock` stops it at its next check. The twin
renews a token that expired, and once per run of refused connections a token
the server may have refused (the browser cannot tell a 401 from other
failures), through the same login and ADR 0018 rule as the sync; a failed
renewal backs off as any failed connection.

Run the vectors, the crypto known answers, the timings and the panic test in
Node, Chromium and WebKit. The timings are a table for information, with the
plugin's budgets: `pbkdf2-600k` under 3 000 ms and `plan-10000` (the planner
alone over 10 000 secrets, no decryption) under 500 ms:

```bash
cd crates/dybw-core-wasm/js
npx playwright install chromium webkit
npx vitest run
```

The size gate (`js/test/size.test.ts`): base64 of the module without `vectors`
plus its glue after esbuild minify must fit in 1 179 648 bytes (ADR 0024),
since the plugin embeds the module as base64 in its `main.js`. Gzip is
reported for information only.

## Checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
uv run vectors/gen/gen.py check
```

`cargo deny check` (advisories, bans, licences and sources; `deny.toml` allows
only the licences the tree uses) and `cargo audit` need the advisory database
and are run locally, not in CI:

```bash
cargo deny check
cargo audit
```

The SDK check (the plugin's `test:sdk`): Bitwarden's SDK
(`vectors/crypto/sdk-vectors verify`, built from git) decrypts strings and a
wrapped item key the core produced. It is opt-in locally; CI runs it in the
`sdk` job:

```bash
cargo test -p dybw-vectors --test sdk --locked -- --ignored
```

Coverage: 100% of lines on stable, and 100% of branches on the pinned nightly
(`NIGHTLY` in `.gitlab-ci.yml` and the GitHub workflow):

```bash
cargo llvm-cov --workspace --all-features --locked --ignore-filename-regex 'crates/dybw-vectors/' --fail-under-lines 100
cargo +nightly-2026-10-01 llvm-cov --branch --workspace --all-features --locked --ignore-filename-regex 'crates/dybw-vectors/' --json --summary-only --output-path branches.json
```

CI runs on GitHub Actions (`.github/workflows/ci.yml`); `.gitlab-ci.yml` is
kept for when GitLab minutes return. Both have a `wasm-vectors` job that runs
the two WASM builds and the harness above; only the GitHub job writes the size
report to the run summary. Both `wasm` jobs also run clippy for the wasm32
target, the only build that compiles `bindings.rs`:

```bash
cargo clippy -p dybw-core-wasm --target wasm32-unknown-unknown --all-features --locked -- -D warnings
```
