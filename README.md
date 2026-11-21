# dybw-core

An I/O-free Rust core for Bitwarden and Vaultwarden clients: crypto, vault
rules, sync, an offline write queue and local unlock protectors, in one
library that runs natively and as WebAssembly.

## Why

Talking to a Bitwarden server correctly takes more than an HTTP client. You
need the KDFs and every EncString and COSE format the official clients
write, the rules for which items a tool may read and write, a three-way sync
that never loses a user's edit, and the checks that stop a hostile or
rolled-back server from downgrading your keys. dybw-core does all of that
once, so every tool built on it agrees on what is in the vault.

It does no I/O of its own. The core is written against a small set of
*ports* (traits for HTTP, storage, secrets, time, randomness, the Argon2id
KDF, RSA-OAEP, the notifications socket and prompts), and each host brings
its own adapters. That is how one crate serves three very different hosts:

| Host | Runtime | Adapters |
|---|---|---|
| the dybw CLI and agent (an `rbw` replacement) | native, tokio | `dybw-native` |
| bwss, a Secret Service daemon backed by Bitwarden | native, tokio | `dybw-native` |
| keychain-bitwarden, an Obsidian plugin | WASM in Electron | JavaScript, through `dybw-core-wasm` |

It implements data model 1.6 of the dybw design: history, rollback and
duplicate handling, `dybw:requires`, blob ciphers, the signed security state
and the KDF pin.

## Crates

| Crate | What it is |
|---|---|
| [`dybw-core`](crates/dybw-core) | The library: ports, crypto, API client, vault rules, sync, profiles. No I/O, no async runtime. |
| [`dybw-native`](crates/dybw-native) | Native host adapters (reqwest + rustls, files, tokio, tungstenite), a pinentry client and the shared config. Unix only. |
| [`dybw-core-wasm`](crates/dybw-core-wasm) | `dybw-core` for `wasm32-unknown-unknown`, with the ports implemented over a JavaScript object. |
| [`dybw-vectors`](crates/dybw-vectors) | Runs the language-neutral conformance vectors in [`vectors/`](vectors) against the core. |

Only `dybw-core` is meant to be published; the other three set
`publish = false`.

## Feature flags

All flags are on `dybw-core`.

| Flag | Default | Adds |
|---|---|---|
| `native` | on | `crypto::NativeArgon2` (a `KdfRunner` on the `argon2` crate) and `crypto::AwsLcRsa` (an `RsaOaep` on `aws-lc-rs`). Turn it off for WASM and bring your own. |
| `testing` | off | `testing`: in-memory fakes (`MemStorage`, `MemSecrets`, `FixedClock`, `SeededRandom`) and a `block_on` for tests. |
| `totp` | off | `totp`: parses a login's `totp` field (`otpauth://totp/...`, bare base32, `steam://`) and generates RFC 6238 or Steam codes. |
| `vault-client` | off | `vault::client` and `sync::client_create` / `client_update` / `client_trash`: create, edit and trash ordinary items. |
| `protectors` | off | `profile::protector`: local unlock with a PIN, biometrics or the login password. Implies `native`. |

The module the Obsidian plugin ships builds with none of them;
`dybw-core-wasm`'s `vectors` feature, for its test harness only, adds
`testing` and `vault-client`.

## Getting started

dybw-core is not on crates.io yet. Depend on it from git and pin a commit:

```bash
cargo add dybw-core --git https://gitlab.com/dynamo-tools/dybw-core.git --rev <commit>
```

```toml
[dependencies]
dybw-core = { git = "https://gitlab.com/dynamo-tools/dybw-core.git", rev = "<commit>" }
```

The same repository is mirrored at `https://github.com/dynamotn/dybw-core`.

Unlocking an account takes a `Client` built from the host's `Http` and
`Clock`, plus `Storage` for the device id, the KDF pin and the security
state. The ports in this example are whatever your host provides; the
`native` feature supplies the KDF and RSA ones:

```rust
use dybw_core::api::{ApiKey, Client, DeviceInfo, origin_of, resolve_server_urls};
use dybw_core::crypto::{AwsLcRsa, NativeArgon2};
use dybw_core::ports::{Clock, Http, Random, Storage};
use dybw_core::profile::{device_id, unlock};
use dybw_core::vault::{Namespace, Organizations, scan_vault};
use zeroize::Zeroizing;

/// Unlocks one account and lists the items the `bwss` namespace owns.
pub async fn list_items(
    http: impl Http,
    clock: impl Clock,
    storage: &impl Storage,
    random: &impl Random,
    (client_id, client_secret): (String, Zeroizing<String>),
    email: &str,
    password: Zeroizing<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let urls = resolve_server_urls("https://vault.example.org")?;
    let key = ApiKey { origin: origin_of(&urls.identity)?, client_id, client_secret };
    let device = DeviceInfo {
        identifier: device_id(storage, random).await?, // saved through `Storage` on first use
        name: "my-tool".into(),
        device_type: 8, // Bitwarden's DeviceType: Linux desktop
        client_name: "my-tool".into(),
        client_version: env!("CARGO_PKG_VERSION").into(),
    };
    let mut client = Client::new(http, clock, urls, device)?;

    let (ns, orgs) = (Namespace::BWSS, Organizations::None);
    let unlocked =
        unlock(&mut client, storage, &key, email, password, &NativeArgon2, &AwsLcRsa, &ns, &orgs).await?;
    for warning in &unlocked.warnings {
        eprintln!("warning: {warning:?}");
    }

    let report = scan_vault(&unlocked.sync, &ns, &unlocked.keys, &orgs);
    for item in &report.items {
        println!("{} -> cipher {}", item.id, item.cipher_id);
    }
    unlocked.lock(); // wipes every key
    Ok(())
}
```

This compiles against the current tree (it also needs `zeroize` as a direct
dependency), but it is illustrative, not a doctest. A few things to know:

- **Futures are `!Send`.** The ports are not `Send`, so the same core runs
  on tokio and in a browser. Run it on a `current_thread` runtime or inside
  a `LocalSet`.
- **Your `Http` decides the redirect rule.** An adapter that refuses
  redirects (`refuses_redirects()` answers `true`, as `dybw-native`'s does)
  may talk to any server. One that follows them only sends the API key to
  Bitwarden cloud or to an identity origin the user acknowledged.
- **Bound every response.** `Http::send` must stop reading once a body
  exceeds `HttpRequest::max_body`.
- **Other ways in.** `profile::unlock_cached` unlocks offline from an
  earlier `/sync`; `unlock_with_key` and `unlock_with_key_cached` take the
  user key itself (a remembered key, or one a protector released).

## What is inside

| Module | Covers |
|---|---|
| `ports` | The traits a host implements: `Http`, `Storage`, `Secrets`, `Clock`, `Random`, `KdfRunner`, `RsaOaep`, `Events`, `Prompter`, `Confirmer`. |
| `crypto` | KDF bounds and floors, PBKDF2, Argon2id, legacy and COSE keys, EncString types 2, 3, 4 and 7, signed security state, value marks, `SymmetricKey::tag` (a keyed HMAC-SHA256). |
| `api` | Server URL resolution, the Bitwarden API client, MessagePack and SignalR frames, the notifications hub (`run_hub`). |
| `vault` | Namespaces, scanning (`scan_vault`, `item_meta`), duplicates, organization keys, write-back and create, line unions into a tool field (`write::LineAppend`). |
| `sync` | The writer with its out-of-date retry, the offline write queue (`enqueue`, `flush`), the three-way planner, device state, and full passes (`plan_pass`, `run_sync`). |
| `profile` | Unlock, device identity, the KDF pin (`accept_kdf`), the security version (`accept_security_version`), acknowledged origins, lock. |
| `totp` | TOTP and Steam codes (feature `totp`). |
| `testing` | Fakes for the ports (feature `testing`). |

### The optional features in detail

`totp` takes the unix time from the caller and returns the code with the
seconds left in its period. Ranges follow Bitwarden's SDK (digits 1-10,
period at least 1 s) and are refused, not clamped. Known answers are in
`vectors/crypto/totp.json`.

`vault-client` is the dybw CLI's writes of ordinary items. A create is a
personal login or secure note. An edit changes the name, notes and folder of
any item and a login's username, password and URIs; a changed password goes
into the history and everything else passes through byte for byte, other
tools' markers included. A trash moves the item to the trash. The writers
fetch the cipher first and refuse a copy at another revision than the edit
was planned on, or a server's out-of-date answer, without re-applying
anything. Organization items are written under their key, never read-only
ones; a personal blob is re-sealed, an organization blob refused. Vectors
are in `vectors/src/write/client/` (`expect.clientWrite`).

`protectors` wraps the user key under a key from a local factor (`pin`,
`biometric` or `login`): Argon2id over a secret (floors 64 MiB, 3
iterations, 1 lane, enforced on wrap and on read) or 32 bytes from hardware,
then HKDF-SHA256 with the device id and machine fingerprint as salt and
`dybw-unlock:<protector>` as info, so an edited binding or name fails the
MAC. The blob is versioned JSON (device state, never synced) with an attempt
count: `unwrap` refuses another device or machine (`binding`), five failures
(`invalidated`), a wrong factor (`wrong`, counted), and a key that no longer
opens the account's private key (`stale`, after a rotation). Known answers
are in `vectors/crypto/protector.json`. It is never built into
`dybw-core-wasm`, which has no device to bind a protector to.

## Design principles

- **No I/O in the core.** `dybw-core`'s normal dependencies hold no I/O
  crate and no `tokio`, `reqwest`, `rsa` or `getrandom`. Everything that
  touches the outside world goes through a port.
- **No unsafe code.** Every crate sets `unsafe_code = "forbid"`.
- **Secrets are wiped.** Keys, passwords and decrypted values live in
  `zeroize` types, including the hash states of the TOTP code. An unlocked
  profile has no `Clone` and no `Debug`, and locking it drops every key.
  Error messages never carry a password, key or value.
- **MAC before decrypt.** An EncString's MAC is checked in constant time
  before anything is decrypted.
- **KDF floors and pins.** The KDF parameters are bounds-checked before
  they run. The first unlock pins them per identity origin, and a later
  server that offers weaker ones is refused until the user confirms it.
  Below the floors (PBKDF2 600,000 iterations; Argon2id 64 MiB, 3
  iterations, 1 lane) the unlock succeeds with a warning.
- **Server integrity checks.** A COSE user key needs a valid signed
  security state, and a version below the highest one this device saw stops
  the unlock. Rolled-back items are held until the user accepts them.
- **Vectors from an independent implementation.** The conformance vectors
  are generated by a separate Python implementation (`cryptography`,
  `argon2-cffi`), not by the Rust code they test, and Bitwarden's own SDK
  decrypts strings and a wrapped item key the core produced.
- **A size budget for WASM.** The module the Obsidian plugin ships, as
  base64, plus its minified glue must fit in 1 179 648 bytes (1.125 MiB). A
  test enforces it.
- **Full coverage.** CI requires 100% line coverage on stable and 100%
  branch coverage on a pinned nightly, excluding only the vector runner.

## Conformance vectors

[`vectors/`](vectors) holds scenarios that every tool on the dybw data model
must satisfy: plaintext sources, a deterministic generator that encrypts
them, the generated files, and JSON Schemas that pin both formats. They are
language-neutral, so another implementation can check itself against the
same files. [`vectors/README.md`](vectors/README.md) describes the formats.

`dybw-vectors` runs them against the core natively, and the WASM harness in
`crates/dybw-core-wasm/js` runs them again in Node, Chromium and WebKit.
`crates/dybw-vectors/expected-failures.txt` lists the vectors the core is
allowed to fail; it lists none.

## WebAssembly

`dybw-core-wasm` exposes a `WasmSession` class to JavaScript; every
`#[wasm_bindgen]` item is in `src/bindings.rs`. The `vectors` feature adds
the conformance runner for the harness in `js/`. The JS API below is what
the Obsidian plugin uses and may still change.

### Building

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

### Panics

A panic traps the instance but leaves it callable with its memory, keys
included. On any trap the plugin calls `lock()` on every live `WasmSession`,
each in its own try/catch, which wipes the keys, then reloads itself (or loads
a fresh glue module): the glue caches its instance, so calling its init again
is no recovery. The buffers of the call that trapped are not wiped; they stay
in the dead instance's memory until it is dropped.

### JS API

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
  acceptRollbacks: { <cipherId>: revisionDate },  // only these, at the revision shown
  overrides: { <id>: { policy, kind } },          // kind: a conflict kind below
  answers: { <id>: { question, answer } },        // question: "first-write-back" | "evicts-foreign-history"
                                                  // answer: "write-to-login" | "keep-separate"
  vaultName: string, uploadFolder: string }
```

A rollback (`rollbacks` below) stays held until the user accepts it: pass each
shown entry's `cipherId` with its `revisionDate` in `acceptRollbacks`. It is
accepted only while the server still holds that revision, so a cipher that
rolled back again since is held and reported again, never taken unseen; an
entry for a cipher that is not rolled back is ignored. `acceptRollback: true`
accepts every one. An override holds only while the conflict is still of its
`kind`; an answer covers only the question it was given for (ADR 0016). An item's
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
  rollbacks: [{id, cipherId, revisionDate}],      // revisionDate: the server's, as text
  held, readOnly: [{id, cipherId}],
  unknownFeatures: [{cipherId, features: [name]}],
  unreadable: [cipherId],
  duplicates: [{id, kept, left: [cipherId], boundKept}],
  skipped: [{cipherId, reason}],
  kept: [{id, reason: "local-changed"}],          // the host refused to write over the user's edit
  warnings: [string] }
```

`runSync` saves as it goes: after each action, every value it wrote
(`secretSave`), then the state (`storageSave`), so an app closed mid-sync
keeps every action that finished. Nothing is written once `lock` runs.

The host may refuse a value write because the user changed that value since
the sync began: `secretSave` then rejects with an `Error` whose message is
exactly `local-changed` (`host::LOCAL_CHANGED`). The sync keeps the user's value
and the base it had, lists the id in `kept` (not in `pulled`, `cleared` or
`errors`) and carries on; the next sync sees both sides changed and resolves
it as a conflict, by the policy. Any other `secretSave` rejection keeps the
base the same way and fails the call with `port` once the sync ends.

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
renewal backs off as any failed connection. After a failed renewal the token
stays marked expired, so each later attempt logs in once more before it
connects: one login per backoff step (2 s, 5 s, 15 s, 60 s, then every 300 s),
bounded and deliberate.

### Testing in Node and browsers

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

## Status

- **Version:** v1.0.0-rc.1, the first release candidate. The crates declare
  `1.0.0-rc.1`; pin the `v1.0.0-rc.1` tag (`tag = "v1.0.0-rc.1"`) or a commit.
- **MSRV:** Rust 1.89 (edition 2024). The WASM build is pinned to Rust
  1.99.1.
- **Platforms:** `dybw-core` builds for native targets and for
  `wasm32-unknown-unknown`. `dybw-native` is Unix only. CI runs on Linux.

## Development

Regenerate the encrypted vectors from their sources, or check that the
committed files are what a build would produce (exit 1 and a list of stale
files otherwise):

```bash
uv run vectors/gen/gen.py build
uv run vectors/gen/gen.py check
```

Test the generator itself:

```bash
uv run --with jsonschema --with pytest --with cryptography --with argon2-cffi pytest vectors/gen -q
```

### Checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
uv run vectors/gen/gen.py check
uv run vectors/gen/gen_protector.py --check
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

## License

MIT. See [`LICENSE`](LICENSE).
