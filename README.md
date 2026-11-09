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

Every `WasmSession` rejection is the JSON text of one object,
`{"code", "message", …fields}`: JS branches on `code` and shows `message`, the
core's own text. No field carries a value, a key or ciphertext. The codes and
their fields are listed in `crates/dybw-core-wasm/src/error.rs`. The profile's
`apiOrigin` is the identity origin the API key was entered for; `unlock` sends
the key nowhere else (`wrong-origin`).

A host whose `http` follows redirects (`refusesRedirects()` answers `false`)
gets ADR 0018's rule: the API key and the bearer token go only to Bitwarden
cloud (`identity.bitwarden.com`, `identity.bitwarden.eu`) or to an identity
origin the user acknowledged on this device; anything else is refused with
`origin-not-acknowledged` (field `origin`) before any request. The
acknowledgements live in the host's `Storage` under `acknowledged-origins`
(a JSON list), set with `acknowledgeOrigin(origin)`, withdrawn with
`forgetOrigin(origin)` and listed by `acknowledgedOrigins()`. Each is bound
to its server: an unlock drops every acknowledgement but its own identity
origin's. A host that refuses redirects, as bwss, is unaffected.

Run the vectors, the crypto known answers, the timings and the panic test in
Node, Chromium and WebKit:

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

`cargo deny check bans sources` and `cargo audit` need the advisory database and
are run locally, not in CI:

```bash
cargo deny check bans sources
cargo audit
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
