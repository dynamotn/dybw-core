# dybw-core

The shared core of bwss (a Rust Secret Service daemon) and the Obsidian
plugin, both backed by Bitwarden. The repository holds the Rust core and the
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
  `expected-failures.txt` lists no vector at the end of M2.

Its futures are `!Send`: run them on a `current_thread` runtime or a `LocalSet`.

## Checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
uv run vectors/gen/gen.py check
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
kept for when GitLab minutes return.
