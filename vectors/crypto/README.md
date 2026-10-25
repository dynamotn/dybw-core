# Known-answer crypto fixtures

Copied byte for byte from the tools that own them today. The copied
scripts are not lint-fixed on purpose: they must stay identical to their
source so the hashes below can be checked.

Plugin = `~/Working/personal/obsidian/keychain-bitwarden` at commit `b9beff5`
(path prefix `test/fixtures/`). bwss = `~/Working/personal/tools/bwss` at
commit `dc65284` (path prefix `tests/fixtures/`).

| File here | Source repo | Source path | Commit | sha256 |
|---|---|---|---|---|
| `vectors.json` | plugin | `test/fixtures/vectors.json` | `b9beff5` | `29f34bf25c50a8f75a27aa568ffa5e0d505ca919a52f5a86c85696f37c20858f` |
| `gen_vectors.py` | plugin | `test/fixtures/gen_vectors.py` | `b9beff5` | `c5fb2e57d917f4daf2a01421ae6802e95130540a816234f4cb24a57bb310df16` |
| `cose-vectors.json` | plugin | `test/fixtures/cose-vectors.json` | `b9beff5` | `b2f424e35df13a6bc6ea6394fe4d5de5ca6728be577882677b2360a173d17ca8` |
| `msgpack.json` | plugin | `test/fixtures/msgpack.json` | `b9beff5` | `ef5c163b733c06827531aac437106a197e4d8a6ddb0d5ca996a4dcd8c84dd3f5` |
| `gen_msgpack.py` | plugin | `test/fixtures/gen_msgpack.py` | `b9beff5` | `86531f5e40cb7563921b216474f30b69a220cdae0d3c7c16a060516fbe81fdad` |
| `sdk-vectors/Cargo.lock` | plugin | `test/fixtures/sdk-vectors/Cargo.lock` | `b9beff5` | `8e44991694866d9a116175d90ea7add107b1ea3294ef4b148d2f61cca3d0272a` |
| `sdk-vectors/Cargo.toml` | plugin | `test/fixtures/sdk-vectors/Cargo.toml` | `b9beff5` | `408e266fbbd6dd9feba25a678794d6270beadb2aab36c0b10a66fbd12701a99a` |
| `sdk-vectors/src/main.rs` | plugin | `test/fixtures/sdk-vectors/src/main.rs` | `b9beff5` | `d96116f0730f0f2d75fb2a9f5193afd330b368c5f4597df9033ca8e0f355f123` |
| `bwss/vectors.json` | bwss | `tests/fixtures/vectors.json` | `dc65284` | `29f34bf25c50a8f75a27aa568ffa5e0d505ca919a52f5a86c85696f37c20858f` |
| `bwss/gen_vectors.py` | bwss | `tests/fixtures/gen_vectors.py` | `dc65284` | `c5fb2e57d917f4daf2a01421ae6802e95130540a816234f4cb24a57bb310df16` |

## What each fixture covers

- `vectors.json`: master key (PBKDF2 and Argon2id), HKDF key stretching and
  EncString type 2 encryption known answers.
- `gen_vectors.py`: independent Python reference that produces `vectors.json`.
- `cose-vectors.json`: EncString type 7 (COSE_Encrypt0) known answers
  produced with Bitwarden's SDK, including accounts and item keys.
- `sdk-vectors/`: Rust crate over `bitwarden-crypto` that generates
  `cose-vectors.json` and verifies another implementation's output.
- `msgpack.json`: MessagePack decoder cases (hex input, expected value).
- `gen_msgpack.py`: reference generator for `msgpack.json`.
- `bwss/vectors.json`, `bwss/gen_vectors.py`: bwss's own crypto known-answer
  fixture and its generator (ruling R6). Both are identical to the plugin's
  `vectors.json` and `gen_vectors.py` (same sha256); they are kept for
  provenance so each tool can later drop its own copy.

`bwss/config-registry.toml` and `bwss/pinentry/` are not crypto fixtures and
are not copied.

## Removal of the tools' copies

The tools' own copies stay where they are for now. They are removed when
each tool moves onto the core: bwss in M4, the plugin in M6.
