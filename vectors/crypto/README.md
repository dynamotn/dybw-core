# Known-answer crypto fixtures

Copied byte for byte from the tools that own them today. The copied
scripts are not lint-fixed on purpose: they must stay identical to their
source so the hashes below can be checked.

Plugin = the `keychain-bitwarden` repository at commit `b9beff5` (path
prefix `test/fixtures/`). bwss = the `dynamo-tools/bwss` repository at commit
`dc65284` (path prefix `tests/fixtures/`).

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
| `marks.json` | dybw-core | `vectors/crypto/marks.json` | written for M2; checked against bwss `6a0bc62` and plugin `409d2a4` | `37035135df1e65740837db6bd3b06ff85e577fb72486f6356165ba48a1607a92` |
| `bwss-subkeys.json` | dybw-core | `vectors/crypto/bwss-subkeys.json` | written for M4 (ADR 0023); the `pbkdf2` rows checked against bwss `79ac1c1` | `596cb95198b679a70601e838e0b6099ef9e238dce10b74df0f60e9dbf7b0cee4` |
| `../gen/gen_marks.py` | dybw-core | `vectors/gen/gen_marks.py` | written for M2 | `2026f804983228c0d3f3c320a61cd7f394498220fef6ee2d098ee37265bcb307` |
| `sdk-m3.json` | sdk-internal | constants of `bitwarden-vault` `cipher/blob/sealed.rs` and `cipher/blob/v1.rs`, `bitwarden-core` `key_management/security_state.rs`, `bitwarden-crypto` `signing/signing_key.rs` and `signing/signed_object.rs` (the file and line of each are inside) | `3d16437` | `8f8817b95d912846513099f3a5502c023aac27f2ed1e19a69274046aa2f19e0b` |

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
- `marks.json`: value marks (HMAC-SHA256 of `id ‖ 0x00 ‖ text`) in both
  tools' schemes for the `pbkdf2`, `org` and `cose` user keys, written by
  `../gen/gen_marks.py` (stdlib only). The first row of each scheme was
  checked against bwss `value_mark` with `derive("value-mark")` and the
  plugin's `ValueFingerprinter`. The `cose` rows use the 32-byte COSE secret as
  the HKDF key: the plugin's `deriveSubKey` does exactly that, and the
  `obsidian` rows were confirmed against the plugin's `ValueFingerprinter`
  with a throwaway test. bwss has no COSE keys, so the `cose` `bwss` rows (the
  owner-approved formula: PRK = the secret, info `bwss value-mark enc/mac`,
  the MAC half) are pinned by the core only.
- `bwss-subkeys.json`: ADR 0023 known answers. For the `pbkdf2` and `cose-v2`
  user keys, the `enc` and `mac` halves of `derive_bwss("queue")` and
  `derive_bwss("acl-confirm")`, and for `acl-confirm` one `tag` (HMAC-SHA256
  under the `mac` half) over `tagData` (`item-1 ‖ 0x00 ‖ /usr/bin/tool`). Written
  by `../gen/gen_marks.py`. The `pbkdf2` rows were checked against bwss `79ac1c1`
  (`derive` and `acl_confirm_tag`) with a throwaway test; the `cose-v2` rows are
  pinned by the core only (bwss has no COSE keys).
- `sdk-m3.json`: recorded SDK vectors for data model 1.6, each constant with
  its source `file` and `line` at `3d16437`, as strings (a Rust byte array is
  written as hex). `sealed` is a sealed blob (the `data` of a blob cipher) with
  its wrapping key, whose envelope uses XChaCha20-Poly1305 and a 24-byte nonce
  (the generator seals with AES-256-GCM, so its readers must open both). `v1`
  holds one DataEnvelope per blob type, each with its CEK and the plaintext
  the SDK test asserts, in the serialized shape. `security_state` is a signed
  security state of version 2 with its Ed25519 verifying key (its payload also
  carries an `entityId`, which is ignored). `mldsa44` is an ML-DSA-44
  verifying key and a raw signature over `Test message`. `signed_object` is a
  COSE_Sign1 over `{"field1": "Test message"}` in namespace -1, with its
  Ed25519 verifying key.
- `bwss/vectors.json`, `bwss/gen_vectors.py`: bwss's own crypto known-answer
  fixture and its generator (ruling R6). Both are identical to the plugin's
  `vectors.json` and `gen_vectors.py` (same sha256); they are kept for
  provenance so each tool can later drop its own copy.

`bwss/config-registry.toml` and `bwss/pinentry/` are not crypto fixtures and
are not copied.

## Removal of the tools' copies

The tools' own copies stay where they are for now. They are removed when
each tool moves onto the core: bwss in M4, the plugin in M6.
