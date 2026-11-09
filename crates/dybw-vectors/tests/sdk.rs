//! The other direction of `crypto/cose-vectors.json`: Bitwarden's SDK (`vectors/crypto/sdk-vectors verify`) decrypts
//! what the core encrypted. The plugin's `test/sdk/verify.test.ts`, case by case. It builds the SDK from git, so it
//! is opt-in: `cargo test -p dybw-vectors --test sdk -- --ignored`.
#![cfg(feature = "native")]
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::crypto::{ContentFormat, SymmetricKey};
use dybw_core::testing::SeededRandom;
use dybw_vectors::vectors_dir;
use serde_json::{Value, json};
use std::io::Write as _;
use std::process::{Command, Stdio};

#[test]
#[ignore = "builds Bitwarden's SDK: run with --ignored"]
fn bitwarden_sdk_decrypts_strings_and_wrapped_keys_the_core_produced() {
    let dir = vectors_dir().unwrap();
    let sdk: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("crypto/cose-vectors.json")).unwrap()).unwrap();
    let rng = SeededRandom::new(0x5d6b);
    let mut cases = Vec::new();
    for account in sdk["accounts"].as_array().unwrap() {
        let user_b64 = account["userKey"].as_str().unwrap();
        let key = SymmetricKey::from_bytes(&B64.decode(user_b64).unwrap()).unwrap();
        for plain in ["", "a", &"y".repeat(32), "Tiếng Việt 🙂 secret\nwith lines"] {
            cases.push(json!({ "key": user_b64, "enc": key.encrypt_str(plain, &rng).unwrap(), "plain": plain }));
        }
        // A value under a legacy item key the core wrapped with the COSE user key, as `vault::write` wraps one.
        let item = SymmetricKey::generate(&rng).unwrap();
        let wrapped = key.encrypt_as(&item.to_bytes(), ContentFormat::LegacyKey, &rng).unwrap();
        let unwrapped = key.decrypt_key(&wrapped).unwrap();
        let plain = "under an item key";
        let enc = item.encrypt_str(plain, &rng).unwrap();
        cases.push(json!({ "key": B64.encode(unwrapped.to_bytes()), "enc": enc, "plain": plain }));
    }
    let manifest = dir.join("crypto/sdk-vectors/Cargo.toml");
    let mut child = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args(["run", "--quiet", "--release", "--locked", "--manifest-path"])
        .arg(&manifest)
        .args(["--", "verify"])
        // The workspace's target dir, which CI caches; the fixture is a project of its own.
        .env("CARGO_TARGET_DIR", dir.join("../target/sdk-vectors"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(Value::from(cases.clone()).to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "the SDK refused a ciphertext the core produced");
    let out = String::from_utf8(out.stdout).unwrap();
    assert!(out.contains(&format!("verified {} ciphertexts", cases.len())), "{out}");
}
