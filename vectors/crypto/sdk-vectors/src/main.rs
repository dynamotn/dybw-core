//! Known-answer vectors for EncString type 7 (COSE_Encrypt0), produced with
//! Bitwarden's SDK (`bitwarden-crypto`), the implementation the official
//! clients use.
//!
//!   cargo run --release -- generate > ../cose-vectors.json
//!   cargo run --release -- verify < plugin-output.json
//!
//! `verify` reads `[{ "key": <base64 key>, "enc": <EncString>, "plain": <text> }]`
//! and fails unless the SDK decrypts every `enc` to its `plain`.

use std::{io::Read, num::NonZeroU32};

use bitwarden_crypto::{
    EncString, Kdf, KeyDecryptable, KeyEncryptable, KeyStore, MasterKey, PrivateKey,
    PublicKeyEncryptionAlgorithm, SymmetricCryptoKey, SymmetricKeyAlgorithm, key_slot_ids,
};
use serde_json::{Value, json};

key_slot_ids! {
    #[symmetric]
    pub enum SymmetricSlots {
        User,
        #[local]
        Local(LocalId),
    }
    #[private]
    pub enum PrivateSlots {
        UserPrivate,
        #[local]
        Local(LocalId),
    }
    #[signing]
    pub enum SigningSlots {
        UserSigning,
        #[local]
        Local(LocalId),
    }
    pub Slots => SymmetricSlots, PrivateSlots, SigningSlots;
}

const EMAIL: &str = "user@example.com";
const PASSWORD: &str = "master password ✓";
const ITERATIONS: u32 = 5_000;

const TEXTS: &[&str] = &[
    "",
    "a",
    "exactly thirty-one bytes long!!",
    "exactly thirty-two bytes long!!!",
    "Tiếng Việt có dấu, emoji 🙂 and a\nnew line",
];

fn account(algorithm: fn() -> SymmetricKeyAlgorithm, name: &str) -> Value {
    let user_key = SymmetricCryptoKey::make(algorithm());
    let kdf = Kdf::PBKDF2 { iterations: NonZeroU32::new(ITERATIONS).unwrap() };
    let master_key = MasterKey::derive(PASSWORD, EMAIL, &kdf).unwrap();
    let protected_user_key = master_key.encrypt_user_key(&user_key).unwrap();

    let texts: Vec<Value> = TEXTS
        .iter()
        .map(|t| {
            let enc: EncString = (*t).encrypt_with_key(&user_key).unwrap();
            json!({ "plain": t, "enc": enc.to_string() })
        })
        .collect();

    // Item keys are wrapped with the user key: a legacy 64-byte item key (what
    // the vault crate creates) and a COSE item key.
    let store: KeyStore<Slots> = KeyStore::default();
    #[allow(deprecated)]
    let mut ctx = store.context_mut();
    let user = ctx.add_local_symmetric_key(user_key.clone());
    let mut item_keys = Vec::new();
    for (kind, alg) in [("legacy", SymmetricKeyAlgorithm::Aes256CbcHmac), ("cose", algorithm())] {
        let item_key = SymmetricCryptoKey::make(alg);
        let slot = ctx.add_local_symmetric_key(item_key.clone());
        let wrapped = ctx.wrap_symmetric_key(user, slot).unwrap();
        let field: EncString = "value under the item key".encrypt_with_key(&item_key).unwrap();
        item_keys.push(json!({
            "kind": kind,
            "key": item_key.to_base64().to_string(),
            "wrapped": wrapped.to_string(),
            "field": field.to_string(),
            "fieldPlain": "value under the item key",
        }));
    }

    let private_key = PrivateKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let private_slot = ctx.add_local_private_key(private_key.clone());
    let wrapped_private = ctx.wrap_private_key(user, private_slot).unwrap();
    let pkcs8: Vec<u8> = private_key.to_der().unwrap().as_ref().to_vec();
    let spki: Vec<u8> = private_key.to_public_key().to_der().unwrap().as_ref().to_vec();

    json!({
        "name": name,
        "userKey": user_key.to_base64().to_string(),
        "protectedUserKey": protected_user_key.to_string(),
        "texts": texts,
        "itemKeys": item_keys,
        "privateKey": { "wrapped": wrapped_private.to_string(), "pkcs8": b64(&pkcs8), "spki": b64(&spki) },
    })
}

fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn verify() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let cases: Vec<Value> = serde_json::from_str(&input).unwrap();
    for (i, c) in cases.iter().enumerate() {
        let key = SymmetricCryptoKey::try_from(c["key"].as_str().unwrap().to_string()).unwrap();
        let enc: EncString = c["enc"].as_str().unwrap().parse().unwrap();
        let plain: String = enc.decrypt_with_key(&key).unwrap_or_else(|e| panic!("case {i}: {e:?}"));
        assert_eq!(plain, c["plain"].as_str().unwrap(), "case {i}");
    }
    println!("verified {} ciphertexts with the Bitwarden SDK", cases.len());
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("generate") => {
            let out = json!({
                "sdkRevision": "3d1643792b202961a84db83f6e45d9b5e2bb1ffe",
                "email": EMAIL,
                "password": PASSWORD,
                "pbkdf2Iterations": ITERATIONS,
                "accounts": [
                    account(|| SymmetricKeyAlgorithm::XAes256Gcm, "xaes-256-gcm"),
                    account(|| SymmetricKeyAlgorithm::XChaCha20Poly1305, "xchacha20-poly1305"),
                ],
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        Some("verify") => verify(),
        _ => {
            eprintln!("usage: sdk-vectors generate | verify");
            std::process::exit(2);
        }
    }
}
