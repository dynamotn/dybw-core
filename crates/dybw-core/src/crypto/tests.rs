use super::*;
use crate::ports::{Argon2Input, KdfRunner, PortError, Random};
use crate::testing::{SeededRandom, block_on};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use zeroize::Zeroizing;

fn vectors() -> Value {
    let dir = std::env::var("DYBW_VECTORS_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors").into());
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/crypto/vectors.json")).unwrap()).unwrap()
}
fn b64(v: &Value) -> Vec<u8> {
    B64.decode(v.as_str().unwrap()).unwrap()
}

struct Panics;
impl KdfRunner for Panics {
    async fn argon2id(&self, _: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError> {
        panic!("runner must not be called");
    }
}
struct Fails;
impl Random for Fails {
    fn fill(&self, _: &mut [u8]) -> Result<(), PortError> {
        Err(PortError("rng down".into()))
    }
}

#[test]
fn master_keys_match_kat() {
    let v = vectors();
    let (pw, email) = (v["password"].as_str().unwrap(), v["email"].as_str().unwrap());
    let p = &v["pbkdf2"];
    let kdf = KdfParams::Pbkdf2 { iterations: p["iterations"].as_u64().unwrap() as u32 };
    let mk = block_on(derive_master_key(pw, email, kdf, &NativeArgon2)).unwrap();
    assert_eq!(mk.to_vec(), b64(&p["masterKey"]));
    assert_eq!(SymmetricKey::stretch(&mk).to_bytes().to_vec(), b64(&p["stretched"]));
    assert_eq!(hash_master_password(&mk, pw), p["masterPasswordHash"].as_str().unwrap());
    let a = &v["argon2id"];
    let kdf = KdfParams::Argon2id {
        iterations: a["iterations"].as_u64().unwrap() as u32,
        memory_mib: a["memory"].as_u64().unwrap() as u32,
        parallelism: a["parallelism"].as_u64().unwrap() as u32,
    };
    let mk = block_on(derive_master_key(pw, email, kdf, &NativeArgon2)).unwrap();
    assert_eq!(mk.to_vec(), b64(&a["masterKey"]));
    assert_eq!(SymmetricKey::stretch(&mk).to_bytes().to_vec(), b64(&a["stretched"]));
}

#[test]
fn native_argon2_reports_bad_parameters() {
    let input =
        Argon2Input { password: Zeroizing::new(vec![1]), salt: [0; 32], iterations: 3, memory_kib: 0, parallelism: 4 };
    assert!(block_on(NativeArgon2.argon2id(input)).is_err());
    let e = block_on(derive_master_key(
        "p",
        "e",
        KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 },
        &FailRunner,
    ))
    .unwrap_err();
    assert_eq!(e, CryptoError::Kdf("boom".into()));
}
struct FailRunner;
impl KdfRunner for FailRunner {
    async fn argon2id(&self, _: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError> {
        Err(PortError("boom".into()))
    }
}

#[test]
fn enc_strings_match_kat() {
    let v = vectors();
    let user = SymmetricKey::from_bytes(&b64(&v["userKey"])).unwrap();
    let stretched = SymmetricKey::from_bytes(&b64(&v["pbkdf2"]["stretched"])).unwrap();
    assert_eq!(
        stretched.decrypt_key(v["protectedUserKey"].as_str().unwrap()).unwrap().to_bytes().to_vec(),
        b64(&v["userKey"])
    );
    for e in v["encStrings"].as_array().unwrap() {
        let enc = e["enc"].as_str().unwrap();
        assert_eq!(user.decrypt_str(enc).unwrap().as_str(), e["plain"].as_str().unwrap());
        let (head, mac) = enc.rsplit_once('|').unwrap();
        let mut m = B64.decode(mac).unwrap();
        m[0] ^= 1;
        assert_eq!(user.decrypt(&format!("{head}|{}", B64.encode(m))).unwrap_err(), CryptoError::BadMac);
    }
    let enc = v["encStrings"][0]["enc"].as_str().unwrap();
    let parts: Vec<&str> = enc[2..].split('|').collect();
    let short_iv = format!("2.{}|{}|{}", B64.encode([0u8; 15]), parts[1], parts[2]);
    assert_eq!(user.decrypt(&short_iv).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn malformed_and_unsupported_inputs() {
    let k = SymmetricKey::generate(&SeededRandom::new(9)).unwrap();
    for s in ["nodot", "x.rest", "2.a|b", "2.!!|!!|!!", "2.|ct|mac"] {
        assert_eq!(k.decrypt(s).unwrap_err(), CryptoError::Malformed, "{s}");
    }
    let iv = B64.encode([0u8; 16]);
    let mac = B64.encode([0u8; 32]);
    for ct in ["", "AA=="] {
        assert_eq!(k.decrypt(&format!("2.{iv}|{ct}|{mac}")).unwrap_err(), CryptoError::Malformed);
    }
    let ct16 = B64.encode([0u8; 16]);
    assert_eq!(k.decrypt(&format!("2.{iv}|{ct16}|{}", B64.encode([0u8; 31]))).unwrap_err(), CryptoError::Malformed);
    assert_eq!(k.decrypt(&format!("2.{iv}|{ct16}|{mac}|{mac}")).unwrap_err(), CryptoError::Malformed);
    let good = k.encrypt(b"x", &SeededRandom::new(1)).unwrap();
    let body = good.strip_prefix("2.").unwrap();
    for pre in ["02.", "+2.", "2 .", "."] {
        assert_eq!(k.decrypt(&format!("{pre}{body}")).unwrap_err(), CryptoError::Malformed, "{pre}");
    }
    assert_eq!(k.decrypt("7.abc").unwrap_err(), CryptoError::UnsupportedType(7));
    assert_eq!(k.decrypt("0.a|b|c").unwrap_err(), CryptoError::UnsupportedType(0));
    assert_eq!(SymmetricKey::from_bytes(&[0; 63]).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn round_trip() {
    let rng = SeededRandom::new(1);
    let k = SymmetricKey::generate(&rng).unwrap();
    assert_eq!(k.decrypt(&k.encrypt(b"x", &SeededRandom::new(1)).unwrap()).unwrap().as_slice(), b"x");
    assert_eq!(k.decrypt_str(&k.encrypt_str("héllo", &rng).unwrap()).unwrap().as_str(), "héllo");
    let bad = k.encrypt(&[0xff, 0xfe], &rng).unwrap();
    assert_eq!(k.decrypt_str(&bad).unwrap_err(), CryptoError::Decrypt);
    let other = SymmetricKey::generate(&rng).unwrap();
    assert_eq!(other.decrypt(&bad).unwrap_err(), CryptoError::BadMac);
    // A valid MAC over ciphertext that is not valid PKCS7 padding.
    let wrapped = k.encrypt(&k.to_bytes(), &rng).unwrap();
    assert_eq!(k.decrypt_key(&wrapped).unwrap().to_bytes().to_vec(), k.to_bytes().to_vec());
}

#[test]
fn bad_padding_is_decrypt_error() {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
    let k = SymmetricKey::generate(&SeededRandom::new(3)).unwrap();
    let (enc, mac) = k.parts();
    let iv = [7u8; 16];
    let ct = cbc::Encryptor::<aes::Aes256>::new(&(*enc).into(), &iv.into()).encrypt_padded_vec::<NoPadding>(&[0u8; 16]);
    let tag = key_hmac(mac, &iv, &ct);
    let s = format!("2.{}|{}|{}", B64.encode(iv), B64.encode(&ct), B64.encode(tag));
    assert_eq!(k.decrypt(&s).unwrap_err(), CryptoError::Decrypt);
}
fn key_hmac(key: &[u8], iv: &[u8], ct: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).unwrap();
    m.update(iv);
    m.update(ct);
    m.finalize().into_bytes().into()
}

#[test]
fn rng_and_key_ref() {
    assert_eq!(SymmetricKey::generate(&Fails).unwrap_err(), CryptoError::Port("rng down".into()));
    let k = SymmetricKey::generate(&SeededRandom::new(5)).unwrap();
    assert_eq!(k.encrypt(b"x", &Fails).unwrap_err(), CryptoError::Port("rng down".into()));
    let owner = KeyRef::Owner(&k);
    assert_eq!(owner.to_bytes().len(), 64);
    let own = KeyRef::Own(SymmetricKey::from_bytes(&k.to_bytes()).unwrap());
    assert_eq!(own.to_bytes().to_vec(), owner.to_bytes().to_vec());
    assert_eq!(CryptoError::WrongKey.to_string(), "wrong key for this value");
}

#[test]
fn kdf_bounds() {
    for kdf in [
        KdfParams::Pbkdf2 { iterations: 4_999 },
        KdfParams::Pbkdf2 { iterations: 2_000_001 },
        KdfParams::Argon2id { iterations: 1, memory_mib: 64, parallelism: 4 },
        KdfParams::Argon2id { iterations: 11, memory_mib: 64, parallelism: 4 },
        KdfParams::Argon2id { iterations: 3, memory_mib: 15, parallelism: 4 },
        KdfParams::Argon2id { iterations: 3, memory_mib: 1_025, parallelism: 4 },
        KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 0 },
        KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 17 },
    ] {
        assert!(matches!(block_on(derive_master_key("p", "e", kdf, &Panics)), Err(CryptoError::Kdf(_))), "{kdf:?}");
    }
    assert!(KdfParams::Pbkdf2 { iterations: 5_000 }.validate().is_ok());
    assert!(KdfParams::Argon2id { iterations: 10, memory_mib: 1_024, parallelism: 16 }.validate().is_ok());
}

#[test]
fn debug_and_errors_are_redacted() {
    let k = SymmetricKey::generate(&SeededRandom::new(2)).unwrap();
    assert_eq!(format!("{k:?}"), "SymmetricKey(<redacted>)");
    let SymmetricKey::Legacy(inner) = &k;
    assert_eq!(format!("{inner:?}"), "LegacyKey(<redacted>)");
    let key_b64 = B64.encode(k.to_bytes().as_slice());
    let plain_b64 = B64.encode(b"secret-plaintext");
    let enc = k.encrypt(b"secret-plaintext", &SeededRandom::new(2)).unwrap();
    let other = SymmetricKey::generate(&SeededRandom::new(4)).unwrap();
    let errs = [
        other.decrypt(&enc).unwrap_err(),
        k.decrypt("2.bad").unwrap_err(),
        k.decrypt("9.x").unwrap_err(),
        SymmetricKey::from_bytes(&k.to_bytes()[..10]).unwrap_err(),
        CryptoError::Kdf("x".into()),
        CryptoError::Decrypt,
        CryptoError::WrongKey,
    ];
    for e in errs {
        let t = format!("{e} {e:?}");
        assert!(!t.contains(&key_b64) && !t.contains(&plain_b64) && !t.contains("secret-plaintext"), "{t}");
    }
}
