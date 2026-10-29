use super::key::hmac;
use super::mark::{MarkScheme, Marker};
use super::rsa::{AwsLcRsa, unwrap_org_key};
use super::*;
use crate::ports::{OaepHash, PortError, RsaOaep};
use crate::testing::{SeededRandom, block_on};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use std::cell::Cell;
use zeroize::Zeroizing;

fn read(rel: &str) -> Value {
    let dir = std::env::var("DYBW_VECTORS_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors").into());
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{rel}")).unwrap()).unwrap()
}
fn b64(v: &Value) -> Vec<u8> {
    B64.decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn marks_match_kat() {
    let rows = read("crypto/marks.json");
    assert_eq!(rows.as_array().unwrap().len(), 12);
    for r in rows.as_array().unwrap() {
        let user = SymmetricKey::from_bytes(&b64(
            &read(&format!("accounts/{}.json", r["account"].as_str().unwrap()))["userKey"]
        ))
        .unwrap();
        let scheme = if r["scheme"] == "bwss" { MarkScheme::Bwss } else { MarkScheme::Obsidian };
        let m = Marker::new(&user, scheme);
        let (id, text) = (r["id"].as_str().unwrap(), r["text"].as_str().unwrap());
        assert_eq!(m.mark(id, text).to_vec(), b64(&r["mark"]), "{r}");
        assert_eq!(m.mark_b64(id, text), r["mark"].as_str().unwrap());
        assert_eq!(format!("{m:?}"), "Marker(<redacted>)");
    }
}

#[test]
fn marks_on_cose_keys_and_subkeys() {
    let acc = &read("crypto/cose-vectors.json")["accounts"][0];
    let user = SymmetricKey::from_bytes(&b64(&acc["userKey"])).unwrap();
    let SymmetricKey::Cose(c) = &user else { unreachable!() };
    // Plugin: deriveSubKey over the single 32-byte COSE key.
    let sub = hmac(c.secret(), &[b"obsidian-keychain-bitwarden:value-fingerprint", &[1]]);
    assert_eq!(Marker::new(&user, MarkScheme::Obsidian).mark("i", "x"), hmac(&sub, &[b"i\0x"]));
    // bwss has no COSE keys; the core derives from the 32-byte key the same way.
    let mac = hmac(c.secret(), &[b"bwss value-mark mac", &[1]]);
    assert_eq!(Marker::new(&user, MarkScheme::Bwss).mark("i", "x"), hmac(&mac, &[b"i\0x"]));
    let legacy = SymmetricKey::generate(&SeededRandom::new(5)).unwrap();
    let queue = legacy.derive_bwss("queue");
    assert_eq!(queue.to_bytes().to_vec(), legacy.derive_bwss("queue").to_bytes().to_vec());
    assert_ne!(queue.to_bytes().to_vec(), legacy.derive_bwss("vault-acl").to_bytes().to_vec());
    let m = Marker::new(&legacy, MarkScheme::Bwss);
    assert_ne!(m.mark("ab", "c"), m.mark("a", "bc"));
}

#[test]
fn org_keys_unwrap() {
    let acc = read("accounts/org.json");
    let pk = b64(&acc["privateKey"]);
    for o in acc["organizations"].as_array().unwrap() {
        let wrapped = o["wrapped"].as_str().unwrap();
        let key = block_on(unwrap_org_key(wrapped, &pk, &AwsLcRsa)).unwrap();
        assert_eq!(key.to_bytes().to_vec(), b64(&o["key"]));
        let mut ct = B64.decode(wrapped.strip_prefix("4.").unwrap()).unwrap();
        ct[7] ^= 1;
        assert!(block_on(unwrap_org_key(&format!("4.{}", B64.encode(&ct)), &pk, &AwsLcRsa)).is_err());
    }
    let body = acc["organizations"][0]["wrapped"].as_str().unwrap().strip_prefix("4.").unwrap();
    assert_eq!(
        block_on(unwrap_org_key(&format!("5.{body}"), &pk, &AwsLcRsa)).unwrap_err(),
        CryptoError::UnsupportedType(5)
    );
    assert_eq!(
        block_on(unwrap_org_key(&format!("6.{body}"), &pk, &AwsLcRsa)).unwrap_err(),
        CryptoError::UnsupportedType(6)
    );
    assert_eq!(
        block_on(unwrap_org_key(&format!("2.{body}"), &pk, &AwsLcRsa)).unwrap_err(),
        CryptoError::UnsupportedType(2)
    );
    for bad in ["nodot", "x.AAAA", "04.AAAA", "4.!!!"] {
        assert_eq!(block_on(unwrap_org_key(bad, &pk, &AwsLcRsa)).unwrap_err(), CryptoError::Malformed, "{bad}");
    }
    // A key that is not PKCS#8 fails without echoing it.
    let e = block_on(unwrap_org_key(&format!("4.{body}"), &[1, 2, 3], &AwsLcRsa)).unwrap_err();
    assert!(matches!(&e, CryptoError::Port(t) if !t.contains("AQID")), "{e}");
}

#[test]
fn org_key_type_3_is_oaep_sha256() {
    use aws_lc_rs::rsa::{OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PublicEncryptingKey};
    let acc = read("accounts/org.json");
    let key = b64(&acc["organizations"][0]["key"]);
    let public = OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(&b64(&acc["publicKey"])).unwrap()).unwrap();
    let mut ct = vec![0; public.ciphertext_size()];
    let ct = public.encrypt(&OAEP_SHA256_MGF1SHA256, &key, &mut ct, None).unwrap();
    let got = block_on(unwrap_org_key(&format!("3.{}", B64.encode(&ct)), &b64(&acc["privateKey"]), &AwsLcRsa)).unwrap();
    assert_eq!(got.to_bytes().to_vec(), key);
    // The same ciphertext read as SHA-1 fails.
    assert!(block_on(unwrap_org_key(&format!("4.{}", B64.encode(&ct)), &b64(&acc["privateKey"]), &AwsLcRsa)).is_err());
}

/// A port that records the hash it was asked for.
struct Records(Cell<Option<OaepHash>>);
impl RsaOaep for Records {
    async fn decrypt(&self, _: &[u8], hash: OaepHash, _: &[u8]) -> Result<Zeroizing<Vec<u8>>, PortError> {
        self.0.set(Some(hash));
        Ok(Zeroizing::new(vec![7; 64]))
    }
}

#[test]
fn org_key_type_picks_the_hash() {
    for (ty, hash) in [("3", OaepHash::Sha256), ("4", OaepHash::Sha1)] {
        let port = Records(Cell::new(None));
        assert_eq!(
            block_on(unwrap_org_key(&format!("{ty}.AAAA"), &[], &port)).unwrap().to_bytes().to_vec(),
            vec![7; 64]
        );
        assert_eq!(port.0.get(), Some(hash));
    }
}

#[test]
fn pkcs8_has_its_own_decrypt() {
    let acc = &read("crypto/cose-vectors.json")["accounts"][0];
    let user = SymmetricKey::from_bytes(&b64(&acc["userKey"])).unwrap();
    let wrapped = acc["privateKey"]["wrapped"].as_str().unwrap();
    assert_eq!(user.decrypt_pkcs8(wrapped).unwrap().to_vec(), b64(&acc["privateKey"]["pkcs8"]));
    assert_eq!(user.decrypt(wrapped).unwrap_err(), CryptoError::Malformed);
    let rng = SeededRandom::new(3);
    let bytes = user.encrypt(b"x", &rng).unwrap();
    assert_eq!(user.decrypt_pkcs8(&bytes).unwrap_err(), CryptoError::Malformed);
    // Type 2 carries no label: a legacy key's private key is plain bytes.
    let legacy = SymmetricKey::generate(&rng).unwrap();
    assert_eq!(legacy.decrypt_pkcs8(&legacy.encrypt(b"der", &rng).unwrap()).unwrap().as_slice(), b"der");
}
