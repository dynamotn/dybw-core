use super::aead::seal;
use super::cbor::{self, Cbor};
use super::cose::{
    ContentFormat, CoseAlgorithm, CoseKey, cose_decrypt, cose_encrypt, enc_structure, int, pad, padded_key_bytes,
    parse_cose_key, parse_cose_key_as,
};
use super::envelope::*;
use super::*;
use crate::ports::{PortError, Random};
use crate::testing::SeededRandom;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};

const NS: EnvelopeNamespace = EnvelopeNamespace::VaultItem;
const CONTENT_TYPE: &str = "application/x.bitwarden.cbor-padded";

struct Fails;
impl Random for Fails {
    fn fill(&self, _: &mut [u8]) -> Result<(), PortError> {
        Err(PortError("rng down".into()))
    }
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../../vectors/crypto/sdk-m3.json")).unwrap()
}

fn b64(v: &Value) -> Vec<u8> {
    B64.decode(v.as_str().unwrap()).unwrap()
}

/// A CEK as the SDK stores it: a COSE key with one padding byte.
fn cek_of(v: &Value) -> CoseKey {
    parse_cek(&b64(v)).unwrap()
}

/// The sealed content as JSON, to compare with the vectors' plaintext.
fn json_of(c: &Cbor) -> Value {
    match c {
        Cbor::Uint(n) => json!(n),
        Cbor::Nint(n) => json!(-1 - i128::from(*n)),
        Cbor::Bool(b) => json!(b),
        Cbor::Null => Value::Null,
        Cbor::Text(t) => json!(t.as_str()),
        Cbor::Bytes(_) => panic!("no bytes in vectors"),
        Cbor::Array(a) => Value::Array(a.iter().map(json_of).collect()),
        Cbor::Map(m) => Value::Object(
            m.iter()
                .map(|(k, v)| match k {
                    Cbor::Text(t) => (t.to_string(), json_of(v)),
                    _ => panic!("text keys only"),
                })
                .collect(),
        ),
    }
}

/// What a forged envelope gets wrong; `Default` is a valid VaultItem envelope under AES-256-GCM.
struct Forge {
    kid: Option<Vec<u8>>,
    object: u64,
    content: u64,
    content_type: &'static str,
    alg: Option<i64>,
    iv_len: Option<usize>,
    crit: bool,
}

impl Default for Forge {
    fn default() -> Self {
        Forge { kid: None, object: 2, content: 1, content_type: CONTENT_TYPE, alg: None, iv_len: None, crit: false }
    }
}

/// Seals `padded` (already padded plaintext) under `cek` with the header `f` describes.
fn forge(cek: &CoseKey, padded: &[u8], f: Forge) -> Vec<u8> {
    let mut header = vec![
        (int(1), int(f.alg.unwrap_or(cek.alg().number()))),
        (int(3), Cbor::text(f.content_type)),
        (int(4), Cbor::bytes(f.kid.unwrap_or_else(|| cek.id().to_vec()))),
        (int(-80002), Cbor::Uint(f.object)),
        (int(-80001), Cbor::Uint(f.content)),
    ];
    if f.crit {
        header.push((int(2), Cbor::Array(vec![int(1)])));
    }
    let protected = cbor::encode(&Cbor::Map(header));
    let iv = vec![7u8; cek.alg().nonce_size()];
    let ct = seal(cek.alg(), cek.secret(), &iv, padded, &enc_structure(&protected)).unwrap();
    let iv = vec![7u8; f.iv_len.unwrap_or(iv.len())];
    cbor::encode(&Cbor::Array(vec![
        Cbor::bytes(protected),
        Cbor::Map(vec![(int(5), Cbor::bytes(iv))]),
        Cbor::bytes(ct),
    ]))
}

fn content() -> Cbor {
    Cbor::Map(vec![(Cbor::text("version"), Cbor::text("1")), (Cbor::text("content"), Cbor::Null)])
}

fn forged_ok(cek: &CoseKey) -> Vec<u8> {
    forge(cek, &pad(&cbor::encode(&content()), 64).unwrap(), Forge::default())
}

fn generated() -> CoseKey {
    CoseKey::generate(CoseAlgorithm::Aes256Gcm, &SeededRandom::new(9)).unwrap()
}

#[test]
fn opens_every_sdk_envelope() {
    let v = vectors();
    let all = v["v1"].as_object().unwrap();
    assert!(all.len() >= 8);
    for (name, item) in all {
        let (mut cek, mut envelope) = (None, None);
        for (k, e) in item.as_object().unwrap() {
            match k {
                k if k.ends_with("_CEK") => cek = Some(cek_of(&e["value"])),
                k if k.ends_with("_ENVELOPE") => envelope = Some(b64(&e["value"])),
                _ => {}
            }
        }
        let cek = cek.unwrap();
        assert!(cek.decrypt_only(), "{name}");
        let opened = open_envelope(&cek, &envelope.unwrap(), NS).unwrap();
        assert_eq!(json_of(&opened), item["plaintext"], "{name}");
    }
}

#[test]
fn opens_the_sealed_blob() {
    let v = vectors();
    let wrapping = SymmetricKey::from_bytes(&b64(&v["sealed"]["TEST_VECTOR_WRAPPING_KEY"]["value"])).unwrap();
    let blob: Value = serde_json::from_str(v["sealed"]["TEST_VECTOR_SEALED_BLOB"]["value"].as_str().unwrap()).unwrap();
    assert_eq!(blob["format_version"], 1);
    let cek = parse_cek(&wrapping.decrypt(blob["wrapped_cek"].as_str().unwrap()).unwrap()).unwrap();
    let opened = open_envelope(&cek, &b64(&blob["envelope"]), NS).unwrap();
    assert_eq!(json_of(&opened), v["sealed"]["plaintext"]);
}

#[test]
fn seal_then_open_round_trips() {
    let rng = SeededRandom::new(1);
    // under and over the 64-byte padding floor
    for len in [0, 100] {
        let c = Cbor::Map(vec![(Cbor::text("x"), Cbor::text("y".repeat(len)))]);
        let (envelope, cek) = seal_envelope(&c, NS, &rng).unwrap();
        assert_eq!(open_envelope(&cek, &envelope, NS).unwrap(), c);
    }
}

#[test]
fn sealed_cek_is_decrypt_only() {
    let (_, cek) = seal_envelope(&content(), NS, &SeededRandom::new(2)).unwrap();
    assert!(cek.decrypt_only());
    assert!(!generated().decrypt_only());
    assert_eq!(seal_envelope(&content(), NS, &Fails).unwrap_err(), CryptoError::Port("rng down".into()));
}

#[test]
fn seal_fails_when_the_second_draw_fails() {
    struct Once(std::cell::Cell<bool>, SeededRandom);
    impl Random for Once {
        fn fill(&self, b: &mut [u8]) -> Result<(), PortError> {
            // the key id and secret draw first, then the iv
            if b.len() == 12 && self.0.replace(true) { Err(PortError("iv".into())) } else { self.1.fill(b) }
        }
    }
    let rng = Once(std::cell::Cell::new(true), SeededRandom::new(3));
    assert_eq!(seal_envelope(&content(), NS, &rng).unwrap_err(), CryptoError::Port("iv".into()));
}

#[test]
fn opens_every_cek_algorithm() {
    for alg in [CoseAlgorithm::Aes256Gcm, CoseAlgorithm::Xaes256Gcm, CoseAlgorithm::XChaCha20Poly1305] {
        let cek = CoseKey::generate(alg, &SeededRandom::new(4)).unwrap();
        assert_eq!(open_envelope(&cek, &forged_ok(&cek), NS).unwrap(), content());
    }
}

#[test]
fn refuses_wrong_kid() {
    let (cek, other) = (generated(), CoseKey::generate(CoseAlgorithm::Aes256Gcm, &SeededRandom::new(5)).unwrap());
    assert_eq!(open_envelope(&other, &forged_ok(&cek), NS).unwrap_err(), CryptoError::WrongKey);
}

#[test]
fn refuses_wrong_object_namespace() {
    let cek = generated();
    let p = pad(&cbor::encode(&content()), 64).unwrap();
    let e = forge(&cek, &p, Forge { object: 1, ..Forge::default() });
    assert_eq!(open_envelope(&cek, &e, NS).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_wrong_content_namespace() {
    let cek = generated();
    let p = pad(&cbor::encode(&content()), 64).unwrap();
    let e = forge(&cek, &p, Forge { content: 9, ..Forge::default() });
    assert_eq!(open_envelope(&cek, &e, NS).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_wrong_content_type_alg_and_iv() {
    let cek = generated();
    let p = pad(&cbor::encode(&content()), 64).unwrap();
    let wrong_type = forge(&cek, &p, Forge { content_type: "application/x.bitwarden.utf8-padded", ..Forge::default() });
    assert_eq!(open_envelope(&cek, &wrong_type, NS).unwrap_err(), CryptoError::Malformed);
    let wrong_alg = forge(&cek, &p, Forge { alg: Some(-70000), ..Forge::default() });
    assert_eq!(open_envelope(&cek, &wrong_alg, NS).unwrap_err(), CryptoError::WrongKey);
    let unknown_alg = forge(&cek, &p, Forge { alg: Some(-25), ..Forge::default() });
    assert_eq!(open_envelope(&cek, &unknown_alg, NS).unwrap_err(), CryptoError::Malformed);
    let short_iv = forge(&cek, &p, Forge { iv_len: Some(11), ..Forge::default() });
    assert_eq!(open_envelope(&cek, &short_iv, NS).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_cbc_cek() {
    // COSE A256CBC-HS512 style: no CEK of that algorithm exists
    let key = cbor::encode(&Cbor::Map(vec![
        (Cbor::Uint(1), Cbor::Uint(4)),
        (Cbor::Uint(2), Cbor::bytes(vec![0; 16])),
        (Cbor::Uint(3), Cbor::Nint(24)),
        (Cbor::Nint(0), Cbor::bytes(vec![0; 32])),
    ]));
    assert_eq!(parse_cose_key(&key).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_an_encrypt_only_cek() {
    let key = cbor::encode(&Cbor::Map(vec![
        (Cbor::Uint(1), Cbor::Uint(4)),
        (Cbor::Uint(2), Cbor::bytes(vec![0; 16])),
        (Cbor::Uint(3), Cbor::Uint(3)),
        (Cbor::Uint(4), Cbor::Array(vec![Cbor::Uint(3)])),
        (Cbor::Nint(0), Cbor::bytes(vec![0; 32])),
    ]));
    let cek = parse_cose_key_as(&key, true).unwrap();
    assert_eq!(open_envelope(&cek, &forged_ok(&cek), NS).unwrap_err(), CryptoError::WrongKey);
}

#[test]
fn refuses_tampered_ciphertext() {
    let cek = generated();
    let mut e = forged_ok(&cek);
    let last = e.len() - 1;
    e[last] ^= 1;
    assert_eq!(open_envelope(&cek, &e, NS).unwrap_err(), CryptoError::BadMac);
}

#[test]
fn refuses_malformed_envelopes() {
    let cek = generated();
    for e in [cbor::encode(&Cbor::Uint(1)), cbor::encode(&Cbor::Array(vec![])), vec![0xff]] {
        assert_eq!(open_envelope(&cek, &e, NS).unwrap_err(), CryptoError::Malformed);
    }
    // a protected header that is not a map, and an unprotected one that is not either
    let part = |p: Cbor, u: Cbor| cbor::encode(&Cbor::Array(vec![p, u, Cbor::bytes(vec![0; 20])]));
    let not_map = part(Cbor::bytes(cbor::encode(&Cbor::Uint(1))), Cbor::Null);
    assert_eq!(open_envelope(&cek, &not_map, NS).unwrap_err(), CryptoError::Malformed);
    // a valid header with a bad unprotected part
    let good = cbor::decode(&forged_ok(&cek)).unwrap();
    let Cbor::Array(mut parts) = good else { panic!() };
    parts[1] = Cbor::Null;
    assert_eq!(open_envelope(&cek, &cbor::encode(&Cbor::Array(parts)), NS).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_bad_padding_and_content() {
    let cek = generated();
    for plain in [&[0u8][..], &[0x01][..]] {
        let e = forge(&cek, plain, Forge::default());
        assert_eq!(open_envelope(&cek, &e, NS).unwrap_err(), CryptoError::Malformed);
    }
}

#[test]
fn envelope_huge_map_header_fails_without_allocating() {
    let cek = generated();
    // a map claiming 2^64-1 entries, then one pad byte
    let plain = [0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1];
    let e = forge(&cek, &plain, Forge::default());
    assert_eq!(open_envelope(&cek, &e, NS).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_a_crit_header() {
    let cek = generated();
    let p = pad(&cbor::encode(&content()), 64).unwrap();
    let e = forge(&cek, &p, Forge { crit: true, ..Forge::default() });
    assert_eq!(open_envelope(&cek, &e, NS).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn aes_gcm_is_only_for_content_keys() {
    let cek = generated();
    let padded = padded_key_bytes(&cek);
    // as a user or item key
    assert_eq!(SymmetricKey::from_bytes(&padded).unwrap_err(), CryptoError::Malformed);
    assert_eq!(parse_cose_key(&super::cose::encode_cose_key(&cek)).unwrap_err(), CryptoError::Malformed);
    // as an EncString type 7 key
    let rng = SeededRandom::new(6);
    assert_eq!(cose_encrypt(&cek, b"x", ContentFormat::OctetStream, &rng).unwrap_err(), CryptoError::WrongKey);
    assert_eq!(cose_decrypt(&cek, "AAAA").unwrap_err(), CryptoError::WrongKey);
}

#[test]
fn an_encoded_cek_is_65_bytes_and_a_legacy_key_is_refused() {
    let (_, cek) = seal_envelope(&content(), NS, &SeededRandom::new(7)).unwrap();
    let padded = padded_key_bytes(&cek);
    // 61 bytes of COSE key with key_ops [4], then four 0x04
    assert_eq!((padded.len(), &padded[61..]), (65, &[4u8, 4, 4, 4][..]));
    assert_eq!(parse_cek(&padded).unwrap().id(), cek.id());
    for len in [32, 64] {
        assert_eq!(parse_cek(&vec![1; len]).unwrap_err(), CryptoError::Malformed);
    }
}
