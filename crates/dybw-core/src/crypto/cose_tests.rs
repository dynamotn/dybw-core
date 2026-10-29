use super::aead::*;
use super::cbor::{self, Cbor};
use super::cose::*;
use super::*;
use crate::ports::{PortError, Random};
use crate::testing::SeededRandom;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;

struct Fails;
impl Random for Fails {
    fn fill(&self, _: &mut [u8]) -> Result<(), PortError> {
        Err(PortError("rng down".into()))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn b64(v: &Value) -> Vec<u8> {
    B64.decode(v.as_str().unwrap()).unwrap()
}
fn cose_vectors() -> Value {
    let dir = std::env::var("DYBW_VECTORS_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors").into());
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/crypto/cose-vectors.json")).unwrap()).unwrap()
}
fn key_map(len: usize, ops: Option<Vec<u64>>) -> Vec<(Cbor, Cbor)> {
    let mut m = vec![
        (Cbor::Uint(1), Cbor::Uint(4)),
        (Cbor::Uint(2), Cbor::Bytes(vec![0; 16])),
        (Cbor::Uint(3), Cbor::Nint(70009)),
        (Cbor::Nint(0), Cbor::Bytes(vec![0; len])),
    ];
    if let Some(ops) = ops {
        m.insert(3, (Cbor::Uint(4), Cbor::Array(ops.into_iter().map(Cbor::Uint).collect())));
    }
    m
}

#[test]
fn xaes_c2sp() {
    let nonce = *b"ABCDEFGHIJKLMNOPQRSTUVWX";
    for (key, aad, want) in [
        (1u8, "", "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"),
        (3, "c2sp.org/XAES-256-GCM", "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"),
    ] {
        let key = [key; 32];
        let ct = xaes256gcm_encrypt(&key, &nonce, b"XAES-256-GCM", aad.as_bytes()).unwrap();
        assert_eq!(hex(&ct), want);
        let pt = xaes256gcm_decrypt(&key, &nonce, &ct, aad.as_bytes()).unwrap();
        assert_eq!(pt.as_slice(), b"XAES-256-GCM");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(xaes256gcm_decrypt(&key, &nonce, &bad, aad.as_bytes()).unwrap_err(), CryptoError::BadMac);
    }
}

#[test]
fn xchacha_round_trip_and_tamper() {
    let (key, nonce) = ([5u8; 32], [6u8; 24]);
    let ct = xchacha20poly1305_encrypt(&key, &nonce, b"hello", b"aad").unwrap();
    assert_eq!(xchacha20poly1305_decrypt(&key, &nonce, &ct, b"aad").unwrap().as_slice(), b"hello");
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert_eq!(xchacha20poly1305_decrypt(&key, &nonce, &bad, b"aad").unwrap_err(), CryptoError::BadMac);
    assert_eq!(xchacha20poly1305_decrypt(&key, &nonce, &ct, b"other").unwrap_err(), CryptoError::BadMac);
}

#[test]
fn aead_inputs() {
    // The AEAD functions take `&[u8; 32]`, so a 16- or 33-byte key cannot reach them (no silent AES-128); the key
    // parser, the only way in from bytes, refuses those lengths.
    for len in [16usize, 31, 33] {
        let k = cbor::encode(&Cbor::Map(key_map(len, None)));
        assert_eq!(parse_cose_key(&k).unwrap_err(), CryptoError::Malformed);
    }
    assert!(parse_cose_key(&cbor::encode(&Cbor::Map(key_map(32, None)))).is_ok());
}

#[test]
fn cose_vectors_decrypt() {
    let v = cose_vectors();
    for acc in v["accounts"].as_array().unwrap() {
        let user = SymmetricKey::from_bytes(&b64(&acc["userKey"])).unwrap();
        assert!(matches!(user, SymmetricKey::Cose(_)));
        assert_eq!(user.to_bytes().to_vec(), b64(&acc["userKey"]));
        for t in acc["texts"].as_array().unwrap() {
            assert_eq!(user.decrypt_str(t["enc"].as_str().unwrap()).unwrap().as_str(), t["plain"].as_str().unwrap());
        }
        let p = &acc["privateKey"];
        assert_eq!(user.decrypt(p["wrapped"].as_str().unwrap()).unwrap().to_vec(), b64(&p["pkcs8"]));
        for k in acc["itemKeys"].as_array().unwrap() {
            let item = user.decrypt_key(k["wrapped"].as_str().unwrap()).unwrap();
            assert_eq!(item.to_bytes().to_vec(), b64(&k["key"]));
            assert_eq!(matches!(item, SymmetricKey::Cose(_)), k["kind"] == "cose");
            assert_eq!(item.decrypt_str(k["field"].as_str().unwrap()).unwrap().as_str(), k["fieldPlain"]);
        }
    }
}

#[test]
fn cose_round_trip() {
    let rng = SeededRandom::new(11);
    for alg in [CoseAlgorithm::Xaes256Gcm, CoseAlgorithm::XChaCha20Poly1305] {
        let key = CoseKey::generate(alg, &rng).unwrap();
        for (plain, f) in [
            (&b""[..], ContentFormat::Utf8),
            (b"x", ContentFormat::Utf8),
            (&[7u8; 31], ContentFormat::Utf8),
            (&[7u8; 32], ContentFormat::Utf8),
            (&[1, 2, 3], ContentFormat::OctetStream),
            (&[1, 2, 3], ContentFormat::Pkcs8),
            (&[1, 2, 3], ContentFormat::LegacyKey),
            (&[1, 2, 3], ContentFormat::CoseKey),
        ] {
            let enc = cose_encrypt(&key, plain, f, &rng).unwrap();
            let (got, fmt) = cose_decrypt(&key, &enc).unwrap();
            assert_eq!((got.as_slice(), fmt), (plain, f));
        }
    }
}

#[test]
fn cbor_rejects() {
    use cbor::decode;
    let bad: &[&[u8]] = &[
        &[0x5f, 0xff],                   // indefinite bytes
        &[0x9f, 0xff],                   // indefinite array
        &[0xc1, 0x01],                   // tag
        &[0x01, 0x02],                   // trailing bytes
        &[0x42, 0x01],                   // truncated bytes
        &[0xa2, 0x01, 0x01, 0x01, 0x02], // duplicate map key
        &[0xf9, 0x00, 0x00],             // float
        &[0xf7],                         // undefined
        &[0x62, 0xff, 0xfe],             // bad UTF-8
        &[0xa1, 0x80, 0x01],             // array as map key
        &[],                             // empty
        &[0x1c],                         // reserved argument
    ];
    for b in bad {
        assert_eq!(decode(b).unwrap_err(), CryptoError::Malformed, "{b:02x?}");
    }
    let nest = |n: usize| [vec![0x81; n], vec![0]].concat();
    assert!(decode(&nest(16)).is_ok());
    assert_eq!(decode(&nest(17)).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn cbor_huge_array_header_fails_without_allocating() {
    for b in [&[0x9a, 0xff, 0xff, 0xff, 0xff][..], &[0xba, 0xff, 0xff, 0xff, 0xff], &[0x5a, 0xff, 0xff, 0xff, 0xff]] {
        assert_eq!(cbor::decode(b).unwrap_err(), CryptoError::Malformed);
    }
    assert_eq!(
        cbor::decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap_err(),
        CryptoError::Malformed
    );
}

#[test]
fn cbor_round_trip_shortest() {
    let v = Cbor::Array(vec![
        Cbor::Uint(0),
        Cbor::Uint(23),
        Cbor::Uint(24),
        Cbor::Uint(255),
        Cbor::Uint(256),
        Cbor::Uint(65535),
        Cbor::Uint(65536),
        Cbor::Uint(u32::MAX as u64),
        Cbor::Uint(1 << 32),
        Cbor::Uint(u64::MAX),
        Cbor::Nint(0),
        Cbor::Nint(u64::MAX),
        Cbor::Bytes(vec![1; 30]),
        Cbor::Text("tiếng".into()),
        Cbor::Bool(true),
        Cbor::Bool(false),
        Cbor::Null,
        Cbor::Map(vec![(Cbor::Uint(1), Cbor::Text("1".into())), (Cbor::Text("1".into()), Cbor::Uint(1))]),
    ]);
    let enc = cbor::encode(&v);
    assert_eq!(cbor::decode(&enc).unwrap(), v);
    let mut wiped = v.clone();
    zeroize::Zeroize::zeroize(&mut wiped);
    let Cbor::Array(items) = wiped else { unreachable!() };
    assert_eq!((&items[12], &items[13]), (&Cbor::Bytes(vec![]), &Cbor::Text(String::new())));
    assert_eq!(cbor::encode(&Cbor::Uint(24)), [0x18, 24]);
    assert_eq!(cbor::encode(&Cbor::Uint(256)), [0x19, 1, 0]);
}

#[test]
fn cose_pad_and_key_errors() {
    assert_eq!(pad(&[9], 4).unwrap().as_slice(), [9, 3, 3, 3]);
    assert_eq!(pad(&[9; 4], 4).unwrap().as_slice(), [9, 9, 9, 9, 1]);
    assert_eq!(pad(&[], 256).unwrap_err(), CryptoError::Malformed);
    assert_eq!(unpad(&[9, 3, 3, 3]).unwrap().as_slice(), [9]);
    for b in [&[][..], &[0], &[5, 1, 9]] {
        assert_eq!(unpad(b).unwrap_err(), CryptoError::Malformed);
    }
    let rng = SeededRandom::new(1);
    let key = CoseKey::generate(CoseAlgorithm::Xaes256Gcm, &rng).unwrap();
    let kb = encode_cose_key(&key);
    assert_eq!(parse_cose_key(&kb).unwrap().id(), key.id());
    let good = key_map(32, Some(vec![3, 4]));
    let enc = |m: Vec<(Cbor, Cbor)>| cbor::encode(&Cbor::Map(m));
    let with = |i: usize, e: Option<(Cbor, Cbor)>| {
        let mut m = good.clone();
        match e {
            Some(e) => m[i] = e,
            None => {
                m.remove(i);
            }
        }
        enc(m)
    };
    assert!(parse_cose_key(&enc(good.clone())).is_ok());
    // No key_ops means no operations allowed (the plugin's `?? []`), not all of them.
    let none = parse_cose_key(&with(3, None)).unwrap();
    let rng = SeededRandom::new(2);
    assert_eq!(cose_encrypt(&none, b"x", ContentFormat::Utf8, &rng).unwrap_err(), CryptoError::WrongKey);
    assert_eq!(cose_decrypt(&none, "AA==").unwrap_err(), CryptoError::WrongKey);
    // Duplicate or too many ops are refused, so an encoded key stays within its fixed buffer.
    for ops in [vec![3, 3], vec![3, 4, 5, 6, 3], vec![3; 200]] {
        let m = key_map(32, Some(ops));
        assert_eq!(parse_cose_key(&enc(m)).unwrap_err(), CryptoError::Malformed);
    }
    assert!(parse_cose_key(&enc(key_map(32, Some(vec![3, 4, 5, 6])))).is_ok());
    for bad in [
        with(0, Some((Cbor::Uint(1), Cbor::Uint(2)))),
        with(2, Some((Cbor::Uint(3), Cbor::Nint(1)))),
        with(2, None),
        with(3, Some((Cbor::Uint(4), Cbor::Array(vec![Cbor::Uint(9)])))),
        with(3, Some((Cbor::Uint(4), Cbor::Uint(3)))),
        with(1, None),
        with(4, None),
        cbor::encode(&Cbor::Uint(1)),
        vec![0xff],
    ] {
        assert_eq!(parse_cose_key(&bad).unwrap_err(), CryptoError::Malformed);
    }
}

#[test]
fn cose_decrypt_refuses_wrong_key_and_shape() {
    let rng = SeededRandom::new(21);
    let a = CoseKey::generate(CoseAlgorithm::Xaes256Gcm, &rng).unwrap();
    let a2 = CoseKey::generate(CoseAlgorithm::Xaes256Gcm, &rng).unwrap();
    let c = CoseKey::generate(CoseAlgorithm::XChaCha20Poly1305, &rng).unwrap();
    let enc = cose_encrypt(&a, b"hi", ContentFormat::Utf8, &rng).unwrap();
    assert_eq!(cose_decrypt(&a2, &enc).unwrap_err(), CryptoError::WrongKey);
    assert_eq!(cose_decrypt(&c, &enc).unwrap_err(), CryptoError::WrongKey);
    for s in ["!!", "", "gA==", "gwA="] {
        assert_eq!(cose_decrypt(&a, s).unwrap_err(), CryptoError::Malformed, "{s}");
    }
    // Key operations: a key that may only wrap cannot encrypt or decrypt.
    let wrap_only = parse_cose_key(&cbor::encode(&Cbor::Map(key_map(32, Some(vec![5]))))).unwrap();
    assert_eq!(cose_encrypt(&wrap_only, b"x", ContentFormat::Utf8, &rng).unwrap_err(), CryptoError::WrongKey);
    assert_eq!(cose_decrypt(&wrap_only, &enc).unwrap_err(), CryptoError::WrongKey);
    assert_eq!(cose_encrypt(&a, b"x", ContentFormat::Utf8, &Fails).unwrap_err(), CryptoError::Port("rng down".into()));
    assert_eq!(CoseKey::generate(CoseAlgorithm::Xaes256Gcm, &Fails).unwrap_err(), CryptoError::Port("rng down".into()));
    // Hand-built messages.
    let prot = |m: Vec<(Cbor, Cbor)>| cbor::encode(&Cbor::Map(m));
    let msg = |p: Vec<u8>, un: Cbor, ct: Cbor| B64.encode(cbor::encode(&Cbor::Array(vec![Cbor::Bytes(p), un, ct])));
    let hdr = |extra: Vec<(Cbor, Cbor)>| {
        let mut m = vec![
            (Cbor::Uint(1), Cbor::Nint(70009)),
            (Cbor::Uint(3), Cbor::Text("application/x.bitwarden.utf8-padded".into())),
            (Cbor::Uint(4), Cbor::Bytes(a.id().to_vec())),
        ];
        m.extend(extra);
        m
    };
    let iv = Cbor::Map(vec![(Cbor::Uint(5), Cbor::Bytes(vec![0; 24]))]);
    let ct = Cbor::Bytes(vec![0; 20]);
    // Valid shape, wrong tag: reaches the AEAD.
    assert_eq!(cose_decrypt(&a, &msg(prot(hdr(vec![])), iv.clone(), ct.clone())).unwrap_err(), CryptoError::BadMac);
    // Critical header.
    let crit = prot(hdr(vec![(Cbor::Uint(2), Cbor::Array(vec![Cbor::Uint(1)]))]));
    assert_eq!(cose_decrypt(&a, &msg(crit, iv.clone(), ct.clone())).unwrap_err(), CryptoError::Malformed);
    // Empty protected header, missing or unknown content type.
    let mut no_ct = hdr(vec![]);
    no_ct.remove(1);
    let mut odd_ct = hdr(vec![]);
    odd_ct[1].1 = Cbor::Text("x".into());
    for m in [
        msg(vec![], iv.clone(), ct.clone()),
        msg(prot(no_ct), iv.clone(), ct.clone()),
        msg(prot(odd_ct), iv.clone(), ct.clone()),
    ] {
        assert_eq!(cose_decrypt(&a, &m).unwrap_err(), CryptoError::Malformed);
    }
    // Missing or short key id.
    let mut no_kid = hdr(vec![]);
    no_kid.remove(2);
    let mut kid_len = hdr(vec![]);
    kid_len[2].1 = Cbor::Bytes(vec![1; 15]);
    for m in [msg(prot(no_kid), iv.clone(), ct.clone()), msg(prot(kid_len), iv.clone(), ct.clone())] {
        assert_eq!(cose_decrypt(&a, &m).unwrap_err(), CryptoError::WrongKey);
    }
    // Bad nonce, unprotected header or ciphertext type.
    let short_iv = Cbor::Map(vec![(Cbor::Uint(5), Cbor::Bytes(vec![0; 12]))]);
    for (un, ct) in [(short_iv, ct.clone()), (Cbor::Uint(1), ct.clone()), (iv.clone(), Cbor::Uint(1))] {
        assert_eq!(cose_decrypt(&a, &msg(prot(hdr(vec![])), un, ct)).unwrap_err(), CryptoError::Malformed);
    }
    let not_map_hdr = msg(cbor::encode(&Cbor::Uint(1)), iv.clone(), ct.clone());
    assert_eq!(cose_decrypt(&a, &not_map_hdr).unwrap_err(), CryptoError::Malformed);
    let bad_hdr = msg(vec![0xff], iv.clone(), ct.clone());
    assert_eq!(cose_decrypt(&a, &bad_hdr).unwrap_err(), CryptoError::Malformed);
    let not_array = B64.encode(cbor::encode(&Cbor::Uint(1)));
    assert_eq!(cose_decrypt(&a, &not_array).unwrap_err(), CryptoError::Malformed);
    let arity = B64.encode(cbor::encode(&Cbor::Array(vec![Cbor::Null])));
    assert_eq!(cose_decrypt(&a, &arity).unwrap_err(), CryptoError::Malformed);
    let not_bytes = B64.encode(cbor::encode(&Cbor::Array(vec![Cbor::Null, iv.clone(), ct.clone()])));
    assert_eq!(cose_decrypt(&a, &not_bytes).unwrap_err(), CryptoError::Malformed);
    // Unknown algorithm in the header.
    let mut bad_alg = hdr(vec![]);
    bad_alg[0].1 = Cbor::Nint(5);
    assert_eq!(cose_decrypt(&a, &msg(prot(bad_alg), iv, ct)).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn key_types_cross_decrypt() {
    let rng = SeededRandom::new(31);
    let legacy = SymmetricKey::generate(&rng).unwrap();
    let cose = SymmetricKey::generate_cose(CoseAlgorithm::Xaes256Gcm, &rng).unwrap();
    assert_eq!(
        SymmetricKey::generate_cose(CoseAlgorithm::Xaes256Gcm, &Fails).unwrap_err(),
        CryptoError::Port("rng down".into())
    );
    let e7 = cose.encrypt_str("héllo", &rng).unwrap();
    assert!(e7.starts_with("7."));
    assert_eq!(cose.decrypt_str(&e7).unwrap().as_str(), "héllo");
    assert_eq!(legacy.decrypt(&e7).unwrap_err(), CryptoError::WrongKey);
    let e2 = legacy.encrypt(b"x", &rng).unwrap();
    assert_eq!(cose.decrypt(&e2).unwrap_err(), CryptoError::WrongKey);
    assert_eq!(cose.decrypt("7.!!").unwrap_err(), CryptoError::Malformed);
    assert_eq!(cose.decrypt("07.x").unwrap_err(), CryptoError::Malformed);
    // Content kinds are not interchangeable.
    let raw = cose.encrypt(b"bytes", &rng).unwrap();
    assert_eq!(cose.decrypt(&raw).unwrap().as_slice(), b"bytes");
    assert_eq!(cose.decrypt_str(&raw).unwrap_err(), CryptoError::Malformed);
    assert_eq!(cose.decrypt_key(&raw).unwrap_err(), CryptoError::Malformed);
    assert_eq!(cose.decrypt(&e7).unwrap_err(), CryptoError::Malformed);
    // Non-UTF-8 under the utf8 format is Decrypt.
    let SymmetricKey::Cose(ck) = &cose else { unreachable!() };
    let bad = format!("7.{}", cose_encrypt(ck, &[0xff, 0xfe], ContentFormat::Utf8, &rng).unwrap());
    assert_eq!(cose.decrypt_str(&bad).unwrap_err(), CryptoError::Decrypt);
    // Keys wrapped inside a COSE key, legacy and COSE, read back.
    let wrapped_legacy = cose.encrypt_as(&legacy.to_bytes(), ContentFormat::LegacyKey, &rng).unwrap();
    assert_eq!(cose.decrypt_key(&wrapped_legacy).unwrap().to_bytes().to_vec(), legacy.to_bytes().to_vec());
    let inner = SymmetricKey::Cose(CoseKey::generate(CoseAlgorithm::XChaCha20Poly1305, &rng).unwrap());
    let SymmetricKey::Cose(ik) = &inner else { unreachable!() };
    let wrapped_cose = cose.encrypt_as(&encode_cose_key(ik), ContentFormat::CoseKey, &rng).unwrap();
    assert_eq!(cose.decrypt_key(&wrapped_cose).unwrap().to_bytes().to_vec(), inner.to_bytes().to_vec());
    // A legacy-key payload that is not 64 bytes is refused.
    let short = cose.encrypt_as(&[1; 10], ContentFormat::LegacyKey, &rng).unwrap();
    assert_eq!(cose.decrypt_key(&short).unwrap_err(), CryptoError::Malformed);
    // 65 or more bytes that are not a padded COSE key.
    assert_eq!(SymmetricKey::from_bytes(&[1; 70]).unwrap_err(), CryptoError::Malformed);
    assert_eq!(SymmetricKey::from_bytes(&[0; 70]).unwrap_err(), CryptoError::Malformed);
    // Debug is redacted.
    assert_eq!(format!("{cose:?}"), "SymmetricKey(<redacted>)");
    assert_eq!(format!("{ik:?}"), "CoseKey(<redacted>)");
}
