use super::cbor::{self, Cbor};
use super::cose::{as_map, get, int};
use super::sign::*;
use super::*;
use crate::testing::SeededRandom;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::Signer as _;
use serde_json::Value;

/// `MLDSA44_SIGNING_KEY` of sdk-internal `3d16437`, `crates/bitwarden-crypto/src/signing/signing_key.rs` line 229:
/// the signing key of the `mldsa44` vectors in `sdk-m3.json`, which records only its verifying key.
const MLDSA44_SIGNING_KEY: &str = "a601070250e11a339366953128787c1b2c16b6945803382f048101205905205cc3620a551a0213972ad845e4930f4ecdfe1d10a81ffde8cdd1a0fffc38eefa3fd659028cad345c823074e870ffb9ed12e1d08a407db8f2431f2b75d3934e8a2662c033c8337aec1afdc1bb1babf185d709365a3057b41774dcf08e3877d4fdca2111b778ed53f6cf5b2d46d4a2427ee72c1c08a87e4e231794d8418513bae5e57d65428c41fa0b1031d6bc3b07a15f3349c4361a627c736d4e86fe3285e74277117f57df4bc53a98afcd55a77aee7e1b1465abb72e68ab2da897ceecfb8f7d4f0ced0dcf39506b31a46b795c8cee3ee6d789a1f8f7c35eb20eb17c6af5402954ec6eb41576eb2d65078b9755aca0e3af11f438df2a8abfb35d75b3fd151099735908f9b15a42f5211d4ea691014142adae9c9fdf0cf704bc4197d10f8f5f60be29abc805c6fa0f6192e4d12c8f7d50289e0ea796217f453730ca5af1ac3eb3c8ccc4bc161925806506160489a175a07bcf0f9323a4d05013117ba5f3c6d5bc6f6feadcfd093e40efbc19b8648cc8251d6d2faca5da7b506ec4b9e66b821c4176205b9ce0cd4c358b5e2a742c93b9ddb481feca10bb213925e1c661149c04e84a7809e440c190977cf015f12b6259581c368c70eec633985b78c1108f7ff42d1cb03d9ce957f705b871b57c3705ada6d6b386e647a3bacf846da4feb5c508bc4960c2d1f5378700b118fd2ea20db2790aafb7d39043bd2ab6f8902111a45fb181be8e83fa5a4c43e5d2d56797042f8d0c3e832857db0fccc61e7ea3616b70da0439eedf1a1a40196435c99b24e2ab07f8515272972faeafb2670ff66b237b00bf092da2de98a99ed4319498b4d8385aa68e36974b9c31d44b2dfebda78b3465b859296c63958cbcb587dd82e04c51986fdb9e0f3a2941ef1eac8d3b08c2fcd32ceb9dc434096c7f03e529c82132cd7e242a5668520baf00332a2de8a4f52420378350993bd35c573ba4f32e5ad89ddca1b7b3ddb0a21b0faa3674de2bdcb3519b86ed33a8939e6c7cbb9b9493279db28739b163916776bdcc40f7368000b5cefb3425b77dce84a957642319cb95226e30e119a4e455795b24e627b69881dc87084c3c1972fd170c87bcf4cc228beb4083a063e7a44c4fa8490f48457d12e4cf44b84ef41556e53599c5b4a030b4d07ee6594b6830ac0cb7823f908130fd6d2f3f9b5d65012f8e9abeeb74f4042a2a8c05fcb28f968f15f4230dfce034595141c770c200c1fd710e86d9b4d820ee0f015762526cb5a148e18874a385acef6f9efb77d43bc14936e8aa966dd53a1d2403a820f735fd60f5867570fa93ffae3214dc9ac93b2c191115a0045f71923249a10fdd8aa6ca35f6420fa1c80a867d7f54ef54b465f151de0b9a040c31d7373c81565d503cc1332dc6808533171ff2513a7139dad63b1848ba46f09255e81f7edab6208e62d17955aa43e27c74b5ed77b8d3c66ea50c478760e0db5c1b8970a22e74a29bd07bed0ba7e9c7a1866531889fa516ffd66c363d9558b2716d67809d85f16b4e18f456d5ec2343d08ea601da77676246c26432bfcd935c0d80a1e32fc41b380dff041a2629683540d5f2b9d9ef6101114242508c68987a44a0169bf8fbdabf1954bd54d745f1d66b7367848e43e0c94a6d88ccbdfd65333301d34d06d400e643e36c681c7f475b0026967d68e58af2fbf4800ca7aad6a43a3782b1d9452226ef881d50fcbb7b4df0c8c3b15ca80321cbb928fa8dce4048f01fc48121eaa1da0a954a6150c3d2e42add1b4f58910c2db0869a5481d469ef4bdccec3e7c0a21253fd19ce941b16808bf14fca6fec2b1ba7f771580235034e5ca95763721d6add9aa3914f476b37097ce67b000d5d215820d6b3615887fa819d9b215654a2494c714a64d4b0c9997149ee853c2bc0a415f3";

const SEED: [u8; 32] = [7; 32];
const KID: [u8; 16] = [9; 16];

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../../vectors/crypto/sdk-m3.json")).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn value<'a>(v: &'a Value, group: &str, name: &str) -> &'a str {
    v[group][name]["value"].as_str().unwrap()
}

fn byte_param(m: &[(Cbor, Cbor)], label: i64) -> Vec<u8> {
    let encoded = cbor::encode(get(m, label).unwrap());
    let Cbor::Bytes(b) = cbor::decode(&encoded).unwrap() else { unreachable!() };
    b.to_vec()
}

/// The test-only constructor: a verifying key read from an SDK COSE verifying key (OKP `x` at -2, AKP `pub` at -1),
/// for the vectors that come without their signing key.
fn verifying_key_of(cose: &[u8]) -> VerifyingKey {
    let v = cbor::decode(cose).unwrap();
    let m = as_map(&v).unwrap();
    let id = byte_param(m, 2).try_into().unwrap();
    let key = if get(m, 1) == Some(&int(1)) {
        RawVerifyingKey::Ed25519(ed25519_dalek::VerifyingKey::try_from(byte_param(m, -2).as_slice()).unwrap())
    } else {
        let encoded = byte_param(m, -1);
        RawVerifyingKey::MlDsa44(Box::new(ml_dsa::VerifyingKey::decode(&encoded.as_slice().try_into().unwrap())))
    };
    VerifyingKey { id, key }
}

fn public_bytes(k: &VerifyingKey) -> Vec<u8> {
    match &k.key {
        RawVerifyingKey::Ed25519(k) => k.to_bytes().to_vec(),
        RawVerifyingKey::MlDsa44(k) => k.encode().to_vec(),
    }
}

fn signing_cose(alg: i64) -> Vec<u8> {
    signing_cose_with(alg, SEED)
}

/// A signing COSE_Key with `seed` and the test kid: Ed25519 for `alg` -8, ML-DSA-44 for -48.
fn signing_cose_with(alg: i64, seed: [u8; 32]) -> Vec<u8> {
    let mut m = vec![(int(2), Cbor::bytes(KID.to_vec())), (int(3), int(alg)), (int(4), Cbor::Array(vec![int(1)]))];
    if alg == -8 {
        m.extend([(int(1), int(1)), (int(-1), int(6)), (int(-4), Cbor::bytes(seed.to_vec()))]);
    } else {
        m.extend([(int(1), int(7)), (int(-2), Cbor::bytes(seed.to_vec()))]);
    }
    cbor::encode(&Cbor::Map(m))
}

fn key(alg: i64) -> SigningKey {
    SigningKey::from_cose(&signing_cose(alg)).unwrap()
}

/// A valid security state header for the test key of `alg`.
fn header(alg: i64) -> Vec<(Cbor, Cbor)> {
    vec![
        (int(1), int(alg)),
        (int(3), Cbor::Uint(60)),
        (int(4), Cbor::bytes(KID.to_vec())),
        (int(-80000), Cbor::Uint(2)),
    ]
}

fn state(version: u64) -> Cbor {
    Cbor::Map(vec![(Cbor::text("entityId"), Cbor::bytes(vec![1; 16])), (Cbor::text("version"), Cbor::Uint(version))])
}

/// A COSE_Sign1 over `payload` with `header`, signed by the test key of `signer` (-8 or -48), as base64.
fn sign1(signer: i64, header: Vec<(Cbor, Cbor)>, payload: &Cbor) -> String {
    let protected = cbor::encode(&Cbor::Map(header));
    let payload = cbor::encode(payload);
    let signed = cbor::encode(&Cbor::Array(vec![
        Cbor::text("Signature1"),
        Cbor::bytes(protected.clone()),
        Cbor::bytes(vec![]),
        Cbor::bytes(payload.clone()),
    ]));
    let signature = if signer == -8 {
        ed25519_dalek::SigningKey::from_bytes(&SEED).sign(&signed).to_bytes().to_vec()
    } else {
        ml_dsa::SigningKey::<ml_dsa::MlDsa44>::from_seed(&SEED.into()).sign(&signed).encode().to_vec()
    };
    B64.encode(cbor::encode(&Cbor::Array(vec![
        Cbor::bytes(protected),
        Cbor::Map(vec![]),
        Cbor::bytes(payload),
        Cbor::bytes(signature),
    ])))
}

/// The SDK's state comes with its verifying key only, so it is checked through the test-only `verifying_key_of`;
/// `verifies_generated_security_state` covers the key derived from a signing key.
#[test]
fn verifies_sdk_security_state() {
    let v = vectors();
    let vk = verifying_key_of(&B64.decode(value(&v, "security_state", "TEST_VERIFYING_KEY")).unwrap());
    let signed = value(&v, "security_state", "TEST_SIGNED_SECURITY_STATE");
    assert_eq!(verify_state(&vk, signed).unwrap(), v["security_state"]["version"].as_u64().unwrap());
    assert_eq!(verify_state(&vk, signed).unwrap(), 2);
}

#[test]
fn ignores_unknown_payload_keys() {
    let v = vectors();
    let vk = verifying_key_of(&B64.decode(value(&v, "security_state", "TEST_VERIFYING_KEY")).unwrap());
    let signed = B64.decode(value(&v, "security_state", "TEST_SIGNED_SECURITY_STATE")).unwrap();
    // The SDK's payload holds `entityId` beside `version`.
    let payload = verify_sign1(&vk, &signed, 2).unwrap();
    let keys: Vec<_> = as_map(&payload).unwrap().iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(keys, [Cbor::text("entityId"), Cbor::text("version")]);
    // and any other key is ignored too
    let mut extra = state(5);
    let Cbor::Map(m) = &mut extra else { unreachable!() };
    m.push((Cbor::text("future"), Cbor::Array(vec![Cbor::Null])));
    assert_eq!(verify_security_state(&key(-8), &sign1(-8, header(-8), &extra)).unwrap(), 5);
}

/// The SDK's ML-DSA-44 key: its derived verifying key equals the recorded one, and verifies the recorded raw
/// signature over "Test message".
#[test]
fn verifies_mldsa44_signature() {
    let v = vectors();
    let recorded = verifying_key_of(&hex(value(&v, "mldsa44", "MLDSA44_VERIFYING_KEY")));
    let signing = SigningKey::from_cose(&hex(MLDSA44_SIGNING_KEY)).unwrap();
    let derived = signing.verifying_key();
    assert_eq!(derived.id, recorded.id);
    assert_eq!(signing.id(), &recorded.id);
    assert_eq!(public_bytes(&derived), public_bytes(&recorded));
    let signature = hex(value(&v, "mldsa44", "MLDSA44_SIGNED_DATA_RAW"));
    let message = v["mldsa44"]["message"].as_str().unwrap().as_bytes();
    derived.verify_raw(&signature, message).unwrap();
    recorded.verify_raw(&signature, message).unwrap();
    assert_eq!(derived.verify_raw(&signature, b"Test messagf").unwrap_err(), CryptoError::BadSignature);
    assert_eq!(derived.verify_raw(&signature[1..], message).unwrap_err(), CryptoError::BadSignature);
}

#[test]
fn verifies_sdk_signed_object() {
    let v = vectors();
    let vk = verifying_key_of(&hex(value(&v, "signed_object", "VERIFYING_KEY")));
    let signed = hex(value(&v, "signed_object", "SIGNED_OBJECT"));
    let ns = v["signed_object"]["namespace"].as_i64().unwrap();
    let payload = verify_sign1(&vk, &signed, ns).unwrap();
    assert_eq!(payload, Cbor::Map(vec![(Cbor::text("field1"), Cbor::text("Test message"))]));
    assert_eq!(verify_sign1(&vk, &signed, 2).unwrap_err(), CryptoError::Malformed);
}

/// The `cose-v2` account: the signing key unwrapped from the user key derives the account's verifying key and
/// verifies its state.
#[test]
fn verifies_generated_security_state() {
    let account: Value = serde_json::from_str(include_str!("../../../../vectors/accounts/cose-v2.json")).unwrap();
    let user = SymmetricKey::from_bytes(&B64.decode(account["userKey"].as_str().unwrap()).unwrap()).unwrap();
    let keys = &account["profile"]["accountKeys"];
    let signing = unwrap_signing_key(&user, keys["signatureKeyPair"]["wrappedSigningKey"].as_str().unwrap()).unwrap();
    let published = verifying_key_of(&B64.decode(keys["signatureKeyPair"]["verifyingKey"].as_str().unwrap()).unwrap());
    assert_eq!(public_bytes(&signing.verifying_key()), public_bytes(&published));
    assert_eq!(signing.id(), &published.id);
    assert_eq!(verify_security_state(&signing, keys["securityState"]["securityState"].as_str().unwrap()).unwrap(), 2);
}

#[test]
fn verifies_both_algorithms() {
    for alg in [-8, -48] {
        assert_eq!(verify_security_state(&key(alg), &sign1(alg, header(alg), &state(3))).unwrap(), 3, "{alg}");
    }
}

#[test]
fn refuses_wrong_namespace() {
    for ns in [Cbor::Uint(1), int(-1), Cbor::text("2")] {
        let mut h = header(-8);
        h[3].1 = ns;
        assert_eq!(verify_security_state(&key(-8), &sign1(-8, h, &state(2))).unwrap_err(), CryptoError::Malformed);
    }
    let mut h = header(-8);
    h.pop();
    assert_eq!(verify_security_state(&key(-8), &sign1(-8, h, &state(2))).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_wrong_content_type() {
    let mut h = header(-8);
    h[1].1 = Cbor::Uint(50);
    assert_eq!(verify_security_state(&key(-8), &sign1(-8, h, &state(2))).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_crit() {
    let mut h = header(-8);
    h.push((int(2), Cbor::Array(vec![int(-80000)])));
    assert_eq!(verify_security_state(&key(-8), &sign1(-8, h, &state(2))).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_wrong_kid() {
    let mut h = header(-8);
    h[2].1 = Cbor::bytes(vec![8; 16]);
    assert_eq!(verify_security_state(&key(-8), &sign1(-8, h, &state(2))).unwrap_err(), CryptoError::WrongKey);
}

#[test]
fn refuses_alg_mismatch() {
    // an Ed25519 key never accepts an ML-DSA-44 state, nor the reverse, even when correctly signed
    assert_eq!(
        verify_security_state(&key(-8), &sign1(-48, header(-48), &state(2))).unwrap_err(),
        CryptoError::WrongKey
    );
    assert_eq!(verify_security_state(&key(-48), &sign1(-8, header(-8), &state(2))).unwrap_err(), CryptoError::WrongKey);
}

#[test]
fn refuses_bad_signature() {
    for alg in [-8, -48] {
        let signed = B64.decode(sign1(alg, header(alg), &state(2))).unwrap();
        let mut tampered = signed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let vk = key(alg).verifying_key();
        assert_eq!(verify_sign1(&vk, &tampered, 2).unwrap_err(), CryptoError::BadSignature, "{alg}");
        // another key with the same id
        let other = SigningKey::from_cose(&signing_cose_with(alg, [6; 32])).unwrap();
        assert_eq!(verify_security_state(&other, &B64.encode(&signed)).unwrap_err(), CryptoError::BadSignature);
    }
    // a signature of the wrong length
    let vk = key(-8).verifying_key();
    assert_eq!(vk.verify_raw(&[0; 63], b"x").unwrap_err(), CryptoError::BadSignature);
}

#[test]
fn refuses_missing_version() {
    let k = key(-8);
    let no_version = Cbor::Map(vec![(Cbor::text("entityId"), Cbor::bytes(vec![1; 16]))]);
    for payload in [no_version, Cbor::Map(vec![(Cbor::text("version"), Cbor::text("2"))]), Cbor::Uint(2)] {
        assert_eq!(verify_security_state(&k, &sign1(-8, header(-8), &payload)).unwrap_err(), CryptoError::Malformed);
    }
}

#[test]
fn refuses_malformed_sign1() {
    let k = key(-8);
    let good = B64.decode(sign1(-8, header(-8), &state(2))).unwrap();
    let Cbor::Array(parts) = cbor::decode(&good).unwrap() else { unreachable!() };
    let with_protected = |p: Vec<u8>| {
        cbor::encode(&Cbor::Array(vec![Cbor::bytes(p), parts[1].clone(), parts[2].clone(), parts[3].clone()]))
    };
    let bad = [
        cbor::encode(&Cbor::Uint(1)),
        cbor::encode(&Cbor::Array(parts[..3].to_vec())),
        with_protected(cbor::encode(&Cbor::Array(vec![]))), // protected header not a map
        with_protected(vec![0xff]),                         // protected header not CBOR
        vec![0xff],
    ];
    for b in bad {
        assert_eq!(verify_security_state(&k, &B64.encode(&b)).unwrap_err(), CryptoError::Malformed);
    }
    assert_eq!(verify_security_state(&k, "not base64!").unwrap_err(), CryptoError::Malformed);
}

#[test]
fn refuses_unsupported_signing_keys() {
    let replace = |alg: i64, label: i64, v: Option<Cbor>| {
        let Cbor::Map(mut m) = cbor::decode(&signing_cose(alg)).unwrap() else { unreachable!() };
        m.retain(|(k, _)| *k != int(label));
        m.extend(v.map(|v| (int(label), v)));
        SigningKey::from_cose(&cbor::encode(&Cbor::Map(m))).unwrap_err()
    };
    let cases = [
        replace(-8, 3, Some(int(-48))),                  // OKP with ML-DSA-44
        replace(-8, -1, Some(int(4))),                   // X25519, not Ed25519
        replace(-8, -4, None),                           // no d
        replace(-8, -4, Some(Cbor::bytes(vec![7; 31]))), // short d
        replace(-48, 3, Some(int(-8))),                  // AKP with EdDSA
        replace(-48, -2, None),                          // no seed
        replace(-48, 1, Some(int(2))),                   // EC2
        replace(-8, 2, None),                            // no kid
        replace(-8, 2, Some(Cbor::bytes(vec![9; 15]))),  // short kid
    ];
    assert!(cases.iter().all(|e| *e == CryptoError::Malformed));
    assert_eq!(SigningKey::from_cose(&cbor::encode(&Cbor::Array(vec![]))).unwrap_err(), CryptoError::Malformed);
    assert_eq!(SigningKey::from_cose(&[0xff]).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn unwraps_only_a_cose_key() {
    let rng = SeededRandom::new(4);
    let user = SymmetricKey::generate_cose(CoseAlgorithm::XChaCha20Poly1305, &rng).unwrap();
    let wrapped = user.encrypt_as(&signing_cose(-48), ContentFormat::CoseKey, &rng).unwrap();
    assert_eq!(unwrap_signing_key(&user, &wrapped).unwrap().id(), &KID);
    // the same bytes labelled as an octet stream
    let octets = user.encrypt(&signing_cose(-8), &rng).unwrap();
    assert_eq!(unwrap_signing_key(&user, &octets).unwrap_err(), CryptoError::Malformed);
    // a legacy key's type 2 cannot say what it holds
    let legacy = SymmetricKey::generate(&rng).unwrap();
    let type2 = legacy.encrypt(&signing_cose(-8), &rng).unwrap();
    assert_eq!(unwrap_signing_key(&legacy, &type2).unwrap_err(), CryptoError::Malformed);
}

#[test]
fn signing_key_debug_is_redacted() {
    for alg in [-8, -48] {
        assert_eq!(format!("{:?}", key(alg)), "SigningKey(<redacted>)");
    }
}

/// `SigningKey`'s `ZeroizeOnDrop` rests on its inner keys wiping themselves.
#[test]
fn signing_keys_are_wiped() {
    fn wiped<T: zeroize::ZeroizeOnDrop>() {}
    wiped::<ed25519_dalek::SigningKey>();
    wiped::<ml_dsa::SigningKey<ml_dsa::MlDsa44>>();
    wiped::<SigningKey>();
}
