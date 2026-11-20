use super::*;
use crate::crypto::NativeArgon2;
use crate::testing::{SeededRandom, block_on};
use serde_json::json;

fn vectors() -> Value {
    let dir = std::env::var("DYBW_VECTORS_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors").into());
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/crypto/protector.json")).unwrap()).unwrap()
}

fn kek_of(v: &Value) -> Kek {
    match v.get("secret") {
        Some(s) => Kek::Secret(Zeroizing::new(s.as_str().unwrap().as_bytes().to_vec())),
        None => Kek::Hardware(Zeroizing::new(B64.decode(v["hardware"].as_str().unwrap()).unwrap().try_into().unwrap())),
    }
}

fn binding_of(v: &Value) -> Binding<'_> {
    Binding { device_id: v["deviceId"].as_str().unwrap(), machine: v["machine"].as_str().unwrap() }
}

/// Runs one row: parse, then unwrap; answers the key or the error, and the blob's count afterwards.
fn run(doc: &Value, row: &Value) -> (Result<SymmetricKey, ProtectorError>, Option<u32>) {
    let mut blob = match ProtectorBlob::from_json(row["raw"].as_str().unwrap().as_bytes()) {
        Ok(blob) => blob,
        Err(e) => return (Err(e), None),
    };
    let sync = &doc["accounts"][row["account"].as_str().unwrap()]["sync"];
    let out = block_on(unwrap(&mut blob, &kek_of(&row["kek"]), binding_of(&row["binding"]), sync, &NativeArgon2));
    (out, Some(blob.attempts()))
}

/// Argon2id at the floor (64 MiB, 3 iterations) and above (128 MiB, 4, 2 lanes) runs in well under a second here: the
/// argon2 crate is built with opt-level 3 in tests.
#[test]
fn unwrap_vectors() {
    let doc = vectors();
    let rows = doc["unwrap"].as_array().unwrap();
    assert!(rows.len() >= 4);
    for row in rows {
        let about = row["about"].as_str().unwrap();
        let (out, attempts) = run(&doc, row);
        let user = out.unwrap_or_else(|e| panic!("{about}: {e}"));
        let want = B64.decode(doc["accounts"][row["account"].as_str().unwrap()]["userKey"].as_str().unwrap()).unwrap();
        assert_eq!(user.to_bytes().as_slice(), want.as_slice(), "{about}");
        assert_eq!(attempts, row["attemptsAfter"].as_u64().map(|n| n as u32), "{about}");
        // The stored form round-trips: the core writes what the reference wrote, field for field.
        let blob = ProtectorBlob::from_json(row["raw"].as_str().unwrap().as_bytes()).unwrap();
        let raw: Value = serde_json::from_str(row["raw"].as_str().unwrap()).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&blob.to_json()).unwrap(), raw, "{about}");
    }
}

#[test]
fn error_vectors() {
    let doc = vectors();
    let rows = doc["errors"].as_array().unwrap();
    let mut codes = std::collections::BTreeSet::new();
    for row in rows {
        let about = row["about"].as_str().unwrap();
        let (out, attempts) = run(&doc, row);
        let e = out.err().unwrap_or_else(|| panic!("{about}: unwrapped"));
        assert_eq!(e.code(), row["error"].as_str().unwrap(), "{about}");
        if let Some(n) = row.get("attemptsAfter") {
            assert_eq!(attempts, Some(n.as_u64().unwrap() as u32), "{about}");
        }
        codes.insert(e.code());
    }
    // Every error a stored blob can raise has a vector; `port` is the host's and has its own test.
    let all = ["binding", "format", "invalidated", "kek", "stale", "weak-kdf", "wrong"];
    assert_eq!(codes.into_iter().collect::<Vec<_>>(), all);
}

#[test]
fn the_fifth_failure_invalidates_and_a_success_resets() {
    let doc = vectors();
    let row = doc["errors"].as_array().unwrap().iter().find(|r| r["attemptsAfter"] == 5).unwrap();
    let mut blob = ProtectorBlob::from_json(row["raw"].as_str().unwrap().as_bytes()).unwrap();
    let (sync, binding) = (&doc["accounts"]["xaes-256-gcm"]["sync"], binding_of(&row["binding"]));
    let wrong = kek_of(&row["kek"]);
    assert_eq!(block_on(unwrap(&mut blob, &wrong, binding, sync, &NativeArgon2)).unwrap_err(), ProtectorError::Wrong);
    assert!(blob.invalidated());
    // The sixth try is refused before anything is derived, even with the right factor.
    let right = kek_of(&json!({ "hardware": doc["unwrap"][2]["kek"]["hardware"] }));
    let e = block_on(unwrap(&mut blob, &right, binding, sync, &NativeArgon2)).unwrap_err();
    assert_eq!(e, ProtectorError::Invalidated);
    assert_eq!(blob.attempts(), 5);
    blob.reset_attempts();
    assert!(block_on(unwrap(&mut blob, &right, binding, sync, &NativeArgon2)).is_ok());
    blob.attempts = u32::MAX;
    blob.record_failure();
    assert_eq!(blob.attempts(), u32::MAX);
}

#[test]
fn wrap_round_trips_for_each_protector() {
    let doc = vectors();
    let binding = Binding { device_id: "dev-1", machine: "machine-1" };
    let rng = SeededRandom::new(9);
    for account in ["org", "xaes-256-gcm"] {
        let a = &doc["accounts"][account];
        let user = SymmetricKey::from_bytes(&B64.decode(a["userKey"].as_str().unwrap()).unwrap()).unwrap();
        let params = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 1 };
        let pin = Zeroizing::new(b"2468".to_vec());
        let cases = [
            (Protector::Pin, KekSource::Secret { secret: pin.clone(), params }, Kek::Secret(pin.clone())),
            (
                Protector::Biometric,
                KekSource::Hardware(Zeroizing::new([7; 32])),
                Kek::Hardware(Zeroizing::new([7; 32])),
            ),
            (Protector::Login, KekSource::Secret { secret: pin.clone(), params }, Kek::Secret(pin)),
        ];
        for (protector, source, kek) in cases {
            let blob = block_on(wrap(&user, protector, source, binding, &NativeArgon2, &rng)).unwrap();
            assert_eq!(blob.protector(), protector);
            assert!(blob.wrapped_key.starts_with("2."));
            let mut stored = ProtectorBlob::from_json(&blob.to_json()).unwrap();
            assert_eq!(stored, blob);
            let text = String::from_utf8(blob.to_json()).unwrap();
            assert!(text.contains(&format!("\"protector\":\"{}\"", protector.name())), "{text}");
            let back = block_on(unwrap(&mut stored, &kek, binding, &a["sync"], &NativeArgon2)).unwrap();
            assert_eq!(back.to_bytes(), user.to_bytes());
        }
    }
}

#[test]
fn wrap_refuses_weak_parameters_and_an_empty_binding() {
    let user = SymmetricKey::generate(&SeededRandom::new(1)).unwrap();
    let binding = Binding { device_id: "dev-1", machine: "machine-1" };
    let secret = |params| KekSource::Secret { secret: Zeroizing::new(b"x".to_vec()), params };
    let weak = [
        KdfParams::Pbkdf2 { iterations: 600_000 },
        KdfParams::Argon2id { iterations: 3, memory_mib: 63, parallelism: 1 },
        KdfParams::Argon2id { iterations: 2, memory_mib: 64, parallelism: 1 },
        KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 0 },
        KdfParams::Argon2id { iterations: 3, memory_mib: 2048, parallelism: 1 },
    ];
    for params in weak {
        // The host's own runner and RNG (the instantiation the other tests use): refused before either is called.
        let e = block_on(wrap(&user, Protector::Pin, secret(params), binding, &NativeArgon2, &SeededRandom::new(1)));
        assert_eq!(e.unwrap_err(), ProtectorError::WeakKdf, "{params:?}");
    }
    for (device_id, machine) in [("", "m"), ("d", "")] {
        let hw = KekSource::Hardware(Zeroizing::new([1; 32]));
        let e = block_on(wrap(
            &user,
            Protector::Biometric,
            hw,
            Binding { device_id, machine },
            &NativeArgon2,
            &SeededRandom::new(1),
        ));
        assert_eq!(e.unwrap_err(), ProtectorError::Binding);
    }
}

struct Panics;
impl KdfRunner for Panics {
    async fn argon2id(&self, _: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError> {
        panic!("no KDF may run here");
    }
}

struct FailsKdf;
impl KdfRunner for FailsKdf {
    async fn argon2id(&self, _: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError> {
        Err(PortError("kdf down".into()))
    }
}

struct Fails;
impl Random for Fails {
    fn fill(&self, _: &mut [u8]) -> Result<(), PortError> {
        Err(PortError("rng down".into()))
    }
}

#[test]
fn port_failures_surface_without_secrets() {
    let user = SymmetricKey::generate(&SeededRandom::new(1)).unwrap();
    let binding = Binding { device_id: "dev-1", machine: "machine-1" };
    let params = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 1 };
    let secret = || KekSource::Secret { secret: Zeroizing::new(b"2468".to_vec()), params };
    let e = block_on(wrap(&user, Protector::Pin, secret(), binding, &Panics, &Fails)).unwrap_err();
    assert_eq!((e.code(), e.to_string()), ("port", "host port failed: rng down".into()));
    let e = block_on(wrap(&user, Protector::Pin, secret(), binding, &FailsKdf, &SeededRandom::new(1))).unwrap_err();
    assert_eq!(e, ProtectorError::Port("host port failed: kdf down".into()));
    let hw = KekSource::Hardware(Zeroizing::new([1; 32]));
    // A hardware KEK draws no salt: the IV is the first draw.
    let e = block_on(wrap(&user, Protector::Biometric, hw, binding, &Panics, &Fails));
    assert_eq!(e.unwrap_err(), ProtectorError::Port("host port failed: rng down".into()));
    // Every message names the problem only.
    for e in [
        ProtectorError::Format,
        ProtectorError::WeakKdf,
        ProtectorError::Binding,
        ProtectorError::Invalidated,
        ProtectorError::Kek,
        ProtectorError::Wrong,
        ProtectorError::Stale,
    ] {
        assert!(!e.to_string().contains("2468"), "{e}");
    }
}

/// `unwrap` checks the blob again: one built by serde directly, past `from_json`, is still held to the floors.
#[test]
fn unwrap_checks_a_blob_that_skipped_from_json() {
    let doc = vectors();
    let row = &doc["unwrap"][0];
    let mut raw: Value = serde_json::from_str(row["raw"].as_str().unwrap()).unwrap();
    raw["kdf"]["memory"] = json!(16);
    let mut blob: ProtectorBlob = serde_json::from_value(raw).unwrap();
    let sync = &doc["accounts"]["org"]["sync"];
    let e = block_on(unwrap(&mut blob, &kek_of(&row["kek"]), binding_of(&row["binding"]), sync, &Panics)).unwrap_err();
    assert_eq!(e, ProtectorError::WeakKdf);
}
