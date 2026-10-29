//! Port of the plugin's `unlockOrganizationKeys` cases (`test/organizations.test.ts`).

use super::orgs::{OrgProblem, unlock_organizations};
use super::*;
use crate::crypto::{AwsLcRsa, ContentFormat, SymmetricKey};
use crate::ports::{OaepHash, PortError, RsaOaep};
use crate::testing::{SeededRandom, block_on};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// Echoes the ciphertext as the plain key and counts calls; a 1-byte ciphertext fails like a wrong key.
#[derive(Default)]
struct EchoRsa(Cell<u32>);

impl RsaOaep for EchoRsa {
    async fn decrypt(&self, pkcs8: &[u8], _hash: OaepHash, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, PortError> {
        self.0.set(self.0.get() + 1);
        assert_eq!(pkcs8, b"der");
        if ct.len() == 1 {
            Err(PortError("organization key decryption failed".into()))
        } else {
            Ok(Zeroizing::new(ct.to_vec()))
        }
    }
}

fn wrapped(byte: u8) -> String {
    format!("4.{}", B64.encode([byte; 64]))
}

fn setup() -> (SeededRandom, SymmetricKey, String) {
    let rng = SeededRandom::new(3);
    let user = SymmetricKey::generate(&rng).unwrap();
    let private = user.encrypt_as(b"der", ContentFormat::Pkcs8, &rng).unwrap();
    (rng, user, private)
}

fn org(id: &str, key: Value, enabled: Value) -> Value {
    json!({ "id": id, "name": id, "key": key, "enabled": enabled })
}

fn problem(org: &str, reason: &str) -> OrgProblem {
    OrgProblem { organization: org.into(), reason: reason.into() }
}

#[test]
fn unlocks_allowed_enabled_confirmed_organizations() {
    let (_rng, user, private) = setup();
    let profile = json!({ "privateKey": private, "organizations": [
        org("a", json!(wrapped(1)), json!(true)),
        org("b", json!(wrapped(2)), Value::Null),
        org("off", json!(wrapped(3)), json!(false)),   // disabled: never unwrapped, no problem
        org("pending", Value::Null, json!(true)),      // membership not confirmed: no key yet
        org("empty", json!(""), json!(true)),
        org("broken", json!("4.AA=="), json!(true)),   // reported, the others still unlock
        org("type", json!("2.x|y|z"), json!(true)),
    ]});
    let rsa = EchoRsa::default();
    let (keys, problems) = block_on(unlock_organizations(&profile, &user, &rsa, &Organizations::All));
    assert_eq!(keys.keys().map(String::as_str).collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(keys["a"].to_bytes().as_slice(), [1u8; 64].as_slice());
    assert_eq!(
        problems,
        [
            problem("broken", "host port failed: organization key decryption failed"),
            problem("type", "unsupported encryption type 2"),
        ]
    );
    assert_eq!(rsa.0.get(), 3);
}

#[test]
fn organizations_not_allowed_are_never_unwrapped() {
    let (_rng, user, private) = setup();
    let profile = json!({ "privateKey": private, "organizations": [org("a", json!(wrapped(1)), json!(true)), org("b", json!(wrapped(2)), json!(true))] });
    let rsa = EchoRsa::default();
    let only = Organizations::Only(BTreeSet::from(["b".to_owned()]));
    let (keys, problems) = block_on(unlock_organizations(&profile, &user, &rsa, &only));
    assert_eq!((keys.keys().map(String::as_str).collect::<Vec<_>>(), problems.len(), rsa.0.get()), (vec!["b"], 0, 1));
    let (keys, problems) = block_on(unlock_organizations(&profile, &user, &rsa, &Organizations::None));
    assert_eq!((keys.len(), problems.len(), rsa.0.get()), (0, 0, 1));
}

#[test]
fn no_organizations_need_no_private_key() {
    let (_rng, user, _) = setup();
    for profile in [json!({}), json!({ "organizations": null }), json!({ "organizations": [] })] {
        let (keys, problems) =
            block_on(unlock_organizations(&profile, &user, &EchoRsa::default(), &Organizations::All));
        assert!(keys.is_empty() && problems.is_empty());
    }
}

#[test]
fn a_missing_or_unreadable_private_key_is_a_problem_per_organization() {
    let (rng, user, private) = setup();
    let orgs = json!([org("a", json!(wrapped(1)), json!(true)), org("b", json!(wrapped(2)), json!(true))]);
    let none = "the account has no private key to read organization keys";
    for profile in [json!({ "organizations": orgs }), json!({ "privateKey": "", "organizations": orgs })] {
        let (keys, problems) =
            block_on(unlock_organizations(&profile, &user, &EchoRsa::default(), &Organizations::All));
        assert!(keys.is_empty());
        assert_eq!(problems, [problem("a", none), problem("b", none)]);
    }
    // Under another key: a problem, not an abort.
    let other = SymmetricKey::generate(&rng).unwrap();
    let profile = json!({ "privateKey": private, "organizations": orgs });
    let (keys, problems) = block_on(unlock_organizations(&profile, &other, &EchoRsa::default(), &Organizations::All));
    assert!(keys.is_empty());
    let why = "the account's private key: MAC verification failed (wrong key or tampered data)";
    assert_eq!(problems, [problem("a", why), problem("b", why)]);
    // The newer place of the private key.
    let profile = json!({ "accountKeys": { "publicKeyEncryptionKeyPair": { "wrappedPrivateKey": private } }, "organizations": orgs });
    let (keys, problems) = block_on(unlock_organizations(&profile, &user, &EchoRsa::default(), &Organizations::All));
    assert_eq!((keys.len(), problems.len()), (2, 0));
}

#[test]
fn real_rsa_on_the_vectors_account() {
    let dir = std::env::var("DYBW_VECTORS_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors").into());
    let acc: Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/accounts/org.json")).unwrap()).unwrap();
    let b64 = |v: &Value| B64.decode(v.as_str().unwrap()).unwrap();
    let rng = SeededRandom::new(4);
    let user = SymmetricKey::from_bytes(&b64(&acc["userKey"])).unwrap();
    let private = user.encrypt_as(&b64(&acc["privateKey"]), ContentFormat::Pkcs8, &rng).unwrap();
    let orgs: Vec<Value> = acc["organizations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| json!({ "id": o["id"], "key": o["wrapped"] }))
        .collect();
    let profile = json!({ "privateKey": private, "organizations": orgs });
    let (keys, problems) = block_on(unlock_organizations(&profile, &user, &AwsLcRsa, &Organizations::All));
    assert!(problems.is_empty(), "{problems:?}");
    for o in acc["organizations"].as_array().unwrap() {
        assert_eq!(keys[o["id"].as_str().unwrap()].to_bytes().as_slice(), b64(&o["key"]).as_slice());
    }
    assert!(Organizations::All.allows("x") && !Organizations::None.allows("x"));
}
