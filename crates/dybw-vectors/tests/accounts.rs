#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::api::{ApiKey, Client, DeviceInfo, origin_of, resolve_server_urls};
use dybw_core::crypto::{
    AwsLcRsa, CoseAlgorithm, CryptoError, KdfParams, NativeArgon2, SymmetricKey, derive_master_key,
    hash_master_password,
};
use dybw_core::ports::{Http, HttpRequest, HttpResponse, PortError};
use dybw_core::profile::{ProfileError, Unlocked, unlock};
use dybw_core::testing::{FixedClock, SeededRandom, block_on};
use dybw_core::vault::{Namespace, Organizations};
use dybw_vectors::canonical::{NOW, canonicalize, drop_tool_defined};
use dybw_vectors::keys::account_keys;
use dybw_vectors::server::{Sent, VectorServer, urls};
use dybw_vectors::vectors_dir;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[test]
fn scenario_keys_load() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    assert!(keys.orgs.is_empty());
    assert!(keys.profile["key"].as_str().unwrap().starts_with("2."));
    let keys = account_keys(&dir, "org", true);
    assert_eq!(keys.orgs.keys().collect::<Vec<_>>(), ["org-a", "org-b"]);
    // The profile carries the private key wrapped under the user key, and the organizations' wrapped keys.
    let wrapped = keys.profile["privateKey"].as_str().unwrap();
    assert!(keys.user.decrypt_pkcs8(wrapped).is_ok());
    assert_eq!(keys.profile["organizations"][0]["key"].as_str().unwrap().split('.').next(), Some("4"));
}

fn client(server: VectorServer) -> Client<VectorServer, FixedClock> {
    let device = DeviceInfo {
        identifier: "vectors-device".into(),
        name: "vectors".into(),
        device_type: 8,
        client_name: "cli".into(),
        client_version: "0".into(),
    };
    Client::new(server, FixedClock { now_ms: 0 }, urls(), device).unwrap()
}

fn api_key() -> ApiKey {
    ApiKey {
        origin: origin_of(&resolve_server_urls("https://vectors.invalid").unwrap().identity).unwrap(),
        client_id: "vectors".into(),
        client_secret: Zeroizing::new("vectors".into()),
    }
}

#[test]
fn server_serves_routes_and_records_writes() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    let cipher = json!({ "id": "c1", "name": "n", "revisionDate": "2026-01-01T00:00:00.000Z" });
    let server = VectorServer::new(keys.profile, vec![cipher], keys.prelogin);
    let mut api = client(server.clone());
    block_on(async {
        assert!(matches!(
            api.prelogin("x").await.unwrap(),
            dybw_core::crypto::KdfParams::Pbkdf2 { iterations: 600_000 }
        ));
        api.login(&api_key()).await.unwrap();
        let sync = api.sync().await.unwrap();
        assert_eq!(sync["ciphers"][0]["id"], "c1");
        assert_eq!(api.get_cipher("c1").await.unwrap()["name"], "n");
        assert_eq!(
            api.get_cipher("nope").await.unwrap_err().to_string(),
            "HTTP 404 (server says: not faked: GET /api/ciphers/nope)"
        );
        let made = api.create_folder("2.x").await.unwrap();
        assert_eq!(made["id"], "folder-created");
        let body = json!({ "name": "2.y", "x1": 1 }).as_object().unwrap().clone();
        let put = api.update_cipher("c1", body.clone()).await.unwrap();
        assert_eq!((put["id"].as_str(), put["revisionDate"].as_str()), (Some("c1"), Some("2026-12-01T00:00:00.000Z")));
        assert_eq!(put["name"], "2.y");
        let post = api.create_cipher(body).await.unwrap();
        assert_eq!(post["id"], "cipher-created");
        api.trash_cipher("c1").await.unwrap();
    });
    let sent = server.sent.borrow();
    assert_eq!(sent.len(), 3);
    assert!(matches!(&sent[0], Sent::Put { cipher, .. } if cipher == "c1"));
    assert!(matches!(&sent[1], Sent::Post { .. }));
    assert!(matches!(&sent[2], Sent::Trash { cipher } if cipher == "c1"));
}

#[test]
fn fresh_rejects_the_first_put_and_serves_the_new_copy() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    let server = VectorServer::new(keys.profile, vec![json!({ "id": "c1", "name": "old" })], keys.prelogin);
    *server.fresh.borrow_mut() = Some(json!({ "id": "c1", "name": "fresh" }));
    let mut api = client(server.clone());
    block_on(async {
        api.login(&api_key()).await.unwrap();
        api.sync().await.unwrap();
        let err = api.update_cipher("c1", serde_json::Map::new()).await.unwrap_err();
        assert!(err.is_out_of_date(), "{err}");
        assert_eq!(api.get_cipher("c1").await.unwrap()["name"], "fresh");
        api.update_cipher("c1", serde_json::Map::new()).await.unwrap();
    });
    assert_eq!(server.sent.borrow().len(), 1, "the rejected write is not recorded");
    assert_eq!(server.rejected.get(), 1);
}

#[test]
fn canonicalize_decrypts_with_the_item_key_and_marks_now() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    let rng = SeededRandom::new(7);
    let item = SymmetricKey::generate(&rng).unwrap();
    let enc = |s: &str| Value::String(item.encrypt_str(s, &rng).unwrap());
    let body = json!({
        "type": 1, "name": enc("nm"), "notes": null, "folderId": null, "organizationId": null,
        "key": keys.user.encrypt(&item.to_bytes(), &rng).unwrap(),
        "login": { "username": enc("u"), "password": enc("p"), "uris": [{ "uri": enc("https://a.invalid") }], "totp": null },
        "passwordHistory": [{ "password": enc("old") }],
        "fields": [{ "name": enc("bwss:id"), "value": enc("alpha"), "type": 0 }, { "name": enc("bwss:x"), "value": null, "type": 1 }],
        "lastKnownRevisionDate": NOW, "xKeep": 1, "other": 2,
    });
    let sent = Sent::Put { cipher: "c1".into(), body };
    let got = canonicalize(&sent, &keys.user, &BTreeMap::new()).unwrap();
    assert_eq!(got["name"], "nm");
    assert_eq!(got["login"]["passwordHistory"], json!(["old"]));
    assert_eq!(got["login"]["uris"], json!(["https://a.invalid"]));
    assert_eq!(got["lastKnownRevisionDate"], "<now>");
    assert_eq!((got["hasItemKey"].as_bool(), &got["extra"]), (Some(true), &json!({ "xKeep": 1 })));
    // Only a POST loses its name and tool-defined fields.
    assert_eq!(drop_tool_defined(got.clone(), "bwss"), got);
    let mut post = got.clone();
    post["method"] = json!("POST");
    let post = drop_tool_defined(post, "bwss");
    assert!(post.get("name").is_none());
    assert_eq!(post["fields"].as_array().unwrap().len(), 1);
    assert_eq!(
        canonicalize(&Sent::Trash { cipher: "c1".into() }, &keys.user, &BTreeMap::new()).unwrap(),
        json!({ "method": "trash", "cipher": "c1" })
    );
    // A wrong key is an error, not a panic.
    let other = SymmetricKey::generate(&rng).unwrap();
    assert!(canonicalize(&sent, &other, &BTreeMap::new()).is_err());
}

#[test]
fn server_percent_decodes_cipher_ids() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    let server = VectorServer::new(keys.profile, vec![json!({ "id": "c 1/é", "name": "n" })], keys.prelogin);
    let mut api = client(server.clone());
    block_on(async {
        api.login(&api_key()).await.unwrap();
        api.sync().await.unwrap();
        // The client percent-encodes the id; the server matches and records it decoded, as decodeURIComponent.
        assert_eq!(api.get_cipher("c 1/é").await.unwrap()["name"], "n");
        api.update_cipher("c 1/é", serde_json::Map::new()).await.unwrap();
        api.trash_cipher("c 1/é").await.unwrap();
    });
    let sent = server.sent.borrow();
    assert!(matches!(&sent[0], Sent::Put { cipher, .. } if cipher == "c 1/é"), "{sent:?}");
    assert!(matches!(&sent[1], Sent::Trash { cipher } if cipher == "c 1/é"), "{sent:?}");
}

// Profile unlock (Task 15): prelogin, API-key login, sync, KDF, user key, private key and organization keys.

/// Records what reaches the server, so a test proves the password never does.
struct Recording {
    inner: VectorServer,
    seen: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
}

impl Http for Recording {
    fn refuses_redirects(&self) -> bool {
        true
    }
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        let body = String::from_utf8_lossy(req.body.as_deref().map_or(&[][..], Vec::as_slice)).into_owned();
        self.seen.borrow_mut().push(format!("{:?} {} {body}", req.method, req.url));
        self.inner.send(req).await
    }
}

fn account(name: &str) -> Value {
    let path = vectors_dir().unwrap().join("accounts").join(format!("{name}.json"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cose_accounts() -> Value {
    let path = vectors_dir().unwrap().join("crypto").join("cose-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn b64(v: &Value) -> Vec<u8> {
    B64.decode(v.as_str().unwrap()).unwrap()
}

struct Outcome {
    result: Result<Unlocked, ProfileError>,
    seen: Vec<String>,
}

fn run_unlock(profile: Value, prelogin: Value, email: &str, password: &str, allowed: &Organizations) -> Outcome {
    let seen = std::rc::Rc::default();
    let server = Recording { inner: VectorServer::new(profile, vec![], prelogin), seen: std::rc::Rc::clone(&seen) };
    let mut api = Client::new(server, FixedClock { now_ms: 0 }, urls(), device()).unwrap();
    let password = Zeroizing::new(password.to_owned());
    let result =
        block_on(unlock(&mut api, &api_key(), email, password, &NativeArgon2, &AwsLcRsa, &Namespace::BWSS, allowed));
    let seen = seen.borrow().clone();
    Outcome { result, seen }
}

/// Unlocks a `vectors/accounts/` account with its own password.
fn unlock_account(name: &str, allowed: &Organizations) -> (Unlocked, Value) {
    let keys = account_keys(&vectors_dir().unwrap(), name, false);
    let acc = account(name);
    let email = acc["email"].as_str().unwrap();
    let out = run_unlock(keys.profile, keys.prelogin, email, acc["password"].as_str().unwrap(), allowed);
    (out.result.unwrap(), acc)
}

fn device() -> DeviceInfo {
    DeviceInfo {
        identifier: "vectors-device".into(),
        name: "vectors".into(),
        device_type: 8,
        client_name: "cli".into(),
        client_version: "0".into(),
    }
}

#[test]
fn unlock_pbkdf2() {
    let (unlocked, acc) = unlock_account("pbkdf2", &Organizations::None);
    assert_eq!(unlocked.keys.user.to_bytes().to_vec(), b64(&acc["userKey"]));
    assert_eq!(unlocked.sync["profile"]["id"], "vectors-user");
    assert!(unlocked.keys.orgs.is_empty() && unlocked.org_problems.is_empty());
    unlocked.lock();
}

#[test]
fn unlock_argon2id() {
    let (unlocked, acc) = unlock_account("argon2id", &Organizations::None);
    assert_eq!(unlocked.keys.user.to_bytes().to_vec(), b64(&acc["userKey"]));
}

#[test]
fn unlock_org() {
    let (unlocked, acc) = unlock_account("org", &Organizations::All);
    let orgs = acc["organizations"].as_array().unwrap();
    assert_eq!(unlocked.keys.orgs.len(), orgs.len());
    for org in orgs {
        let key = &unlocked.keys.orgs[org["id"].as_str().unwrap()];
        assert_eq!(key.to_bytes().to_vec(), b64(&org["key"]));
    }
    assert!(unlocked.org_problems.is_empty());
    let (unlocked, _) = unlock_account("org", &Organizations::None);
    assert!(unlocked.keys.orgs.is_empty() && unlocked.org_problems.is_empty());
}

/// Both SDK accounts (sdk-internal 3d16437): a COSE user key (XAES-256-GCM, then XChaCha20-Poly1305) wrapped as a
/// type 2 string under the stretched master key, and a type 7 private key under that user key.
#[test]
fn unlock_cose() {
    let cose = cose_accounts();
    let (email, password) = (cose["email"].as_str().unwrap(), cose["password"].as_str().unwrap());
    let prelogin = json!({ "kdf": 0, "kdfIterations": cose["pbkdf2Iterations"] });
    let accounts = cose["accounts"].as_array().unwrap();
    let names: Vec<&str> = accounts.iter().map(|a| a["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["xaes-256-gcm", "xchacha20-poly1305"]);
    let mut ids = Vec::new();
    for acc in accounts {
        let profile = json!({
            "id": "vectors-user", "email": email, "key": acc["protectedUserKey"],
            "privateKey": acc["privateKey"]["wrapped"], "organizations": [],
        });
        let unlocked =
            run_unlock(profile.clone(), prelogin.clone(), email, password, &Organizations::All).result.unwrap();
        assert_eq!(unlocked.keys.user.to_bytes().to_vec(), b64(&acc["userKey"]), "{}", acc["name"]);
        let wrapped = acc["privateKey"]["wrapped"].as_str().unwrap();
        assert_eq!(unlocked.keys.user.decrypt_pkcs8(wrapped).unwrap().to_vec(), b64(&acc["privateKey"]["pkcs8"]));
        // A COSE user key keeps its id across unlocks too.
        let again = run_unlock(profile, prelogin.clone(), email, password, &Organizations::All).result.unwrap();
        ids.push(unlocked.user_key_id());
        assert_eq!(again.user_key_id(), unlocked.user_key_id());
    }
    assert_ne!(ids.first(), ids.last());
}

#[test]
fn wrong_password() {
    let keys = account_keys(&vectors_dir().unwrap(), "pbkdf2", false);
    let acc = account("pbkdf2");
    let (email, user_key) = (acc["email"].as_str().unwrap(), acc["userKey"].as_str().unwrap());
    let wrong = "not-the-vectors-password";
    let out = run_unlock(keys.profile, keys.prelogin, email, wrong, &Organizations::All);
    let Err(err) = out.result else { panic!("a wrong password unlocked") };
    assert!(matches!(err, ProfileError::WrongPassword), "{err:?}");
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains(wrong) && !text.contains(user_key) && !text.contains("vectors"), "{text}");
    }
    // As in bwss: prelogin, the API-key login and /sync; the password, or a hash of it, never leaves.
    let routes: Vec<&str> = out.seen.iter().map(|s| s.split(' ').nth(1).unwrap()).collect();
    assert_eq!(
        routes,
        [
            "https://vectors.invalid/identity/accounts/prelogin",
            "https://vectors.invalid/identity/connect/token",
            "https://vectors.invalid/api/sync?excludeDomains=true",
        ]
    );
    let master = block_on(derive_master_key(wrong, email, KdfParams::Pbkdf2 { iterations: 600_000 }, &NativeArgon2));
    let hash = hash_master_password(&master.unwrap(), wrong);
    assert!(out.seen.iter().all(|s| !s.contains(wrong) && !s.contains(&hash)), "{:?}", out.seen);
}

/// The SDK refuses a type 7 user key under the master key (bitwarden-crypto/src/keys/master_key.rs:191): it is
/// not taken for a wrong password.
#[test]
fn type7_profile_key_is_refused() {
    let keys = account_keys(&vectors_dir().unwrap(), "pbkdf2", false);
    let acc = account("pbkdf2");
    let mut profile = keys.profile;
    profile["key"] = cose_accounts()["accounts"][0]["texts"][0]["enc"].clone();
    let out = run_unlock(
        profile,
        keys.prelogin,
        acc["email"].as_str().unwrap(),
        acc["password"].as_str().unwrap(),
        &Organizations::None,
    );
    let Err(err) = out.result else { panic!("a type 7 user key unlocked") };
    assert!(matches!(err, ProfileError::Crypto(CryptoError::WrongKey)), "{err:?}");
}

#[test]
fn unlock_reports_server_and_kdf_errors() {
    let keys = account_keys(&vectors_dir().unwrap(), "pbkdf2", false);
    let acc = account("pbkdf2");
    let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
    // A KDF below the floor is refused before any derivation.
    let low = json!({ "kdf": 0, "kdfIterations": 1 });
    let err = run_unlock(keys.profile.clone(), low, email, password, &Organizations::None).result.err().unwrap();
    assert!(matches!(err, ProfileError::Crypto(CryptoError::Kdf(_))), "{err:?}");
    // An unknown KDF type is the server's error.
    let bad = json!({ "kdf": 9 });
    let err = run_unlock(keys.profile, bad, email, password, &Organizations::None).result.err().unwrap();
    assert!(matches!(err, ProfileError::Api(_)), "{err:?}");
}

/// The user-key id is the same for every unlock of one key, and changes when Bitwarden rotates the user key
/// (sdk-internal 3d16437 bitwarden-core/src/key_management/account_cryptographic_state.rs `rotate`, V1 to V2).
#[test]
fn user_key_id_is_stable_and_changes_on_rotation() {
    let (first, acc) = unlock_account("pbkdf2", &Organizations::None);
    let (second, _) = unlock_account("pbkdf2", &Organizations::None);
    let id = first.user_key_id();
    assert_eq!(id, second.user_key_id());
    assert_eq!(id.len(), 22, "{id}");
    assert!(!id.contains(acc["userKey"].as_str().unwrap()) && !acc["userKey"].as_str().unwrap().contains(&id));

    // Rotation: the same password now unwraps another key, legacy (V1 to V1) or COSE (V1 to V2).
    let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
    let master =
        block_on(derive_master_key(password, email, KdfParams::Pbkdf2 { iterations: 600_000 }, &NativeArgon2)).unwrap();
    let stretched = SymmetricKey::stretch(&master);
    let rng = SeededRandom::new(15);
    let rotated =
        [SymmetricKey::generate(&rng).unwrap(), SymmetricKey::generate_cose(CoseAlgorithm::Xaes256Gcm, &rng).unwrap()];
    let mut ids = vec![id];
    for new in rotated {
        let keys = account_keys(&vectors_dir().unwrap(), "pbkdf2", false);
        let mut profile = keys.profile;
        profile["key"] = json!(stretched.encrypt(&new.to_bytes(), &rng).unwrap());
        let unlocked = run_unlock(profile, keys.prelogin, email, password, &Organizations::None).result.unwrap();
        assert_eq!(unlocked.keys.user.to_bytes(), new.to_bytes());
        ids.push(unlocked.user_key_id());
    }
    let distinct: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(distinct.len(), 3, "{ids:?}");
}
