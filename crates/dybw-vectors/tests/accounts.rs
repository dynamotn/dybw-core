#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::api::{ApiKey, Client, DeviceInfo, origin_of, resolve_server_urls};
use dybw_core::crypto::{
    AwsLcRsa, CryptoError, KdfParams, NativeArgon2, SymmetricKey, derive_master_key, hash_master_password,
    unwrap_signing_key, verify_security_state,
};
use dybw_core::ports::{Argon2Input, Http, HttpRequest, HttpResponse, KdfRunner, PortError, Storage};
use dybw_core::profile::{
    CachedSync, KdfPin, KdfSource, ProfileError, SecurityFault, UnlockWarning, Unlocked, accept_kdf,
    accept_security_version, unlock, unlock_cached,
};
use dybw_core::testing::{FixedClock, MemStorage, SeededRandom, block_on};
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
    /// Top-level members added to the `/sync` answer (`userDecryption` of newer servers).
    extra: Value,
}

impl Http for Recording {
    fn refuses_redirects(&self) -> bool {
        true
    }
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        let body = String::from_utf8_lossy(req.body.as_deref().map_or(&[][..], Vec::as_slice)).into_owned();
        self.seen.borrow_mut().push(format!("{:?} {} {body}", req.method, req.url));
        let is_sync = req.url.contains("/api/sync");
        let mut res = self.inner.send(req).await?;
        if is_sync && let Some(extra) = self.extra.as_object() {
            let mut sync: Value = serde_json::from_slice(&res.body).unwrap();
            sync.as_object_mut().unwrap().extend(extra.clone());
            res.body = Zeroizing::new(sync.to_string().into_bytes());
        }
        Ok(res)
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
    run_unlock_with(profile, prelogin, email, password, allowed, Value::Null)
}

fn run_unlock_with(
    profile: Value,
    prelogin: Value,
    email: &str,
    password: &str,
    allowed: &Organizations,
    extra: Value,
) -> Outcome {
    run_full(profile, prelogin, email, password, allowed, extra, &MemStorage::default(), &NativeArgon2)
}

/// Every port the test may want to see or replace: the pin storage and the Argon2id runner.
#[expect(clippy::too_many_arguments, reason = "a test helper over unlock's ports")]
fn run_full(
    profile: Value,
    prelogin: Value,
    email: &str,
    password: &str,
    allowed: &Organizations,
    extra: Value,
    storage: &MemStorage,
    runner: &impl KdfRunner,
) -> Outcome {
    let seen = std::rc::Rc::default();
    let inner = VectorServer::new(profile, vec![], prelogin);
    let server = Recording { inner, seen: std::rc::Rc::clone(&seen), extra };
    let mut api = Client::new(server, FixedClock { now_ms: 0 }, urls(), device()).unwrap();
    let password = Zeroizing::new(password.to_owned());
    let result =
        block_on(unlock(&mut api, storage, &api_key(), email, password, runner, &AwsLcRsa, &Namespace::BWSS, allowed));
    let seen = seen.borrow().clone();
    Outcome { result, seen }
}

/// The `/sync` members of a newer server for a PBKDF2 account: all three of `masterPasswordUnlock`.
fn unlock_data(wrapped: &Value, iterations: u32, salt: &str) -> Value {
    json!({ "userDecryption": { "masterPasswordUnlock": {
        "kdf": { "kdfType": 0, "iterations": iterations }, "masterKeyEncryptedUserKey": wrapped, "salt": salt,
    } } })
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

/// Both SDK accounts (sdk-internal 3d16437) hold a COSE user key (XAES-256-GCM, then XChaCha20-Poly1305) wrapped as
/// a type 2 string under the stretched master key, but a sync without a signed security state is refused (ADR 0019).
#[test]
fn cose_account_without_state_is_refused() {
    let cose = cose_accounts();
    let (email, password) = (cose["email"].as_str().unwrap(), cose["password"].as_str().unwrap());
    let prelogin = json!({ "kdf": 0, "kdfIterations": cose["pbkdf2Iterations"] });
    for acc in cose["accounts"].as_array().unwrap() {
        let profile = json!({
            "id": "vectors-user", "email": email, "key": acc["protectedUserKey"],
            "privateKey": acc["privateKey"]["wrapped"], "organizations": [],
        });
        let storage = MemStorage::default();
        let out = run_full(
            profile,
            prelogin.clone(),
            email,
            password,
            &Organizations::All,
            Value::Null,
            &storage,
            &NativeArgon2,
        );
        let Err(err) = out.result else { panic!("{}: unlocked without a security state", acc["name"]) };
        assert!(matches!(err, ProfileError::SecurityState(SecurityFault::Missing)), "{err:?}");
        assert_eq!(err.to_string(), "security state is missing from the sync data");
        // Nothing is saved after a refusal: no version and no KDF pin.
        assert!(block_on(storage.load("security-version")).unwrap().is_none());
        assert!(block_on(storage.load("kdf-pin")).unwrap().is_none());
    }
    // The `cose` account has none either.
    let keys = account_keys(&vectors_dir().unwrap(), "cose", false);
    let acc = account("cose");
    let out = run_unlock(
        keys.profile,
        keys.prelogin,
        acc["email"].as_str().unwrap(),
        acc["password"].as_str().unwrap(),
        &Organizations::None,
    );
    assert!(matches!(out.result, Err(ProfileError::SecurityState(SecurityFault::Missing))));
}

/// Unlocks `cose-v2` after `edit` changed its sync profile, on `storage`.
fn unlock_v2(storage: &MemStorage, edit: impl FnOnce(&mut Value)) -> Result<Unlocked, ProfileError> {
    let keys = account_keys(&vectors_dir().unwrap(), "cose-v2", false);
    let acc = account("cose-v2");
    let mut profile = keys.profile;
    edit(&mut profile);
    let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
    run_full(profile, keys.prelogin, email, password, &Organizations::None, Value::Null, storage, &NativeArgon2).result
}

fn stored_version(storage: &MemStorage) -> Option<Vec<u8>> {
    block_on(storage.load("security-version")).unwrap()
}

#[test]
fn cose_v2_unlocks_with_version_2() {
    let storage = MemStorage::default();
    let unlocked = unlock_v2(&storage, |_| {}).unwrap();
    assert_eq!((unlocked.security_version, unlocked.keys.security_version), (2, 2));
    assert_eq!(stored_version(&storage).as_deref(), Some(&b"2"[..]));
    assert_eq!(unlocked.keys.user.to_bytes().to_vec(), b64(&account("cose-v2")["userKey"]));
    // The same version again, and a lower saved one raised to it.
    assert_eq!(unlock_v2(&storage, |_| {}).unwrap().security_version, 2);
    block_on(storage.save("security-version", b"1")).unwrap();
    assert_eq!(unlock_v2(&storage, |_| {}).unwrap().security_version, 2);
    assert_eq!(stored_version(&storage).as_deref(), Some(&b"2"[..]));
}

#[test]
fn lower_version_is_refused() {
    let storage = MemStorage::default();
    block_on(storage.save("security-version", b"3")).unwrap();
    let Err(err) = unlock_v2(&storage, |_| {}) else { panic!("a lower version unlocked") };
    assert!(matches!(err, ProfileError::SecurityDowngrade { seen: 3, offered: 2 }), "{err:?}");
    // Nothing changed: the saved version stays and no KDF pin was written.
    assert_eq!(stored_version(&storage).as_deref(), Some(&b"3"[..]));
    assert!(block_on(storage.load("kdf-pin")).unwrap().is_none());
}

#[test]
fn accepting_a_security_version_lets_the_unlock_through() {
    // The profile moved to another account or server, whose state is older: the user accepts its version.
    let storage = MemStorage::default();
    block_on(storage.save("security-version", b"3")).unwrap();
    assert!(unlock_v2(&storage, |_| {}).is_err());
    block_on(accept_security_version(&storage, 2)).unwrap();
    assert_eq!(stored_version(&storage).as_deref(), Some(&b"2"[..]));
    assert_eq!(unlock_v2(&storage, |_| {}).unwrap().security_version, 2);
    // A legacy key after it: 0 is accepted as well.
    block_on(accept_security_version(&storage, 0)).unwrap();
    assert_eq!(pbkdf2_account().unlock(Value::Null, &storage).result.unwrap().security_version, 0);
}

#[test]
fn legacy_key_after_v2_is_refused() {
    let storage = MemStorage::default();
    block_on(storage.save("security-version", b"2")).unwrap();
    let acc = pbkdf2_account();
    let Err(err) = acc.unlock(Value::Null, &storage).result else { panic!("a legacy key unlocked after v2") };
    assert!(matches!(err, ProfileError::SecurityDowngrade { seen: 2, offered: 0 }), "{err:?}");
    // Without a saved version a legacy key unlocks with version 0 and saves nothing.
    let storage = MemStorage::default();
    let unlocked = acc.unlock(Value::Null, &storage).result.unwrap();
    assert_eq!((unlocked.security_version, unlocked.keys.security_version), (0, 0));
    assert_eq!(stored_version(&storage), None);
}

/// A state whose signature does not verify, an unreadable signing key and a missing half are all refused as
/// `SecurityState`, and none of them is a wrong password.
#[test]
fn forged_state_is_refused() {
    let flip_signature = |profile: &mut Value| {
        let state = profile["accountKeys"]["securityState"]["securityState"].as_str().unwrap();
        let mut bytes = B64.decode(state).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        profile["accountKeys"]["securityState"]["securityState"] = json!(B64.encode(bytes));
    };
    type Edit = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, SecurityFault, Edit)> = vec![
        ("bad signature", SecurityFault::Invalid, Box::new(flip_signature)),
        (
            "state not base64",
            SecurityFault::Invalid,
            Box::new(|p| p["accountKeys"]["securityState"]["securityState"] = json!("!")),
        ),
        (
            "signing key not decryptable",
            SecurityFault::Invalid,
            Box::new(|p| p["accountKeys"]["signatureKeyPair"]["wrappedSigningKey"] = json!("2.x|y|z")),
        ),
        (
            "no signing key",
            SecurityFault::Missing,
            Box::new(|p| p["accountKeys"]["signatureKeyPair"].as_object_mut().unwrap().clear()),
        ),
        (
            "no state",
            SecurityFault::Missing,
            Box::new(|p| _ = p["accountKeys"].as_object_mut().unwrap().remove("securityState")),
        ),
    ];
    for (what, fault, edit) in cases {
        let storage = MemStorage::default();
        let Err(err) = unlock_v2(&storage, |p| edit(p)) else { panic!("{what}: unlocked") };
        assert!(matches!(err, ProfileError::SecurityState(f) if f == fault), "{what}: {err:?}");
        assert_eq!(stored_version(&storage), None, "{what}");
    }
}

/// The server's `verifyingKey` and `securityVersion` are never read.
#[test]
fn server_verifying_key_is_ignored() {
    let storage = MemStorage::default();
    let unlocked = unlock_v2(&storage, |p| {
        p["accountKeys"]["signatureKeyPair"]["verifyingKey"] = json!("AAAA");
        p["accountKeys"]["securityState"]["securityVersion"] = json!(9);
    })
    .unwrap();
    assert_eq!(unlocked.security_version, 2);
    assert_eq!(stored_version(&storage).as_deref(), Some(&b"2"[..]));
}

/// A damaged saved version is refused, not reset to 0.
#[test]
fn unreadable_saved_version_is_refused() {
    for damaged in [&b"two"[..], b"", b"-1", &[0xff, 0xfe][..], b"99999999999999999999999"] {
        let storage = MemStorage::default();
        block_on(storage.save("security-version", damaged)).unwrap();
        let Err(err) = unlock_v2(&storage, |_| {}) else { panic!("{damaged:?}: unlocked") };
        assert!(matches!(err, ProfileError::SecurityState(SecurityFault::StoredUnreadable)), "{err:?}");
        assert_eq!(stored_version(&storage).as_deref(), Some(damaged));
    }
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
    // The API-key login and /sync, then prelogin (source 2); the password, or a hash of it, never leaves.
    let routes: Vec<&str> = out.seen.iter().map(|s| s.split(' ').nth(1).unwrap()).collect();
    assert_eq!(
        routes,
        [
            "https://vectors.invalid/identity/connect/token",
            "https://vectors.invalid/api/sync?excludeDomains=true",
            "https://vectors.invalid/identity/accounts/prelogin",
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
    // The COSE key is the `cose-v2` account's, with its signed state (a COSE key needs one).
    let v2 = account_keys(&vectors_dir().unwrap(), "cose-v2", false);
    let rotated = [(SymmetricKey::generate(&rng).unwrap(), None), (v2.user, Some(v2.profile["accountKeys"].clone()))];
    let mut ids = vec![id];
    for (new, state) in rotated {
        let keys = account_keys(&vectors_dir().unwrap(), "pbkdf2", false);
        let mut profile = keys.profile;
        if let Some(state) = state {
            profile["accountKeys"] = state;
        }
        profile["key"] = json!(stretched.encrypt(&new.to_bytes(), &rng).unwrap());
        let unlocked = run_unlock(profile, keys.prelogin, email, password, &Organizations::None).result.unwrap();
        assert_eq!(unlocked.keys.user.to_bytes(), new.to_bytes());
        ids.push(unlocked.user_key_id());
    }
    let distinct: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(distinct.len(), 3, "{ids:?}");
}

/// Newer servers carry the wrapped user key in `userDecryption.masterPasswordUnlock` (sdk-internal 3d16437
/// bitwarden-api-api/src/models/master_password_unlock_response_model.rs); a sync without `profile.key` unlocks.
#[test]
fn unlock_from_user_decryption_only() {
    let keys = account_keys(&vectors_dir().unwrap(), "pbkdf2", false);
    let acc = account("pbkdf2");
    let mut profile = keys.profile;
    let wrapped = profile["key"].take();
    let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
    let extra = unlock_data(&wrapped, 600_000, email);
    let out = run_unlock_with(profile, keys.prelogin, email, password, &Organizations::None, extra);
    assert_eq!(out.result.unwrap().keys.user.to_bytes().to_vec(), b64(&acc["userKey"]));
}

/// The master key's salt is `masterPasswordUnlock.salt` when the server sends one (an account that kept its salt
/// when its email changed), trimmed and lowercased like the email; the email alone then fails.
#[test]
fn unlock_uses_the_server_salt() {
    let keys = account_keys(&vectors_dir().unwrap(), "pbkdf2", false);
    let acc = account("pbkdf2");
    let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
    let user = SymmetricKey::from_bytes(&b64(&acc["userKey"])).unwrap();
    let prelogin = json!({ "kdf": 0, "kdfIterations": 5000 });
    let params = KdfParams::Pbkdf2 { iterations: 5000 };
    let master = block_on(derive_master_key(password, "old-address@vectors.invalid", params, &NativeArgon2)).unwrap();
    let mut profile = keys.profile;
    profile["key"] = json!(SymmetricKey::stretch(&master).encrypt(&user.to_bytes(), &SeededRandom::new(3)).unwrap());
    let extra = unlock_data(&profile["key"], 5000, " Old-Address@Vectors.invalid ");
    let out = run_unlock_with(profile.clone(), prelogin.clone(), email, password, &Organizations::None, extra);
    assert_eq!(out.result.unwrap().keys.user.to_bytes(), user.to_bytes());
    let out = run_unlock(profile, prelogin, email, password, &Organizations::None);
    assert!(matches!(out.result, Err(ProfileError::WrongPassword)));
}

/// The version comes from the signed state, verified with the key derived from the wrapped signing key; accounts
/// without a signed state read 0.
#[test]
fn cose_v2_security_state_is_2() {
    let dir = vectors_dir().unwrap();
    for (name, version) in [("pbkdf2", 0), ("cose", 0), ("cose-v2", 2)] {
        assert_eq!(account_keys(&dir, name, false).security_version, version, "{name}");
    }
    let v2 = account_keys(&dir, "cose-v2", false);
    let keys = &v2.profile["accountKeys"];
    let signing =
        unwrap_signing_key(&v2.user, keys["signatureKeyPair"]["wrappedSigningKey"].as_str().unwrap()).unwrap();
    assert_eq!(verify_security_state(&signing, keys["securityState"]["securityState"].as_str().unwrap()), Ok(2));
    assert!(account_keys(&dir, "cose", false).profile.get("accountKeys").is_none());
}

// Blob ciphers the generator made for the `cose-v2` account (`encrypt_cipher` with id `b1` or `b2`, scenario
// `test/blob`, namespace `bwss`); `V2` has its content version set to "2".
const BLOB_KEY: &str = "7.g1g+owE6AAEReQN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUFHYp5ZxciEqDVIAAaWt0KKhBVgYhw/UtZymRxRaiTwzGseF3YagFG2dNU3UWFDlfTHYXvFKFWla8z3cDZR8Us64K+Y57dUYfMk8EuVlTpIB23gsD41t/om3a9Pd3xN/MVxmjPg9li7dTkJbXcwcvfi0hoHNOrfc9zZd8cgkVA==";
const BLOB_LOGIN: &str = r#"{"format_version":1,"wrapped_cek":"2.DECH2lF+X/igdEgcaHl4ZQ==|jCc4JIVD19hNG/yvo+d2cE0DZFhiFIUejH1Jmytb9gFLHv8E+ehtflZHPOTYUXPfza1P23ep8k7luoXwoyiIZdHvubLXfknKgWEetqOk76c=|H7sEjoSLgQEs5dsc6XOn+/SseUgSwMLcbNADg8emYyk=","envelope":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUAExRAbJDG+AlWbvWDy0odA6AAE4gQI6AAE4gAGhBUx/4oeVajl+Klur3g9ZAUXnCW8z0RvWdqBucl0fvUEV7LXNWIlRQrka5usy8Sxx7SAwiYOmTSIZDLVNugEoyYgFfJ+tDEWKM75YGjVNn9oxHOYM5EWJvUyWBqdt9AcqSFOwBOyNaKkC3P2+EjIOcFtWsuGTC94kuO4FDwZCD+lWktLaGiSJ6ScIhsBuII5cdoikaeG3FpTKArHSTUV6gEYLTMiW/e4flZR4XD/DjJe4wKLKV5NDVyEspfKBFv7pQyMa7vK/Q41bHCbWDxx7to++mgZjGRRaBVjyZ+kEeR+86CQGyCQpsOW4ouLOoz98/PaWFP8leDV3p/1GpqLTG+Lkzazt1a+onABzk18xvIl6ijaLfNsM0wBXCVo5GvI9ANNiQoFK1BUJfdDSH1wKFJC0c/3YCuKt3qx4RsdKoUQa8izp9mdhBQXs4XlhHIOeYGFCbBoP"}"#;
const BLOB_V2: &str = r#"{"format_version":1,"wrapped_cek":"2.DECH2lF+X/igdEgcaHl4ZQ==|jCc4JIVD19hNG/yvo+d2cE0DZFhiFIUejH1Jmytb9gFLHv8E+ehtflZHPOTYUXPfza1P23ep8k7luoXwoyiIZdHvubLXfknKgWEetqOk76c=|H7sEjoSLgQEs5dsc6XOn+/SseUgSwMLcbNADg8emYyk=","envelope":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUAExRAbJDG+AlWbvWDy0odA6AAE4gQI6AAE4gAGhBUx/4oeVajl+Klur3g9ZAUXnCW8z0RvWdqBucV0fvUEV7LXNWIlRQrka5usy8Sxx7SAwiYOmTSIZDLVNugEoyYgFfJ+tDEWKM75YGjVNn9oxHOYM5EWJvUyWBqdt9AcqSFOwBOyNaKkC3P2+EjIOcFtWsuGTC94kuO4FDwZCD+lWktLaGiSJ6ScIhsBuII5cdoikaeG3FpTKArHSTUV6gEYLTMiW/e4flZR4XD/DjJe4wKLKV5NDVyEspfKBFv7pQyMa7vK/Q41bHCbWDxx7to++mgZjGRRaBVjyZ+kEeR+86CQGyCQpsOW4ouLOoz98/PaWFP8leDV3p/1GpqLTG+Lkzazt1a+onABzk18xvIl6ijaLfNsM0wBXCVo5GvI9ANNiQoFK1BUJfdDSH1wKFJC0c/3YCuKt3qx4RsdKoUQa8izp9meFGu5Wz+zqRtlofOUXvh4W"}"#;
const BLOB_NOTE_KEY: &str = "7.g1g+owE6AAEReQN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUFHYp5ZxciEqDVIAAaWt0KKhBVgYLRvsoBE6bITTzkExqa8mZykhbjNhZskIWFCiGzvJESZRSAuknORbwCtT0JgV2vcJlSghs7gEoUXLaWO3gRw3WTyU1U8XIYrlnR1s07t1le/15B0Z4OvX8yxe9IenFYs8Q7qa0eXDbeooQA==";
const BLOB_NOTE: &str = r#"{"format_version":1,"wrapped_cek":"2.IvG2gWqHNtc3s+4HYozOJg==|9yfRbSBVRtBOMkVfPM72PDUXafIaa1J7ezCRKJT4b1oNf5EzuacPZ+pFPYMyV4vD4pTidjTnQOnjE5l+ChbE8jZjrdMZvnASwpwTJt7SxrA=|Mwt1cbHL3jqNDnpAXo4q4itXIa1PlXWcoGdaMxsMobo=","envelope":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUDfZOxLzuxqoab5QZ0Jg8yw6AAE4gQI6AAE4gAGhBUzF8bKl8LEjdYkcBRpYYM9dmk3rI9o2COmzNOWmdkjqbU3w96IHhliu1aR7Vzz87Vr8pGaEPREZ/xOoQNRnrKbgGs/i7H29epbwXA2e6ZxkM/SqINCVkB++FCNORBT2aYGUGr5k3r55OPGR7OqUpw=="}"#;

fn blob_put(key: &str, data: Value) -> Sent {
    let body = json!({
        "type": 1, "name": null, "notes": null, "login": null, "fields": null, "passwordHistory": null,
        "organizationId": null, "folderId": null, "key": key, "data": data, "lastKnownRevisionDate": NOW,
    });
    Sent::Put { cipher: "b1".into(), body }
}

/// `data` with `f` applied to its parsed JSON.
fn edited(data: &str, f: impl FnOnce(&mut Value)) -> Value {
    let mut v: Value = serde_json::from_str(data).unwrap();
    f(&mut v);
    Value::String(v.to_string())
}

#[test]
fn canonicalize_opens_a_blob_with_the_scenarios_keys() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "cose-v2", false);
    let got = canonicalize(&blob_put(BLOB_KEY, json!(BLOB_LOGIN)), &keys.user, &BTreeMap::new()).unwrap();
    assert_eq!(
        got,
        json!({
            "method": "PUT", "cipher": "b1", "type": 1, "name": "Blob", "notes": "n",
            "login": {
                "username": "u", "password": "pw", "uris": ["https://a.invalid"], "totp": null,
                "passwordHistory": ["old"],
            },
            "fields": [{ "name": "bwss:id", "value": "x", "type": 0 }, { "name": "f", "value": null, "type": 1 }],
            "organizationId": null, "folderId": null, "lastKnownRevisionDate": "<now>", "hasItemKey": true,
            "extra": {}, "blob": true,
        })
    );
    let note = canonicalize(&blob_put(BLOB_NOTE_KEY, json!(BLOB_NOTE)), &keys.user, &BTreeMap::new()).unwrap();
    assert_eq!(
        (&note["login"], &note["fields"], &note["notes"], &note["blob"]),
        (&json!(null), &json!([]), &json!(null), &json!(true))
    );
}

#[test]
fn canonicalize_refuses_a_blob_it_cannot_open() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "cose-v2", false);
    let flip = |text: &str| {
        let mut raw = B64.decode(text).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        json!(B64.encode(raw))
    };
    let cases = [
        ("envelope", edited(BLOB_LOGIN, |v| v["envelope"] = flip(v["envelope"].as_str().unwrap()))),
        (
            "wrapped_cek",
            edited(BLOB_LOGIN, |v| {
                v["wrapped_cek"] = json!("2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAA")
            }),
        ),
        ("newer format", edited(BLOB_LOGIN, |v| v["format_version"] = json!(2))),
        ("newer content", Value::String(BLOB_V2.into())),
        ("no envelope", edited(BLOB_LOGIN, |v| _ = v.as_object_mut().unwrap().remove("envelope"))),
        ("not JSON", json!("{")),
        ("not text", json!(5)),
    ];
    for (what, data) in cases {
        assert!(canonicalize(&blob_put(BLOB_KEY, data), &keys.user, &BTreeMap::new()).is_err(), "{what}");
    }
    // The wrong user key does not open the item key.
    let other = account_keys(&dir, "cose", false);
    assert!(canonicalize(&blob_put(BLOB_KEY, json!(BLOB_LOGIN)), &other.user, &BTreeMap::new()).is_err());
}

// One KDF source per unlock (ADR 0022) and the KDF pin (ADR 0017).

const PBKDF2_600K: KdfParams = KdfParams::Pbkdf2 { iterations: 600_000 };
const ARGON_FLOOR: KdfParams = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };

/// The `pbkdf2` account's pieces, as an unlock needs them.
struct Pbkdf2Account {
    profile: Value,
    prelogin: Value,
    email: String,
    password: String,
}

fn pbkdf2_account() -> Pbkdf2Account {
    let keys = account_keys(&vectors_dir().unwrap(), "pbkdf2", false);
    let acc = account("pbkdf2");
    Pbkdf2Account {
        profile: keys.profile,
        prelogin: keys.prelogin,
        email: acc["email"].as_str().unwrap().to_owned(),
        password: acc["password"].as_str().unwrap().to_owned(),
    }
}

impl Pbkdf2Account {
    fn clone_parts(&self) -> Pbkdf2Account {
        Pbkdf2Account {
            profile: self.profile.clone(),
            prelogin: self.prelogin.clone(),
            email: self.email.clone(),
            password: self.password.clone(),
        }
    }

    fn unlock(&self, extra: Value, storage: &MemStorage) -> Outcome {
        let allowed = Organizations::None;
        run_full(
            self.profile.clone(),
            self.prelogin.clone(),
            &self.email,
            &self.password,
            &allowed,
            extra,
            storage,
            &NativeArgon2,
        )
    }

    /// Source 1 with the account's real KDF.
    fn data(&self) -> Value {
        unlock_data(&self.profile["key"], 600_000, &self.email)
    }

    /// The same user key wrapped under a master key of `iterations`, as source 1.
    fn rewrapped(&mut self, iterations: u32) -> Value {
        let user = SymmetricKey::from_bytes(&b64(&account("pbkdf2")["userKey"])).unwrap();
        let params = KdfParams::Pbkdf2 { iterations };
        let master = block_on(derive_master_key(&self.password, &self.email, params, &NativeArgon2)).unwrap();
        let wrapped = SymmetricKey::stretch(&master).encrypt(&user.to_bytes(), &SeededRandom::new(3)).unwrap();
        self.profile["key"] = json!(wrapped);
        unlock_data(&self.profile["key"], iterations, &self.email)
    }
}

fn pin_of(storage: &MemStorage) -> Option<KdfPin> {
    let raw = block_on(storage.load("kdf-pin")).unwrap()?;
    let v: Value = serde_json::from_slice(&raw).unwrap();
    let n = |k: &str| u32::try_from(v[k].as_u64().unwrap()).unwrap();
    let params = match n("kdf") {
        0 => KdfParams::Pbkdf2 { iterations: n("iterations") },
        _ => {
            KdfParams::Argon2id { iterations: n("iterations"), memory_mib: n("memory"), parallelism: n("parallelism") }
        }
    };
    Some(KdfPin { params, origin: v["origin"].as_str().unwrap().to_owned() })
}

fn pin(storage: &MemStorage, params: KdfParams, origin: &str) {
    block_on(accept_kdf(storage, params, origin)).unwrap();
}

fn origin() -> String {
    api_key().origin
}

fn prelogin_calls(out: &Outcome) -> usize {
    out.seen.iter().filter(|s| s.contains("/accounts/prelogin")).count()
}

#[test]
fn source_one_needs_no_prelogin() {
    let acc = pbkdf2_account();
    // A prelogin that would fail if it were asked.
    let out =
        Pbkdf2Account { prelogin: json!({ "kdf": 9 }), ..acc.clone_parts() }.unlock(acc.data(), &MemStorage::default());
    assert!(out.result.is_ok());
    assert_eq!(prelogin_calls(&out), 0, "{:?}", out.seen);
}

#[test]
fn source_two_uses_prelogin_and_email() {
    let acc = pbkdf2_account();
    let out = acc.unlock(Value::Null, &MemStorage::default());
    assert!(out.result.is_ok());
    assert_eq!(prelogin_calls(&out), 1);
    assert!(out.seen.last().unwrap().contains("/accounts/prelogin"), "login and sync come first: {:?}", out.seen);
}

#[test]
fn partial_unlock_data_falls_back_to_profile_key() {
    let acc = pbkdf2_account();
    let extra =
        json!({ "userDecryption": { "masterPasswordUnlock": { "masterKeyEncryptedUserKey": acc.profile["key"] } } });
    let out = acc.unlock(extra, &MemStorage::default());
    assert!(out.result.is_ok());
    assert_eq!(prelogin_calls(&out), 1);
}

#[test]
fn partial_unlock_data_without_profile_key_is_incomplete() {
    let mut acc = pbkdf2_account();
    let wrapped = acc.profile["key"].take();
    let extra = json!({ "userDecryption": { "masterPasswordUnlock": { "masterKeyEncryptedUserKey": wrapped } } });
    let storage = MemStorage::default();
    let out = acc.unlock(extra, &storage);
    assert_eq!(prelogin_calls(&out), 0, "sources are not mixed");
    let err = out.result.err().unwrap();
    assert!(matches!(err, ProfileError::IncompleteUnlockData), "{err:?}");
    assert!(pin_of(&storage).is_none());
}

/// Source 1's KDF is right and prelogin's is another one: mixing them would fail as a wrong password.
#[test]
fn sources_are_never_mixed() {
    let mut acc = pbkdf2_account();
    acc.prelogin = json!({ "kdf": 0, "kdfIterations": 5000 });
    let out = acc.unlock(acc.data(), &MemStorage::default());
    assert!(out.result.is_ok());
    assert_eq!(prelogin_calls(&out), 0);
}

#[test]
fn first_unlock_pins() {
    let acc = pbkdf2_account();
    let storage = MemStorage::default();
    assert!(pin_of(&storage).is_none());
    let unlocked = acc.unlock(Value::Null, &storage).result.unwrap();
    assert!(unlocked.warnings.is_empty());
    let expected = KdfPin { params: PBKDF2_600K, origin: origin() };
    assert_eq!(pin_of(&storage), Some(expected.clone()));
    // The same KDF again keeps the pin.
    assert!(acc.unlock(Value::Null, &storage).result.is_ok());
    assert_eq!(pin_of(&storage), Some(expected));
}

/// A pinned Argon2id stronger than the account's: stopped before the runner is asked.
#[test]
fn weaker_kdf_stops_before_derivation() {
    struct Panics;
    impl KdfRunner for Panics {
        async fn argon2id(&self, _: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError> {
            panic!("the KDF ran");
        }
    }
    let keys = account_keys(&vectors_dir().unwrap(), "argon2id", false);
    let acc = account("argon2id");
    let storage = MemStorage::default();
    let pinned = KdfParams::Argon2id { iterations: 3, memory_mib: 128, parallelism: 4 };
    pin(&storage, pinned, &origin());
    let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
    let out =
        run_full(keys.profile, keys.prelogin, email, password, &Organizations::None, Value::Null, &storage, &Panics);
    let err = out.result.err().unwrap();
    assert!(
        matches!(err, ProfileError::KdfWeakened { pinned: p, offered, kdf_source: KdfSource::Prelogin } if p == pinned && offered == ARGON_FLOOR),
        "{err:?}"
    );
    assert!(!err.to_string().contains(password));
    assert_eq!(pin_of(&storage).unwrap().params, pinned);
}

#[test]
fn accept_kdf_then_unlock_succeeds() {
    let acc = pbkdf2_account();
    let storage = MemStorage::default();
    pin(&storage, KdfParams::Pbkdf2 { iterations: 700_000 }, &origin());
    let err = acc.unlock(Value::Null, &storage).result.err().unwrap();
    assert!(matches!(err, ProfileError::KdfWeakened { .. }), "{err:?}");
    pin(&storage, PBKDF2_600K, &origin());
    assert!(acc.unlock(Value::Null, &storage).result.is_ok());
    assert_eq!(pin_of(&storage).unwrap().params, PBKDF2_600K);
}

#[test]
fn stronger_kdf_repins() {
    let acc = pbkdf2_account();
    let storage = MemStorage::default();
    pin(&storage, KdfParams::Pbkdf2 { iterations: 500_000 }, &origin());
    assert!(acc.unlock(Value::Null, &storage).result.is_ok());
    assert_eq!(pin_of(&storage).unwrap().params, PBKDF2_600K);
}

#[test]
fn other_origin_drops_the_pin() {
    let acc = pbkdf2_account();
    let storage = MemStorage::default();
    pin(&storage, KdfParams::Pbkdf2 { iterations: 700_000 }, "https://other.invalid");
    assert!(acc.unlock(Value::Null, &storage).result.is_ok());
    assert_eq!(pin_of(&storage), Some(KdfPin { params: PBKDF2_600K, origin: origin() }));
}

#[test]
fn below_floor_warns_and_pins() {
    let mut acc = pbkdf2_account();
    let extra = acc.rewrapped(5000);
    let storage = MemStorage::default();
    let unlocked = acc.unlock(extra, &storage).result.unwrap();
    let low = KdfParams::Pbkdf2 { iterations: 5000 };
    assert_eq!(
        unlocked.warnings,
        [UnlockWarning::KdfBelowFloor { params: low, kdf_source: KdfSource::SyncUnlockData }]
    );
    assert_eq!(pin_of(&storage), Some(KdfPin { params: low, origin: origin() }));
}

/// Review Focus 4: another KDF type is weaker than the pin unless it meets the floors.
#[test]
fn kdf_type_change_needs_the_floors() {
    let mut acc = pbkdf2_account();
    let storage = MemStorage::default();
    pin(&storage, ARGON_FLOOR, &origin());
    // PBKDF2 at the floor replaces an Argon2id pin.
    assert!(acc.unlock(Value::Null, &storage).result.is_ok());
    assert_eq!(pin_of(&storage).unwrap().params, PBKDF2_600K);
    // PBKDF2 below the floor does not.
    pin(&storage, ARGON_FLOOR, &origin());
    let extra = acc.rewrapped(5000);
    let err = acc.unlock(extra, &storage).result.err().unwrap();
    let low = KdfParams::Pbkdf2 { iterations: 5000 };
    assert!(
        matches!(err, ProfileError::KdfWeakened { pinned, offered, kdf_source: KdfSource::SyncUnlockData } if pinned == ARGON_FLOOR && offered == low),
        "{err:?}"
    );
    assert_eq!(pin_of(&storage).unwrap().params, ARGON_FLOOR);
}

#[test]
fn wrong_password_writes_no_pin() {
    let acc = pbkdf2_account();
    let storage = MemStorage::default();
    let wrong = Pbkdf2Account { password: "not-the-vectors-password".into(), ..acc.clone_parts() };
    let err = wrong.unlock(Value::Null, &storage).result.err().unwrap();
    assert!(matches!(err, ProfileError::WrongPassword), "{err:?}");
    assert!(pin_of(&storage).is_none());
}

/// A bound violation names its source.
#[test]
fn out_of_range_kdf_names_its_source() {
    let acc = pbkdf2_account();
    let low = unlock_data(&acc.profile["key"], 1, &acc.email);
    let err = acc.unlock(low, &MemStorage::default()).result.err().unwrap();
    assert!(err.to_string().contains("KDF from sync unlock data"), "{err}");
    let weak = format!(
        "{}",
        ProfileError::KdfWeakened { pinned: PBKDF2_600K, offered: PBKDF2_600K, kdf_source: KdfSource::Prelogin }
    );
    assert!(weak.contains("KDF from prelogin"), "{weak}");
    let low = Pbkdf2Account { prelogin: json!({ "kdf": 0, "kdfIterations": 1 }), ..acc.clone_parts() };
    let err = low.unlock(Value::Null, &MemStorage::default()).result.err().unwrap();
    assert!(err.to_string().contains("KDF from prelogin"), "{err}");
}

/// A partial `masterPasswordUnlock` is not mixed in: its salt is ignored, the email is the salt.
#[test]
fn partial_unlock_data_salt_is_ignored() {
    let acc = pbkdf2_account();
    let extra = json!({ "userDecryption": { "masterPasswordUnlock": {
        "masterKeyEncryptedUserKey": acc.profile["key"], "salt": "someone-else@vectors.invalid",
    } } });
    let out = acc.unlock(extra, &MemStorage::default());
    assert!(out.result.is_ok());
    assert_eq!(prelogin_calls(&out), 1);
}

/// Zero iterations make source 1 malformed: the unlock falls back to source 2.
#[test]
fn zero_iterations_fall_back_to_source_two() {
    let acc = pbkdf2_account();
    let out = acc.unlock(unlock_data(&acc.profile["key"], 0, &acc.email), &MemStorage::default());
    assert!(out.result.is_ok());
    assert_eq!(prelogin_calls(&out), 1);
}

/// An unreadable pin asks for a new confirmation, and accepting replaces it.
#[test]
fn unreadable_pin_needs_a_new_confirmation() {
    let acc = pbkdf2_account();
    let storage = MemStorage::default();
    block_on(storage.save("kdf-pin", b"not json")).unwrap();
    let err = acc.unlock(Value::Null, &storage).result.err().unwrap();
    assert!(matches!(err, ProfileError::KdfPinUnreadable), "{err:?}");
    pin(&storage, PBKDF2_600K, &origin());
    assert!(acc.unlock(Value::Null, &storage).result.is_ok());
}

#[test]
fn accept_kdf_refuses_out_of_bounds_params() {
    let storage = MemStorage::default();
    let err = block_on(accept_kdf(&storage, KdfParams::Pbkdf2 { iterations: 1 }, &origin())).unwrap_err();
    assert!(matches!(err, ProfileError::Crypto(CryptoError::Kdf(_))), "{err:?}");
    assert!(pin_of(&storage).is_none());
}

#[test]
fn below_floor_warning_names_the_prelogin_source() {
    let mut acc = pbkdf2_account();
    acc.rewrapped(5000);
    acc.prelogin = json!({ "kdf": 0, "kdfIterations": 5000 });
    let unlocked = acc.unlock(Value::Null, &MemStorage::default()).result.unwrap();
    let low = KdfParams::Pbkdf2 { iterations: 5000 };
    assert_eq!(unlocked.warnings, [UnlockWarning::KdfBelowFloor { params: low, kdf_source: KdfSource::Prelogin }]);
}

// Offline unlock from a cached `/sync`: the same checks as online, with no network.

fn cached_unlock(
    sync: Value,
    prelogin_kdf: Option<KdfParams>,
    email: &str,
    password: &str,
    storage: &MemStorage,
) -> Result<Unlocked, ProfileError> {
    let cached = CachedSync { sync, prelogin_kdf, email: email.to_owned() };
    let password = Zeroizing::new(password.to_owned());
    let (rsa, ns) = (AwsLcRsa, Namespace::BWSS);
    block_on(unlock_cached(cached, storage, &origin(), password, &NativeArgon2, &rsa, &ns, &Organizations::None))
}

/// Unlocks `name` online, then again from the sync it was given.
fn online_then_cached(name: &str) -> (Unlocked, Result<Unlocked, ProfileError>) {
    let keys = account_keys(&vectors_dir().unwrap(), name, false);
    let acc = account(name);
    let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
    let online = run_unlock(keys.profile, keys.prelogin, email, password, &Organizations::None).result.unwrap();
    let cached = cached_unlock(online.sync.clone(), Some(PBKDF2_600K), email, password, &MemStorage::default());
    (online, cached)
}

#[test]
fn cached_unlock_matches_online_unlock() {
    for name in ["pbkdf2", "cose-v2"] {
        let (online, cached) = online_then_cached(name);
        let cached = cached.unwrap();
        assert_eq!(cached.keys.user.to_bytes(), online.keys.user.to_bytes(), "{name}");
        assert_eq!(cached.keys.marker.mark_b64("id", "text"), online.keys.marker.mark_b64("id", "text"), "{name}");
        assert_eq!(cached.security_version, online.security_version, "{name}");
        assert_eq!(cached.keys.security_version, online.keys.security_version, "{name}");
    }
}

#[test]
fn cached_unlock_checks_the_pin() {
    let acc = pbkdf2_account();
    let online = acc.unlock(Value::Null, &MemStorage::default()).result.unwrap();
    // A stronger pin for this origin refuses the cached KDF; another origin's pin does not.
    let stronger = KdfParams::Pbkdf2 { iterations: 900_000 };
    let storage = MemStorage::default();
    pin(&storage, stronger, &origin());
    let err = cached_unlock(online.sync.clone(), Some(PBKDF2_600K), &acc.email, &acc.password, &storage).err().unwrap();
    assert!(
        matches!(err, ProfileError::KdfWeakened { pinned, offered, kdf_source: KdfSource::Prelogin }
            if pinned == stronger && offered == PBKDF2_600K),
        "{err:?}"
    );
    let storage = MemStorage::default();
    pin(&storage, stronger, "https://other.invalid");
    cached_unlock(online.sync.clone(), Some(PBKDF2_600K), &acc.email, &acc.password, &storage).unwrap();
    assert_eq!(pin_of(&storage).unwrap(), KdfPin { params: PBKDF2_600K, origin: origin() });
    // A wrong password is a wrong password.
    let err = cached_unlock(online.sync, Some(PBKDF2_600K), &acc.email, "nope", &MemStorage::default()).err().unwrap();
    assert!(matches!(err, ProfileError::WrongPassword), "{err:?}");
}

#[test]
fn cached_unlock_refuses_a_security_downgrade() {
    let (online, _) = online_then_cached("cose-v2");
    let acc = account("cose-v2");
    let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
    let storage = MemStorage::default();
    block_on(storage.save("security-version", b"3")).unwrap();
    let err = cached_unlock(online.sync.clone(), Some(PBKDF2_600K), email, password, &storage).err().unwrap();
    assert!(matches!(err, ProfileError::SecurityDowngrade { seen: 3, offered: 2 }), "{err:?}");
    assert_eq!(stored_version(&storage).as_deref(), Some(&b"3"[..]));
    // A lower saved version is raised, as online.
    let storage = MemStorage::default();
    block_on(storage.save("security-version", b"1")).unwrap();
    cached_unlock(online.sync, Some(PBKDF2_600K), email, password, &storage).unwrap();
    assert_eq!(stored_version(&storage).as_deref(), Some(&b"2"[..]));
}

#[test]
fn cached_unlock_without_prelogin_kdf_needs_source_one() {
    let acc = pbkdf2_account();
    let online = acc.unlock(Value::Null, &MemStorage::default()).result.unwrap();
    let err = cached_unlock(online.sync.clone(), None, &acc.email, &acc.password, &MemStorage::default());
    assert!(matches!(err, Err(ProfileError::IncompleteUnlockData)));
    // Without `profile.key` either, it is incomplete whatever the KDF.
    let mut bare = online.sync.clone();
    bare["profile"].as_object_mut().unwrap().remove("key");
    let err = cached_unlock(bare, Some(PBKDF2_600K), &acc.email, &acc.password, &MemStorage::default());
    assert!(matches!(err, Err(ProfileError::IncompleteUnlockData)));
    // Source 1 in the sync needs no prelogin KDF, and its own salt and KDF win.
    let mut one = online.sync;
    let wrapped = one["profile"].as_object_mut().unwrap().remove("key").unwrap();
    one["userDecryption"] = unlock_data(&wrapped, 600_000, &acc.email)["userDecryption"].clone();
    let unlocked = cached_unlock(one, None, &acc.email, &acc.password, &MemStorage::default()).unwrap();
    assert_eq!(unlocked.keys.user.to_bytes().to_vec(), b64(&account("pbkdf2")["userKey"]));
}
