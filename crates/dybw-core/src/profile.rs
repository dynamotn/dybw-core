//! A profile's session: unlock (prelogin, KDF, user key, private key, organization keys), device identity, lock.
//! Port of bwss `BitwardenBackend::unlock` and the plugin's `unlockUserKey` and `unlockOrganizationKeys`.

use crate::api::{ApiError, ApiKey, Client};
use crate::crypto::{CryptoError, Marker, SymmetricKey, derive_master_key};
use crate::ports::{Clock, Http, KdfRunner, PortError, Random, RsaOaep, Storage};
use crate::vault::{Keys, Namespace, OrgProblem, Organizations, unlock_organizations};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::Value;
use zeroize::Zeroizing;

/// The storage key of the device identifier.
const DEVICE: &str = "device";
/// Domain separation for [`Unlocked::user_key_id`], so the id is no hash of the key used anywhere else.
const USER_KEY_ID_LABEL: &[u8] = b"dybw user-key-id v1";
/// Newer servers' unlock data: the wrapped user key and the master key's salt (sdk-internal 3d16437
/// bitwarden-api-api/src/models/user_decryption_response_model.rs:18, master_password_unlock_response_model.rs:22).
const UNLOCK_DATA_KEY: &str = "/userDecryption/masterPasswordUnlock/masterKeyEncryptedUserKey";
const UNLOCK_DATA_SALT: &str = "/userDecryption/masterPasswordUnlock/salt";

/// Why a profile could not be unlocked. Messages name the problem, never a password, key or value.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The stretched master key fails the user key's MAC.
    #[error("wrong master password")]
    WrongPassword,
    #[error("host port failed: {0}")]
    Port(#[from] PortError),
}

/// An unlocked profile. No `Clone` and no `Debug`: the keys are wiped when it is dropped or locked.
pub struct Unlocked {
    pub keys: Keys,
    pub sync: Value,
    pub org_problems: Vec<OrgProblem>,
}

impl Unlocked {
    /// A stable, non-secret id of the user key: the same for every unlock of one key, another one after Bitwarden
    /// rotates it (sdk-internal 3d16437 bitwarden-core/src/key_management/account_cryptographic_state.rs `rotate`).
    /// SHA-256 over a fixed label and the key's own fields (`SymmetricKey::fingerprint`), cut to 128 bits: it
    /// cannot be turned back into the key.
    ///
    /// The server also sends `userDecryption.userKeyId`, and V2 COSE keys carry a 16-byte id. Neither replaces
    /// this hash: it works for V1 (legacy) keys too, and it is computed here from the key, never trusted from the
    /// server.
    pub fn user_key_id(&self) -> String {
        key_id(&self.keys.user)
    }

    /// Drops every key, which wipes it.
    pub fn lock(self) {
        drop(self);
    }
}

fn key_id(user: &SymmetricKey) -> String {
    B64.encode(user.fingerprint(USER_KEY_ID_LABEL).get(..16).unwrap_or_default())
}

/// The device identifier: the saved one (any non-blank text, trimmed, as bwss), else a new UUID v4 that is saved.
pub async fn device_id(storage: &impl Storage, rng: &impl Random) -> Result<String, ProfileError> {
    let saved = storage.load(DEVICE).await?.and_then(|b| String::from_utf8(b).ok());
    if let Some(id) = saved.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(id.to_owned());
    }
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes)?;
    let id = uuid::Builder::from_random_bytes(bytes).into_uuid().to_string();
    storage.save(DEVICE, id.as_bytes()).await?;
    Ok(id)
}

/// bwss `BitwardenBackend::unlock`: prelogin, the API-key login and `/sync` first, then the KDF, so the password
/// never leaves this process. The wrapped user key is `profile.key`, else `userDecryption.masterPasswordUnlock`'s,
/// and the salt that one's `salt`, else the email (the plugin's `encryptedUserKeyOf` and `masterKeySaltOf`; the SDK
/// reads both in bitwarden-core/src/key_management/master_password.rs:125-160, salt at :57, derived at :82).
/// The key is a type 2 string under the stretched master key holding a legacy or a COSE user key (XAES-256-GCM or
/// XChaCha20-Poly1305); a type 7 one is refused with `WrongKey`, as the SDK does
/// (bitwarden-crypto/src/keys/master_key.rs:176-200 `decrypt_user_key`). Organization keys follow the opt-in.
#[expect(clippy::too_many_arguments, reason = "the brief's signature: each port is the host's")]
pub async fn unlock<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    key: &ApiKey,
    email: &str,
    password: Zeroizing<String>,
    kdf: &impl KdfRunner,
    rsa: &impl RsaOaep,
    ns: &Namespace,
    allowed: &Organizations,
) -> Result<Unlocked, ProfileError> {
    let params = client.prelogin(email).await?;
    client.login(key).await?;
    let sync = client.sync().await?;
    open_sync(sync, email, password, params, kdf, rsa, ns, allowed).await
}

#[expect(clippy::too_many_arguments, reason = "unlock's arguments, after the network")]
async fn open_sync(
    sync: Value,
    email: &str,
    password: Zeroizing<String>,
    params: crate::crypto::KdfParams,
    kdf: &impl KdfRunner,
    rsa: &impl RsaOaep,
    ns: &Namespace,
    allowed: &Organizations,
) -> Result<Unlocked, ProfileError> {
    let text = |p: &str| sync.pointer(p).and_then(Value::as_str).filter(|s| !s.is_empty());
    // bwss "sync without account key": refused before the KDF runs.
    let protected = text("/profile/key")
        .or_else(|| text(UNLOCK_DATA_KEY))
        .ok_or_else(|| ApiError::Protocol("sync without account key".into()))?;
    let salt = text(UNLOCK_DATA_SALT).unwrap_or(email);
    let master = derive_master_key(&password, salt, params, kdf).await?;
    drop(password);
    let stretched = SymmetricKey::stretch(&master);
    drop(master);
    let user = stretched.decrypt_key(protected).map_err(|e| match e {
        CryptoError::BadMac => ProfileError::WrongPassword,
        e => ProfileError::Crypto(e),
    })?;
    drop(stretched);
    let profile = sync.get("profile").unwrap_or(&Value::Null);
    let (orgs, org_problems) = unlock_organizations(profile, &user, rsa, allowed).await;
    let marker = Marker::new(&user, ns.marks);
    Ok(Unlocked { keys: Keys { user, orgs, marker }, sync, org_problems })
}

#[cfg(all(test, feature = "testing"))]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::crypto::{AwsLcRsa, KdfParams, MarkScheme, NativeArgon2};
    use crate::ports::Argon2Input;
    use crate::testing::{MemStorage, SeededRandom, block_on};
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;
    use std::cell::Cell;

    fn fixture(path: &str) -> Value {
        let dir = std::env::var("DYBW_VECTORS_DIR")
            .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors").into());
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{path}")).unwrap()).unwrap()
    }

    fn key_of(v: &Value) -> SymmetricKey {
        SymmetricKey::from_bytes(&STANDARD.decode(v.as_str().unwrap()).unwrap()).unwrap()
    }

    /// Pins the id's encoding (computed independently from the fixtures): label, variant, then `enc`, `mac` or
    /// `alg`, `id`, `key`, each length-prefixed. An encoding change fails here, not silently in a tool.
    #[test]
    fn user_key_id_known_answers() {
        assert_eq!(key_id(&key_of(&fixture("accounts/pbkdf2.json")["userKey"])), "G93ysCnI0ywBDp8IPTowHA");
        let cose = fixture("crypto/cose-vectors.json");
        assert_eq!(key_id(&key_of(&cose["accounts"][0]["userKey"])), "Th8WTyJpPgZsUoxdrswGVA");
        assert_eq!(key_id(&key_of(&cose["accounts"][1]["userKey"])), "LcCjTBwGGk7PzPpGKFuqFw");
        let user = key_of(&cose["accounts"][1]["userKey"]);
        let marker = Marker::new(&user, MarkScheme::Bwss);
        let unlocked =
            Unlocked { keys: Keys { user, orgs: Default::default(), marker }, sync: json!({}), org_problems: vec![] };
        assert_eq!(unlocked.user_key_id(), "LcCjTBwGGk7PzPpGKFuqFw");
    }

    /// Counts Argon2id runs, delegating to the native runner.
    struct Counting(Cell<u32>);

    impl KdfRunner for Counting {
        async fn argon2id(&self, input: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError> {
            self.0.set(self.0.get() + 1);
            NativeArgon2.argon2id(input).await
        }
    }

    /// bwss `unlock` ("sync without account key"): no wrapped user key in either place stops before the KDF.
    #[test]
    fn missing_account_key_stops_before_the_kdf() {
        let acc = fixture("accounts/argon2id.json");
        let (email, password) = (acc["email"].as_str().unwrap(), acc["password"].as_str().unwrap());
        let params = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        let open = |sync: Value, runner: &Counting| {
            let password = Zeroizing::new(password.to_owned());
            block_on(open_sync(
                sync,
                email,
                password,
                params,
                runner,
                &AwsLcRsa,
                &Namespace::BWSS,
                &Organizations::None,
            ))
        };
        let runner = Counting(Cell::new(0));
        for sync in [json!({ "profile": { "id": "u" } }), json!({ "profile": { "key": "" }, "userDecryption": null })] {
            let err = open(sync, &runner).err().unwrap();
            assert!(matches!(&err, ProfileError::Api(ApiError::Protocol(_))), "{err:?}");
            assert_eq!(err.to_string(), "unexpected response: sync without account key");
        }
        assert_eq!(runner.0.get(), 0, "the KDF ran");
        // With the key, the same call runs the KDF once and unlocks.
        let unlocked = open(json!({ "profile": { "key": acc["profileKey"] } }), &runner).ok().unwrap();
        assert_eq!(runner.0.get(), 1);
        assert_eq!(unlocked.keys.user.to_bytes().to_vec(), STANDARD.decode(acc["userKey"].as_str().unwrap()).unwrap());
    }

    /// Loads what it holds; every write fails.
    struct Broken(Option<Vec<u8>>);

    impl Storage for Broken {
        async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>, PortError> {
            Ok(self.0.clone())
        }
        async fn save(&self, _key: &str, _data: &[u8]) -> Result<(), PortError> {
            Err(PortError("disk gone".into()))
        }
        async fn remove(&self, _key: &str) -> Result<(), PortError> {
            Err(PortError("disk gone".into()))
        }
    }

    #[test]
    fn device_id_is_stable() {
        let (storage, rng) = (MemStorage::default(), SeededRandom::new(1));
        let first = block_on(device_id(&storage, &rng)).unwrap();
        let parsed = uuid::Uuid::parse_str(&first).unwrap();
        assert_eq!(parsed.get_version_num(), 4);
        assert_eq!(first.as_bytes().get(14), Some(&b'4'), "{first}");
        assert_eq!(block_on(device_id(&storage, &SeededRandom::new(2))).unwrap(), first);
        assert_eq!(block_on(storage.load("device")).unwrap().unwrap(), first.as_bytes());
    }

    #[test]
    fn device_id_keeps_any_saved_text_and_replaces_a_blank_one() {
        // bwss keeps whatever non-blank id it saved (older ones were not UUIDs).
        let storage = MemStorage::default();
        block_on(storage.save("device", b" dev-1234\n")).unwrap();
        assert_eq!(block_on(device_id(&storage, &SeededRandom::new(1))).unwrap(), "dev-1234");
        for blank in [&b" \n"[..], &[0xff, 0xfe][..]] {
            block_on(storage.save("device", blank)).unwrap();
            let id = block_on(device_id(&storage, &SeededRandom::new(1))).unwrap();
            assert!(uuid::Uuid::parse_str(&id).is_ok(), "{id}");
        }
    }

    #[test]
    fn device_id_reports_a_failing_storage() {
        let err = block_on(device_id(&Broken(None), &SeededRandom::new(1))).unwrap_err();
        assert!(matches!(err, ProfileError::Port(_)), "{err:?}");
        assert_eq!(err.to_string(), "host port failed: disk gone");
        assert!(block_on(Broken(None).remove("device")).is_err());
        // A saved id needs no write.
        assert_eq!(block_on(device_id(&Broken(Some(b"dev-1".to_vec())), &SeededRandom::new(1))).unwrap(), "dev-1");
    }
}
