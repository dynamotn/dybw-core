//! A profile's session: unlock (prelogin, KDF, user key, private key, organization keys), device identity, lock.
//! Port of bwss `BitwardenBackend::unlock` and the plugin's `unlockUserKey` and `unlockOrganizationKeys`.

use crate::api::{ApiError, ApiKey, Client};
use crate::crypto::{CryptoError, KdfParams, Marker, SymmetricKey, derive_master_key};
use crate::ports::{Clock, Http, KdfRunner, PortError, Random, RsaOaep, Storage};
use crate::vault::{Keys, Namespace, OrgProblem, Organizations, unlock_organizations};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::Value;
use zeroize::Zeroizing;

/// The storage key of the device identifier.
const DEVICE: &str = "device";
/// Domain separation for [`Unlocked::user_key_id`], so the id is no hash of the key used anywhere else.
const USER_KEY_ID_LABEL: &[u8] = b"dybw user-key-id v1";

/// The storage key of the KDF pin (ADR 0017).
const KDF_PIN: &str = "kdf-pin";
/// The names of the KDF's two sources in messages (ADR 0022).
const FROM_UNLOCK_DATA: &str = "KDF from sync unlock data";
const FROM_PRELOGIN: &str = "KDF from prelogin";

/// The KDF a device accepted for a profile, and the identity origin it came from (ADR 0017). Device state, no
/// secret; a pin for another origin is ignored and replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfPin {
    pub params: KdfParams,
    pub origin: String,
}

/// The pin as stored: flat JSON, `kdf` the Bitwarden KDF type (0 PBKDF2, 1 Argon2id).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredPin {
    kdf: u32,
    iterations: u32,
    memory: u32,
    parallelism: u32,
    origin: String,
}

impl StoredPin {
    fn of(pin: &KdfPin) -> Self {
        let origin = pin.origin.clone();
        match pin.params {
            KdfParams::Pbkdf2 { iterations } => StoredPin { kdf: 0, iterations, memory: 0, parallelism: 0, origin },
            KdfParams::Argon2id { iterations, memory_mib, parallelism } => {
                StoredPin { kdf: 1, iterations, memory: memory_mib, parallelism, origin }
            }
        }
    }

    fn into_pin(self) -> Option<KdfPin> {
        let StoredPin { kdf, iterations, memory: memory_mib, parallelism, origin } = self;
        let params = match kdf {
            0 => KdfParams::Pbkdf2 { iterations },
            1 => KdfParams::Argon2id { iterations, memory_mib, parallelism },
            _ => return None,
        };
        Some(KdfPin { params, origin })
    }
}

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
    /// The KDF is weaker than the pinned one; raised before the KDF runs (ADR 0017).
    #[error(
        "the KDF is weaker than the one pinned on this device (pinned {pinned:?}, offered {offered:?}): check it in \
         the web vault, then confirm it on this device"
    )]
    KdfWeakened { pinned: KdfParams, offered: KdfParams },
    /// No well-formed `masterPasswordUnlock` and no `profile.key` (ADR 0022).
    #[error("incomplete unlock data: no well-formed KDF, salt and key in the sync unlock data, and no profile key")]
    IncompleteUnlockData,
}

/// Something the user should know about a successful unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockWarning {
    /// The KDF the unlock ran is below ADR 0017's floors.
    KdfBelowFloor(KdfParams),
}

/// An unlocked profile. No `Clone` and no `Debug`: the keys are wiped when it is dropped or locked.
pub struct Unlocked {
    pub keys: Keys,
    pub sync: Value,
    pub org_problems: Vec<OrgProblem>,
    pub warnings: Vec<UnlockWarning>,
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

/// Source 1 of ADR 0022: `userDecryption.masterPasswordUnlock`, parsed as the SDK does (sdk-internal 3d16437
/// bitwarden-core/src/key_management/master_password.rs): the KDF, the wrapped user key and the salt, all present.
/// An unknown KDF type, or a missing or zero Argon2id `memory` or `parallelism`, is malformed. `None` for a
/// partial or malformed object.
fn unlock_data(sync: &Value) -> Option<(KdfParams, &str, &str)> {
    let data = sync.pointer("/userDecryption/masterPasswordUnlock")?;
    let text = |k: &str| data.get(k).and_then(Value::as_str).filter(|s| !s.is_empty());
    let kdf = data.get("kdf")?;
    let num = |k: &str| kdf.get(k).and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok());
    let nonzero = |k: &str| num(k).filter(|v| *v != 0);
    let iterations = num("iterations")?;
    let params = match num("kdfType")? {
        0 => KdfParams::Pbkdf2 { iterations },
        1 => KdfParams::Argon2id { iterations, memory_mib: nonzero("memory")?, parallelism: nonzero("parallelism")? },
        _ => return None,
    };
    Some((params, text("masterKeyEncryptedUserKey")?, text("salt")?))
}

async fn load_pin(storage: &impl Storage) -> Result<Option<KdfPin>, ProfileError> {
    let Some(raw) = storage.load(KDF_PIN).await? else { return Ok(None) };
    // A damaged pin is no pin to trust, and no reason to drop it silently.
    let pin = serde_json::from_slice::<StoredPin>(&raw).ok().and_then(StoredPin::into_pin);
    Ok(Some(pin.ok_or_else(|| PortError("the KDF pin is unreadable".into()))?))
}

async fn save_pin(storage: &impl Storage, params: KdfParams, origin: &str) -> Result<(), ProfileError> {
    let pin = KdfPin { params, origin: origin.to_owned() };
    // A plain struct of numbers and text always serializes.
    let raw = serde_json::to_vec(&StoredPin::of(&pin)).unwrap_or_default();
    Ok(storage.save(KDF_PIN, &raw).await?)
}

/// The user's confirmation, on this device, of a weaker KDF (ADR 0017): the pin becomes `params` for `origin`.
pub async fn accept_kdf(storage: &impl Storage, params: KdfParams, origin: &str) -> Result<(), ProfileError> {
    save_pin(storage, params, origin).await
}

/// bwss `BitwardenBackend::unlock`: the API-key login and `/sync` first, then the KDF, so the password never leaves
/// this process. One source per unlock, never mixed (ADR 0022): `masterPasswordUnlock` when its KDF, wrapped user key
/// and salt are all well formed, else `profile.key` with the email as salt and the KDF from prelogin (called only
/// then); neither gives `IncompleteUnlockData`. The KDF's bounds, then ADR 0017's pin, are checked before it runs;
/// the pin is written only once the user key opened: a new one (none, or for another origin), or a stronger one.
/// Below the floors the unlock succeeds with a warning, and the pin is still written.
/// The key is a type 2 string under the stretched master key holding a legacy or a COSE user key (XAES-256-GCM or
/// XChaCha20-Poly1305); a type 7 one is refused with `WrongKey`, as the SDK does
/// (bitwarden-crypto/src/keys/master_key.rs:176-200 `decrypt_user_key`). Organization keys follow the opt-in.
#[expect(clippy::too_many_arguments, reason = "the brief's signature: each port is the host's")]
pub async fn unlock<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    storage: &impl Storage,
    key: &ApiKey,
    email: &str,
    password: Zeroizing<String>,
    kdf: &impl KdfRunner,
    rsa: &impl RsaOaep,
    ns: &Namespace,
    allowed: &Organizations,
) -> Result<Unlocked, ProfileError> {
    client.login(key).await?;
    let sync = client.sync().await?;
    let (source, params, protected, salt) = match unlock_data(&sync) {
        Some((params, protected, salt)) => (FROM_UNLOCK_DATA, params, protected.to_owned(), salt.to_owned()),
        None => {
            let protected = sync.pointer("/profile/key").and_then(Value::as_str).filter(|s| !s.is_empty());
            let protected = protected.ok_or(ProfileError::IncompleteUnlockData)?.to_owned();
            (FROM_PRELOGIN, client.prelogin(email).await?, protected, email.to_owned())
        }
    };
    if let Err(CryptoError::Kdf(why)) = params.validate() {
        return Err(CryptoError::Kdf(format!("{source}: {why}")).into());
    }
    let pinned = load_pin(storage).await?.filter(|p| p.origin == key.origin).map(|p| p.params);
    if let Some(pinned) = pinned.filter(|p| params.weaker_than(p)) {
        return Err(ProfileError::KdfWeakened { pinned, offered: params });
    }
    let master = derive_master_key(&password, &salt, params, kdf).await?;
    drop(password);
    let stretched = SymmetricKey::stretch(&master);
    drop(master);
    let user = stretched.decrypt_key(&protected).map_err(|e| match e {
        CryptoError::BadMac => ProfileError::WrongPassword,
        e => ProfileError::Crypto(e),
    })?;
    drop(stretched);
    if pinned != Some(params) {
        save_pin(storage, params, &key.origin).await?;
    }
    let warnings = if params.meets_floors() { vec![] } else { vec![UnlockWarning::KdfBelowFloor(params)] };
    let profile = sync.get("profile").unwrap_or(&Value::Null);
    let (orgs, org_problems) = unlock_organizations(profile, &user, rsa, allowed).await;
    let marker = Marker::new(&user, ns.marks);
    Ok(Unlocked { keys: Keys { user, orgs, marker }, sync, org_problems, warnings })
}

#[cfg(all(test, feature = "testing"))]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use super::*;
    use crate::crypto::MarkScheme;
    use crate::testing::{MemStorage, SeededRandom, block_on};
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;

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
        let unlocked = Unlocked {
            keys: Keys { user, orgs: Default::default(), marker },
            sync: json!({}),
            org_problems: vec![],
            warnings: vec![],
        };
        assert_eq!(unlocked.user_key_id(), "LcCjTBwGGk7PzPpGKFuqFw");
    }

    /// ADR 0022 source 1: the three members together, parsed as the SDK does; anything less is `None`.
    #[test]
    fn unlock_data_needs_every_member() {
        let good = json!({ "userDecryption": { "masterPasswordUnlock": {
            "kdf": { "kdfType": 1, "iterations": 3, "memory": 64, "parallelism": 4 },
            "masterKeyEncryptedUserKey": "k", "salt": "s",
        } } });
        let params = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        assert_eq!(unlock_data(&good), Some((params, "k", "s")));
        let pbkdf2 = json!({ "userDecryption": { "masterPasswordUnlock": {
            "kdf": { "kdfType": 0, "iterations": 600000 }, "masterKeyEncryptedUserKey": "k", "salt": "s",
        } } });
        assert_eq!(unlock_data(&pbkdf2).map(|d| d.0), Some(KdfParams::Pbkdf2 { iterations: 600_000 }));
        let broken = |path: &str, value: Value| {
            let mut v = good.clone();
            *v.pointer_mut(&format!("/userDecryption/masterPasswordUnlock{path}")).unwrap() = value;
            unlock_data(&v).is_some()
        };
        let cases = [
            ("/kdf/kdfType", json!(2)),
            ("/kdf/kdfType", json!(null)),
            ("/kdf/iterations", json!(null)),
            ("/kdf/memory", json!(0)),
            ("/kdf/memory", json!(null)),
            ("/kdf/parallelism", json!(0)),
            ("/kdf/parallelism", json!(null)),
            ("/kdf/memory", json!(u64::MAX)),
            ("/kdf", json!(null)),
            ("/masterKeyEncryptedUserKey", json!("")),
            ("/salt", json!(null)),
        ];
        for (path, value) in cases {
            assert!(!broken(path, value.clone()), "{path} {value}");
        }
        assert_eq!(unlock_data(&json!({ "userDecryption": null })), None);
        assert_eq!(unlock_data(&json!({})), None);
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

    #[test]
    fn pin_storage_round_trips_and_reports_damage() {
        let storage = MemStorage::default();
        assert_eq!(block_on(load_pin(&storage)).unwrap(), None);
        let params = KdfParams::Pbkdf2 { iterations: 600_000 };
        block_on(accept_kdf(&storage, params, "https://id.invalid")).unwrap();
        let pin = block_on(load_pin(&storage)).unwrap().unwrap();
        assert_eq!(pin, KdfPin { params, origin: "https://id.invalid".into() });
        let argon = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        block_on(accept_kdf(&storage, argon, "o")).unwrap();
        assert_eq!(block_on(load_pin(&storage)).unwrap().unwrap().params, argon);
        let unknown = br#"{"kdf":7,"iterations":1,"memory":0,"parallelism":0,"origin":"o"}"#;
        block_on(storage.save("kdf-pin", unknown)).unwrap();
        assert!(block_on(load_pin(&storage)).is_err());
        block_on(storage.save("kdf-pin", b"{")).unwrap();
        let err = block_on(load_pin(&storage)).unwrap_err();
        assert_eq!(err.to_string(), "host port failed: the KDF pin is unreadable");
        let err = block_on(accept_kdf(&Broken(None), params, "o")).unwrap_err();
        assert_eq!(err.to_string(), "host port failed: disk gone");
    }
}
