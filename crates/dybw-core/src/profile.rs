//! A profile's session: unlock (prelogin, KDF, user key, private key, organization keys), device identity, lock.
//! Port of bwss `BitwardenBackend::unlock` and the plugin's `unlockUserKey` and `unlockOrganizationKeys`.

use crate::api::{ApiError, ApiKey, Client};
use crate::crypto::{CryptoError, Marker, SymmetricKey, derive_master_key};
use crate::ports::{Clock, Http, KdfRunner, PortError, Random, RsaOaep, Storage};
use crate::vault::{Keys, Namespace, OrgProblem, Organizations, unlock_organizations};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The storage key of the device identifier.
const DEVICE: &str = "device";
/// Domain separation for [`Unlocked::user_key_id`], so the id is no hash of the key used anywhere else.
const USER_KEY_ID_LABEL: &[u8] = b"dybw user-key-id v1\0";

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
    /// SHA-256 over a fixed label and the key's bytes, cut to 128 bits: it cannot be turned back into the key.
    pub fn user_key_id(&self) -> String {
        let digest = Sha256::new().chain_update(USER_KEY_ID_LABEL).chain_update(&*self.keys.user.to_bytes()).finalize();
        B64.encode(digest.get(..16).unwrap_or_default())
    }

    /// Drops every key, which wipes it.
    pub fn lock(self) {
        drop(self);
    }
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
/// never leaves this process. `profile.key` is a type 2 string under the stretched master key holding a legacy or
/// a COSE user key (XAES-256-GCM or XChaCha20-Poly1305); a type 7 one is refused with `WrongKey`, as the SDK does
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
    let profile = sync.get("profile").unwrap_or(&Value::Null);
    let protected = profile.get("key").and_then(Value::as_str).unwrap_or_default();
    let master = derive_master_key(&password, email, params, kdf).await?;
    drop(password);
    let stretched = SymmetricKey::stretch(&master);
    drop(master);
    let user = stretched.decrypt_key(protected).map_err(|e| match e {
        CryptoError::BadMac => ProfileError::WrongPassword,
        e => ProfileError::Crypto(e),
    })?;
    drop(stretched);
    let (orgs, org_problems) = unlock_organizations(profile, &user, rsa, allowed).await;
    let marker = Marker::new(&user, ns.marks);
    Ok(Unlocked { keys: Keys { user, orgs, marker }, sync, org_problems })
}

#[cfg(all(test, feature = "testing"))]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::testing::{MemStorage, SeededRandom, block_on};

    struct Broken;

    impl Storage for Broken {
        async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>, PortError> {
            Ok(None)
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
        let err = block_on(device_id(&Broken, &SeededRandom::new(1))).unwrap_err();
        assert!(matches!(err, ProfileError::Port(_)), "{err:?}");
        assert_eq!(err.to_string(), "host port failed: disk gone");
        assert!(block_on(Broken.remove("device")).is_err());
    }
}
