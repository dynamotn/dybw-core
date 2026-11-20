//! Local unlock protectors (ADR 0006): a copy of the user key wrapped by a key-encryption key (KEK) from a local
//! factor, either Argon2id over a secret (a PIN, the login password) or 32 bytes released by hardware (the Secure
//! Enclave). A protector is device state, never synced (data model §10), and bound to the profile's device id and a
//! machine fingerprint. The core is I/O-free: the host stores the blob, reads the binding and runs the KDF.
//!
//! The wrapping key is HKDF-SHA256 over the KEK, with the binding (each field length-prefixed, u32 big-endian) as
//! the salt and `dybw-unlock:<protector>` as the info: a blob whose binding or protector name was edited derives
//! another key and fails its MAC. The user key is wrapped as an authenticated EncString of type 2, as the master key
//! wraps it. Known answers in `vectors/crypto/protector.json`.

use super::opens_private_key;
use crate::crypto::{CryptoError, KdfParams, SymmetricKey};
use crate::ports::{Argon2Input, KdfRunner, PortError, Random};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use zeroize::Zeroizing;

/// The blob format this core reads and writes.
pub const VERSION: u32 = 1;
/// Failed unwraps before a protector is invalidated (ADR 0006: five failed PIN attempts).
pub const MAX_ATTEMPTS: u32 = 5;

/// The protectors of ADR 0006; the name is the HKDF purpose label's suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protector {
    Pin,
    Biometric,
    Login,
}

impl Protector {
    pub fn name(self) -> &'static str {
        match self {
            Protector::Pin => "pin",
            Protector::Biometric => "biometric",
            Protector::Login => "login",
        }
    }

    /// Whether the KEK comes from hardware (`biometric`); `pin` and `login` are Argon2id over a secret.
    fn hardware(self) -> bool {
        self == Protector::Biometric
    }
}

/// What binds a protector to this device: the profile's device identifier and the machine fingerprint
/// (`/etc/machine-id` or `IOPlatformUUID`), both read by the host. Neither may be empty.
#[derive(Debug, Clone, Copy)]
pub struct Binding<'a> {
    pub device_id: &'a str,
    pub machine: &'a str,
}

/// The local factor that unwraps a protector.
pub enum Kek {
    /// A secret (PIN, login password): Argon2id runs over it with the blob's parameters and salt.
    Secret(Zeroizing<Vec<u8>>),
    /// 32 bytes released by hardware (the Secure Enclave after Touch ID): no KDF.
    Hardware(Zeroizing<[u8; 32]>),
}

/// The local factor that wraps a new protector: a secret with its Argon2id parameters, or hardware bytes.
pub enum KekSource {
    Secret { secret: Zeroizing<Vec<u8>>, params: KdfParams },
    Hardware(Zeroizing<[u8; 32]>),
}

/// Why a protector was not written or did not unwrap. Messages name the problem, never a secret or key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtectorError {
    /// Not JSON, an unknown version, protector or KDF, an unknown field, a bad salt, an empty binding, or a wrapped
    /// key that is no type 2 EncString.
    #[error("the protector blob is unreadable or of an unknown version")]
    Format,
    /// Not Argon2id, or below ADR 0006's floors (64 MiB, 3 iterations, 1 lane), or above the KDF's upper bounds.
    #[error(
        "the protector's KDF parameters are below the floors (Argon2id, 64 MiB, 3 iterations, 1 lane) or out of range"
    )]
    WeakKdf,
    /// The blob belongs to another device or machine, or the binding to wrap with is empty: ignore and report it.
    #[error("the protector is bound to another device or machine")]
    Binding,
    /// `MAX_ATTEMPTS` failed unwraps: only the master password unlocks now, and re-enrolling needs it too.
    #[error("the protector is invalidated after too many failed attempts")]
    Invalidated,
    /// A secret for a hardware protector, or hardware bytes for a secret one.
    #[error("the unlock factor is not of this protector's kind")]
    Kek,
    /// The wrapped key fails its MAC: a wrong PIN or password (or an edited blob). Counts an attempt.
    #[error("wrong PIN or password for this protector")]
    Wrong,
    /// The key unwrapped but no longer opens the account (a key rotation, another account): delete the protector.
    #[error("the protector's key no longer opens this account")]
    Stale,
    /// A host port failed (the KDF, randomness); the text never carries a secret.
    #[error("{0}")]
    Port(String),
}

impl ProtectorError {
    /// A stable code for hosts and the known-answer vectors.
    pub fn code(&self) -> &'static str {
        match self {
            ProtectorError::Format => "format",
            ProtectorError::WeakKdf => "weak-kdf",
            ProtectorError::Binding => "binding",
            ProtectorError::Invalidated => "invalidated",
            ProtectorError::Kek => "kek",
            ProtectorError::Wrong => "wrong",
            ProtectorError::Stale => "stale",
            ProtectorError::Port(_) => "port",
        }
    }
}

impl From<PortError> for ProtectorError {
    fn from(e: PortError) -> Self {
        ProtectorError::Port(CryptoError::from(e).to_string())
    }
}

/// How the KEK is derived, as stored: `memory` in MiB, as Bitwarden's KDF settings; `salt` 32 bytes, base64.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum BlobKdf {
    Argon2id { iterations: u32, memory: u32, parallelism: u32, salt: String },
    // A struct variant, not a unit one, so `deny_unknown_fields` refuses extra keys here too.
    Hardware {},
}

/// A protector as the host stores it (device state, 0600 on disk, or memory only): JSON with no secret in clear.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtectorBlob {
    version: u32,
    protector: Protector,
    device_id: String,
    machine: String,
    kdf: BlobKdf,
    wrapped_key: String,
    attempts: u32,
}

/// ADR 0006's floors, and the KDF's own upper bounds so an edited blob cannot pin the CPU or memory.
/// The arguments are Argon2id's (a protector has no other KDF).
fn floors(iterations: u32, memory_mib: u32, parallelism: u32) -> Result<(), ProtectorError> {
    let params = KdfParams::Argon2id { iterations, memory_mib, parallelism };
    if params.validate().is_ok() && params.meets_floors() { Ok(()) } else { Err(ProtectorError::WeakKdf) }
}

/// Argon2id's iterations, memory in MiB, lanes and salt.
type Argon = (u32, u32, u32, [u8; 32]);

impl ProtectorBlob {
    /// Parses a stored blob and checks its version, binding fields and floors.
    pub fn from_json(raw: &[u8]) -> Result<Self, ProtectorError> {
        let blob: Self = serde_json::from_slice(raw).map_err(|_| ProtectorError::Format)?;
        blob.check()?;
        Ok(blob)
    }

    pub fn to_json(&self) -> Vec<u8> {
        // Strings and numbers only: serializing cannot fail.
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn protector(&self) -> Protector {
        self.protector
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// `MAX_ATTEMPTS` failed unwraps: the host deletes the blob and asks for the master password.
    pub fn invalidated(&self) -> bool {
        self.attempts >= MAX_ATTEMPTS
    }

    /// Counts a failed attempt; `unwrap` calls it on `Wrong`. The host persists the blob afterwards.
    pub fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
    }

    /// Clears the count; `unwrap` calls it on success.
    pub fn reset_attempts(&mut self) {
        self.attempts = 0;
    }

    /// The version, binding fields, the KDF of the protector's kind and the floors; answers the Argon2id parameters
    /// and salt, `None` for a hardware KEK.
    fn check(&self) -> Result<Option<Argon>, ProtectorError> {
        let hardware = matches!(self.kdf, BlobKdf::Hardware {});
        if self.version != VERSION
            || self.device_id.is_empty()
            || self.machine.is_empty()
            || hardware != self.protector.hardware()
        {
            return Err(ProtectorError::Format);
        }
        let BlobKdf::Argon2id { iterations, memory, parallelism, ref salt } = self.kdf else { return Ok(None) };
        floors(iterations, memory, parallelism)?;
        let salt = B64.decode(salt).ok().and_then(|s| <[u8; 32]>::try_from(s).ok()).ok_or(ProtectorError::Format)?;
        Ok(Some((iterations, memory, parallelism, salt)))
    }

    /// The wrapping key, from `kek` and this blob's KDF (`argon`, as `check` answers it), binding and protector name.
    async fn wrapping_key(
        &self,
        kek: &Kek,
        argon: Option<Argon>,
        runner: &impl KdfRunner,
    ) -> Result<SymmetricKey, ProtectorError> {
        let ikm = match (kek, argon) {
            (Kek::Secret(secret), Some((iterations, memory_mib, parallelism, salt))) => {
                let input = Argon2Input {
                    password: secret.clone(),
                    salt,
                    iterations,
                    memory_kib: memory_mib * 1024,
                    parallelism,
                };
                runner.argon2id(input).await?
            }
            (Kek::Hardware(bytes), None) => bytes.clone(),
            _ => return Err(ProtectorError::Kek),
        };
        let mut salt = Vec::new();
        for field in [&self.device_id, &self.machine] {
            salt.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
            salt.extend_from_slice(field.as_bytes());
        }
        let info = format!("dybw-unlock:{}", self.protector.name());
        Ok(SymmetricKey::hkdf(&salt, ikm.as_ref(), info.as_bytes()))
    }
}

/// Wraps `user` as a new `protector` bound to `binding`. `biometric` takes hardware bytes, `pin` and `login` a secret
/// (else `Kek`), whose parameters must meet the floors; its salt comes from `rng`. The caller enrolls only after the master password unlocked `user` on this device (ADR 0006).
pub async fn wrap(
    user: &SymmetricKey,
    protector: Protector,
    source: KekSource,
    binding: Binding<'_>,
    runner: &impl KdfRunner,
    rng: &impl Random,
) -> Result<ProtectorBlob, ProtectorError> {
    if binding.device_id.is_empty() || binding.machine.is_empty() {
        return Err(ProtectorError::Binding);
    }
    if matches!(source, KekSource::Hardware(_)) != protector.hardware() {
        return Err(ProtectorError::Kek);
    }
    let (kdf, kek, argon) = match source {
        KekSource::Secret { secret, params } => {
            let KdfParams::Argon2id { iterations, memory_mib, parallelism } = params else {
                return Err(ProtectorError::WeakKdf);
            };
            floors(iterations, memory_mib, parallelism)?;
            let mut salt = [0u8; 32];
            rng.fill(&mut salt)?;
            let kdf = BlobKdf::Argon2id { iterations, memory: memory_mib, parallelism, salt: B64.encode(salt) };
            (kdf, Kek::Secret(secret), Some((iterations, memory_mib, parallelism, salt)))
        }
        KekSource::Hardware(bytes) => (BlobKdf::Hardware {}, Kek::Hardware(bytes), None),
    };
    let mut blob = ProtectorBlob {
        version: VERSION,
        protector,
        device_id: binding.device_id.to_owned(),
        machine: binding.machine.to_owned(),
        kdf,
        wrapped_key: String::new(),
        attempts: 0,
    };
    let key = blob.wrapping_key(&kek, argon, runner).await?;
    blob.wrapped_key = key.encrypt(&user.to_bytes(), rng).map_err(|e| ProtectorError::Port(e.to_string()))?;
    Ok(blob)
}

/// Unwraps the user key, in this order: the blob's format and floors, the binding (a copied blob reports `Binding`
/// whatever its count), the attempt count, the KEK's kind (no KDF runs before it), the MAC (`Wrong` counts an attempt in `blob`), then the master password's check against
/// the cached `sync`: the key must open the account's private key, else `Stale`. Success resets the count. The host
/// persists `blob` after every call, deletes it on `Stale` or once `invalidated()`, and ignores and reports it on
/// `Binding`.
pub async fn unwrap(
    blob: &mut ProtectorBlob,
    kek: &Kek,
    binding: Binding<'_>,
    sync: &Value,
    runner: &impl KdfRunner,
) -> Result<SymmetricKey, ProtectorError> {
    let argon = blob.check()?;
    if blob.device_id != binding.device_id || blob.machine != binding.machine {
        return Err(ProtectorError::Binding);
    }
    if blob.invalidated() {
        return Err(ProtectorError::Invalidated);
    }
    let key = blob.wrapping_key(kek, argon, runner).await?;
    let user = match key.decrypt_key(&blob.wrapped_key) {
        Ok(user) => user,
        Err(CryptoError::BadMac) => {
            blob.record_failure();
            return Err(ProtectorError::Wrong);
        }
        Err(_) => return Err(ProtectorError::Format),
    };
    if !opens_private_key(sync, &user) {
        return Err(ProtectorError::Stale);
    }
    blob.reset_attempts();
    Ok(user)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
#[path = "protector_tests.rs"]
mod tests;
