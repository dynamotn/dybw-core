//! What a session call rejects with: one JSON object `{"code", "message", …fields}`, so JS branches on `code` and
//! shows `message`, the core's text. No field carries a value, a key or ciphertext: only codes, numbers, KDF
//! parameters and origins.
//!
//! | `code` | fields |
//! |---|---|
//! | `locked`, `busy` | |
//! | `wrong-password` | |
//! | `kdf-weakened` | `pinned`, `offered` (KDFs as `acceptKdf` takes them), `source` (`"sync-unlock-data"` or `"prelogin"`), `origin` (identity origin) |
//! | `kdf-pin-unreadable` | |
//! | `security-downgrade` | `seen`, `offered` (versions) |
//! | `security-state` | `fault` (`"missing"`, `"invalid"` or `"stored-unreadable"`) |
//! | `origin-not-acknowledged` | `origin` (identity origin, for `acknowledgeOrigin`) |
//! | `wrong-origin` | |
//! | `mass-clear` | `clears`, `base` (counts) |
//! | `api` | `status`, only for an HTTP error |
//! | `port` | |
//! | `invalid` | |

use dybw_core::api::ApiError;
use dybw_core::crypto::{CryptoError, KdfParams};
use dybw_core::ports::PortError;
use dybw_core::profile::{KdfSource, ProfileError, SecurityFault};
use dybw_core::sync::SyncError;
use serde_json::{Map, Value, json};

/// Every key needs the keys, and no call has them: the session is locked.
pub const LOCKED: &str = "locked";
/// Another call has the keys out.
pub const BUSY: &str = "busy";
/// A rejected input: the JSON, the arguments, the server URL, the device info, or data the core cannot read.
pub const INVALID: &str = "invalid";
pub const WRONG_PASSWORD: &str = "wrong-password";
pub const KDF_WEAKENED: &str = "kdf-weakened";
pub const KDF_PIN_UNREADABLE: &str = "kdf-pin-unreadable";
pub const SECURITY_DOWNGRADE: &str = "security-downgrade";
pub const SECURITY_STATE: &str = "security-state";
pub const ORIGIN_NOT_ACKNOWLEDGED: &str = "origin-not-acknowledged";
pub const WRONG_ORIGIN: &str = "wrong-origin";
pub const MASS_CLEAR: &str = "mass-clear";
pub const API: &str = "api";
pub const PORT: &str = "port";

#[derive(Debug, Clone, PartialEq)]
pub struct Error(Map<String, Value>);

impl Error {
    pub fn new(code: &str, message: impl ToString) -> Self {
        let mut m = Map::new();
        m.insert("code".into(), code.into());
        m.insert("message".into(), message.to_string().into());
        Error(m)
    }

    fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }

    pub fn locked() -> Self {
        Error::new(LOCKED, "Bitwarden is locked")
    }

    pub fn busy() -> Self {
        Error::new(BUSY, "another call is using the keys")
    }

    pub fn invalid(message: impl ToString) -> Self {
        Error::new(INVALID, message)
    }

    pub fn code(&self) -> &str {
        self.0.get("code").and_then(Value::as_str).unwrap_or_default()
    }

    pub fn message(&self) -> &str {
        self.0.get("message").and_then(Value::as_str).unwrap_or_default()
    }

    pub fn field(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// The identity origin a weakened KDF is accepted for (`acceptKdf(offered, origin)`); other codes unchanged.
    pub(crate) fn at(self, origin: &str) -> Self {
        if self.code() == KDF_WEAKENED { self.with("origin", origin) } else { self }
    }
}

/// The JSON text JS receives.
impl From<Error> for String {
    fn from(e: Error) -> String {
        Value::Object(e.0).to_string()
    }
}

/// KDF parameters as `acceptKdf` takes them.
pub(crate) fn kdf_json(p: KdfParams) -> Value {
    match p {
        KdfParams::Pbkdf2 { iterations } => json!({ "type": "pbkdf2", "iterations": iterations }),
        KdfParams::Argon2id { iterations, memory_mib, parallelism } => {
            json!({ "type": "argon2id", "iterations": iterations, "memory": memory_mib, "parallelism": parallelism })
        }
    }
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        match e {
            ApiError::Http { status, .. } => Error::new(API, &e).with("status", status),
            ApiError::OriginNotAcknowledged { ref origin } => {
                Error::new(ORIGIN_NOT_ACKNOWLEDGED, &e).with("origin", origin.as_str())
            }
            ApiError::WrongOrigin => Error::new(WRONG_ORIGIN, e),
            ApiError::Invalid(_) => Error::invalid(e),
            _ => Error::new(API, e),
        }
    }
}

impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::Port(_) => Error::new(PORT, e),
            _ => Error::invalid(e),
        }
    }
}

impl From<PortError> for Error {
    fn from(e: PortError) -> Self {
        Error::new(PORT, e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::invalid(e)
    }
}

impl From<ProfileError> for Error {
    fn from(e: ProfileError) -> Self {
        let message = e.to_string();
        match e {
            ProfileError::Api(e) => e.into(),
            ProfileError::Crypto(e) => e.into(),
            ProfileError::Port(_) => Error::new(PORT, message),
            ProfileError::WrongPassword => Error::new(WRONG_PASSWORD, message),
            ProfileError::KdfWeakened { pinned, offered, kdf_source } => {
                let source = match kdf_source {
                    KdfSource::SyncUnlockData => "sync-unlock-data",
                    KdfSource::Prelogin => "prelogin",
                };
                Error::new(KDF_WEAKENED, message)
                    .with("pinned", kdf_json(pinned))
                    .with("offered", kdf_json(offered))
                    .with("source", source)
            }
            ProfileError::KdfPinUnreadable => Error::new(KDF_PIN_UNREADABLE, message),
            ProfileError::IncompleteUnlockData => Error::invalid(message),
            ProfileError::SecurityDowngrade { seen, offered } => {
                Error::new(SECURITY_DOWNGRADE, message).with("seen", seen).with("offered", offered)
            }
            ProfileError::SecurityState(fault) => {
                let fault = match fault {
                    SecurityFault::Missing => "missing",
                    SecurityFault::Invalid => "invalid",
                    SecurityFault::StoredUnreadable => "stored-unreadable",
                };
                Error::new(SECURITY_STATE, message).with("fault", fault)
            }
        }
    }
}

impl From<SyncError> for Error {
    fn from(e: SyncError) -> Self {
        match e {
            SyncError::Api(e) => e.into(),
            SyncError::MassClear { clears, base } => {
                Error::new(MASS_CLEAR, &e).with("clears", clears).with("base", base)
            }
            // A sync stopped by `lock`: the same code as any call after it, with the sync's own text.
            SyncError::Cancelled => Error::new(LOCKED, e),
        }
    }
}
