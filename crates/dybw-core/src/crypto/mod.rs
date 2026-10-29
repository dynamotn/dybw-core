//! Bitwarden client-side cryptography: keys, EncString types 2 and 7, and the KDFs.

mod aead;
mod cbor;
mod cose;
mod enc_string;
mod kdf;
mod key;

pub use cose::{ContentFormat, CoseAlgorithm};
#[cfg(feature = "native")]
pub use kdf::NativeArgon2;
pub use kdf::{KdfParams, MasterKey, derive_master_key, hash_master_password};
pub use key::{KeyRef, SymmetricKey};

/// Why a key could not be derived or a value could not be opened. Messages name the problem, never the data.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("malformed encrypted string or key")]
    Malformed,
    #[error("MAC verification failed (wrong key or tampered data)")]
    BadMac,
    #[error("decryption failed")]
    Decrypt,
    #[error("KDF failed or parameters out of range: {0}")]
    Kdf(String),
    #[error("unsupported encryption type {0}")]
    UnsupportedType(u8),
    #[error("wrong key for this value")]
    WrongKey,
    #[error("host port failed: {0}")]
    Port(String),
}

impl From<crate::ports::PortError> for CryptoError {
    fn from(e: crate::ports::PortError) -> Self {
        CryptoError::Port(e.0)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests;

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod cose_tests;
