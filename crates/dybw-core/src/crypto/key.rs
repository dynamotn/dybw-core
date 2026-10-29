use super::CryptoError;
use crate::crypto::kdf::MasterKey;
use crate::ports::Random;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A Bitwarden symmetric key. Task 3 adds the COSE variant.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SymmetricKey {
    Legacy { enc: [u8; 32], mac: [u8; 32] },
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

/// A key owned or borrowed, so an item key never needs `Clone`.
pub enum KeyRef<'k> {
    Own(SymmetricKey),
    Owner(&'k SymmetricKey),
}

impl Deref for KeyRef<'_> {
    type Target = SymmetricKey;
    fn deref(&self) -> &SymmetricKey {
        match self {
            KeyRef::Own(k) => k,
            KeyRef::Owner(k) => k,
        }
    }
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
pub(super) fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

impl SymmetricKey {
    pub(super) fn legacy(enc: [u8; 32], mac: [u8; 32]) -> Self {
        SymmetricKey::Legacy { enc, mac }
    }

    /// Exactly 64 bytes (AES key, then HMAC key) is a legacy key; Task 3 accepts a COSE key for longer input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: &[u8; 64] = bytes.try_into().map_err(|_| CryptoError::Malformed)?;
        let (enc, mac) = bytes.split_at(32);
        let mut key = Self::legacy([0; 32], [0; 32]);
        let SymmetricKey::Legacy { enc: e, mac: m } = &mut key;
        e.copy_from_slice(enc);
        m.copy_from_slice(mac);
        Ok(key)
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let SymmetricKey::Legacy { enc, mac } = self;
        let mut v = Zeroizing::new(Vec::with_capacity(64));
        v.extend_from_slice(enc);
        v.extend_from_slice(mac);
        v
    }

    /// Turns the master key into the key that protects the user key (HKDF-Expand `enc` and `mac`).
    pub fn stretch(master: &MasterKey) -> Self {
        let expand = |info: &[u8]| Zeroizing::new(hmac(master.as_ref(), &[info, &[1u8]]));
        Self::legacy(*expand(b"enc"), *expand(b"mac"))
    }

    pub fn generate(rng: &impl Random) -> Result<Self, CryptoError> {
        let mut b = Zeroizing::new([0u8; 64]);
        rng.fill(b.as_mut())?;
        Self::from_bytes(b.as_ref())
    }

    pub(super) fn parts(&self) -> (&[u8; 32], &[u8; 32]) {
        let SymmetricKey::Legacy { enc, mac } = self;
        (enc, mac)
    }
}
