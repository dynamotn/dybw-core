use super::CryptoError;
use super::cose::{CoseAlgorithm, CoseKey, padded_key_bytes, parse_cose_key, unpad};
use crate::crypto::kdf::MasterKey;
use crate::ports::Random;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A Bitwarden symmetric key: legacy (AES-CBC and HMAC, EncString type 2) or COSE (type 7).
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SymmetricKey {
    Legacy(LegacyKey),
    Cose(CoseKey),
}

/// The payload of a legacy key. Not re-exported, with private fields: nothing outside this module can build one or
/// read the bytes. `CoseKey` is the same for the other variant.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LegacyKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl LegacyKey {
    pub(super) fn parts(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.enc, &self.mac)
    }
}

impl fmt::Debug for LegacyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyKey(<redacted>)")
    }
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
        SymmetricKey::Legacy(LegacyKey { enc, mac })
    }

    /// Exactly 64 bytes (AES key, then HMAC key) is a legacy key; longer input is a padded COSE key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if let Ok(bytes) = <&[u8; 64]>::try_from(bytes) {
            let (enc, mac) = bytes.split_at(32);
            let (mut e, mut m) = ([0; 32], [0; 32]);
            e.copy_from_slice(enc);
            m.copy_from_slice(mac);
            return Ok(Self::legacy(e, m));
        }
        if bytes.len() > 64 {
            return Ok(SymmetricKey::Cose(parse_cose_key(&unpad(bytes)?)?));
        }
        Err(CryptoError::Malformed)
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            SymmetricKey::Legacy(LegacyKey { enc, mac }) => {
                let mut v = Zeroizing::new(Vec::with_capacity(64));
                v.extend_from_slice(enc);
                v.extend_from_slice(mac);
                v
            }
            SymmetricKey::Cose(k) => padded_key_bytes(k),
        }
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

    /// bwss `SymmetricKey::derive`: a key of its own for `purpose` (`value-mark`, `queue`, `acl-confirm`,
    /// `vault-acl`), so nothing encrypted with this key can pass for data of that purpose.
    pub fn derive_bwss(&self, purpose: &str) -> SymmetricKey {
        let enc = self.expand_bwss(&format!("bwss {purpose} enc"));
        let mac = self.expand_bwss(&format!("bwss {purpose} mac"));
        Self::legacy(*enc, *mac)
    }

    /// HKDF-Expand for one block over bwss's PRK, `enc ‖ mac`. bwss has no COSE keys; a COSE key expands from its
    /// 32-byte key, as the plugin does.
    pub(super) fn expand_bwss(&self, info: &str) -> Zeroizing<[u8; 32]> {
        let legacy;
        let prk: &[u8] = match self {
            SymmetricKey::Legacy(_) => {
                legacy = self.to_bytes();
                &legacy
            }
            SymmetricKey::Cose(c) => c.secret(),
        };
        Zeroizing::new(hmac(prk, &[info.as_bytes(), &[1]]))
    }

    /// The plugin's `deriveSubKey`: HKDF-Expand over the MAC half of a legacy key, or over a COSE key.
    pub(super) fn expand_obsidian(&self, purpose: &str) -> Zeroizing<[u8; 32]> {
        let prk: &[u8] = match self {
            SymmetricKey::Legacy(k) => k.parts().1,
            SymmetricKey::Cose(c) => c.secret(),
        };
        Zeroizing::new(hmac(prk, &[b"obsidian-keychain-bitwarden:", purpose.as_bytes(), &[1]]))
    }

    pub fn generate_cose(alg: CoseAlgorithm, rng: &impl Random) -> Result<Self, CryptoError> {
        Ok(SymmetricKey::Cose(CoseKey::generate(alg, rng)?))
    }
}
