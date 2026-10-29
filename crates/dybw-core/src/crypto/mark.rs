//! Value marks: a keyed fingerprint of a stored value, so a tool notices a changed value without keeping it or a
//! plain (brute-forceable) hash of it. Both tools' schemes, byte for byte, since device state carries them over.

use super::key::{SymmetricKey, hmac};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkScheme {
    /// bwss `value_mark` under `derive("value-mark")`.
    Bwss,
    /// The plugin's `ValueFingerprinter` (`deriveSubKey("value-fingerprint")`).
    Obsidian,
}

/// Marks values under a key derived from the user key. Wiped on drop, no `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Marker {
    key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for Marker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Marker(<redacted>)")
    }
}

impl Marker {
    pub fn new(user: &SymmetricKey, scheme: MarkScheme) -> Marker {
        let key = match scheme {
            MarkScheme::Bwss => user.expand_bwss("bwss value-mark mac"), // the MAC half of derive_bwss
            MarkScheme::Obsidian => user.expand_obsidian("value-fingerprint"),
        };
        Marker { key }
    }

    /// HMAC-SHA256 of `id ‖ 0x00 ‖ text`: two items holding the same value get different marks.
    pub fn mark(&self, id: &str, text: &str) -> [u8; 32] {
        hmac(self.key.as_ref(), &[id.as_bytes(), &[0], text.as_bytes()])
    }

    /// The mark in base64, as the plugin stores it.
    pub fn mark_b64(&self, id: &str, text: &str) -> String {
        B64.encode(self.mark(id, text))
    }
}
