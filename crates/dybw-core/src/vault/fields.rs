//! Custom-field primitives (port of bwss `src/bw/fields.rs` and `items.rs` `item_key`): field names are decrypted
//! without touching values, and one value at a time, so secrets are decrypted only when asked for.

use crate::crypto::{CryptoError, KeyRef, SymmetricKey};
use serde_json::Value;
use zeroize::Zeroizing;

/// What the first `{ns}:location` or `{ns}:encoding` field says, compared after trimming (data model §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// No field, or a value blank after trimming.
    Absent,
    /// The one known value.
    Set,
    /// Any other value.
    Unknown,
}

impl Mark {
    pub fn classify(value: Option<&str>, known: &str) -> Mark {
        match value.map(str::trim) {
            None | Some("") => Mark::Absent,
            Some(v) if v == known => Mark::Set,
            Some(_) => Mark::Unknown,
        }
    }
}

fn field_array(cipher: &Value) -> &[Value] {
    cipher.get("fields").and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// Decrypts the name of every field, in order; a `null` name is `None`. Non-UTF-8 is an error (Review Focus 3).
pub fn field_names(cipher: &Value, key: &SymmetricKey) -> Result<Vec<Option<String>>, CryptoError> {
    field_array(cipher)
        .iter()
        .map(|f| match f.get("name").and_then(Value::as_str) {
            Some(s) => key.decrypt_str(s).map(|n| Some(n.as_str().to_owned())),
            None => Ok(None),
        })
        .collect()
}

/// Decrypts the value of the field at `index`; a `null` value is `""`, a missing field `Malformed`.
pub fn field_value(cipher: &Value, index: usize, key: &SymmetricKey) -> Result<Zeroizing<String>, CryptoError> {
    let field = field_array(cipher).get(index).ok_or(CryptoError::Malformed)?;
    decrypt_opt(field.get("value"), key)
}

/// A string the server may send as `null`, absent or empty: all three read as `""`.
pub fn decrypt_opt(raw: Option<&Value>, key: &SymmetricKey) -> Result<Zeroizing<String>, CryptoError> {
    match raw.and_then(Value::as_str) {
        Some(s) if !s.is_empty() => key.decrypt_str(s),
        _ => Ok(Zeroizing::default()),
    }
}

/// Index of the first field called `name`.
pub fn first_index(names: &[Option<String>], name: &str) -> Option<usize> {
    names.iter().position(|n| n.as_deref() == Some(name))
}

/// The key an item's strings are encrypted with: its own wrapped key, else the owner's.
pub fn item_key<'k>(cipher: &Value, owner: &'k SymmetricKey) -> Result<KeyRef<'k>, CryptoError> {
    match cipher.get("key").and_then(Value::as_str) {
        Some(k) if !k.is_empty() => owner.decrypt_key(k).map(KeyRef::Own),
        _ => Ok(KeyRef::Owner(owner)),
    }
}
