//! Personal blob ciphers (ADR 0021, data model §4.2): the whole item sealed in `cipher.data`. Opened in memory with
//! the core's own zeroizing CBOR, read through the same rules as a field-level item, and dropped with the scan. A
//! write edits the decoded content in place, through the same rules as a field-level write, and seals it again.

use super::fields::item_key;
use super::scan::{TYPE_LOGIN, Uninspectable, copied};
use super::write::{Body, HISTORY_MAX};
use crate::crypto::{Cbor, CryptoError, EnvelopeNamespace, SymmetricKey, open_envelope, parse_cek, seal_envelope};
use crate::ports::Random;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use std::fmt;
use zeroize::Zeroizing;

/// The security state version from which the SDK seals a new personal item as a blob (`BLOB_SECURITY_VERSION`).
pub const BLOB_SECURITY_VERSION: u64 = 2;

/// The decoded `CipherBlobV1` of a blob cipher, as its map entries in order. Every text in it is wiped on drop; no
/// `Clone`.
pub(crate) struct OpenBlob(Vec<(Cbor, Cbor)>);

impl fmt::Debug for OpenBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenBlob(<redacted>)")
    }
}

#[cfg(test)]
thread_local!(static VALUES_READ: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) });

/// The values (not names) read from blobs on this thread since the last call, oldest first.
#[cfg(test)]
pub(super) fn take_values_read() -> Vec<String> {
    VALUES_READ.take()
}

#[cfg(test)]
fn note_read(what: String) {
    VALUES_READ.with_borrow_mut(|v| v.push(what));
}

fn find<'a>(entries: &'a [(Cbor, Cbor)], key: &str) -> Option<&'a Cbor> {
    entries.iter().find(|(k, _)| text(Some(k)) == Some(key)).map(|(_, v)| v)
}

pub(super) fn get<'a>(map: &'a Cbor, key: &str) -> Option<&'a Cbor> {
    let Cbor::Map(entries) = map else { return None };
    find(entries, key)
}

fn text(v: Option<&Cbor>) -> Option<&str> {
    match v {
        Some(Cbor::Text(t)) => Some(t.as_str()),
        _ => None,
    }
}

/// Sets `key` where it is, or appends it, so every other key keeps its place.
fn put(entries: &mut Vec<(Cbor, Cbor)>, key: &str, value: Cbor) {
    match entries.iter_mut().find(|(k, _)| text(Some(k)) == Some(key)) {
        Some((_, v)) => *v = value,
        None => entries.push((Cbor::text(key), value)),
    }
}

/// Takes `key`'s value out, leaving null in its place for `put`; null when absent.
fn take(entries: &mut [(Cbor, Cbor)], key: &str) -> Cbor {
    entries
        .iter_mut()
        .find(|(k, _)| text(Some(k)) == Some(key))
        .map_or(Cbor::Null, |(_, v)| std::mem::replace(v, Cbor::Null))
}

/// An empty text is no value, as a field-level write stores it.
fn stored(value: &str) -> Cbor {
    if value.is_empty() { Cbor::Null } else { Cbor::text(value) }
}

/// Absent, null or a text: what every string of `CipherBlobV1` the core reads may be.
fn text_or_null(v: Option<&Cbor>) -> bool {
    matches!(v, None | Some(Cbor::Null | Cbor::Text(_)))
}

/// The parts the core reads have the SDK's types, so a broken blob is held rather than read as unmarked.
fn well_formed(content: &[(Cbor, Cbor)]) -> bool {
    let fields = match find(content, "fields") {
        None | Some(Cbor::Null) => true,
        Some(Cbor::Array(fields)) => fields
            .iter()
            .all(|f| matches!(f, Cbor::Map(_)) && text_or_null(get(f, "name")) && text_or_null(get(f, "value"))),
        Some(_) => false,
    };
    let type_data = match find(content, "typeData") {
        None | Some(Cbor::Null) => true,
        Some(t @ Cbor::Map(_)) => text_or_null(get(t, "type")) && text_or_null(get(t, "password")),
        Some(_) => false,
    };
    fields && type_data && text_or_null(find(content, "notes"))
}

/// Opens a personal blob with its owner's key: the item key, then the content key, then the envelope (ADR 0021).
/// A `format_version` or content `version` other than 1 is `NewerFormat`; any other failure is `Blob`, and so is a
/// login cipher whose `typeData` is not a login's (its password would read as empty, then be written over).
pub(crate) fn open_blob(cipher: &Value, owner: &SymmetricKey) -> Result<OpenBlob, Uninspectable> {
    let data: Value = cipher
        .get("data")
        .and_then(Value::as_str)
        .and_then(|d| serde_json::from_str(d).ok())
        .ok_or(Uninspectable::Blob)?;
    if data.get("format_version").and_then(Value::as_u64) != Some(1) {
        return Err(Uninspectable::NewerFormat);
    }
    let login = cipher.get("type").and_then(Value::as_u64) == Some(TYPE_LOGIN);
    let part = |name: &str| data.get(name).and_then(Value::as_str).ok_or(Uninspectable::Blob);
    let key = item_key(cipher, owner).map_err(|_| Uninspectable::Blob)?;
    let cek = key.decrypt(part("wrapped_cek")?).and_then(|bytes| parse_cek(&bytes)).map_err(|_| Uninspectable::Blob)?;
    let envelope = B64.decode(part("envelope")?).map_err(|_| Uninspectable::Blob)?;
    let opened = open_envelope(&cek, &envelope, EnvelopeNamespace::VaultItem).map_err(|_| Uninspectable::Blob)?;
    let Cbor::Map(entries) = opened else { return Err(Uninspectable::Blob) };
    if !entries.iter().any(|(k, v)| text(Some(k)) == Some("version") && text(Some(v)) == Some("1")) {
        return Err(Uninspectable::NewerFormat);
    }
    entries
        .into_iter()
        .find(|(k, _)| text(Some(k)) == Some("content"))
        .and_then(|(_, content)| match content {
            Cbor::Map(c)
                if well_formed(&c)
                    && (!login || text(find(&c, "typeData").and_then(|t| get(t, "type"))) == Some("login")) =>
            {
                Some(OpenBlob(c))
            }
            _ => None,
        })
        .ok_or(Uninspectable::Blob)
}

impl OpenBlob {
    /// A new secure note as the SDK seals one (§6.2): no notes, no fields yet.
    pub(crate) fn new_note(name: &str) -> OpenBlob {
        let type_data = Cbor::Map(vec![
            (Cbor::text("type"), Cbor::text("secureNote")),
            (Cbor::text("secureNoteType"), Cbor::Uint(0)),
        ]);
        OpenBlob(vec![
            (Cbor::text("name"), Cbor::text(name)),
            (Cbor::text("notes"), Cbor::Null),
            (Cbor::text("typeData"), type_data),
        ])
    }

    /// Seals the content under a fresh content key, wrapped under `item_key`, and returns the new `cipher.data`.
    pub(crate) fn seal(self, item_key: &SymmetricKey, rng: &impl Random) -> Result<String, CryptoError> {
        let sealed =
            Cbor::Map(vec![(Cbor::text("version"), Cbor::text("1")), (Cbor::text("content"), Cbor::Map(self.0))]);
        let (envelope, cek) = seal_envelope(&sealed, EnvelopeNamespace::VaultItem, rng)?;
        // Content format OctetStream, as the SDK wraps it under a legacy item key; unverified for a COSE (type 7) item
        // key, which the core never creates.
        let wrapped = item_key.encrypt(&SymmetricKey::Cose(cek).to_bytes(), rng)?;
        // The SDK's key order; an EncString and base64 need no JSON escaping.
        Ok(format!(r#"{{"format_version":1,"wrapped_cek":"{wrapped}","envelope":"{}"}}"#, B64.encode(envelope)))
    }

    #[cfg(test)]
    pub(super) fn get(&self, key: &str) -> Option<&Cbor> {
        find(&self.0, key)
    }

    fn fields(&self) -> &[Cbor] {
        match find(&self.0, "fields") {
            Some(Cbor::Array(fields)) => fields,
            _ => &[],
        }
    }

    /// Every field's name, in order; a field without one is `None`.
    pub(crate) fn field_names(&self) -> Vec<Option<&str>> {
        self.fields().iter().map(|f| text(get(f, "name"))).collect()
    }

    pub(crate) fn field_value(&self, i: usize) -> Option<&str> {
        #[cfg(test)]
        note_read(format!("field {i}"));
        text(self.fields().get(i).and_then(|f| get(f, "value")))
    }

    pub(crate) fn notes(&self) -> Option<&str> {
        #[cfg(test)]
        note_read("notes".into());
        text(find(&self.0, "notes"))
    }

    /// `typeData.password`; `open_blob` made sure a login's `typeData` is a login's.
    pub(crate) fn login_password(&self) -> Option<&str> {
        #[cfg(test)]
        note_read("login password".into());
        text(find(&self.0, "typeData").and_then(|t| get(t, "password")))
    }

    fn take_fields(&mut self) -> Vec<Cbor> {
        match take(&mut self.0, "fields") {
            Cbor::Array(fields) => fields,
            _ => Vec::new(),
        }
    }

    /// Whether anything in the blob is not the tool's, `prefix` being its `{ns}:` (§8.2).
    pub(crate) fn has_foreign_content(&self, prefix: &str) -> bool {
        let filled = |v: Option<&Cbor>| text(v).is_some_and(|t| !t.is_empty());
        let listed = |v: Option<&Cbor>| matches!(v, Some(Cbor::Array(a)) if !a.is_empty());
        let login = |key: &str| find(&self.0, "typeData").and_then(|t| get(t, key));
        let uris = match login("uris") {
            Some(Cbor::Array(uris)) => uris.as_slice(),
            _ => &[],
        };
        self.field_names().iter().any(|n| n.is_none_or(|n| !n.starts_with(prefix)))
            || filled(find(&self.0, "notes"))
            || listed(find(&self.0, "passwordHistory"))
            || listed(login("fido2Credentials"))
            || ["username", "password", "totp"].into_iter().any(|k| filled(login(k)))
            || uris.iter().any(|u| filled(get(u, "uri")))
    }
}

/// The plaintext content under the field-level rules: values are measured as plaintext, since a blob has no
/// ciphertext per value, and every key the core does not know stays as decoded.
impl Body for OpenBlob {
    fn stored_len(&self, value: &str) -> usize {
        value.len()
    }

    fn names(&self) -> Vec<Option<&str>> {
        self.field_names()
    }

    fn value(&self, i: usize) -> Result<Zeroizing<String>, CryptoError> {
        Ok(copied(self.field_value(i)))
    }

    fn set_field(&mut self, name: &str, value: &str, hidden: bool) -> Result<(), CryptoError> {
        let mut fields = self.take_fields();
        match fields.iter_mut().find(|f| text(get(f, "name")) == Some(name)) {
            Some(Cbor::Map(f)) => put(f, "value", stored(value)),
            _ => fields.push(Cbor::Map(vec![
                (Cbor::text("name"), Cbor::text(name)),
                (Cbor::text("value"), stored(value)),
                (Cbor::text("type"), Cbor::Uint(u64::from(hidden))),
                (Cbor::text("linkedId"), Cbor::Null),
            ])),
        }
        put(&mut self.0, "fields", Cbor::Array(fields));
        Ok(())
    }

    fn remove_fields(&mut self, remove: impl Fn(&str) -> bool) {
        let mut fields = self.take_fields();
        fields.retain(|f| !text(get(f, "name")).is_some_and(&remove));
        put(&mut self.0, "fields", Cbor::Array(fields));
    }

    fn notes_text(&self) -> Result<Zeroizing<String>, CryptoError> {
        Ok(copied(self.notes()))
    }

    fn set_notes(&mut self, value: &str) -> Result<(), CryptoError> {
        put(&mut self.0, "notes", stored(value));
        Ok(())
    }

    fn password_text(&self) -> Result<Zeroizing<String>, CryptoError> {
        Ok(copied(self.login_password()))
    }

    fn replace_password(&mut self, value: &str, now: &str) -> Result<(), CryptoError> {
        // `open_blob` made sure a login's `typeData` is a login's map.
        let Cbor::Map(mut login) = take(&mut self.0, "typeData") else { return Err(CryptoError::Malformed) };
        if let Some(old @ Cbor::Text(_)) = find(&login, "password") {
            let entry =
                Cbor::Map(vec![(Cbor::text("password"), old.clone()), (Cbor::text("lastUsedDate"), Cbor::text(now))]);
            let mut history = match take(&mut self.0, "passwordHistory") {
                Cbor::Array(history) => history,
                _ => Vec::new(),
            };
            history.insert(0, entry);
            history.truncate(HISTORY_MAX);
            put(&mut self.0, "passwordHistory", Cbor::Array(history));
        }
        put(&mut login, "password", stored(value));
        put(&mut login, "passwordRevisionDate", Cbor::text(now));
        put(&mut self.0, "typeData", Cbor::Map(login));
        Ok(())
    }

    fn evicted(&self) -> Result<Vec<Zeroizing<String>>, CryptoError> {
        // As `replace_password`: only a password that is there goes into the history.
        if !matches!(find(&self.0, "typeData").and_then(|t| get(t, "password")), Some(Cbor::Text(_))) {
            return Ok(Vec::new());
        }
        let history = match find(&self.0, "passwordHistory") {
            Some(Cbor::Array(history)) => history.as_slice(),
            _ => &[],
        };
        Ok(history.iter().skip(HISTORY_MAX - 1).map(|e| copied(text(get(e, "password")))).collect())
    }

    fn longest_value(&self) -> usize {
        self.fields().iter().map(|f| text(get(f, "value")).map_or(0, str::len)).max().unwrap_or(0)
    }
}
