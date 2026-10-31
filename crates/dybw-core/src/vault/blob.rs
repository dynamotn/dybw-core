//! Personal blob ciphers (ADR 0021, data model §4.2): the whole item sealed in `cipher.data`. Opened in memory with
//! the core's own zeroizing CBOR, read through the same rules as a field-level item, and dropped with the scan.

use super::fields::item_key;
use super::scan::{TYPE_LOGIN, Uninspectable};
use crate::crypto::{Cbor, EnvelopeNamespace, SymmetricKey, open_envelope, parse_cek};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use std::fmt;

/// The decoded `CipherBlobV1` of a blob cipher. Every text in it is wiped on drop; no `Clone`.
pub(crate) struct OpenBlob(Cbor);

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

fn get<'a>(map: &'a Cbor, key: &str) -> Option<&'a Cbor> {
    let Cbor::Map(entries) = map else { return None };
    entries.iter().find(|(k, _)| text(Some(k)) == Some(key)).map(|(_, v)| v)
}

fn text(v: Option<&Cbor>) -> Option<&str> {
    match v {
        Some(Cbor::Text(t)) => Some(t.as_str()),
        _ => None,
    }
}

/// Absent, null or a text: what every string of `CipherBlobV1` the core reads may be.
fn text_or_null(v: Option<&Cbor>) -> bool {
    matches!(v, None | Some(Cbor::Null | Cbor::Text(_)))
}

/// The parts the core reads have the SDK's types, so a broken blob is held rather than read as unmarked.
fn well_formed(content: &Cbor) -> bool {
    let fields = match get(content, "fields") {
        None | Some(Cbor::Null) => true,
        Some(Cbor::Array(fields)) => fields
            .iter()
            .all(|f| matches!(f, Cbor::Map(_)) && text_or_null(get(f, "name")) && text_or_null(get(f, "value"))),
        Some(_) => false,
    };
    let type_data = match get(content, "typeData") {
        None | Some(Cbor::Null) => true,
        Some(t @ Cbor::Map(_)) => text_or_null(get(t, "type")) && text_or_null(get(t, "password")),
        Some(_) => false,
    };
    matches!(content, Cbor::Map(_)) && fields && type_data && text_or_null(get(content, "notes"))
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
        .map(|(_, content)| content)
        .filter(|c| {
            well_formed(c) && (!login || text(get(c, "typeData").and_then(|t| get(t, "type"))) == Some("login"))
        })
        .map(OpenBlob)
        .ok_or(Uninspectable::Blob)
}

impl OpenBlob {
    fn fields(&self) -> &[Cbor] {
        match get(&self.0, "fields") {
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
        text(get(&self.0, "notes"))
    }

    /// `typeData.password`; `open_blob` made sure a login's `typeData` is a login's.
    pub(crate) fn login_password(&self) -> Option<&str> {
        #[cfg(test)]
        note_read("login password".into());
        text(get(&self.0, "typeData").and_then(|t| get(t, "password")))
    }
}
