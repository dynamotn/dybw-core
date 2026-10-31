//! Writing (data model §6, §8.2): port of bwss `src/bw/write.rs` onto `Namespace`, with the plugin's
//! `newSecretRequest` and `updateValueRequest`. A write changes only the value source and the tool's own fields;
//! every other field, key and unknown property passes through byte for byte (§6.3).

use super::blob::{BLOB_SECURITY_VERSION, OpenBlob, open_blob};
use super::fields::{Mark, decrypt_opt, field_names, first_index, item_key};
use super::namespace::{Encodings, Namespace};
use super::scan::{
    Scan, TYPE_SECURE_NOTE, Uninspectable, ValueSource, is_blob, organization, read_only, scan, supported_type,
    too_large, trashed,
};
use super::{Keys, Organizations};
use crate::crypto::{ContentFormat, CryptoError, SymmetricKey};
use crate::ports::Random;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

/// Bitwarden's limits, in encrypted characters (§6.4).
const MAX_FIELD_ENC: usize = 5_000;
const MAX_PASSWORD_ENC: usize = 5_000;
const MAX_NOTES_ENC: usize = 10_000;
const FIELD_TEXT: u64 = 0;
const FIELD_HIDDEN: u64 = 1;
/// `passwordHistory` keeps at most this many entries, newest first (§6.1).
pub(super) const HISTORY_MAX: usize = 5;
/// Metadata only the server sends, dropped from every update body (§6.3). A blob's update body sends a new `data`.
const RESPONSE_ONLY: [&str; 12] = [
    "id",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "object",
    "edit",
    "viewPassword",
    "permissions",
    "collectionIds",
    "attachments",
    "organizationUseTotp",
    "data",
];

/// One tool field to set: the first field of that name changes, or a new one is appended (§3.1).
#[derive(Clone, Serialize, Deserialize)]
pub struct FieldSet {
    pub name: String,
    pub value: Zeroizing<String>,
    pub hidden: bool,
}

/// A tool's own changes to one item, kept so they can be re-applied to a fresh copy when the server rejects a write
/// as out of date (§6.5).
#[derive(Clone, Serialize, Deserialize)]
pub struct Patch {
    /// The `{ns}:id` the patch was built for.
    pub id: String,
    /// The cipher the patch was read from; `None` for an item not on the server yet.
    pub cipher_id: Option<String>,
    /// The organization of the copy the patch was read from (`MarkedItem::organization_id`); `None` for a personal
    /// item, and for a patch queued before this was recorded.
    #[serde(default)]
    pub organization_id: Option<String>,
    pub base_revision: String,
    pub set: Vec<FieldSet>,
    /// Field names; every copy goes (ADR 0014). `{ns}:attr:` removes every attribute field.
    pub remove: Vec<String>,
    pub value: ValueChange,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ValueChange {
    Keep,
    /// Writes `secret` back to the value source. `source` and `base_mark` are what the change was based on, checked
    /// against the copy written over. With `owned`, the secret goes into the tool's own storage even when the source
    /// is the user's: an earlier binary write already added `{ns}:password`, the source from then on (§6.1).
    Set {
        source: ValueSource,
        secret: Zeroizing<Vec<u8>>,
        base_mark: [u8; 32],
        owned: bool,
    },
}

/// A new item (§6.2). `tool_fields` follow the marker and the value, in order.
#[derive(Clone, Serialize, Deserialize)]
pub struct NewItem {
    pub id: String,
    pub value: Zeroizing<Vec<u8>>,
    pub name: String,
    pub folder_id: Option<String>,
    pub tool_fields: Vec<FieldSet>,
}

/// Why a write was refused. Messages never carry a value, a key or a ciphertext.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WriteError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("the value is too long for a Bitwarden item")]
    TooLong,
    #[error("the value does not fit its field, and the notes hold the user's text")]
    NotesTaken,
    #[error("the value was changed elsewhere")]
    SourceChanged,
    #[error("the item was deleted elsewhere")]
    Gone,
    #[error("the item no longer carries its marker")]
    Unmarked,
    /// The copy cannot be read now; unlike `Unmarked`, the change must not be dropped.
    #[error("the item cannot be read: {0:?}")]
    Uninspectable(Uninspectable),
    #[error("the organization does not let this account edit the item")]
    ReadOnly,
    #[error("the value is not text, and this namespace stores text only")]
    BinaryNotSupported,
    /// The clock is outside the years 0000-9999, so no date can be written from it.
    #[error("the clock is out of range")]
    BadClock,
}

impl WriteError {
    /// The vectors' `expect.write.error` code, for the errors that have one.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            WriteError::TooLong => Some("too-long"),
            WriteError::NotesTaken => Some("notes-hold-user-text"),
            WriteError::SourceChanged => Some("value-source-changed"),
            _ => None,
        }
    }
}

/// The encrypted length of a text of `plain_len` bytes under `key`, for the §6.4 decisions: type 7 strings are
/// longer than type 2 ones.
pub fn encrypted_len(plain_len: usize, key: &SymmetricKey) -> usize {
    key.encrypted_str_len(plain_len)
}

/// `now` as JavaScript's `toISOString` writes it, the form the vectors freeze. A clock outside the years 0000-9999
/// is an error, never a made-up date.
fn iso_ms(ms: i64) -> Result<String, WriteError> {
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .filter(|t| t.year() >= 0)
        .ok_or(WriteError::BadClock)?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    ))
}

/// The key an item's strings (or its own key) are under: its organization's, else the user's.
fn owner<'k>(cipher: &Value, keys: &'k Keys) -> Result<&'k SymmetricKey, WriteError> {
    match organization(cipher) {
        None => Ok(&keys.user),
        Some(org) => keys
            .orgs
            .get(org.as_str().unwrap_or_default())
            .ok_or(WriteError::Uninspectable(Uninspectable::OrganizationKeyMissing)),
    }
}

/// The two shapes a write edits: a field-level cipher's encrypted strings, or an open blob's decoded content (ADR
/// 0021). The rules of §6 are written once, in `Edit`, over these.
pub(crate) trait Body {
    /// The length §6.4 compares with Bitwarden's limits; 0 for the empty text, which is stored as no value.
    fn stored_len(&self, value: &str) -> usize;
    /// Every field's name, in order; a field without one is `None`.
    fn names(&self) -> Vec<Option<&str>>;
    /// The value of field `i`; `""` for none.
    fn value(&self, i: usize) -> Result<Zeroizing<String>, CryptoError>;
    /// Sets the first field called `name`, keeping its kind; appends a field when there is none (§3.1).
    fn set_field(&mut self, name: &str, value: &str, hidden: bool) -> Result<(), CryptoError>;
    /// Removes every field whose name matches, so no later copy takes its place (ADR 0014).
    fn remove_fields(&mut self, remove: impl Fn(&str) -> bool);
    fn notes_text(&self) -> Result<Zeroizing<String>, CryptoError>;
    fn set_notes(&mut self, value: &str) -> Result<(), CryptoError>;
    fn password_text(&self) -> Result<Zeroizing<String>, CryptoError>;
    /// Sets the login password and its revision date to `now`; the old one, when there is one, goes first into the
    /// history, which keeps `HISTORY_MAX` entries (§6.1).
    fn replace_password(&mut self, value: &str, now: &str) -> Result<(), CryptoError>;
    /// The longest field value, as stored.
    fn longest_value(&self) -> usize;
}

/// A field-level cipher being written: the request body and the custom fields, each raw (encrypted) entry beside
/// its decrypted name. Entries the write does not change are kept byte for byte.
struct Fields<'a, R: Random> {
    key: &'a SymmetricKey,
    rng: &'a R,
    body: Map<String, Value>,
    fields: Vec<(Value, Option<String>)>,
}

/// The cipher as returned, minus response-only metadata; the item key and unknown keys stay.
fn request_body(cipher: &Value) -> Map<String, Value> {
    cipher
        .as_object()
        .map(|o| o.iter().filter(|(k, _)| !RESPONSE_ONLY.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())))
        .map(Iterator::collect)
        .unwrap_or_default()
}

impl<'a, R: Random> Fields<'a, R> {
    fn read(cipher: &Value, key: &'a SymmetricKey, rng: &'a R) -> Result<Self, CryptoError> {
        let names = field_names(cipher, key)?;
        let raw = cipher.get("fields").and_then(Value::as_array).cloned().unwrap_or_default();
        Ok(Fields { key, rng, body: request_body(cipher), fields: raw.into_iter().zip(names).collect() })
    }

    /// Encrypted under the item key; an empty text is no value (`null`), as the plugin stores it.
    fn enc(&self, text: &str) -> Result<Value, CryptoError> {
        if text.is_empty() {
            return Ok(Value::Null);
        }
        Ok(Value::String(self.key.encrypt_str(text, self.rng)?))
    }

    fn take_fields(&mut self) -> Value {
        Value::Array(std::mem::take(&mut self.fields).into_iter().map(|(raw, _)| raw).collect())
    }

    /// The end of every update body: the edited fields, a `passwordHistory` that is always an array (the server
    /// replaces the history with it), and the revision the write is based on.
    fn finish(mut self, revision: &str) -> Map<String, Value> {
        let fields = self.take_fields();
        self.body.insert("fields".into(), fields);
        if !self.body.get("passwordHistory").is_some_and(Value::is_array) {
            self.body.insert("passwordHistory".into(), json!([]));
        }
        self.body.insert("lastKnownRevisionDate".into(), json!(revision));
        self.body
    }
}

impl<R: Random> Body for Fields<'_, R> {
    /// The encrypted length (type 7 strings are longer than type 2 ones).
    fn stored_len(&self, value: &str) -> usize {
        if value.is_empty() { 0 } else { encrypted_len(value.len(), self.key) }
    }

    fn names(&self) -> Vec<Option<&str>> {
        self.fields.iter().map(|(_, n)| n.as_deref()).collect()
    }

    fn value(&self, i: usize) -> Result<Zeroizing<String>, CryptoError> {
        decrypt_opt(self.fields.get(i).and_then(|(f, _)| f.get("value")), self.key)
    }

    fn set_field(&mut self, name: &str, value: &str, hidden: bool) -> Result<(), CryptoError> {
        let value = self.enc(value)?;
        // Only an object can carry a name, so the first named entry is one.
        let existing = self
            .fields
            .iter_mut()
            .find_map(|(raw, n)| if n.as_deref() == Some(name) { raw.as_object_mut() } else { None });
        match existing {
            Some(f) => {
                f.insert("value".into(), value);
            }
            None => {
                let kind = if hidden { FIELD_HIDDEN } else { FIELD_TEXT };
                let enc_name = self.key.encrypt_str(name, self.rng)?;
                let field = json!({ "type": kind, "name": enc_name, "value": value, "linkedId": null });
                self.fields.push((field, Some(name.to_owned())));
            }
        }
        Ok(())
    }

    fn remove_fields(&mut self, remove: impl Fn(&str) -> bool) {
        self.fields.retain(|(_, n)| !n.as_deref().is_some_and(&remove));
    }

    fn notes_text(&self) -> Result<Zeroizing<String>, CryptoError> {
        decrypt_opt(self.body.get("notes"), self.key)
    }

    fn set_notes(&mut self, value: &str) -> Result<(), CryptoError> {
        let value = self.enc(value)?;
        self.body.insert("notes".into(), value);
        Ok(())
    }

    fn password_text(&self) -> Result<Zeroizing<String>, CryptoError> {
        decrypt_opt(self.body.get("login").and_then(|l| l.get("password")), self.key)
    }

    /// The old password moves to the history as it is, still encrypted.
    fn replace_password(&mut self, value: &str, now: &str) -> Result<(), CryptoError> {
        let existing = self.body.get("login").and_then(Value::as_object).cloned();
        let had_login = existing.is_some();
        let mut login = existing.unwrap_or_default();
        if let Some(old) = login.get("password").filter(|p| p.is_string()) {
            let mut history = self.body.get("passwordHistory").and_then(Value::as_array).cloned().unwrap_or_default();
            history.insert(0, json!({ "password": old, "lastUsedDate": now }));
            history.truncate(HISTORY_MAX);
            self.body.insert("passwordHistory".into(), Value::Array(history));
        }
        login.insert("password".into(), self.enc(value)?);
        login.insert("passwordRevisionDate".into(), json!(now));
        if !had_login {
            for k in ["username", "uris", "totp"] {
                login.entry(k).or_insert(Value::Null);
            }
        }
        self.body.insert("login".into(), Value::Object(login));
        Ok(())
    }

    fn longest_value(&self) -> usize {
        self.fields.iter().map(|(f, _)| f.get("value").and_then(Value::as_str).map_or(0, str::len)).max().unwrap_or(0)
    }
}

/// One write in progress, on either shape of item: the rules of §6.
struct Edit<'a, B: Body> {
    ns: &'a Namespace,
    body: B,
}

impl<B: Body> Edit<'_, B> {
    /// Whether the first `{ns}:location` says `notes` after trimming (§3.2, ADR 0010); absent and `null` say nothing.
    fn notes_marked(&self) -> Result<bool, CryptoError> {
        let names = self.body.names();
        let value = match first_index(&names, &self.ns.field("location")) {
            Some(i) => self.body.value(i)?,
            None => Zeroizing::default(),
        };
        Ok(Mark::classify(Some(&value), "notes") == Mark::Set)
    }

    fn set(&mut self, name: &str, text: &str, hidden: bool) -> Result<(), CryptoError> {
        self.body.set_field(name, text, hidden)
    }

    fn remove_where(&mut self, remove: impl Fn(&str) -> bool) {
        self.body.remove_fields(remove);
    }

    /// Stores `stored` (text, or base64 of bytes) where the tool owns the storage: `{ns}:password`, or the notes
    /// when it does not fit a field and the notes are empty or already the tool's (§6.4).
    fn write_owned_field(&mut self, stored: &str) -> Result<(), WriteError> {
        let ns = self.ns;
        let (password, location) = (ns.field("password"), ns.field("location"));
        let notes_marked = self.notes_marked()?;
        let len = self.body.stored_len(stored);
        if len <= MAX_FIELD_ENC {
            self.set(&password, stored, true)?;
            // The notes held an older copy of the secret (ADR 0010): clear it and its mark in the same write.
            if notes_marked {
                self.body.set_notes("")?;
                self.remove_where(|n| n == location);
            }
            return Ok(());
        }
        if len > MAX_NOTES_ENC {
            return Err(WriteError::TooLong);
        }
        // Decrypted: notes holding "" are empty too (the plugin's empty-notes fix).
        let notes_empty = self.body.notes_text()?.is_empty();
        if !notes_marked && !notes_empty {
            return Err(WriteError::NotesTaken);
        }
        self.body.set_notes(stored)?;
        self.set(&location, "notes", false)?;
        self.remove_where(|n| n == password);
        Ok(())
    }

    fn write_notes(&mut self, text: &str) -> Result<(), WriteError> {
        if self.body.stored_len(text) > MAX_NOTES_ENC {
            return Err(WriteError::TooLong);
        }
        Ok(self.body.set_notes(text)?)
    }

    /// Writes the login password as the official clients do: the old one goes first into the history (at most 5)
    /// and the revision date is set (§6.1). An identical value is not written.
    fn write_login_password(&mut self, text: &str, now: &str) -> Result<(), WriteError> {
        if self.body.stored_len(text) > MAX_PASSWORD_ENC {
            return Err(WriteError::TooLong);
        }
        if self.body.password_text()?.as_str() == text {
            return Ok(());
        }
        Ok(self.body.replace_password(text, now)?)
    }

    /// Writes `secret` back to `source` (§6.1, ADR 0005); with `owned`, into the tool's storage instead of a value
    /// the user owns.
    fn write_value(&mut self, source: ValueSource, secret: &[u8], owned: bool, now: &str) -> Result<(), WriteError> {
        let encoding = self.ns.field("encoding");
        if let Ok(text) = std::str::from_utf8(secret) {
            // Text drops the encoding mark; a namespace without encodings leaves its (blank) field as the plugin does.
            if self.ns.encodings != Encodings::None {
                self.remove_where(|n| n == encoding);
            }
            return match source {
                ValueSource::Field => self.write_owned_field(text),
                ValueSource::LoginPassword | ValueSource::NoteBody if owned => self.write_owned_field(text),
                ValueSource::Notes | ValueSource::NoteBody => self.write_notes(text),
                ValueSource::LoginPassword => self.write_login_password(text, now),
            };
        }
        if self.ns.encodings == Encodings::None {
            return Err(WriteError::BinaryNotSupported);
        }
        // Binary only goes where the tool owns the storage: a login password or a note's own text is never touched,
        // a new `{ns}:password` becomes the source instead.
        let b64 = Zeroizing::new(B64.encode(secret));
        match source {
            ValueSource::Notes => self.write_notes(&b64)?,
            ValueSource::Field | ValueSource::LoginPassword | ValueSource::NoteBody => self.write_owned_field(&b64)?,
        }
        self.set(&encoding, "base64", false)?;
        Ok(())
    }

    /// Fails when any field value is over Bitwarden's limit, so an oversize tool field never reaches the server.
    fn check_sizes(&self) -> Result<(), WriteError> {
        if self.body.longest_value() > MAX_FIELD_ENC { Err(WriteError::TooLong) } else { Ok(()) }
    }

    /// Steps 3 and 4 of a write: the value back to its source, then the tool's own fields.
    fn patch(&mut self, source: ValueSource, patch: &Patch, now_ms: i64) -> Result<(), WriteError> {
        if let ValueChange::Set { secret, owned, .. } = &patch.value {
            self.write_value(source, secret, *owned, &iso_ms(now_ms)?)?;
        }
        let attr = self.ns.field("attr:");
        for name in &patch.remove {
            if *name == attr {
                self.remove_where(|n| n.starts_with(&attr));
            } else {
                self.remove_where(|n| n == name);
            }
        }
        for f in &patch.set {
            self.set(&f.name, &f.value, f.hidden)?;
        }
        self.check_sizes()
    }

    /// §8.2 step 1: every field of the namespace goes, and the notes when they held the tool's secret.
    fn strip(&mut self) -> Result<(), WriteError> {
        if self.notes_marked()? {
            self.body.set_notes("")?;
        }
        let prefix = self.ns.field("");
        self.remove_where(|n| n.starts_with(&prefix));
        Ok(())
    }

    /// A new item's fields (§6.2): the marker, the value, then the tool's.
    fn create(&mut self, item: &NewItem) -> Result<(), WriteError> {
        self.set(&self.ns.field("id"), &item.id, false)?;
        // The `Field` source never touches a login, so no date is needed.
        self.write_value(ValueSource::Field, &item.value, false, "")?;
        for f in &item.tool_fields {
            self.set(&f.name, &f.value, f.hidden)?;
        }
        self.check_sizes()
    }
}

/// The update body of a blob cipher: its new `data` beside the cipher's own metadata and item key, with the
/// field-level parts null, as the SDK sends it (ADR 0021).
fn blob_body(cipher: &Value, data: String, revision: &str) -> Map<String, Value> {
    let mut body = request_body(cipher);
    for k in ["name", "notes", "login", "fields", "passwordHistory"] {
        body.insert(k.into(), Value::Null);
    }
    body.insert("data".into(), json!(data));
    body.insert("lastKnownRevisionDate".into(), json!(revision));
    body
}

/// Applies `patch` to `cipher` (the server's copy, fresh or as last read) and returns the body of the update
/// request. `now_ms` dates a replaced login password. A blob stays a blob, sealed under a fresh content key.
pub fn apply(
    cipher: &Value,
    patch: &Patch,
    ns: &Namespace,
    keys: &Keys,
    rng: &impl Random,
    now_ms: i64,
) -> Result<Map<String, Value>, WriteError> {
    // 1. Abort checks against the copy being written over (§6.5). An organization blob scans as held.
    if trashed(cipher) {
        return Err(WriteError::Gone);
    }
    let fresh = match scan(cipher, ns, keys, &Organizations::All) {
        Scan::Marked(m) if m.id == patch.id => m,
        Scan::Uninspectable(why) => return Err(WriteError::Uninspectable(why)),
        Scan::Marked(_) | Scan::Unmarked | Scan::Skipped(_) => return Err(WriteError::Unmarked),
    };
    if fresh.read_only {
        return Err(WriteError::ReadOnly);
    }
    if let ValueChange::Set { source, base_mark, .. } = &patch.value
        && (fresh.source != *source || fresh.mark != *base_mark)
    {
        return Err(WriteError::SourceChanged);
    }
    let revision = cipher.get("revisionDate").and_then(Value::as_str).unwrap_or(&patch.base_revision);

    // 2. Everything new is encrypted under the item's own key; 3 and 4, the value and the tool's own fields.
    let owner = owner(cipher, keys)?;
    let key = item_key(cipher, owner)?;
    if is_blob(cipher) {
        let mut edit = Edit { ns, body: open_blob(cipher, owner).map_err(WriteError::Uninspectable)? };
        edit.patch(fresh.source, patch, now_ms)?;
        return Ok(blob_body(cipher, edit.body.seal(&key, rng)?, revision));
    }
    let mut edit = Edit { ns, body: Fields::read(cipher, &key, rng)? };
    edit.patch(fresh.source, patch, now_ms)?;
    Ok(edit.body.finish(revision))
}

/// Body of the update that removes every field of the tool's namespace from `cipher` (§8.2 step 1). The notes are
/// cleared when they held the tool's secret (`{ns}:location=notes`); everything else passes through as in `apply`.
pub fn strip(cipher: &Value, ns: &Namespace, keys: &Keys, rng: &impl Random) -> Result<Map<String, Value>, WriteError> {
    if trashed(cipher) {
        return Err(WriteError::Gone);
    }
    if too_large(cipher) {
        return Err(WriteError::Uninspectable(Uninspectable::TooLarge));
    }
    let blob = is_blob(cipher);
    // The SDK never seals an organization item: one is held, never opened (ADR 0021).
    if blob && organization(cipher).is_some() {
        return Err(WriteError::Uninspectable(Uninspectable::NewerFormat));
    }
    if read_only(cipher) {
        return Err(WriteError::ReadOnly);
    }
    // Without the revision it is based on, a write could overwrite a newer copy: held, as bwss does.
    let Some(revision) = cipher.get("revisionDate").and_then(Value::as_str) else {
        return Err(WriteError::Uninspectable(Uninspectable::Value));
    };
    let owner = owner(cipher, keys)?;
    let key = item_key(cipher, owner)?;
    if blob {
        let mut edit = Edit { ns, body: open_blob(cipher, owner).map_err(WriteError::Uninspectable)? };
        edit.strip()?;
        return Ok(blob_body(cipher, edit.body.seal(&key, rng)?, revision));
    }
    let mut edit = Edit { ns, body: Fields::read(cipher, &key, rng)? };
    edit.strip()?;
    Ok(edit.body.finish(revision))
}

/// Whether anything in `cipher` is not the tool's (§8.2). Only what the answer needs is decrypted, except in a
/// blob, which opens whole. An item that cannot be read is an error, never `false`: it must not be trashed.
pub fn has_foreign_content(cipher: &Value, ns: &Namespace, keys: &Keys) -> Result<bool, WriteError> {
    if too_large(cipher) {
        return Err(WriteError::Uninspectable(Uninspectable::TooLarge));
    }
    let blob = is_blob(cipher);
    if blob && organization(cipher).is_some() {
        return Err(WriteError::Uninspectable(Uninspectable::NewerFormat));
    }
    // Card, identity and SSH key data is never inspected: not bare.
    if !supported_type(cipher) {
        return Ok(true);
    }
    // A blob's own `passwordHistory` and `login` are null: its history and passkeys are inside it.
    let non_empty_array = |v: Option<&Value>| v.and_then(Value::as_array).is_some_and(|a| !a.is_empty());
    if non_empty_array(cipher.get("attachments"))
        || non_empty_array(cipher.get("passwordHistory"))
        || non_empty_array(cipher.pointer("/login/fido2Credentials"))
    {
        return Ok(true);
    }
    let prefix = ns.field("");
    if blob {
        return Ok(open_blob(cipher, &keys.user).map_err(WriteError::Uninspectable)?.has_foreign_content(&prefix));
    }
    let key = item_key(cipher, owner(cipher, keys)?)?;
    if field_names(cipher, &key)?.iter().any(|n| n.as_deref().is_none_or(|n| !n.starts_with(&prefix))) {
        return Ok(true);
    }
    let filled = |v: Option<&Value>| -> Result<bool, CryptoError> { Ok(!decrypt_opt(v, &key)?.is_empty()) };
    if filled(cipher.get("notes"))? {
        return Ok(true);
    }
    let Some(login) = cipher.get("login").filter(|l| l.is_object()) else { return Ok(false) };
    for k in ["username", "password", "totp"] {
        if filled(login.get(k))? {
            return Ok(true);
        }
    }
    for uri in login.get("uris").and_then(Value::as_array).into_iter().flatten() {
        if filled(uri.get("uri"))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Body of the create request for a new item (§6.2): a personal secure note with empty notes and the value in a
/// hidden `{ns}:password`, or in the notes with `{ns}:location=notes` when it does not fit (§6.4). On an account
/// whose verified security state is at `BLOB_SECURITY_VERSION` or higher it is a blob under a fresh item key, as the
/// SDK seals one (ADR 0021); field-level otherwise.
pub fn new_item(
    item: &NewItem,
    ns: &Namespace,
    keys: &Keys,
    rng: &impl Random,
) -> Result<Map<String, Value>, WriteError> {
    let mut body = Map::new();
    for (k, v) in [
        ("type", json!(TYPE_SECURE_NOTE)),
        ("organizationId", Value::Null),
        ("folderId", json!(item.folder_id)),
        ("login", Value::Null),
        ("favorite", json!(false)),
        ("reprompt", json!(0)),
    ] {
        body.insert(k.into(), v);
    }
    if keys.security_version >= BLOB_SECURITY_VERSION {
        let mut edit = Edit { ns, body: OpenBlob::new_note(&item.name) };
        edit.create(item)?;
        let item_key = SymmetricKey::generate(rng)?;
        let data = edit.body.seal(&item_key, rng)?;
        let key = keys.user.encrypt_as(&item_key.to_bytes(), ContentFormat::LegacyKey, rng)?;
        // The type data lives in the blob's `typeData`: the SDK sends every legacy part null.
        for k in ["name", "notes", "secureNote", "fields", "passwordHistory"] {
            body.insert(k.into(), Value::Null);
        }
        body.insert("key".into(), json!(key));
        body.insert("data".into(), json!(data));
        return Ok(body);
    }
    let mut edit = Edit { ns, body: Fields { key: &keys.user, rng, body: Map::new(), fields: Vec::new() } };
    edit.create(item)?;
    let fields = edit.body.take_fields();
    let notes = edit.body.body.remove("notes").unwrap_or(Value::Null);
    for (k, v) in [
        ("name", json!(keys.user.encrypt_str(&item.name, rng)?)),
        ("notes", notes),
        ("key", Value::Null),
        ("passwordHistory", json!([])),
        ("secureNote", json!({ "type": 0 })),
        ("fields", fields),
    ] {
        body.insert(k.into(), v);
    }
    Ok(body)
}
