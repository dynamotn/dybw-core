//! Vault-client writes (ADR 0025, data model §1.1): the bodies the dybw CLI's `add`, `edit` and `remove` send, on the
//! machinery of a tool's writes (`write::Fields`, the blob's `Body`).
//!
//! - A create is a personal login or secure note (§6.2's shape: field-level, or a blob under a fresh item key when
//!   the verified security state is at `BLOB_SECURITY_VERSION` or higher).
//! - An edit changes the name, notes and folder of any item, and a login's username, password and URIs. Everything
//!   it does not change passes through byte for byte (§6.3): other tools' fields and markers, unknown keys, the item
//!   key; a changed password goes first into the history (§6.1); a part set to what it holds is not written.
//! - A trash moves the item to the trash (§8.2), never purges it.
//!
//! An edit or a trash planned on another revision than the server's copy is refused (§6.5). Organization items are
//! written under their organization's key, never when it is missing or the item is read-only (§9); a personal blob
//! is re-sealed whole, an organization blob is refused as the read path holds it (ADR 0021). Every text is wiped on
//! drop, and no error carries a value.

use super::blob::{BLOB_SECURITY_VERSION, OpenBlob, find, get, open_blob, put, stored, take, text};
use super::fields::{Mark, decrypt_opt, item_key};
use super::scan::trashed;
use super::scan::{TYPE_LOGIN, TYPE_SECURE_NOTE, Uninspectable, copied, is_blob, organization, read_only, too_large};
use super::write::{Body, Fields, MAX_NOTES_ENC, MAX_PASSWORD_ENC, WriteError, blob_body, iso_ms};
use crate::crypto::{Cbor, ContentFormat, CryptoError, SymmetricKey};
use crate::ports::Random;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Bitwarden's limits in encrypted characters (the server's `EncryptedStringLength`), beside §6.4's.
const MAX_NAME_ENC: usize = 1_000;
const MAX_USERNAME_ENC: usize = 1_000;
const MAX_TOTP_ENC: usize = 1_000;
const MAX_URI_ENC: usize = 10_000;
/// The highest URI match type: 0 domain, 1 host, 2 starts with, 3 exact, 4 regular expression, 5 never.
const MATCH_MAX: u64 = 5;

/// One URI of a login. An empty `uri` is none, and is left out.
#[derive(Clone)]
pub struct NewUri {
    pub uri: Zeroizing<String>,
    /// `None` is the account's default match.
    pub match_type: Option<u64>,
}

/// A new login's part; an empty text is none.
pub struct NewLogin {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
    /// The `login.totp` key, as `totp::parse` reads it; not checked here.
    pub totp: Zeroizing<String>,
    pub uris: Vec<NewUri>,
}

pub enum NewKind {
    Login(NewLogin),
    SecureNote,
}

/// A new personal item. No `Debug`: every text is the user's.
pub struct NewEntry {
    pub name: Zeroizing<String>,
    /// Empty for none.
    pub notes: Zeroizing<String>,
    pub folder_id: Option<String>,
    pub kind: NewKind,
}

/// One edit of an item. `None` leaves a part as it is; an empty text clears it (the name excepted).
#[derive(Default)]
pub struct ClientEdit {
    /// The `revisionDate` of the copy the edit was planned on (§6.5).
    pub base_revision: String,
    pub name: Option<Zeroizing<String>>,
    pub notes: Option<Zeroizing<String>>,
    pub username: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
    /// The whole new list, in order. A URI already there with the same match keeps its entry as the server sent it.
    pub uris: Option<Vec<NewUri>>,
    /// `Some(None)` moves the item out of every folder.
    pub folder_id: Option<Option<String>>,
}

/// A URI's decrypted text and match type.
type UriText = (Zeroizing<String>, Option<u64>);

/// The parts a vault client edits beyond a tool's, on both shapes of an item.
trait Parts: Body {
    fn name_text(&self) -> Result<Zeroizing<String>, CryptoError>;
    fn set_name(&mut self, value: &str) -> Result<(), CryptoError>;
    /// The login part's `username`, `password` or `totp`; `""` for none.
    fn login_text(&self, part: &str) -> Result<Zeroizing<String>, CryptoError>;
    /// Sets one string of the login part, adding the part when the item has none. No history: `replace_password`
    /// is the edit of a password.
    fn set_login_text(&mut self, part: &str, value: &str) -> Result<(), CryptoError>;
    /// Each URI's text and match type, in order.
    fn uris(&self) -> Result<Vec<UriText>, CryptoError>;
    /// Replaces the URI list: `reuse[i]`, when set, is the index of an entry kept as it is for `uris[i]`.
    fn set_uris(&mut self, uris: &[&NewUri], reuse: &[Option<usize>]) -> Result<(), CryptoError>;
}

/// The checksum the official clients keep beside each URI of an item with its own key (and drop a URI without
/// one): base64 of the URI's SHA-256.
fn checksum(uri: &str) -> Zeroizing<String> {
    Zeroizing::new(B64.encode(Sha256::digest(uri.as_bytes())))
}

fn login_uris(body: &Map<String, Value>) -> &[Value] {
    body.get("login").and_then(|l| l.get("uris")).and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// Runs `change` on the login part, made with the four strings null when the item has none.
fn edit_login(body: &mut Map<String, Value>, change: impl FnOnce(&mut Map<String, Value>)) {
    let mut login = body.get("login").and_then(Value::as_object).cloned().unwrap_or_else(|| {
        ["username", "password", "uris", "totp"].into_iter().map(|k| (k.to_owned(), Value::Null)).collect()
    });
    change(&mut login);
    body.insert("login".into(), Value::Object(login));
}

impl<R: Random> Parts for Fields<'_, R> {
    fn name_text(&self) -> Result<Zeroizing<String>, CryptoError> {
        decrypt_opt(self.body.get("name"), self.key)
    }

    fn set_name(&mut self, value: &str) -> Result<(), CryptoError> {
        let value = self.enc(value)?;
        self.body.insert("name".into(), value);
        Ok(())
    }

    fn login_text(&self, part: &str) -> Result<Zeroizing<String>, CryptoError> {
        decrypt_opt(self.body.get("login").and_then(|l| l.get(part)), self.key)
    }

    fn set_login_text(&mut self, part: &str, value: &str) -> Result<(), CryptoError> {
        let value = self.enc(value)?;
        edit_login(&mut self.body, |l| {
            l.insert(part.to_owned(), value);
        });
        Ok(())
    }

    fn uris(&self) -> Result<Vec<UriText>, CryptoError> {
        login_uris(&self.body)
            .iter()
            .map(|u| Ok((decrypt_opt(u.get("uri"), self.key)?, u.get("match").and_then(Value::as_u64))))
            .collect()
    }

    fn set_uris(&mut self, uris: &[&NewUri], reuse: &[Option<usize>]) -> Result<(), CryptoError> {
        let old = login_uris(&self.body).to_vec();
        let mut list = Vec::with_capacity(uris.len());
        for (u, kept) in uris.iter().zip(reuse) {
            list.push(match kept.and_then(|j| old.get(j)) {
                Some(entry) => entry.clone(),
                None => json!({
                    "uri": self.enc(&u.uri)?,
                    "match": u.match_type,
                    "uriChecksum": self.enc(&checksum(&u.uri))?,
                }),
            });
        }
        let list = if list.is_empty() { Value::Null } else { Value::Array(list) };
        edit_login(&mut self.body, |l| {
            l.insert("uris".into(), list);
        });
        Ok(())
    }
}

fn blob_uris(blob: &OpenBlob) -> &[Cbor] {
    match find(&blob.0, "typeData").and_then(|t| get(t, "uris")) {
        Some(Cbor::Array(uris)) => uris,
        _ => &[],
    }
}

/// Runs `change` on the blob's `typeData`, made a login's when it is no map.
fn edit_type_data(blob: &mut OpenBlob, change: impl FnOnce(&mut Vec<(Cbor, Cbor)>)) {
    let mut part = match take(&mut blob.0, "typeData") {
        Cbor::Map(part) => part,
        _ => vec![(Cbor::text("type"), Cbor::text("login"))],
    };
    change(&mut part);
    put(&mut blob.0, "typeData", Cbor::Map(part));
}

/// A blob's content in plaintext, edited in place: every key the core does not know stays as decoded.
impl Parts for OpenBlob {
    fn name_text(&self) -> Result<Zeroizing<String>, CryptoError> {
        Ok(copied(self.name()))
    }

    fn set_name(&mut self, value: &str) -> Result<(), CryptoError> {
        put(&mut self.0, "name", stored(value));
        Ok(())
    }

    fn login_text(&self, part: &str) -> Result<Zeroizing<String>, CryptoError> {
        Ok(copied(text(find(&self.0, "typeData").and_then(|t| get(t, part)))))
    }

    fn set_login_text(&mut self, part: &str, value: &str) -> Result<(), CryptoError> {
        edit_type_data(self, |t| put(t, part, stored(value)));
        Ok(())
    }

    fn uris(&self) -> Result<Vec<UriText>, CryptoError> {
        let kind = |u: &Cbor| match get(u, "match") {
            Some(Cbor::Uint(n)) => Some(*n),
            _ => None,
        };
        Ok(blob_uris(self).iter().map(|u| (copied(text(get(u, "uri"))), kind(u))).collect())
    }

    fn set_uris(&mut self, uris: &[&NewUri], reuse: &[Option<usize>]) -> Result<(), CryptoError> {
        let old = blob_uris(self).to_vec();
        let list: Vec<Cbor> = uris
            .iter()
            .zip(reuse)
            .map(|(u, kept)| match kept.and_then(|j| old.get(j)) {
                Some(entry) => entry.clone(),
                None => Cbor::Map(vec![
                    (Cbor::text("uri"), Cbor::text(u.uri.as_str())),
                    (Cbor::text("match"), u.match_type.map_or(Cbor::Null, Cbor::Uint)),
                ]),
            })
            .collect();
        let list = if list.is_empty() { Cbor::Null } else { Cbor::Array(list) };
        edit_type_data(self, |t| put(t, "uris", list));
        Ok(())
    }
}

/// `value` fits `max` as the body stores it (encrypted length, or a blob's plaintext length).
fn fits(body: &impl Body, value: &str, max: usize) -> Result<(), WriteError> {
    if body.stored_len(value) > max { Err(WriteError::TooLong) } else { Ok(()) }
}

/// Whether a tool's first `<ns>:location` says `notes` (§6.4): those notes are the tool's secret, any namespace's.
fn notes_held(body: &impl Body) -> Result<bool, CryptoError> {
    let names = body.names();
    for (i, name) in names.iter().enumerate() {
        let location =
            name.and_then(|n| n.split_once(':')).is_some_and(|(ns, rest)| !ns.is_empty() && rest == "location");
        // Only the first field of a name counts (§3.1).
        if location
            && names.iter().position(|n| n == name) == Some(i)
            && Mark::classify(Some(&body.value(i)?), "notes") == Mark::Set
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Sets the URI list when it differs from the item's. Returns whether it did.
fn write_uris<P: Parts>(body: &mut P, uris: &[NewUri]) -> Result<bool, WriteError> {
    let wanted: Vec<&NewUri> = uris.iter().filter(|u| !u.uri.is_empty()).collect();
    for u in &wanted {
        if u.match_type.is_some_and(|m| m > MATCH_MAX) {
            return Err(WriteError::BadUriMatch);
        }
        fits(body, &u.uri, MAX_URI_ENC)?;
    }
    let current = body.uris()?;
    let same = |u: &NewUri, (uri, kind): &UriText| *uri == u.uri && *kind == u.match_type;
    if wanted.len() == current.len() && wanted.iter().zip(&current).all(|(u, c)| same(u, c)) {
        return Ok(false);
    }
    let reuse: Vec<Option<usize>> = wanted.iter().map(|u| current.iter().position(|c| same(u, c))).collect();
    body.set_uris(&wanted, &reuse)?;
    Ok(true)
}

/// Applies `edit`'s parts to `body`; `now` dates a replaced password. Returns whether anything changed.
fn apply<P: Parts>(body: &mut P, edit: &ClientEdit, now: &str) -> Result<bool, WriteError> {
    let mut changed = false;
    if let Some(name) = &edit.name {
        if name.trim().is_empty() {
            return Err(WriteError::NameRequired);
        }
        fits(body, name, MAX_NAME_ENC)?;
        if body.name_text()? != *name {
            body.set_name(name)?;
            changed = true;
        }
    }
    if let Some(notes) = &edit.notes {
        fits(body, notes, MAX_NOTES_ENC)?;
        if body.notes_text()? != *notes {
            if notes_held(body)? {
                return Err(WriteError::NotesHeldByTool);
            }
            body.set_notes(notes)?;
            changed = true;
        }
    }
    if let Some(username) = &edit.username {
        fits(body, username, MAX_USERNAME_ENC)?;
        if body.login_text("username")? != *username {
            body.set_login_text("username", username)?;
            changed = true;
        }
    }
    if let Some(password) = &edit.password {
        fits(body, password, MAX_PASSWORD_ENC)?;
        if body.password_text()? != *password {
            body.replace_password(password, now)?;
            changed = true;
        }
    }
    if let Some(uris) = &edit.uris {
        changed |= write_uris(body, uris)?;
    }
    Ok(changed)
}

/// The checks before an edit or a trash; the key the item's own key is under.
fn owner_key<'k>(
    cipher: &Value,
    base_revision: &str,
    user: &'k SymmetricKey,
    orgs: &'k BTreeMap<String, SymmetricKey>,
) -> Result<&'k SymmetricKey, WriteError> {
    if trashed(cipher) {
        return Err(WriteError::Gone);
    }
    if cipher.get("revisionDate").and_then(Value::as_str) != Some(base_revision) {
        return Err(WriteError::OutOfDate);
    }
    if too_large(cipher) {
        return Err(WriteError::Uninspectable(Uninspectable::TooLarge));
    }
    if read_only(cipher) {
        return Err(WriteError::ReadOnly);
    }
    let Some(org) = organization(cipher) else { return Ok(user) };
    if is_blob(cipher) {
        return Err(WriteError::Uninspectable(Uninspectable::NewerFormat));
    }
    orgs.get(org.as_str().unwrap_or_default()).ok_or(WriteError::Uninspectable(Uninspectable::OrganizationKeyMissing))
}

/// The update body of `edit` on `cipher`, the server's current copy; `None` when the edit changes nothing, so nothing
/// is sent. `user` opens personal items and blobs, `orgs` (from `unlock_organizations`) organization items; `now_ms`
/// dates a replaced password. A blob stays a blob, sealed under a fresh content key.
pub fn edit(
    cipher: &Value,
    edit: &ClientEdit,
    user: &SymmetricKey,
    orgs: &BTreeMap<String, SymmetricKey>,
    rng: &impl Random,
    now_ms: i64,
) -> Result<Option<Map<String, Value>>, WriteError> {
    let owner = owner_key(cipher, &edit.base_revision, user, orgs)?;
    let login_parts = edit.username.is_some() || edit.password.is_some() || edit.uris.is_some();
    if login_parts && cipher.get("type").and_then(Value::as_u64) != Some(TYPE_LOGIN) {
        return Err(WriteError::NotALogin);
    }
    // The old password would move into the history, where this account could read it.
    if edit.password.is_some() && cipher.get("viewPassword") == Some(&Value::Bool(false)) {
        return Err(WriteError::PasswordHidden);
    }
    let now = iso_ms(now_ms)?;
    let key = item_key(cipher, owner)?;
    let folder = edit.folder_id.as_ref().filter(|f| f.as_deref() != cipher.get("folderId").and_then(Value::as_str));
    let mut body = if is_blob(cipher) {
        let mut blob = open_blob(cipher, owner).map_err(WriteError::Uninspectable)?;
        if !apply(&mut blob, edit, &now)? && folder.is_none() {
            return Ok(None);
        }
        blob_body(cipher, blob.seal(&key, rng)?, &edit.base_revision)
    } else {
        let mut fields = Fields::read(cipher, &key, rng)?;
        if !apply(&mut fields, edit, &now)? && folder.is_none() {
            return Ok(None);
        }
        fields.finish(&edit.base_revision)
    };
    if let Some(folder) = folder {
        body.insert("folderId".into(), json!(folder));
    }
    Ok(Some(body))
}

/// The checks before `cipher`, the server's current copy, moves to the trash: live, at `base_revision`, editable, and
/// readable with the keys given (an organization's, or not an organization blob). The trash endpoint takes no
/// revision, as in the official clients: an edit landing between this check and the trash is trashed too (it can be
/// restored; nothing is purged).
pub fn check_trash(
    cipher: &Value,
    base_revision: &str,
    user: &SymmetricKey,
    orgs: &BTreeMap<String, SymmetricKey>,
) -> Result<(), WriteError> {
    owner_key(cipher, base_revision, user, orgs).map(|_| ())
}

/// The new item's parts, through the same steps and limits as an edit; a new password has no history.
fn fill<P: Parts>(body: &mut P, entry: &NewEntry, login: Option<&NewLogin>) -> Result<(), WriteError> {
    let parts = ClientEdit {
        name: Some(entry.name.clone()),
        notes: Some(entry.notes.clone()),
        username: login.map(|l| l.username.clone()),
        uris: login.map(|l| l.uris.clone()),
        ..ClientEdit::default()
    };
    apply(body, &parts, "")?;
    for (part, value, max) in
        login.iter().flat_map(|l| [("password", &l.password, MAX_PASSWORD_ENC), ("totp", &l.totp, MAX_TOTP_ENC)])
    {
        fits(body, value, max)?;
        body.set_login_text(part, value)?;
    }
    Ok(())
}

/// Body of the create request for `entry`: always personal. A blob under a fresh item key when `security_version`
/// (the verified security state's, ADR 0019) is at `BLOB_SECURITY_VERSION` or higher, as the SDK seals one (ADR 0021);
/// field-level under the user key otherwise.
pub fn create(
    entry: &NewEntry,
    user: &SymmetricKey,
    security_version: u64,
    rng: &impl Random,
) -> Result<Map<String, Value>, WriteError> {
    let (kind, login) = match &entry.kind {
        NewKind::Login(l) => (TYPE_LOGIN, Some(l)),
        NewKind::SecureNote => (TYPE_SECURE_NOTE, None),
    };
    let mut body = Map::new();
    for (k, v) in [
        ("type", json!(kind)),
        ("organizationId", Value::Null),
        ("folderId", json!(entry.folder_id)),
        ("favorite", json!(false)),
        ("reprompt", json!(0)),
        ("name", Value::Null),
        ("notes", Value::Null),
        ("login", Value::Null),
        ("secureNote", if login.is_some() { Value::Null } else { json!({ "type": 0 }) }),
        ("fields", json!([])),
        ("passwordHistory", json!([])),
    ] {
        body.insert(k.into(), v);
    }
    if security_version >= BLOB_SECURITY_VERSION {
        // The SDK's login `typeData`, every string null until `fill`.
        let null = |k: &str| (Cbor::text(k), Cbor::Null);
        let mut blob = match login {
            Some(_) => OpenBlob(vec![
                null("name"),
                null("notes"),
                (
                    Cbor::text("typeData"),
                    Cbor::Map(vec![
                        (Cbor::text("type"), Cbor::text("login")),
                        null("username"),
                        null("password"),
                        null("passwordRevisionDate"),
                        null("totp"),
                        null("autofillOnPageLoad"),
                    ]),
                ),
            ]),
            None => OpenBlob::new_note(""),
        };
        fill(&mut blob, entry, login)?;
        let item_key = SymmetricKey::generate(rng)?;
        let data = blob.seal(&item_key, rng)?;
        let key = user.encrypt_as(&item_key.to_bytes(), ContentFormat::LegacyKey, rng)?;
        // The type data lives in the blob's `typeData`: the SDK sends every legacy part null.
        for k in ["name", "notes", "login", "secureNote", "fields", "passwordHistory"] {
            body.insert(k.into(), Value::Null);
        }
        body.insert("key".into(), json!(key));
        body.insert("data".into(), json!(data));
        return Ok(body);
    }
    body.insert("key".into(), Value::Null);
    let mut fields = Fields { key: user, rng, body, fields: Vec::new() };
    fill(&mut fields, entry, login)?;
    Ok(fields.body)
}

#[cfg(test)]
#[path = "client_tests.rs"]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod tests;
