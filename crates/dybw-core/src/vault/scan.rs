//! Discovery and reading (data model §4, §5) and duplicates (§7): port of bwss `src/bw/scan.rs` and the plugin's
//! `readVault`. Only an item with a non-blank marker is read past its field names.

use super::fields::{Mark, decrypt_opt, field_names, field_value, first_index, item_key};
use super::namespace::{Encodings, IdProblem, Namespace};
use super::{Keys, Organizations};
use crate::crypto::{CryptoError, SymmetricKey};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroizing;

const TYPE_LOGIN: u64 = 1;
const TYPE_SECURE_NOTE: u64 = 2;

/// Where a marked item's secret was read from (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSource {
    /// `{ns}:password`.
    Field,
    /// The notes, because of `{ns}:location=notes`.
    Notes,
    LoginPassword,
    /// A secure note's own text.
    NoteBody,
}

impl ValueSource {
    pub fn code(self) -> &'static str {
        match self {
            ValueSource::Field => "field",
            ValueSource::Notes => "notes",
            ValueSource::LoginPassword => "login-password",
            ValueSource::NoteBody => "note-body",
        }
    }
}

/// A marked item the tool does not read; reported (the vectors' reason codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    WrongType,
    EncodingOnUserSource,
    UnknownLocation,
    UnknownEncoding,
    InvalidId,
    ReservedId,
    ViewPasswordHidden,
    InvalidBase64,
}

impl SkipReason {
    pub fn code(self) -> &'static str {
        match self {
            SkipReason::WrongType => "wrong-type",
            SkipReason::EncodingOnUserSource => "encoding-on-user-source",
            SkipReason::UnknownLocation => "unknown-location",
            SkipReason::UnknownEncoding => "unknown-encoding",
            SkipReason::InvalidId => "invalid-id",
            SkipReason::ReservedId => "reserved-id",
            SkipReason::ViewPasswordHidden => "view-password-hidden",
            SkipReason::InvalidBase64 => "invalid-base64",
        }
    }
}

/// Why a live cipher cannot be inspected; it is held, never treated as deleted (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uninspectable {
    OrganizationNotRead,
    OrganizationKeyMissing,
    ItemKey,
    FieldNames,
    Marker,
    Value,
    /// A blob cipher (`data` with `format_version`), which no tool reads yet.
    NewerFormat,
}

/// A marked, readable item. No `Clone`; `Debug` shows neither the value nor tool field values.
pub struct MarkedItem {
    pub cipher_id: String,
    pub revision_date: String,
    /// `creationDate` in Unix milliseconds; `None` when absent or unparseable.
    pub creation_date: Option<i64>,
    pub organization_id: Option<String>,
    /// An organization item the user may not edit.
    pub read_only: bool,
    /// The trimmed `{ns}:id`.
    pub id: String,
    pub source: ValueSource,
    /// The secret, base64-decoded under `{ns}:encoding=base64`.
    pub value: Zeroizing<Vec<u8>>,
    /// Mark of the stored text: decrypted, before any base64 decoding.
    pub mark: [u8; 32],
    /// Stored lookup attributes (§3.4): name after `{ns}:attr:`, value as stored; the first of a name counts.
    pub attributes: BTreeMap<String, String>,
    /// The first of each other `{ns}:*` field (`bwss:label`, `obsidian:scope`, ...), decrypted.
    pub tool_fields: Vec<(String, Zeroizing<String>)>,
    /// The cipher as the server sent it, still encrypted.
    pub cipher: Value,
}

impl fmt::Debug for MarkedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MarkedItem")
            .field("cipher_id", &self.cipher_id)
            .field("id", &self.id)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum Scan {
    /// No marker (or a blank one), or in the trash.
    Unmarked,
    Marked(Box<MarkedItem>),
    Skipped(SkipReason),
    Uninspectable(Uninspectable),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Duplicate {
    pub id: String,
    pub kept: String,
    /// Sorted cipher ids.
    pub left: Vec<String>,
}

#[derive(Debug)]
pub struct ScanReport {
    /// One per id after §7, sorted by id.
    pub items: Vec<MarkedItem>,
    pub skipped: Vec<(String, SkipReason)>,
    pub uninspectable: Vec<(String, Uninspectable)>,
    pub duplicates: Vec<Duplicate>,
    /// Marked (skipped and duplicate losers included) or uninspectable cipher ids: a readable cipher without its
    /// marker counts as deleted (§8.1), an uninspectable one is held (§4).
    pub present: BTreeSet<String>,
}

fn trashed(cipher: &Value) -> bool {
    cipher.get("deletedDate").is_some_and(|d| !d.is_null())
}

/// Bitwarden's blob form, with the SDK's own gate: `data` parses as a JSON object holding a `format_version` key
/// (sdk-internal 3d16437, bitwarden-vault/src/cipher/blob/sealed.rs from_opaque_string). Whatever else it holds,
/// the SDK cannot read it either, so it is held.
fn is_blob(cipher: &Value) -> bool {
    cipher
        .get("data")
        .and_then(Value::as_str)
        .and_then(|d| serde_json::from_str::<Value>(d).ok())
        .is_some_and(|v| v.as_object().is_some_and(|o| o.contains_key("format_version")))
}

/// Unix milliseconds; at or before the epoch counts as undated, as bwss.
fn parse_date(s: &str) -> Option<i64> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok().filter(|&ms| ms > 0)
}

pub fn scan(cipher: &Value, ns: &Namespace, keys: &Keys, allowed: &Organizations) -> Scan {
    if trashed(cipher) {
        return Scan::Unmarked;
    }
    if is_blob(cipher) {
        return Scan::Uninspectable(Uninspectable::NewerFormat);
    }
    // Any non-null organizationId is an organization item (bwss), even "" (which the plugin read as personal).
    let org = cipher.get("organizationId").filter(|o| !o.is_null());
    let owner = match org {
        None => &keys.user,
        Some(org) => {
            let org = org.as_str().unwrap_or_default();
            if !allowed.allows(org) {
                return Scan::Uninspectable(Uninspectable::OrganizationNotRead);
            }
            match keys.orgs.get(org) {
                Some(k) => k,
                None => return Scan::Uninspectable(Uninspectable::OrganizationKeyMissing),
            }
        }
    };
    let Ok(key) = item_key(cipher, owner) else { return Scan::Uninspectable(Uninspectable::ItemKey) };
    let Ok(names) = field_names(cipher, &key) else { return Scan::Uninspectable(Uninspectable::FieldNames) };
    let Some(id_index) = first_index(&names, &ns.field("id")) else { return Scan::Unmarked };
    let Ok(id) = field_value(cipher, id_index, &key) else { return Scan::Uninspectable(Uninspectable::Marker) };
    let id = id.trim().to_owned();
    if id.is_empty() {
        return Scan::Unmarked;
    }
    let org = org.map(|o| o.as_str().unwrap_or_default().to_owned());
    read_marked(cipher, ns, &key, keys, &names, id, org).unwrap_or(Scan::Uninspectable(Uninspectable::Value))
}

fn read_marked(
    cipher: &Value,
    ns: &Namespace,
    key: &SymmetricKey,
    keys: &Keys,
    names: &[Option<String>],
    id: String,
    org: Option<String>,
) -> Result<Scan, CryptoError> {
    let ty = cipher.get("type").and_then(Value::as_u64);
    if ty != Some(TYPE_LOGIN) && ty != Some(TYPE_SECURE_NOTE) {
        return Ok(Scan::Skipped(SkipReason::WrongType));
    }
    if org.is_some() && cipher.get("viewPassword") == Some(&Value::Bool(false)) {
        return Ok(Scan::Skipped(SkipReason::ViewPasswordHidden));
    }
    match (ns.id_rule)(&id) {
        Ok(()) => {}
        Err(IdProblem::Invalid) => return Ok(Scan::Skipped(SkipReason::InvalidId)),
        Err(IdProblem::Reserved) => return Ok(Scan::Skipped(SkipReason::ReservedId)),
    }
    let field = |name: &str| -> Result<Option<Zeroizing<String>>, CryptoError> {
        first_index(names, &ns.field(name)).map(|i| field_value(cipher, i, key)).transpose()
    };

    let encoding = field("encoding")?;
    let encoding = Mark::classify(encoding.as_deref().map(String::as_str), "base64");
    // A namespace without encodings reports every non-blank mark first (README reason table).
    if ns.encodings == Encodings::None && encoding != Mark::Absent {
        return Ok(Scan::Skipped(SkipReason::UnknownEncoding));
    }
    let location = field("location")?;
    let in_notes = match Mark::classify(location.as_deref().map(String::as_str), "notes") {
        Mark::Absent => false,
        Mark::Set => true,
        Mark::Unknown => return Ok(Scan::Skipped(SkipReason::UnknownLocation)),
    };
    let base64 = match encoding {
        Mark::Absent => false,
        Mark::Set => true,
        Mark::Unknown => return Ok(Scan::Skipped(SkipReason::UnknownEncoding)),
    };

    // The value source: the first present one (§5).
    let password_index = first_index(names, &ns.field("password"));
    let source = match password_index {
        Some(_) => ValueSource::Field,
        None if in_notes => ValueSource::Notes,
        None if ty == Some(TYPE_SECURE_NOTE) => ValueSource::NoteBody,
        None => ValueSource::LoginPassword,
    };
    // Never decrypt (or decode) a value the user owns when base64 is asked of it (ADR 0005).
    if base64 && matches!(source, ValueSource::LoginPassword | ValueSource::NoteBody) {
        return Ok(Scan::Skipped(SkipReason::EncodingOnUserSource));
    }
    let text = match (password_index, source) {
        (Some(i), _) => field_value(cipher, i, key)?,
        (None, ValueSource::LoginPassword) => decrypt_opt(cipher.pointer("/login/password"), key)?,
        (None, _) => decrypt_opt(cipher.get("notes"), key)?,
    };
    let value = if base64 {
        match B64.decode(text.as_bytes()) {
            Ok(b) => Zeroizing::new(b),
            Err(_) => return Ok(Scan::Skipped(SkipReason::InvalidBase64)),
        }
    } else {
        Zeroizing::new(text.as_bytes().to_vec())
    };
    // Over the decrypted text, never the ciphertext: clients re-encrypt every value with a fresh IV on any save.
    let mark = keys.marker.mark(&id, &text);

    let prefix = ns.field("");
    let attr_prefix = ns.field("attr:");
    let own = ["id", "password", "location", "encoding"].map(|n| ns.field(n));
    let mut attributes = BTreeMap::new();
    let mut tool_fields: Vec<(String, Zeroizing<String>)> = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let Some(name) = name.as_deref().filter(|n| n.starts_with(&prefix)) else { continue };
        if let Some(attr) = name.strip_prefix(&attr_prefix) {
            if !attr.is_empty() && !attributes.contains_key(attr) {
                attributes.insert(attr.to_owned(), field_value(cipher, i, key)?.as_str().to_owned());
            }
        } else if !own.iter().any(|o| o == name) && !tool_fields.iter().any(|(n, _)| n == name) {
            tool_fields.push((name.to_owned(), field_value(cipher, i, key)?));
        }
    }

    let text_at = |k: &str| cipher.get(k).and_then(Value::as_str);
    Ok(Scan::Marked(Box::new(MarkedItem {
        cipher_id: text_at("id").unwrap_or_default().to_owned(),
        revision_date: text_at("revisionDate").unwrap_or_default().to_owned(),
        creation_date: text_at("creationDate").and_then(parse_date),
        read_only: org.is_some() && cipher.get("edit") == Some(&Value::Bool(false)),
        organization_id: org,
        id,
        source,
        value,
        mark,
        attributes,
        tool_fields,
        cipher: cipher.clone(),
    })))
}

/// Picks one item per id (§7): a personal item over an organization one, then a dated one over an undated one,
/// then the oldest, then the lowest cipher id, so every device chooses alike. Winners and duplicates by id.
pub(crate) fn resolve_duplicates(mut items: Vec<MarkedItem>) -> (Vec<MarkedItem>, Vec<Duplicate>) {
    let rank = |m: &MarkedItem| (m.organization_id.is_some(), m.creation_date.is_none(), m.creation_date);
    items.sort_by(|a, b| {
        a.id.cmp(&b.id).then_with(|| rank(a).cmp(&rank(b))).then_with(|| a.cipher_id.cmp(&b.cipher_id))
    });
    let mut winners: Vec<MarkedItem> = Vec::new();
    let mut duplicates: Vec<Duplicate> = Vec::new();
    for item in items {
        match winners.last() {
            Some(kept) if kept.id == item.id => match duplicates.last_mut() {
                Some(d) if d.id == item.id => d.left.push(item.cipher_id),
                _ => {
                    duplicates.push(Duplicate { id: item.id, kept: kept.cipher_id.clone(), left: vec![item.cipher_id] })
                }
            },
            _ => winners.push(item),
        }
    }
    for d in &mut duplicates {
        d.left.sort();
    }
    (winners, duplicates)
}

/// Scans every cipher of a `/sync` response.
pub fn scan_vault(sync: &Value, ns: &Namespace, keys: &Keys, allowed: &Organizations) -> ScanReport {
    let mut marked = Vec::new();
    let mut skipped = Vec::new();
    let mut uninspectable = Vec::new();
    let mut present = BTreeSet::new();
    for cipher in sync.get("ciphers").and_then(Value::as_array).map_or(&[][..], Vec::as_slice) {
        let cipher_id = cipher.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
        let result = scan(cipher, ns, keys, allowed);
        if !matches!(result, Scan::Unmarked) {
            present.insert(cipher_id.clone());
        }
        match result {
            Scan::Unmarked => {}
            Scan::Marked(m) => marked.push(*m),
            Scan::Skipped(r) => skipped.push((cipher_id, r)),
            Scan::Uninspectable(u) => uninspectable.push((cipher_id, u)),
        }
    }
    let (items, duplicates) = resolve_duplicates(marked);
    ScanReport { items, skipped, uninspectable, duplicates, present }
}
