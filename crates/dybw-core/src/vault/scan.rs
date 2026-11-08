//! Discovery and reading (data model §4, §5) and duplicates (§7): port of bwss `src/bw/scan.rs` and the plugin's
//! `readVault`. Only an item with a non-blank marker is read past its field names; a personal blob is opened whole
//! (ADR 0021), and only its field names are looked at until then.

use super::blob::{OpenBlob, open_blob};
use super::fields::{Mark, decrypt_opt, field_names, field_value, first_index, item_key};
use super::namespace::{Encodings, IdProblem, Namespace};
use super::{Keys, Organizations};
use crate::crypto::{CryptoError, SymmetricKey};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroizing;

pub(crate) const TYPE_LOGIN: u64 = 1;
pub(crate) const TYPE_SECURE_NOTE: u64 = 2;

/// Where a marked item's secret was read from (§5). Serialized as its code, for the write queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
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
    /// A feature of `dybw:requires` the tool does not implement (ADR 0020): the item is held, never used or cleared.
    NewerFormat,
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
            SkipReason::NewerFormat => "newer-format",
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
    /// A blob cipher (`data` with `format_version`) the core does not read: an organization blob, or a
    /// `format_version` or content version other than 1.
    NewerFormat,
    /// A personal blob whose item key, content key or envelope fails, or whose content is malformed (ADR 0021).
    Blob,
    /// A cipher whose JSON is longer than `MAX_CIPHER` (ADR 0019): never decrypted.
    TooLarge,
}

/// Largest cipher, as its JSON, that is read (ADR 0019).
pub const MAX_CIPHER: usize = 1024 * 1024;

/// Whether the cipher's JSON is longer than `MAX_CIPHER`.
pub(crate) fn too_large(cipher: &Value) -> bool {
    serde_json::to_vec(cipher).is_ok_and(|v| v.len() > MAX_CIPHER)
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
    /// `kept` is the cipher the device's base binds to the id, though §7 would pick another (ADR 0019).
    pub bound_kept: bool,
}

#[derive(Debug)]
pub struct ScanReport {
    /// One per id after §7, sorted by id.
    pub items: Vec<MarkedItem>,
    pub skipped: Vec<(String, SkipReason)>,
    pub uninspectable: Vec<(String, Uninspectable)>,
    pub duplicates: Vec<Duplicate>,
    /// Cipher id and the sorted `dybw:requires` names the tool does not implement; those items are in `skipped`.
    pub unknown_features: Vec<(String, Vec<String>)>,
    /// Marked (skipped and duplicate losers included) or uninspectable cipher ids: a readable cipher without its
    /// marker counts as deleted (§8.1), an uninspectable one is held (§4).
    pub present: BTreeSet<String>,
    /// `{ns}:id`s read from ciphers then skipped or left uninspectable: such an item holds its id (ADR 0020). A cipher
    /// whose marker cannot be read names no id, so it is not here.
    pub held_ids: BTreeSet<String>,
}

/// The cipher's `organizationId` when it is an organization item: any non-null value (bwss), even `""` (which the
/// plugin read as personal).
pub(crate) fn organization(cipher: &Value) -> Option<&Value> {
    cipher.get("organizationId").filter(|o| !o.is_null())
}

/// An organization item this account may only read (§9).
pub(crate) fn read_only(cipher: &Value) -> bool {
    organization(cipher).is_some() && cipher.get("edit") == Some(&Value::Bool(false))
}

/// A login or a secure note: the only item types a tool reads or writes.
pub(crate) fn supported_type(cipher: &Value) -> bool {
    matches!(cipher.get("type").and_then(Value::as_u64), Some(TYPE_LOGIN | TYPE_SECURE_NOTE))
}

pub(crate) fn trashed(cipher: &Value) -> bool {
    cipher.get("deletedDate").is_some_and(|d| !d.is_null())
}

/// Bitwarden's blob form, with the SDK's own gate: `data` parses as a JSON object holding a `format_version` key
/// (sdk-internal 3d16437, bitwarden-vault/src/cipher/blob/sealed.rs from_opaque_string). Whatever else it holds,
/// the SDK cannot read it either, so it is held.
pub(crate) fn is_blob(cipher: &Value) -> bool {
    cipher
        .get("data")
        .and_then(Value::as_str)
        .and_then(|d| serde_json::from_str::<Value>(d).ok())
        .is_some_and(|v| v.as_object().is_some_and(|o| o.contains_key("format_version")))
}

/// Unix milliseconds; at or before the epoch counts as undated, as bwss.
pub(crate) fn parse_date(s: &str) -> Option<i64> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok().filter(|&ms| ms > 0)
}

/// Where a cipher's field values and value sources come from: its own encrypted strings, or its opened blob. Both
/// formats run the same rules (§4, §5) through it.
enum Item<'a> {
    Fields(&'a Value, &'a SymmetricKey),
    Blob(&'a OpenBlob),
}

pub(super) fn copied(text: Option<&str>) -> Zeroizing<String> {
    Zeroizing::new(text.unwrap_or_default().to_owned())
}

impl Item<'_> {
    fn value(&self, index: usize) -> Result<Zeroizing<String>, CryptoError> {
        match self {
            Item::Fields(cipher, key) => field_value(cipher, index, key),
            Item::Blob(blob) => Ok(copied(blob.field_value(index))),
        }
    }

    fn notes(&self) -> Result<Zeroizing<String>, CryptoError> {
        match self {
            Item::Fields(cipher, key) => decrypt_opt(cipher.get("notes"), key),
            Item::Blob(blob) => Ok(copied(blob.notes())),
        }
    }

    fn login_password(&self) -> Result<Zeroizing<String>, CryptoError> {
        match self {
            Item::Fields(cipher, key) => decrypt_opt(cipher.pointer("/login/password"), key),
            Item::Blob(blob) => Ok(copied(blob.login_password())),
        }
    }
}

pub fn scan(cipher: &Value, ns: &Namespace, keys: &Keys, allowed: &Organizations) -> Scan {
    scan_noting(cipher, ns, keys, allowed, &mut Noted::default())
}

/// What a scan read of a cipher besides its result.
#[derive(Default)]
pub(crate) struct Noted {
    /// The `{ns}:id`, once read.
    pub(crate) id: Option<String>,
    /// The unknown `dybw:requires` names of an item skipped for them.
    unknown: Vec<String>,
}

/// `scan`, also filling `noted`.
pub(crate) fn scan_noting(
    cipher: &Value,
    ns: &Namespace,
    keys: &Keys,
    allowed: &Organizations,
    noted: &mut Noted,
) -> Scan {
    if trashed(cipher) {
        return Scan::Unmarked;
    }
    if too_large(cipher) {
        return Scan::Uninspectable(Uninspectable::TooLarge);
    }
    let org = organization(cipher);
    if is_blob(cipher) {
        // The SDK never seals an organization item as a blob: one is held, never decrypted (ADR 0021).
        if org.is_some() {
            return Scan::Uninspectable(Uninspectable::NewerFormat);
        }
        // Dropped, and every decoded text wiped, before this returns (§4.2).
        let blob = match open_blob(cipher, &keys.user) {
            Ok(blob) => blob,
            Err(u) => return Scan::Uninspectable(u),
        };
        return discover(cipher, ns, keys, &Item::Blob(&blob), &blob.field_names(), None, noted);
    }
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
    let names: Vec<Option<&str>> = names.iter().map(Option::as_deref).collect();
    let org = org.map(|o| o.as_str().unwrap_or_default().to_owned());
    discover(cipher, ns, keys, &Item::Fields(cipher, &key), &names, org, noted)
}

/// Steps 3 and 4 of §4 on the field names: the marker, then the item.
fn discover(
    cipher: &Value,
    ns: &Namespace,
    keys: &Keys,
    item: &Item,
    names: &[Option<&str>],
    org: Option<String>,
    noted: &mut Noted,
) -> Scan {
    let Some(id_index) = first_index(names, &ns.field("id")) else { return Scan::Unmarked };
    let Ok(id) = item.value(id_index) else { return Scan::Uninspectable(Uninspectable::Marker) };
    let id = id.trim().to_owned();
    if id.is_empty() {
        return Scan::Unmarked;
    }
    noted.id = Some(id.clone());
    // Before any other value is read (ADR 0020).
    match unknown_features(ns, item, names) {
        Ok(found) if found.is_empty() => {}
        Ok(found) => {
            noted.unknown = found;
            return Scan::Skipped(SkipReason::NewerFormat);
        }
        Err(_) => return Scan::Uninspectable(Uninspectable::Value),
    }
    read_marked(cipher, ns, item, keys, names, id, org).unwrap_or(Scan::Uninspectable(Uninspectable::Value))
}

/// The considered names of the first `dybw:requires` field that the namespace does not implement, sorted (ADR 0020):
/// one per line, trimmed; only `{ns}:` and `dybw:` names count.
fn unknown_features(ns: &Namespace, item: &Item, names: &[Option<&str>]) -> Result<Vec<String>, CryptoError> {
    let Some(index) = first_index(names, "dybw:requires") else { return Ok(Vec::new()) };
    let text = item.value(index)?;
    let own = ns.field("");
    let found: BTreeSet<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| (l.starts_with(&own) || l.starts_with("dybw:")) && !ns.features.contains(l))
        .collect();
    Ok(found.into_iter().map(str::to_owned).collect())
}

fn read_marked(
    cipher: &Value,
    ns: &Namespace,
    item: &Item,
    keys: &Keys,
    names: &[Option<&str>],
    id: String,
    org: Option<String>,
) -> Result<Scan, CryptoError> {
    let ty = cipher.get("type").and_then(Value::as_u64);
    if !supported_type(cipher) {
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
        first_index(names, &ns.field(name)).map(|i| item.value(i)).transpose()
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
        (Some(i), _) => item.value(i)?,
        (None, ValueSource::LoginPassword) => item.login_password()?,
        (None, _) => item.notes()?,
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
        let Some(name) = name.filter(|n| n.starts_with(&prefix)) else { continue };
        if let Some(attr) = name.strip_prefix(&attr_prefix) {
            if !attr.is_empty() && !attributes.contains_key(attr) {
                attributes.insert(attr.to_owned(), item.value(i)?.as_str().to_owned());
            }
        } else if !own.iter().any(|o| o == name) && !tool_fields.iter().any(|(n, _)| n == name) {
            tool_fields.push((name.to_owned(), item.value(i)?));
        }
    }

    let text_at = |k: &str| cipher.get(k).and_then(Value::as_str);
    Ok(Scan::Marked(Box::new(MarkedItem {
        cipher_id: text_at("id").unwrap_or_default().to_owned(),
        revision_date: text_at("revisionDate").unwrap_or_default().to_owned(),
        creation_date: text_at("creationDate").and_then(parse_date),
        read_only: read_only(cipher),
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

/// The §7 order of two copies of one item: the smaller wins. Shared by the scan and by queued ops, so both pick
/// the same cipher.
/// An item's name, login username and first URI, for labels and derived attributes. `Debug` shows none of them.
#[derive(Default)]
pub struct ItemMeta {
    pub name: Option<Zeroizing<String>>,
    pub username: Option<Zeroizing<String>>,
    pub uri: Option<Zeroizing<String>>,
}

impl fmt::Debug for ItemMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ItemMeta(<redacted>)")
    }
}

/// Reads the name, username and first URI of a marked item from its encrypted copy (the blob opened again, nothing
/// else of it kept). A part that is absent or does not decrypt is `None`; the secret value is never read.
pub fn item_meta(item: &MarkedItem, keys: &Keys) -> ItemMeta {
    let owner = match &item.organization_id {
        None => Some(&keys.user),
        Some(org) => keys.orgs.get(org),
    };
    owner.and_then(|owner| meta_under(&item.cipher, owner)).unwrap_or_default()
}

fn meta_under(cipher: &Value, owner: &SymmetricKey) -> Option<ItemMeta> {
    let own = |s: Option<&str>| s.map(|s| Zeroizing::new(s.to_owned()));
    if is_blob(cipher) {
        let blob = open_blob(cipher, owner).ok()?;
        return Some(ItemMeta {
            name: own(blob.name()),
            username: own(blob.login_username()),
            uri: own(blob.login_uri()),
        });
    }
    let key = item_key(cipher, owner).ok()?;
    let part = |pointer: &str| {
        let sealed = cipher.pointer(pointer)?.as_str()?;
        key.decrypt_str(sealed).ok()
    };
    Some(ItemMeta { name: part("/name"), username: part("/login/username"), uri: part("/login/uris/0/uri") })
}

pub(crate) fn duplicate_order(a: &MarkedItem, b: &MarkedItem) -> std::cmp::Ordering {
    let rank = |m: &MarkedItem| (m.organization_id.is_some(), m.creation_date.is_none(), m.creation_date);
    rank(a).cmp(&rank(b)).then_with(|| a.cipher_id.cmp(&b.cipher_id))
}

/// Picks one item per id (§7): a personal item over an organization one, then a dated one over an undated one,
/// then the oldest, then the lowest cipher id, so every device chooses alike. A cipher `bound` to its id (the base's
/// binding, id to cipher id) that is among the items stays the winner instead (ADR 0019). Winners and duplicates by id.
pub(crate) fn resolve_duplicates(
    mut items: Vec<MarkedItem>,
    bound: &BTreeMap<String, String>,
) -> (Vec<MarkedItem>, Vec<Duplicate>) {
    items.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| duplicate_order(a, b)));
    let mut winners: Vec<MarkedItem> = Vec::new();
    let mut duplicates: Vec<Duplicate> = Vec::new();
    let mut items = items.into_iter().peekable();
    while let Some(mut winner) = items.next() {
        let mut rest: Vec<MarkedItem> = Vec::new();
        while let Some(copy) = items.next_if(|i| i.id == winner.id) {
            rest.push(copy);
        }
        let held = bound.get(&winner.id).and_then(|b| rest.iter().position(|i| i.cipher_id == *b));
        if let Some(at) = held {
            let kept = rest.swap_remove(at);
            rest.push(std::mem::replace(&mut winner, kept));
        }
        if !rest.is_empty() {
            let mut left: Vec<String> = rest.into_iter().map(|i| i.cipher_id).collect();
            left.sort();
            duplicates.push(Duplicate {
                id: winner.id.clone(),
                kept: winner.cipher_id.clone(),
                left,
                bound_kept: held.is_some(),
            });
        }
        winners.push(winner);
    }
    (winners, duplicates)
}

/// The ciphers the last scan found unmarked, by `(cipher id, revisionDate)` (data model §4, §4.2): an unchanged one
/// is not decrypted again, not even its field names. Device state (§10): ids and dates only. It is per namespace and
/// per account: never share one across them, since a cipher unmarked for one may be marked for another.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct UnmarkedCache(BTreeSet<(String, String)>);

/// Scans every cipher of a `/sync` response.
pub fn scan_vault(sync: &Value, ns: &Namespace, keys: &Keys, allowed: &Organizations) -> ScanReport {
    scan_vault_with(sync, ns, keys, allowed, &|_| true, &mut UnmarkedCache::default(), &BTreeMap::new())
}

/// `scan_vault` keeping only the marked items `applies` takes, before §7 picks one per id (the plugin filters by
/// scope first). Items left out still count as `present`. A cipher in `cache` is unmarked without being opened;
/// afterwards `cache` holds exactly the ciphers of this response that are unmarked. `bound` is the device's base,
/// `{ns}:id` to cipher id: a bound cipher still marked and readable keeps its id against §7 (ADR 0019).
pub fn scan_vault_with(
    sync: &Value,
    ns: &Namespace,
    keys: &Keys,
    allowed: &Organizations,
    applies: &dyn Fn(&MarkedItem) -> bool,
    cache: &mut UnmarkedCache,
    bound: &BTreeMap<String, String>,
) -> ScanReport {
    let mut marked = Vec::new();
    let mut skipped = Vec::new();
    let mut uninspectable = Vec::new();
    let mut unknown_features = Vec::new();
    let mut present = BTreeSet::new();
    let mut held_ids = BTreeSet::new();
    let mut unmarked = BTreeSet::new();
    // Every marked cipher's id, `applies` or not: tells a bound cipher that moved to another id from one that
    // still holds its own.
    let mut marked_as: BTreeMap<String, String> = BTreeMap::new();
    for cipher in sync.get("ciphers").and_then(Value::as_array).map_or(&[][..], Vec::as_slice) {
        let cipher_id = cipher.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
        // Without an id and a revision a cipher cannot be told apart: never cached.
        let revision = cipher.get("revisionDate").and_then(Value::as_str).filter(|r| !r.is_empty());
        let seen = revision.filter(|_| !cipher_id.is_empty()).map(|r| (cipher_id.clone(), r.to_owned()));
        let mut noted = Noted::default();
        let result = match &seen {
            Some(seen) if cache.0.contains(seen) => Scan::Unmarked,
            _ => scan_noting(cipher, ns, keys, allowed, &mut noted),
        };
        if !noted.unknown.is_empty() {
            unknown_features.push((cipher_id.clone(), noted.unknown));
        }
        if matches!(result, Scan::Unmarked) {
            unmarked.extend(seen);
        } else {
            present.insert(cipher_id.clone());
        }
        if let Scan::Marked(m) = &result {
            marked_as.insert(cipher_id.clone(), m.id.clone());
        }
        match result {
            Scan::Unmarked => {}
            Scan::Marked(m) if applies(&m) => marked.push(*m),
            Scan::Marked(_) => {}
            Scan::Skipped(r) => {
                held_ids.extend(noted.id);
                skipped.push((cipher_id, r));
            }
            Scan::Uninspectable(u) => {
                held_ids.extend(noted.id);
                uninspectable.push((cipher_id, u));
            }
        }
    }
    cache.0 = unmarked;
    let (mut items, duplicates) = resolve_duplicates(marked, bound);
    // A bound cipher that is still there and still this id's (or cannot be inspected) but did not win (held,
    // skipped, out of scope) keeps its id held: no copy of it is taken instead (ADR 0019).
    items.retain(|i| {
        bound.get(&i.id).is_none_or(|a| {
            *a == i.cipher_id || !present.contains(a) || marked_as.get(a).is_some_and(|other| *other != i.id)
        })
    });
    ScanReport { items, skipped, uninspectable, duplicates, unknown_features, present, held_ids }
}
