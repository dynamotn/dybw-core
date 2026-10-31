//! Blob ciphers (ADR 0021, data model §4.2): opening, discovery through the field-level rules, and the cache of
//! unmarked ciphers.

use super::blob::{self, OpenBlob, open_blob};
use super::scan::{Scan, SkipReason, Uninspectable, UnmarkedCache, ValueSource, scan, scan_vault_with};
use super::*;
use crate::crypto::{Cbor, EnvelopeNamespace, MarkScheme, Marker, SymmetricKey, seal_envelope};
use crate::testing::{SeededRandom, cbor_texts_alive};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) struct Bx {
    pub(super) rng: SeededRandom,
    pub(super) keys: Keys,
}

pub(super) fn t(s: &str) -> Cbor {
    Cbor::text(s)
}

fn opt(s: Option<&str>) -> Cbor {
    s.map_or(Cbor::Null, t)
}

/// `CipherBlobV1` with a login `typeData`.
pub(super) fn login(fields: &[(&str, &str)], password: Option<&str>, notes: Option<&str>) -> Cbor {
    let fields = fields
        .iter()
        .map(|(n, v)| {
            Cbor::Map(vec![
                (t("name"), t(n)),
                (t("value"), t(v)),
                (t("type"), Cbor::Uint(0)),
                (t("linkedId"), Cbor::Null),
            ])
        })
        .collect();
    Cbor::Map(vec![
        (t("name"), t("Blob")),
        (t("notes"), opt(notes)),
        (
            t("typeData"),
            Cbor::Map(vec![(t("type"), t("login")), (t("username"), t("me")), (t("password"), opt(password))]),
        ),
        (t("fields"), Cbor::Array(fields)),
    ])
}

pub(super) fn versioned(content: Cbor) -> Cbor {
    Cbor::Map(vec![(t("version"), t("1")), (t("content"), content)])
}

impl Bx {
    pub(super) fn new() -> Bx {
        let rng = SeededRandom::new(21);
        let user = SymmetricKey::generate(&rng).unwrap();
        let org = SymmetricKey::generate(&rng).unwrap();
        let marker = Marker::new(&user, MarkScheme::Bwss);
        Bx { rng, keys: Keys { user, orgs: BTreeMap::from([("org1".to_owned(), org)]), marker, security_version: 2 } }
    }

    /// A cipher whose `data` seals `sealed` (the whole CBOR value) under a fresh CEK and item key of `owner`.
    pub(super) fn sealed_with(&self, owner: &SymmetricKey, sealed: &Cbor, format_version: Value) -> Value {
        let item = SymmetricKey::generate(&self.rng).unwrap();
        let (envelope, cek) = seal_envelope(sealed, EnvelopeNamespace::VaultItem, &self.rng).unwrap();
        let wrapped = item.encrypt(&SymmetricKey::Cose(cek).to_bytes(), &self.rng).unwrap();
        let data =
            json!({ "format_version": format_version, "wrapped_cek": wrapped, "envelope": B64.encode(envelope) });
        json!({
            "id": "b1", "type": 1, "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z",
            "name": null, "notes": null, "login": null, "fields": null, "passwordHistory": null,
            "key": owner.encrypt(&item.to_bytes(), &self.rng).unwrap(),
            "data": data.to_string(),
        })
    }

    pub(super) fn cipher(&self, content: Cbor) -> Value {
        self.sealed_with(&self.keys.user, &versioned(content), json!(1))
    }

    fn scan(&self, c: &Value) -> Scan {
        scan(c, &Namespace::BWSS, &self.keys, &Organizations::All)
    }

    fn open(&self, c: &Value) -> Result<OpenBlob, Uninspectable> {
        open_blob(c, &self.keys.user)
    }

    fn scan_all(&self, ciphers: &[&Value], cache: &mut UnmarkedCache) -> ScanReport {
        let sync = json!({ "ciphers": ciphers });
        scan_vault_with(&sync, &Namespace::BWSS, &self.keys, &Organizations::All, &|_| true, cache, &BTreeMap::new())
    }
}

/// The same cipher with one ciphertext byte of its envelope flipped: opening it fails.
pub(super) fn tampered(c: &Value) -> Value {
    let mut data: Value = serde_json::from_str(c["data"].as_str().unwrap()).unwrap();
    let mut env = B64.decode(data["envelope"].as_str().unwrap()).unwrap();
    let last = env.len() - 1;
    env[last] ^= 1;
    data["envelope"] = json!(B64.encode(env));
    let mut c = c.clone();
    c["data"] = json!(data.to_string());
    c
}

fn marked(s: Scan) -> Box<MarkedItem> {
    let Scan::Marked(m) = s else { panic!("expected Marked, got {s:?}") };
    m
}

fn skipped(s: Scan) -> SkipReason {
    let Scan::Skipped(r) = s else { panic!("expected Skipped, got {s:?}") };
    r
}

fn held(s: Scan) -> Uninspectable {
    let Scan::Uninspectable(u) = s else { panic!("expected Uninspectable, got {s:?}") };
    u
}

#[test]
fn marked_blob_reads_like_a_field_level_item() {
    let k = Bx::new();
    let fields = [
        ("note", "text"),
        ("bwss:id", " alpha "),
        ("bwss:password", "secret"),
        ("bwss:password", "second"),
        ("bwss:label", "Label"),
        ("bwss:attr:service", "svc"),
    ];
    let c = k.cipher(login(&fields, Some("login-pw"), Some("user notes")));
    let m = marked(k.scan(&c));
    assert_eq!((m.id.as_str(), m.source, m.value.as_slice()), ("alpha", ValueSource::Field, &b"secret"[..]));
    assert_eq!(m.mark, k.keys.marker.mark("alpha", "secret"));
    assert_eq!(m.attributes, BTreeMap::from([("service".to_owned(), "svc".to_owned())]));
    assert_eq!(m.tool_fields.len(), 1);
    assert_eq!((m.tool_fields[0].0.as_str(), m.tool_fields[0].1.as_str()), ("bwss:label", "Label"));
    // The cipher is kept as the server sent it, still sealed.
    assert_eq!(m.cipher, c);
    assert_eq!(m.organization_id, None);

    let c = k.cipher(login(&[("bwss:id", "a")], Some("login-pw"), None));
    let m = marked(k.scan(&c));
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::LoginPassword, &b"login-pw"[..]));
    let c = k.cipher(login(&[("bwss:id", "a"), ("bwss:location", "notes")], Some("pw"), Some("in notes")));
    let m = marked(k.scan(&c));
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::Notes, &b"in notes"[..]));
    // A null password and absent notes read as empty, as on a field-level item.
    let c = k.cipher(login(&[("bwss:id", "a")], None, None));
    assert_eq!(marked(k.scan(&c)).value.as_slice(), b"");
    let c = k.cipher(login(&[("bwss:id", "a"), ("bwss:location", "notes")], None, None));
    assert_eq!(marked(k.scan(&c)).value.as_slice(), b"");
    // The same skips as a field-level item.
    let c = k.cipher(login(&[("bwss:id", "a"), ("bwss:encoding", "base64")], Some("pw"), None));
    assert_eq!(skipped(k.scan(&c)), SkipReason::EncodingOnUserSource);
    let c = k.cipher(login(&[("bwss:id", "a"), ("bwss:password", "%%"), ("bwss:encoding", "base64")], None, None));
    assert_eq!(skipped(k.scan(&c)), SkipReason::InvalidBase64);
}

#[test]
fn marked_blob_is_written_as_a_blob() {
    // A field-level body would drop `data` and with it the user's whole item.
    let k = Bx::new();
    let c = k.cipher(login(&[("bwss:id", "a")], Some("pw"), None));
    let m = marked(k.scan(&c));
    let patch = write::Patch {
        id: m.id.clone(),
        cipher_id: Some(m.cipher_id.clone()),
        organization_id: None,
        base_revision: m.revision_date.clone(),
        set: Vec::new(),
        remove: Vec::new(),
        value: write::ValueChange::Keep,
        answer: None,
    };
    let got =
        write::apply(&c, &patch, &Namespace::BWSS, &k.keys, &Default::default(), &k.rng, 0).unwrap().body.unwrap();
    assert!(got["data"].is_string());
    assert_eq!((&got["fields"], &got["key"]), (&Value::Null, &c["key"]));
}

#[test]
fn a_password_needs_a_logins_type_data() {
    // `open_blob` holds a login without one; a secure note's blob has none to write to.
    use write::Body as _;
    let k = Bx::new();
    let mut c = k.cipher(Cbor::Map(vec![(t("name"), t("N")), (t("typeData"), Cbor::Null)]));
    c["type"] = json!(2);
    let mut open = k.open(&c).unwrap();
    assert_eq!(open.replace_password("pw", "now"), Err(crate::crypto::CryptoError::Malformed));
}

#[test]
fn unmarked_blob_keeps_nothing() {
    let k = Bx::new();
    let fields = [("other:id", "alpha"), ("bwss:password", "secret"), ("bwss:id", " ")];
    let c = k.cipher(login(&fields, Some("login-pw"), Some("user notes")));
    assert_eq!(cbor_texts_alive(), 0);
    // The counter sees what an open blob holds...
    let open = k.open(&c).unwrap();
    assert!(cbor_texts_alive() > 0);
    drop(open);
    assert_eq!(cbor_texts_alive(), 0);
    // ...and nothing outlives the scan of an unmarked blob, in the result or anywhere else.
    let result = k.scan(&c);
    assert!(matches!(result, Scan::Unmarked));
    assert_eq!(cbor_texts_alive(), 0);
    let mut cache = UnmarkedCache::default();
    let report = k.scan_all(&[&c], &mut cache);
    assert!(report.items.is_empty() && report.present.is_empty() && report.uninspectable.is_empty());
    assert_eq!(cbor_texts_alive(), 0);
    // The cache holds the cipher id and revision, nothing from inside the blob.
    assert_eq!(serde_json::to_value(&cache).unwrap(), json!([["b1", "2026-01-02T03:04:05Z"]]));
    // A marked blob's item holds no decoded text either: its values are copied out into zeroizing memory.
    let item = k.scan(&k.cipher(login(&[("bwss:id", "a"), ("bwss:password", "s")], None, None)));
    assert!(matches!(item, Scan::Marked(_)));
    assert_eq!(cbor_texts_alive(), 0);
}

#[test]
fn blob_field_names_only_until_marker() {
    let k = Bx::new();
    blob::take_values_read();
    let c = k.cipher(login(&[("note", "text"), ("bwss:id", "x"), ("bwss:password", "pw")], Some("login"), Some("n")));
    assert_eq!(marked(k.scan(&c)).value.as_slice(), b"pw");
    // Field 0 comes before the marker: its name is looked at, never its value. Then the marker, the value source.
    assert_eq!(blob::take_values_read(), ["field 1", "field 2"]);
    // No marker: no value, no notes, no password is read.
    let c = k.cipher(login(&[("note", "text"), ("other:id", "x"), ("bwss:password", "pw")], Some("pw"), Some("n")));
    assert!(matches!(k.scan(&c), Scan::Unmarked));
    assert!(blob::take_values_read().is_empty());
    // A blank marker reads the marker's value and stops there.
    let c = k.cipher(login(&[("note", "text"), ("bwss:id", "  ")], Some("pw"), Some("n")));
    assert!(matches!(k.scan(&c), Scan::Unmarked));
    assert_eq!(blob::take_values_read(), ["field 1"]);
}

#[test]
fn blob_type_follows_cipher_type() {
    let k = Bx::new();
    let content = || login(&[("bwss:id", "a")], Some("login-pw"), Some("note body"));
    // `cipher.type` decides, not the blob's `typeData.type`.
    let mut c = k.cipher(content());
    c["type"] = json!(3);
    assert_eq!(skipped(k.scan(&c)), SkipReason::WrongType);
    let mut c = k.cipher(content());
    c["type"] = json!(2);
    let m = marked(k.scan(&c));
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::NoteBody, &b"note body"[..]));
    // A login whose blob holds another type, no type, or no `typeData` is held: reading its password as empty
    // could later overwrite the local secret.
    let with_type_data = |type_data: Option<Cbor>| {
        let mut odd = content();
        let Cbor::Map(entries) = &mut odd else { unreachable!() };
        match type_data {
            Some(td) => entries[2].1 = td,
            None => _ = entries.remove(2),
        }
        k.cipher(odd)
    };
    let odd = [
        Some(Cbor::Map(vec![(t("type"), t("secureNote")), (t("password"), t("hidden"))])),
        Some(Cbor::Map(vec![(t("password"), t("hidden"))])),
        Some(Cbor::Null),
        None,
    ];
    for type_data in odd {
        assert_eq!(held(k.scan(&with_type_data(type_data))), Uninspectable::Blob);
    }
    // A `typeData.type` that is not a text is malformed, whatever the cipher's type.
    let mut c = with_type_data(Some(Cbor::Map(vec![(t("type"), Cbor::Uint(1)), (t("password"), t("pw"))])));
    assert_eq!(held(k.scan(&c)), Uninspectable::Blob);
    c["type"] = json!(2);
    assert_eq!(held(k.scan(&c)), Uninspectable::Blob);
    // A secure note does not need a login's `typeData`.
    let mut c = with_type_data(None);
    c["type"] = json!(2);
    assert_eq!(marked(k.scan(&c)).value.as_slice(), b"note body");
}

#[test]
fn organization_blob_is_held_without_decrypting() {
    let k = Bx::new();
    // Sealed under the organization's key, which this account holds and reads: still held, never opened.
    let org = &k.keys.orgs["org1"];
    let mut c = k.sealed_with(org, &versioned(login(&[("bwss:id", "a")], Some("pw"), None)), json!(1));
    c["organizationId"] = json!("org1");
    assert_eq!(held(k.scan(&c)), Uninspectable::NewerFormat);
    assert_eq!(held(scan(&c, &Namespace::BWSS, &k.keys, &Organizations::None)), Uninspectable::NewerFormat);
    // Nothing of it is touched: a garbage key, content key and envelope give the same answer.
    c["key"] = json!("2.x|y|z");
    c["data"] = json!(r#"{"format_version":1,"wrapped_cek":"2.x|y|z","envelope":"AAAA"}"#);
    assert_eq!(held(k.scan(&c)), Uninspectable::NewerFormat);
    assert_eq!(cbor_texts_alive(), 0);
}

#[test]
fn cached_unmarked_blob_is_not_opened() {
    let k = Bx::new();
    let c = k.cipher(login(&[("other", "x")], Some("pw"), None));
    let mut cache = UnmarkedCache::default();
    assert!(k.scan_all(&[&c], &mut cache).uninspectable.is_empty());
    // Same id and revision, but the envelope no longer opens: a cipher that were opened would be held as `Blob`.
    let broken = tampered(&c);
    assert_eq!(held(k.scan(&broken)), Uninspectable::Blob);
    let r = k.scan_all(&[&broken], &mut cache);
    assert!(r.uninspectable.is_empty() && r.present.is_empty());
    assert_eq!(cbor_texts_alive(), 0);
    // The cache keeps it, and it round-trips as device state.
    let kept: UnmarkedCache = serde_json::from_value(serde_json::to_value(&cache).unwrap()).unwrap();
    assert_eq!(kept, cache);
    assert_eq!(serde_json::to_value(&cache).unwrap(), json!([["b1", "2026-01-02T03:04:05Z"]]));
}

#[test]
fn changed_revision_is_opened_again() {
    let k = Bx::new();
    let c = k.cipher(login(&[("other", "x")], Some("pw"), None));
    let mut cache = UnmarkedCache::default();
    k.scan_all(&[&c], &mut cache);
    let mut broken = tampered(&c);
    broken["revisionDate"] = json!("2026-02-01T00:00:00Z");
    let r = k.scan_all(&[&broken], &mut cache);
    assert_eq!(r.uninspectable, [("b1".to_owned(), Uninspectable::Blob)]);
    assert!(r.present.contains("b1"));
    // Only ciphers that scan as unmarked are cached; the old revision is gone.
    assert_eq!(cache, UnmarkedCache::default());
    // A blob that gained its marker under a new revision is read.
    let mut now_marked = k.cipher(login(&[("bwss:id", "a")], Some("pw"), None));
    now_marked["revisionDate"] = json!("2026-03-01T00:00:00Z");
    k.scan_all(&[&c], &mut cache);
    let r = k.scan_all(&[&now_marked], &mut cache);
    assert_eq!(r.items.len(), 1);
    assert_eq!(cache, UnmarkedCache::default());
    // Field-level ciphers and the trash are cached the same way.
    let mut trashed = c.clone();
    trashed["deletedDate"] = json!("2026-01-03T00:00:00Z");
    k.scan_all(&[&trashed], &mut cache);
    assert_eq!(serde_json::to_value(&cache).unwrap(), json!([["b1", "2026-01-02T03:04:05Z"]]));
}

#[test]
fn ciphers_without_id_or_revision_are_never_cached() {
    let k = Bx::new();
    let unmarked = k.cipher(login(&[("other", "x")], Some("pw"), None));
    let without = |key: &str, c: &Value| {
        let mut c = c.clone();
        c.as_object_mut().unwrap().remove(key);
        c
    };
    for key in ["id", "revisionDate"] {
        let mut cache = UnmarkedCache::default();
        let first = without(key, &unmarked);
        assert!(k.scan_all(&[&first], &mut cache).uninspectable.is_empty());
        assert_eq!(cache, UnmarkedCache::default(), "{key}");
        // The second still gets scanned: a tampered one is held, not unmarked.
        let second = without(key, &tampered(&unmarked));
        assert_eq!(k.scan_all(&[&first, &second], &mut cache).uninspectable.len(), 1, "{key}");
    }
    // An empty id or revision counts as missing.
    let mut cache = UnmarkedCache::default();
    for (key, empty) in [("id", json!("")), ("revisionDate", json!(""))] {
        let mut c = unmarked.clone();
        c[key] = empty;
        k.scan_all(&[&c], &mut cache);
        assert_eq!(cache, UnmarkedCache::default(), "{key}");
    }
}

#[test]
fn blob_that_fails_any_check_is_held() {
    let k = Bx::new();
    let good = || versioned(login(&[("bwss:id", "a")], Some("pw"), None));
    let user = &k.keys.user;
    // Format and content versions other than 1 are a newer format.
    for v in [json!(2), json!("1"), json!(null), json!(0)] {
        assert_eq!(held(k.scan(&k.sealed_with(user, &good(), v.clone()))), Uninspectable::NewerFormat, "{v}");
    }
    let content_versions = [
        Cbor::Map(vec![(t("version"), t("2")), (t("content"), login(&[], None, None))]),
        Cbor::Map(vec![(t("version"), Cbor::Uint(1)), (t("content"), login(&[], None, None))]),
        Cbor::Map(vec![(t("content"), login(&[], None, None))]),
    ];
    for sealed in content_versions {
        assert_eq!(held(k.scan(&k.sealed_with(user, &sealed, json!(1)))), Uninspectable::NewerFormat);
    }
    // Every other failure is `Blob`: the item key, the content key, the envelope, the content's shape.
    let mut c = k.cipher(login(&[("bwss:id", "a")], None, None));
    c["key"] = json!("2.x|y|z");
    assert_eq!(held(k.scan(&c)), Uninspectable::Blob);
    assert_eq!(held(k.scan(&tampered(&k.cipher(login(&[], None, None))))), Uninspectable::Blob);
    let edit = |f: &dyn Fn(&mut Value)| {
        let c = k.cipher(login(&[("bwss:id", "a")], None, None));
        let mut data: Value = serde_json::from_str(c["data"].as_str().unwrap()).unwrap();
        f(&mut data);
        let mut c = c;
        c["data"] = json!(data.to_string());
        held(k.scan(&c))
    };
    assert_eq!(edit(&|d| d["wrapped_cek"] = json!("2.x|y|z")), Uninspectable::Blob);
    assert_eq!(edit(&|d| d["wrapped_cek"] = json!(1)), Uninspectable::Blob);
    assert_eq!(edit(&|d| d["envelope"] = json!("not base64!")), Uninspectable::Blob);
    assert_eq!(edit(&|d| _ = d.as_object_mut().unwrap().remove("envelope")), Uninspectable::Blob);
    // A content key that is a legacy 64-byte key is refused.
    let item = SymmetricKey::generate(&k.rng).unwrap();
    let mut c = k.cipher(login(&[], None, None));
    c["key"] = json!(user.encrypt(&item.to_bytes(), &k.rng).unwrap());
    let mut data: Value = serde_json::from_str(c["data"].as_str().unwrap()).unwrap();
    data["wrapped_cek"] = json!(item.encrypt(&item.to_bytes(), &k.rng).unwrap());
    c["data"] = json!(data.to_string());
    assert_eq!(held(k.scan(&c)), Uninspectable::Blob);
    // `data` that is not a JSON object, reached only by a direct call (the scan's gate is `is_blob`).
    for data in [json!("not json"), json!(7)] {
        let mut c = k.cipher(login(&[], None, None));
        c["data"] = data;
        assert_eq!(k.open(&c).unwrap_err(), Uninspectable::Blob);
    }
    // Malformed content.
    let field = |name: Cbor, value: Cbor| Cbor::Array(vec![Cbor::Map(vec![(t("name"), name), (t("value"), value)])]);
    let shaped = |key: &str, v: Cbor| Cbor::Map(vec![(t("name"), t("Blob")), (t(key), v)]);
    let bad = [
        Cbor::Map(vec![(t("version"), t("1"))]),
        Cbor::Map(vec![(t("version"), t("1")), (t("content"), t("text"))]),
        versioned(shaped("fields", t("x"))),
        versioned(shaped("fields", Cbor::Array(vec![t("x")]))),
        versioned(shaped("fields", field(Cbor::Uint(1), t("v")))),
        versioned(shaped("fields", field(t("bwss:id"), Cbor::bytes(vec![1])))),
        versioned(shaped("notes", Cbor::Uint(1))),
        versioned(shaped("typeData", t("login"))),
        versioned(shaped("typeData", Cbor::Map(vec![(t("type"), t("login")), (t("password"), Cbor::Bool(true))]))),
    ];
    for sealed in bad {
        assert_eq!(held(k.scan(&k.sealed_with(user, &sealed, json!(1)))), Uninspectable::Blob, "{sealed:?}");
    }
    let not_a_map = Cbor::Array(vec![t("version"), t("1")]);
    assert_eq!(held(k.scan(&k.sealed_with(user, &not_a_map, json!(1)))), Uninspectable::Blob);
    // Null and absent parts are fine: no fields, a field without a name or value.
    let sparse = [
        shaped("fields", Cbor::Null),
        shaped("typeData", Cbor::Null),
        shaped("fields", field(Cbor::Null, Cbor::Null)),
        shaped("fields", Cbor::Array(vec![Cbor::Map(vec![])])),
    ];
    // (as secure notes: a login's blob must hold a login's `typeData`)
    let note = |content: Cbor| {
        let mut c = k.cipher(content);
        c["type"] = json!(2);
        c
    };
    for content in sparse {
        assert!(matches!(k.scan(&note(content)), Scan::Unmarked));
    }
    let open = k.open(&note(shaped("fields", field(Cbor::Null, Cbor::Null)))).unwrap();
    assert_eq!((open.field_names(), open.field_value(0), open.field_value(1)), (vec![None], None, None));
    assert_eq!((open.notes(), open.login_password()), (None, None));
    assert_eq!(format!("{open:?}"), "OpenBlob(<redacted>)");
}

#[test]
fn a_blob_requiring_an_unknown_feature_is_skipped() {
    let k = Bx::new();
    let c = k.cipher(login(&[("bwss:id", "x"), ("dybw:requires", "bwss:acl-host")], Some("pw"), None));
    assert_eq!(skipped(k.scan(&c)), SkipReason::NewerFormat);
    let r = k.scan_all(&[&c], &mut UnmarkedCache::default());
    assert_eq!(r.unknown_features, [("b1".to_owned(), vec!["bwss:acl-host".to_owned()])]);
    assert!(r.present.contains("b1"));
    // An unmarked blob is not asked.
    let c = k.cipher(login(&[("dybw:requires", "bwss:acl-host")], Some("pw"), None));
    assert!(matches!(k.scan(&c), Scan::Unmarked));
}
