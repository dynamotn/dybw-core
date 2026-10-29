//! Ported from bwss `src/bw/scan.rs`, `fields.rs`, `items.rs` and the plugin's `readVault` cases
//! (`test/sync.test.ts`, `test/organizations.test.ts`) that no vector covers.

use super::fields::{Mark, field_names, field_value, first_index, item_key};
use super::scan::{Duplicate, MarkedItem, Scan, SkipReason, Uninspectable, ValueSource, resolve_duplicates};
use super::*;
use crate::crypto::{MarkScheme, Marker, SymmetricKey};
use crate::testing::SeededRandom;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

struct Fx {
    rng: SeededRandom,
    keys: Keys,
}

impl Fx {
    fn new(scheme: MarkScheme) -> Fx {
        let rng = SeededRandom::new(9);
        let user = SymmetricKey::generate(&rng).unwrap();
        let org = SymmetricKey::generate(&rng).unwrap();
        let marker = Marker::new(&user, scheme);
        Fx { rng, keys: Keys { user, orgs: BTreeMap::from([("org1".to_owned(), org)]), marker } }
    }
    fn enc(&self, s: &str) -> Value {
        json!(self.keys.user.encrypt_str(s, &self.rng).unwrap())
    }
    fn fields(&self, fields: &[(&str, &str)]) -> Value {
        Value::Array(
            fields.iter().map(|(n, v)| json!({ "type": 0, "name": self.enc(n), "value": self.enc(v) })).collect(),
        )
    }
    fn login(&self, fields: &[(&str, &str)], password: Option<&str>, notes: Option<&str>) -> Value {
        json!({
            "id": "c1", "type": 1, "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z",
            "name": self.enc("GitHub"),
            "notes": notes.map(|n| self.enc(n)),
            "login": {
                "username": self.enc("me"),
                "password": password.map(|p| self.enc(p)),
                "uris": [{ "uri": self.enc("https://github.com"), "match": null }],
            },
            "fields": self.fields(fields),
        })
    }
    fn note(&self, fields: &[(&str, &str)], notes: Option<&str>) -> Value {
        json!({
            "id": "n1", "type": 2, "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z",
            "name": self.enc("Note"), "notes": notes.map(|n| self.enc(n)), "secureNote": { "type": 0 },
            "fields": self.fields(fields),
        })
    }
    fn scan(&self, c: &Value) -> Scan {
        scan::scan(c, &Namespace::BWSS, &self.keys, &Organizations::All)
    }
    fn scan_ns(&self, c: &Value, ns: &Namespace) -> Scan {
        scan::scan(c, ns, &self.keys, &Organizations::All)
    }
}

fn bwss() -> Fx {
    Fx::new(MarkScheme::Bwss)
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

const BAD: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

#[test]
fn unmarked_values_never_decrypted() {
    // name, notes, login and other field values are garbage: §4 decrypts field names only.
    let k = bwss();
    let c = json!({ "id": "c1", "type": 1, "name": BAD, "notes": "2.bad|bad|bad",
        "login": { "password": BAD, "username": "garbage", "uris": [{ "uri": BAD }] },
        "fields": [{ "type": 0, "name": k.enc("other"), "value": BAD }, { "type": 0, "name": k.enc("obsidian:id"), "value": BAD }] });
    assert!(matches!(k.scan(&c), Scan::Unmarked));
}

#[test]
fn non_utf8_field_name_is_uninspectable() {
    let k = bwss();
    let mut c = k.login(&[("bwss:id", "x")], Some("pw"), None);
    c["fields"][0]["name"] = json!(k.keys.user.encrypt(&[0xff, 0xfe, 0x00], &k.rng).unwrap());
    assert_eq!(held(k.scan(&c)), Uninspectable::FieldNames);
    // A non-UTF-8 marker value is held too, never a panic or bytes in the report.
    let mut c = k.login(&[("bwss:id", "x")], Some("pw"), None);
    c["fields"][0]["value"] = json!(k.keys.user.encrypt(&[0xc3, 0x28], &k.rng).unwrap());
    assert_eq!(held(k.scan(&c)), Uninspectable::Marker);
    // And a non-UTF-8 value once marked.
    let mut c = k.login(&[("bwss:id", "x"), ("bwss:password", "p")], None, None);
    c["fields"][1]["value"] = json!(k.keys.user.encrypt(&[0x80], &k.rng).unwrap());
    assert_eq!(held(k.scan(&c)), Uninspectable::Value);
}

#[test]
fn secret_comes_from_the_first_present_source() {
    let k = bwss();
    // An empty bwss:password still wins over the login password.
    let s = marked(k.scan(&k.login(&[("bwss:id", "x"), ("bwss:password", "")], Some("pw"), None)));
    assert_eq!((s.value.as_slice(), s.source), (&b""[..], ValueSource::Field));
    let s = marked(k.scan(&k.login(&[("bwss:id", "x")], Some("pw"), Some("n"))));
    assert_eq!((s.value.as_slice(), s.source), (&b"pw"[..], ValueSource::LoginPassword));
    let s = marked(k.scan(&k.note(&[("bwss:id", "x")], Some("body"))));
    assert_eq!((s.value.as_slice(), s.source), (&b"body"[..], ValueSource::NoteBody));
    let s = marked(k.scan(&k.login(&[("bwss:id", "x"), ("bwss:location", "notes")], Some("pw"), Some("big"))));
    assert_eq!((s.value.as_slice(), s.source), (&b"big"[..], ValueSource::Notes));
    let s = marked(k.scan(&k.note(&[("bwss:id", "x"), ("bwss:encoding", "base64"), ("bwss:password", "AAE=")], None)));
    assert_eq!(s.value.as_slice(), &[0u8, 1][..]);
    // The mark follows the stored text, decrypted but not decoded.
    assert_eq!(s.mark, k.keys.marker.mark("x", "AAE="));
    assert_eq!(
        [ValueSource::Field, ValueSource::Notes, ValueSource::LoginPassword, ValueSource::NoteBody].map(|s| s.code()),
        ["field", "notes", "login-password", "note-body"]
    );
}

#[test]
fn item_metadata_attributes_and_tool_fields() {
    let k = bwss();
    let c = k.login(
        &[
            ("bwss:id", " gh "),
            ("bwss:attr:service", "git"),
            ("bwss:attr:service", "second"),
            ("bwss:attr:", "ignored"),
            ("bwss:attr:a:b", " v "),
            ("bwss:label", "Mine"),
            ("bwss:label", "later"),
            ("bwss:acl", "/a\n/b"),
            ("obsidian:scope", "global"),
            ("plain", "x"),
        ],
        Some("pw"),
        None,
    );
    let s = marked(k.scan(&c));
    assert_eq!((s.id.as_str(), s.cipher_id.as_str()), ("gh", "c1"));
    assert_eq!(s.revision_date, "2026-01-02T03:04:05Z");
    assert_eq!(s.creation_date, Some(1_735_787_045_000));
    assert_eq!((s.organization_id.as_deref(), s.read_only), (None, false));
    let attrs: Vec<(&str, &str)> = s.attributes.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    assert_eq!(attrs, [("a:b", " v "), ("service", "git")]);
    let tool: Vec<(&str, &str)> = s.tool_fields.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    assert_eq!(tool, [("bwss:label", "Mine"), ("bwss:acl", "/a\n/b")]);
    assert_eq!(s.cipher, c);
    // Debug never shows the value or a tool field's value.
    let shown = format!("{s:?}");
    assert!(shown.contains("gh") && !shown.contains("pw") && !shown.contains("Mine"), "{shown}");
    // Milliseconds count; an unparseable or absent date is none.
    let mut c = k.login(&[("bwss:id", "x")], Some("pw"), None);
    c["creationDate"] = json!("2025-01-02T03:04:05.250+01:00");
    assert_eq!(marked(k.scan(&c)).creation_date, Some(1_735_783_445_250));
    // At or before the Unix epoch counts as undated, as bwss.
    for epoch in ["1970-01-01T00:00:00Z", "1969-12-31T23:59:59Z"] {
        c["creationDate"] = json!(epoch);
        assert_eq!(marked(k.scan(&c)).creation_date, None, "{epoch}");
    }
    c["creationDate"] = json!("1970-01-01T00:00:00.001Z");
    assert_eq!(marked(k.scan(&c)).creation_date, Some(1));
    c["creationDate"] = json!("not a date");
    assert_eq!(marked(k.scan(&c)).creation_date, None);
    c["creationDate"] = Value::Null;
    c["revisionDate"] = Value::Null;
    let s = marked(k.scan(&c));
    assert_eq!((s.creation_date, s.revision_date.as_str()), (None, ""));
}

#[test]
fn duplicate_fields_first_wins() {
    let k = bwss();
    let c = k.login(&[("bwss:id", "a"), ("bwss:id", "b"), ("bwss:password", "1"), ("bwss:password", "2")], None, None);
    let s = marked(k.scan(&c));
    assert_eq!((s.id.as_str(), s.value.as_slice()), ("a", &b"1"[..]));
}

#[test]
fn blank_marker_reads_nothing_else() {
    let k = bwss();
    let mut c = k.login(&[("bwss:id", "  ")], Some("pw"), None);
    c["name"] = json!(BAD);
    c["notes"] = json!(BAD);
    c["login"]["password"] = json!(BAD);
    assert!(matches!(k.scan(&c), Scan::Unmarked));
    // A marker field without a value is blank (plugin: "reads a field ... without a value as empty").
    let mut c = k.login(&[("bwss:id", "x")], Some("pw"), None);
    c["fields"][0]["value"] = Value::Null;
    assert!(matches!(k.scan(&c), Scan::Unmarked));
}

#[test]
fn blob_ciphers_are_held_not_unmarked() {
    // The SDK gate (sdk-internal 3d16437, bitwarden-vault/src/cipher/blob/sealed.rs from_opaque_string).
    let k = bwss();
    let blob = r#"{"format_version":1,"wrapped_cek":"2.x|y|z","envelope":"AAAA"}"#;
    let mut c = k.login(&[("bwss:id", "x")], Some("pw"), None);
    c["data"] = json!(blob);
    for field in ["name", "notes", "login", "fields"] {
        c[field] = Value::Null;
    }
    assert_eq!(held(k.scan(&c)), Uninspectable::NewerFormat);
    // In the trash it is still just the trash.
    c["deletedDate"] = json!("2026-01-01T00:00:00Z");
    assert!(matches!(k.scan(&c), Scan::Unmarked));
    // The gate is the key alone: a bare or odd `format_version` is held too, before any key unwrap.
    for data in [r#"{"format_version":1}"#, r#"{"format_version":2,"x":1}"#, r#"{"format_version":null}"#] {
        let mut c = k.login(&[("bwss:id", "x")], Some("pw"), None);
        c["data"] = json!(data);
        c["key"] = json!(BAD);
        assert_eq!(held(k.scan(&c)), Uninspectable::NewerFormat, "{data}");
    }
    // An organization blob is held as a blob, even for an organization not read.
    let mut c = k.login(&[("bwss:id", "x")], Some("pw"), None);
    c["data"] = json!(blob);
    c["organizationId"] = json!("org-unknown");
    assert_eq!(held(scan::scan(&c, &Namespace::BWSS, &k.keys, &Organizations::None)), Uninspectable::NewerFormat);
    // Legacy `data` without `format_version`, and anything that is not a JSON object, reads as before.
    let legacy = [json!(r#"{"uri":"x","fields":[],"formatVersion":1}"#), json!("not json"), json!("[1]")];
    for data in legacy.into_iter().chain([json!("null"), json!(7), Value::Null]) {
        let mut c = k.login(&[("bwss:id", "x")], Some("pw"), None);
        c["data"] = data.clone();
        assert!(matches!(k.scan(&c), Scan::Marked(_)), "{data}");
        let mut c = k.login(&[("other", "x")], Some("pw"), None);
        c["data"] = data;
        assert!(matches!(k.scan(&c), Scan::Unmarked));
    }
}

#[test]
fn what_is_skipped_or_uninspectable() {
    let k = bwss();
    let id = ("bwss:id", "x");
    let mut card = k.login(&[id], None, None);
    card["type"] = json!(3);
    assert_eq!(skipped(k.scan(&card)), SkipReason::WrongType);
    card["type"] = Value::Null;
    assert_eq!(skipped(k.scan(&card)), SkipReason::WrongType);
    assert_eq!(
        skipped(k.scan(&k.login(&[id, ("bwss:location", "attachment")], Some("pw"), None))),
        SkipReason::UnknownLocation
    );
    assert_eq!(
        skipped(k.scan(&k.login(&[id, ("bwss:encoding", "hex")], Some("pw"), None))),
        SkipReason::UnknownEncoding
    );
    // base64 on the login password or a note's text: skipped, and the value is never decrypted (ADR 0005).
    let mut c = k.login(&[id, ("bwss:encoding", "base64")], Some("AAE="), None);
    c["login"]["password"] = json!(BAD);
    assert_eq!(skipped(k.scan(&c)), SkipReason::EncodingOnUserSource);
    let mut c = k.note(&[id, ("bwss:encoding", "base64")], Some("AAE="));
    c["notes"] = json!(BAD);
    assert_eq!(skipped(k.scan(&c)), SkipReason::EncodingOnUserSource);
    // A wrapped item key that does not unwrap.
    let mut c = k.login(&[id], Some("pw"), None);
    c["key"] = json!(BAD);
    assert_eq!(held(k.scan(&c)), Uninspectable::ItemKey);
    // The trash is not scanned.
    let mut c = k.login(&[id], Some("pw"), None);
    c["deletedDate"] = json!("2026-01-01T00:00:00Z");
    assert!(matches!(k.scan(&c), Scan::Unmarked));
    // Blank location or encoding is absent; only `notes` / `base64` after trimming is the mark.
    for blank in ["", "  ", "\t\n"] {
        let m = marked(k.scan(&k.login(&[id, ("bwss:location", blank)], Some("pw"), Some("mine"))));
        assert_eq!((m.source, m.value.as_slice()), (ValueSource::LoginPassword, b"pw".as_slice()));
    }
    for odd in ["Notes", "hex"] {
        assert_eq!(
            skipped(k.scan(&k.login(&[id, ("bwss:location", odd)], Some("pw"), None))),
            SkipReason::UnknownLocation
        );
        assert_eq!(
            skipped(k.scan(&k.login(&[id, ("bwss:encoding", odd)], Some("pw"), None))),
            SkipReason::UnknownEncoding
        );
    }
    // bwss checks the location before the encoding.
    let both = k.login(&[id, ("bwss:encoding", "hex"), ("bwss:location", "x")], Some("pw"), None);
    assert_eq!(skipped(k.scan(&both)), SkipReason::UnknownLocation);
    // Undecryptable field names, marker, later value.
    let mut c = k.login(&[id], Some("pw"), None);
    c["fields"][0]["name"] = json!(BAD);
    assert_eq!(held(k.scan(&c)), Uninspectable::FieldNames);
    let mut c = k.login(&[id], Some("pw"), None);
    c["fields"][0]["value"] = json!(BAD);
    assert_eq!(held(k.scan(&c)), Uninspectable::Marker);
    // An empty-string marker is not a blank marker: it is no EncString, so the item is held (bwss).
    c["fields"][0]["value"] = json!("");
    assert_eq!(held(k.scan(&c)), Uninspectable::Marker);
    // An empty-string login password once marked: held too.
    let mut c = k.login(&[id], Some("pw"), None);
    c["login"]["password"] = json!("");
    assert_eq!(held(k.scan(&c)), Uninspectable::Value);
    let mut c = k.login(&[id, ("bwss:password", "pw")], None, None);
    c["fields"][1]["value"] = json!(BAD);
    assert_eq!(held(k.scan(&c)), Uninspectable::Value);
    // The plugin skipped a marked item whose notes do not decrypt; the core holds it (stricter).
    let mut c = k.note(&[id], Some("body"));
    c["notes"] = json!(BAD);
    assert_eq!(held(k.scan(&c)), Uninspectable::Value);
    // Base64 that does not decode.
    let c = k.login(&[id, ("bwss:encoding", "base64"), ("bwss:password", "!!not base64!!")], None, None);
    assert_eq!(skipped(k.scan(&c)), SkipReason::InvalidBase64);
    // Reserved and invalid ids.
    assert_eq!(skipped(k.scan(&k.login(&[("bwss:id", " _collections ")], Some("pw"), None))), SkipReason::ReservedId);
    let codes = [
        SkipReason::WrongType,
        SkipReason::EncodingOnUserSource,
        SkipReason::UnknownLocation,
        SkipReason::UnknownEncoding,
        SkipReason::InvalidId,
        SkipReason::ReservedId,
        SkipReason::ViewPasswordHidden,
        SkipReason::InvalidBase64,
    ]
    .map(|r| r.code());
    assert_eq!(
        codes,
        [
            "wrong-type",
            "encoding-on-user-source",
            "unknown-location",
            "unknown-encoding",
            "invalid-id",
            "reserved-id",
            "view-password-hidden",
            "invalid-base64"
        ]
    );
}

#[test]
fn obsidian_rules() {
    let k = Fx::new(MarkScheme::Obsidian);
    let ns = &Namespace::OBSIDIAN;
    // Any non-blank encoding is unknown, before the location and before encoding-on-user-source.
    let c =
        k.login(&[("obsidian:id", "a"), ("obsidian:location", "x"), ("obsidian:encoding", "base64")], Some("p"), None);
    assert_eq!(skipped(k.scan_ns(&c, ns)), SkipReason::UnknownEncoding);
    let c = k.login(&[("obsidian:id", "a"), ("obsidian:encoding", " ")], Some("p"), None);
    assert_eq!(marked(k.scan_ns(&c, ns)).value.as_slice(), b"p");
    // Invalid and reserved ids (plugin: "Not A Valid Id", its own credentials).
    let c = k.login(&[("obsidian:id", "Not A Valid Id")], Some("p"), None);
    assert_eq!(skipped(k.scan_ns(&c, ns)), SkipReason::InvalidId);
    for reserved in ["keychain-bitwarden-api-key", "bitwarden-secrets-x"] {
        let c = k.login(&[("obsidian:id", reserved)], Some("p"), None);
        assert_eq!(skipped(k.scan_ns(&c, ns)), SkipReason::ReservedId, "{reserved}");
    }
    // Another namespace's marker is not this one's.
    assert!(matches!(k.scan_ns(&k.login(&[("bwss:id", "a")], Some("p"), None), ns), Scan::Unmarked));
    // The mark is the plugin's fingerprint.
    let s = marked(k.scan_ns(&k.login(&[("obsidian:id", "a"), ("obsidian:scope", "vault:v")], Some("p"), None), ns));
    assert_eq!(s.mark, Marker::new(&k.keys.user, MarkScheme::Obsidian).mark("a", "p"));
    assert_eq!(s.tool_fields.first().map(|(n, v)| (n.as_str(), v.as_str())), Some(("obsidian:scope", "vault:v")));
}

#[test]
fn namespace_presets() {
    assert_eq!((Namespace::BWSS.name, Namespace::OBSIDIAN.name), ("bwss", "obsidian"));
    assert_eq!(Namespace::BWSS.encodings, Encodings::Base64);
    assert_eq!(Namespace::OBSIDIAN.encodings, Encodings::None);
    assert_eq!((Namespace::BWSS.marks, Namespace::OBSIDIAN.marks), (MarkScheme::Bwss, MarkScheme::Obsidian));
    let b = Namespace::BWSS.id_rule;
    assert_eq!(
        (b("any Thing/é"), b(" "), b("_collections")),
        (Ok(()), Err(IdProblem::Invalid), Err(IdProblem::Reserved))
    );
    let o = Namespace::OBSIDIAN.id_rule;
    for good in ["a", "a-b", "0-9z", "keychain-bitwarde"] {
        assert_eq!(o(good), Ok(()), "{good}");
    }
    for bad in ["", "-a", "a-", "a--b", "A", "a b", "é", "a_b"] {
        assert_eq!(o(bad), Err(IdProblem::Invalid), "{bad}");
    }
    assert_eq!(o("keychain-bitwarden-x"), Err(IdProblem::Reserved));
    assert_eq!(Namespace::BWSS.field("id"), "bwss:id");
}

#[test]
fn organization_items() {
    let k = bwss();
    let org = |c: &mut Value, id: &str| c["organizationId"] = json!(id);
    let scan_with = |c: &Value, allowed: &Organizations| scan::scan(c, &Namespace::BWSS, &k.keys, allowed);
    // Encrypted under the organization key; the user key does not open it.
    let rng = &k.rng;
    let enc = |s: &str| json!(k.keys.orgs["org1"].encrypt_str(s, rng).unwrap());
    let mut c = json!({ "id": "o1", "type": 1, "organizationId": "org1", "edit": false, "viewPassword": true,
        "login": { "password": enc("org-pw") },
        "fields": [{ "type": 0, "name": enc("bwss:id"), "value": enc("x") }] });
    let s = marked(scan_with(&c, &Organizations::All));
    assert_eq!((s.organization_id.as_deref(), s.read_only, s.value.as_slice()), (Some("org1"), true, &b"org-pw"[..]));
    assert!(matches!(scan_with(&c, &Organizations::Only(BTreeSet::from(["org1".to_owned()]))), Scan::Marked(_)));
    // Not read: off, or not in the list.
    assert_eq!(held(scan_with(&c, &Organizations::None)), Uninspectable::OrganizationNotRead);
    assert_eq!(
        held(scan_with(&c, &Organizations::Only(BTreeSet::from(["other".to_owned()])))),
        Uninspectable::OrganizationNotRead
    );
    // Allowed but no key (not confirmed, disabled, or its key did not unwrap).
    org(&mut c, "org2");
    assert_eq!(held(scan_with(&c, &Organizations::All)), Uninspectable::OrganizationKeyMissing);
    // An empty or non-text organization id is still an organization item (bwss), never personal (plugin).
    for odd in [json!(""), json!(7)] {
        c["organizationId"] = odd;
        assert_eq!(held(scan_with(&c, &Organizations::All)), Uninspectable::OrganizationKeyMissing);
    }
    // A hidden password is skipped; only for organization items.
    org(&mut c, "org1");
    c["viewPassword"] = json!(false);
    assert_eq!(skipped(scan_with(&c, &Organizations::All)), SkipReason::ViewPasswordHidden);
    let mut p = k.login(&[("bwss:id", "x")], Some("pw"), None);
    p["viewPassword"] = json!(false);
    p["edit"] = json!(false);
    let s = marked(k.scan(&p));
    assert!(!s.read_only);
}

type Spec = (&'static str, &'static str, bool, Option<i64>);

fn m((id, cipher_id, org, created): Spec) -> MarkedItem {
    MarkedItem {
        cipher_id: cipher_id.to_owned(),
        revision_date: String::new(),
        creation_date: created,
        organization_id: org.then(|| "o".to_owned()),
        read_only: false,
        id: id.to_owned(),
        source: ValueSource::LoginPassword,
        value: Zeroizing::new(Vec::new()),
        mark: [0; 32],
        attributes: BTreeMap::new(),
        tool_fields: Vec::new(),
        cipher: Value::Null,
    }
}

fn permutations<T: Copy>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, head);
            out.push(tail);
        }
    }
    out
}

fn dup(id: &str, kept: &str, left: &[&str]) -> Duplicate {
    Duplicate { id: id.into(), kept: kept.into(), left: left.iter().map(|s| (*s).to_owned()).collect() }
}

#[test]
fn duplicates_resolve_the_same_way_in_any_order() {
    // a: org, oldest; b: personal, created 200; c: personal, created 100; d: personal, no date.
    let all = [
        ("x", "a", true, Some(50)),
        ("x", "b", false, Some(200)),
        ("x", "c", false, Some(100)),
        ("x", "d", false, None),
    ];
    for perm in permutations(&all) {
        let (win, lost) = resolve_duplicates(perm.into_iter().map(m).collect());
        assert_eq!(win.iter().map(|w| w.cipher_id.as_str()).collect::<Vec<_>>(), ["c"]);
        assert_eq!(lost, vec![dup("x", "c", &["a", "b", "d"])]);
    }
    for perm in permutations(&[("x", "q", false, Some(7)), ("x", "p", false, Some(7))]) {
        let (win, lost) = resolve_duplicates(perm.into_iter().map(m).collect());
        assert_eq!(win[0].cipher_id, "p");
        assert_eq!(lost, vec![dup("x", "p", &["q"])]);
    }
}

#[test]
fn distinct_ids_all_win_and_losers_are_sorted_by_id() {
    let (win, lost) = resolve_duplicates(vec![m(("a", "c1", false, None)), m(("b", "c2", true, Some(1)))]);
    assert_eq!(win.len(), 2);
    assert!(lost.is_empty());
    let all = [
        ("z", "z2", false, Some(2)),
        ("z", "z1", false, Some(1)),
        ("m", "m2", false, Some(2)),
        ("m", "m1", false, Some(1)),
        ("solo", "s", false, None),
        ("c", "c3", true, None),
        ("c", "c1", false, None),
    ];
    for perm in permutations(&all) {
        let (win, lost) = resolve_duplicates(perm.into_iter().map(m).collect());
        let ids: Vec<_> = win.iter().map(|w| (w.id.as_str(), w.cipher_id.as_str())).collect();
        assert_eq!(ids, [("c", "c1"), ("m", "m1"), ("solo", "s"), ("z", "z1")]);
        assert_eq!(lost, vec![dup("c", "c1", &["c3"]), dup("m", "m1", &["m2"]), dup("z", "z1", &["z2"])]);
    }
}

#[test]
fn scan_vault_reports_everything_once() {
    let k = bwss();
    let mut trashed = k.login(&[("bwss:id", "t")], Some("pw"), None);
    trashed["id"] = json!("trash");
    trashed["deletedDate"] = json!("2026-01-01T00:00:00Z");
    let mut unmarked = k.login(&[("other", "v")], Some("pw"), None);
    unmarked["id"] = json!("plain");
    let mut card = k.login(&[("bwss:id", "card")], None, None);
    card["id"] = json!("card");
    card["type"] = json!(3);
    let mut broken = k.login(&[("bwss:id", "b")], Some("pw"), None);
    broken["id"] = json!("broken");
    broken["key"] = json!(BAD);
    let mut a2 = k.login(&[("bwss:id", "a")], Some("pw2"), None);
    a2["id"] = json!("c2");
    let a1 = k.login(&[("bwss:id", "a")], Some("pw1"), None);
    let mut z = k.login(&[("bwss:id", "0")], Some("z"), None);
    z["id"] = json!("cz");
    let sync = json!({ "ciphers": [trashed, unmarked, card, broken, a2, a1, z] });
    let r = scan::scan_vault(&sync, &Namespace::BWSS, &k.keys, &Organizations::None);
    assert_eq!(
        r.items.iter().map(|i| (i.id.as_str(), i.cipher_id.as_str())).collect::<Vec<_>>(),
        [("0", "cz"), ("a", "c1")]
    );
    assert_eq!(r.skipped, [("card".to_owned(), SkipReason::WrongType)]);
    assert_eq!(r.uninspectable, [("broken".to_owned(), Uninspectable::ItemKey)]);
    assert_eq!(r.duplicates, [dup("a", "c1", &["c2"])]);
    let present: Vec<&str> = r.present.iter().map(String::as_str).collect();
    // §8.1: marked (skipped and duplicate losers included) or uninspectable; a readable unmarked cipher is not
    // present, so a secret synced from it is cleared once its marker is removed.
    assert_eq!(present, ["broken", "c1", "c2", "card", "cz"]);
    // No ciphers at all.
    let r = scan::scan_vault(&json!({}), &Namespace::BWSS, &k.keys, &Organizations::None);
    assert!(r.items.is_empty() && r.present.is_empty());
}

#[test]
fn field_primitives() {
    let k = bwss();
    let key = &k.keys.user;
    for (v, want) in [(None, Mark::Absent), (Some(""), Mark::Absent), (Some(" \t\n"), Mark::Absent)] {
        assert_eq!(Mark::classify(v, "notes"), want);
    }
    for v in ["notes", " notes ", "notes\n", "\tnotes"] {
        assert_eq!(Mark::classify(Some(v), "notes"), Mark::Set, "{v:?}");
    }
    for v in ["Notes", "NOTES", "attachment", "no tes"] {
        assert_eq!(Mark::classify(Some(v), "notes"), Mark::Unknown, "{v:?}");
    }
    // Names only are decrypted; null names and values.
    let c = json!({ "fields": [
        { "type": 0, "name": null, "value": k.enc("v") },
        { "type": 0, "name": k.enc("bwss:id"), "value": null },
        { "type": 0, "name": k.enc("x"), "value": "2.garbage|x|y" },
    ]});
    let names = field_names(&c, key).unwrap();
    assert_eq!(names, vec![None, Some("bwss:id".into()), Some("x".into())]);
    assert_eq!(first_index(&names, "bwss:id"), Some(1));
    assert_eq!(field_value(&c, 1, key).unwrap().as_str(), "");
    assert_eq!(field_value(&c, 0, key).unwrap().as_str(), "v");
    assert!(field_value(&c, 3, key).is_err());
    // A present string is always decrypted (bwss): "" is no EncString and fails; only null or absent is empty.
    assert!(field_value(&json!({ "fields": [{ "name": null, "value": "" }] }), 0, key).is_err());
    assert_eq!(field_value(&json!({ "fields": [{ "name": null }] }), 0, key).unwrap().as_str(), "");
    assert!(field_names(&json!({ "fields": null }), key).unwrap().is_empty());
    assert!(field_names(&json!({}), key).unwrap().is_empty());
    // The item key: its own when wrapped, else the owner's.
    let own = SymmetricKey::generate(&k.rng).unwrap();
    let wrapped = key.encrypt(&own.to_bytes(), &k.rng).unwrap();
    let got = item_key(&json!({ "key": wrapped }), key).unwrap();
    assert_eq!(got.decrypt_str(&own.encrypt_str("x", &k.rng).unwrap()).unwrap().as_str(), "x");
    for c in [json!({ "key": null }), json!({ "key": "" }), json!({})] {
        let plain = item_key(&c, key).unwrap();
        assert_eq!(plain.decrypt_str(&key.encrypt_str("y", &k.rng).unwrap()).unwrap().as_str(), "y");
    }
}
