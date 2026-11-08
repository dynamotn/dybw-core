//! Ported from bwss `src/bw/write.rs` (except the registry note, M4) and the plugin's
//! `newSecretRequest` / `updateValueRequest` cases (`test/sync.test.ts`).

use super::blob::{BLOB_SECURITY_VERSION, OpenBlob, open_blob};
use super::blob_tests::{Bx, login as blob_login, t, versioned};
use super::scan::{MarkedItem, Scan, Uninspectable, ValueSource};
use super::write::*;
use super::*;
use crate::crypto::{Cbor, CoseAlgorithm, CryptoError, MarkScheme, Marker, SymmetricKey, parse_cek};
use crate::testing::SeededRandom;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// 2099-09-09T09:09:09.999Z, the vectors' frozen clock.
const NOW: i64 = 4_092_628_149_999;
const NOW_ISO: &str = "2099-09-09T09:09:09.999Z";
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
const B: &Namespace = &Namespace::BWSS;
const O: &Namespace = &Namespace::OBSIDIAN;

/// `write::apply` for the tests written before ADR 0016: a history question is answered "write to the login", as the
/// vectors' default does, and the body is the one sent.
fn apply(
    c: &Value,
    p: &Patch,
    ns: &Namespace,
    keys: &Keys,
    rng: &SeededRandom,
    now_ms: i64,
) -> Result<Map<String, Value>, WriteError> {
    let record = WriteRecord::default();
    let out = match write::apply(c, p, ns, keys, &record, rng, now_ms) {
        Err(WriteError::Ask(q)) => {
            let answered = Patch { answer: Some((q, HistoryAnswer::WriteToLogin)), ..p.clone() };
            write::apply(c, &answered, ns, keys, &record, rng, now_ms)
        }
        other => other,
    }?;
    Ok(out.body.unwrap())
}

/// `(name, value, hidden)`.
type F<'a> = (&'a str, &'a str, bool);

struct Fx {
    rng: SeededRandom,
    keys: Keys,
}

fn fx_with(seed: u64, scheme: MarkScheme) -> Fx {
    let rng = SeededRandom::new(seed);
    let user = SymmetricKey::generate(&rng).unwrap();
    let org = SymmetricKey::generate(&rng).unwrap();
    let marker = Marker::new(&user, scheme);
    Fx { rng, keys: Keys { user, orgs: BTreeMap::from([("org1".to_owned(), org)]), marker, security_version: 0 } }
}

fn fx() -> Fx {
    fx_with(7, MarkScheme::Bwss)
}

impl Fx {
    fn e_with(&self, key: &SymmetricKey, s: &str) -> Value {
        json!(key.encrypt_str(s, &self.rng).unwrap())
    }
    fn e(&self, s: &str) -> Value {
        self.e_with(&self.keys.user, s)
    }
    fn fields_with(&self, key: &SymmetricKey, fields: &[F]) -> Value {
        Value::Array(
            fields
                .iter()
                .map(|(n, v, h)| {
                    json!({ "type": u64::from(*h), "name": self.e_with(key, n), "value": self.e_with(key, v), "linkedId": null })
                })
                .collect(),
        )
    }
    fn fields(&self, fields: &[F]) -> Value {
        self.fields_with(&self.keys.user, fields)
    }
    fn history(&self, n: usize) -> Value {
        Value::Array(
            (0..n)
                .map(|i| json!({ "password": self.e(&format!("h{i}")), "lastUsedDate": "2025-01-01T00:00:00Z" }))
                .collect(),
        )
    }
    fn login(&self, fields: &[F], password: Option<&str>, notes: Option<&str>) -> Value {
        json!({
            "id": "c1", "object": "cipherDetails", "type": 1, "organizationId": null, "folderId": "f1",
            "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z", "deletedDate": null,
            "edit": true, "viewPassword": true, "permissions": { "delete": true, "restore": true },
            "collectionIds": [], "attachments": null, "organizationUseTotp": false, "data": "{\"x\":1}",
            "favorite": false, "reprompt": 0, "key": null, "archivedDate": "2026-02-02T00:00:00Z",
            "name": self.e("GitHub"),
            "notes": notes.map(|n| self.e(n)),
            "login": {
                "username": self.e("me"),
                "password": password.map(|p| self.e(p)),
                "passwordRevisionDate": "2025-06-01T00:00:00Z",
                "totp": null,
                "uris": [{ "uri": self.e("https://github.com"), "match": null }],
            },
            "passwordHistory": self.history(2),
            "fields": self.fields(fields),
        })
    }
    fn note(&self, fields: &[F], notes: Option<&str>) -> Value {
        json!({
            "id": "n1", "type": 2, "organizationId": null, "folderId": "f1",
            "revisionDate": "2026-01-02T03:04:05Z", "creationDate": "2025-01-02T03:04:05Z",
            "name": self.e("Note"),
            "notes": notes.map(|n| self.e(n)),
            "secureNote": { "type": 0 },
            "passwordHistory": null,
            "fields": self.fields(fields),
        })
    }
    fn marked(&self, c: &Value, ns: &Namespace) -> Box<MarkedItem> {
        let s = scan(c, ns, &self.keys, &Organizations::All);
        let Scan::Marked(m) = s else { panic!("expected Marked, got {s:?}") };
        m
    }
    fn keep(&self, c: &Value, ns: &Namespace) -> Patch {
        let m = self.marked(c, ns);
        Patch {
            id: m.id.clone(),
            cipher_id: Some(m.cipher_id.clone()),
            organization_id: m.organization_id.clone(),
            base_revision: m.revision_date.clone(),
            set: Vec::new(),
            remove: Vec::new(),
            append_lines: Vec::new(),
            value: ValueChange::Keep,
            answer: None,
        }
    }
    fn set_secret(&self, c: &Value, ns: &Namespace, secret: &[u8]) -> Patch {
        let m = self.marked(c, ns);
        let value = ValueChange::Set {
            source: m.source,
            secret: Zeroizing::new(secret.to_vec()),
            base_mark: m.mark,
            owned: false,
        };
        Patch { value, ..self.keep(c, ns) }
    }
    fn apply(&self, c: &Value, p: &Patch, ns: &Namespace) -> Result<Map<String, Value>, WriteError> {
        apply(c, p, ns, &self.keys, &self.rng, NOW)
    }
    fn new_item(&self, item: &NewItem, ns: &Namespace) -> Result<Map<String, Value>, WriteError> {
        new_item(item, ns, &self.keys, &self.rng)
    }
    fn dec(&self, v: &Value) -> String {
        dec_with(&self.keys.user, v)
    }
}

fn dec_with(key: &SymmetricKey, v: &Value) -> String {
    key.decrypt_str(v.as_str().unwrap()).unwrap().to_string()
}

fn la(name: &str, lines: &[&str]) -> LineAppend {
    LineAppend { name: name.into(), lines: lines.iter().map(|l| Zeroizing::new((*l).into())).collect(), hidden: true }
}

fn fs(name: &str, value: &str, hidden: bool) -> FieldSet {
    FieldSet { name: name.into(), value: Zeroizing::new(value.into()), hidden }
}

/// The server's copy after a write: the body plus response-only metadata.
fn as_server(body: &Map<String, Value>) -> Value {
    let mut b = body.clone();
    b.remove("lastKnownRevisionDate");
    b.insert("id".into(), json!("c1"));
    b.insert("revisionDate".into(), json!("2026-03-03T00:00:00Z"));
    Value::Object(b)
}

/// Decrypted names of every field, in order.
fn names(body: &Map<String, Value>, key: &SymmetricKey) -> Vec<String> {
    body["fields"].as_array().unwrap().iter().map(|f| dec_with(key, &f["name"])).collect()
}

/// Decrypted value (`""` for null) and type of the first field called `name`.
fn field(body: &Map<String, Value>, key: &SymmetricKey, name: &str) -> Option<(String, u64)> {
    body["fields"].as_array().unwrap().iter().find(|f| dec_with(key, &f["name"]) == name).map(|f| {
        let v = if f["value"].is_null() { String::new() } else { dec_with(key, &f["value"]) };
        (v, f["type"].as_u64().unwrap())
    })
}

/// Every top-level key of `c` except `fields` and the response-only ones is unchanged in `body`, and `body` has no
/// key `c` lacks (except `lastKnownRevisionDate`).
fn assert_rest_unchanged(c: &Value, body: &Map<String, Value>, except: &[&str]) {
    for (k, v) in c.as_object().unwrap() {
        if RESPONSE_ONLY.contains(&k.as_str()) || except.contains(&k.as_str()) {
            continue;
        }
        assert_eq!(body.get(k), Some(v), "key {k} changed");
    }
    for k in body.keys() {
        assert!(c.get(k).is_some() || k == "lastKnownRevisionDate" || except.contains(&k.as_str()), "new key {k}");
    }
}

#[test]
fn write_back_to_login_password_keeps_history() {
    let k = fx();
    let mut c = k.login(&[("bwss:id", "x", false)], Some("old"), None);
    c["passwordHistory"] = k.history(5);
    let body = k.apply(&c, &k.set_secret(&c, B, b"new"), B).unwrap();
    assert_eq!(k.dec(&body["login"]["password"]), "new");
    let h = body["passwordHistory"].as_array().unwrap();
    assert_eq!(h.len(), 5);
    assert_eq!(h[0]["password"], c["login"]["password"]);
    assert_eq!(h[0]["lastUsedDate"], NOW_ISO);
    // the oldest entry fell off
    assert_eq!(h[1..], c["passwordHistory"].as_array().unwrap()[..4]);
    assert_eq!(body["login"]["passwordRevisionDate"], NOW_ISO);
    assert_eq!(body["login"]["username"], c["login"]["username"]);
    assert_eq!(body["login"]["uris"], c["login"]["uris"]);
    assert_eq!(body["fields"], c["fields"]);
    assert_eq!(body["lastKnownRevisionDate"], json!("2026-01-02T03:04:05Z"));
    assert_rest_unchanged(&c, &body, &["login", "passwordHistory"]);

    // an identical value is never written (§6.1): nothing is sent
    let same = write::apply(&c, &k.set_secret(&c, B, b"old"), B, &k.keys, &WriteRecord::default(), &k.rng, NOW);
    assert!(same.unwrap().body.is_none());
    // with a field change, the rest is sent and the password is left as it is
    let p = Patch { set: vec![fs("bwss:label", "l", false)], ..k.set_secret(&c, B, b"old") };
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(body["login"], c["login"]);
    assert_eq!(body["passwordHistory"], c["passwordHistory"]);
}

#[test]
fn write_back_to_null_login_password() {
    let k = fx();
    let mut c = k.login(&[("bwss:id", "x", false)], None, None);
    c["passwordHistory"] = Value::Null;
    c["login"] = Value::Null;
    let body = k.apply(&c, &k.set_secret(&c, B, b"new"), B).unwrap();
    assert_eq!(k.dec(&body["login"]["password"]), "new");
    assert_eq!(body["login"]["username"], Value::Null);
    assert_eq!(body["passwordHistory"], json!([]));

    let mut c = k.login(&[("bwss:id", "x", false)], None, None);
    c["passwordHistory"] = Value::Null;
    c["login"] = json!({ "password": null });
    let body = k.apply(&c, &k.set_secret(&c, B, b"new"), B).unwrap();
    assert_eq!(k.dec(&body["login"]["password"]), "new");
    assert_eq!(body["passwordHistory"], json!([]));
    assert_eq!(body["login"]["passwordRevisionDate"], NOW_ISO);
    // an empty value over no password is no change: nothing is sent
    let same = write::apply(&c, &k.set_secret(&c, B, b""), B, &k.keys, &WriteRecord::default(), &k.rng, NOW);
    assert!(same.unwrap().body.is_none());
}

#[test]
fn write_back_to_field_and_notes_leaves_the_rest() {
    let k = fx();
    let fields = [
        ("bwss:id", "x", false),
        ("obsidian:id", "o", false),
        ("bwss:password", "old", true),
        ("dybw:x", "d", false),
        ("plain", "p", false),
    ];
    let c = k.login(&fields, Some("pw"), Some("user notes"));
    let body = k.apply(&c, &k.set_secret(&c, B, b"new"), B).unwrap();
    assert_eq!(field(&body, &k.keys.user, "bwss:password"), Some(("new".into(), 1)));
    let (before, after) = (c["fields"].as_array().unwrap(), body["fields"].as_array().unwrap());
    assert_eq!(after.len(), before.len());
    for i in [0, 1, 3, 4] {
        assert_eq!(after[i], before[i], "field {i} changed");
    }
    // login.password, notes, history, name, uris, folderId, archivedDate unchanged
    assert_rest_unchanged(&c, &body, &["fields"]);
    assert_eq!(k.marked(&as_server(&body), B).value.as_slice(), b"new");

    // NoteBody source: notes change, fields unchanged
    let c = k.note(&[("bwss:id", "x", false), ("obsidian:id", "o", false)], Some("body"));
    let body = k.apply(&c, &k.set_secret(&c, B, b"new"), B).unwrap();
    assert_eq!(k.dec(&body["notes"]), "new");
    assert_eq!(body["fields"], c["fields"]);
    assert_rest_unchanged(&c, &body, &["notes", "passwordHistory"]);
    assert_eq!(body["passwordHistory"], json!([]));

    // Notes source: notes change, fields unchanged
    let c = k.login(&[("bwss:id", "x", false), ("bwss:location", "notes", false)], Some("pw"), Some("big"));
    let body = k.apply(&c, &k.set_secret(&c, B, b"new"), B).unwrap();
    assert_eq!(k.dec(&body["notes"]), "new");
    assert_eq!(body["fields"], c["fields"]);
    assert_rest_unchanged(&c, &body, &["notes"]);
}

#[test]
fn patch_changes_the_first_duplicate_and_removes_every_copy() {
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "1", true), ("bwss:password", "2", true)], None, None);
    let body = k.apply(&c, &k.set_secret(&c, B, b"new"), B).unwrap();
    let after = body["fields"].as_array().unwrap();
    assert_eq!(k.dec(&after[1]["value"]), "new");
    assert_eq!(after[2], c["fields"][2]);

    // set and remove act on the first match too
    let c = k.login(
        &[
            ("bwss:id", "x", false),
            ("bwss:label", "L1", false),
            ("bwss:label", "L2", false),
            ("bwss:content-type", "a", false),
            ("bwss:content-type", "b", false),
        ],
        Some("pw"),
        None,
    );
    let mut p = k.keep(&c, B);
    p.set = vec![fs("bwss:label", "New", false)];
    p.remove = vec!["bwss:content-type".into()];
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(names(&body, &k.keys.user), ["bwss:id", "bwss:label", "bwss:label"]);
    let after = body["fields"].as_array().unwrap();
    assert_eq!(k.dec(&after[1]["value"]), "New");
    assert_eq!(after[2], c["fields"][2]);
}

#[test]
fn set_and_remove_replace_the_attribute_set() {
    let k = fx();
    let c = k.login(
        &[
            ("bwss:id", "x", false),
            ("bwss:attr:a", "1", false),
            ("obsidian:id", "o", false),
            ("bwss:attr:b", "2", false),
        ],
        Some("pw"),
        None,
    );
    let mut p = k.keep(&c, B);
    p.remove = vec!["bwss:attr:".into()];
    p.set = vec![fs("bwss:attr:c", "3", false), fs("bwss:acl", "/x", true), fs("bwss:attr:e", "", false)];
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(names(&body, &k.keys.user), ["bwss:id", "obsidian:id", "bwss:attr:c", "bwss:acl", "bwss:attr:e"]);
    assert_eq!(field(&body, &k.keys.user, "bwss:attr:c"), Some(("3".into(), 0)));
    assert_eq!(field(&body, &k.keys.user, "bwss:acl"), Some(("/x".into(), 1)));
    // an empty value is no value, and reads back as ""
    assert_eq!(body["fields"][4]["value"], Value::Null);
    assert_eq!(k.marked(&as_server(&body), B).attributes["e"], "");
    assert_eq!(body["fields"][1], c["fields"][2]);
    assert_rest_unchanged(&c, &body, &["fields"]);
}

#[test]
fn response_only_keys_are_stripped_and_history_always_sent() {
    let k = fx();
    let item_key = SymmetricKey::generate(&k.rng).unwrap();
    let mut c = k.note(&[], Some("body"));
    c["key"] = json!(k.keys.user.encrypt(&item_key.to_bytes(), &k.rng).unwrap());
    c["fields"] = k.fields_with(&item_key, &[("bwss:id", "x", false), ("bwss:password", "old", true)]);
    c["notes"] = k.e_with(&item_key, "body");
    c["name"] = k.e_with(&item_key, "Note");
    c["passwordHistory"] = Value::Null;
    for key in RESPONSE_ONLY {
        c.as_object_mut().unwrap().entry(key).or_insert(json!("present"));
    }
    c["deletedDate"] = Value::Null;
    let mut p = k.set_secret(&c, B, b"new");
    p.set = vec![fs("bwss:attr:a", "1", false)];
    p.append_lines = vec![la("bwss:acl", &["/bin/x"])];
    let body = k.apply(&c, &p, B).unwrap();
    for key in RESPONSE_ONLY {
        assert!(!body.contains_key(key), "{key} was sent");
    }
    assert_eq!(body["passwordHistory"], json!([]));
    assert_eq!(body["lastKnownRevisionDate"], json!("2026-01-02T03:04:05Z"));
    assert_eq!(body["key"], c["key"]);
    assert_eq!(field(&body, &item_key, "bwss:password"), Some(("new".into(), 1)));
    assert_eq!(field(&body, &item_key, "bwss:attr:a"), Some(("1".into(), 0)));
    assert_eq!(field(&body, &item_key, "bwss:acl"), Some(("/bin/x".into(), 1)));
    assert_eq!(dec_with(&item_key, &body["notes"]), "body");
    assert_eq!(k.marked(&as_server(&body), B).value.as_slice(), b"new");
}

#[test]
fn oversize_field_value_moves_to_empty_notes_or_fails() {
    let k = fx();
    let big = vec![b'x'; 4_000];
    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
    let body = k.apply(&c, &k.set_secret(&c, B, &big), B).unwrap();
    assert_eq!(k.dec(&body["notes"]).as_bytes(), big.as_slice());
    assert_eq!(field(&body, &k.keys.user, "bwss:location"), Some(("notes".into(), 0)));
    assert_eq!(field(&body, &k.keys.user, "bwss:password"), None);
    assert_eq!(body["login"], c["login"]);
    let m = k.marked(&as_server(&body), B);
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::Notes, big.as_slice()));

    // the notes already hold the tool's secret: they are reused
    let c = k.login(
        &[("bwss:id", "x", false), ("bwss:password", "old", true), ("bwss:location", "notes", false)],
        None,
        Some("old big"),
    );
    let body = k.apply(&c, &k.set_secret(&c, B, &big), B).unwrap();
    assert_eq!(k.dec(&body["notes"]).as_bytes(), big.as_slice());
    assert_eq!(names(&body, &k.keys.user), ["bwss:id", "bwss:location"]);

    // notes encrypting the empty string are empty (the plugin's empty-notes fix)
    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), Some(""));
    let body = k.apply(&c, &k.set_secret(&c, B, &big), B).unwrap();
    assert_eq!(k.dec(&body["notes"]).as_bytes(), big.as_slice());

    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), Some("mine"));
    assert_eq!(k.apply(&c, &k.set_secret(&c, B, &big), B), Err(WriteError::NotesTaken));

    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
    assert_eq!(k.apply(&c, &k.set_secret(&c, B, &[b'x'; 8_000]), B), Err(WriteError::TooLong));

    let c = k.login(&[("bwss:id", "x", false)], Some("pw"), None);
    assert_eq!(k.apply(&c, &k.set_secret(&c, B, &big), B), Err(WriteError::TooLong));

    let c = k.note(&[("bwss:id", "x", false)], Some("body"));
    assert_eq!(k.apply(&c, &k.set_secret(&c, B, &[b'x'; 8_000]), B), Err(WriteError::TooLong));
}

#[test]
fn a_fitting_value_clears_the_stale_notes_copy() {
    let k = fx();
    let small = b"short".to_vec();
    let pw = ("bwss:password", "old", true);
    let id = ("bwss:id", "x", false);

    // fits, notes marked as the tool's: notes cleared, location removed, same write (ADR 0010)
    let c = k.login(&[id, pw, ("bwss:location", "notes", false)], None, Some("stale copy"));
    let body = k.apply(&c, &k.set_secret(&c, B, &small), B).unwrap();
    assert!(body["notes"].is_null());
    assert_eq!(names(&body, &k.keys.user), ["bwss:id", "bwss:password"]);
    assert_eq!(field(&body, &k.keys.user, "bwss:password"), Some(("short".into(), 1)));

    // fits, notes hold something else, location is blank or absent: nothing cleared
    for loc in ["", "  "] {
        let c = k.login(&[id, pw, ("bwss:location", loc, false)], None, Some("mine"));
        let body = k.apply(&c, &k.set_secret(&c, B, &small), B).unwrap();
        assert_eq!(k.dec(&body["notes"]), "mine", "location {loc:?}");
        assert_eq!(field(&body, &k.keys.user, "bwss:location"), Some((loc.into(), 0)), "location {loc:?}");
    }
    let c = k.login(&[id, pw], None, Some("mine"));
    let body = k.apply(&c, &k.set_secret(&c, B, &small), B).unwrap();
    assert_eq!(k.dec(&body["notes"]), "mine");
}

#[test]
fn clearing_the_stale_copy_drops_every_location_mark() {
    let k = fx();
    for second in ["notes", "attachment"] {
        let c = k.login(
            &[
                ("bwss:id", "x", false),
                ("bwss:password", "old", true),
                ("bwss:location", "notes", false),
                ("bwss:location", second, false),
            ],
            None,
            Some("stale"),
        );
        let body = k.apply(&c, &k.set_secret(&c, B, b"short"), B).unwrap();
        assert!(body["notes"].is_null(), "second {second:?}");
        assert_eq!(names(&body, &k.keys.user), ["bwss:id", "bwss:password"], "second {second:?}");
        k.marked(&as_server(&body), B);
    }
}

#[test]
fn moving_into_the_notes_sets_the_first_location_in_place() {
    // The plugin's "move into empty notes over an empty obsidian:location"; the first copy changes and later ones
    // stay (§3.1), where the plugin drops them.
    let k = fx_with(3, MarkScheme::Obsidian);
    let long = "y".repeat(4_000);
    let c = k.login(
        &[
            ("obsidian:id", "db", false),
            ("obsidian:location", "", false),
            ("obsidian:password", "token", true),
            ("obsidian:location", "attic", false),
        ],
        Some("pw"),
        None,
    );
    let body = k.apply(&c, &k.set_secret(&c, O, long.as_bytes()), O).unwrap();
    assert_eq!(names(&body, &k.keys.user), ["obsidian:id", "obsidian:location", "obsidian:location"]);
    assert_eq!(field(&body, &k.keys.user, "obsidian:location"), Some(("notes".into(), 0)));
    assert_eq!(body["fields"][2], c["fields"][3]);
    assert_eq!(k.marked(&as_server(&body), O).value.as_slice(), long.as_bytes());
}

#[test]
fn strip_clears_the_notes_for_a_padded_mark_only() {
    let k = fx();
    for mark in ["notes", " notes ", "notes\n"] {
        let c = k.note(&[("bwss:id", "x", false), ("bwss:location", mark, false)], Some("mine"));
        assert!(strip(&c, B, &k.keys, &k.rng).unwrap()["notes"].is_null(), "{mark:?}");
    }
    for other in ["Notes", "", "  "] {
        let c = k.note(&[("bwss:id", "x", false), ("bwss:location", other, false)], Some("mine"));
        assert_eq!(strip(&c, B, &k.keys, &k.rng).unwrap()["notes"], c["notes"], "{other:?}");
    }
}

#[test]
fn a_padded_mark_is_a_mark_when_writing() {
    let k = fx();
    let id = ("bwss:id", "x", false);
    let pw = ("bwss:password", "old", true);
    // fitting value: the stale copy behind a padded mark is cleared
    let c = k.login(&[id, pw, ("bwss:location", " notes\n", false)], None, Some("stale"));
    let body = k.apply(&c, &k.set_secret(&c, B, b"short"), B).unwrap();
    assert!(body["notes"].is_null());
    assert_eq!(field(&body, &k.keys.user, "bwss:location"), None);
    // oversize value: the notes behind a padded mark are reused, not NotesTaken
    let big = vec![b'a'; 6000];
    let c = k.login(&[id, pw, ("bwss:location", " notes ", false)], None, Some("old big"));
    let body = k.apply(&c, &k.set_secret(&c, B, &big), B).unwrap();
    assert_eq!(k.dec(&body["notes"]).as_bytes(), big.as_slice());
}

#[test]
fn binary_secrets_only_go_into_tool_storage() {
    let k = fx();
    let u = &k.keys.user;
    let bin = [0xff_u8, 0];

    // Field source: base64 in bwss:password; then text removes the encoding
    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
    let body = k.apply(&c, &k.set_secret(&c, B, &bin), B).unwrap();
    assert_eq!(field(&body, u, "bwss:password"), Some(("/wA=".into(), 1)));
    assert_eq!(field(&body, u, "bwss:encoding"), Some(("base64".into(), 0)));
    assert_eq!(body["login"], c["login"]);
    let c = as_server(&body);
    assert_eq!(k.marked(&c, B).value.as_slice(), &bin);
    let body = k.apply(&c, &k.set_secret(&c, B, b"text"), B).unwrap();
    assert_eq!(field(&body, u, "bwss:password"), Some(("text".into(), 1)));
    assert_eq!(field(&body, u, "bwss:encoding"), None);
    assert_eq!(k.marked(&as_server(&body), B).value.as_slice(), b"text");

    // Notes source: base64 in the notes
    let c = k.login(&[("bwss:id", "x", false), ("bwss:location", "notes", false)], None, Some("big"));
    let body = k.apply(&c, &k.set_secret(&c, B, &bin), B).unwrap();
    assert_eq!(k.dec(&body["notes"]), "/wA=");
    assert_eq!(field(&body, u, "bwss:encoding"), Some(("base64".into(), 0)));
    assert_eq!(field(&body, u, "bwss:password"), None);
    let m = k.marked(&as_server(&body), B);
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::Notes, &bin[..]));

    // LoginPassword source: a new field holds it, the login is untouched
    let c = k.login(&[("bwss:id", "x", false), ("obsidian:id", "o", false)], Some("pw"), None);
    let body = k.apply(&c, &k.set_secret(&c, B, &bin), B).unwrap();
    assert_eq!(body["login"], c["login"]);
    assert_eq!(body["passwordHistory"], c["passwordHistory"]);
    assert_eq!(names(&body, u), ["bwss:id", "obsidian:id", "bwss:password", "bwss:encoding"]);
    assert_eq!(body["fields"].as_array().unwrap()[..2], c["fields"].as_array().unwrap()[..]);
    assert_eq!(field(&body, u, "bwss:password"), Some(("/wA=".into(), 1)));
    assert_rest_unchanged(&c, &body, &["fields"]);
    let m = k.marked(&as_server(&body), B);
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::Field, &bin[..]));

    // NoteBody source: same, the notes are untouched
    let c = k.note(&[("bwss:id", "x", false)], Some("body"));
    let body = k.apply(&c, &k.set_secret(&c, B, &bin), B).unwrap();
    assert_eq!(body["notes"], c["notes"]);
    assert_eq!(names(&body, u), ["bwss:id", "bwss:password", "bwss:encoding"]);
    assert_rest_unchanged(&c, &body, &["fields", "passwordHistory"]);
    let m = k.marked(&as_server(&body), B);
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::Field, &bin[..]));

    // NoteBody source, binary too large for a field, user notes present
    let huge = vec![0xff_u8; 4_000];
    assert_eq!(k.apply(&c, &k.set_secret(&c, B, &huge), B), Err(WriteError::NotesTaken));
    // ... and with empty notes it goes to the notes, owned by the tool from then on
    let c = k.note(&[("bwss:id", "x", false)], None);
    let body = k.apply(&c, &k.set_secret(&c, B, &huge), B).unwrap();
    assert_eq!(field(&body, u, "bwss:location"), Some(("notes".into(), 0)));
    assert_eq!(field(&body, u, "bwss:password"), None);
    let m = k.marked(&as_server(&body), B);
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::Notes, huge.as_slice()));
}

#[test]
fn an_owned_change_goes_to_the_tool_field_not_the_users_value() {
    // A queued binary write already added bwss:password; a later text change merged into it stays there.
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false)], Some("pw"), None);
    let mut p = k.set_secret(&c, B, b"text");
    if let ValueChange::Set { owned, .. } = &mut p.value {
        *owned = true;
    }
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(body["login"], c["login"]);
    assert_eq!(field(&body, &k.keys.user, "bwss:password"), Some(("text".into(), 1)));
    let c = k.note(&[("bwss:id", "x", false)], Some("body"));
    let mut p = k.set_secret(&c, B, b"text");
    if let ValueChange::Set { owned, .. } = &mut p.value {
        *owned = true;
    }
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(body["notes"], c["notes"]);
    assert_eq!(field(&body, &k.keys.user, "bwss:password"), Some(("text".into(), 1)));
}

#[test]
fn retry_checks_abort_on_the_fresh_copy() {
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false), ("obsidian:id", "o", false)], Some("pw"), None);
    let p = k.set_secret(&c, B, b"new");

    // value source changed on the server (mark differs)
    let mut fresh = c.clone();
    fresh["login"]["password"] = k.e("theirs");
    assert_eq!(k.apply(&fresh, &p, B), Err(WriteError::SourceChanged));
    // a bwss:password appeared: the source itself changed
    let mut fresh = c.clone();
    fresh["fields"].as_array_mut().unwrap().push(k.fields(&[("bwss:password", "pw", true)])[0].clone());
    assert_eq!(k.apply(&fresh, &p, B), Err(WriteError::SourceChanged));
    // Keep never compares marks
    let mut fresh = c.clone();
    fresh["login"]["password"] = k.e("other");
    assert!(k.apply(&fresh, &k.keep(&c, B), B).is_ok());

    // trashed
    let mut fresh = c.clone();
    fresh["deletedDate"] = json!("2026-05-05T00:00:00Z");
    assert_eq!(k.apply(&fresh, &p, B), Err(WriteError::Gone));
    assert_eq!(k.apply(&fresh, &k.keep(&c, B), B), Err(WriteError::Gone));

    // bwss:id removed, changed or blanked
    let fresh = k.login(&[("obsidian:id", "o", false)], Some("pw"), None);
    assert_eq!(k.apply(&fresh, &k.keep(&c, B), B), Err(WriteError::Unmarked));
    let fresh = k.login(&[("bwss:id", "y", false), ("obsidian:id", "o", false)], Some("pw"), None);
    assert_eq!(k.apply(&fresh, &k.keep(&c, B), B), Err(WriteError::Unmarked));
    let fresh = k.login(&[("bwss:id", " ", false), ("obsidian:id", "o", false)], Some("pw"), None);
    assert_eq!(k.apply(&fresh, &k.keep(&c, B), B), Err(WriteError::Unmarked));
    // cannot be read right now: distinct from unmarked, so the change is not dropped
    let mut fresh = c.clone();
    fresh["key"] = json!("2.bad|bad|bad");
    assert_eq!(k.apply(&fresh, &k.keep(&c, B), B), Err(WriteError::Uninspectable(Uninspectable::ItemKey)));
    assert_eq!(k.apply(&fresh, &p, B), Err(WriteError::Uninspectable(Uninspectable::ItemKey)));
    // no longer readable as the tool's item (skipped)
    let mut fresh = c.clone();
    fresh["type"] = json!(3);
    assert_eq!(k.apply(&fresh, &k.keep(&c, B), B), Err(WriteError::Unmarked));

    // a feature this tool lacks (`dybw:requires`): never written to, and the change is kept (ADR 0020)
    let fresh = k.login(&[("bwss:id", "x", false), ("dybw:requires", "bwss:acl-host", false)], Some("pw"), None);
    assert_eq!(k.apply(&fresh, &k.keep(&c, B), B), Err(WriteError::Unsupported));
    assert_eq!(WriteError::Unsupported.code(), Some("unsupported"));

    // only a foreign field changed: the write goes through and keeps it
    let mut fresh = c.clone();
    fresh["fields"][1]["value"] = k.e("o2");
    fresh["name"] = k.e("Renamed");
    fresh["revisionDate"] = json!("2026-04-04T00:00:00Z");
    let body = k.apply(&fresh, &p, B).unwrap();
    assert_eq!(body["fields"][1], fresh["fields"][1]);
    assert_eq!(body["name"], fresh["name"]);
    assert_eq!(body["lastKnownRevisionDate"], json!("2026-04-04T00:00:00Z"));
    assert_eq!(k.dec(&body["login"]["password"]), "new");

    // a copy without revisionDate falls back to the patch's base
    let mut undated = c.clone();
    undated.as_object_mut().unwrap().remove("revisionDate");
    let body = k.apply(&undated, &p, B).unwrap();
    assert_eq!(body["lastKnownRevisionDate"], json!("2026-01-02T03:04:05Z"));
}

#[test]
fn a_value_re_encrypted_elsewhere_is_not_a_conflict() {
    // Official clients re-encrypt every EncString with a fresh IV on any save: renaming the item must not look like a
    // new password.
    let k = fx();
    for c in [
        k.login(&[("bwss:id", "x", false)], Some("pw"), None),
        k.login(&[("bwss:id", "x", false), ("bwss:password", "pw", true)], None, None),
        k.note(&[("bwss:id", "x", false)], Some("body")),
    ] {
        let p = k.set_secret(&c, B, b"new");
        let mut fresh = c.clone();
        fresh["name"] = k.e("Renamed");
        if c["type"] == 2 {
            fresh["notes"] = k.e("body");
        } else if c["login"]["password"].is_string() {
            fresh["login"]["password"] = k.e("pw");
        } else {
            fresh["fields"][1]["value"] = k.e("pw");
        }
        assert_ne!(fresh, c);
        assert!(k.apply(&fresh, &p, B).is_ok());
    }
}

fn item(value: &[u8], tool_fields: Vec<FieldSet>) -> NewItem {
    NewItem {
        id: "abc123".into(),
        value: Zeroizing::new(value.to_vec()),
        name: "GitHub token".into(),
        folder_id: Some("f1".into()),
        tool_fields,
    }
}

#[test]
fn new_items_are_personal_secure_notes() {
    let k = fx();
    let u = &k.keys.user;
    let tool = vec![fs("bwss:attr:service", "github", false), fs("bwss:acl", "/usr/bin/git", true)];
    let body = k.new_item(&item(b"s", tool.clone()), B).unwrap();
    assert_eq!(body["type"], 2);
    assert_eq!(body["notes"], Value::Null);
    assert_eq!(body["login"], Value::Null);
    assert_eq!(body["organizationId"], Value::Null);
    assert_eq!(body["folderId"], "f1");
    assert_eq!(body["secureNote"], json!({ "type": 0 }));
    assert_eq!(body["passwordHistory"], json!([]));
    assert_eq!(body["key"], Value::Null);
    assert_eq!(k.dec(&body["name"]), "GitHub token");
    assert!(!body.contains_key("lastKnownRevisionDate"));
    assert_eq!(names(&body, u), ["bwss:id", "bwss:password", "bwss:attr:service", "bwss:acl"]);
    assert_eq!(field(&body, u, "bwss:id"), Some(("abc123".into(), 0)));
    assert_eq!(field(&body, u, "bwss:password"), Some(("s".into(), 1)));
    assert_eq!(field(&body, u, "bwss:acl"), Some(("/usr/bin/git".into(), 1)));
    let m = k.marked(&as_server(&body), B);
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::Field, &b"s"[..]));

    // no folder and a binary secret
    let mut it = item(&[0xff, 0], tool);
    it.folder_id = None;
    let body = k.new_item(&it, B).unwrap();
    assert_eq!(body["folderId"], Value::Null);
    assert_eq!(names(&body, u), ["bwss:id", "bwss:password", "bwss:encoding", "bwss:attr:service", "bwss:acl"]);
    assert_eq!(k.marked(&as_server(&body), B).value.as_slice(), &[0xff_u8, 0][..]);

    // a 4,000-byte secret goes to the notes
    let big = vec![b'x'; 4_000];
    let body = k.new_item(&item(&big, vec![]), B).unwrap();
    assert_eq!(k.dec(&body["notes"]).as_bytes(), big.as_slice());
    assert_eq!(field(&body, u, "bwss:location"), Some(("notes".into(), 0)));
    assert_eq!(field(&body, u, "bwss:password"), None);
    let m = k.marked(&as_server(&body), B);
    assert_eq!((m.source, m.value.as_slice()), (ValueSource::Notes, big.as_slice()));
    assert_eq!(k.new_item(&item(&[b'x'; 8_000], vec![]), B), Err(WriteError::TooLong));
}

#[test]
fn plugin_new_secret_request() {
    // newSecretRequest: obsidian:id, then obsidian:password (or the location), then obsidian:scope.
    let k = fx_with(5, MarkScheme::Obsidian);
    let u = &k.keys.user;
    let scope = vec![fs("obsidian:scope", "vault:Work", false)];
    let mut it = item(b"tok", scope.clone());
    it.id = "api-token".into();
    let body = k.new_item(&it, O).unwrap();
    assert_eq!(names(&body, u), ["obsidian:id", "obsidian:password", "obsidian:scope"]);
    assert_eq!(field(&body, u, "obsidian:password"), Some(("tok".into(), 1)));
    assert_eq!(k.marked(&as_server(&body), O).tool_fields[0].1.as_str(), "vault:Work");

    // a value too long for a field goes into the (still empty) notes
    let long = "z".repeat(4_000);
    let mut it = item(long.as_bytes(), scope.clone());
    it.id = "big".into();
    let body = k.new_item(&it, O).unwrap();
    assert_eq!(names(&body, u), ["obsidian:id", "obsidian:location", "obsidian:scope"]);
    assert_eq!(k.dec(&body["notes"]), long);
    // too long even for the notes
    let mut it = item("z".repeat(8_000).as_bytes(), scope);
    it.id = "huge".into();
    assert_eq!(k.new_item(&it, O), Err(WriteError::TooLong));
    // an empty secret is stored as no value ("uploads ... an empty secret as no value")
    let mut it = item(b"", vec![]);
    it.id = "blank".into();
    let body = k.new_item(&it, O).unwrap();
    assert_eq!(body["fields"][1]["value"], Value::Null);
    assert_eq!(body["notes"], Value::Null);
    assert_eq!(k.marked(&as_server(&body), O).value.as_slice(), b"");
    // binary is refused: the namespace stores text only
    assert_eq!(k.new_item(&item(&[0xff], vec![]), O), Err(WriteError::BinaryNotSupported));
}

#[test]
fn plugin_pushes_an_empty_secret_as_no_value() {
    let k = fx_with(6, MarkScheme::Obsidian);
    let field_item = k.note(&[("obsidian:id", "blank", false), ("obsidian:password", "token", true)], Some("mine"));
    let body = k.apply(&field_item, &k.set_secret(&field_item, O, b""), O).unwrap();
    assert_eq!(body["fields"][1]["value"], Value::Null);
    assert_eq!(body["notes"], field_item["notes"]);
    assert_eq!(k.marked(&as_server(&body), O).value.as_slice(), b"");

    let login = k.login(&[("obsidian:id", "site", false)], Some("pw"), None);
    let body = k.apply(&login, &k.set_secret(&login, O, b""), O).unwrap();
    assert_eq!(body["login"]["password"], Value::Null);
    assert_eq!(body["passwordHistory"][0]["password"], login["login"]["password"]);
    assert_eq!(k.marked(&as_server(&body), O).value.as_slice(), b"");

    let note = k.note(&[("obsidian:id", "note", false)], Some("body"));
    let body = k.apply(&note, &k.set_secret(&note, O, b""), O).unwrap();
    assert_eq!(body["notes"], Value::Null);
}

#[test]
fn obsidian_writes_leave_a_blank_encoding_and_refuse_binary() {
    // obsidian implements no encoding: a blank obsidian:encoding is read as absent and left as it is, as the plugin
    // does; bwss removes its own on a text write (ADR 0005).
    let k = fx_with(8, MarkScheme::Obsidian);
    let c = k.login(
        &[("obsidian:id", "a", false), ("obsidian:password", "old", true), ("obsidian:encoding", " ", false)],
        Some("pw"),
        None,
    );
    let body = k.apply(&c, &k.set_secret(&c, O, b"new"), O).unwrap();
    assert_eq!(body["fields"][2], c["fields"][2]);
    assert_eq!(field(&body, &k.keys.user, "obsidian:password"), Some(("new".into(), 1)));
    assert_eq!(k.apply(&c, &k.set_secret(&c, O, &[0xc3, 0x28]), O), Err(WriteError::BinaryNotSupported));
}

#[test]
fn oversize_tool_field_values_never_reach_the_server() {
    let k = fx();
    let long = "x".repeat(4_000);
    let c = k.login(&[("bwss:id", "x", false)], Some("pw"), None);
    for (name, hidden) in [("bwss:label", false), ("bwss:attr:k", false), ("bwss:acl", true)] {
        let p = Patch { set: vec![fs(name, &long, hidden)], ..k.keep(&c, B) };
        assert_eq!(k.apply(&c, &p, B), Err(WriteError::TooLong), "{name}");
    }
    let p = Patch { append_lines: vec![la("bwss:acl", &[&long])], ..k.keep(&c, B) };
    assert_eq!(k.apply(&c, &p, B), Err(WriteError::TooLong));
    // Just under the limit is fine.
    let p = Patch { set: vec![fs("bwss:label", &"x".repeat(3_000), false)], ..k.keep(&c, B) };
    assert!(k.apply(&c, &p, B).is_ok());

    let it = item(b"s", vec![fs("bwss:attr:k", &long, false)]);
    assert_eq!(k.new_item(&it, B), Err(WriteError::TooLong));
}

/// A secure note holding nothing but its name, as a delete step 1 leaves one.
fn bare(k: &Fx) -> Value {
    let created = as_server(&k.new_item(&item(b"s", vec![]), B).unwrap());
    as_server(&strip(&created, B, &k.keys, &k.rng).unwrap())
}

fn with_field(k: &Fx, c: &Value, name: &str, value: &str) -> Value {
    let mut c = c.clone();
    let f = json!({ "type": 0, "name": k.e(name), "value": k.e(value), "linkedId": null });
    c["fields"].as_array_mut().unwrap().push(f);
    c
}

fn with_key(c: &Value, key: &str, v: Value) -> Value {
    let mut c = c.clone();
    c[key] = v;
    c
}

/// `bare` turned into a login whose `login` object is `login`.
fn with_login(c: &Value, login: Value) -> Value {
    let mut c = with_key(c, "type", json!(1));
    c["login"] = login;
    c
}

#[test]
fn foreign_content_decides_the_trash() {
    let k = fx();
    let e = |s: &str| k.e(s);
    let b = bare(&k);
    let foreign = |c: &Value| has_foreign_content(c, B, &k.keys);
    assert_eq!(foreign(&b), Ok(false));
    for (what, c) in [
        ("username", with_login(&b, json!({ "username": e("me") }))),
        ("password", with_login(&b, json!({ "password": e("pw") }))),
        ("totp", with_login(&b, json!({ "totp": e("otpauth://totp/x") }))),
        ("uri", with_login(&b, json!({ "uris": [{ "uri": e("https://a.b"), "match": null }] }))),
        ("second uri", with_login(&b, json!({ "uris": [{ "uri": null }, { "uri": e("https://a.b") }] }))),
        ("notes", with_key(&b, "notes", e("x"))),
        ("other namespace", with_field(&k, &b, "obsidian:id", "t")),
        ("other namespace, empty value", with_field(&k, &b, "obsidian:id", "")),
        ("no namespace", with_field(&k, &b, "pin", "1")),
        ("attachment", with_key(&b, "attachments", json!([{}]))),
        ("passkey", with_login(&b, json!({ "fido2Credentials": [{}] }))),
        ("history", with_key(&b, "passwordHistory", k.history(1))),
    ] {
        assert_eq!(foreign(&c), Ok(true), "{what}");
    }

    // types other than login and secure note are never bare
    for t in [0, 3, 4, 5, 6] {
        assert_eq!(foreign(&with_key(&b, "type", json!(t))), Ok(true), "type {t}");
    }
    assert_eq!(foreign(&with_key(&b, "type", Value::Null)), Ok(true), "no type");

    // a null field name has no namespace
    let nameless = with_key(&b, "fields", json!([{ "type": 0, "name": null, "value": null }]));
    assert_eq!(foreign(&nameless), Ok(true), "null field name");

    // the item name alone does not count, and neither do the tool's own fields
    assert_eq!(foreign(&with_key(&b, "name", e("Something the user named"))), Ok(false), "item name");
    let still_marked = with_field(&k, &with_field(&k, &b, "bwss:id", "abc"), "bwss:attr:x", "y");
    assert_eq!(foreign(&still_marked), Ok(false), "tool fields");

    // empty after decryption is empty; so are null and absent, and empty lists
    let empty_login = json!({
        "username": e(""), "password": null, "totp": e(""),
        "uris": [{ "uri": e(""), "match": null }, { "uri": null }], "fido2Credentials": [],
    });
    let mut c = with_login(&b, empty_login);
    c["notes"] = e("");
    c["attachments"] = json!([]);
    c["passwordHistory"] = json!([]);
    assert_eq!(foreign(&c), Ok(false), "encrypted empty strings");
    c["attachments"] = Value::Null;
    c["passwordHistory"] = Value::Null;
    c["login"] = Value::Null;
    assert_eq!(foreign(&c), Ok(false), "nulls");
    let mut no_keys = c.clone();
    no_keys.as_object_mut().unwrap().remove("login");
    no_keys.as_object_mut().unwrap().remove("fields");
    assert_eq!(foreign(&no_keys), Ok(false), "absent keys");
}

#[test]
fn unreadable_items_are_never_reported_bare() {
    let k = fx();
    let other = fx_with(99, MarkScheme::Bwss);
    let b = bare(&k);
    let x = other.e("x");
    // each needed value is under a key that is not ours
    for (what, c) in [
        ("notes", with_key(&b, "notes", x.clone())),
        ("username", with_login(&b, json!({ "username": x }))),
        ("password", with_login(&b, json!({ "password": x }))),
        ("totp", with_login(&b, json!({ "totp": x }))),
        ("uri", with_login(&b, json!({ "uris": [{ "uri": x }] }))),
        ("field name", with_key(&b, "fields", json!([{ "type": 0, "name": other.e("bwss:id"), "value": null }]))),
        ("item key", with_key(&b, "key", json!("2.garbage|x|y"))),
        ("empty string", with_key(&b, "notes", json!(""))),
    ] {
        assert!(matches!(has_foreign_content(&c, B, &k.keys), Err(WriteError::Crypto(_))), "{what}");
    }
    // foreign content found without decrypting wins over an unreadable value
    let c = with_key(&with_key(&b, "notes", x), "attachments", json!([{}]));
    assert_eq!(has_foreign_content(&c, B, &k.keys), Ok(true));
}

#[test]
fn strip_removes_tool_fields_and_tool_notes_only() {
    let k = fx();
    let u = &k.keys.user;

    // a login the user marked by hand: password and notes are theirs
    let c = k.login(
        &[
            ("bwss:id", "x", false),
            ("obsidian:id", "t", false),
            ("bwss:attr:a", "1", false),
            ("pin", "1", false),
            ("bwss:id", "dup", false),
            ("bwss:acl", "/bin/x", true),
        ],
        Some("pw"),
        Some("user text"),
    );
    let body = strip(&c, B, &k.keys, &k.rng).unwrap();
    assert_eq!(names(&body, u), ["obsidian:id", "pin"]);
    assert_eq!(body["fields"][0], c["fields"][1], "kept fields are byte for byte");
    assert_eq!(body["fields"][1], c["fields"][3]);
    assert_eq!(body["lastKnownRevisionDate"], c["revisionDate"]);
    assert_eq!(body["login"]["password"], c["login"]["password"], "login password untouched");
    assert_rest_unchanged(&c, &body, &["fields"]);
    assert_eq!(body["notes"], c["notes"]);
    assert_eq!(has_foreign_content(&as_server(&body), B, &k.keys), Ok(true), "the user's login stays");

    // a field with a null name is kept
    let mut c = k.note(&[("bwss:id", "x", false)], None);
    let nameless = json!({ "type": 0, "name": null, "value": null });
    c["fields"].as_array_mut().unwrap().push(nameless.clone());
    assert_eq!(strip(&c, B, &k.keys, &k.rng).unwrap()["fields"], json!([nameless]));

    // bwss:location=notes: the notes held the tool's secret
    let c = k.note(&[("bwss:id", "x", false), ("bwss:location", "notes", false), ("pin", "1", false)], Some("secret"));
    let body = strip(&c, B, &k.keys, &k.rng).unwrap();
    assert_eq!(body["notes"], Value::Null);
    assert_eq!(names(&body, u), ["pin"]);
    assert_eq!(body["passwordHistory"], json!([]), "history is always sent");
    assert_rest_unchanged(&c, &body, &["fields", "notes", "passwordHistory"]);

    // any other location keeps the notes; the first location decides
    let c = k.note(&[("bwss:id", "x", false), ("bwss:location", "login", false)], Some("text"));
    assert_eq!(strip(&c, B, &k.keys, &k.rng).unwrap()["notes"], c["notes"]);
    let c = k.note(
        &[("bwss:id", "x", false), ("bwss:location", "field", false), ("bwss:location", "notes", false)],
        Some("text"),
    );
    assert_eq!(strip(&c, B, &k.keys, &k.rng).unwrap()["notes"], c["notes"]);

    // a notes-located item with a value in the notes and nothing else is bare after
    let c = k.note(&[("bwss:id", "x", false), ("bwss:location", "notes", false)], Some("secret"));
    assert_eq!(has_foreign_content(&as_server(&strip(&c, B, &k.keys, &k.rng).unwrap()), B, &k.keys), Ok(false));

    // the item key and unknown keys pass through; fields are read with the item key
    let ik = SymmetricKey::generate(&k.rng).unwrap();
    let mut c = k.note(&[], None);
    c["key"] = json!(k.keys.user.encrypt(&ik.to_bytes(), &k.rng).unwrap());
    c["xSomethingNew"] = json!({ "a": 1 });
    c["fields"] = k.fields_with(&ik, &[("bwss:id", "x", false), ("pin", "1", false)]);
    let body = strip(&c, B, &k.keys, &k.rng).unwrap();
    assert_eq!(body["key"], c["key"]);
    assert_eq!(body["xSomethingNew"], c["xSomethingNew"]);
    assert_eq!(names(&body, &ik), ["pin"]);
}

#[test]
fn strip_refuses_trashed_and_unreadable_items() {
    let k = fx();
    let c = k.note(&[("bwss:id", "x", false)], None);
    assert_eq!(
        strip(&with_key(&c, "deletedDate", json!("2026-05-05T00:00:00Z")), B, &k.keys, &k.rng),
        Err(WriteError::Gone)
    );
    let mut undated = c.clone();
    undated.as_object_mut().unwrap().remove("revisionDate");
    assert_eq!(strip(&undated, B, &k.keys, &k.rng), Err(WriteError::Uninspectable(Uninspectable::Value)));
    let other = fx_with(99, MarkScheme::Bwss);
    assert!(matches!(strip(&c, B, &other.keys, &other.rng), Err(WriteError::Crypto(_))));
    let mut located = k.note(&[("bwss:location", "notes", false)], Some("s"));
    located["fields"][0]["value"] = other.e("notes");
    assert!(matches!(strip(&located, B, &k.keys, &k.rng), Err(WriteError::Crypto(_))));
}

#[test]
fn oversized_cipher_is_never_written() {
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
    let p = k.set_secret(&c, B, b"new");
    let big = with_key(&c, "junk", json!("a".repeat(super::scan::MAX_CIPHER)));
    let held = Err(WriteError::Uninspectable(Uninspectable::TooLarge));
    assert_eq!(k.apply(&big, &p, B), held);
    assert_eq!(strip(&big, B, &k.keys, &k.rng), held);
    assert_eq!(has_foreign_content(&big, B, &k.keys), held.map(|_: Map<String, Value>| false));
}

#[test]
fn unreadable_blob_is_never_written() {
    // A blob that does not open is held; a field-level body would drop `data` (response-only) and wipe the blob.
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
    let p = k.set_secret(&c, B, b"new");
    let blob = with_key(&with_key(&c, "passwordHistory", json!(null)), "data", json!("{\"format_version\":1,\"x\":2}"));
    let held = Err(WriteError::Uninspectable(Uninspectable::Blob));
    assert_eq!(k.apply(&blob, &p, B), held);
    assert_eq!(k.apply(&blob, &k.keep(&c, B), B), held);
    assert_eq!(strip(&blob, B, &k.keys, &k.rng), held);
    assert_eq!(has_foreign_content(&blob, B, &k.keys), held.map(|_: Map<String, Value>| false));
    // a `data` without format_version is ordinary response-only metadata: written over, never sent back
    let plain = with_key(&c, "data", json!("{\"x\":1}"));
    let body = k.apply(&plain, &p, B).unwrap();
    assert!(!body.contains_key("data"));
    assert_eq!(field(&body, &k.keys.user, "bwss:password"), Some(("new".into(), 1)));
}

#[test]
fn organization_items_use_the_organization_key() {
    let k = fx();
    let org = &k.keys.orgs["org1"];
    let mut c = k.login(&[], Some("pw"), None);
    c["organizationId"] = json!("org1");
    c["fields"] = k.fields_with(org, &[("bwss:id", "x", false), ("bwss:password", "old", true), ("pin", "1", false)]);
    let body = k.apply(&c, &k.set_secret(&c, B, b"new"), B).unwrap();
    assert_eq!(field(&body, org, "bwss:password"), Some(("new".into(), 1)));
    assert_eq!(body["organizationId"], "org1");
    let body = strip(&c, B, &k.keys, &k.rng).unwrap();
    assert_eq!(names(&body, org), ["pin"]);
    // pin is foreign; login fields are under the user key in this fixture, so the field check answers first
    assert_eq!(has_foreign_content(&c, B, &k.keys), Ok(true));

    // read-only: never written
    let ro = with_key(&c, "edit", json!(false));
    assert_eq!(k.apply(&ro, &k.keep(&c, B), B), Err(WriteError::ReadOnly));
    assert_eq!(strip(&ro, B, &k.keys, &k.rng), Err(WriteError::ReadOnly));

    // an organization whose key is not unlocked
    let locked = with_key(&c, "organizationId", json!("org2"));
    let missing = Err(WriteError::Uninspectable(Uninspectable::OrganizationKeyMissing));
    assert_eq!(k.apply(&locked, &k.keep(&c, B), B), missing);
    assert_eq!(strip(&locked, B, &k.keys, &k.rng), missing);
    // (a non-empty history is foreign without decrypting anything, so it answers first)
    assert_eq!(has_foreign_content(&locked, B, &k.keys), Ok(true));
    let no_history = with_key(&locked, "passwordHistory", json!([]));
    assert_eq!(has_foreign_content(&no_history, B, &k.keys), missing.map(|_: Map<String, Value>| false));
}

#[test]
fn type7_item_is_written_type7() {
    let k = fx();
    for alg in [CoseAlgorithm::Xaes256Gcm, CoseAlgorithm::XChaCha20Poly1305] {
        let ik = SymmetricKey::generate_cose(alg, &k.rng).unwrap();
        let mut c = k.login(&[], Some("pw"), None);
        c["key"] = json!(k.keys.user.encrypt(&ik.to_bytes(), &k.rng).unwrap());
        c["login"]["password"] = k.e_with(&ik, "pw");
        c["fields"] = k.fields_with(&ik, &[("bwss:id", "x", false)]);
        let body = k.apply(&c, &k.set_secret(&c, B, &[0xff]), B).unwrap();
        let fields = body["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 3);
        for f in &fields[1..] {
            assert!(f["name"].as_str().unwrap().starts_with("7."));
            assert!(f["value"].as_str().unwrap().starts_with("7."));
        }
        assert_eq!(field(&body, &ik, "bwss:password"), Some(("/w==".into(), 1)));
        let body = k.apply(&c, &k.set_secret(&c, B, b"next"), B).unwrap();
        assert!(body["login"]["password"].as_str().unwrap().starts_with("7."));
        assert_eq!(dec_with(&ik, &body["login"]["password"]), "next");
    }
}

#[test]
fn encrypted_len_matches_encryption() {
    let k = fx();
    let keys = [
        SymmetricKey::generate(&k.rng).unwrap(),
        SymmetricKey::generate_cose(CoseAlgorithm::Xaes256Gcm, &k.rng).unwrap(),
        SymmetricKey::generate_cose(CoseAlgorithm::XChaCha20Poly1305, &k.rng).unwrap(),
    ];
    for key in &keys {
        for len in [0, 1, 15, 16, 17, 23, 24, 31, 32, 33, 100, 255, 256, 3_700, 3_800, 7_400, 70_000] {
            let enc = key.encrypt_str(&"a".repeat(len), &k.rng).unwrap();
            assert_eq!(encrypted_len(len, key), enc.len(), "{len}");
        }
    }
    // type 7 is longer than type 2 for the same text
    assert!(encrypted_len(100, &keys[1]) > encrypted_len(100, &keys[0]));
}

#[test]
fn write_errors_carry_no_value() {
    // Review Focus 2: no error built from a real secret shows it.
    let k = fx();
    let secret = "hunter2-SECRET-VALUE";
    let big = format!("{secret}{}", "x".repeat(8_000));
    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", secret, true)], Some(secret), Some(secret));
    let mut errors = vec![
        k.apply(&c, &k.set_secret(&c, B, big.as_bytes()), B).unwrap_err(),
        k.apply(&c, &k.set_secret(&c, B, &big.as_bytes()[..4_000]), B).unwrap_err(),
    ];
    let mut fresh = c.clone();
    fresh["fields"][1]["value"] = k.e("changed-SECRET");
    errors.push(k.apply(&fresh, &k.set_secret(&c, B, secret.as_bytes()), B).unwrap_err());
    let other = fx_with(99, MarkScheme::Bwss);
    errors.push(strip(&with_key(&c, "notes", other.e(secret)), B, &other.keys, &other.rng).unwrap_err());
    errors.push(has_foreign_content(&with_key(&k.note(&[], None), "notes", other.e(secret)), B, &k.keys).unwrap_err());
    let ob = fx_with(4, MarkScheme::Obsidian);
    let oc = ob.login(&[("obsidian:id", "x", false)], Some(secret), None);
    errors.push(ob.apply(&oc, &ob.set_secret(&oc, O, &[0xff, b'S', b'E']), O).unwrap_err());
    let mut ro = c.clone();
    ro["organizationId"] = json!("org1");
    ro["edit"] = json!(false);
    ro["fields"] = k.fields_with(&k.keys.orgs["org1"], &[("bwss:id", "x", false), ("bwss:password", secret, true)]);
    errors.push(k.apply(&ro, &k.keep(&ro, B), B).unwrap_err());
    errors.push(k.apply(&with_key(&c, "deletedDate", json!("2026-01-01T00:00:00Z")), &k.keep(&c, B), B).unwrap_err());
    errors.push(k.apply(&k.login(&[], Some(secret), None), &k.keep(&c, B), B).unwrap_err());
    errors.push(k.apply(&with_key(&c, "key", json!("2.x|y|z")), &k.keep(&c, B), B).unwrap_err());
    let codes: Vec<_> = errors.iter().map(WriteError::code).collect();
    assert_eq!(
        codes,
        [
            Some("too-long"),
            Some("notes-hold-user-text"),
            Some("value-source-changed"),
            None,
            None,
            None,
            None,
            None,
            None,
            None
        ]
    );
    for e in &errors {
        for shown in [format!("{e}"), format!("{e:?}")] {
            assert!(!shown.contains("SECRET") && !shown.contains("hunter2"), "{shown}");
            assert!(!shown.contains("2.") || shown.contains("2.x"), "no ciphertext: {shown}");
        }
    }
    assert!(matches!(errors[3], WriteError::Crypto(CryptoError::BadMac | CryptoError::WrongKey)));
    assert_eq!(errors[5], WriteError::BinaryNotSupported);
}

#[test]
fn patch_round_trips_for_the_queue() {
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false)], Some("pw"), None);
    let mut p = k.set_secret(&c, B, &[0xff, 1]);
    p.set = vec![fs("bwss:label", "L", false)];
    p.remove = vec!["bwss:attr:".into()];
    let json = serde_json::to_string(&p).unwrap();
    assert!(json.contains("\"login-password\""), "{json}");
    let back: Patch = serde_json::from_str(&json).unwrap();
    // A queue written before `append_lines` still reads.
    let mut old: Value = serde_json::from_str(&json).unwrap();
    assert!(old.as_object_mut().unwrap().remove("append_lines").is_some());
    assert!(serde_json::from_value::<Patch>(old).unwrap().append_lines.is_empty());
    assert_eq!(k.apply(&c, &back, B).unwrap()["fields"].as_array().unwrap().len(), 4);
    let keep: Patch = serde_json::from_str(&serde_json::to_string(&k.keep(&c, B)).unwrap()).unwrap();
    assert!(matches!(keep.value, ValueChange::Keep));
}

#[test]
fn a_clock_outside_the_year_range_is_an_error() {
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false)], Some("old"), None);
    let p = k.set_secret(&c, B, b"new");
    // year 10000 and year -1: no four-digit date
    for ms in [253_402_300_800_000, -62_167_219_200_001, i64::MAX, i64::MIN] {
        assert_eq!(apply(&c, &p, B, &k.keys, &k.rng, ms), Err(WriteError::BadClock), "{ms}");
    }
    assert!(apply(&c, &p, B, &k.keys, &k.rng, 253_402_300_799_999).is_ok());
    assert!(apply(&c, &p, B, &k.keys, &k.rng, -62_167_219_200_000).is_ok());
    // no date is needed when the value is kept
    assert!(apply(&c, &k.keep(&c, B), B, &k.keys, &k.rng, i64::MAX).is_ok());
}

// Blob ciphers (ADR 0021): a write keeps a blob a blob, and a new item is a blob on a version 2 account.

fn bx_patch(k: &Bx, c: &Value, secret: Option<&[u8]>) -> Patch {
    let s = scan(c, B, &k.keys, &Organizations::All);
    let Scan::Marked(m) = s else { panic!("expected Marked, got {s:?}") };
    let value = match secret {
        Some(secret) => ValueChange::Set {
            source: m.source,
            secret: Zeroizing::new(secret.to_vec()),
            base_mark: m.mark,
            owned: false,
        },
        None => ValueChange::Keep,
    };
    Patch {
        id: m.id.clone(),
        cipher_id: Some(m.cipher_id.clone()),
        organization_id: None,
        base_revision: m.revision_date.clone(),
        set: Vec::new(),
        remove: Vec::new(),
        append_lines: Vec::new(),
        value,
        answer: None,
    }
}

fn bx_write(k: &Bx, c: &Value, secret: &[u8]) -> Result<Map<String, Value>, WriteError> {
    apply(c, &bx_patch(k, c, Some(secret)), B, &k.keys, &k.rng, NOW)
}

/// The blob a body sends, opened as the server's copy.
fn sent(k: &Bx, body: &Map<String, Value>) -> OpenBlob {
    open_blob(&as_server(body), &k.keys.user).unwrap()
}

fn sent_value(k: &Bx, body: &Map<String, Value>) -> (ValueSource, Vec<u8>) {
    let s = scan(&as_server(body), B, &k.keys, &Organizations::All);
    let Scan::Marked(m) = s else { panic!("expected Marked, got {s:?}") };
    (m.source, m.value.to_vec())
}

/// The id of the content key a blob body is sealed with.
fn cek_id(k: &Bx, body: &Map<String, Value>) -> [u8; 16] {
    let item = k.keys.user.decrypt_key(body["key"].as_str().unwrap()).unwrap();
    let data: Value = serde_json::from_str(body["data"].as_str().unwrap()).unwrap();
    *parse_cek(&item.decrypt(data["wrapped_cek"].as_str().unwrap()).unwrap()).unwrap().id()
}

fn blob_fields(fields: &[(&str, Cbor)]) -> Cbor {
    Cbor::Array(
        fields
            .iter()
            .map(|(n, v)| {
                Cbor::Map(vec![
                    (t("name"), t(n)),
                    (t("value"), v.clone()),
                    (t("type"), Cbor::Uint(0)),
                    (t("linkedId"), Cbor::Null),
                ])
            })
            .collect(),
    )
}

/// A `CipherBlobV1` from its parts, in this order; a cipher of `ty`.
fn blob_cipher(k: &Bx, ty: u64, parts: Vec<(&str, Cbor)>) -> Value {
    let mut c = k.cipher(Cbor::Map(parts.into_iter().map(|(key, v)| (t(key), v)).collect()));
    c["type"] = json!(ty);
    c
}

fn secure_note(k: &Bx, fields: &[(&str, &str)], notes: Option<&str>) -> Value {
    let fields: Vec<(&str, Cbor)> = fields.iter().map(|(n, v)| (*n, t(v))).collect();
    let type_data = Cbor::Map(vec![(t("type"), t("secureNote")), (t("secureNoteType"), Cbor::Uint(0))]);
    let notes = notes.map_or(Cbor::Null, t);
    blob_cipher(
        k,
        2,
        vec![("name", t("Note")), ("notes", notes), ("typeData", type_data), ("fields", blob_fields(&fields))],
    )
}

fn history_entry(password: &str, date: &str) -> Cbor {
    Cbor::Map(vec![(t("password"), t(password)), (t("lastUsedDate"), t(date))])
}

fn names_of(blob: &OpenBlob) -> Vec<Option<&str>> {
    blob.field_names()
}

#[test]
fn blob_write_uses_a_fresh_cek() {
    let k = Bx::new();
    let c = k.cipher(blob_login(&[("bwss:id", "a"), ("bwss:password", "old")], Some("pw"), None));
    let p = bx_patch(&k, &c, Some(b"new"));
    let one = apply(&c, &p, B, &k.keys, &k.rng, NOW).unwrap();
    let two = apply(&c, &p, B, &k.keys, &k.rng, NOW).unwrap();
    let ids = [cek_id(&k, c.as_object().unwrap()), cek_id(&k, &one), cek_id(&k, &two)];
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[0], ids[2]);
    assert_ne!(ids[1], ids[2]);
    assert_ne!(one["data"], two["data"]);
}

#[test]
fn blob_write_keeps_the_item_key() {
    let k = Bx::new();
    let mut c = k.cipher(blob_login(&[("bwss:id", "a"), ("bwss:password", "old")], Some("pw"), Some("mine")));
    for (key, v) in [
        ("folderId", json!("f1")),
        ("favorite", json!(true)),
        ("xUnknown", json!({ "a": 1 })),
        ("attachments", json!([{ "id": "att" }])),
        ("edit", json!(true)),
    ] {
        c[key] = v;
    }
    let body = bx_write(&k, &c, b"new").unwrap();
    assert_eq!(body["key"], c["key"]);
    for key in ["name", "notes", "login", "fields", "passwordHistory"] {
        assert_eq!(body[key], Value::Null, "{key}");
    }
    assert_eq!(body["lastKnownRevisionDate"], c["revisionDate"]);
    assert_ne!(body["data"], c["data"]);
    assert_rest_unchanged(&c, &body, &[]);
    assert_eq!(sent_value(&k, &body), (ValueSource::Field, b"new".to_vec()));
    let blob = sent(&k, &body);
    assert_eq!((blob.login_password(), blob.notes()), (Some("pw"), Some("mine")));
    // A kept value still seals the content again.
    let body = apply(&c, &bx_patch(&k, &c, None), B, &k.keys, &k.rng, NOW).unwrap();
    assert_eq!(sent_value(&k, &body), (ValueSource::Field, b"old".to_vec()));
    assert_ne!(body["data"], c["data"]);
    // A field-level cipher on the same account never becomes a blob.
    let fields = Fx { rng: SeededRandom::new(3), keys: Bx::new().keys };
    let plain = fields.note(&[("bwss:id", "a", false), ("bwss:password", "old", true)], None);
    let body = fields.apply(&plain, &fields.set_secret(&plain, B, b"new"), B).unwrap();
    assert!(!body.contains_key("data") && !body.contains_key("key"));
    assert_eq!(field(&body, &fields.keys.user, "bwss:password"), Some(("new".into(), 1)));
}

#[test]
fn blob_create_needs_version_2() {
    assert_eq!(BLOB_SECURITY_VERSION, 2);
    let mut k = Bx::new();
    let it = item(b"s", vec![fs("bwss:label", "L", false)]);
    for v in [0, 1] {
        k.keys.security_version = v;
        let body = new_item(&it, B, &k.keys, &k.rng).unwrap();
        assert!(!body.contains_key("data"), "{v}");
        assert_eq!(body["key"], Value::Null);
        assert_eq!(names(&body, &k.keys.user), ["bwss:id", "bwss:password", "bwss:label"]);
    }
    let mut item_keys = Vec::new();
    for v in [BLOB_SECURITY_VERSION, 3] {
        k.keys.security_version = v;
        let body = new_item(&it, B, &k.keys, &k.rng).unwrap();
        for key in ["name", "notes", "login", "secureNote", "fields", "passwordHistory"] {
            assert_eq!(body[key], Value::Null, "{key}");
        }
        assert_eq!(
            (&body["type"], &body["organizationId"], &body["folderId"]),
            (&json!(2), &Value::Null, &json!("f1"))
        );
        assert!(!body.contains_key("lastKnownRevisionDate"));
        // A fresh 64-byte item key, wrapped under the user key.
        let item_key = k.keys.user.decrypt_key(body["key"].as_str().unwrap()).unwrap();
        assert_eq!(item_key.to_bytes().len(), 64);
        item_keys.push(item_key.to_bytes().to_vec());
        let blob = sent(&k, &body);
        assert_eq!(names_of(&blob), [Some("bwss:id"), Some("bwss:password"), Some("bwss:label")]);
        assert_eq!(blob.get("name"), Some(&t("GitHub token")));
        assert_eq!(blob.get("notes"), Some(&Cbor::Null));
        assert_eq!(
            blob.get("typeData"),
            Some(&Cbor::Map(vec![(t("type"), t("secureNote")), (t("secureNoteType"), Cbor::Uint(0))]))
        );
        let Some(Cbor::Array(fields)) = blob.get("fields") else { panic!("no fields") };
        let kinds: Vec<_> = fields.iter().map(|f| super::blob::get(f, "type").cloned()).collect();
        assert_eq!(kinds, [Some(Cbor::Uint(0)), Some(Cbor::Uint(1)), Some(Cbor::Uint(0))]);
        assert_eq!(sent_value(&k, &body), (ValueSource::Field, b"s".to_vec()));
    }
    assert_ne!(item_keys[0], item_keys[1]);
    // §6.4 on the plaintext: too long for a field goes to the new item's notes, too long for the notes fails.
    let body = new_item(&item(&[b'x'; 6_000], vec![]), B, &k.keys, &k.rng).unwrap();
    assert_eq!(names_of(&sent(&k, &body)), [Some("bwss:id"), Some("bwss:location")]);
    assert_eq!(sent_value(&k, &body), (ValueSource::Notes, vec![b'x'; 6_000]));
    assert_eq!(new_item(&item(&[b'x'; 10_001], vec![]), B, &k.keys, &k.rng), Err(WriteError::TooLong));
    let oversize = item(b"s", vec![fs("bwss:label", &"x".repeat(5_001), false)]);
    assert_eq!(new_item(&oversize, B, &k.keys, &k.rng), Err(WriteError::TooLong));
}

#[test]
fn blob_login_write_back_keeps_the_history() {
    let k = Bx::new();
    let mut content = blob_login(&[("bwss:id", "a")], Some("cur"), None);
    let Cbor::Map(entries) = &mut content else { unreachable!() };
    let history: Vec<Cbor> = (0..5).map(|i| history_entry(&format!("h{i}"), "2025-01-01T00:00:00Z")).collect();
    entries.push((t("passwordHistory"), Cbor::Array(history)));
    let c = k.cipher(content);
    let body = bx_write(&k, &c, b"next").unwrap();
    let blob = sent(&k, &body);
    assert_eq!(blob.login_password(), Some("next"));
    let Some(Cbor::Array(history)) = blob.get("passwordHistory") else { panic!("no history") };
    assert_eq!(history.len(), 5);
    assert_eq!(history[0], history_entry("cur", NOW_ISO));
    assert_eq!(history[1], history_entry("h0", "2025-01-01T00:00:00Z"));
    assert_eq!(history[4], history_entry("h3", "2025-01-01T00:00:00Z"));
    let Some(type_data) = blob.get("typeData") else { panic!("no typeData") };
    assert_eq!(super::blob::get(type_data, "passwordRevisionDate"), Some(&t(NOW_ISO)));
    assert_eq!(super::blob::get(type_data, "username"), Some(&t("me")));
    // An identical value is not written: nothing is sent, and with a field change the history stays.
    let same = write::apply(&c, &bx_patch(&k, &c, Some(b"cur")), B, &k.keys, &WriteRecord::default(), &k.rng, NOW);
    assert!(same.unwrap().body.is_none());
    let p = Patch { set: vec![fs("bwss:label", "l", false)], ..bx_patch(&k, &c, Some(b"cur")) };
    let body = apply(&c, &p, B, &k.keys, &k.rng, NOW).unwrap();
    let blob = sent(&k, &body);
    let Some(Cbor::Array(history)) = blob.get("passwordHistory") else { panic!("no history") };
    assert_eq!(history[0], history_entry("h0", "2025-01-01T00:00:00Z"));
    // No old password: no history entry; an empty value is no value.
    let c = k.cipher(blob_login(&[("bwss:id", "a")], None, None));
    let blob = sent(&k, &bx_write(&k, &c, b"x").unwrap());
    assert_eq!((blob.login_password(), blob.get("passwordHistory")), (Some("x"), None));
    let c = k.cipher(blob_login(&[("bwss:id", "a")], Some("cur"), None));
    let blob = sent(&k, &bx_write(&k, &c, b"").unwrap());
    let type_data = blob.get("typeData").unwrap();
    assert_eq!(super::blob::get(type_data, "password"), Some(&Cbor::Null));
    assert_eq!(blob.get("passwordHistory"), Some(&Cbor::Array(vec![history_entry("cur", NOW_ISO)])));
    // Too long for the password, on its plaintext length.
    assert_eq!(bx_write(&k, &c, &[b'x'; 5_001]), Err(WriteError::TooLong));
    assert!(bx_write(&k, &c, &[b'x'; 5_000]).is_ok());
    // Binary goes into a new tool field; the password and its history are left alone (ADR 0005).
    let body = bx_write(&k, &c, &[0xff, 0]).unwrap();
    let blob = sent(&k, &body);
    assert_eq!(names_of(&blob), [Some("bwss:id"), Some("bwss:password"), Some("bwss:encoding")]);
    assert_eq!((blob.login_password(), blob.get("passwordHistory")), (Some("cur"), None));
    assert_eq!(sent_value(&k, &body), (ValueSource::Field, vec![0xff, 0]));
}

#[test]
fn blob_size_rules_use_the_plaintext() {
    let k = Bx::new();
    let c = k.cipher(blob_login(&[("bwss:id", "a"), ("bwss:password", "old")], Some("pw"), None));
    // 4,500 bytes fit a blob field, though a type 2 string of them would not.
    let body = bx_write(&k, &c, &[b'x'; 4_500]).unwrap();
    assert_eq!(names_of(&sent(&k, &body)), [Some("bwss:id"), Some("bwss:password")]);
    // Over 5,000: into the empty notes, with the location mark; over 10,000: refused.
    let body = bx_write(&k, &c, &[b'x'; 6_000]).unwrap();
    let blob = sent(&k, &body);
    assert_eq!(names_of(&blob), [Some("bwss:id"), Some("bwss:location")]);
    assert_eq!(blob.notes().map(str::len), Some(6_000));
    assert_eq!(bx_write(&k, &c, &[b'x'; 10_001]), Err(WriteError::TooLong));
    // Notes the user wrote are never overwritten.
    let mine = k.cipher(blob_login(&[("bwss:id", "a"), ("bwss:password", "old")], Some("pw"), Some("mine")));
    assert_eq!(bx_write(&k, &mine, &[b'x'; 6_000]), Err(WriteError::NotesTaken));
    // A value that fits again clears the stale copy in the notes and its mark (ADR 0010).
    let stale = k.cipher(blob_login(
        &[("bwss:id", "a"), ("bwss:password", "old"), ("bwss:location", " notes "), ("bwss:location", "x")],
        Some("pw"),
        Some("stale"),
    ));
    let blob = sent(&k, &bx_write(&k, &stale, b"fresh").unwrap());
    assert_eq!(names_of(&blob), [Some("bwss:id"), Some("bwss:password")]);
    assert_eq!((blob.notes(), blob.get("notes")), (None, Some(&Cbor::Null)));
    // The notes as the value source.
    let in_notes = k.cipher(blob_login(&[("bwss:id", "a"), ("bwss:location", "notes")], Some("pw"), Some("old")));
    let body = bx_write(&k, &in_notes, b"n2").unwrap();
    assert_eq!(sent_value(&k, &body), (ValueSource::Notes, b"n2".to_vec()));
    assert_eq!(bx_write(&k, &in_notes, &[b'x'; 10_001]), Err(WriteError::TooLong));
    let note = secure_note(&k, &[("bwss:id", "a")], Some("body"));
    let body = bx_write(&k, &note, b"b2").unwrap();
    assert_eq!(sent_value(&k, &body), (ValueSource::NoteBody, b"b2".to_vec()));
    // A tool field over the limit never reaches the server; an empty one is no value.
    let p = Patch { set: vec![fs("bwss:label", &"x".repeat(5_001), false)], ..bx_patch(&k, &c, None) };
    assert_eq!(apply(&c, &p, B, &k.keys, &k.rng, NOW), Err(WriteError::TooLong));
    let p = Patch { set: vec![fs("bwss:label", "", false)], ..bx_patch(&k, &c, None) };
    let blob = sent(&k, &apply(&c, &p, B, &k.keys, &k.rng, NOW).unwrap());
    assert_eq!(blob.field_value(2), None);
}

#[test]
fn blob_tool_fields_and_unknown_keys() {
    let k = Bx::new();
    let fido = Cbor::Array(vec![Cbor::Map(vec![(t("credentialId"), t("c"))])]);
    let type_data = Cbor::Map(vec![
        (t("type"), t("login")),
        (t("password"), t("pw")),
        (t("fido2Credentials"), fido.clone()),
        (t("xTypeData"), Cbor::bytes(vec![1, 2])),
    ]);
    let fields = Cbor::Array(vec![
        Cbor::Map(vec![(t("name"), t("bwss:id")), (t("value"), t("a")), (t("xField"), Cbor::Bool(true))]),
        Cbor::Map(vec![(t("name"), t("bwss:attr:k")), (t("value"), t("1")), (t("type"), Cbor::Uint(1))]),
        Cbor::Map(vec![(t("name"), t("other:id")), (t("value"), t("b"))]),
        Cbor::Map(vec![(t("name"), t("bwss:attr:k")), (t("value"), t("2"))]),
        Cbor::Map(vec![(t("name"), t("bwss:label")), (t("value"), t("old")), (t("type"), Cbor::Uint(1))]),
        Cbor::Map(vec![(t("value"), t("nameless"))]),
    ]);
    let unknown = Cbor::Map(vec![(t("nested"), Cbor::Array(vec![Cbor::Nint(4), Cbor::Null]))]);
    let c = blob_cipher(
        &k,
        1,
        vec![
            ("xFirst", unknown.clone()),
            ("name", t("Blob")),
            ("typeData", type_data.clone()),
            ("fields", fields),
            ("notes", Cbor::Null),
        ],
    );
    let p = Patch {
        set: vec![fs("bwss:label", "new", false), fs("bwss:attr:j", "3", false)],
        remove: vec!["bwss:attr:".into()],
        ..bx_patch(&k, &c, None)
    };
    let blob = sent(&k, &apply(&c, &p, B, &k.keys, &k.rng, NOW).unwrap());
    assert_eq!(names_of(&blob), [Some("bwss:id"), Some("other:id"), Some("bwss:label"), None, Some("bwss:attr:j")]);
    let Some(Cbor::Array(fields)) = blob.get("fields") else { panic!("no fields") };
    // Changed in place, kind kept; every key of an untouched field kept as decoded.
    assert_eq!(
        fields[2],
        Cbor::Map(vec![(t("name"), t("bwss:label")), (t("value"), t("new")), (t("type"), Cbor::Uint(1))])
    );
    assert_eq!(
        fields[0],
        Cbor::Map(vec![(t("name"), t("bwss:id")), (t("value"), t("a")), (t("xField"), Cbor::Bool(true))])
    );
    assert_eq!(
        fields[4],
        Cbor::Map(vec![
            (t("name"), t("bwss:attr:j")),
            (t("value"), t("3")),
            (t("type"), Cbor::Uint(0)),
            (t("linkedId"), Cbor::Null)
        ])
    );
    assert_eq!((blob.get("xFirst"), blob.get("typeData")), (Some(&unknown), Some(&type_data)));
    let Some(Cbor::Map(_)) = blob.get("typeData") else { panic!() };
    // The content's keys keep their order.
    let open = sent(&k, &apply(&c, &bx_patch(&k, &c, Some(b"next")), B, &k.keys, &k.rng, NOW).unwrap());
    let Some(Cbor::Map(td)) = open.get("typeData") else { panic!("no typeData") };
    let keys: Vec<_> = td.iter().map(|(key, _)| key.clone()).collect();
    assert_eq!(keys, [t("type"), t("password"), t("fido2Credentials"), t("xTypeData"), t("passwordRevisionDate")]);
    assert_eq!(super::blob::get(open.get("typeData").unwrap(), "fido2Credentials"), Some(&fido));
}

#[test]
fn blob_strip_and_foreign_content() {
    let k = Bx::new();
    let c = secure_note(
        &k,
        &[("bwss:id", "a"), ("bwss:location", "notes"), ("other:id", "b"), ("bwss:attr:x", "1")],
        Some("secret"),
    );
    let body = strip(&c, B, &k.keys, &k.rng).unwrap();
    assert_eq!(body["key"], c["key"]);
    for key in ["name", "notes", "login", "fields", "passwordHistory"] {
        assert_eq!(body[key], Value::Null, "{key}");
    }
    assert_eq!(body["lastKnownRevisionDate"], c["revisionDate"]);
    let blob = sent(&k, &body);
    assert_eq!((names_of(&blob), blob.notes()), (vec![Some("other:id")], None));
    assert_eq!(has_foreign_content(&as_server(&body), B, &k.keys), Ok(true));
    // Notes the user wrote stay.
    let mine = secure_note(&k, &[("bwss:id", "a"), ("bwss:password", "s")], Some("mine"));
    let body = strip(&mine, B, &k.keys, &k.rng).unwrap();
    assert_eq!(sent(&k, &body).notes(), Some("mine"));
    let bare = secure_note(&k, &[("bwss:id", "a"), ("bwss:password", "s")], None);
    let body = strip(&bare, B, &k.keys, &k.rng).unwrap();
    assert_eq!(names_of(&sent(&k, &body)), Vec::<Option<&str>>::new());
    assert_eq!(has_foreign_content(&as_server(&body), B, &k.keys), Ok(false));

    // Each kind of foreign content of §8.2, inside the blob.
    let login = |td: Vec<(&str, Cbor)>, rest: Vec<(&str, Cbor)>| {
        let mut type_data = vec![(t("type"), t("login"))];
        type_data.extend(td.into_iter().map(|(key, v)| (t(key), v)));
        let mut parts = vec![("name", t("L")), ("typeData", Cbor::Map(type_data))];
        parts.extend(rest);
        has_foreign_content(&blob_cipher(&k, 1, parts), B, &k.keys).unwrap()
    };
    let uris = |uri: Cbor| Cbor::Array(vec![Cbor::Map(vec![(t("uri"), uri), (t("match"), Cbor::Null)])]);
    let cases = [
        (vec![], vec![], false),
        (vec![("username", t("")), ("password", Cbor::Null), ("uris", uris(Cbor::Null))], vec![], false),
        (vec![("uris", t("not a list")), ("fido2Credentials", Cbor::Array(vec![]))], vec![], false),
        (vec![("username", t("me"))], vec![], true),
        (vec![("password", t("pw"))], vec![], true),
        (vec![("totp", t("otp"))], vec![], true),
        (vec![("uris", uris(t("https://x")))], vec![], true),
        (vec![("fido2Credentials", Cbor::Array(vec![Cbor::Null]))], vec![], true),
        (vec![], vec![("passwordHistory", Cbor::Array(vec![]))], false),
        (vec![], vec![("passwordHistory", Cbor::Array(vec![history_entry("h", "2025-01-01T00:00:00Z")]))], true),
        (vec![], vec![("notes", t(""))], false),
        (vec![], vec![("notes", t("n"))], true),
        (vec![], vec![("fields", blob_fields(&[("bwss:id", t("a"))]))], false),
        (vec![], vec![("fields", blob_fields(&[("note", t("a"))]))], true),
        (vec![], vec![("fields", Cbor::Array(vec![Cbor::Map(vec![(t("value"), t("v"))])]))], true),
    ];
    for (i, (td, rest, want)) in cases.into_iter().enumerate() {
        assert_eq!(login(td, rest), want, "case {i}");
    }
    // An attachment, and a type the tool does not read, count without opening the blob.
    let mut c = secure_note(&k, &[("bwss:id", "a")], None);
    c["attachments"] = json!([{ "id": "att" }]);
    assert_eq!(has_foreign_content(&c, B, &k.keys), Ok(true));
    let mut card = super::blob_tests::tampered(&secure_note(&k, &[("bwss:id", "a")], None));
    card["type"] = json!(3);
    assert_eq!(has_foreign_content(&card, B, &k.keys), Ok(true));
    card["type"] = json!(2);
    assert_eq!(has_foreign_content(&card, B, &k.keys), Err(WriteError::Uninspectable(Uninspectable::Blob)));
    assert_eq!(strip(&card, B, &k.keys, &k.rng), Err(WriteError::Uninspectable(Uninspectable::Blob)));
}

#[test]
fn organization_blob_is_never_written() {
    let k = Bx::new();
    let org = &k.keys.orgs["org1"];
    let mut c = k.sealed_with(org, &versioned(blob_login(&[("bwss:id", "a")], Some("pw"), None)), json!(1));
    c["organizationId"] = json!("org1");
    let held = Err(WriteError::Uninspectable(Uninspectable::NewerFormat));
    assert_eq!(strip(&c, B, &k.keys, &k.rng), held);
    let p = bx_patch(&k, &k.cipher(blob_login(&[("bwss:id", "a")], None, None)), None);
    assert_eq!(apply(&c, &p, B, &k.keys, &k.rng, NOW), held);
    assert_eq!(has_foreign_content(&c, B, &k.keys), held.map(|_: Map<String, Value>| false));
    // A trashed blob is gone, as any item.
    let mut gone = k.cipher(blob_login(&[("bwss:id", "a")], Some("pw"), None));
    gone["deletedDate"] = json!("2026-01-03T00:00:00Z");
    assert_eq!(strip(&gone, B, &k.keys, &k.rng), Err(WriteError::Gone));
}

// Password history protection (ADR 0016).

use HistoryAnswer::{KeepSeparate, WriteToLogin};
use HistoryQuestion::{EvictsForeign, FirstWriteBack};

type Answer = Option<(HistoryQuestion, HistoryAnswer)>;

fn ask(q: HistoryQuestion) -> Option<WriteError> {
    Some(WriteError::Ask(q))
}

/// `set_secret` with `answer`, applied under `record`.
fn guarded(k: &Fx, c: &Value, secret: &[u8], answer: Answer, record: &WriteRecord) -> Result<ApplyOutcome, WriteError> {
    let p = Patch { answer, ..k.set_secret(c, B, secret) };
    write::apply(c, &p, B, &k.keys, record, &k.rng, NOW)
}

/// The body `guarded` sends.
fn sent_body(out: Result<ApplyOutcome, WriteError>) -> Map<String, Value> {
    out.ok().and_then(|o| o.body).unwrap()
}

fn history_of(k: &Fx, body: &Map<String, Value>) -> Vec<String> {
    body["passwordHistory"].as_array().unwrap().iter().map(|e| k.dec(&e["password"])).collect()
}

#[test]
fn record_caps_at_six() {
    let mut record = WriteRecord::default();
    for i in 0..8 {
        record_write(&mut record, [i; 32]);
    }
    assert_eq!(record.written, [[7; 32], [6; 32], [5; 32], [4; 32], [3; 32], [2; 32]]);
    assert!(record.confirmed);
    assert_eq!(FirstWriteBack.code(), "first-write-back");
    assert_eq!(EvictsForeign.code(), "evicts-foreign-history");
    // The question is named, never a value.
    assert_eq!(WriteError::Ask(EvictsForeign).to_string(), "the write needs the user's answer: evicts-foreign-history");
    assert_eq!(WriteError::Ask(FirstWriteBack).code(), None);
}

#[test]
fn seven_own_writes_in_a_row_ask_nothing() {
    // The password and all five history entries can be this device's: the record must hold six.
    let k = fx();
    let mut c = k.login(&[("bwss:id", "x", false)], Some("p0"), None);
    c["passwordHistory"] = json!([]);
    let mut record = WriteRecord { written: vec![k.keys.marker.mark("x", "p0")], confirmed: true };
    for i in 1..=7 {
        let out = guarded(&k, &c, format!("p{i}").as_bytes(), None, &record).unwrap();
        record_write(&mut record, out.wrote_login.unwrap());
        c = as_server(&out.body.unwrap());
    }
    assert_eq!(history_of(&k, c.as_object().unwrap()), ["p6", "p5", "p4", "p3", "p2"]);
}

#[test]
fn first_write_back_asks_until_confirmed() {
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false)], Some("old"), None);
    let mut record = WriteRecord::default();
    assert_eq!(guarded(&k, &c, b"new", None, &record).err(), ask(FirstWriteBack));
    // An answer to the other question does not cover this one.
    assert_eq!(guarded(&k, &c, b"new", Some((EvictsForeign, WriteToLogin)), &record).err(), ask(FirstWriteBack));
    let out = guarded(&k, &c, b"new", Some((FirstWriteBack, WriteToLogin)), &record).unwrap();
    assert_eq!(k.dec(&out.body.unwrap()["login"]["password"]), "new");
    assert_eq!(out.wrote_login, Some(k.keys.marker.mark("x", "new")));
    record_write(&mut record, out.wrote_login.unwrap());
    // Confirmed, and the history (2 entries) is not full: nothing to ask.
    let body = sent_body(guarded(&k, &c, b"newer", None, &record));
    assert_eq!(history_of(&k, &body), ["old", "h0", "h1"]);
}

#[test]
fn a_full_history_asks_before_evicting_a_foreign_password() {
    let k = fx();
    let mut c = k.login(&[("bwss:id", "x", false)], Some("old"), None);
    c["passwordHistory"] = k.history(5);
    let mark = |t: &str| k.keys.marker.mark("x", t);
    let foreign = WriteRecord { written: vec![mark("h0"), mark("old")], confirmed: true };
    assert_eq!(guarded(&k, &c, b"new", None, &foreign).err(), ask(EvictsForeign));
    // The oldest entry is this device's: it may go.
    let own = WriteRecord { written: vec![mark("h4")], confirmed: true };
    assert_eq!(history_of(&k, &sent_body(guarded(&k, &c, b"new", None, &own))), ["old", "h0", "h1", "h2", "h3"]);
    // "Write to the login", given to this question, evicts a foreign one.
    let answered = guarded(&k, &c, b"new", Some((EvictsForeign, WriteToLogin)), &foreign);
    assert_eq!(history_of(&k, &sent_body(answered)), ["old", "h0", "h1", "h2", "h3"]);
    // Over the cap, every entry that goes must be this device's.
    c["passwordHistory"] = k.history(6);
    assert_eq!(guarded(&k, &c, b"new", None, &own).err(), ask(EvictsForeign));
    let both = WriteRecord { written: vec![mark("h4"), mark("h5")], confirmed: true };
    assert!(guarded(&k, &c, b"new", None, &both).is_ok());
    // No password: nothing goes into the history, so nothing leaves it.
    let mut empty = k.login(&[("bwss:id", "x", false)], None, None);
    empty["passwordHistory"] = k.history(5);
    assert_eq!(history_of(&k, &sent_body(guarded(&k, &empty, b"new", None, &own))).len(), 5);
}

#[test]
fn an_answer_covers_only_its_own_question() {
    let k = fx();
    let mut c = k.login(&[("bwss:id", "x", false)], Some("old"), None);
    let none = WriteRecord::default();
    let first = Some((FirstWriteBack, WriteToLogin));
    assert!(guarded(&k, &c, b"new", first, &none).is_ok());
    // The history filled while the answer waited: it is stale, and the stronger question is asked.
    c["passwordHistory"] = k.history(5);
    assert_eq!(guarded(&k, &c, b"new", first, &none).err(), ask(EvictsForeign));
    // Unconfirmed with a foreign entry to evict: one question, the eviction, and its answer confirms both.
    assert_eq!(guarded(&k, &c, b"new", None, &none).err(), ask(EvictsForeign));
    let out = guarded(&k, &c, b"new", Some((EvictsForeign, WriteToLogin)), &none).unwrap();
    assert_eq!(history_of(&k, &out.body.unwrap()), ["old", "h0", "h1", "h2", "h3"]);
    // "Keep separate" holds whatever question it answered.
    let out = guarded(&k, &c, b"new", Some((FirstWriteBack, KeepSeparate)), &none).unwrap();
    assert_eq!(field(&out.body.unwrap(), &k.keys.user, "bwss:password"), Some(("new".into(), 1)));
}

#[test]
fn identical_or_too_long_values_ask_nothing() {
    let k = fx();
    let mut c = k.login(&[("bwss:id", "x", false)], Some("old"), None);
    c["passwordHistory"] = k.history(5);
    let none = WriteRecord::default();
    let out = guarded(&k, &c, b"old", None, &none).unwrap();
    assert!(out.body.is_none() && out.wrote_login.is_none());
    assert_eq!(guarded(&k, &c, &[b'x'; 8_000], None, &none).err(), Some(WriteError::TooLong));
    // Only the login password asks: a tool field never does.
    let field_item = k.note(&[("bwss:id", "x", false), ("bwss:password", "s", true)], None);
    assert_eq!(guarded(&k, &field_item, b"t", None, &none).unwrap().wrote_login, None);
}

#[test]
fn keep_separate_ends_the_questions() {
    let k = fx();
    let mut c = k.login(&[("bwss:id", "x", false)], Some("old"), Some("my notes"));
    c["passwordHistory"] = k.history(5);
    let none = WriteRecord::default();
    let out = guarded(&k, &c, b"new", Some((EvictsForeign, KeepSeparate)), &none).unwrap();
    assert_eq!(out.wrote_login, None);
    let body = out.body.unwrap();
    assert_eq!(field(&body, &k.keys.user, "bwss:password"), Some(("new".into(), 1)));
    assert_rest_unchanged(&c, &body, &["fields"]);
    // From then on the field is the value source: a second write asks nothing and leaves the login alone.
    let after = as_server(&body);
    assert_eq!(k.marked(&after, B).source, ValueSource::Field);
    let again = sent_body(guarded(&k, &after, b"next", None, &none));
    assert_eq!(field(&again, &k.keys.user, "bwss:password"), Some(("next".into(), 1)));
    assert_eq!(again["login"], c["login"]);
}

fn blob_with_history(k: &Bx, password: Option<&str>, history: Option<Cbor>) -> Value {
    let mut content = blob_login(&[("bwss:id", "a")], password, None);
    let Cbor::Map(entries) = &mut content else { unreachable!() };
    if let Some(history) = history {
        entries.push((t("passwordHistory"), history));
    }
    k.cipher(content)
}

#[test]
fn blob_history_is_protected_too() {
    let k = Bx::new();
    let full = || Cbor::Array((0..5).map(|i| history_entry(&format!("h{i}"), "2025-01-01T00:00:00Z")).collect());
    let mark = |t: &str| k.keys.marker.mark("a", t);
    let write = |c: &Value, record: &WriteRecord| {
        let p = Patch { answer: None, ..bx_patch(&k, c, Some(b"next")) };
        write::apply(c, &p, B, &k.keys, record, &k.rng, NOW)
    };
    let c = blob_with_history(&k, Some("cur"), Some(full()));
    assert_eq!(write(&c, &WriteRecord::default()).err(), ask(EvictsForeign));
    assert_eq!(write(&blob_with_history(&k, Some("cur"), None), &WriteRecord::default()).err(), ask(FirstWriteBack));
    let foreign = WriteRecord { written: vec![], confirmed: true };
    assert_eq!(write(&c, &foreign).err(), ask(EvictsForeign));
    let own = WriteRecord { written: vec![mark("h4")], confirmed: true };
    let out = write(&c, &own).unwrap();
    assert_eq!(out.wrote_login, Some(mark("next")));
    let blob = sent(&k, &out.body.unwrap());
    let Some(Cbor::Array(history)) = blob.get("passwordHistory") else { panic!("no history") };
    assert_eq!(history[4], history_entry("h3", "2025-01-01T00:00:00Z"));
    // An entry without a text password is the empty password: not this device's.
    let odd = Cbor::Array(vec![t("x"), t("x"), t("x"), t("x"), Cbor::Map(vec![])]);
    let c = blob_with_history(&k, Some("cur"), Some(odd));
    assert_eq!(write(&c, &own).err(), ask(EvictsForeign));
    assert!(write(&c, &WriteRecord { written: vec![mark("")], confirmed: true }).is_ok());
    // No password or no history: nothing leaves.
    assert!(write(&blob_with_history(&k, None, Some(full())), &foreign).is_ok());
    assert!(write(&blob_with_history(&k, Some("cur"), Some(Cbor::Null)), &foreign).is_ok());
}

#[test]
fn acl_merges_as_a_union() {
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false), ("bwss:acl", "a\nb", true)], Some("pw"), None);
    let mut p = Patch { append_lines: vec![la("bwss:acl", &["c", "a"])], ..k.keep(&c, B) };
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(field(&body, &k.keys.user, "bwss:acl"), Some(("a\nb\nc".into(), 1)));

    // nothing new: the field is left as it was
    p.append_lines = vec![la("bwss:acl", &["b"])];
    assert_eq!(k.apply(&c, &p, B).unwrap()["fields"], c["fields"]);

    // an ACL field holding null counts as empty and keeps its kind
    let mut null_acl = k.login(&[("bwss:id", "x", false), ("bwss:acl", "", true)], Some("pw"), None);
    null_acl["fields"][1]["value"] = Value::Null;
    p.append_lines = vec![la("bwss:acl", &["/bin/y"])];
    let body = k.apply(&null_acl, &p, B).unwrap();
    assert_eq!(field(&body, &k.keys.user, "bwss:acl"), Some(("/bin/y".into(), 1)));
    assert_eq!(body["fields"].as_array().unwrap().len(), 2);

    // no ACL yet: a hidden field is added
    let c = k.login(&[("bwss:id", "x", false)], Some("pw"), None);
    p.append_lines = vec![la("bwss:acl", &["/bin/x"])];
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(field(&body, &k.keys.user, "bwss:acl"), Some(("/bin/x".into(), 1)));
}

#[test]
fn append_lines_union_keeps_order() {
    let k = fx();
    // Existing order stays, blank lines (either side) are dropped, only the first copy of the field is read, and
    // a repeated new line is added once.
    let c = k.login(
        &[("bwss:id", "x", false), ("bwss:acl", "b\n\n  \na", true), ("bwss:acl", "other", true)],
        Some("pw"),
        None,
    );
    // (and an identical value does not make the union "nothing to send")
    let p = Patch { append_lines: vec![la("bwss:acl", &["z", "", "a", "y", "z", " "])], ..k.set_secret(&c, B, b"pw") };
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(field(&body, &k.keys.user, "bwss:acl"), Some(("b\na\nz\ny".into(), 1)));
    assert_eq!(names(&body, &k.keys.user), ["bwss:id", "bwss:acl", "bwss:acl"]);
    // Absent, and nothing but blank lines: the (empty) field is still created.
    let c2 = k.login(&[("bwss:id", "x", false)], Some("pw"), None);
    let p = Patch { append_lines: vec![la("bwss:acl", &[" "])], ..k.keep(&c2, B) };
    let body = k.apply(&c2, &p, B).unwrap();
    assert_eq!(field(&body, &k.keys.user, "bwss:acl"), Some((String::new(), 1)));
    // It runs after `remove` and `set`: a removed field is created anew, a set one is added to.
    let p = Patch { remove: vec!["bwss:acl".into()], append_lines: vec![la("bwss:acl", &["n"])], ..k.keep(&c, B) };
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(names(&body, &k.keys.user), ["bwss:id", "bwss:acl"]);
    assert_eq!(field(&body, &k.keys.user, "bwss:acl"), Some(("n".into(), 1)));
    let p = Patch { set: vec![fs("bwss:acl", "s", true)], append_lines: vec![la("bwss:acl", &["n"])], ..k.keep(&c, B) };
    let body = k.apply(&c, &p, B).unwrap();
    assert_eq!(field(&body, &k.keys.user, "bwss:acl"), Some(("s\nn".into(), 1)));
}

#[test]
fn append_lines_too_long_is_refused() {
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false), ("bwss:acl", "a", true)], Some("pw"), None);
    // Each line fits, the union does not.
    let line = "x".repeat(2_000);
    let p = Patch { append_lines: vec![la("bwss:acl", &[&line, &line.replace('x', "y")])], ..k.keep(&c, B) };
    assert_eq!(k.apply(&c, &p, B), Err(WriteError::TooLong));
}

#[test]
fn append_lines_on_a_blob() {
    let k = Bx::new();
    let c = k.cipher(blob_login(&[("bwss:id", "a"), ("bwss:acl", "p\nq")], Some("pw"), None));
    let p = Patch { append_lines: vec![la("bwss:acl", &["q", "r"])], ..bx_patch(&k, &c, None) };
    let blob = sent(&k, &apply(&c, &p, B, &k.keys, &k.rng, NOW).unwrap());
    let Some(Cbor::Array(fields)) = blob.get("fields") else { panic!("no fields") };
    // Changed in place, its kind kept.
    let (value, kind) = (super::blob::get(&fields[1], "value"), super::blob::get(&fields[1], "type"));
    assert_eq!((value, kind), (Some(&t("p\nq\nr")), Some(&Cbor::Uint(0))));
    // Absent: created hidden. Over the limit, on the plaintext length.
    let c = k.cipher(blob_login(&[("bwss:id", "a")], Some("pw"), None));
    let p = Patch { append_lines: vec![la("bwss:acl", &["r"])], ..bx_patch(&k, &c, None) };
    let blob = sent(&k, &apply(&c, &p, B, &k.keys, &k.rng, NOW).unwrap());
    assert_eq!(names_of(&blob), [Some("bwss:id"), Some("bwss:acl")]);
    let p = Patch { append_lines: vec![la("bwss:acl", &[&"x".repeat(5_001)])], ..bx_patch(&k, &c, None) };
    assert_eq!(apply(&c, &p, B, &k.keys, &k.rng, NOW), Err(WriteError::TooLong));
}
