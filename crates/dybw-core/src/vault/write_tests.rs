//! Ported from bwss `src/bw/write.rs` (except the ACL union and the registry note, M4) and the plugin's
//! `newSecretRequest` / `updateValueRequest` cases (`test/sync.test.ts`).

use super::scan::{MarkedItem, Scan, Uninspectable, ValueSource};
use super::write::*;
use super::*;
use crate::crypto::{CoseAlgorithm, CryptoError, MarkScheme, Marker, SymmetricKey};
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
    Fx { rng, keys: Keys { user, orgs: BTreeMap::from([("org1".to_owned(), org)]), marker } }
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
            value: ValueChange::Keep,
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

    // an identical value is never written (§6.1): no history entry, no new date
    let body = k.apply(&c, &k.set_secret(&c, B, b"old"), B).unwrap();
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
    // an empty value over no password is no change
    let body = k.apply(&c, &k.set_secret(&c, B, b""), B).unwrap();
    assert_eq!(body["login"], c["login"]);
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
    let body = k.apply(&c, &p, B).unwrap();
    for key in RESPONSE_ONLY {
        assert!(!body.contains_key(key), "{key} was sent");
    }
    assert_eq!(body["passwordHistory"], json!([]));
    assert_eq!(body["lastKnownRevisionDate"], json!("2026-01-02T03:04:05Z"));
    assert_eq!(body["key"], c["key"]);
    assert_eq!(field(&body, &item_key, "bwss:password"), Some(("new".into(), 1)));
    assert_eq!(field(&body, &item_key, "bwss:attr:a"), Some(("1".into(), 0)));
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
fn blob_cipher_is_never_written() {
    // A blob cipher scans as held; the update body would drop `data` (response-only) and wipe the blob.
    let k = fx();
    let c = k.login(&[("bwss:id", "x", false), ("bwss:password", "old", true)], Some("pw"), None);
    let p = k.set_secret(&c, B, b"new");
    let blob = with_key(&c, "data", json!("{\"format_version\":1,\"x\":2}"));
    let held = Err(WriteError::Uninspectable(Uninspectable::NewerFormat));
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
