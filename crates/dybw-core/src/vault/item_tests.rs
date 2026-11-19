//! `vault::item` beyond the vectors (`vectors/src/open/`): blob shapes the generator does not write, malformed
//! parts, redaction and wiping.

use super::blob_tests::{Bx, t};
use super::item::{Data, Text, field_names, open, summary, summary_with_uris};
use super::scan::Uninspectable;
use crate::crypto::{Cbor, SymmetricKey};
use crate::testing::{SeededRandom, cbor_texts_alive};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn map(entries: Vec<(&str, Cbor)>) -> Cbor {
    Cbor::Map(entries.into_iter().map(|(k, v)| (t(k), v)).collect())
}

fn blob(bx: &Bx, kind: u64, content: Cbor) -> Value {
    let mut cipher = bx.cipher(content);
    cipher["type"] = json!(kind);
    cipher
}

fn text(t: &Text) -> Option<&str> {
    t.as_deref().map(String::as_str)
}

#[test]
fn a_blob_of_a_type_unknown_here_reads_its_name_notes_and_fields() {
    let bx = Bx::new();
    // The SDK's bank account (sdk-m3.json `v1.bank_account`), with a history entry that is no map.
    let field = map(vec![("name", t("iban")), ("value", t("US12")), ("type", Cbor::Uint(1)), ("linkedId", Cbor::Null)]);
    let content = map(vec![
        ("name", t("Test Bank Account")),
        ("notes", t("Bank account notes")),
        ("typeData", map(vec![("type", t("bankAccount")), ("accountNumber", t("1234567890"))])),
        ("fields", Cbor::Array(vec![field, map(vec![("type", t("not a number"))])])),
        ("passwordHistory", Cbor::Array(vec![t("not a map")])),
    ]);
    let item = open(&blob(&bx, 8, content), &bx.keys.user, &bx.keys.orgs).unwrap();
    assert_eq!((item.id.as_str(), item.kind, item.name.as_str()), ("b1", 8, "Test Bank Account"));
    assert!(matches!(item.data, Data::Unknown));
    assert_eq!(text(&item.notes), Some("Bank account notes"));
    assert_eq!(item.fields.len(), 2);
    assert_eq!((text(&item.fields[0].name), text(&item.fields[0].value)), (Some("iban"), Some("US12")));
    assert_eq!((item.fields[0].kind, item.fields[0].linked_id), (1, None));
    assert_eq!((text(&item.fields[1].name), item.fields[1].kind), (None, 0));
    assert_eq!((text(&item.history[0].password), item.history[0].last_used.as_deref()), (None, None));
    drop(item);
    assert_eq!(cbor_texts_alive(), 0, "every decoded text of the blob is wiped");
}

#[test]
fn a_blob_whose_type_data_is_not_its_type_is_held() {
    let bx = Bx::new();
    for (kind, type_data) in [
        (3, map(vec![("type", t("secureNote"))])),
        (5, map(vec![("type", t("card")), ("privateKey", t("k"))])),
        (4, Cbor::Null),
    ] {
        let cipher = blob(&bx, kind, map(vec![("name", t("x")), ("typeData", type_data)]));
        assert_eq!(open(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap_err(), Uninspectable::Blob, "{kind}");
        assert_eq!(summary(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap_err(), Uninspectable::Blob, "{kind}");
    }
    assert_eq!(cbor_texts_alive(), 0);
}

#[test]
fn a_blob_login_reads_its_uris_with_their_match_types() {
    let bx = Bx::new();
    let uris = Cbor::Array(vec![
        map(vec![("uri", t("https://a.invalid")), ("match", Cbor::Uint(3))]),
        map(vec![("uri", Cbor::Null), ("match", t("not a number"))]),
    ]);
    let login = map(vec![("type", t("login")), ("username", t("me")), ("uris", uris)]);
    let cipher = blob(&bx, 1, map(vec![("name", t("L")), ("typeData", login)]));
    let item = open(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap();
    let Data::Login(l) = &item.data else { panic!("not a login") };
    assert_eq!((text(&l.username), text(&l.password)), (Some("me"), None));
    assert_eq!((text(&l.uris[0].uri), l.uris[0].match_type), (Some("https://a.invalid"), Some(3)));
    assert_eq!((text(&l.uris[1].uri), l.uris[1].match_type), (None, None));
    let s = summary(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap();
    assert_eq!((s.name.as_str(), text(&s.user), s.kind), ("L", Some("me"), 1));
}

#[test]
fn malformed_field_level_parts_read_as_absent() {
    let bx = Bx::new();
    let rng = SeededRandom::new(5);
    let enc = |s: &str| bx.keys.user.encrypt(s.as_bytes(), &rng).unwrap();
    let cipher = json!({
        "id": "c1", "type": 1, "name": enc("n"), "reprompt": 2, "folderId": 7,
        "login": { "username": 5, "uris": [ "not an object", { "uri": enc("u"), "match": -1 } ] },
        "fields": { "not": "a list" },
        "passwordHistory": [ { "password": enc("old"), "lastUsedDate": 3 } ],
    });
    let item = open(&cipher, &bx.keys.user, &BTreeMap::new()).unwrap();
    assert!(item.reprompt, "any reprompt other than 0 asks again");
    assert_eq!(item.folder_id, None);
    let Data::Login(l) = &item.data else { panic!("not a login") };
    assert_eq!(text(&l.username), None);
    assert_eq!((text(&l.uris[0].uri), text(&l.uris[1].uri), l.uris[1].match_type), (None, Some("u"), None));
    assert!(item.fields.is_empty());
    assert_eq!((text(&item.history[0].password), item.history[0].last_used.as_deref()), (Some("old"), None));
    // No type, no id, a reprompt that is no number: an unknown type with an empty id, no reprompt.
    let bare = json!({ "name": enc("n"), "reprompt": "1" });
    let item = open(&bare, &bx.keys.user, &BTreeMap::new()).unwrap();
    assert_eq!((item.id.as_str(), item.kind, item.reprompt), ("", 0, false));
    assert!(matches!(item.data, Data::Unknown));
    let s = summary(&json!({ "type": 4, "name": null }), &bx.keys.user, &BTreeMap::new()).unwrap();
    assert_eq!((s.name.as_str(), text(&s.user)), ("", None));
}

#[test]
fn an_organization_item_needs_its_key_and_a_large_cipher_is_never_opened() {
    let bx = Bx::new();
    let rng = SeededRandom::new(6);
    let org = &bx.keys.orgs["org1"];
    let cipher = json!({ "id": "o", "type": 2, "organizationId": "org1", "name": org.encrypt(b"n", &rng).unwrap() });
    assert_eq!(open(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap().organization_id.as_deref(), Some("org1"));
    assert_eq!(open(&cipher, &bx.keys.user, &BTreeMap::new()).unwrap_err(), Uninspectable::OrganizationKeyMissing);
    let odd = json!({ "type": 2, "organizationId": 1, "name": null });
    assert_eq!(summary(&odd, &bx.keys.user, &bx.keys.orgs).unwrap_err(), Uninspectable::OrganizationKeyMissing);
    let large = json!({ "type": 2, "notes": "x".repeat(1024 * 1024) });
    assert_eq!(open(&large, &bx.keys.user, &bx.keys.orgs).unwrap_err(), Uninspectable::TooLarge);
}

#[test]
fn every_reason_not_to_open_holds_for_both_forms() {
    let bx = Bx::new();
    let rng = SeededRandom::new(9);
    let note = map(vec![("name", t("n")), ("typeData", map(vec![("type", t("secureNote"))]))]);
    let mut org_blob = bx.sealed_with(&bx.keys.orgs["org1"], &super::blob_tests::versioned(note.clone()), json!(1));
    org_blob["organizationId"] = json!("org1");
    let mut broken_blob = blob(&bx, 2, note);
    broken_blob["key"] = json!("2.AAAA|AAAA|AAAA");
    let other = SymmetricKey::generate(&rng).unwrap();
    let cases = [
        (json!({ "type": 2, "notes": "x".repeat(1024 * 1024) }), Uninspectable::TooLarge),
        (org_blob, Uninspectable::NewerFormat),
        (broken_blob, Uninspectable::Blob),
        (json!({ "type": 2, "organizationId": "org2" }), Uninspectable::OrganizationKeyMissing),
        (json!({ "type": 2, "key": other.encrypt(&other.to_bytes(), &rng).unwrap() }), Uninspectable::ItemKey),
        (json!({ "type": 1, "name": other.encrypt(b"n", &rng).unwrap() }), Uninspectable::Value),
    ];
    for (cipher, why) in cases {
        assert_eq!(open(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap_err(), why);
        assert_eq!(summary(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap_err(), why);
    }
}

#[test]
fn debug_shows_no_decrypted_text() {
    let bx = Bx::new();
    let user = SymmetricKey::generate(&SeededRandom::new(7)).unwrap();
    let rng = SeededRandom::new(8);
    let cipher = json!({
        "id": "c1", "type": 1, "name": user.encrypt(b"secret-name", &rng).unwrap(),
        "login": { "username": user.encrypt(b"secret-user", &rng).unwrap() },
    });
    let item = format!("{:?}", open(&cipher, &user, &bx.keys.orgs).unwrap());
    let summary = format!("{:?}", summary(&cipher, &user, &bx.keys.orgs).unwrap());
    for shown in [&item, &summary] {
        assert!(shown.contains("c1") && !shown.contains("secret"), "{shown}");
    }
}

#[test]
fn a_login_uri_that_does_not_decrypt_makes_the_item_unreadable() {
    let bx = Bx::new();
    let rng = SeededRandom::new(11);
    let other = SymmetricKey::generate(&rng).unwrap();
    let cipher = json!({
        "type": 1,
        "name": bx.keys.user.encrypt(b"n", &rng).unwrap(),
        "login": { "uris": [{ "uri": other.encrypt(b"https://example.com", &rng).unwrap(), "match": null }] },
    });
    assert_eq!(open(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap_err(), Uninspectable::Value);
}

const BAD: &str = "not an enc string";

#[test]
fn the_narrow_decrypts_never_touch_a_password_notes_totp_or_value() {
    let bx = Bx::new();
    let rng = SeededRandom::new(12);
    let enc = |s: &str| bx.keys.user.encrypt(s.as_bytes(), &rng).unwrap();
    // Everything the narrow reads skip is garbage: decrypting any of it would fail.
    let cipher = json!({
        "id": "c1", "type": 1, "folderId": "f1", "name": enc("n"), "notes": BAD,
        "login": {
            "username": enc("me"), "password": BAD, "totp": BAD,
            "uris": [{ "uri": enc("https://a.invalid"), "match": 4 }, { "uri": null }],
        },
        "fields": [{ "name": enc("f1"), "value": BAD, "type": 1 }, { "name": null, "value": BAD }],
        "passwordHistory": [{ "password": BAD }],
    });
    assert_eq!(open(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap_err(), Uninspectable::Value);
    let l = summary_with_uris(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap();
    assert_eq!(
        (l.summary.name.as_str(), text(&l.summary.user), l.summary.folder_id.as_deref()),
        ("n", Some("me"), Some("f1"))
    );
    assert_eq!(
        (text(&l.uris[0].uri), l.uris[0].match_type, text(&l.uris[1].uri)),
        (Some("https://a.invalid"), Some(4), None)
    );
    let names = field_names(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap();
    assert_eq!((text(&names[0].name), names[0].kind, text(&names[1].name), names[1].kind), (Some("f1"), 1, None, 0));
    let shown = format!("{l:?} {:?}", names[0]);
    assert!(shown.contains("c1") && !shown.contains("https") && !shown.contains("f1"), "{shown}");

    // Another type has no URIs; a name that does not decrypt is `Value`, as for `open`.
    let card = json!({ "type": 3, "name": enc("c"), "card": { "number": BAD }, "fields": [{ "name": BAD }] });
    assert!(summary_with_uris(&card, &bx.keys.user, &bx.keys.orgs).unwrap().uris.is_empty());
    assert_eq!(field_names(&card, &bx.keys.user, &bx.keys.orgs).unwrap_err(), Uninspectable::Value);
}

#[test]
fn the_narrow_decrypts_open_a_blob_whole_and_wipe_it() {
    let bx = Bx::new();
    let uris = Cbor::Array(vec![map(vec![("uri", t("https://a.invalid")), ("match", Cbor::Uint(1))])]);
    let login = map(vec![("type", t("login")), ("password", t("pw")), ("uris", uris)]);
    let field = map(vec![("name", t("hidden")), ("value", t("v")), ("type", Cbor::Uint(1))]);
    let content = map(vec![("name", t("L")), ("typeData", login), ("fields", Cbor::Array(vec![field]))]);
    let cipher = blob(&bx, 1, content);
    let l = summary_with_uris(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap();
    assert_eq!((text(&l.uris[0].uri), l.uris[0].match_type), (Some("https://a.invalid"), Some(1)));
    let names = field_names(&cipher, &bx.keys.user, &bx.keys.orgs).unwrap();
    assert_eq!((text(&names[0].name), names[0].kind), (Some("hidden"), 1));
    assert_eq!(cbor_texts_alive(), 0, "the opened blob is wiped before either returns");
    let wrong = blob(&bx, 2, map(vec![("name", t("x")), ("typeData", map(vec![("type", t("card"))]))]));
    assert_eq!(field_names(&wrong, &bx.keys.user, &bx.keys.orgs).unwrap_err(), Uninspectable::Blob);
    assert_eq!(cbor_texts_alive(), 0);
}
