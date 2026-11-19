//! `vault::item` through the public API. Integration tests link the library built without `cfg(test)`, the one
//! other crates use: coverage counts it apart from the unit-test build, so its error paths need a run here too.
#![expect(clippy::unwrap_used, reason = "tests")]

use dybw_core::crypto::SymmetricKey;
use dybw_core::testing::SeededRandom;
use dybw_core::vault::Uninspectable;
use dybw_core::vault::item::{field_names, open, summary, summary_with_uris};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const BAD: &str = "not an enc string";

#[test]
fn the_error_paths_of_every_list_and_the_redacted_debug() {
    let rng = SeededRandom::new(21);
    let user = SymmetricKey::generate(&rng).unwrap();
    let orgs = BTreeMap::new();
    let enc = |s: &str| user.encrypt(s.as_bytes(), &rng).unwrap();
    // A login with a URI, a field and a past password; each argument is one of the three, or its bad twin.
    let login = |uri: &str, field: &str, old: &str| -> Value {
        json!({
            "id": "c1", "type": 1, "name": enc("secret-name"),
            "login": { "username": enc("secret-user"), "uris": [{ "uri": uri, "match": 1 }] },
            "fields": [{ "name": field, "value": enc("v"), "type": 1, "linkedId": 2 }],
            "passwordHistory": [{ "password": old, "lastUsedDate": "2020-01-01" }],
        })
    };
    let (uri, field, old) = (enc("https://example.com"), enc("f"), enc("old"));

    let ok = login(&uri, &field, &old);
    let shown =
        [format!("{:?}", open(&ok, &user, &orgs).unwrap()), format!("{:?}", summary(&ok, &user, &orgs).unwrap())];
    assert!(shown.iter().all(|s| s.contains("c1") && !s.contains("secret")), "{shown:?}");

    for bad in [login(BAD, &field, &old), login(&uri, BAD, &old), login(&uri, &field, BAD)] {
        assert_eq!(open(&bad, &user, &orgs).unwrap_err(), Uninspectable::Value);
    }
}

#[test]
fn the_narrow_decrypts_report_the_same_errors_as_open() {
    let rng = SeededRandom::new(22);
    let user = SymmetricKey::generate(&rng).unwrap();
    let other = SymmetricKey::generate(&rng).unwrap();
    let orgs = BTreeMap::new();
    let enc = |s: &str| user.encrypt(s.as_bytes(), &rng).unwrap();
    let login = |name: &str, uri: &str, field: &str| -> Value {
        json!({
            "id": "c1", "type": 1, "name": name, "login": { "uris": [{ "uri": uri }] },
            "fields": [{ "name": field, "value": BAD, "type": 0 }],
        })
    };
    let ok = login(&enc("secret-name"), &enc("https://example.com"), &enc("f"));
    let l = summary_with_uris(&ok, &user, &orgs).unwrap();
    assert_eq!(
        (l.summary.name.as_str(), l.uris.len(), field_names(&ok, &user, &orgs).unwrap().len()),
        ("secret-name", 1, 1)
    );
    assert!(!format!("{l:?}").contains("secret"));

    let (n, u, f) = (enc("n"), enc("u"), enc("f"));
    for bad in [login(BAD, &u, &f), login(&n, BAD, &f)] {
        assert_eq!(summary_with_uris(&bad, &user, &orgs).unwrap_err(), Uninspectable::Value);
    }
    assert_eq!(field_names(&login(&n, &u, BAD), &user, &orgs).unwrap_err(), Uninspectable::Value);
    let large = json!({ "type": 2, "notes": "x".repeat(1024 * 1024) });
    let foreign = json!({ "type": 2, "organizationId": "org2" });
    let sealed = json!({ "type": 2, "key": other.encrypt(&other.to_bytes(), &rng).unwrap() });
    for (cipher, why) in [
        (large, Uninspectable::TooLarge),
        (foreign, Uninspectable::OrganizationKeyMissing),
        (sealed, Uninspectable::ItemKey),
    ] {
        assert_eq!(summary_with_uris(&cipher, &user, &orgs).unwrap_err(), why);
        assert_eq!(field_names(&cipher, &user, &orgs).unwrap_err(), why);
    }
}
