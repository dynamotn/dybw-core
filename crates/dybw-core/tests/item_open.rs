//! `vault::item` through the public API. Integration tests link the library built without `cfg(test)`, the one
//! other crates use: coverage counts it apart from the unit-test build, so its error paths need a run here too.
#![expect(clippy::unwrap_used, reason = "tests")]

use dybw_core::crypto::SymmetricKey;
use dybw_core::testing::SeededRandom;
use dybw_core::vault::Uninspectable;
use dybw_core::vault::item::{open, summary};
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
