//! `vault::folder` beyond the vectors (`vectors/src/folders/`): malformed folders, redaction.

use super::folder::folder_names;
use super::scan::Uninspectable;
use crate::crypto::SymmetricKey;
use crate::testing::SeededRandom;
use serde_json::json;

#[test]
fn every_folder_is_kept_whatever_its_shape() {
    let rng = SeededRandom::new(11);
    let user = SymmetricKey::generate(&rng).unwrap();
    let other = SymmetricKey::generate(&rng).unwrap();
    let sync = json!({ "folders": [
        { "id": "f1", "name": user.encrypt(b"Work", &rng).unwrap() },
        { "id": "f2", "name": other.encrypt(b"Not mine", &rng).unwrap() },
        { "id": "f3" },
        { "id": "f4", "name": 7 },
        { "name": user.encrypt(b"No id", &rng).unwrap() },
    ] });
    let names = folder_names(&sync, &user);
    assert_eq!(names.get("f1"), Some(Ok("Work")));
    for id in ["f2", "f3", "f4"] {
        assert_eq!(names.get(id), Some(Err(Uninspectable::Value)), "{id}");
    }
    assert_eq!(names.get(""), Some(Ok("No id")));
    assert_eq!(names.get("f5"), None);
    assert_eq!(names.iter().map(|(id, _)| id).collect::<Vec<_>>(), ["", "f1", "f2", "f3", "f4"]);
}

#[test]
fn no_list_is_no_folders() {
    let user = SymmetricKey::generate(&SeededRandom::new(12)).unwrap();
    for sync in [json!({}), json!({ "folders": null }), json!({ "folders": "x" })] {
        assert_eq!(folder_names(&sync, &user).iter().count(), 0, "{sync}");
    }
}

#[test]
fn debug_shows_no_name() {
    let rng = SeededRandom::new(13);
    let user = SymmetricKey::generate(&rng).unwrap();
    let sync = json!({ "folders": [{ "id": "f1", "name": user.encrypt(b"secret-name", &rng).unwrap() }] });
    let shown = format!("{:?}", folder_names(&sync, &user));
    assert!(shown.contains("f1") && !shown.contains("secret"), "{shown}");
}
