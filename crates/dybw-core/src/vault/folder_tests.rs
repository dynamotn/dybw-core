//! `vault::folder` beyond the vectors (`vectors/src/folders/`): malformed folders, redaction.

use super::folder::folder_names;
use super::scan::Uninspectable;
use crate::crypto::{CoseAlgorithm, SymmetricKey};
use crate::testing::SeededRandom;
use serde_json::json;

#[test]
fn every_folder_is_kept_whatever_its_shape() {
    let rng = SeededRandom::new(11);
    let user = SymmetricKey::generate(&rng).unwrap();
    let other = SymmetricKey::generate(&rng).unwrap();
    let sync = json!({ "folders": [
        { "id": "f1", "name": user.encrypt_str("Work", &rng).unwrap() },
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

#[test]
fn a_cose_name_that_is_tampered_or_under_another_key_is_unreadable() {
    let rng = SeededRandom::new(14);
    for alg in [CoseAlgorithm::Xaes256Gcm, CoseAlgorithm::XChaCha20Poly1305] {
        let user = SymmetricKey::generate_cose(alg, &rng).unwrap();
        let other = SymmetricKey::generate_cose(alg, &rng).unwrap();
        let good = user.encrypt_str("Work", &rng).unwrap();
        // Another base64 character in the middle of the sealed bytes.
        let mut bytes = good.clone().into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        let sync = json!({ "folders": [
            { "id": "ok", "name": good },
            { "id": "bad", "name": tampered },
            { "id": "other", "name": other.encrypt_str("Work", &rng).unwrap() },
        ] });
        let names = folder_names(&sync, &user);
        assert_eq!(names.get("ok"), Some(Ok("Work")), "{alg:?}");
        assert_eq!(names.get("bad"), Some(Err(Uninspectable::Value)), "{alg:?}");
        assert_eq!(names.get("other"), Some(Err(Uninspectable::Value)), "{alg:?}");
    }
}

#[test]
fn a_repeated_id_is_unreadable_not_collapsed() {
    let rng = SeededRandom::new(15);
    let user = SymmetricKey::generate(&rng).unwrap();
    let name = |s: &str| user.encrypt(s.as_bytes(), &rng).unwrap();
    let sync = json!({ "folders": [
        { "id": "d", "name": name("A") }, { "id": "d", "name": name("B") }, { "id": "d", "name": name("C") },
        { "name": name("X") }, { "name": name("Y") },
        { "id": "s", "name": name("Solo") },
    ] });
    let names = folder_names(&sync, &user);
    assert_eq!(names.iter().count(), 3);
    for id in ["d", ""] {
        assert_eq!(names.get(id), Some(Err(Uninspectable::Value)), "{id:?}");
    }
    assert_eq!(names.get("s"), Some(Ok("Solo")));
}
