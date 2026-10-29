#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use dybw_vectors::{check, expected_failures, load_all, vectors_dir};
use std::collections::BTreeMap;

#[test]
fn vectors_found() {
    let dir = vectors_dir().unwrap();
    for ns in ["bwss", "obsidian"] {
        let all = load_all(&dir, ns);
        assert!(!all.is_empty(), "{ns}: no vectors");
        let ids: Vec<&str> = all.iter().map(|(_, s)| s.id.as_str()).collect();
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "{ns}: not sorted by id");
        for (path, s) in &all {
            assert_eq!(s.namespace, ns, "{}", path.display());
            assert_eq!(s.spec, "1.5", "{}", path.display());
            let rel = path.strip_prefix(dir.join("generated").join(ns)).unwrap();
            assert_eq!(rel.with_extension("").to_str().unwrap(), s.id, "{}", path.display());
        }
    }
}

#[test]
fn expected_failures_list_existing_vectors() {
    let dir = vectors_dir().unwrap();
    let listed = expected_failures();
    let known: Vec<String> = ["bwss", "obsidian"].iter().flat_map(|ns| load_all(&dir, ns)).map(|(_, s)| s.id).collect();
    for id in listed.keys() {
        assert!(known.contains(id), "expected-failures.txt lists unknown vector {id}");
    }
}

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
}

#[test]
fn check_flags_listed_passes() {
    let results = vec![("a".to_owned(), Ok(())), ("b".to_owned(), Err("boom".to_owned())), ("c".to_owned(), Ok(()))];
    // b fails unlisted; c is listed but passed.
    let err = check(results, &map(&[("c", "why")])).unwrap_err();
    assert!(err.contains("b: boom"), "{err}");
    assert!(err.contains("c: listed as failing") && err.contains("passed"), "{err}");
    assert!(!err.contains("a:"), "{err}");
    // Exactly the listed vectors fail: fine.
    let results = vec![("a".to_owned(), Ok(())), ("b".to_owned(), Err("boom".to_owned()))];
    check(results, &map(&[("b", "why")])).unwrap();
}

#[test]
fn every_vector_deserializes_with_its_account() {
    let dir = vectors_dir().unwrap();
    for ns in ["bwss", "obsidian"] {
        for (path, s) in load_all(&dir, ns) {
            assert!(dir.join("accounts").join(format!("{}.json", s.account)).is_file(), "{}", path.display());
        }
    }
}

#[test]
fn write_expect_refuses_unknown_keys() {
    use dybw_vectors::scenario::WriteExpect;
    let parse = |v: serde_json::Value| serde_json::from_value::<WriteExpect>(v);
    assert!(matches!(parse(serde_json::json!({ "requests": [] })).unwrap(), WriteExpect::Requests(_)));
    assert!(matches!(parse(serde_json::json!({ "error": "too-long" })).unwrap(), WriteExpect::Error(_)));
    assert!(parse(serde_json::json!({ "requests": [], "extra": 1 })).is_err());
    assert!(parse(serde_json::json!({ "error": "too-long", "extra": 1 })).is_err());
}
