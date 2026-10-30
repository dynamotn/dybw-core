#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use dybw_vectors::scenario::{Expect, Scenario};
use dybw_vectors::{check, expected_failures, load_all, vectors_dir};
use std::collections::BTreeMap;
use std::path::Path;

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

type Runner = fn(&Path, &Scenario) -> Result<(), String>;
type Has = fn(&Expect) -> bool;

/// Each expectation kind, how to tell a scenario has it, and its runner: the one table the vector tests and
/// `every_vector_runs` share, so no kind is left out.
const KINDS: [(&str, Has, Runner); 3] = [
    ("read", |e| e.read.is_some(), dybw_vectors::run::read),
    ("write", |e| e.write.is_some(), dybw_vectors::run::write),
    ("plan", |e| e.plan.is_some(), dybw_vectors::run::plan),
];

/// Runs every vector of `kind`; returns the count per namespace.
fn run_kind(kind: &str) -> BTreeMap<&'static str, usize> {
    let (_, has, runner) = KINDS.iter().find(|(k, _, _)| *k == kind).unwrap();
    let dir = vectors_dir().unwrap();
    let mut counts = BTreeMap::new();
    let mut results = Vec::new();
    for ns in ["bwss", "obsidian"] {
        for (_, s) in load_all(&dir, ns).into_iter().filter(|(_, s)| has(&s.expect)) {
            *counts.entry(ns).or_insert(0) += 1;
            let result = runner(&dir, &s).map_err(|e| format!("[{ns}] {e}"));
            results.push((s.id, result));
        }
    }
    check(results, &expected_failures()).unwrap();
    counts
}

#[test]
fn read_vectors() {
    let counts = run_kind("read");
    assert!(counts.values().sum::<usize>() > 50, "too few read vectors: {counts:?}");
}

#[test]
fn write_vectors() {
    let counts = run_kind("write");
    assert!(counts.values().all(|&n| n >= 15), "too few write vectors: {counts:?}");
}

#[test]
fn sync_vectors() {
    // The sync vectors are the plugin's: bwss keeps no local copies to plan against.
    let counts = run_kind("plan");
    assert!(counts.get("obsidian").is_some_and(|&n| n >= 28), "too few sync vectors: {counts:?}");
}

#[test]
fn every_vector_runs() {
    let dir = vectors_dir().unwrap();
    let names: Vec<&str> = KINDS.iter().map(|(k, _, _)| *k).collect();
    assert_eq!(names, ["read", "write", "plan"], "a kind of expectation without a vector test");
    for ns in ["bwss", "obsidian"] {
        for (path, s) in load_all(&dir, ns) {
            assert!(KINDS.iter().any(|(_, has, _)| has(&s.expect)), "{} is run by no vector test", path.display());
        }
    }
}

#[test]
fn gone_or_unmarked_after_a_refetch_is_giving_up() {
    use dybw_core::vault::write::WriteError;
    use dybw_vectors::run::gave_up;
    for e in [WriteError::Unmarked, WriteError::Gone] {
        assert!(gave_up(true, &e));
        assert!(!gave_up(false, &e));
    }
    assert!(!gave_up(true, &WriteError::SourceChanged));
}
