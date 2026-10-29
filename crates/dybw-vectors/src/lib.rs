//! Conformance vector runner for dybw-core (`vectors/README.md` is the format).

pub mod canonical;
pub mod keys;
pub mod run;
pub mod scenario;
pub mod server;

use scenario::Scenario;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const NOT_FOUND: &str = "conformance vectors not found: set DYBW_VECTORS_DIR";
const EXPECTED_FAILURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/expected-failures.txt");

/// `DYBW_VECTORS_DIR`, else `<repo>/vectors`; either must hold `generated/`.
pub fn vectors_dir() -> Result<PathBuf, String> {
    let dir = std::env::var_os("DYBW_VECTORS_DIR")
        .map_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors"), PathBuf::from);
    if dir.join("generated").is_dir() { Ok(dir) } else { Err(NOT_FOUND.into()) }
}

fn json_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for path in entries.flatten().map(|e| e.path()) {
        if path.is_dir() {
            json_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

/// Every generated scenario of namespace `ns`, sorted by id. Panics on a file that does not parse: a format
/// change must fail loudly.
pub fn load_all(dir: &Path, ns: &str) -> Vec<(PathBuf, Scenario)> {
    let mut files = Vec::new();
    json_files(&dir.join("generated").join(ns), &mut files);
    let mut out: Vec<(PathBuf, Scenario)> = files
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let scenario = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            (path, scenario)
        })
        .collect();
    out.sort_by(|a, b| a.1.id.cmp(&b.1.id));
    out
}

/// `vector id -> reason` from `expected-failures.txt`: `<vector id> <reason>` per line, blanks and `#` ignored.
/// A line without a reason, or a repeated id, panics.
pub fn expected_failures() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(EXPECTED_FAILURES).unwrap_or_else(|e| panic!("{EXPECTED_FAILURES}: {e}"));
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (id, reason) = line.split_once(' ').unwrap_or((line, ""));
        assert!(!reason.trim().is_empty(), "expected-failures.txt: {id} has no reason");
        assert!(out.insert(id.to_owned(), reason.trim().to_owned()).is_none(), "expected-failures.txt: {id} twice");
    }
    out
}

/// Passes only when exactly the listed vectors fail: names every unlisted failure and every listed vector that
/// passed, so the list stays honest.
pub fn check(results: Vec<(String, Result<(), String>)>, expected: &BTreeMap<String, String>) -> Result<(), String> {
    let mut problems = Vec::new();
    for (id, result) in &results {
        match (result, expected.get(id)) {
            (Err(why), None) => problems.push(format!("{id}: {why}")),
            (Ok(()), Some(reason)) => problems.push(format!("{id}: listed as failing ({reason}) but passed")),
            _ => {}
        }
    }
    if problems.is_empty() { Ok(()) } else { Err(problems.join("\n")) }
}
