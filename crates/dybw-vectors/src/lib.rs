//! Conformance vector runner for dybw-core (`vectors/README.md` is the format).

pub mod canonical;
pub mod keys;
pub mod run;
pub mod scenario;
pub mod server;

use dybw_core::ports::RsaOaep;
use scenario::{Expect, Scenario};
use std::collections::BTreeMap;
#[cfg(feature = "native")]
use std::path::{Path, PathBuf};

pub const NOT_FOUND: &str = "conformance vectors not found: set DYBW_VECTORS_DIR";
const EXPECTED_FAILURES: &str = include_str!("../expected-failures.txt");

/// What a vector run gives: `Err` names the first difference.
pub type Outcome = Result<(), String>;

/// `DYBW_VECTORS_DIR`, else `<repo>/vectors`; either must hold `generated/`.
#[cfg(feature = "native")]
pub fn vectors_dir() -> Result<PathBuf, String> {
    let dir = std::env::var_os("DYBW_VECTORS_DIR")
        .map_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors"), PathBuf::from);
    if dir.join("generated").is_dir() { Ok(dir) } else { Err(NOT_FOUND.into()) }
}

/// The vector files by path relative to `vectors/`, with `/` separators: read from disk natively, handed in as a
/// map where there is no file system (WASM).
pub struct Files(BTreeMap<String, String>);

impl Files {
    /// Every `.json` file under `dir`, recursively.
    #[cfg(feature = "native")]
    pub fn from_dir(dir: &Path) -> std::io::Result<Files> {
        fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, String>) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                let rel = if rel.is_empty() { name.to_owned() } else { format!("{rel}/{name}") };
                if path.is_dir() {
                    walk(&path, &rel, out)?;
                } else if path.extension().is_some_and(|e| e == "json") {
                    out.insert(rel, std::fs::read_to_string(&path)?);
                }
            }
            Ok(())
        }
        let mut out = BTreeMap::new();
        walk(dir, "", &mut out)?;
        Ok(Files(out))
    }

    pub fn from_map(map: BTreeMap<String, String>) -> Files {
        Files(map)
    }

    pub fn get(&self, rel: &str) -> Option<&str> {
        self.0.get(rel).map(String::as_str)
    }

    /// Every generated scenario of namespace `ns`, sorted by id. A file that does not parse is an error: a format
    /// change must fail loudly.
    pub fn scenarios(&self, ns: &str) -> Result<Vec<Scenario>, String> {
        let prefix = format!("generated/{ns}/");
        let mut out = self
            .0
            .iter()
            .filter(|(path, _)| path.starts_with(&prefix) && path.ends_with(".json"))
            .map(|(path, text)| serde_json::from_str::<Scenario>(text).map_err(|e| format!("{path}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }
}

/// The kinds of expectation a scenario carries, each checked by its own runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Read,
    Write,
    Plan,
    Open,
    Folders,
    ClientWrite,
}

impl Kind {
    pub const ALL: [Kind; 6] = [Kind::Read, Kind::Write, Kind::Plan, Kind::Open, Kind::Folders, Kind::ClientWrite];

    pub fn has(self, e: &Expect) -> bool {
        match self {
            Kind::Read => e.read.is_some(),
            Kind::Write => e.write.is_some(),
            Kind::Plan => e.plan.is_some(),
            Kind::Open => e.open.is_some(),
            Kind::Folders => e.folders.is_some(),
            Kind::ClientWrite => e.client_write.is_some(),
        }
    }
}

/// Runs every scenario of `ns` that carries `kind`, in id order; an error names its namespace. Scenarios that do
/// not parse give one failing entry instead of a run.
pub async fn run_all(files: &Files, ns: &str, kind: Kind, rsa: &impl RsaOaep) -> Vec<(String, Outcome)> {
    let scenarios = match files.scenarios(ns) {
        Ok(s) => s,
        Err(e) => return vec![(format!("generated/{ns}"), Err(e))],
    };
    let mut out = Vec::new();
    for s in scenarios.into_iter().filter(|s| kind.has(&s.expect)) {
        let outcome = match kind {
            Kind::Read => run::read(files, &s, rsa).await,
            Kind::Write => run::write(files, &s, rsa).await,
            Kind::Plan => run::plan(files, &s, rsa).await,
            Kind::Open => run::open(files, &s, rsa).await,
            Kind::Folders => run::folders(files, &s, rsa).await,
            Kind::ClientWrite => run::client_write(files, &s, rsa).await,
        };
        out.push((s.id, outcome.map_err(|e| format!("[{ns}] {e}"))));
    }
    out
}

/// `vector id -> reason` from `expected-failures.txt`: `<vector id> <reason>` per line, blanks and `#` ignored.
/// A line without a reason, or a repeated id, panics.
pub fn expected_failures() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in EXPECTED_FAILURES.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (id, reason) = line.split_once(' ').unwrap_or((line, ""));
        assert!(!reason.trim().is_empty(), "expected-failures.txt: {id} has no reason");
        assert!(out.insert(id.to_owned(), reason.trim().to_owned()).is_none(), "expected-failures.txt: {id} twice");
    }
    out
}

/// Passes only when exactly the listed vectors fail: names every unlisted failure and every listed vector that
/// passed, so the list stays honest.
pub fn check(results: Vec<(String, Outcome)>, expected: &BTreeMap<String, String>) -> Result<(), String> {
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
