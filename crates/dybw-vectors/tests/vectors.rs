#![cfg(feature = "native")]
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use dybw_core::crypto::AwsLcRsa;
use dybw_core::testing::block_on;
use dybw_vectors::{Files, Kind, check, expected_failures, run_all, vectors_dir};
use std::collections::BTreeMap;

fn files() -> Files {
    Files::from_dir(&vectors_dir().unwrap()).unwrap()
}

#[test]
fn vectors_found() {
    let files = files();
    for ns in ["bwss", "obsidian"] {
        let all = files.scenarios(ns).unwrap();
        assert!(!all.is_empty(), "{ns}: no vectors");
        let ids: Vec<&str> = all.iter().map(|s| s.id.as_str()).collect();
        // Unique ids, each the path of an existing file: one scenario per file, named by its path.
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "{ns}: not sorted by id");
        for s in &all {
            let path = format!("generated/{ns}/{}.json", s.id);
            assert!(files.get(&path).is_some(), "{} is not at {path}", s.id);
            assert_eq!(s.namespace, ns, "{path}");
            assert!(["1.5", "1.6"].contains(&s.spec.as_str()), "{path}");
        }
    }
}

#[test]
fn files_from_a_map_and_a_broken_scenario() {
    let map = |text: &str| {
        Files::from_map(BTreeMap::from([
            ("generated/bwss/a.json".to_owned(), text.to_owned()),
            ("accounts/x.json".to_owned(), "{}".to_owned()),
        ]))
    };
    let files = map("{");
    assert_eq!(files.get("accounts/x.json"), Some("{}"));
    assert!(files.scenarios("obsidian").unwrap().is_empty());
    assert!(files.scenarios("bwss").unwrap_err().starts_with("generated/bwss/a.json: "));
    let results = block_on(run_all(&files, "bwss", Kind::Read, &AwsLcRsa));
    assert!(matches!(results.as_slice(), [(id, Err(_))] if id == "generated/bwss"));
}

#[test]
fn expected_failures_list_existing_vectors() {
    let files = files();
    let listed = expected_failures();
    let known: Vec<String> =
        ["bwss", "obsidian"].iter().flat_map(|ns| files.scenarios(ns).unwrap()).map(|s| s.id).collect();
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
    let files = files();
    for ns in ["bwss", "obsidian"] {
        for s in files.scenarios(ns).unwrap() {
            assert!(files.get(&format!("accounts/{}.json", s.account)).is_some(), "{}", s.id);
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

/// Runs every vector of `kind`; returns the count per namespace.
fn run_kind(kind: Kind) -> BTreeMap<&'static str, usize> {
    let files = files();
    let mut counts = BTreeMap::new();
    let mut results = Vec::new();
    for ns in ["bwss", "obsidian"] {
        let ran = block_on(run_all(&files, ns, kind, &AwsLcRsa));
        counts.insert(ns, ran.len());
        results.extend(ran);
    }
    check(results, &expected_failures()).unwrap();
    counts
}

#[test]
fn read_vectors() {
    let counts = run_kind(Kind::Read);
    assert!(counts.values().sum::<usize>() > 50, "too few read vectors: {counts:?}");
}

#[test]
fn write_vectors() {
    let counts = run_kind(Kind::Write);
    assert!(counts.values().all(|&n| n >= 15), "too few write vectors: {counts:?}");
}

#[test]
fn sync_vectors() {
    // The sync vectors are the plugin's: bwss keeps no local copies to plan against.
    let counts = run_kind(Kind::Plan);
    assert!(counts.get("obsidian").is_some_and(|&n| n >= 28), "too few sync vectors: {counts:?}");
}

#[test]
fn open_vectors() {
    let counts = run_kind(Kind::Open);
    assert!(counts.values().all(|&n| n >= 8), "too few open vectors: {counts:?}");
}

#[test]
fn folder_vectors() {
    let counts = run_kind(Kind::Folders);
    assert!(counts.values().all(|&n| n >= 2), "too few folder vectors: {counts:?}");
}

#[test]
fn client_write_vectors() {
    let counts = run_kind(Kind::ClientWrite);
    assert!(counts.values().all(|&n| n >= 15), "too few vault-client write vectors: {counts:?}");
}

#[test]
fn every_vector_runs() {
    let files = files();
    assert_eq!(
        Kind::ALL,
        [Kind::Read, Kind::Write, Kind::Plan, Kind::Open, Kind::Folders, Kind::ClientWrite],
        "a kind of expectation without a vector test"
    );
    for ns in ["bwss", "obsidian"] {
        for s in files.scenarios(ns).unwrap() {
            assert!(Kind::ALL.iter().any(|k| k.has(&s.expect)), "{} is run by no vector test", s.id);
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

#[test]
fn write_expect_accepts_a_question() {
    use dybw_vectors::scenario::WriteExpect;
    let parse = |v: serde_json::Value| serde_json::from_value::<WriteExpect>(v);
    let q = parse(serde_json::json!({ "question": "first-write-back" })).unwrap();
    assert!(matches!(q, WriteExpect::Question(ref q) if q.question == "first-write-back"));
    assert!(parse(serde_json::json!({ "question": "x", "extra": 1 })).is_err());
}

#[test]
fn device_record_deserializes() {
    use dybw_vectors::scenario::{Answer, BaseEntry, Operation, Options};
    let base: BaseEntry = serde_json::from_value(serde_json::json!({
        "cipher": "c", "revisionDate": null, "value": "v", "written": ["a", "b"], "writeBackConfirmed": true
    }))
    .unwrap();
    assert_eq!((base.written.len(), base.write_back_confirmed), (2, true));
    let plain: BaseEntry =
        serde_json::from_value(serde_json::json!({ "cipher": "c", "revisionDate": null, "value": "v" })).unwrap();
    assert!(plain.written.is_empty() && !plain.write_back_confirmed);
    let op: Operation = serde_json::from_value(serde_json::json!({ "kind": "delete", "id": "a" })).unwrap();
    assert!(matches!(op, Operation::Delete { answer: Answer::WriteToLogin, .. }));
    let op: Operation = serde_json::from_value(
        serde_json::json!({ "kind": "create", "id": "a", "value": "v", "folderId": null, "answer": "keep-separate" }),
    )
    .unwrap();
    assert!(matches!(op, Operation::Create { answer: Answer::KeepSeparate, .. }));
    let op: Operation = serde_json::from_value(
        serde_json::json!({ "kind": "set-value", "id": "a", "value": "v", "answer": "unanswered" }),
    )
    .unwrap();
    assert!(matches!(op, Operation::SetValue { answer: Answer::Unanswered, .. }));
    let o: Options = serde_json::from_value(serde_json::json!({ "acceptRollback": true })).unwrap();
    assert!(o.accept_rollback && !Options::default().accept_rollback);
}

/// Polls `f` to completion with a no-op waker and no cap on `Pending`, unlike `testing::block_on`.
fn poll_until_ready<F: std::future::Future>(f: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// `AwsLcRsa` behind a port that answers late, as WebCrypto's promise does: `Pending` 20 001 times per call.
struct LateRsa(std::cell::Cell<u32>);

impl dybw_core::ports::RsaOaep for LateRsa {
    async fn decrypt(
        &self,
        pkcs8: &[u8],
        hash: dybw_core::ports::OaepHash,
        ciphertext: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, dybw_core::ports::PortError> {
        self.0.set(self.0.get() + 1);
        let mut left = 20_001_u32;
        std::future::poll_fn(|cx| {
            if left == 0 {
                return std::task::Poll::Ready(());
            }
            left -= 1;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        })
        .await;
        AwsLcRsa.decrypt(pkcs8, hash, ciphertext).await
    }
}

#[test]
fn the_runner_awaits_a_late_rsa_port() {
    let files = files();
    for kind in [Kind::Read, Kind::Plan] {
        let orgs = files
            .scenarios("obsidian")
            .unwrap()
            .iter()
            .filter(|s| kind.has(&s.expect))
            .filter(|s| s.options.organizations)
            .count();
        assert!(orgs > 0, "no organization {kind:?} vector");
        let late = LateRsa(std::cell::Cell::new(0));
        let got = poll_until_ready(run_all(&files, "obsidian", kind, &late));
        let want = poll_until_ready(run_all(&files, "obsidian", kind, &AwsLcRsa));
        assert!(late.0.get() > 0, "{kind:?}: the late port was never asked");
        assert_eq!(got, want);
        check(got, &expected_failures()).unwrap();
    }
}
