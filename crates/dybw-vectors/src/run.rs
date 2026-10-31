//! Runs a scenario through the core: `/sync` from the fake server with the real `Client`, then the core's scan.

use crate::canonical::{NOW_MS, canonicalize, drop_tool_defined};
use crate::keys::account_keys;
use crate::scenario::{Answer, Operation, Policy, Scenario, WriteExpect};
use crate::server::{SERVER, VectorServer, urls};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::api::{ApiKey, Client, DeviceInfo, origin_of};
use dybw_core::sync::{self, Action, BaseEntry, DeviceState, LocalValues, SyncContext, SyncWriteError};
use dybw_core::testing::{FixedClock, SeededRandom, block_on};
use dybw_core::vault::write::{HistoryAnswer, NewItem, Patch, ValueChange, WriteError, WriteRecord};
use dybw_core::vault::{
    Keys, Namespace, Organizations, SkipReason, UnmarkedCache, ValueSource, scan_vault, scan_vault_with,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroizing;

pub fn namespace(name: &str) -> Result<&'static Namespace, String> {
    match name {
        "bwss" => Ok(&Namespace::BWSS),
        "obsidian" => Ok(&Namespace::OBSIDIAN),
        other => Err(format!("unknown namespace {other}")),
    }
}

/// A client of the fake server, with a fixed clock.
pub fn client(server: VectorServer) -> Result<Client<VectorServer, FixedClock>, String> {
    let device = DeviceInfo {
        identifier: "vectors-device".into(),
        name: "vectors".into(),
        device_type: 8,
        client_name: "cli".into(),
        client_version: "0".into(),
    };
    Client::new(server, FixedClock { now_ms: 0 }, urls(), device).map_err(|e| e.to_string())
}

fn api_key() -> Result<ApiKey, String> {
    Ok(ApiKey {
        origin: origin_of(&format!("{SERVER}/identity")).map_err(|e| e.to_string())?,
        client_id: "vectors".into(),
        client_secret: Zeroizing::new("vectors".into()),
    })
}

/// The read rule of the README: text when the bytes are UTF-8, else `base64:<canonical b64>`.
fn shown(value: &[u8]) -> String {
    std::str::from_utf8(value).map_or_else(|_| format!("base64:{}", B64.encode(value)), str::to_owned)
}

fn compare<T: PartialEq + std::fmt::Debug>(what: &str, got: T, want: T) -> Result<(), String> {
    if got == want { Ok(()) } else { Err(format!("{what}: expected {want:?}, got {got:?}")) }
}

/// Checks `expect.read`: items (attributes only when the vector lists them), skipped, uninspectable and, when
/// given, duplicates. Lists other than items are compared sorted.
pub fn read(dir: &Path, s: &Scenario) -> Result<(), String> {
    let want = s.expect.read.as_ref().ok_or("no expect.read")?;
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(dir, &s.account, s.options.organizations);
    let server = VectorServer::new(scenario_keys.profile.clone(), s.ciphers.clone(), scenario_keys.prelogin.clone());
    let keys = scenario_keys.into_keys(ns);
    let mut api = client(server)?;
    let sync = block_on(async {
        api.login(&api_key()?).await.map_err(|e| e.to_string())?;
        api.sync().await.map_err(|e| e.to_string())
    })?;
    let allowed = if s.options.organizations { Organizations::All } else { Organizations::None };
    // The device's bindings, when the vector has one (ADR 0019).
    let bound: BTreeMap<String, String> =
        s.device.iter().flat_map(|d| &d.base).map(|(id, e)| (id.clone(), e.cipher.clone())).collect();
    let report = scan_vault_with(&sync, ns, &keys, &allowed, &|_| true, &mut UnmarkedCache::default(), &bound);

    let mut items = report.items.iter().collect::<Vec<_>>();
    items.sort_by(|a, b| a.id.cmp(&b.id));
    compare("item count", items.len(), want.items.len())?;
    for (got, want) in items.iter().zip(&want.items) {
        let what = format!("item {}", want.id);
        compare(&what, (got.cipher_id.as_str(), got.id.as_str()), (want.cipher.as_str(), want.id.as_str()))?;
        compare(&format!("{what} source"), got.source.code(), want.source.as_str())?;
        compare(&format!("{what} value"), shown(&got.value), want.value.clone())?;
        if let Some(attributes) = &want.attributes {
            compare(&format!("{what} attributes"), &got.attributes, attributes)?;
        }
    }
    let mut skipped: Vec<(String, String)> =
        report.skipped.iter().map(|(c, r)| (c.clone(), r.code().to_owned())).collect();
    skipped.sort();
    let mut want_skipped: Vec<(String, String)> =
        want.skipped.iter().map(|s| (s.cipher.clone(), s.reason.clone())).collect();
    want_skipped.sort();
    compare("skipped", skipped, want_skipped)?;
    let mut held: Vec<&str> = report.uninspectable.iter().map(|(c, _)| c.as_str()).collect();
    held.sort_unstable();
    let mut want_held: Vec<&str> = want.uninspectable.iter().map(String::as_str).collect();
    want_held.sort_unstable();
    compare("uninspectable", held, want_held)?;
    let dups: Vec<(&str, &str, &[String], bool)> =
        report.duplicates.iter().map(|d| (d.id.as_str(), d.kept.as_str(), d.left.as_slice(), d.bound_kept)).collect();
    let want_dups: Vec<(&str, &str, &[String], bool)> = want
        .duplicates
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|d| (d.id.as_str(), d.kept.as_str(), d.left.as_slice(), d.bound_kept))
        .collect();
    compare("duplicates", dups, want_dups)
}

/// The operation value rule of the README: `base64:<b64>` is bytes, anything else is that UTF-8 text.
fn op_value(value: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    match value.strip_prefix("base64:") {
        Some(b64) => B64.decode(b64).map(Zeroizing::new).map_err(|e| format!("operation value: {e}")),
        None => Ok(Zeroizing::new(value.as_bytes().to_vec())),
    }
}

/// Checks `expect.write`: runs the operation through the core's writer against the fake server, then compares the
/// decrypted requests it accepted (after `fresh`'s one rejection, which is not listed) or the error code.
///
/// The README's canonical body keeps the password history under `login`; the core writes it at the top level
/// (data model §6.3, as the server stores it), and `canonicalize` maps one onto the other, so the two sides are
/// compared by meaning.
pub fn write(dir: &Path, s: &Scenario) -> Result<(), String> {
    let want = s.expect.write.as_ref().ok_or("no expect.write")?;
    let Some(op) = s.operation.as_ref() else { return sync_write(dir, s, want) };
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(dir, &s.account, s.options.organizations);
    let server = VectorServer::new(scenario_keys.profile.clone(), s.ciphers.clone(), scenario_keys.prelogin.clone());
    let keys = scenario_keys.into_keys(ns);
    let state = device_state(s, &keys);
    let mut api = client(server.clone())?;
    let rng = SeededRandom::new(0x0077_7269_7465);
    let allowed = if s.options.organizations { Organizations::All } else { Organizations::None };

    let outcome = block_on(async {
        api.login(&api_key()?).await.map_err(|e| e.to_string())?;
        let sync = api.sync().await.map_err(|e| e.to_string())?;
        let report = scan_vault(&sync, ns, &keys, &allowed);
        let item = |id: &str| report.items.iter().find(|i| i.id == id).ok_or(format!("no item {id}"));
        *server.fresh.borrow_mut() = op.fresh().cloned();
        Ok::<_, String>(match op {
            Operation::SetValue { id, value, answer, .. } => {
                // An item skipped for `dybw:requires` is not among the items: the write is tried on its cipher, as
                // an app holding a stale copy would (the vector's one `newer-format` cipher).
                let (cipher, found) = match item(id) {
                    Ok(f) => (
                        f.cipher.clone(),
                        (f.cipher_id.clone(), f.organization_id.clone(), f.revision_date.clone(), f.source, f.mark),
                    ),
                    Err(e) => {
                        let (skipped_id, _) =
                            report.skipped.iter().find(|(_, r)| *r == SkipReason::NewerFormat).ok_or(e)?;
                        let cipher = sync.get("ciphers").and_then(Value::as_array).into_iter().flatten();
                        let cipher =
                            cipher.into_iter().find(|c| c.get("id").and_then(Value::as_str) == Some(skipped_id));
                        let cipher = cipher.ok_or("the skipped cipher is not in the sync")?.clone();
                        (cipher, (skipped_id.clone(), None, String::new(), ValueSource::Field, [0; 32]))
                    }
                };
                let record = state.base.get(id).map(|b| b.record.clone()).unwrap_or_default();
                let patch = Patch {
                    id: id.clone(),
                    cipher_id: Some(found.0),
                    organization_id: found.1,
                    base_revision: found.2,
                    set: Vec::new(),
                    remove: Vec::new(),
                    value: ValueChange::Set {
                        source: found.3,
                        secret: op_value(value)?,
                        base_mark: found.4,
                        owned: false,
                    },
                    answer: None,
                };
                // Asked first, as a tool asks: the vector's answer then goes to the question the copy raised.
                let given = match answer {
                    Answer::WriteToLogin => Some(HistoryAnswer::WriteToLogin),
                    Answer::KeepSeparate => Some(HistoryAnswer::KeepSeparate),
                    Answer::Unanswered => None,
                };
                match (sync::update(&mut api, ns, &keys, &record, &rng, NOW_MS, &cipher, &patch).await, given) {
                    (Err(SyncWriteError::Write(WriteError::Ask(q))), Some(a)) => {
                        let patch = Patch { answer: Some((q, a)), ..patch };
                        sync::update(&mut api, ns, &keys, &record, &rng, NOW_MS, &cipher, &patch).await
                    }
                    (sent, _) => sent,
                }
                .map(|_| ())
            }
            Operation::Create { id, value, folder_id, .. } => {
                let new = NewItem {
                    id: id.clone(),
                    value: op_value(value)?,
                    name: "<tool-defined>".into(),
                    folder_id: folder_id.clone(),
                    tool_fields: Vec::new(),
                };
                sync::create(&mut api, ns, &keys, &rng, &new).await.map(|_| ())
            }
            Operation::Delete { id, .. } => {
                sync::delete(&mut api, ns, &keys, &rng, &item(id)?.cipher, id).await.map(|_| ())
            }
        })
    })?;

    let rejected = server.rejected.get();
    compare("out-of-date rejections", rejected, u32::from(op.fresh().is_some()))?;
    let sent =
        server.sent.borrow().iter().map(|r| canonicalize(r, &keys.user, &keys.orgs)).collect::<Result<Vec<_>, _>>()?;
    match (want, outcome) {
        (WriteExpect::Requests(want), Ok(())) => compare_requests(&s.namespace, sent, &want.requests),
        (WriteExpect::Requests(want), Err(SyncWriteError::Write(e))) if gave_up(op.fresh().is_some(), &e) => {
            compare_requests(&s.namespace, sent, &want.requests)
        }
        (WriteExpect::Error(want), Err(SyncWriteError::Write(e))) => {
            compare("error code", e.code(), Some(want.error.as_str()))?;
            compare_requests(&s.namespace, sent, &[])
        }
        (WriteExpect::Question(want), Err(SyncWriteError::Write(WriteError::Ask(q)))) => {
            compare("question", q.code(), want.question.as_str())?;
            compare_requests(&s.namespace, sent, &[])
        }
        (_, Ok(())) => Err("expected an error, the write succeeded".into()),
        (_, Err(e)) => Err(format!("unexpected error: {e}")),
    }
}

/// The tool's local copies, from the scenario's `local` (a `null` is no value).
struct MapValues(BTreeMap<String, String>);

impl LocalValues for MapValues {
    fn get(&self, id: &str) -> Option<Zeroizing<String>> {
        self.0.get(id).map(|v| Zeroizing::new(v.clone()))
    }
    fn set(&mut self, id: &str, value: &str) {
        self.0.insert(id.to_owned(), value.to_owned());
    }
}

/// The device state of `device` (fingerprints and write records marked from the plaintext with the namespace's
/// marker); empty without one.
fn device_state(s: &Scenario, keys: &Keys) -> DeviceState {
    let marker = &keys.marker;
    let mut state = DeviceState::new("vectors-device".into());
    if let Some(device) = &s.device {
        for (id, e) in &device.base {
            let record = WriteRecord {
                written: e.written.iter().map(|w| marker.mark(id, w)).collect(),
                confirmed: e.write_back_confirmed,
            };
            let entry = BaseEntry {
                cipher_id: e.cipher.clone(),
                revision_date: e.revision_date.clone().unwrap_or_default(),
                fingerprint: marker.mark_b64(id, &e.value),
                scope: None,
                push_confirmed: e.push_confirmed == Some(true),
                record,
            };
            state.base.insert(id.clone(), entry);
        }
        state.pending_creates.clone_from(&device.pending_creates);
    }
    state
}

fn local_values(s: &Scenario) -> MapValues {
    MapValues(s.local.iter().flatten().filter_map(|(id, v)| Some((id.clone(), v.clone()?))).collect())
}

fn policy(s: &Scenario) -> sync::Policy {
    match s.options.policy {
        Policy::Ask => sync::Policy::Ask,
        Policy::PreferRemote => sync::Policy::PreferRemote,
        Policy::PreferLocal => sync::Policy::PreferLocal,
    }
}

/// `expect.write` of a sync vector (no `operation`): one sync from `device` and `local` with no answers, then the
/// requests it sent, or the question it asked first with nothing sent and the base unchanged.
fn sync_write(dir: &Path, s: &Scenario, want: &WriteExpect) -> Result<(), String> {
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(dir, &s.account, s.options.organizations);
    let server = VectorServer::new(scenario_keys.profile.clone(), s.ciphers.clone(), scenario_keys.prelogin.clone());
    let keys = scenario_keys.into_keys(ns);
    let mut state = device_state(s, &keys);
    let before = state.clone();
    let mut local = local_values(s);
    let allowed = if s.options.organizations { Organizations::All } else { Organizations::None };
    let rng = SeededRandom::new(0x0000_7379_6e63);
    let (overrides, answers) = (BTreeMap::new(), BTreeMap::new());
    let mut unmarked = UnmarkedCache::default();
    let mut api = client(server.clone())?;
    let report = block_on(async {
        api.login(&api_key()?).await.map_err(|e| e.to_string())?;
        let mut ctx = SyncContext {
            client: &mut api,
            ns,
            keys: &keys,
            rng: &rng,
            allowed: &allowed,
            policy: policy(s),
            accept_rollback: s.options.accept_rollback,
            overrides: &overrides,
            answers: &answers,
            applies: &|_| true,
            upload_folder: None,
            unmarked: &mut unmarked,
        };
        sync::run_sync(&mut ctx, &mut state, &mut local, |_| {}, || false).await.map_err(|e| e.to_string())
    })?;
    let sent =
        server.sent.borrow().iter().map(|r| canonicalize(r, &keys.user, &keys.orgs)).collect::<Result<Vec<_>, _>>()?;
    match want {
        WriteExpect::Requests(want) => compare_requests(&s.namespace, sent, &want.requests),
        WriteExpect::Question(want) => {
            // The format names no id: the question is about the vector's single planned push.
            let pushes = s.expect.plan.iter().flatten().filter(|p| p.kind == "push").collect::<Vec<_>>();
            let [push] = pushes.as_slice() else { return Err("a sync question needs one planned push".into()) };
            let asked: Vec<(&str, &str)> =
                report.skipped.questions.iter().map(|(i, q)| (i.as_str(), q.code())).collect();
            compare("questions", asked, vec![(push.id.as_str(), want.question.as_str())])?;
            compare("base", &state.base, &before.base)?;
            compare_requests(&s.namespace, sent, &[])
        }
        WriteExpect::Error(_) => Err("a sync vector has no error expectation".into()),
    }
}

/// The vectors' name of an action, and its conflict kind.
fn plan_entry(a: &Action) -> (&'static str, &str, Option<&'static str>) {
    match a {
        Action::Pull(id) => ("pull", id, None),
        Action::Push { id, .. } => ("push", id, None),
        Action::Create(id) => ("create", id, None),
        Action::Adopt(id) => ("adopt", id, None),
        Action::ClearLocal(id) => ("clear-local", id, None),
        Action::Forget(id) => ("forget", id, None),
        Action::Conflict { id, kind } => ("conflict", id, Some(kind.code())),
    }
}

/// Checks `expect.plan`: the device state from `device` (fingerprints of the plaintext with the namespace's marker)
/// and the local values from `local`, planned by the core's pass against the fake server. `confirmed` is not
/// compared.
pub fn plan(dir: &Path, s: &Scenario) -> Result<(), String> {
    let want = s.expect.plan.as_ref().ok_or("no expect.plan")?;
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(dir, &s.account, s.options.organizations);
    let server = VectorServer::new(scenario_keys.profile.clone(), s.ciphers.clone(), scenario_keys.prelogin.clone());
    let keys = scenario_keys.into_keys(ns);
    let state = device_state(s, &keys);
    let local = local_values(s);
    let allowed = if s.options.organizations { Organizations::All } else { Organizations::None };
    let rng = SeededRandom::new(0x0000_706c_616e);
    let (overrides, answers) = (BTreeMap::new(), BTreeMap::new());
    let mut unmarked = UnmarkedCache::default();
    let mut api = client(server)?;
    let planned = block_on(async {
        api.login(&api_key()?).await.map_err(|e| e.to_string())?;
        let mut ctx = SyncContext {
            client: &mut api,
            ns,
            keys: &keys,
            rng: &rng,
            allowed: &allowed,
            policy: policy(s),
            accept_rollback: s.options.accept_rollback,
            overrides: &overrides,
            answers: &answers,
            applies: &|_| true,
            upload_folder: None,
            unmarked: &mut unmarked,
        };
        sync::plan_pass(&mut ctx, &state, &local).await.map_err(|e| e.to_string())
    })?;
    let mut got: Vec<_> = planned.actions.iter().map(plan_entry).collect();
    got.extend(planned.report.rollbacks.iter().map(|(id, _)| ("rollback", id.as_str(), None)));
    got.sort_by(|a, b| a.1.cmp(b.1));
    let want: Vec<_> = want.iter().map(|p| (p.kind.as_str(), p.id.as_str(), p.conflict.as_deref())).collect();
    compare("plan", got, want)
}

fn compare_requests(ns: &str, sent: Vec<Value>, want: &[Value]) -> Result<(), String> {
    let strip = |v: Value| drop_tool_defined(v, ns);
    compare(
        "requests",
        sent.into_iter().map(strip).collect::<Vec<_>>(),
        want.iter().cloned().map(strip).collect::<Vec<_>>(),
    )
}

/// After a refetch (`fresh`), a copy that lost its marker or was deleted or trashed means the tool gave up
/// (README "Requests after a refetch", data model §6.5); without one, the same errors are real failures.
pub fn gave_up(refetched: bool, e: &WriteError) -> bool {
    refetched && matches!(e, WriteError::Unmarked | WriteError::Gone)
}
