//! Runs a scenario through the core: `/sync` from the fake server with the real `Client`, then the core's scan.

use crate::canonical::{NOW_MS, canonicalize, drop_tool_defined};
use crate::keys::account_keys;
use crate::scenario::{Answer, ClientLogin, ClientUri, Operation, Policy, ReadExpect, Scenario, Server, WriteExpect};
use crate::server::{CLOUD, SERVER, VectorServer, urls};
use crate::{Files, Outcome};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::api::{ApiError, ApiKey, Client, DeviceInfo, ServerUrls, origin_of, resolve_server_urls};
use dybw_core::ports::RsaOaep;
use dybw_core::sync::{self, Action, BaseEntry, DeviceState, LocalValues, SyncContext, SyncWriteError};
use dybw_core::testing::{FixedClock, SeededRandom};
use dybw_core::vault::client::{ClientEdit, NewEntry, NewKind, NewLogin, NewUri};
use dybw_core::vault::fields::{field_names, field_value, first_index, item_key};
use dybw_core::vault::folder::folder_names;
use dybw_core::vault::item::{self, Data, Item, Text};
use dybw_core::vault::write::{HistoryAnswer, LineAppend, NewItem, Patch, ValueChange, WriteError, WriteRecord};
use dybw_core::vault::{
    Keys, Namespace, Organizations, SkipReason, Uninspectable, UnmarkedCache, ValueSource, scan_vault, scan_vault_with,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
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
    client_at(server, urls())
}

/// A client of the fake server at `urls`, with a fixed clock.
fn client_at(server: VectorServer, urls: ServerUrls) -> Result<Client<VectorServer, FixedClock>, String> {
    let device = DeviceInfo {
        identifier: "vectors-device".into(),
        name: "vectors".into(),
        device_type: 8,
        client_name: "cli".into(),
        client_version: "0".into(),
    };
    Client::new(server, FixedClock { now_ms: 0 }, urls, device).map_err(|e| e.to_string())
}

fn api_key() -> Result<ApiKey, String> {
    api_key_for(&format!("{SERVER}/identity"))
}

/// The vectors' API key, entered for the identity URL `identity`.
fn api_key_for(identity: &str) -> Result<ApiKey, String> {
    Ok(ApiKey {
        origin: origin_of(identity).map_err(|e| e.to_string())?,
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
/// given, duplicates. Lists other than items are compared sorted. A refused read compares the error code and the
/// requests sent before it (ADR 0018: none).
pub async fn read(files: &Files, s: &Scenario, rsa: &impl RsaOaep) -> Outcome {
    let want = s.expect.read.as_ref().ok_or("no expect.read")?;
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(files, &s.account, s.options.organizations, rsa).await;
    let mut server =
        VectorServer::new(scenario_keys.profile.clone(), s.ciphers.clone(), scenario_keys.prelogin.clone());
    server.follows_redirects = s.options.follows_redirects;
    let requests = server.requests.clone();
    let keys = scenario_keys.into_keys(ns);
    let urls = match s.options.server {
        Server::SelfHosted => urls(),
        Server::Cloud => resolve_server_urls(CLOUD).map_err(|e| e.to_string())?,
    };
    let key = api_key_for(&urls.identity)?;
    let mut api = client_at(server, urls)?.with_acknowledged(s.options.acknowledged.clone());
    let synced = async {
        api.login(&key).await?;
        api.sync().await
    }
    .await;
    let (want, sync) = match (want, synced) {
        (ReadExpect::Items(want), Ok(sync)) => (want, sync),
        (ReadExpect::Refused(want), Err(e)) => {
            let code = match e {
                ApiError::OriginNotAcknowledged { .. } => "origin-not-acknowledged",
                e => return Err(format!("unexpected error: {e}")),
            };
            compare("error", code, want.error.as_str())?;
            return compare("sent", requests.borrow().as_slice(), want.sent.as_slice());
        }
        (ReadExpect::Refused(_), Ok(_)) => return Err("expected an error, the read succeeded".into()),
        (ReadExpect::Items(_), Err(e)) => return Err(e.to_string()),
    };
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
pub async fn write(files: &Files, s: &Scenario, rsa: &impl RsaOaep) -> Outcome {
    let want = s.expect.write.as_ref().ok_or("no expect.write")?;
    let Some(op) = s.operation.as_ref() else { return sync_write(files, s, want, rsa).await };
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(files, &s.account, s.options.organizations, rsa).await;
    let server = VectorServer::new(scenario_keys.profile.clone(), s.ciphers.clone(), scenario_keys.prelogin.clone());
    let keys = scenario_keys.into_keys(ns);
    let state = device_state(s, &keys);
    let mut api = client(server.clone())?;
    let rng = SeededRandom::new(0x0077_7269_7465);
    let allowed = if s.options.organizations { Organizations::All } else { Organizations::None };

    let outcome = async {
        api.login(&api_key()?).await.map_err(|e| e.to_string())?;
        let sync = api.sync().await.map_err(|e| e.to_string())?;
        let report = scan_vault(&sync, ns, &keys, &allowed);
        let item = |id: &str| report.items.iter().find(|i| i.id == id).ok_or(format!("no item {id}"));
        *server.fresh.borrow_mut() = op.fresh().cloned();
        Ok::<_, String>(match op {
            Operation::SetValue { id, value, answer, append_lines, .. } => {
                // An item skipped for `dybw:requires` is not among the items: the write is tried on its cipher, as
                // an app holding a stale copy would (the vector's one `newer-format` cipher).
                let (cipher, found) = match item(id) {
                    Ok(f) => (
                        f.cipher.clone(),
                        (f.cipher_id.clone(), f.organization_id.clone(), f.revision_date.clone(), f.source, f.mark),
                    ),
                    Err(e) => {
                        let ciphers = sync.get("ciphers").and_then(Value::as_array).into_iter().flatten();
                        let carries = |c: &Value| -> Option<bool> {
                            let key = item_key(c, &keys.user).ok()?;
                            let names = field_names(c, &key).ok()?;
                            let at = first_index(&names, &ns.field("id"))?;
                            Some(field_value(c, at, &key).ok()?.trim() == id)
                        };
                        let stopped = |c: &&Value| {
                            let cid = c.get("id").and_then(Value::as_str).unwrap_or_default();
                            report.skipped.iter().any(|(s, r)| s == cid && *r == SkipReason::NewerFormat)
                        };
                        let cipher = ciphers.filter(stopped).find(|c| carries(c) == Some(true));
                        let cipher = cipher.ok_or(e)?.clone();
                        let cid = cipher.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
                        (cipher, (cid, None, String::new(), ValueSource::Field, [0; 32]))
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
                    append_lines: append_lines
                        .iter()
                        .map(|a| LineAppend {
                            name: a.name.clone(),
                            lines: a.lines.iter().map(|l| Zeroizing::new(l.clone())).collect(),
                            hidden: a.hidden,
                        })
                        .collect(),
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
            Operation::ClientCreate { .. } | Operation::ClientEdit { .. } | Operation::ClientTrash { .. } => {
                return Err("a vault client's operation goes with expect.clientWrite".into());
            }
        })
    }
    .await?;

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
                cipher_id: None,
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
async fn sync_write(files: &Files, s: &Scenario, want: &WriteExpect, rsa: &impl RsaOaep) -> Outcome {
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(files, &s.account, s.options.organizations, rsa).await;
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
    let report = async {
        api.login(&api_key()?).await.map_err(|e| e.to_string())?;
        let mut ctx = SyncContext {
            client: &mut api,
            ns,
            keys: &keys,
            rng: &rng,
            allowed: &allowed,
            policy: policy(s),
            accept_rollback: s.options.accept_rollback,
            accepted_rollbacks: &BTreeMap::new(),
            overrides: &overrides,
            answers: &answers,
            applies: &|_| true,
            upload_folder: None,
            unmarked: &mut unmarked,
        };
        sync::run_sync(&mut ctx, &mut state, &mut local, async |_: &mut _, _: &mut _| {}, || false)
            .await
            .map_err(|e| e.to_string())
    }
    .await?;
    let sent =
        server.sent.borrow().iter().map(|r| canonicalize(r, &keys.user, &keys.orgs)).collect::<Result<Vec<_>, _>>()?;
    match want {
        WriteExpect::Requests(want) => compare_requests(&s.namespace, sent, &want.requests),
        WriteExpect::Question(want) => {
            // The format names no id: the question is about the vector's single planned push.
            let pushes = s.expect.plan.iter().flatten().filter(|p| p.kind == "push").collect::<Vec<_>>();
            let [push] = pushes.as_slice() else { return Err("a sync question needs one planned push".into()) };
            let asked: Vec<(&str, &str)> =
                report.skipped.questions.iter().map(|q| (q.id.as_str(), q.question.code())).collect();
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
pub async fn plan(files: &Files, s: &Scenario, rsa: &impl RsaOaep) -> Outcome {
    let want = s.expect.plan.as_ref().ok_or("no expect.plan")?;
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(files, &s.account, s.options.organizations, rsa).await;
    let server = VectorServer::new(scenario_keys.profile.clone(), s.ciphers.clone(), scenario_keys.prelogin.clone());
    let keys = scenario_keys.into_keys(ns);
    let state = device_state(s, &keys);
    let local = local_values(s);
    let allowed = if s.options.organizations { Organizations::All } else { Organizations::None };
    let rng = SeededRandom::new(0x0000_706c_616e);
    let (overrides, answers) = (BTreeMap::new(), BTreeMap::new());
    let mut unmarked = UnmarkedCache::default();
    let mut api = client(server)?;
    let planned = async {
        api.login(&api_key()?).await.map_err(|e| e.to_string())?;
        let mut ctx = SyncContext {
            client: &mut api,
            ns,
            keys: &keys,
            rng: &rng,
            allowed: &allowed,
            policy: policy(s),
            accept_rollback: s.options.accept_rollback,
            accepted_rollbacks: &BTreeMap::new(),
            overrides: &overrides,
            answers: &answers,
            applies: &|_| true,
            upload_folder: None,
            unmarked: &mut unmarked,
        };
        sync::plan_pass(&mut ctx, &state, &local).await.map_err(|e| e.to_string())
    }
    .await?;
    let mut got: Vec<_> = planned.actions.iter().map(plan_entry).collect();
    got.extend(planned.report.rollbacks.iter().map(|(id, _, _)| ("rollback", id.as_str(), None)));
    got.sort_by(|a, b| a.1.cmp(b.1));
    let want: Vec<_> = want.iter().map(|p| (p.kind.as_str(), p.id.as_str(), p.conflict.as_deref())).collect();
    compare("plan", got, want)
}

fn compare_requests(ns: &str, mut sent: Vec<Value>, want: &[Value]) -> Result<(), String> {
    // `secureNote` is compared only where the expectation lists it (README, canonical body).
    for (i, s) in sent.iter_mut().enumerate() {
        if want.get(i).is_none_or(|w| w.get("secureNote").is_none())
            && let Some(o) = s.as_object_mut()
        {
            o.remove("secureNote");
        }
    }
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

/// The code of a reason a cipher does not open, as `expect.open[].error` names it.
fn uninspectable_code(u: Uninspectable) -> &'static str {
    match u {
        Uninspectable::TooLarge => "too-large",
        Uninspectable::OrganizationKeyMissing => "organization-key-missing",
        Uninspectable::ItemKey => "item-key",
        Uninspectable::Value => "value",
        Uninspectable::NewerFormat => "newer-format",
        Uninspectable::Blob => "blob",
        Uninspectable::NotSshKey => "not-ssh-key",
        other => panic!("vault::item gave {other:?}, which no vector names"),
    }
}

fn shown_text(t: &Text) -> Value {
    t.as_deref().map_or(Value::Null, |s| Value::String(s.as_str().to_owned()))
}

fn texts(pairs: &[(&str, &Text)]) -> Value {
    Value::Object(pairs.iter().map(|(k, v)| ((*k).to_owned(), shown_text(v))).collect())
}

/// An opened item as the plaintext JSON of `vectors/README.md` (`expect.open`).
pub fn item_json(item: &Item) -> Value {
    let mut out = json!({
        "type": item.kind,
        "name": item.name.as_str(),
        "notes": shown_text(&item.notes),
        "folderId": item.folder_id,
        "organizationId": item.organization_id,
        "reprompt": item.reprompt,
        "fields": item.fields.iter().map(|f| json!({
            "name": shown_text(&f.name), "value": shown_text(&f.value), "type": f.kind, "linkedId": f.linked_id,
        })).collect::<Vec<_>>(),
        "passwordHistory": item.history.iter().map(|h| json!({
            "password": shown_text(&h.password), "lastUsedDate": h.last_used,
        })).collect::<Vec<_>>(),
    });
    let (key, part) = match &item.data {
        Data::Login(l) => {
            let uris: Vec<Value> =
                l.uris.iter().map(|u| json!({ "uri": shown_text(&u.uri), "match": u.match_type })).collect();
            let login = json!({
                "username": shown_text(&l.username), "password": shown_text(&l.password),
                "totp": shown_text(&l.totp), "uris": uris,
            });
            ("login", login)
        }
        Data::Card(c) => (
            "card",
            texts(&[
                ("cardholderName", &c.cardholder_name),
                ("brand", &c.brand),
                ("number", &c.number),
                ("expMonth", &c.exp_month),
                ("expYear", &c.exp_year),
                ("code", &c.code),
            ]),
        ),
        Data::Identity(i) => (
            "identity",
            texts(&[
                ("title", &i.title),
                ("firstName", &i.first_name),
                ("middleName", &i.middle_name),
                ("lastName", &i.last_name),
                ("address1", &i.address1),
                ("address2", &i.address2),
                ("address3", &i.address3),
                ("city", &i.city),
                ("state", &i.state),
                ("postalCode", &i.postal_code),
                ("country", &i.country),
                ("company", &i.company),
                ("email", &i.email),
                ("phone", &i.phone),
                ("ssn", &i.ssn),
                ("username", &i.username),
                ("passportNumber", &i.passport_number),
                ("licenseNumber", &i.license_number),
            ]),
        ),
        Data::SshKey(k) => (
            "sshKey",
            texts(&[("privateKey", &k.private_key), ("publicKey", &k.public_key), ("fingerprint", &k.fingerprint)]),
        ),
        Data::SecureNote | Data::Unknown => return out,
    };
    if let Some(o) = out.as_object_mut() {
        o.insert(key.to_owned(), part);
    }
    out
}

/// Checks `expect.open`: each listed cipher opened by `vault::item::open` and summarized by `vault::item::summary`
/// with the account's user key and, under `options.organizations`, its organization keys.
pub async fn open(files: &Files, s: &Scenario, rsa: &impl RsaOaep) -> Outcome {
    let want = s.expect.open.as_ref().ok_or("no expect.open")?;
    let keys = account_keys(files, &s.account, s.options.organizations, rsa).await;
    for w in want {
        let cipher = s
            .ciphers
            .iter()
            .find(|c| c.get("id").and_then(Value::as_str) == Some(w.cipher.as_str()))
            .ok_or_else(|| format!("open: no cipher {}", w.cipher))?;
        let got = item::open(cipher, &keys.user, &keys.orgs)
            .map(|i| json!({ "id": i.id, "item": item_json(&i) }))
            .map_err(uninspectable_code);
        let expected = match (&w.item, &w.error) {
            (Some(item), None) => Ok(json!({ "id": w.cipher, "item": item })),
            (None, Some(error)) => Err(error.as_str()),
            _ => return Err(format!("open {}: give an item or an error", w.cipher)),
        };
        compare(&format!("open {}", w.cipher), got, expected.clone())?;
        let summary = item::summary(cipher, &keys.user, &keys.orgs)
            .map(|m| {
                json!({ "type": m.kind, "name": m.name.as_str(), "user": shown_text(&m.user), "folderId": m.folder_id })
            })
            .map_err(uninspectable_code);
        let opened = expected.clone();
        let expected = match (&w.summary, expected) {
            (Some(summary), _) => Ok(summary.clone()),
            (None, Ok(opened)) => {
                let at = |p: &str| opened.pointer(&format!("/item/{p}")).cloned().unwrap_or(Value::Null);
                Ok(
                    json!({ "type": at("type"), "name": at("name"), "folderId": at("folderId"), "user": at("login/username") }),
                )
            }
            (None, Err(e)) => Err(e),
        };
        compare(&format!("summary {}", w.cipher), summary, expected.clone())?;
        // The lookup (a summary and the login's URIs) and the field names are the opened item's parts, or the same error.
        let lookup = item::summary_with_uris(cipher, &keys.user, &keys.orgs)
            .map(|l| {
                let uris: Vec<Value> =
                    l.uris.iter().map(|u| json!({ "uri": shown_text(&u.uri), "match": u.match_type })).collect();
                json!({
                    "type": l.summary.kind, "name": l.summary.name.as_str(), "user": shown_text(&l.summary.user),
                    "folderId": l.summary.folder_id, "uris": uris,
                })
            })
            .map_err(uninspectable_code);
        let with_uris = |summary: Value, uris: Value| {
            let mut out = summary;
            if let Some(o) = out.as_object_mut() {
                o.insert("uris".to_owned(), uris);
            }
            out
        };
        let want_lookup = match (expected, opened.clone()) {
            (Ok(summary), Ok(o)) => {
                Ok(with_uris(summary, o.pointer("/item/login/uris").cloned().unwrap_or_else(|| json!([]))))
            }
            // The item does not open, yet its summary and URIs may read: the vector says so.
            (Ok(summary), Err(_)) if w.uris.is_some() => Ok(with_uris(summary, w.uris.clone().unwrap_or_default())),
            (Err(e), _) | (Ok(_), Err(e)) => Err(e),
        };
        compare(&format!("lookup {}", w.cipher), lookup, want_lookup)?;
        let names = item::field_names(cipher, &keys.user, &keys.orgs)
            .map(|fields| fields.iter().map(|f| json!({ "name": shown_text(&f.name), "type": f.kind })).collect())
            .map_err(uninspectable_code);
        let want_names = match (&w.field_names, opened.clone()) {
            (Some(names), _) => Ok(names.clone()),
            (None, Ok(o)) => {
                let fields = o.pointer("/item/fields").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
                Ok(fields.iter().map(|f| json!({ "name": f["name"], "type": f["type"] })).collect())
            }
            (None, Err(e)) => Err(e),
        };
        compare(&format!("field names {}", w.cipher), names, want_names)?;
        // The SSH agent's read: a key's name, public key and fingerprint, or `not-ssh-key` for any other type.
        let ssh = item::ssh_public(cipher, &keys.user, &keys.orgs)
            .map(|p| {
                json!({
                    "type": p.summary.kind, "name": p.summary.name.as_str(),
                    "publicKey": shown_text(&p.public_key), "fingerprint": shown_text(&p.fingerprint),
                })
            })
            .map_err(uninspectable_code);
        let want_ssh = match (&w.ssh_public, opened) {
            _ if cipher.get("type").and_then(Value::as_u64) != Some(5) => Err("not-ssh-key"),
            (Some(given), _) => Ok(given.clone()),
            (None, Ok(o)) => {
                let at = |p: &str| o.pointer(&format!("/item/{p}")).cloned().unwrap_or(Value::Null);
                Ok(json!({
                    "type": 5, "name": at("name"),
                    "publicKey": at("sshKey/publicKey"), "fingerprint": at("sshKey/fingerprint"),
                }))
            }
            (None, Err(e)) => Err(e),
        };
        compare(&format!("ssh public {}", w.cipher), ssh, want_ssh)?;
    }
    Ok(())
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn new_uris(uris: &[ClientUri]) -> Vec<NewUri> {
    uris.iter()
        .map(|u| match u {
            ClientUri::Plain(uri) => NewUri { uri: z(uri), match_type: None },
            ClientUri::Matched { uri, match_type } => NewUri { uri: z(uri), match_type: *match_type },
        })
        .collect()
}

/// The code of a vault client's refusal, as `expect.clientWrite.error` names it.
fn client_error_code(e: &SyncWriteError) -> Option<&'static str> {
    match e {
        SyncWriteError::Write(WriteError::Uninspectable(u)) => Some(uninspectable_code(*u)),
        SyncWriteError::Write(e) => e.code(),
        _ => None,
    }
}

/// Checks `expect.clientWrite`: runs a vault client's create, edit or trash (`sync::client_*`) against the fake
/// server with the account's keys, then compares the decrypted requests it accepted, or the error code with nothing
/// accepted. Unlike a tool's create, a vault client's whole body is compared: its name is the user's.
pub async fn client_write(files: &Files, s: &Scenario, rsa: &impl RsaOaep) -> Outcome {
    let want = s.expect.client_write.as_ref().ok_or("no expect.clientWrite")?;
    let op = s.operation.as_ref().ok_or("expect.clientWrite needs an operation")?;
    let keys = account_keys(files, &s.account, s.options.organizations, rsa).await;
    let server = VectorServer::new(keys.profile.clone(), s.ciphers.clone(), keys.prelogin.clone());
    let mut api = client(server.clone())?;
    let rng = SeededRandom::new(0x0063_6c69_656e);
    api.login(&api_key()?).await.map_err(|e| e.to_string())?;
    api.sync().await.map_err(|e| e.to_string())?;
    *server.fresh.borrow_mut() = op.fresh().cloned();
    let outcome = match op {
        Operation::ClientCreate { item } => {
            let none = ClientLogin::default();
            let kind = match (item.kind, &item.login) {
                (1, login) => {
                    let l = login.as_ref().unwrap_or(&none);
                    NewKind::Login(NewLogin {
                        username: z(&l.username),
                        password: z(&l.password),
                        totp: z(&l.totp),
                        uris: new_uris(&l.uris),
                    })
                }
                (2, None) => NewKind::SecureNote,
                _ => return Err("a new item is a login, or a secure note without a login part".into()),
            };
            let entry =
                NewEntry { name: z(&item.name), notes: z(&item.notes), folder_id: item.folder_id.clone(), kind };
            sync::client_create(&mut api, &keys.user, keys.security_version, &rng, &entry).await.map(|_| ())
        }
        Operation::ClientEdit { cipher, base_revision, name, notes, username, password, uris, folder_id, .. } => {
            let edit = ClientEdit {
                base_revision: base_revision.clone(),
                name: name.as_deref().map(z),
                notes: notes.as_deref().map(z),
                username: username.as_deref().map(z),
                password: password.as_deref().map(z),
                uris: uris.as_deref().map(new_uris),
                folder_id: folder_id.clone(),
            };
            sync::client_update(&mut api, &keys.user, &keys.orgs, &rng, NOW_MS, cipher, &edit).await.map(|_| ())
        }
        Operation::ClientTrash { cipher, base_revision } => {
            sync::client_trash(&mut api, &keys.user, &keys.orgs, cipher, base_revision).await
        }
        _ => return Err("expect.clientWrite goes with a vault client's operation".into()),
    };
    compare("out-of-date rejections", server.rejected.get(), u32::from(op.fresh().is_some()))?;
    let sent =
        server.sent.borrow().iter().map(|r| canonicalize(r, &keys.user, &keys.orgs)).collect::<Result<Vec<_>, _>>()?;
    let want = match (want, outcome) {
        (WriteExpect::Requests(want), Ok(())) => want.requests.as_slice(),
        (WriteExpect::Error(want), Err(e)) => {
            compare("error code", client_error_code(&e), Some(want.error.as_str()))?;
            &[]
        }
        (WriteExpect::Question(_), _) => return Err("a vault client is never asked a history question".into()),
        (_, Ok(())) => return Err("expected an error, the write succeeded".into()),
        (_, Err(e)) => return Err(format!("unexpected error: {e}")),
    };
    // `secureNote` is compared only where the expectation lists it, as for a tool's write.
    let sent: Vec<Value> = sent
        .into_iter()
        .enumerate()
        .map(|(i, mut r)| {
            if want.get(i).is_none_or(|w| w.get("secureNote").is_none())
                && let Some(o) = r.as_object_mut()
            {
                o.remove("secureNote");
            }
            r
        })
        .collect();
    compare("requests", sent.as_slice(), want)
}

/// Checks `expect.folders`: the names `vault::folder::folder_names` reads from the scenario's folders with the
/// account's user key, in id order, each a name or the error code; nothing listed, nothing in the map.
pub async fn folders(files: &Files, s: &Scenario, rsa: &impl RsaOaep) -> Outcome {
    let want = s.expect.folders.as_ref().ok_or("no expect.folders")?;
    let keys = account_keys(files, &s.account, false, rsa).await;
    let got: Vec<Value> = folder_names(&json!({ "folders": s.folders }), &keys.user)
        .iter()
        .map(|(id, r)| match r {
            Ok(name) => json!({ "id": id, "name": name }),
            Err(e) => json!({ "id": id, "error": uninspectable_code(e) }),
        })
        .collect();
    let mut expected: Vec<Value> = want
        .iter()
        .map(|w| match (&w.name, &w.error) {
            (Some(name), None) => Ok(json!({ "id": w.id, "name": name })),
            (None, Some(error)) => Ok(json!({ "id": w.id, "error": error })),
            _ => Err(format!("folder {}: give a name or an error", w.id)),
        })
        .collect::<Result<_, String>>()?;
    expected.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    compare("folders", got, expected)
}
