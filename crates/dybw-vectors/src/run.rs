//! Runs a scenario through the core: `/sync` from the fake server with the real `Client`, then the core's scan.

use crate::canonical::{NOW_MS, canonicalize, drop_tool_defined};
use crate::keys::account_keys;
use crate::scenario::{Operation, Scenario, WriteExpect};
use crate::server::{SERVER, VectorServer, urls};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::api::{ApiKey, Client, DeviceInfo, origin_of};
use dybw_core::sync::{self, SyncWriteError};
use dybw_core::testing::{FixedClock, SeededRandom, block_on};
use dybw_core::vault::write::{NewItem, Patch, ValueChange, WriteError};
use dybw_core::vault::{Namespace, Organizations, scan_vault};
use serde_json::Value;
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
    let report = scan_vault(&sync, ns, &keys, &allowed);

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
    let dups: Vec<(&str, &str, &[String])> =
        report.duplicates.iter().map(|d| (d.id.as_str(), d.kept.as_str(), d.left.as_slice())).collect();
    let want_dups: Vec<(&str, &str, &[String])> = want
        .duplicates
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|d| (d.id.as_str(), d.kept.as_str(), d.left.as_slice()))
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
    let op = s.operation.as_ref().ok_or("no operation")?;
    let ns = namespace(&s.namespace)?;
    let scenario_keys = account_keys(dir, &s.account, s.options.organizations);
    let server = VectorServer::new(scenario_keys.profile.clone(), s.ciphers.clone(), scenario_keys.prelogin.clone());
    let keys = scenario_keys.into_keys(ns);
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
            Operation::SetValue { id, value, .. } => {
                let found = item(id)?;
                let patch = Patch {
                    id: found.id.clone(),
                    cipher_id: Some(found.cipher_id.clone()),
                    base_revision: found.revision_date.clone(),
                    set: Vec::new(),
                    remove: Vec::new(),
                    value: ValueChange::Set {
                        source: found.source,
                        secret: op_value(value)?,
                        base_mark: found.mark,
                        owned: false,
                    },
                };
                sync::update(&mut api, ns, &keys, &rng, NOW_MS, &found.cipher, &patch).await.map(|_| ())
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
        (_, Ok(())) => Err("expected an error, the write succeeded".into()),
        (_, Err(e)) => Err(format!("unexpected error: {e}")),
    }
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
