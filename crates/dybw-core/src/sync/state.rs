//! Per-device sync state, version 1 of the plugin. It lives on the device, never in synced settings: a base
//! copied to another device would make it believe its still-empty secrets were deleted or edited.

use super::plan::BaseEntry;
use crate::vault::namespace::Namespace;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceState {
    /// Always 1.
    pub version: u8,
    pub device_id: String,
    pub base: BTreeMap<String, BaseEntry>,
    pub pending_creates: Vec<String>,
    /// Scope chosen when the secret was queued for upload, e.g. `device:<id>`.
    pub pending_scopes: BTreeMap<String, String>,
}

impl DeviceState {
    pub fn new(device_id: String) -> Self {
        Self { version: 1, device_id, base: BTreeMap::new(), pending_creates: vec![], pending_scopes: BTreeMap::new() }
    }

    /// Forgets what was synced and queued, keeps the device identity.
    pub fn reset(&self) -> Self {
        Self::new(self.device_id.clone())
    }
}

/// Accepts only a well-formed state; anything else starts fresh but keeps the device id. Entries whose id the
/// namespace refuses are dropped: the stored state is only as trustworthy as the storage holding it.
pub fn parse_plugin_state(raw: &Value, ns: &Namespace, fresh_id: impl FnOnce() -> String) -> DeviceState {
    let empty = Map::new();
    let r = raw.as_object().unwrap_or(&empty);
    let synced = |id: &str| (ns.id_rule)(id).is_ok();
    let str_of = |e: &Map<String, Value>, k: &str| e.get(k).and_then(Value::as_str).map(String::from);
    let device_id = match str_of(r, "deviceId") {
        Some(d) if !d.is_empty() => d,
        _ => fresh_id(),
    };
    let mut state = DeviceState::new(device_id);
    // `=== 1` in JavaScript, where `1.0` is `1`.
    if r.get("version").and_then(Value::as_f64) != Some(1.0) {
        return state;
    }
    for (id, e) in r.get("base").and_then(Value::as_object).into_iter().flatten() {
        let Some(e) = e.as_object().filter(|_| synced(id)) else { continue };
        if let (Some(cipher_id), Some(revision_date), Some(fingerprint)) =
            (str_of(e, "cipherId"), str_of(e, "revisionDate"), str_of(e, "fingerprint"))
        {
            let (scope, push_confirmed) = (str_of(e, "scope"), e.get("pushConfirmed") == Some(&Value::Bool(true)));
            state.base.insert(id.clone(), BaseEntry { cipher_id, revision_date, fingerprint, scope, push_confirmed });
        }
    }
    for (id, s) in r.get("pendingScopes").and_then(Value::as_object).into_iter().flatten() {
        if let (true, Some(s)) = (synced(id), s.as_str()) {
            state.pending_scopes.insert(id.clone(), s.into());
        }
    }
    let creates = r.get("pendingCreates").and_then(Value::as_array).into_iter().flatten();
    state.pending_creates = creates.filter_map(Value::as_str).filter(|id| synced(id)).map(String::from).collect();
    state
}

/// The JSON the plugin writes today.
pub fn to_plugin_json(state: &DeviceState) -> Value {
    let base: Map<String, Value> = state
        .base
        .iter()
        .map(|(id, e)| {
            let mut o = Map::new();
            o.insert("cipherId".into(), json!(e.cipher_id));
            o.insert("revisionDate".into(), json!(e.revision_date));
            o.insert("fingerprint".into(), json!(e.fingerprint));
            if let Some(scope) = &e.scope {
                o.insert("scope".into(), json!(scope));
            }
            if e.push_confirmed {
                o.insert("pushConfirmed".into(), json!(true));
            }
            (id.clone(), Value::Object(o))
        })
        .collect();
    json!({
        // The only version this writes.
        "version": 1,
        "deviceId": state.device_id,
        "base": base,
        "pendingCreates": state.pending_creates,
        "pendingScopes": state.pending_scopes,
    })
}
