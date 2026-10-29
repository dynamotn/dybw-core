//! Port of the plugin's `test/vectors/canonical.ts`: the decrypted body a tool sent, in the vectors' canonical shape.

use crate::server::Sent;
use dybw_core::crypto::SymmetricKey;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// The time the tests freeze the clock at (`FixedClock`); a date equal to it was written by the tool.
pub const NOW: &str = "2099-09-09T09:09:09.999Z";

/// Replaces every string equal to [`NOW`] by the literal `<now>` of the vectors.
fn mark_now(value: Value) -> Value {
    match value {
        Value::String(s) if s == NOW => Value::String("<now>".into()),
        Value::Array(a) => Value::Array(a.into_iter().map(mark_now).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, mark_now(v))).collect()),
        v => v,
    }
}

/// Only the `x` convention keys pass through; any other key of the body is ignored (README, canonical body).
fn is_extra(key: &str) -> bool {
    key.strip_prefix('x').is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Decrypts the request a tool sent with the scenario's keys (the item key when the body has one). An error, not a
/// panic, when a value does not decrypt, so one bad vector never stops the run.
pub fn canonicalize(sent: &Sent, user: &SymmetricKey, orgs: &BTreeMap<String, SymmetricKey>) -> Result<Value, String> {
    let (method, cipher, body) = match sent {
        Sent::Trash { cipher } => return Ok(json!({ "method": "trash", "cipher": cipher })),
        Sent::Post { body } => ("POST", Value::Null, body),
        Sent::Put { cipher, body } => ("PUT", json!(cipher), body),
    };
    let body = body.as_object().ok_or("request body is not an object")?;
    let plain = |k: &str| body.get(k).cloned().unwrap_or(Value::Null);
    let owner = match body.get("organizationId").and_then(Value::as_str) {
        Some(org) => orgs.get(org).ok_or_else(|| format!("no key for organization {org}"))?,
        None => user,
    };
    let item_key = match body.get("key").and_then(Value::as_str) {
        Some(wrapped) => Some(owner.decrypt_key(wrapped).map_err(|e| format!("request item key: {e}"))?),
        None => None,
    };
    let key = item_key.as_ref().unwrap_or(owner);
    let dec = |v: Option<&Value>, what: &str| -> Result<Value, String> {
        match v {
            None | Some(Value::Null) => Ok(Value::Null),
            Some(Value::String(s)) => key
                .decrypt_str(s)
                .map(|t| json!(t.as_str()))
                .map_err(|e| format!("request {what} does not decrypt: {e}")),
            Some(_) => Err(format!("request {what} is not an EncString")),
        }
    };
    let list = |v: Option<&Value>| v.and_then(Value::as_array).cloned().unwrap_or_default();

    // `uris`, `fields` and `passwordHistory` read null as [] because the canonical body types them as arrays.
    let login = match body.get("login") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Object(l)) => {
            let uris = list(l.get("uris")).iter().map(|u| dec(u.get("uri"), "uri")).collect::<Result<Vec<_>, _>>()?;
            let history = list(body.get("passwordHistory"))
                .iter()
                .map(|h| dec(h.get("password"), "passwordHistory"))
                .collect::<Result<Vec<_>, _>>()?;
            json!({
                "username": dec(l.get("username"), "username")?,
                "password": dec(l.get("password"), "password")?,
                "uris": uris,
                "totp": dec(l.get("totp"), "totp")?,
                "passwordHistory": history,
            })
        }
        Some(_) => return Err("request login is not an object".into()),
    };
    let fields = list(body.get("fields"))
        .iter()
        .map(|f| {
            Ok(json!({
                "name": dec(f.get("name"), "field name")?,
                "value": dec(f.get("value"), "field value")?,
                "type": f.get("type").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let extra: Map<String, Value> =
        body.iter().filter(|(k, _)| is_extra(k)).map(|(k, v)| (k.clone(), v.clone())).collect();

    Ok(mark_now(json!({
        "method": method,
        "cipher": cipher,
        "type": plain("type"),
        "name": dec(body.get("name"), "name")?,
        "notes": dec(body.get("notes"), "notes")?,
        "login": login,
        "fields": fields,
        "organizationId": plain("organizationId"),
        "folderId": plain("folderId"),
        "lastKnownRevisionDate": plain("lastKnownRevisionDate"),
        "hasItemKey": body.get("key").is_some_and(|k| !k.is_null()),
        "extra": extra,
    })))
}

/// R16: the data model leaves a new item's name and the tool's other fields open (§6.2), so a `POST` is compared
/// without its name and without every `{ns}:*` field but `{ns}:id` and `{ns}:password`. Applied to both sides.
pub fn drop_tool_defined(mut request: Value, ns: &str) -> Value {
    if request.get("method") != Some(&json!("POST")) {
        return request;
    }
    let Some(o) = request.as_object_mut() else { return request };
    o.remove("name");
    let prefix = format!("{ns}:");
    let (id, password) = (format!("{ns}:id"), format!("{ns}:password"));
    if let Some(Value::Array(fields)) = o.get_mut("fields") {
        fields.retain(|f| {
            let name = f.get("name").and_then(Value::as_str).unwrap_or_default();
            !name.starts_with(&prefix) || name == id || name == password
        });
    }
    request
}
