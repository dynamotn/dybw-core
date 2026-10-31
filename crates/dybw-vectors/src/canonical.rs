//! Port of the plugin's `test/vectors/canonical.ts`: the decrypted body a tool sent, in the vectors' canonical shape.

use crate::server::Sent;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::crypto::SymmetricKey;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// The time the tests freeze the clock at (`FixedClock`); a date equal to it was written by the tool.
pub const NOW: &str = "2099-09-09T09:09:09.999Z";
/// [`NOW`] in Unix milliseconds.
pub const NOW_MS: i64 = 4_092_628_149_999;

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

/// Reads one CBOR item (definite lengths, no tags or floats) as JSON: a byte string is its base64 text and a map key
/// of any kind is its text, which is all a COSE header and a blob need.
fn cbor_item(b: &mut &[u8], depth: u8) -> Result<Value, String> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], String> {
        let (head, rest) = b.split_at_checked(n).ok_or("truncated CBOR")?;
        *b = rest;
        Ok(head)
    }
    let depth = depth.checked_sub(1).ok_or("CBOR nested too deep")?;
    let &[first] = take(b, 1)? else { return Err("truncated CBOR".into()) };
    let (major, info) = (first >> 5, first & 31);
    let n = match info {
        0..=23 => u64::from(info),
        24..=27 => take(b, 1 << (info - 24))?.iter().fold(0u64, |acc, x| acc << 8 | u64::from(*x)),
        _ => return Err("unsupported CBOR item".into()),
    };
    let len = usize::try_from(n).map_err(|_| "CBOR length")?;
    Ok(match major {
        0 => json!(n),
        1 => json!(-1 - i64::try_from(n).map_err(|_| "CBOR integer")?),
        2 => json!(B64.encode(take(b, len)?)),
        3 => json!(std::str::from_utf8(take(b, len)?).map_err(|_| "CBOR text")?),
        4 | 5 if len > b.len() => return Err("truncated CBOR".into()),
        4 => Value::Array((0..len).map(|_| cbor_item(b, depth)).collect::<Result<_, _>>()?),
        5 => {
            let mut map = Map::new();
            for _ in 0..len {
                let key = match cbor_item(b, depth)? {
                    Value::String(s) => s,
                    Value::Number(n) => n.to_string(),
                    _ => return Err("CBOR map key".into()),
                };
                map.insert(key, cbor_item(b, depth)?);
            }
            Value::Object(map)
        }
        7 if n == 20 || n == 21 => json!(n == 21),
        7 if n == 22 => Value::Null,
        _ => return Err("unsupported CBOR item".into()),
    })
}

fn cbor(bytes: &[u8]) -> Result<Value, String> {
    let mut rest = bytes;
    let value = cbor_item(&mut rest, 16)?;
    if rest.is_empty() { Ok(value) } else { Err("trailing CBOR bytes".into()) }
}

fn b64_of(v: Option<&Value>, what: &str) -> Result<Vec<u8>, String> {
    let text = v.and_then(Value::as_str).ok_or_else(|| format!("blob {what} is missing"))?;
    B64.decode(text).map_err(|_| format!("blob {what} is not base64"))
}

/// Opens a blob: `data` is the JSON text of the sealed blob, and `key` the item key the content key is wrapped under.
/// Returns the sealed content (`CipherBlobV1`). Only an AES-256-GCM content key is read here.
// shortcut: Task 3's `open_envelope` in the core replaces this, with every algorithm and the key-op checks.
fn open_blob(data: &str, key: &SymmetricKey) -> Result<Value, String> {
    let sealed: Value = serde_json::from_str(data).map_err(|_| "blob data is not JSON")?;
    if sealed.get("format_version") != Some(&json!(1)) {
        return Err("blob format_version is not 1".into());
    }
    let wrapped = sealed.get("wrapped_cek").and_then(Value::as_str).ok_or("blob wrapped_cek is missing")?;
    let cek = key.decrypt(wrapped).map_err(|e| format!("blob wrapped_cek: {e}"))?;
    let cek = cek.split_last().filter(|(pad, _)| **pad == 1).ok_or("blob content key is not a padded COSE key")?.1;
    let cek = cbor(cek)?;
    let secret = b64_of(cek.get("-1"), "content key")?;
    if cek.get("3") != Some(&json!(3)) {
        return Err("blob content key is not AES-256-GCM".into());
    }

    let envelope = b64_of(sealed.get("envelope"), "envelope")?;
    let Value::Array(parts) = cbor(&envelope)? else { return Err("blob envelope is not a COSE_Encrypt0".into()) };
    let [protected, unprotected, ct] = parts.as_slice() else {
        return Err("blob envelope is not a COSE_Encrypt0".into());
    };
    let protected = b64_of(Some(protected), "protected header")?;
    let header = cbor(&protected)?;
    if header.get("1") != cek.get("3") || header.get("4") != cek.get("2") {
        return Err("blob envelope names another key".into());
    }
    if header.get("-80002") != Some(&json!(2)) {
        return Err("blob envelope is not a DataEnvelope".into());
    }
    let nonce = b64_of(unprotected.get("5"), "nonce")?;
    // Enc_structure ["Encrypt0", protected, h'']; a protected header is short, so its length is one byte
    let len = u8::try_from(protected.len()).map_err(|_| "blob header is too long")?;
    let head = if len < 24 { vec![0x40 | len] } else { vec![0x58, len] };
    let aad = [&[0x83, 0x68][..], b"Encrypt0", &head, &protected, &[0x40]].concat();
    let cipher = Aes256Gcm::new_from_slice(&secret).map_err(|_| "blob content key length")?;
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| "blob nonce length")?;
    let mut plain = cipher
        .decrypt(&Nonce::from(nonce), Payload { msg: &b64_of(Some(ct), "ciphertext")?, aad: &aad })
        .map_err(|_| "blob envelope does not decrypt")?;
    let pad = usize::from(plain.last().copied().unwrap_or(0));
    let content_len = plain.len().checked_sub(pad).filter(|_| pad > 0).ok_or("blob padding")?;
    plain.truncate(content_len);
    let content = cbor(&plain)?;
    if content.get("version") != Some(&json!("1")) {
        return Err("blob content version is not 1".into());
    }
    content.get("content").cloned().ok_or_else(|| "blob has no content".into())
}

/// The canonical `name`, `notes`, `login` and `fields` of a blob's content.
fn blob_parts(content: &Value) -> (Value, Value, Value, Value) {
    let get = |v: &Value, k: &str| v.get(k).cloned().unwrap_or(Value::Null);
    let list = |v: &Value, k: &str| v.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let type_data = content.get("typeData").cloned().unwrap_or(Value::Null);
    let login = if type_data.get("type") == Some(&json!("login")) {
        json!({
            "username": get(&type_data, "username"),
            "password": get(&type_data, "password"),
            "uris": list(&type_data, "uris").iter().map(|u| get(u, "uri")).collect::<Vec<_>>(),
            "totp": get(&type_data, "totp"),
            "passwordHistory": list(content, "passwordHistory").iter().map(|h| get(h, "password")).collect::<Vec<_>>(),
        })
    } else {
        Value::Null
    };
    let fields = list(content, "fields")
        .iter()
        .map(|f| json!({ "name": get(f, "name"), "value": get(f, "value"), "type": get(f, "type") }))
        .collect::<Vec<_>>();
    (get(content, "name"), get(content, "notes"), login, json!(fields))
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

    let blob = match body.get("data") {
        None | Some(Value::Null) => None,
        Some(Value::String(data)) => Some(open_blob(data, key)?),
        Some(_) => return Err("request data is not text".into()),
    };
    let (name, notes, login, fields) = if let Some(content) = &blob {
        blob_parts(content)
    } else {
        // `uris`, `fields` and `passwordHistory` read null as [] because the canonical body types them as arrays.
        let login = match body.get("login") {
            None | Some(Value::Null) => Value::Null,
            Some(Value::Object(l)) => {
                let uris =
                    list(l.get("uris")).iter().map(|u| dec(u.get("uri"), "uri")).collect::<Result<Vec<_>, _>>()?;
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
        (dec(body.get("name"), "name")?, dec(body.get("notes"), "notes")?, login, json!(fields))
    };
    let extra: Map<String, Value> =
        body.iter().filter(|(k, _)| is_extra(k)).map(|(k, v)| (k.clone(), v.clone())).collect();

    let mut request = json!({
        "method": method,
        "cipher": cipher,
        "type": plain("type"),
        "name": name,
        "notes": notes,
        "login": login,
        "fields": fields,
        "organizationId": plain("organizationId"),
        "folderId": plain("folderId"),
        "lastKnownRevisionDate": plain("lastKnownRevisionDate"),
        "hasItemKey": body.get("key").is_some_and(|k| !k.is_null()),
        "extra": extra,
    });
    if let (Some(_), Some(o)) = (&blob, request.as_object_mut()) {
        o.insert("blob".into(), json!(true));
    }
    Ok(mark_now(request))
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
