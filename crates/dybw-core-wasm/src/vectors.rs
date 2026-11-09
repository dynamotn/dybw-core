//! The conformance vectors and the crypto known answers over a [`Host`], behind `runVectors` and `runKnownAnswers`
//! (bindings.rs). The native tests run them on a mock host, the JS harness (`js/`) in WASM under Node and browsers.
//!
//! Each answers JSON `{"results": [[name, null | error]], "failures": [...]}`: `failures` is what
//! `dybw_vectors::check` finds, so empty means exactly the expected ones failed. Errors name what differs, never a
//! value.

use crate::host::Host;
use crate::ports::Ports;
use dybw_core::api::{Msg, decode_msgpack};
use dybw_core::crypto::{
    Cbor, EnvelopeNamespace, KdfParams, MarkScheme, Marker, MasterKey, SymmetricKey, derive_master_key,
    hash_master_password, open_envelope, parse_cek,
};
use dybw_vectors::{Files, Kind, Outcome, check, expected_failures, run_all};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Every scenario of both namespaces, every kind, RSA through the host; against `expected-failures.txt`.
pub async fn run_vectors_json<H: Host>(files: &Files, ports: &Ports<H>) -> String {
    let mut results = Vec::new();
    for ns in ["bwss", "obsidian"] {
        for kind in Kind::ALL {
            results.extend(run_all(files, ns, kind, ports).await);
        }
    }
    report(results, &expected_failures())
}

/// The known answers of `vectors/crypto` that need no file system, Argon2id through the host; none may fail.
pub async fn run_known_answers_json<H: Host>(files: &Files, ports: &Ports<H>) -> String {
    let results = vec![
        ("pbkdf2".to_owned(), pbkdf2(files, ports).await),
        ("argon2id".to_owned(), argon2id(files, ports).await),
        ("cose".to_owned(), cose(files)),
        ("sdk".to_owned(), sdk(files)),
        ("msgpack".to_owned(), msgpack(files)),
        ("marks".to_owned(), marks(files)),
    ];
    report(results, &BTreeMap::new())
}

fn report(results: Vec<(String, Outcome)>, expected: &BTreeMap<String, String>) -> String {
    let listed: Vec<Value> = results.iter().map(|(id, o)| json!([id, o.as_ref().err()])).collect();
    let failures: Vec<String> =
        check(results, expected).err().iter().flat_map(|e| e.lines()).map(String::from).collect();
    json!({ "results": listed, "failures": failures }).to_string()
}

fn fail(e: impl ToString) -> String {
    e.to_string()
}

fn read(files: &Files, rel: &str) -> Result<Value, String> {
    let text = files.get(rel).ok_or_else(|| format!("{rel} is missing"))?;
    serde_json::from_str(text).map_err(fail)
}

/// `v[key]`, `null` when missing.
fn at<'v>(v: &'v Value, key: &str) -> &'v Value {
    v.get(key).unwrap_or(&Value::Null)
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

fn number(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap_or_default()).unwrap_or_default()
}

/// A list the vectors must not leave empty: an empty one would pass without checking anything.
fn list(v: &Value) -> Result<&[Value], String> {
    v.as_array().map(Vec::as_slice).filter(|l| !l.is_empty()).ok_or_else(|| "an empty list".into())
}

fn object(v: &Value) -> Result<&Map<String, Value>, String> {
    v.as_object().filter(|o| !o.is_empty()).ok_or_else(|| "an empty object".into())
}

fn same<T: PartialEq + ?Sized>(got: &T, want: &T, what: &str) -> Outcome {
    if got == want { Ok(()) } else { Err(format!("{what} differs")) }
}

fn key(v: &Value) -> Result<SymmetricKey, String> {
    SymmetricKey::from_bytes(&unb64(text(v))).map_err(fail)
}

/// Derives the master key of `crypto/vectors.json` with `kdf` and checks it and its stretched key against `want`.
async fn master<H: Host>(v: &Value, kdf: KdfParams, want: &Value, ports: &Ports<H>) -> Result<MasterKey, String> {
    let mk = derive_master_key(text(at(v, "password")), text(at(v, "email")), kdf, ports).await.map_err(fail)?;
    same(mk.as_slice(), unb64(text(at(want, "masterKey"))).as_slice(), "masterKey")?;
    same(SymmetricKey::stretch(&mk).to_bytes().as_slice(), unb64(text(at(want, "stretched"))).as_slice(), "stretched")?;
    Ok(mk)
}

async fn pbkdf2<H: Host>(files: &Files, ports: &Ports<H>) -> Outcome {
    let v = read(files, "crypto/vectors.json")?;
    let p = at(&v, "pbkdf2");
    let mk = master(&v, KdfParams::Pbkdf2 { iterations: number(at(p, "iterations")) }, p, ports).await?;
    same(hash_master_password(&mk, text(at(&v, "password"))).as_str(), text(at(p, "masterPasswordHash")), "hash")?;
    let user = key(at(&v, "userKey"))?;
    let unwrapped = SymmetricKey::stretch(&mk).decrypt_key(text(at(&v, "protectedUserKey"))).map_err(fail)?;
    same(unwrapped.to_bytes().as_slice(), user.to_bytes().as_slice(), "protectedUserKey")?;
    for e in list(at(&v, "encStrings"))? {
        same(user.decrypt_str(text(at(e, "enc"))).map_err(fail)?.as_str(), text(at(e, "plain")), "encString")?;
    }
    Ok(())
}

async fn argon2id<H: Host>(files: &Files, ports: &Ports<H>) -> Outcome {
    let v = read(files, "crypto/vectors.json")?;
    let a = at(&v, "argon2id");
    let (iterations, memory_mib, parallelism) =
        (number(at(a, "iterations")), number(at(a, "memory")), number(at(a, "parallelism")));
    master(&v, KdfParams::Argon2id { iterations, memory_mib, parallelism }, a, ports).await.map(drop)
}

fn cose(files: &Files) -> Outcome {
    let v = read(files, "crypto/cose-vectors.json")?;
    for acc in list(at(&v, "accounts"))? {
        let user = key(at(acc, "userKey"))?;
        for t in list(at(acc, "texts"))? {
            same(user.decrypt_str(text(at(t, "enc"))).map_err(fail)?.as_str(), text(at(t, "plain")), "text")?;
        }
        let p = at(acc, "privateKey");
        same(
            user.decrypt_pkcs8(text(at(p, "wrapped"))).map_err(fail)?.as_slice(),
            unb64(text(at(p, "pkcs8"))).as_slice(),
            "pkcs8",
        )?;
        for k in list(at(acc, "itemKeys"))? {
            let item = user.decrypt_key(text(at(k, "wrapped"))).map_err(fail)?;
            same(item.to_bytes().as_slice(), unb64(text(at(k, "key"))).as_slice(), "itemKey")?;
            same(item.decrypt_str(text(at(k, "field"))).map_err(fail)?.as_str(), text(at(k, "fieldPlain")), "field")?;
        }
    }
    Ok(())
}

/// Opens `envelope` (base64) with the content key `cek` as the SDK stores it, and checks it opens to `plaintext`.
fn opens(cek: &[u8], envelope: &str, plaintext: &Value, what: &str) -> Outcome {
    let cek = parse_cek(cek).map_err(fail)?;
    let opened = open_envelope(&cek, &unb64(envelope), EnvelopeNamespace::VaultItem).map_err(fail)?;
    same(&cbor_json(&opened), plaintext, what)
}

/// The SDK's DataEnvelope of each blob type, and its sealed blob.
fn sdk(files: &Files) -> Outcome {
    let v = read(files, "crypto/sdk-m3.json")?;
    for (name, item) in object(at(&v, "v1"))? {
        let fields = item.as_object().into_iter().flatten();
        let value =
            |suffix: &str| fields.clone().find(|(k, _)| k.ends_with(suffix)).map_or("", |(_, e)| text(at(e, "value")));
        opens(&unb64(value("_CEK")), value("_ENVELOPE"), at(item, "plaintext"), name)?;
    }
    let s = at(&v, "sealed");
    let blob: Value = serde_json::from_str(text(at(at(s, "TEST_VECTOR_SEALED_BLOB"), "value"))).map_err(fail)?;
    let cek =
        key(at(at(s, "TEST_VECTOR_WRAPPING_KEY"), "value"))?.decrypt(text(at(&blob, "wrapped_cek"))).map_err(fail)?;
    opens(&cek, text(at(&blob, "envelope")), at(s, "plaintext"), "sealed")
}

fn msgpack(files: &Files) -> Outcome {
    let v = read(files, "crypto/msgpack.json")?;
    for case in list(&v)? {
        let got = decode_msgpack(&unhex(text(at(case, "hex")))).map_err(fail)?;
        same(&msg_is(&got, at(case, "expected")), &true, text(at(case, "name")))?;
    }
    Ok(())
}

fn marks(files: &Files) -> Outcome {
    let v = read(files, "crypto/marks.json")?;
    for r in list(&v)? {
        let account = read(files, &format!("accounts/{}.json", text(at(r, "account"))))?;
        let scheme = if at(r, "scheme") == "bwss" { MarkScheme::Bwss } else { MarkScheme::Obsidian };
        let marker = Marker::new(&key(at(&account, "userKey"))?, scheme);
        same(marker.mark_b64(text(at(r, "id")), text(at(r, "text"))).as_str(), text(at(r, "mark")), "mark")?;
    }
    Ok(())
}

/// Standard base64 with padding. A character outside the alphabet decodes as `/`: it only makes a comparison fail.
pub(crate) fn unb64(s: &str) -> Vec<u8> {
    let six = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    };
    let sixes: Vec<u8> = s.bytes().filter(|&c| c != b'=').map(six).collect();
    let bytes = |c: &[u8]| {
        let n = c.iter().fold(0u32, |n, &x| (n << 6) | u32::from(x)) << (6 * (4 - c.len()));
        n.to_be_bytes().into_iter().skip(1).take(c.len().saturating_sub(1))
    };
    sixes.chunks(4).flat_map(bytes).collect()
}

/// Lowercase or uppercase hex; a pair that is not hex decodes as 0.
pub(crate) fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2).unwrap_or_default(), 16).unwrap_or(0)).collect()
}

/// A sealed content as JSON, to compare with the vectors' plaintext. The vectors hold no bytes: bytes become a
/// text no plaintext has.
pub(crate) fn cbor_json(c: &Cbor) -> Value {
    match c {
        Cbor::Uint(n) => json!(n),
        Cbor::Nint(n) => json!(-1 - i64::try_from(*n).unwrap_or(i64::MAX)),
        Cbor::Bool(b) => json!(b),
        Cbor::Null => Value::Null,
        Cbor::Text(t) => json!(t.as_str()),
        Cbor::Bytes(_) => json!("<bytes>"),
        Cbor::Array(a) => Value::Array(a.iter().map(cbor_json).collect()),
        Cbor::Map(m) => Value::Object(m.iter().map(|(k, v)| (map_key(k), cbor_json(v))).collect()),
    }
}

fn map_key(k: &Cbor) -> String {
    match cbor_json(k) {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

/// Whether the decoded value is the vector's JSON, with its `$bin` (hex), `$big` (decimal) and `$date` (ms) tags.
pub(crate) fn msg_is(m: &Msg, j: &Value) -> bool {
    let tag = |name: &str| j.get(name).and_then(Value::as_str);
    match (m, j) {
        (Msg::Nil, Value::Null) => true,
        (Msg::Bool(a), Value::Bool(b)) => a == b,
        (Msg::Int(a), Value::Number(n)) => n.to_string().parse::<i128>().ok() == Some(*a),
        (Msg::Float(a), Value::Number(n)) => n.as_f64() == Some(*a),
        (Msg::Str(a), Value::String(b)) => a == b,
        (Msg::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| msg_is(x, y)),
        (Msg::Map(a), Value::Object(o)) => {
            a.len() == o.len() && a.iter().all(|(k, v)| o.get(k).is_some_and(|y| msg_is(v, y)))
        }
        (Msg::Bin(a), _) => tag("$bin").map(unhex).as_ref() == Some(a),
        (Msg::Int(a), _) => tag("$big").and_then(|s| s.parse::<i128>().ok()) == Some(*a),
        (Msg::Timestamp { seconds, nanos }, _) => {
            let ms = seconds.saturating_mul(1000).saturating_add(i64::from(*nanos) / 1_000_000);
            j.get("$date").and_then(Value::as_i64) == Some(ms)
        }
        _ => false,
    }
}
