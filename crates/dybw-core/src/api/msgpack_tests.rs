use super::*;
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn vectors() -> Value {
    let dir = std::env::var("DYBW_VECTORS_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors").into());
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/crypto/msgpack.json")).unwrap()).unwrap()
}

/// Does the decoded value match the vector's JSON, with its `$bin`, `$date` and `$big` tags?
fn same(m: &Msg, j: &Value) -> bool {
    match (m, j) {
        (Msg::Nil, Value::Null) => true,
        (Msg::Bool(a), Value::Bool(b)) => a == b,
        (Msg::Int(a), Value::Number(n)) if !n.is_f64() => n.to_string().parse::<i128>().unwrap() == *a,
        (Msg::Float(a), Value::Number(n)) => n.as_f64() == Some(*a),
        (Msg::Str(a), Value::String(b)) => a == b,
        (Msg::Array(a), Value::Array(b)) => a.len() == b.len() && a.iter().zip(b).all(|(x, y)| same(x, y)),
        (Msg::Bin(a), Value::Object(o)) if o.contains_key("$bin") => unhex(o["$bin"].as_str().unwrap()) == *a,
        (Msg::Int(a), Value::Object(o)) if o.contains_key("$big") => {
            o["$big"].as_str().unwrap().parse::<i128>().unwrap() == *a
        }
        (Msg::Timestamp { seconds, nanos }, Value::Object(o)) if o.contains_key("$date") => {
            o["$date"].as_i64() == Some(seconds * 1000 + i64::from(*nanos) / 1_000_000)
        }
        (Msg::Map(a), Value::Object(o)) => {
            a.len() == o.len() && a.iter().all(|(k, v)| o.get(k).is_some_and(|y| same(v, y)))
        }
        _ => false,
    }
}

#[test]
fn msgpack_kat() {
    for case in vectors().as_array().unwrap() {
        let got = decode_msgpack(&unhex(case["hex"].as_str().unwrap())).unwrap();
        assert!(same(&got, &case["expected"]), "{}", case["name"]);
    }
}

#[test]
fn msgpack_ext_and_int_keys() {
    assert_eq!(decode_msgpack(&[0xd4, 0x05, 0x09]).unwrap(), Msg::Ext(5, vec![9]));
    assert_eq!(decode_msgpack(&[0x81, 0x07, 0xc3]).unwrap(), Msg::Map(vec![("7".into(), Msg::Bool(true))]));
}

#[test]
fn msgpack_wide_headers() {
    assert_eq!(decode_msgpack(&[0xc6, 0, 0, 0, 1, 7]).unwrap(), Msg::Bin(vec![7]));
    assert_eq!(decode_msgpack(&[0xc8, 0, 1, 0x02, 7]).unwrap(), Msg::Ext(2, vec![7]));
    assert_eq!(decode_msgpack(&[0xc9, 0, 0, 0, 1, 0x02, 7]).unwrap(), Msg::Ext(2, vec![7]));
    let mut fix16 = vec![0xd8, 0x03];
    fix16.extend([0; 16]);
    assert_eq!(decode_msgpack(&fix16).unwrap(), Msg::Ext(3, vec![0; 16]));
    assert_eq!(decode_msgpack(&[0xdd, 0, 0, 0, 1, 0xc0]).unwrap(), Msg::Array(vec![Msg::Nil]));
    let map = Msg::Map(vec![("a".into(), Msg::Nil)]);
    assert_eq!(decode_msgpack(&[0xdf, 0, 0, 0, 1, 0xa1, b'a', 0xc0]).unwrap(), map);
    assert_eq!(decode_msgpack(&[0xde, 0, 1, 0xa1, b'a', 0xc0]).unwrap(), map);
}

#[test]
fn msgpack_rejects() {
    use MsgPackError::{Malformed, TooDeep, Truncated};
    let mut deep = vec![0x91; 33];
    deep.push(0xc0);
    let mut ok = vec![0x91; 32];
    ok.push(0xc0);
    for (bytes, want, why) in [
        (vec![], Truncated, "empty"),
        (vec![0xcd, 0x01], Truncated, "truncated int"),
        (vec![0xa3, b'a'], Truncated, "truncated str"),
        (vec![0xa1, 0xff], Malformed, "invalid utf-8"),
        (vec![0x81, 0x90, 0x01], Malformed, "array key"),
        (vec![0x81, 0xca, 0, 0, 0, 0, 0x01], Malformed, "float key"),
        (deep, TooDeep, "depth 33"),
        (vec![0xd7, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0], Malformed, "trailing"),
        (vec![0xd6, 0xff, 0, 0, 0], Truncated, "truncated timestamp"),
        (vec![0xd5, 0xff, 0, 0], Malformed, "timestamp length 2"),
        (vec![0xc1], Malformed, "unknown byte"),
        (vec![0x82, 0xa1, b'k', 0x01, 0xa1, b'k', 0x02], Malformed, "repeated string key"),
        (vec![0x82, 0x05, 0x01, 0x05, 0x02], Malformed, "repeated integer key"),
        (vec![0x82, 0x01, 0x01, 0xa1, b'1', 0x02], Malformed, "int 1 and str \"1\" are one key"),
        (vec![0x81, 0xcf, 0, 0x20, 0, 0, 0, 0, 0, 0, 0], Malformed, "uint64 key beyond 2^53"),
        (vec![0x81, 0xd3, 0xff, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0], Malformed, "int64 key below -2^53"),
    ] {
        assert_eq!(decode_msgpack(&bytes), Err(want), "{why}");
    }
    assert!(decode_msgpack(&ok).is_ok());
    // The largest safe integer is still a key.
    let max = [0x81, 0xcf, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0];
    assert_eq!(decode_msgpack(&max).unwrap(), Msg::Map(vec![("9007199254740991".into(), Msg::Nil)]));
    // A leading BOM is kept (the plugin's TextDecoder strips it).
    assert_eq!(decode_msgpack(&[0xa3, 0xef, 0xbb, 0xbf]).unwrap(), Msg::Str("\u{feff}".into()));
}

#[test]
fn msgpack_huge_array_header_fails_without_allocating() {
    for head in [0xdd, 0xdf] {
        assert_eq!(decode_msgpack(&[head, 0xff, 0xff, 0xff, 0xff]), Err(MsgPackError::Truncated));
    }
}

#[test]
fn signalr_frames() {
    assert_eq!(split_signalr_frames(&[2, 1, 2, 1, 3], 8).unwrap(), vec![&[1u8, 2][..], &[3][..]]);
    assert!(split_signalr_frames(&[], 8).unwrap().is_empty());
    assert_eq!(
        split_signalr_frames(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01], 8),
        Err(MsgPackError::Malformed),
        "6-byte prefix"
    );
    assert_eq!(split_signalr_frames(&[0x80], 8), Err(MsgPackError::Malformed), "truncated prefix");
    assert_eq!(split_signalr_frames(&[9, 0], 8), Err(MsgPackError::TooLarge));
    assert_eq!(split_signalr_frames(&[3, 1], 8), Err(MsgPackError::Truncated));
    let mut big = vec![0x80, 0x80, 0x40]; // exactly 1 MiB
    big.extend(vec![0; 1 << 20]);
    assert_eq!(split_signalr_frames(&big, 1 << 20).unwrap().len(), 1);
    big[2] = 0x41;
    assert_eq!(split_signalr_frames(&big, 1 << 20), Err(MsgPackError::TooLarge));
}
