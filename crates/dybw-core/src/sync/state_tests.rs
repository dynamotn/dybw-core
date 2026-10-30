//! The plugin's `state.test.ts`, plus the round trip of the JSON the plugin writes today.

use super::*;
use crate::vault::namespace::Namespace;
use serde_json::{Value, json};

const NS: Namespace = Namespace::OBSIDIAN;

fn parse(raw: &Value) -> DeviceState {
    parse_plugin_state(raw, &NS, || "fresh-id".into())
}

fn entry() -> Value {
    json!({ "cipherId": "c1", "revisionDate": "r1", "fingerprint": "f1" })
}

#[test]
fn makes_up_a_device_id_when_the_stored_one_is_missing_or_empty() {
    for device_id in [None, Some(json!("")), Some(json!(42))] {
        let mut raw = json!({ "version": 1, "base": { "a": entry() } });
        if let Some(d) = device_id {
            raw["deviceId"] = d;
        }
        let s = parse(&raw);
        assert_eq!(s.device_id, "fresh-id");
        assert_eq!(to_plugin_json(&s)["base"], json!({ "a": entry() }));
    }
}

#[test]
fn a_stored_device_id_never_asks_for_a_fresh_one() {
    let s = parse_plugin_state(&json!({ "version": 1, "deviceId": "d1" }), &NS, || unreachable!("fresh id"));
    assert_eq!(s.device_id, "d1");
}

#[test]
fn starts_fresh_from_a_state_of_another_version_keeping_only_the_device_id() {
    let raw = json!({ "version": 2, "deviceId": "d1", "base": { "a": entry() }, "pendingCreates": ["b"],
        "pendingScopes": { "b": "global" } });
    assert_eq!(parse(&raw), DeviceState::new("d1".into()));
}

#[test]
fn drops_parts_that_are_not_of_the_right_kind() {
    let raw = json!({ "version": 1, "deviceId": "d1", "base": "a", "pendingCreates": "b", "pendingScopes": null });
    assert_eq!(parse(&raw), DeviceState::new("d1".into()));
    // Not an object at all: fresh, with a made-up device id.
    assert_eq!(parse(&json!(null)), DeviceState::new("fresh-id".into()));
    assert_eq!(parse(&json!("state")), DeviceState::new("fresh-id".into()));
}

#[test]
fn drops_entries_the_plugin_drops() {
    let raw = json!({
        "version": 1,
        "deviceId": "d1",
        "base": {
            "ok": entry(),
            "Bad_Id": entry(),
            "keychain-bitwarden-x": entry(),
            "bitwarden-secrets-x": entry(),
            "null-entry": null,
            "string-entry": "e",
            "no-cipher": { "revisionDate": "r", "fingerprint": "f" },
            "no-revision": { "cipherId": "c", "fingerprint": "f" },
            "no-fingerprint": { "cipherId": "c", "revisionDate": "r" },
            "number-fingerprint": { "cipherId": "c", "revisionDate": "r", "fingerprint": 1 },
            "loose": { "cipherId": "c", "revisionDate": "r", "fingerprint": "f", "scope": 3, "pushConfirmed": "yes" },
        },
        "pendingCreates": ["a", "Bad_Id", 7, "keychain-bitwarden-y", "b", "a"],
        "pendingScopes": { "a": "device:d1", "Bad_Id": "x", "b": 1, "bitwarden-secrets-z": "y" },
    });
    let s = parse(&raw);
    assert_eq!(s.base.keys().collect::<Vec<_>>(), ["loose", "ok"]);
    // A non-string scope and a non-true pushConfirmed are dropped, as the plugin does.
    let loose = &s.base["loose"];
    assert_eq!((loose.scope.clone(), loose.push_confirmed), (None, false));
    assert_eq!(s.pending_creates, ["a", "b", "a"]);
    assert_eq!(s.pending_scopes.into_iter().collect::<Vec<_>>(), [("a".into(), "device:d1".into())]);
}

#[test]
fn the_namespace_decides_which_ids_are_synced() {
    let raw = json!({ "version": 1, "deviceId": "d", "pendingCreates": ["Any Id", "_collections"] });
    assert_eq!(parse_plugin_state(&raw, &Namespace::BWSS, || unreachable!("fresh id")).pending_creates, ["Any Id"]);
    assert!(parse(&raw).pending_creates.is_empty());
}

#[test]
fn reset_forgets_what_was_synced_and_queued_but_keeps_the_device_id() {
    let raw = json!({
        "version": 1,
        "deviceId": "d1",
        "base": { "a": { "cipherId": "c1", "revisionDate": "r1", "fingerprint": "f1", "pushConfirmed": true } },
        "pendingCreates": ["b"],
        "pendingScopes": { "b": "device:d1" },
    });
    let s = parse(&raw);
    assert_eq!(s.reset(), DeviceState::new("d1".into()));
    // The state it came from is not changed.
    assert_eq!(s.pending_creates, ["b"]);
}

#[test]
fn plugin_state_round_trips() {
    // As the plugin writes it today: a personal item, a scoped one, a confirmed organization item, queued uploads.
    let written = json!({
        "version": 1,
        "deviceId": "6f1c2f4e-3b1a-4c55-9d0e-2a7f8e1b9c33",
        "base": {
            "github-token": { "cipherId": "0b9f1d2e-aaaa-4bbb-8ccc-1234567890ab", "revisionDate": "2026-10-01T08:30:00.123Z",
                "fingerprint": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo", "scope": "global" },
            "work-key": { "cipherId": "7d2e3f40-bbbb-4ccc-8ddd-0987654321ba", "revisionDate": "2026-10-02T09:00:00.000Z",
                "fingerprint": "ZmluZ2VycHJpbnQ", "scope": "device:6f1c2f4e-3b1a-4c55-9d0e-2a7f8e1b9c33", "pushConfirmed": true },
            "plain": { "cipherId": "c3", "revisionDate": "2026-10-03T00:00:00.000Z", "fingerprint": "bm8tc2NvcGU" },
        },
        "pendingCreates": ["new-secret", "another-one"],
        "pendingScopes": { "new-secret": "vault:Notes" },
    });
    let state = parse(&written);
    assert_eq!(to_plugin_json(&state), written);
    assert_eq!(parse(&to_plugin_json(&state)), state);
}

#[test]
fn a_version_stored_as_one_point_zero_is_version_one() {
    // JavaScript reads `1.0` as `1`; anything else is another version.
    let raw: Value = serde_json::from_str(r#"{ "version": 1.0, "deviceId": "d1", "pendingCreates": ["a"] }"#).unwrap();
    assert_eq!(parse(&raw).pending_creates, ["a"]);
    for other in [json!(1.5), json!("1"), json!(true)] {
        let raw = json!({ "version": other, "deviceId": "d1", "pendingCreates": ["a"] });
        assert!(parse(&raw).pending_creates.is_empty());
    }
}

#[test]
fn the_plugin_json_is_always_version_one() {
    let mut s = DeviceState::new("d1".into());
    s.version = 7;
    assert_eq!(to_plugin_json(&s)["version"], json!(1));
}
