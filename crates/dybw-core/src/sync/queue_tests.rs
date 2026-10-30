//! The queue: the merges of bwss `runner.rs` and the flush against the scripted server of `write_tests`.

use super::queue::{Step, classify};
use super::write_tests::{B, Rig};
use super::*;
use crate::api::ApiError;
use crate::crypto::SymmetricKey;
use crate::testing::block_on;
use crate::vault::scan::ValueSource;
use crate::vault::write::{FieldSet, NewItem, Patch, ValueChange, WriteError};
use serde_json::{Value, json};
use zeroize::Zeroizing;

fn set(source: ValueSource, secret: &[u8], mark: u8) -> ValueChange {
    ValueChange::Set { source, secret: Zeroizing::new(secret.to_vec()), base_mark: [mark; 32], owned: false }
}

fn value(v: &ValueChange) -> (ValueSource, Vec<u8>, [u8; 32], bool) {
    let ValueChange::Set { source, secret, base_mark, owned } = v else { panic!("the value was kept") };
    (*source, secret.to_vec(), *base_mark, *owned)
}

fn patch(id: &str, v: ValueChange) -> Patch {
    Patch {
        id: id.into(),
        cipher_id: None,
        organization_id: None,
        base_revision: "r".into(),
        set: vec![],
        remove: vec![],
        value: v,
    }
}

fn field(name: &str, value: &str) -> FieldSet {
    FieldSet { name: name.into(), value: Zeroizing::new(value.into()), hidden: false }
}

fn delete_op(id: &str) -> Op {
    Op::Delete { id: id.into(), base_revision: "r".into(), cipher_id: None, organization_id: None }
}

fn create_op(id: &str) -> Op {
    Op::Create(NewItem {
        id: id.into(),
        value: Zeroizing::new(b"v".to_vec()),
        name: "Note".into(),
        folder_id: None,
        tool_fields: vec![],
    })
}

fn push(queue: &mut Vec<Op>, op: Op, server: Option<(ValueSource, [u8; 32])>) {
    enqueue(queue, B, op, server);
}

fn ids(queue: &[Op]) -> Vec<String> {
    queue
        .iter()
        .map(|o| match o {
            Op::Create(i) => format!("create {}", i.id),
            Op::Patch(p) => format!("patch {}", p.id),
            Op::Delete { id, .. } => format!("delete {id}"),
        })
        .collect()
}

fn as_patch(op: &Op) -> &Patch {
    let Op::Patch(p) = op else { panic!("not a patch") };
    p
}

#[test]
fn queued_patches_of_one_item_merge_on_the_server_base() {
    let mut first = patch("a", set(ValueSource::LoginPassword, b"1", 1));
    first.base_revision = "r1".into();
    first.cipher_id = Some("c1".into());
    first.set = vec![field("bwss:label", "One"), field("bwss:collection", "work")];
    first.remove = vec!["bwss:content-type".into(), "bwss:collection".into()];
    let mut later = patch("a", set(ValueSource::Field, b"2", 2));
    later.base_revision = "r2".into();
    later.set = vec![field("bwss:label", "Two"), field("bwss:attr:k", "v")];
    later.remove = vec!["bwss:attr:".into(), "bwss:collection".into()];
    let mut queue = vec![Op::Patch(first), delete_op("other")];
    // The server still holds what the first change was based on.
    push(&mut queue, Op::Patch(later), Some((ValueSource::LoginPassword, [1; 32])));
    assert_eq!(ids(&queue), ["patch a", "delete other"]);
    let m = as_patch(&queue[0]);
    assert_eq!((m.base_revision.as_str(), m.cipher_id.as_deref()), ("r1", Some("c1")));
    // What the first change removes stays, unless the later one says otherwise.
    assert_eq!(m.remove, ["bwss:content-type", "bwss:attr:", "bwss:collection"]);
    let set_names: Vec<(&str, &str)> = m.set.iter().map(|f| (f.name.as_str(), f.value.as_str())).collect();
    assert_eq!(set_names, [("bwss:label", "Two"), ("bwss:attr:k", "v")]);
    assert_eq!(value(&m.value), (ValueSource::LoginPassword, b"2".to_vec(), [1; 32], false));
}

#[test]
fn a_later_attribute_removal_drops_earlier_attribute_sets() {
    let mut first = patch("a", ValueChange::Keep);
    first.set = vec![field("bwss:attr:k", "v"), field("bwss:label", "L")];
    first.remove = vec!["bwss:attr:j".into()];
    let mut later = patch("a", ValueChange::Keep);
    later.remove = vec!["bwss:attr:".into()];
    let mut queue = vec![Op::Patch(first)];
    push(&mut queue, Op::Patch(later), None);
    let m = as_patch(&queue[0]);
    assert_eq!(m.remove, ["bwss:attr:"]);
    assert_eq!(m.set.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["bwss:label"]);
}

#[test]
fn the_first_cipher_id_wins_and_a_missing_one_is_filled() {
    let mut later = patch("a", ValueChange::Keep);
    later.cipher_id = Some("c9".into());
    let mut queue = vec![Op::Patch(patch("a", ValueChange::Keep))];
    push(&mut queue, Op::Patch(later), None);
    assert_eq!(as_patch(&queue[0]).cipher_id.as_deref(), Some("c9"));
}

#[test]
fn a_patch_behind_a_delete_or_another_item_does_not_merge() {
    let mut queue = vec![delete_op("a")];
    push(&mut queue, Op::Patch(patch("a", ValueChange::Keep)), None);
    push(&mut queue, Op::Patch(patch("b", ValueChange::Keep)), None);
    assert_eq!(ids(&queue), ["delete a", "patch a", "patch b"]);
    // Only the last op of an item counts: a create is not a patch to fold into.
    let mut queue = vec![create_op("a")];
    push(&mut queue, Op::Patch(patch("a", ValueChange::Keep)), None);
    assert_eq!(ids(&queue), ["create a", "patch a"]);
}

#[test]
fn a_change_read_from_the_server_replaces_a_queued_one() {
    // Queued against M0; the server now holds M1 and the app wrote again from it.
    let mut queue = vec![Op::Patch(patch("a", set(ValueSource::LoginPassword, b"one", 0)))];
    let later = patch("a", set(ValueSource::LoginPassword, b"two", 1));
    push(&mut queue, Op::Patch(later), Some((ValueSource::LoginPassword, [1; 32])));
    assert_eq!(value(&as_patch(&queue[0]).value), (ValueSource::LoginPassword, b"two".to_vec(), [1; 32], false));
}

#[test]
fn text_after_a_queued_binary_write_goes_to_the_added_field() {
    // The binary write adds bwss:password, which the text was read from.
    let server = Some((ValueSource::LoginPassword, [0; 32]));
    let mut queue = vec![Op::Patch(patch("a", set(ValueSource::LoginPassword, &[0xff, 0], 0)))];
    push(&mut queue, Op::Patch(patch("a", set(ValueSource::Field, b"text", 7))), server);
    assert_eq!(value(&as_patch(&queue[0]).value), (ValueSource::LoginPassword, b"text".to_vec(), [0; 32], true));
    // A text write first: no field was added.
    let mut queue = vec![Op::Patch(patch("a", set(ValueSource::LoginPassword, b"t", 0)))];
    push(&mut queue, Op::Patch(patch("a", set(ValueSource::LoginPassword, b"u", 7))), server);
    assert!(!value(&as_patch(&queue[0]).value).3);
}

#[test]
fn a_later_write_with_nothing_to_set_keeps_the_queued_value() {
    let mut queue = vec![Op::Patch(patch("a", set(ValueSource::LoginPassword, b"one", 0)))];
    push(&mut queue, Op::Patch(patch("a", ValueChange::Keep)), Some((ValueSource::LoginPassword, [0; 32])));
    assert_eq!(value(&as_patch(&queue[0]).value), (ValueSource::LoginPassword, b"one".to_vec(), [0; 32], false));
}

#[test]
fn a_value_after_a_queued_change_without_one_is_the_value_to_send() {
    // Not the server's base (the first change was never shown), and no earlier value to build on.
    let mut queue = vec![Op::Patch(patch("a", ValueChange::Keep))];
    push(
        &mut queue,
        Op::Patch(patch("a", set(ValueSource::Field, b"two", 3))),
        Some((ValueSource::LoginPassword, [9; 32])),
    );
    assert_eq!(value(&as_patch(&queue[0]).value), (ValueSource::Field, b"two".to_vec(), [3; 32], false));
}

#[test]
fn a_delete_after_a_create_cancels_both() {
    let mut queue = vec![delete_op("a"), create_op("a"), create_op("b")];
    push(&mut queue, Op::Patch(patch("a", ValueChange::Keep)), None);
    push(&mut queue, delete_op("a"), None);
    // The earlier delete of a stays: it is a different item on the server.
    assert_eq!(ids(&queue), ["delete a", "create b"]);
    // A delete of something not created here is queued.
    push(&mut queue, delete_op("c"), None);
    assert_eq!(ids(&queue), ["delete a", "create b", "delete c"]);
}

#[test]
fn queue_round_trips_serde() {
    let mut p = patch("a", set(ValueSource::Field, b"s3cret", 4));
    p.cipher_id = Some("c1".into());
    p.set = vec![FieldSet { name: "bwss:password".into(), value: Zeroizing::new("hid".into()), hidden: true }];
    p.remove = vec!["bwss:attr:".into()];
    let queue = vec![create_op("n"), Op::Patch(p), delete_op("d")];
    let json = serde_json::to_string(&queue).unwrap();
    let back: Vec<Op> = serde_json::from_str(&json).unwrap();
    assert_eq!(ids(&back), ids(&queue));
    let Op::Create(item) = &back[0] else { panic!() };
    assert_eq!((&**item.value, item.name.as_str()), (&b"v"[..], "Note"));
    let m = as_patch(&back[1]);
    assert_eq!(value(&m.value), (ValueSource::Field, b"s3cret".to_vec(), [4; 32], false));
    assert_eq!((m.set[0].value.as_str(), m.set[0].hidden, m.cipher_id.as_deref()), ("hid", true, Some("c1")));
    let Op::Delete { id, base_revision, cipher_id, organization_id } = &back[2] else { panic!() };
    assert_eq!((id.as_str(), base_revision.as_str(), cipher_id, organization_id), ("d", "r", &None, &None));
    assert_eq!(serde_json::to_string(&back).unwrap(), json);
    // An op queued before the owner was recorded reads as personal.
    let old: Vec<Op> = serde_json::from_value(json!([
        { "Patch": { "id": "a", "cipher_id": "c1", "base_revision": "r", "set": [], "remove": [], "value": "Keep" } },
        { "Delete": { "id": "d", "base_revision": "r", "cipher_id": null } },
    ]))
    .unwrap();
    assert!(as_patch(&old[0]).organization_id.is_none());
    assert!(matches!(&old[1], Op::Delete { organization_id: None, .. }));
}

// ---- flush ----

const REV: &str = "2026-01-01T00:00:00Z";

impl Rig {
    fn flush(&mut self, queue: &mut Vec<Op>, ciphers: &[Value]) -> FlushReport {
        let sync = json!({ "ciphers": ciphers });
        block_on(flush(queue, &mut self.client, B, &self.keys, &self.rng, 1_000, &sync))
    }

    /// A tool item with `bwss:id` `id` and the server id `cid`.
    fn item(&self, cid: &str, id: &str, secret: &str) -> Value {
        let mut c = self.note(REV, &[("bwss:id", id, false), ("bwss:password", secret, true)]);
        c["id"] = json!(cid);
        c
    }

    /// A patch of `c` with a new label and, when `secret` is given, a new value.
    fn change(&self, c: &Value, secret: Option<&[u8]>) -> Op {
        let mut p = self.patch_for(c, secret.unwrap_or(b"unused"));
        if secret.is_none() {
            p.value = ValueChange::Keep;
        }
        p.cipher_id = c["id"].as_str().map(str::to_owned);
        Op::Patch(p)
    }
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

#[test]
fn flush_sends_every_op_in_order() {
    let mut r = Rig::new();
    let (c1, c2) = (r.item("c1", "x", "old"), r.item("c2", "z", "s"));
    let mut queue = vec![r.change(&c1, Some(b"new")), create_op("y"), delete_op("z")];
    queue[2] =
        Op::Delete { id: "z".into(), base_revision: REV.into(), cipher_id: Some("c2".into()), organization_id: None };
    r.fake.echo();
    r.fake.echo();
    r.fake.echo();
    r.fake.reply(200, json!({}));
    let report = r.flush(&mut queue, &[c1, c2]);
    assert_eq!(strs(&report.done), ["x", "y", "z"]);
    assert!(queue.is_empty() && report.kept.is_empty() && report.dropped.is_empty() && report.refused.is_empty());
    assert_eq!(r.log(), ["Put /ciphers/c1", "Post /ciphers", "Put /ciphers/c2", "Put /ciphers/c2/delete"]);
}

#[test]
fn transient_error_keeps_the_rest() {
    let mut r = Rig::new();
    let (c1, c2) = (r.item("c1", "x", "old"), r.item("c2", "z", "s"));
    let mut queue = vec![create_op("y"), r.change(&c1, None), r.change(&c2, None)];
    r.fake.echo();
    r.fake.reply(503, json!({ "message": "busy" }));
    let report = r.flush(&mut queue, &[c1, c2]);
    assert_eq!(strs(&report.done), ["y"]);
    assert_eq!(report.kept.iter().map(|(i, _)| i.as_str()).collect::<Vec<_>>(), ["x"]);
    assert!(!report.kept[0].1.is_empty());
    assert_eq!(ids(&queue), ["patch x", "patch z"]);
    assert_eq!(r.log(), ["Post /ciphers", "Put /ciphers/c1"]);
}

#[test]
fn gone_and_unmarked_are_dropped_and_the_flush_goes_on() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "x", "old");
    let unmarked = r.note(REV, &[("pin", "1", false)]);
    let mut missing = r.change(&c1, None);
    if let Op::Patch(p) = &mut missing {
        p.id = "nowhere".into();
        p.cipher_id = None;
    }
    // c1 is now a plain note on the server: x is gone.
    let mut queue = vec![missing, r.change(&c1, None), create_op("y")];
    r.fake.echo();
    let report = r.flush(&mut queue, &[unmarked]);
    assert_eq!(
        report.dropped.iter().map(|(i, e)| (i.as_str(), e)).collect::<Vec<_>>(),
        [("nowhere", &WriteError::Gone), ("x", &WriteError::Gone)]
    );
    assert_eq!(strs(&report.done), ["y"]);
    assert!(queue.is_empty());
    assert_eq!(r.log(), ["Post /ciphers"]);
}

#[test]
fn a_changed_secret_is_dropped_but_the_other_changes_go() {
    let mut r = Rig::new();
    let old = r.item("c1", "x", "old");
    let now = r.item("c1", "x", "someone else's");
    let mut queue = vec![r.change(&old, Some(b"new"))];
    r.fake.echo();
    let report = r.flush(&mut queue, std::slice::from_ref(&now));
    assert_eq!(report.dropped.len(), 1);
    assert!(matches!(report.dropped[0], (ref i, WriteError::SourceChanged) if i == "x"));
    assert_eq!(strs(&report.done), ["x"]);
    assert_eq!(r.log(), ["Put /ciphers/c1"]);

    // Nothing but the value: nothing is sent.
    let mut r = Rig::new();
    let mut op = r.change(&old, Some(b"new"));
    if let Op::Patch(p) = &mut op {
        p.set.clear();
    }
    let mut queue = vec![op];
    let report = r.flush(&mut queue, std::slice::from_ref(&now));
    assert!(queue.is_empty() && report.done.is_empty() && report.dropped.len() == 1);
    assert!(r.log().is_empty());
}

#[test]
fn a_refusal_is_reported_and_the_flush_goes_on() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "x", "old");
    let mut queue = vec![r.change(&c1, None), create_op("y")];
    r.fake.reply(400, json!({ "message": "bad" }));
    r.fake.echo();
    let report = r.flush(&mut queue, &[c1]);
    assert_eq!(report.refused.len(), 1);
    assert!(matches!(&report.refused[0], (i, ApiError::Http { status: 400, .. }) if i == "x"));
    assert_eq!(strs(&report.done), ["y"]);
    assert!(queue.is_empty());
}

#[test]
fn a_write_that_keeps_changing_or_cannot_be_read_stays_queued() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "x", "old");
    let mut queue = vec![r.change(&c1, None), create_op("y")];
    for _ in 0..crate::sync::ATTEMPTS {
        r.fake.out_of_date();
        r.fake.reply(200, r.item("c1", "x", "old"));
    }
    let report = r.flush(&mut queue, &[c1]);
    assert_eq!(report.kept.len(), 1);
    assert_eq!(ids(&queue), ["patch x", "create y"]);
    assert!(report.done.is_empty() && report.dropped.is_empty());

    // A copy that cannot be read now is held, not dropped.
    let mut r = Rig::new();
    let readable = r.item("c1", "x", "old");
    let unreadable = r.note_under(&r.other, REV, &[("bwss:id", "x", false)]);
    let mut queue = vec![r.change(&readable, None), create_op("y")];
    let report = r.flush(
        &mut queue,
        &[{
            let mut u = unreadable;
            u["id"] = json!("c1");
            u
        }],
    );
    assert_eq!(report.kept.len(), 1);
    assert_eq!(queue.len(), 2);
    assert!(r.log().is_empty());
}

#[test]
fn an_empty_patch_is_done_without_a_request() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "x", "old");
    let mut op = r.change(&c1, None);
    if let Op::Patch(p) = &mut op {
        p.set.clear();
    }
    let mut queue = vec![op];
    let report = r.flush(&mut queue, &[c1]);
    assert_eq!(strs(&report.done), ["x"]);
    assert!(r.log().is_empty());
}

#[test]
fn ops_find_their_cipher_by_marker_and_see_what_the_flush_created() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "x", "old");
    let mut by_marker = r.change(&c1, None);
    if let Op::Patch(p) = &mut by_marker {
        p.cipher_id = None;
    }
    let mut after_create = r.change(&c1, None);
    if let Op::Patch(p) = &mut after_create {
        p.id = "y".into();
        p.cipher_id = None;
    }
    let mut queue = vec![by_marker, create_op("y"), after_create, delete_op("gone")];
    r.fake.echo();
    r.fake.echo();
    r.fake.echo();
    let report = r.flush(&mut queue, &[c1]);
    assert_eq!(strs(&report.done), ["x", "y", "y", "gone"]);
    assert_eq!(r.log(), ["Put /ciphers/c1", "Post /ciphers", "Put /ciphers/created"]);
}

#[test]
fn a_cipher_without_an_id_is_gone() {
    let mut r = Rig::new();
    let mut c = r.item("c1", "x", "old");
    let op = r.change(&c, None);
    c.as_object_mut().unwrap().remove("id");
    let mut op = op;
    if let Op::Patch(p) = &mut op {
        p.cipher_id = None;
    }
    let mut queue = vec![op];
    let report = r.flush(&mut queue, &[c]);
    assert!(matches!(report.dropped[..], [(ref i, WriteError::Gone)] if i == "x"));
}

fn delete_of(cid: &str, id: &str) -> Op {
    Op::Delete { id: id.into(), base_revision: REV.into(), cipher_id: Some(cid.into()), organization_id: None }
}

#[test]
fn delete_outcomes_are_reported() {
    // Kept for the user's own content: done.
    let mut r = Rig::new();
    let mut foreign = r.note(REV, &[("bwss:id", "x", false), ("pin", "1", false)]);
    foreign["id"] = json!("c1");
    let mut queue = vec![delete_of("c1", "x")];
    r.fake.echo();
    assert_eq!(strs(&r.flush(&mut queue, &[foreign]).done), ["x"]);

    // Stripped, but the trash failed for good: reported, the flush goes on.
    let mut r = Rig::new();
    let (c1, c2) = (r.item("c1", "x", "s"), r.item("c2", "z", "s"));
    let mut queue = vec![delete_of("c1", "x"), delete_of("c2", "z")];
    r.fake.echo();
    r.fake.reply(403, json!({}));
    r.fake.echo();
    r.fake.reply(200, json!({}));
    let report = r.flush(&mut queue, &[c1.clone(), c2.clone()]);
    assert!(matches!(&report.refused[..], [(i, ApiError::Http { status: 403, .. })] if i == "x"));
    assert_eq!(strs(&report.done), ["z"]);
    assert!(queue.is_empty());

    // Stripped and the network is down: reported and the flush stops. Retrying could not trash it (it is no
    // longer the tool's), so the delete is not kept.
    let mut r = Rig::new();
    let mut queue = vec![delete_of("c1", "x"), delete_of("c2", "z")];
    r.fake.echo();
    r.fake.reply(503, json!({}));
    let report = r.flush(&mut queue, &[c1.clone(), c2]);
    assert!(matches!(&report.refused[..], [(i, ApiError::Http { status: 503, .. })] if i == "x"));
    assert_eq!(ids(&queue), ["delete z"]);

    // The reply cannot be read: the item stays stripped; reported as dropped.
    let mut r = Rig::new();
    let mut queue = vec![delete_of("c1", "x")];
    r.fake.reply(200, r.note_under(&r.other, REV, &[("bwss:id", "x", false)]));
    let report = r.flush(&mut queue, &[c1]);
    assert!(matches!(&report.dropped[..], [(i, WriteError::Crypto(_))] if i == "x"));

    // Not the tool's any more: nothing to do.
    let mut r = Rig::new();
    let mut queue = vec![delete_of("c1", "x")];
    let report = r.flush(&mut queue, &[r.note(REV, &[("pin", "1", false)])]);
    assert_eq!(strs(&report.done), ["x"]);
}

#[test]
fn a_delete_that_keeps_changing_stays_queued_and_a_failed_create_is_classified() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "x", "s");
    let mut queue = vec![delete_of("c1", "x")];
    for _ in 0..crate::sync::ATTEMPTS {
        r.fake.out_of_date();
        r.fake.reply(200, r.item("c1", "x", "s"));
    }
    assert_eq!(r.flush(&mut queue, &[c1]).kept.len(), 1);
    assert_eq!(queue.len(), 1);

    let mut r = Rig::new();
    let mut queue = vec![Op::Create(NewItem { value: Zeroizing::new(vec![b'a'; 20_000]), ..item_of("y") })];
    let report = r.flush(&mut queue, &[]);
    assert!(matches!(report.dropped[..], [(ref i, WriteError::TooLong)] if i == "y"));
}

fn item_of(id: &str) -> NewItem {
    let Op::Create(i) = create_op(id) else { unreachable!() };
    i
}

#[test]
fn merging_keeps_unrelated_fields_and_ownership() {
    let mut first = patch("a", set(ValueSource::LoginPassword, b"1", 0));
    first.set = vec![field("bwss:label", "L")];
    first.remove = vec!["bwss:note".into()];
    let mut later = patch("a", set(ValueSource::Field, b"2", 5));
    later.set = vec![field("bwss:other", "O")];
    // No attribute removal here, so the earlier fields stay.
    let mut queue = vec![Op::Patch(first)];
    push(&mut queue, Op::Patch(later), Some((ValueSource::LoginPassword, [0; 32])));
    let m = as_patch(&queue[0]);
    assert_eq!((m.set.len(), m.remove.len()), (2, 1));
    assert!(!value(&m.value).3);

    // Ownership of either change is kept.
    for (first_owned, later_owned) in [(true, false), (false, true)] {
        let owned = |secret: &[u8], owned| ValueChange::Set {
            source: ValueSource::LoginPassword,
            secret: Zeroizing::new(secret.to_vec()),
            base_mark: [0; 32],
            owned,
        };
        let mut queue = vec![Op::Patch(patch("a", owned(b"1", first_owned)))];
        push(&mut queue, Op::Patch(patch("a", owned(b"2", later_owned))), Some((ValueSource::Field, [9; 32])));
        assert!(value(&as_patch(&queue[0]).value).3);
    }
}

#[test]
fn a_value_conflict_keeps_the_removals_and_skips_trashed_and_other_items_by_marker() {
    let mut r = Rig::new();
    let old = r.item("c1", "x", "old");
    let now = r.item("c1", "x", "someone else's");
    let mut op = r.change(&old, Some(b"new"));
    if let Op::Patch(p) = &mut op {
        p.set.clear();
        p.remove = vec!["bwss:label".into()];
        p.cipher_id = None;
    }
    // A trashed copy of the item and another item come first; only the live one with the marker counts.
    let mut trashed = r.item("c0", "x", "old");
    trashed["deletedDate"] = json!("2026-02-02T00:00:00Z");
    let other = r.item("c2", "z", "s");
    let mut queue = vec![op];
    r.fake.echo();
    let report = r.flush(&mut queue, &[trashed, other, now]);
    assert_eq!((report.dropped.len(), strs(&report.done)), (1, vec!["x"]));
    assert_eq!(r.log(), ["Put /ciphers/c1"]);
}

#[test]
fn an_expired_session_keeps_the_whole_queue() {
    let mut r = Rig::new();
    let (c1, c2) = (r.item("c1", "x", "old"), r.item("c2", "z", "s"));
    let mut queue = vec![r.change(&c1, None), r.change(&c2, None)];
    r.fake.reply(401, json!({}));
    let report = r.flush(&mut queue, &[c1, c2]);
    assert!(report.refused.is_empty() && report.dropped.is_empty() && report.done.is_empty());
    assert_eq!(report.kept.len(), 1);
    assert_eq!(queue.len(), 2);
    assert_eq!(r.log(), ["Put /ciphers/c1"]);
    assert!(matches!(classify(SyncWriteError::Api(ApiError::NotLoggedIn)), Step::Keep(_)));
}

#[test]
fn errors_that_may_pass_keep_the_op() {
    use crate::crypto::CryptoError;
    assert!(matches!(classify(SyncWriteError::Write(WriteError::Crypto(CryptoError::BadMac))), Step::Keep(_)));
    assert!(matches!(classify(SyncWriteError::Write(WriteError::BadClock)), Step::Keep(_)));
    assert!(matches!(classify(SyncWriteError::Write(WriteError::TooLong)), Step::Drop(_)));
    // The item changed owner under the write: kept, and re-read on the next flush.
    assert!(matches!(classify(SyncWriteError::OwnerChanged), Step::Keep(_)));
}

#[test]
fn a_delete_of_a_re_marked_cipher_sends_nothing() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "b", "s");
    let mut queue = vec![delete_of("c1", "x")];
    let report = r.flush(&mut queue, &[c1]);
    assert_eq!(strs(&report.done), ["x"]);
    assert!(r.log().is_empty() && queue.is_empty());
}

#[test]
fn an_empty_patch_leaves_the_cipher_for_the_next_op() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "x", "s");
    let mut empty = r.change(&c1, None);
    if let Op::Patch(p) = &mut empty {
        p.set.clear();
        p.cipher_id = None;
    }
    let mut later = r.change(&c1, None);
    if let Op::Patch(p) = &mut later {
        p.cipher_id = None;
    }
    let mut queue = vec![empty, later, delete_op("x")];
    r.fake.echo();
    r.fake.echo();
    r.fake.reply(200, json!({}));
    let report = r.flush(&mut queue, &[c1]);
    assert_eq!(strs(&report.done), ["x", "x", "x"]);
    assert_eq!(r.log(), ["Put /ciphers/c1", "Put /ciphers/c1", "Put /ciphers/c1/delete"]);
}

#[test]
fn an_unreadable_target_is_held_not_gone() {
    let mut r = Rig::new();
    let c1 = r.item("c1", "x", "s");
    let mut unreadable = r.note_under(&r.other, REV, &[("bwss:id", "x", false)]);
    unreadable["id"] = json!("c9");
    let mut by_marker = r.change(&c1, None);
    if let Op::Patch(p) = &mut by_marker {
        p.cipher_id = None;
    }
    for op in [by_marker, delete_op("x")] {
        let mut queue = vec![op, create_op("y")];
        let report = r.flush(&mut queue, std::slice::from_ref(&unreadable));
        assert_eq!((report.kept.len(), queue.len()), (1, 2));
        assert!(report.dropped.is_empty() && report.done.is_empty());
    }
    // Without a cipher id naming it, an organization cipher we cannot read is not ours to hold for: the target is
    // gone (`an_organization_target_named_by_its_cipher_id_is_held` covers the hinted case).
    let mut org = unreadable.clone();
    org["organizationId"] = json!("o1");
    let mut queue = vec![delete_op("x")];
    assert_eq!(strs(&r.flush(&mut queue, &[org]).done), ["x"]);
}

#[test]
fn an_organization_target_named_by_its_cipher_id_is_held() {
    // The op was read from organization cipher c9, whose key failed this unlock: held, as the engine holds it.
    let mut r = Rig::new();
    let mut unreadable = r.note_under(&r.other, REV, &[("bwss:id", "x", false)]);
    unreadable["id"] = json!("c9");
    unreadable["organizationId"] = json!("o1");
    let was = r.item("c9", "x", "old");
    for op in [r.change(&was, Some(b"new")), delete_of("c9", "x")] {
        let mut queue = vec![op];
        let report = r.flush(&mut queue, std::slice::from_ref(&unreadable));
        assert_eq!((report.kept.len(), queue.len()), (1, 1));
        assert!(report.done.is_empty() && report.dropped.is_empty() && report.refused.is_empty());
    }
    assert!(r.log().is_empty());
}

#[test]
fn an_item_that_moved_into_an_organization_since_queued_is_kept_unsent() {
    // Queued against personal c1; c1 is now in org-a, which this account can read and write.
    let mut r = Rig::new();
    let was = r.item("c1", "x", "old");
    let org = SymmetricKey::generate(&r.rng).unwrap();
    let mut now = r.note_under(&org, REV, &[("bwss:id", "x", false), ("bwss:password", "old", true)]);
    now["organizationId"] = json!("org-a");
    r.keys.orgs.insert("org-a".into(), org);
    for op in [r.change(&was, Some(b"new")), delete_of("c1", "x")] {
        let mut queue = vec![op];
        r.fake.echo();
        r.fake.reply(200, json!({}));
        let report = r.flush(&mut queue, std::slice::from_ref(&now));
        assert_eq!((report.kept.len(), queue.len()), (1, 1), "{:?}", report.kept);
        assert!(report.done.is_empty() && report.dropped.is_empty() && report.refused.is_empty());
        assert!(r.log().is_empty(), "{:?}", r.log());
        r.fake.replies.borrow_mut().clear();
    }
}

#[test]
fn a_create_whose_item_is_already_there_is_not_sent_twice() {
    let mut r = Rig::new();
    let there = r.item("c5", "y", "s");
    let mut queue = vec![create_op("y")];
    let report = r.flush(&mut queue, &[there]);
    assert_eq!(strs(&report.done), ["y"]);
    assert!(r.log().is_empty() && queue.is_empty());
}

#[test]
fn a_queued_item_is_found_by_marker_before_its_cipher_id() {
    // Cipher "a" now carries another marker; the item x lives on "b".
    let mut r = Rig::new();
    let a = r.item("a", "q", "s");
    let b = r.item("b", "x", "old");
    let was = r.item("a", "x", "old");
    let mut queue = vec![r.change(&was, Some(b"new"))];
    r.fake.echo();
    let report = r.flush(&mut queue, &[a.clone(), b.clone()]);
    assert_eq!(strs(&report.done), ["x"]);
    assert_eq!(r.log(), ["Put /ciphers/b"]);

    let mut r = Rig::new();
    let mut queue = vec![delete_of("a", "x")];
    r.fake.echo();
    r.fake.reply(200, json!({}));
    let report = r.flush(&mut queue, &[a, b]);
    assert_eq!(strs(&report.done), ["x"]);
    assert_eq!(r.log(), ["Put /ciphers/b", "Put /ciphers/b/delete"]);
}

#[test]
fn the_cipher_id_only_hints_at_a_held_target() {
    let mut r = Rig::new();
    let mut unreadable = r.note_under(&r.other, REV, &[("bwss:id", "x", false)]);
    unreadable["id"] = json!("a");
    let was = r.item("a", "x", "old");
    for op in [r.change(&was, None), delete_of("a", "x")] {
        let mut queue = vec![op];
        let report = r.flush(&mut queue, std::slice::from_ref(&unreadable));
        assert_eq!((report.kept.len(), queue.len()), (1, 1));
    }
    // Another cipher that cannot be read is not the hinted one: the target is gone.
    let mut queue = vec![r.change(&was, None), delete_of("a", "x")];
    let report = r.flush(
        &mut queue,
        &[{
            let mut u = unreadable.clone();
            u["id"] = json!("c9");
            u
        }],
    );
    assert!(matches!(report.dropped[..], [(ref i, WriteError::Gone)] if i == "x"));
    assert_eq!(strs(&report.done), ["x"]);
}

#[test]
fn queued_items_follow_the_duplicate_winner() {
    let r = Rig::new();
    let dated = |cid: &str, date: &str| {
        let mut c = r.item(cid, "x", "old");
        c["creationDate"] = json!(date);
        c
    };
    // The oldest dated copy wins whatever the list order; undated ones tie on the lowest cipher id.
    let sets = [
        (vec![dated("c1", "2026-02-01T00:00:00Z"), dated("c2", "2026-01-01T00:00:00Z")], "c2"),
        (vec![dated("c2", "2026-01-01T00:00:00Z"), dated("c1", "2026-02-01T00:00:00Z")], "c2"),
        (vec![r.item("c5", "x", "old"), r.item("c3", "x", "old")], "c3"),
        (vec![r.item("c3", "x", "old"), r.item("c5", "x", "old")], "c3"),
    ];
    for (ciphers, winner) in sets {
        let mut r = Rig::new();
        let mut op = r.change(&ciphers[0], None);
        if let Op::Patch(p) = &mut op {
            p.cipher_id = None;
        }
        let mut queue = vec![op];
        r.fake.echo();
        assert_eq!(strs(&r.flush(&mut queue, &ciphers).done), ["x"]);
        assert_eq!(r.log(), [format!("Put /ciphers/{winner}")]);

        let mut r = Rig::new();
        let mut queue = vec![delete_op("x")];
        r.fake.echo();
        r.fake.reply(200, json!({}));
        assert_eq!(strs(&r.flush(&mut queue, &ciphers).done), ["x"]);
        assert_eq!(r.log(), [format!("Put /ciphers/{winner}"), format!("Put /ciphers/{winner}/delete")]);
    }
}
