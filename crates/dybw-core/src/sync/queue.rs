//! The offline write queue: port of bwss `Op`, `push_op` and `merge_patches` (`src/backend/runner.rs`) and the
//! flush loop, without the sealed file (M4) and the registry and ACL ops (M4).

use super::write::{DeleteOutcome, SyncWriteError, create, delete, update};
use crate::api::{ApiError, Client};
use crate::ports::{Clock, Http, Random};
use crate::vault::scan::{MarkedItem, Scan, ValueSource, duplicate_order, scan, trashed};
use crate::vault::write::{FieldSet, NewItem, Patch, ValueChange, WriteError};
use crate::vault::{Keys, Namespace, Organizations};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One queued write. Secrets inside are `Zeroizing`, so they are wiped when the op is dropped.
#[derive(Clone, Serialize, Deserialize)]
pub enum Op {
    Create(NewItem),
    Patch(Patch),
    /// `cipher_id` is the cipher the delete was read from, when known.
    Delete {
        id: String,
        base_revision: String,
        cipher_id: Option<String>,
    },
}

/// What a flush did, by `{ns}:id`. An op ends in one list, except a patch whose value was dropped as changed
/// elsewhere: it is in `dropped` and, when its other changes went through, also in `done`. A delete that stripped
/// the item but could not trash it (`refused`) or whose reply could not be read (`dropped`) is not counted done,
/// which is stricter than bwss.
#[derive(Debug, Default)]
pub struct FlushReport {
    /// Sent and accepted, or nothing left to send (an empty patch, a delete of what is no longer the tool's).
    pub done: Vec<String>,
    /// Still queued, with why: the flush stopped at the first of these. Not sent because the server or network
    /// is unavailable or the session expired (401), the item keeps changing, or its copy cannot be read now.
    pub kept: Vec<(String, String)>,
    /// Removed without being sent (or without finishing): `Gone`, `Unmarked`, `SourceChanged`, size and other
    /// write errors, and a delete whose reply could not be read (`Unreadable`: the item stays stripped).
    pub dropped: Vec<(String, WriteError)>,
    /// Removed after the server refused it for good, or after a delete stripped the item but could not trash it
    /// (retrying cannot trash it: it is no longer the tool's, so the delete is not kept). A transient cause
    /// of the latter also stops the flush. The user must hear about these.
    pub refused: Vec<(String, ApiError)>,
}

fn target(op: &Op) -> &str {
    match op {
        Op::Create(i) => &i.id,
        Op::Patch(p) => &p.id,
        Op::Delete { id, .. } => id,
    }
}

/// One patch with the changes of `first` and then `later`, for the same item. `server` is the cached server copy's
/// base: a later value change read from it (the first one could not be shown, for example because the value
/// changed elsewhere) replaces the first one; a later change read from the first one's result keeps the first
/// one's base, so the value check still compares against what the server holds. bwss's `acl_add` is M4.
fn merge_patches(first: &Patch, mut later: Patch, ns: &Namespace, server: Option<(ValueSource, [u8; 32])>) -> Patch {
    let attr = ns.field("attr:");
    let replaces_attributes = later.remove.contains(&attr);
    let touched = |name: &str| {
        (replaces_attributes && name.starts_with(&attr))
            || later.set.iter().any(|f| f.name == name)
            || later.remove.iter().any(|n| n == name)
    };
    let mut remove: Vec<String> = first.remove.iter().filter(|n| !touched(n)).cloned().collect();
    let mut set: Vec<FieldSet> = first.set.iter().filter(|f| !touched(&f.name)).cloned().collect();
    remove.append(&mut later.remove);
    set.append(&mut later.set);
    let value = merged_value(&first.value, later.value, server);
    Patch {
        id: first.id.clone(),
        cipher_id: first.cipher_id.clone().or(later.cipher_id),
        base_revision: first.base_revision.clone(),
        set,
        remove,
        value,
    }
}

fn merged_value(first: &ValueChange, later: ValueChange, server: Option<(ValueSource, [u8; 32])>) -> ValueChange {
    let ValueChange::Set { source: later_source, secret, base_mark: later_mark, owned: later_owned } = later else {
        return first.clone();
    };
    let (source, base_mark, owned) = match first {
        ValueChange::Set { source, base_mark, secret: first_secret, owned }
            if server != Some((later_source, later_mark)) =>
        {
            // A binary first change to a value the user owns adds `{ns}:password` (§5.2): the later change was read
            // from that field and must go there, never into the user's value.
            let added_field = matches!(source, ValueSource::LoginPassword | ValueSource::NoteBody)
                && std::str::from_utf8(first_secret).is_err();
            (*source, *base_mark, *owned || later_owned || added_field)
        }
        _ => (later_source, later_mark, later_owned),
    };
    ValueChange::Set { source, secret, base_mark, owned }
}

/// Queues `op`. A patch for an item whose last queued op is a patch merges into it: two queued patches of one
/// value could not both pass the value check, since the first changes what the second was read from. `server` is
/// the base of the cached server copy of the patched item. A delete of an item whose create is still queued
/// cancels the create and everything queued for the item since: it never reached the server.
pub fn enqueue(queue: &mut Vec<Op>, ns: &Namespace, op: Op, server: Option<(ValueSource, [u8; 32])>) {
    let id = target(&op).to_owned();
    match op {
        Op::Patch(later) => {
            let last = queue.iter().rposition(|o| target(o) == id);
            if let Some(Op::Patch(first)) = last.and_then(|i| queue.get_mut(i)) {
                *first = merge_patches(first, later, ns, server);
            } else {
                queue.push(Op::Patch(later));
            }
        }
        other => {
            let created = queue.iter().rposition(|o| matches!(o, Op::Create(i) if i.id == id));
            match created {
                Some(pos) if matches!(other, Op::Delete { .. }) => {
                    let mut n = 0;
                    queue.retain(|o| {
                        n += 1;
                        n <= pos || target(o) != id
                    });
                }
                _ => queue.push(other),
            }
        }
    }
}

/// How one op ended.
pub(super) enum Step {
    Done,
    Drop(WriteError),
    /// Only the value changed elsewhere: the other changes of the patch still go.
    DropValue,
    Refuse(ApiError),
    Keep(String),
}

/// Errors that pass with time or a new login (bwss `api_failure` treats 401 as transient): the op waits.
fn waits(e: &ApiError) -> bool {
    e.is_transient() || matches!(e, ApiError::NotLoggedIn | ApiError::Http { status: 401, .. })
}

pub(super) fn classify(e: SyncWriteError) -> Step {
    match e {
        // May pass (a copy that cannot be read now, bwss `Wait`): the change must not be lost.
        SyncWriteError::Write(e @ (WriteError::Uninspectable(_) | WriteError::Crypto(_) | WriteError::BadClock)) => {
            Step::Keep(e.to_string())
        }
        SyncWriteError::Write(WriteError::SourceChanged) => Step::DropValue,
        SyncWriteError::Write(e) => Step::Drop(e),
        SyncWriteError::Api(e) if waits(&e) => Step::Keep(e.to_string()),
        SyncWriteError::Api(e) => Step::Refuse(e),
        SyncWriteError::StillChanging => Step::Keep(e.to_string()),
        // A cipher without an id cannot be addressed, so for the queue it is gone.
        SyncWriteError::MissingId => Step::Drop(WriteError::Gone),
    }
}

/// Where an op's target is.
enum Lookup {
    Found(Value),
    /// Not found, but a live personal cipher that cannot be read now might be it (bwss `Held`).
    Held,
    Missing,
}

/// The copy of the item the op is for: the live cipher carrying its marker, whatever its cipher id (bwss `locate`).
/// Only when none does, `cipher_id` is a hint: a live personal cipher with that id that cannot be read now might
/// be the item, so the op is held; every other case is a target that is gone. With no hint, any such cipher holds it.
fn find(ciphers: &[Value], ns: &Namespace, keys: &Keys, id: &str, cipher_id: Option<&str>) -> Lookup {
    let mut held = false;
    let mut winner: Option<Box<MarkedItem>> = None;
    for c in ciphers.iter().filter(|c| !trashed(c)) {
        match scan(c, ns, keys, &Organizations::All) {
            // With duplicates the §7 winner is the item, as in the scan.
            Scan::Marked(m) if m.id == id => {
                if winner.as_ref().is_none_or(|w| duplicate_order(&m, w).is_lt()) {
                    winner = Some(m);
                }
            }
            Scan::Uninspectable(_) if c.get("organizationId").is_none_or(Value::is_null) => {
                held |= cipher_id.is_none_or(|cid| server_id(c) == cid);
            }
            _ => {}
        }
    }
    match winner {
        Some(w) => Lookup::Found(w.cipher),
        None if held => Lookup::Held,
        None => Lookup::Missing,
    }
}

fn server_id(cipher: &Value) -> &str {
    cipher.get("id").and_then(Value::as_str).unwrap_or_default()
}

const HELD: &str = "the item cannot be read now";

async fn run<H: Http, C: Clock>(
    op: &Op,
    client: &mut Client<H, C>,
    ns: &Namespace,
    keys: &Keys,
    rng: &impl Random,
    now_ms: i64,
    ciphers: &mut Vec<Value>,
) -> Step {
    match op {
        Op::Create(item) => {
            // Never twice: a create whose reply was lost has left its item in the list (bwss `run_create`).
            if matches!(find(ciphers, ns, keys, &item.id, None), Lookup::Found(_)) {
                return Step::Done;
            }
            match create(client, ns, keys, rng, item).await {
                Ok(reply) => {
                    ciphers.push(reply);
                    Step::Done
                }
                Err(e) => classify(e),
            }
        }
        Op::Patch(p) => {
            let cipher = match find(ciphers, ns, keys, &p.id, p.cipher_id.as_deref()) {
                Lookup::Found(c) => c,
                Lookup::Held => return Step::Keep(HELD.into()),
                Lookup::Missing => return Step::Drop(WriteError::Gone),
            };
            match update(client, ns, keys, rng, now_ms, &cipher, p).await {
                Ok(reply) => {
                    // The next op for this item reads the server's answer, not the snapshot.
                    if let Some(reply) = reply {
                        ciphers.retain(|c| server_id(c) != server_id(&cipher));
                        ciphers.push(reply);
                    }
                    Step::Done
                }
                Err(e) => classify(e),
            }
        }
        Op::Delete { id, cipher_id, .. } => {
            let cipher = match find(ciphers, ns, keys, id, cipher_id.as_deref()) {
                Lookup::Found(c) => c,
                Lookup::Held => return Step::Keep(HELD.into()),
                Lookup::Missing => return Step::Done,
            };
            match delete(client, ns, keys, rng, &cipher, id).await {
                Ok(outcome) => {
                    ciphers.retain(|c| server_id(c) != server_id(&cipher));
                    match outcome {
                        DeleteOutcome::Trashed | DeleteOutcome::KeptForeign | DeleteOutcome::Nothing => Step::Done,
                        DeleteOutcome::Stripped { trash } => Step::Refuse(trash),
                        DeleteOutcome::Unreadable(e) => Step::Drop(e),
                    }
                }
                Err(e) => classify(e),
            }
        }
    }
}

/// Sends the queued ops in order against `sync` (the `/sync` reply the ops were made from; later ops see the
/// replies of earlier ones). A transient failure, an item that keeps changing and a copy that cannot be read keep
/// the op and stop the flush; everything else removes the op and goes on, and says so in the report.
/// `Gone` and `Unmarked` drop an op (the item left the tool); `SourceChanged` drops the value
/// and sends the patch's other changes (bwss). The caller saves the queue afterwards.
pub async fn flush<H: Http, C: Clock>(
    queue: &mut Vec<Op>,
    client: &mut Client<H, C>,
    ns: &Namespace,
    keys: &Keys,
    rng: &impl Random,
    now_ms: i64,
    sync: &Value,
) -> FlushReport {
    let mut report = FlushReport::default();
    let mut ciphers = sync.get("ciphers").and_then(Value::as_array).cloned().unwrap_or_default();
    while let Some(op) = queue.first() {
        let id = target(op).to_owned();
        match run(op, client, ns, keys, rng, now_ms, &mut ciphers).await {
            Step::Done => report.done.push(id),
            Step::Drop(e) => report.dropped.push((id, e)),
            Step::DropValue => {
                report.dropped.push((id, WriteError::SourceChanged));
                match queue.first_mut() {
                    Some(Op::Patch(p)) if !(p.set.is_empty() && p.remove.is_empty()) => {
                        p.value = ValueChange::Keep;
                        continue;
                    }
                    _ => {}
                }
            }
            Step::Refuse(e) => {
                let stop = waits(&e);
                report.refused.push((id, e));
                if stop {
                    queue.remove(0);
                    break;
                }
            }
            Step::Keep(why) => {
                report.kept.push((id, why));
                break;
            }
        }
        queue.remove(0);
    }
    report
}
