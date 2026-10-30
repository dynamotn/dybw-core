//! The three-way planner: remote (Bitwarden), local (the tool's store) and base (both after the last sync).
//! Pure: no I/O, ids sorted. A line-by-line port of the plugin's `plan.ts`.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseEntry {
    pub cipher_id: String,
    pub revision_date: String,
    /// Keyed fingerprint of the value at the last sync, never the value itself.
    pub fingerprint: String,
    /// Scope of the item, so a re-upload keeps it (`global` when absent).
    pub scope: Option<String>,
    /// Organization items only: the user agreed to send this device's values to the item.
    pub push_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub id: String,
    pub cipher_id: String,
    pub revision_date: String,
    pub fingerprint: String,
    /// Members of an organization (and a hostile server) can create items.
    pub organization: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    BothChanged,
    LocalUnsynced,
    DeletedRemotely,
    OrganizationClaim,
    OrganizationPush,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Pull(String),
    /// `confirmed`: the user just agreed to this first push to an organization item.
    Push {
        id: String,
        confirmed: bool,
    },
    Create(String),
    Adopt(String),
    ClearLocal(String),
    Forget(String),
    Conflict {
        id: String,
        kind: ConflictKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Ask,
    PreferRemote,
    PreferLocal,
}

/// A decision about one conflict; ignored if the conflict has since changed kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConflictOverride {
    pub policy: Policy,
    pub kind: ConflictKind,
}

pub struct PlanInput<'a> {
    pub remote: &'a BTreeMap<String, RemoteEntry>,
    pub base: &'a BTreeMap<String, BaseEntry>,
    /// The fingerprint of the local value, `None` when it does not exist on this device.
    pub local: &'a dyn Fn(&str) -> Option<String>,
    /// Secrets the user asked to upload that have no item yet.
    pub pending_creates: &'a BTreeSet<String>,
    pub policy: Policy,
    pub overrides: &'a BTreeMap<String, ConflictOverride>,
}

/// An organization item's members see whatever is pushed to it, and anyone among them may have planted it:
/// the first push to it is always asked.
fn push(input: &PlanInput, id: &str) -> Action {
    let org = input.remote.get(id).is_some_and(|r| r.organization);
    if org && !input.base.get(id).is_some_and(|b| b.push_confirmed) {
        return resolve(input, id, ConflictKind::OrganizationPush);
    }
    Action::Push { id: id.into(), confirmed: false }
}

fn resolve(input: &PlanInput, id: &str, kind: ConflictKind) -> Action {
    use ConflictKind::{DeletedRemotely, LocalUnsynced, OrganizationClaim, OrganizationPush};
    // A never-synced local value may belong to someone else, and an organization item new to this id may have
    // been planted by anyone in it: only an explicit decision overwrites either side.
    let fallback = match kind {
        LocalUnsynced | OrganizationClaim | OrganizationPush => Policy::Ask,
        _ => input.policy,
    };
    let policy = input.overrides.get(id).filter(|o| o.kind == kind).map_or(fallback, |o| o.policy);
    let id_s = id.to_string();
    match policy {
        Policy::PreferRemote if kind == DeletedRemotely => Action::ClearLocal(id_s),
        Policy::PreferRemote => Action::Pull(id_s),
        // Keeping the local value next to a claiming organization item uploads it as a new personal item.
        Policy::PreferLocal if matches!(kind, DeletedRemotely | OrganizationClaim) => Action::Create(id_s),
        Policy::PreferLocal if kind == OrganizationPush => Action::Push { id: id_s, confirmed: true },
        Policy::PreferLocal => push(input, id),
        Policy::Ask => Action::Conflict { id: id_s, kind },
    }
}

pub fn plan_sync(input: &PlanInput) -> Vec<Action> {
    use ConflictKind::{BothChanged, DeletedRemotely, LocalUnsynced, OrganizationClaim};
    let mut actions = Vec::new();
    let ids: BTreeSet<&String> =
        input.remote.keys().chain(input.base.keys()).chain(input.pending_creates.iter()).collect();
    for id in ids {
        let (r, b, l) = (input.remote.get(id), input.base.get(id), (input.local)(id));
        let id_s = || id.clone();
        // An organization item other than the one this id was synced with: taking it binds the id, so later
        // local edits would go to its members. Only an empty, never-synced id takes it without asking.
        let claimed = r.is_some_and(|r| r.organization && Some(&r.cipher_id) != b.map(|b| &b.cipher_id));
        if claimed && (b.is_some() || l.is_some()) {
            actions.push(resolve(input, id, OrganizationClaim));
            continue;
        }
        match (r, b) {
            (Some(r), None) => actions.push(match &l {
                None => Action::Pull(id_s()),
                Some(l) if *l == r.fingerprint => Action::Adopt(id_s()),
                Some(_) if input.pending_creates.contains(id) => resolve(input, id, BothChanged),
                Some(_) => resolve(input, id, LocalUnsynced),
            }),
            (Some(r), Some(b)) => {
                // Values, not just revisions: edits to the name or folder bump the revision, not the secret.
                let remote_changed = r.cipher_id != b.cipher_id || r.fingerprint != b.fingerprint;
                let remote_touched = remote_changed || r.revision_date != b.revision_date;
                // A secret missing on this device is restored, never treated as a deletion.
                let Some(l) = l else {
                    actions.push(Action::Pull(id_s()));
                    continue;
                };
                let local_changed = l != b.fingerprint;
                match (remote_changed, local_changed) {
                    (false, false) if remote_touched => actions.push(Action::Adopt(id_s())),
                    (false, false) => {}
                    (true, false) => actions.push(Action::Pull(id_s())),
                    (false, true) => actions.push(push(input, id)),
                    (true, true) if l == r.fingerprint => actions.push(Action::Adopt(id_s())),
                    (true, true) => actions.push(resolve(input, id, BothChanged)),
                }
            }
            (None, Some(b)) => actions.push(match &l {
                None => Action::Forget(id_s()),
                Some(l) if *l == b.fingerprint => Action::ClearLocal(id_s()),
                Some(_) => resolve(input, id, DeletedRemotely),
            }),
            // Only in `ids` because the user asked to upload it: nothing else ever creates an item.
            (None, None) => actions.push(if l.is_none() { Action::Forget(id_s()) } else { Action::Create(id_s()) }),
        }
    }
    actions
}
