//! The plugin's `plan.test.ts`, case by case.

use super::*;
use ConflictKind::{BothChanged, DeletedRemotely, LocalUnsynced, OrganizationClaim, OrganizationPush};
use std::collections::{BTreeMap, BTreeSet};

fn r(id: &str, rev: &str, fp: &str) -> RemoteEntry {
    ro(id, rev, fp, &format!("c-{id}"), false)
}

fn ro(id: &str, rev: &str, fp: &str, cipher_id: &str, organization: bool) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        cipher_id: cipher_id.into(),
        revision_date: rev.into(),
        fingerprint: fp.into(),
        organization,
    }
}

fn b(id: &str, rev: &str, fp: &str) -> (String, BaseEntry) {
    bc(id, rev, fp, &format!("c-{id}"))
}

fn bc(id: &str, rev: &str, fp: &str, cipher_id: &str) -> (String, BaseEntry) {
    let e = BaseEntry {
        cipher_id: cipher_id.into(),
        revision_date: rev.into(),
        fingerprint: fp.into(),
        scope: None,
        push_confirmed: false,
    };
    (id.into(), e)
}

#[derive(Default)]
struct Case {
    remote: Vec<RemoteEntry>,
    base: Vec<(String, BaseEntry)>,
    local: Vec<(&'static str, &'static str)>,
    pending: Vec<&'static str>,
    policy: Option<Policy>,
    overrides: Vec<(&'static str, ConflictOverride)>,
}

impl Case {
    fn plan(&self) -> Vec<Action> {
        let remote: BTreeMap<_, _> = self.remote.iter().map(|e| (e.id.clone(), e.clone())).collect();
        let base: BTreeMap<_, _> = self.base.iter().cloned().collect();
        let pending: BTreeSet<_> = self.pending.iter().map(|s| s.to_string()).collect();
        let overrides: BTreeMap<_, _> = self.overrides.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        let local = |id: &str| self.local.iter().find(|(k, _)| *k == id).map(|(_, v)| v.to_string());
        plan_sync(&PlanInput {
            remote: &remote,
            base: &base,
            local: &local,
            pending_creates: &pending,
            policy: self.policy.unwrap_or(Policy::Ask),
            overrides: &overrides,
        })
    }
}

fn pull(id: &str) -> Action {
    Action::Pull(id.into())
}
fn adopt(id: &str) -> Action {
    Action::Adopt(id.into())
}
fn push(id: &str) -> Action {
    Action::Push { id: id.into(), confirmed: false }
}
fn confirmed_push(id: &str) -> Action {
    Action::Push { id: id.into(), confirmed: true }
}
fn conflict(id: &str, kind: ConflictKind) -> Action {
    Action::Conflict { id: id.into(), kind }
}
fn create(id: &str) -> Action {
    Action::Create(id.into())
}

#[test]
fn pulls_a_new_remote_secret_onto_a_fresh_device() {
    assert_eq!(Case { remote: vec![r("a", "1", "x")], ..Default::default() }.plan(), [pull("a")]);
}

#[test]
fn adopts_a_remote_secret_whose_value_already_matches_locally() {
    let c = Case { remote: vec![r("a", "1", "x")], local: vec![("a", "x")], ..Default::default() };
    assert_eq!(c.plan(), [adopt("a")]);
}

#[test]
fn does_nothing_when_neither_side_changed() {
    let c = Case {
        remote: vec![r("a", "1", "x")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "x")],
        ..Default::default()
    };
    assert_eq!(c.plan(), []);
}

#[test]
fn pulls_remote_edits_and_pushes_local_edits() {
    let c = Case {
        remote: vec![r("a", "2", "y")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "x")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [pull("a")]);
    let c = Case {
        remote: vec![r("a", "1", "x")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "z")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [push("a")]);
}

#[test]
fn only_refreshes_the_base_when_the_item_changed_but_the_value_did_not() {
    let c = Case {
        remote: vec![r("a", "2", "x")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "x")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [adopt("a")]);
    let c = Case {
        remote: vec![r("a", "2", "x")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "z")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [push("a")]);
}

#[test]
fn treats_a_replaced_item_as_a_remote_change() {
    let c = Case {
        remote: vec![ro("a", "1", "x", "new", false)],
        base: vec![bc("a", "1", "x", "old")],
        local: vec![("a", "x")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [pull("a")]);
}

#[test]
fn restores_a_secret_missing_on_this_device_instead_of_deleting_it_remotely() {
    let c = Case { remote: vec![r("a", "1", "x")], base: vec![b("a", "1", "x")], ..Default::default() };
    assert_eq!(c.plan(), [pull("a")]);
}

#[test]
fn detects_both_changed_and_converges_when_both_made_the_same_edit() {
    let c = Case {
        remote: vec![r("a", "2", "y")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "z")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [conflict("a", BothChanged)]);
    let c = Case {
        remote: vec![r("a", "2", "y")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "y")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [adopt("a")]);
}

#[test]
fn applies_the_conflict_policy() {
    let c = |policy| Case {
        remote: vec![r("a", "2", "y")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "z")],
        policy: Some(policy),
        ..Default::default()
    };
    assert_eq!(c(Policy::PreferRemote).plan(), [pull("a")]);
    assert_eq!(c(Policy::PreferLocal).plan(), [push("a")]);
}

#[test]
fn flags_an_unsynced_local_value_that_differs_from_a_new_remote_one() {
    let c = Case { remote: vec![r("a", "1", "x")], local: vec![("a", "local")], ..Default::default() };
    assert_eq!(c.plan(), [conflict("a", LocalUnsynced)]);
    // Only an explicit decision settles it, never the policy.
    for policy in [Policy::PreferLocal, Policy::PreferRemote] {
        let c = Case {
            remote: vec![r("a", "1", "x")],
            local: vec![("a", "local")],
            policy: Some(policy),
            ..Default::default()
        };
        assert_eq!(c.plan(), [conflict("a", LocalUnsynced)]);
    }
}

#[test]
fn clears_locally_when_deleted_remotely_unless_edited_here() {
    let c = Case { base: vec![b("a", "1", "x")], local: vec![("a", "x")], ..Default::default() };
    assert_eq!(c.plan(), [Action::ClearLocal("a".into())]);
    let c = Case { base: vec![b("a", "1", "x")], local: vec![("a", "edited")], ..Default::default() };
    assert_eq!(c.plan(), [conflict("a", DeletedRemotely)]);
    let c = Case {
        base: vec![b("a", "1", "x")],
        local: vec![("a", "edited")],
        policy: Some(Policy::PreferLocal),
        ..Default::default()
    };
    assert_eq!(c.plan(), [create("a")]);
    let c = Case { base: vec![b("a", "1", "x")], ..Default::default() };
    assert_eq!(c.plan(), [Action::Forget("a".into())]);
}

#[test]
fn clears_an_edited_secret_deleted_remotely_only_when_the_policy_prefers_bitwarden() {
    let c = Case {
        base: vec![b("a", "1", "x")],
        local: vec![("a", "edited")],
        policy: Some(Policy::PreferRemote),
        ..Default::default()
    };
    assert_eq!(c.plan(), [Action::ClearLocal("a".into())]);
}

#[test]
fn a_queued_upload_meeting_a_new_remote_item_of_the_same_id_is_both_changed() {
    let c = |policy| Case {
        remote: vec![r("a", "1", "remote")],
        local: vec![("a", "queued")],
        pending: vec!["a"],
        policy,
        ..Default::default()
    };
    assert_eq!(c(None).plan(), [conflict("a", BothChanged)]);
    // Unlike a never-synced value, the user asked for this one to be uploaded: the policy may settle it.
    assert_eq!(c(Some(Policy::PreferLocal)).plan(), [push("a")]);
    assert_eq!(c(Some(Policy::PreferRemote)).plan(), [pull("a")]);
}

#[test]
fn creates_only_what_the_user_queued() {
    let c = Case { local: vec![("a", "v"), ("b", "w")], pending: vec!["a"], ..Default::default() };
    assert_eq!(c.plan(), [create("a")]);
    let c = Case { pending: vec!["gone"], ..Default::default() };
    assert_eq!(c.plan(), [Action::Forget("gone".into())]);
}

#[test]
fn is_deterministic_sorted_by_id() {
    let c = Case { remote: ["c", "a", "b"].map(|id| r(id, "1", "x")).to_vec(), ..Default::default() };
    assert_eq!(c.plan(), [pull("a"), pull("b"), pull("c")]);
}

#[test]
fn honours_per_secret_overrides() {
    let c = Case {
        remote: vec![r("a", "2", "y"), r("b", "2", "y")],
        base: vec![b("a", "1", "x"), b("b", "1", "x")],
        // "z" for both, as the plugin's `local: () => "z"`.
        local: vec![("a", "z"), ("b", "z")],
        overrides: vec![("b", ConflictOverride { policy: Policy::PreferLocal, kind: BothChanged })],
        ..Default::default()
    };
    assert_eq!(c.plan(), [conflict("a", BothChanged), push("b")]);
}

#[test]
fn an_override_for_another_kind_is_ignored() {
    let c = Case {
        base: vec![b("a", "1", "x")],
        local: vec![("a", "edited")],
        overrides: vec![("a", ConflictOverride { policy: Policy::PreferLocal, kind: BothChanged })],
        ..Default::default()
    };
    assert_eq!(c.plan(), [conflict("a", DeletedRemotely)]);
}

const POLICIES: [Policy; 3] = [Policy::Ask, Policy::PreferLocal, Policy::PreferRemote];

#[test]
fn always_asks_before_a_pending_or_unsynced_local_value_meets_a_new_organization_item() {
    for policy in POLICIES {
        for pending in [vec![], vec!["a"]] {
            let c = Case {
                remote: vec![ro("a", "1", "theirs", "org-1", true)],
                local: vec![("a", "mine")],
                pending,
                policy: Some(policy),
                ..Default::default()
            };
            assert_eq!(c.plan(), [conflict("a", OrganizationClaim)]);
        }
    }
}

#[test]
fn always_asks_when_an_organization_item_replaces_the_item_a_secret_was_synced_with() {
    for policy in POLICIES {
        for local in ["base", "edited"] {
            let c = Case {
                remote: vec![ro("a", "2", "theirs", "org-1", true)],
                base: vec![bc("a", "1", "base", "mine-1")],
                local: vec![("a", local)],
                policy: Some(policy),
                ..Default::default()
            };
            assert_eq!(c.plan(), [conflict("a", OrganizationClaim)]);
        }
    }
}

#[test]
fn asks_even_when_the_values_match_or_the_local_value_is_gone() {
    let claim = [conflict("a", OrganizationClaim)];
    let c = Case {
        remote: vec![ro("a", "1", "same", "org-1", true)],
        local: vec![("a", "same")],
        policy: Some(Policy::PreferLocal),
        ..Default::default()
    };
    assert_eq!(c.plan(), claim);
    let c = Case {
        remote: vec![ro("a", "1", "same", "org-1", true)],
        base: vec![bc("a", "1", "same", "mine-1")],
        policy: Some(Policy::PreferRemote),
        ..Default::default()
    };
    assert_eq!(c.plan(), claim);
}

#[test]
fn keeps_a_local_value_as_a_new_personal_item_never_pushing_it_to_the_organization() {
    let c = Case {
        remote: vec![ro("a", "1", "theirs", "org-1", true)],
        local: vec![("a", "mine")],
        pending: vec!["a"],
        policy: Some(Policy::PreferLocal),
        overrides: vec![("a", ConflictOverride { policy: Policy::PreferLocal, kind: OrganizationClaim })],
        ..Default::default()
    };
    assert_eq!(c.plan(), [create("a")]);
}

#[test]
fn still_pulls_onto_an_empty_device_and_pushes_to_the_organization_item_it_synced_with() {
    let c = Case { remote: vec![ro("a", "1", "theirs", "org-1", true)], ..Default::default() };
    assert_eq!(c.plan(), [pull("a")]);
    let (id, mut e) = bc("a", "1", "x", "org-1");
    e.push_confirmed = true;
    let c = Case {
        remote: vec![ro("a", "1", "x", "org-1", true)],
        base: vec![(id, e)],
        local: vec![("a", "y")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [push("a")]);
}

/// What a silent pull onto an empty device leaves behind: bound, but never confirmed.
fn first_push(policy: Policy, remote_fp: &str) -> Case {
    Case {
        remote: vec![ro("a", if remote_fp == "x" { "1" } else { "2" }, remote_fp, "org-1", true)],
        base: vec![bc("a", "1", "x", "org-1")],
        local: vec![("a", "mine")],
        policy: Some(policy),
        ..Default::default()
    }
}

#[test]
fn the_first_push_to_an_organization_item_is_always_asked_whatever_the_policy() {
    for policy in POLICIES {
        assert_eq!(first_push(policy, "x").plan(), [conflict("a", OrganizationPush)]);
    }
}

#[test]
fn the_first_push_is_asked_when_prefer_local_settles_a_both_changed_conflict() {
    assert_eq!(first_push(Policy::PreferLocal, "theirs").plan(), [conflict("a", OrganizationPush)]);
}

#[test]
fn pushes_marked_confirmed_only_once_the_user_agreed() {
    let run = |policy, kind| {
        let mut c = first_push(Policy::PreferLocal, "x");
        c.overrides = vec![("a", ConflictOverride { policy, kind })];
        c.plan()
    };
    assert_eq!(run(Policy::PreferLocal, OrganizationPush), [confirmed_push("a")]);
    assert_eq!(run(Policy::PreferRemote, OrganizationPush), [pull("a")]);
    // An answer about another kind of conflict is not an agreement to this push.
    assert_eq!(run(Policy::PreferLocal, BothChanged), [conflict("a", OrganizationPush)]);
}

#[test]
fn never_asks_for_personal_items() {
    let c = Case {
        remote: vec![r("a", "1", "x")],
        base: vec![b("a", "1", "x")],
        local: vec![("a", "y")],
        ..Default::default()
    };
    assert_eq!(c.plan(), [push("a")]);
}
