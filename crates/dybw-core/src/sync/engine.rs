//! Sync passes: port of the plugin's `engine.ts` (`runSync`, `runPass`, `apply`). Each pass reads the vault, plans
//! with the three-way planner and applies the actions; an edit racing with a pass asks for another, up to
//! `MAX_PASSES`. Every action is checked again against what the pass read itself (§9), so a planner bug can never
//! write to the wrong item.

use super::plan::{Action, BaseEntry, ConflictKind, ConflictOverride, PlanInput, Policy, RemoteEntry, plan_sync};
use super::state::DeviceState;
use super::write::{SyncWriteError, create, update};
use crate::api::{ApiError, Client};
use crate::ports::{Clock, Http, Random};
use crate::vault::scan::{Duplicate, MarkedItem, ScanReport, SkipReason, scan_vault_with};
use crate::vault::write::{FieldSet, NewItem, Patch, ValueChange, WriteError};
use crate::vault::{Keys, Namespace, Organizations};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// Passes per sync before giving up on an item that keeps changing (the plugin's `MAX_PASSES`).
pub const MAX_PASSES: usize = 3;

/// The tool's local copies of values (the plugin's secret storage); not a host port.
pub trait LocalValues {
    fn get(&self, id: &str) -> Option<Zeroizing<String>>;
    fn set(&mut self, id: &str, value: &str);
}

pub struct SyncContext<'a, H: Http, C: Clock, R: Random> {
    pub client: &'a mut Client<H, C>,
    pub ns: &'a Namespace,
    pub keys: &'a Keys,
    pub rng: &'a R,
    pub allowed: &'a Organizations,
    pub policy: Policy,
    pub overrides: &'a BTreeMap<String, ConflictOverride>,
    /// Whether a marked item is the tool's to sync here (the plugin's scope); the others are left out before §7.
    pub applies: &'a dyn Fn(&MarkedItem) -> bool,
    /// Folder new uploads are filed in, created when missing; `None` or blank files them in no folder.
    pub upload_folder: Option<String>,
}

/// Why a sync stopped. Messages never carry a value.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Api(#[from] ApiError),
    /// More than one clear and at least half the base (§10): nothing was applied.
    #[error(
        "{clears} of {base} synced secrets would be cleared because they disappeared from Bitwarden; refusing. \
         Restore them in Bitwarden, or reset the sync state if this is intended."
    )]
    MassClear { clears: usize, base: usize },
    /// The tool was locked or unloaded; the actions applied before it are saved.
    #[error("Bitwarden was locked during the sync")]
    Cancelled,
}

/// Why one action failed; the others still run.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("refusing to upload to an organization item this secret was not synced with")]
    NotSyncedWith,
    #[error("refusing to upload to an organization item without your confirmation")]
    NotConfirmed,
    /// A binary value, which local copies (text) cannot hold.
    #[error("the value is not text")]
    NotText,
    #[error(transparent)]
    Write(#[from] SyncWriteError),
}

#[derive(Debug)]
pub struct ActionError {
    pub id: String,
    pub error: ApplyError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub id: String,
    pub kind: ConflictKind,
    /// The organization of the item, for the question to the user.
    pub organization: Option<String>,
}

/// What a pass left out, and why.
#[derive(Debug, Default)]
pub struct PassReport {
    pub skipped: Vec<(String, SkipReason)>,
    pub duplicates: Vec<Duplicate>,
    /// `(id, cipher id)` of synced secrets whose item is still there but can no longer be used: kept as is.
    pub held: Vec<(String, String)>,
    /// `(id, cipher id)` changed here, in an item its organization does not let this account edit: not uploaded.
    pub read_only: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct SyncReport {
    pub pulled: Vec<String>,
    pub pushed: Vec<String>,
    pub created: Vec<String>,
    pub cleared: Vec<String>,
    /// Of the last pass.
    pub conflicts: Vec<Conflict>,
    /// Of the last pass.
    pub skipped: PassReport,
    pub errors: Vec<ActionError>,
    pub passes: usize,
    /// Every pass met an edit racing with it: try again later.
    pub kept_changing: bool,
}

/// One pass's plan, and what it read to make it.
pub struct PassPlan {
    pub actions: Vec<Action>,
    pub report: PassReport,
    /// `(clears, base size)` when the plan would clear more than one secret and at least half the base (§10).
    pub mass_clear: Option<(usize, usize)>,
    /// The `/sync` response, for the upload folder.
    pub(super) sync: Value,
    /// The usable items by id.
    pub(super) items: BTreeMap<String, MarkedItem>,
    /// The base the plan was made from: the state's, without held entries.
    pub(super) base: BTreeMap<String, BaseEntry>,
    /// Local values the plan was made from, with their fingerprints; absent ids had none.
    pub(super) local: BTreeMap<String, (Zeroizing<String>, String)>,
}

/// Reads the vault and plans one pass (`runPass` up to the mass-clear guard). Sends nothing but `/sync`.
pub async fn plan_pass<H: Http, C: Clock, R: Random>(
    ctx: &mut SyncContext<'_, H, C, R>,
    state: &DeviceState,
    local: &impl LocalValues,
) -> Result<PassPlan, SyncError> {
    let sync = ctx.client.sync().await?;
    // Reserved ids are refused by the namespace's id rule, so the scan already skips them.
    let ScanReport { items, skipped, duplicates, present, .. } =
        scan_vault_with(&sync, ctx.ns, ctx.keys, ctx.allowed, ctx.applies);
    let mut report = PassReport { skipped, duplicates, ..PassReport::default() };
    let items: BTreeMap<String, MarkedItem> = items.into_iter().map(|i| (i.id.clone(), i)).collect();

    // A synced secret whose item is still there but cannot be used here any more (newer format, renamed to an
    // invalid id, moved to an organization, re-scoped) is left alone rather than treated as deleted.
    let mut base = BTreeMap::new();
    for (id, entry) in &state.base {
        if !items.contains_key(id) && present.contains(&entry.cipher_id) {
            report.held.push((id.clone(), entry.cipher_id.clone()));
        } else {
            base.insert(id.clone(), entry.clone());
        }
    }
    let remote: BTreeMap<String, RemoteEntry> = items
        .iter()
        .map(|(id, i)| {
            let entry = RemoteEntry {
                id: id.clone(),
                cipher_id: i.cipher_id.clone(),
                revision_date: i.revision_date.clone(),
                fingerprint: B64.encode(i.mark),
                organization: i.organization_id.is_some(),
            };
            (id.clone(), entry)
        })
        .collect();
    let pending: BTreeSet<String> = state.pending_creates.iter().cloned().collect();
    let mut values = BTreeMap::new();
    for id in remote.keys().chain(base.keys()).chain(&pending) {
        if let Some(v) = local.get(id) {
            let fingerprint = ctx.keys.marker.mark_b64(id, &v);
            values.insert(id.clone(), (v, fingerprint));
        }
    }
    let fingerprint = |id: &str| values.get(id).map(|(_, f)| f.clone());
    let actions = plan_sync(&PlanInput {
        remote: &remote,
        base: &base,
        local: &fingerprint,
        pending_creates: &pending,
        policy: ctx.policy,
        overrides: ctx.overrides,
    });
    // Clearing many secrets at once is almost always a mistake (wrong account, a half-finished migration, a hostile
    // server) rather than intent.
    let clears = actions.iter().filter(|a| matches!(a, Action::ClearLocal(_))).count();
    let mass_clear = (clears > 1 && clears * 2 >= base.len()).then_some((clears, base.len()));
    Ok(PassPlan { actions, report, mass_clear, sync, items, base, local: values })
}

/// One sync (`runSync`): up to `MAX_PASSES` passes, each planned afresh. Refuses a mass clear before applying
/// anything; `save` runs after every action, `cancelled` before each.
pub async fn run_sync<H: Http, C: Clock, R: Random>(
    ctx: &mut SyncContext<'_, H, C, R>,
    state: &mut DeviceState,
    local: &mut impl LocalValues,
    mut save: impl FnMut(&DeviceState),
    cancelled: impl Fn() -> bool,
) -> Result<SyncReport, SyncError> {
    let mut report = SyncReport::default();
    for pass in 1..=MAX_PASSES {
        report.passes = pass;
        report.conflicts.clear();
        let plan = plan_pass(ctx, state, local).await?;
        if cancelled() {
            return Err(SyncError::Cancelled);
        }
        if let Some((clears, base)) = plan.mass_clear {
            return Err(SyncError::MassClear { clears, base });
        }
        if !apply_pass(ctx, state, local, plan, &mut report, &mut save, &cancelled).await? {
            return Ok(report);
        }
    }
    report.kept_changing = true;
    Ok(report)
}

/// Applies a pass's actions; true when another pass is needed (an edit raced with this one).
pub(super) async fn apply_pass<H: Http, C: Clock, R: Random>(
    ctx: &mut SyncContext<'_, H, C, R>,
    state: &mut DeviceState,
    local: &mut impl LocalValues,
    plan: PassPlan,
    report: &mut SyncReport,
    save: &mut impl FnMut(&DeviceState),
    cancelled: &impl Fn() -> bool,
) -> Result<bool, SyncError> {
    let PassPlan { actions, report: skipped, sync, items, base, local: values, .. } = plan;
    report.skipped = skipped;
    let mut pass = Pass { sync, items, base, local: values, folder: None };
    let mut again = false;
    for action in &actions {
        if cancelled() {
            return Err(SyncError::Cancelled);
        }
        match apply(ctx, state, local, &mut pass, action, report).await {
            Ok(a) => again |= a,
            Err(error) => report.errors.push(ActionError { id: id_of(action).to_owned(), error }),
        }
        save(state);
    }
    Ok(again)
}

struct Pass {
    sync: Value,
    items: BTreeMap<String, MarkedItem>,
    base: BTreeMap<String, BaseEntry>,
    local: BTreeMap<String, (Zeroizing<String>, String)>,
    /// The upload folder, resolved on the first upload of the pass.
    folder: Option<Option<String>>,
}

fn id_of(action: &Action) -> &str {
    match action {
        Action::Pull(id)
        | Action::Push { id, .. }
        | Action::Create(id)
        | Action::Adopt(id)
        | Action::ClearLocal(id)
        | Action::Forget(id)
        | Action::Conflict { id, .. } => id,
    }
}

/// The plugin's `parseScope` then `formatScope`: a scope it does not know is global.
fn normalize_scope(raw: Option<&str>) -> String {
    let v = raw.unwrap_or_default().trim();
    let known = ["vault:", "device:"].iter().any(|p| v.len() > p.len() && v.starts_with(p));
    if known { v.to_owned() } else { "global".to_owned() }
}

/// The item's scope from its `{ns}:scope` field, as the base keeps it.
pub(super) fn scope_of(ns: &Namespace, item: &MarkedItem) -> String {
    let field = ns.field("scope");
    normalize_scope(item.tool_fields.iter().find(|(n, _)| *n == field).map(|(_, v)| v.as_str()))
}

/// The base entry for what the item holds now. A confirmation to push belongs to the one item it was given for.
fn remote_base(ns: &Namespace, state: &DeviceState, item: &MarkedItem) -> BaseEntry {
    let confirmed = state.base.get(&item.id).is_some_and(|b| b.push_confirmed && b.cipher_id == item.cipher_id);
    BaseEntry {
        cipher_id: item.cipher_id.clone(),
        revision_date: item.revision_date.clone(),
        fingerprint: B64.encode(item.mark),
        scope: Some(scope_of(ns, item)),
        push_confirmed: confirmed,
    }
}

fn drop_pending(state: &mut DeviceState, id: &str) {
    state.pending_creates.retain(|p| p != id);
    state.pending_scopes.remove(id);
}

fn text_at<'v>(reply: Option<&'v Value>, key: &str) -> Option<&'v str> {
    reply.and_then(|r| r.get(key)).and_then(Value::as_str)
}

/// The folder for new uploads: the existing one with the lowest id, so devices agree, or a new one.
async fn upload_folder<H: Http, C: Clock, R: Random>(
    ctx: &mut SyncContext<'_, H, C, R>,
    sync: &Value,
) -> Result<Option<String>, SyncWriteError> {
    let Some(name) = ctx.upload_folder.as_deref().map(str::trim).filter(|n| !n.is_empty()) else { return Ok(None) };
    let folders = sync.get("folders").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    // A folder that cannot be decrypted is not ours.
    let mine = |f: &&Value| {
        let decrypted = f.get("name").and_then(Value::as_str).and_then(|n| ctx.keys.user.decrypt_str(n).ok());
        decrypted.is_some_and(|n| n.as_str() == name)
    };
    if let Some(id) = folders.iter().filter(mine).filter_map(|f| f.get("id").and_then(Value::as_str)).min() {
        return Ok(Some(id.to_owned()));
    }
    let encrypted = ctx.keys.user.encrypt_str(name, ctx.rng).map_err(WriteError::from)?;
    let reply = ctx.client.create_folder(&encrypted).await?;
    Ok(text_at(Some(&reply), "id").map(String::from))
}

/// True when the local value changed since the pass read it.
fn local_moved(keys: &Keys, pass: &Pass, local: &impl LocalValues, id: &str) -> bool {
    let now = local.get(id).map(|v| keys.marker.mark_b64(id, &v));
    now.as_deref() != pass.local.get(id).map(|(_, f)| f.as_str())
}

/// Applies one action (`apply`); true when another pass is needed.
async fn apply<H: Http, C: Clock, R: Random>(
    ctx: &mut SyncContext<'_, H, C, R>,
    state: &mut DeviceState,
    local: &mut impl LocalValues,
    pass: &mut Pass,
    action: &Action,
    report: &mut SyncReport,
) -> Result<bool, ApplyError> {
    let id = id_of(action);
    let rec = pass.items.get(id);
    let snapshot = pass.local.get(id);
    match action {
        Action::Pull(_) => {
            let Some(rec) = rec else { return Ok(false) };
            // Never overwrite an edit made while earlier network calls were in flight.
            if local_moved(ctx.keys, pass, local, id) {
                return Ok(true);
            }
            local.set(id, std::str::from_utf8(&rec.value).map_err(|_| ApplyError::NotText)?);
            state.base.insert(id.to_owned(), remote_base(ctx.ns, state, rec));
            drop_pending(state, id);
            report.pulled.push(id.to_owned());
        }
        Action::Adopt(_) => {
            let Some(rec) = rec else { return Ok(false) };
            state.base.insert(id.to_owned(), remote_base(ctx.ns, state, rec));
            drop_pending(state, id);
        }
        Action::Push { confirmed, .. } => {
            let (Some(rec), Some((value, fingerprint))) = (rec, snapshot) else { return Ok(false) };
            let org = rec.organization_id.is_some();
            let bound = state.base.get(id);
            // Only an organization item this secret was already synced with is ever written to; anything else
            // would hand a personal value to its members.
            if org && bound.map(|b| &b.cipher_id) != Some(&rec.cipher_id) {
                return Err(ApplyError::NotSyncedWith);
            }
            // Being bound is not enough: a pull binds without asking, so the user must have agreed to send there.
            let confirmed = org && (*confirmed || bound.is_some_and(|b| b.push_confirmed));
            if org && !confirmed {
                return Err(ApplyError::NotConfirmed);
            }
            if rec.read_only {
                report.skipped.read_only.push((id.to_owned(), rec.cipher_id.clone()));
                return Ok(false);
            }
            let patch = Patch {
                id: id.to_owned(),
                cipher_id: Some(rec.cipher_id.clone()),
                base_revision: rec.revision_date.clone(),
                set: Vec::new(),
                remove: Vec::new(),
                value: ValueChange::Set {
                    source: rec.source,
                    secret: Zeroizing::new(value.as_bytes().to_vec()),
                    base_mark: rec.mark,
                    owned: false,
                },
            };
            let now_ms = ctx.client.now_ms();
            let reply = match update(ctx.client, ctx.ns, ctx.keys, ctx.rng, now_ms, &rec.cipher, &patch).await {
                Ok(reply) => reply,
                // The item changed under the write: the next pass plans again from what it holds then.
                Err(
                    SyncWriteError::StillChanging
                    | SyncWriteError::Write(WriteError::Gone | WriteError::Unmarked | WriteError::Uninspectable(_)),
                ) => return Ok(true),
                // The value itself changed meanwhile: never overwritten silently (§6.5).
                Err(SyncWriteError::Write(WriteError::SourceChanged)) => {
                    let organization = rec.organization_id.clone();
                    report.conflicts.push(Conflict {
                        id: id.to_owned(),
                        kind: ConflictKind::BothChanged,
                        organization,
                    });
                    return Ok(false);
                }
                Err(e) => return Err(e.into()),
            };
            // A value patch is never empty, so there is always a reply.
            let entry = BaseEntry {
                cipher_id: text_at(reply.as_ref(), "id").unwrap_or(&rec.cipher_id).to_owned(),
                revision_date: text_at(reply.as_ref(), "revisionDate").unwrap_or(&rec.revision_date).to_owned(),
                fingerprint: fingerprint.clone(),
                scope: Some(scope_of(ctx.ns, rec)),
                push_confirmed: confirmed,
            };
            state.base.insert(id.to_owned(), entry);
            drop_pending(state, id);
            report.pushed.push(id.to_owned());
        }
        Action::Create(_) => {
            let Some((value, fingerprint)) = snapshot else { return Ok(false) };
            // Re-uploading after a remote deletion keeps the scope the item had.
            let queued = state.pending_scopes.get(id).or_else(|| pass.base.get(id).and_then(|b| b.scope.as_ref()));
            let scope = normalize_scope(queued.map(String::as_str));
            if pass.folder.is_none() {
                pass.folder = Some(upload_folder(ctx, &pass.sync).await?);
            }
            let tool_fields = if scope == "global" {
                Vec::new()
            } else {
                vec![FieldSet { name: ctx.ns.field("scope"), value: Zeroizing::new(scope.clone()), hidden: false }]
            };
            let item = NewItem {
                id: id.to_owned(),
                value: Zeroizing::new(value.as_bytes().to_vec()),
                name: id.to_owned(),
                folder_id: pass.folder.clone().flatten(),
                tool_fields,
            };
            let reply = create(ctx.client, ctx.ns, ctx.keys, ctx.rng, &item).await?;
            let entry = BaseEntry {
                cipher_id: text_at(Some(&reply), "id").unwrap_or_default().to_owned(),
                revision_date: text_at(Some(&reply), "revisionDate").unwrap_or_default().to_owned(),
                fingerprint: fingerprint.clone(),
                scope: Some(scope),
                push_confirmed: false,
            };
            state.base.insert(id.to_owned(), entry);
            drop_pending(state, id);
            report.created.push(id.to_owned());
        }
        Action::ClearLocal(_) => {
            if local_moved(ctx.keys, pass, local, id) {
                return Ok(true);
            }
            // Secret storage cannot delete; an empty value is the closest equivalent.
            local.set(id, "");
            state.base.remove(id);
            report.cleared.push(id.to_owned());
        }
        Action::Forget(_) => {
            state.base.remove(id);
            drop_pending(state, id);
        }
        Action::Conflict { kind, .. } => match rec {
            Some(rec) if *kind == ConflictKind::OrganizationPush && rec.read_only => {
                report.skipped.read_only.push((id.to_owned(), rec.cipher_id.clone()));
            }
            _ => {
                let organization = rec.and_then(|r| r.organization_id.clone());
                report.conflicts.push(Conflict { id: id.to_owned(), kind: *kind, organization });
            }
        },
    }
    Ok(false)
}
