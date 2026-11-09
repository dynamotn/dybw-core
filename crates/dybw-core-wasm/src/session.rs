//! A profile's session for the JS host. The keys, the client and the device's sync state (the planner's base) stay
//! here; JS gets results as JSON text and errors as messages without a value. The state is saved through `Storage`
//! as the plugin's JSON (spec §7). Unstable: M6 may reshape it.

use crate::host::Host;
use crate::ports::Ports;
use dybw_core::api::{self, ApiKey, Client, DeviceInfo, Hub, HubOptions, hub_url, origin_of, resolve_server_urls};
use dybw_core::crypto::KdfParams;
use dybw_core::ports::{Secrets, Storage};
use dybw_core::profile::{self, CachedSync, UnlockWarning, Unlocked};
use dybw_core::sync::{
    self, Action, ConflictOverride, DeviceState, LocalValues, SyncContext, SyncReport, parse_plugin_state,
    to_plugin_json,
};
use dybw_core::vault::write::{HistoryAnswer, HistoryQuestion};
use dybw_core::vault::{MarkedItem, Namespace, OrgProblem, Organizations, UnmarkedCache};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use zeroize::Zeroizing;

/// The storage key of the device's sync state.
pub const STATE: &str = "sync-state";
/// What every method that needs the keys answers once locked.
pub const LOCKED: &str = "locked";

static NO_OVERRIDES: BTreeMap<String, ConflictOverride> = BTreeMap::new();
static NO_ANSWERS: BTreeMap<String, (HistoryQuestion, HistoryAnswer)> = BTreeMap::new();

fn text(e: impl ToString) -> String {
    e.to_string()
}

fn parse<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T, String> {
    serde_json::from_str(json).map_err(text)
}

/// A KDF as the vectors' account files write it.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Kdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory: u32, parallelism: u32 },
}

impl From<Kdf> for KdfParams {
    fn from(k: Kdf) -> Self {
        match k {
            Kdf::Pbkdf2 { iterations } => KdfParams::Pbkdf2 { iterations },
            Kdf::Argon2id { iterations, memory, parallelism } => {
                KdfParams::Argon2id { iterations, memory_mib: memory, parallelism }
            }
        }
    }
}

/// `"none"`, `"all"` or `{"only": [ids]}`.
#[derive(Deserialize, Default)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Orgs {
    #[default]
    None,
    All,
    Only(BTreeSet<String>),
}

impl From<Orgs> for Organizations {
    fn from(o: Orgs) -> Self {
        match o {
            Orgs::None => Organizations::None,
            Orgs::All => Organizations::All,
            Orgs::Only(ids) => Organizations::Only(ids),
        }
    }
}

#[derive(Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Policy {
    #[default]
    Ask,
    PreferRemote,
    PreferLocal,
}

impl From<Policy> for sync::Policy {
    fn from(p: Policy) -> Self {
        match p {
            Policy::Ask => sync::Policy::Ask,
            Policy::PreferRemote => sync::Policy::PreferRemote,
            Policy::PreferLocal => sync::Policy::PreferLocal,
        }
    }
}

/// The profile an unlock is for. No secret: the API key's secret and the password come as their own arguments.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    server: String,
    email: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    organizations: Orgs,
    device_name: String,
    device_type: u8,
    client_name: String,
    client_version: String,
    /// `unlock_cached` only: an earlier `/sync`, and the KDF prelogin gave with it.
    #[serde(default)]
    cached_sync: Value,
    #[serde(default)]
    prelogin_kdf: Option<Kdf>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncOptions {
    #[serde(default)]
    policy: Policy,
    #[serde(default)]
    accept_rollback: bool,
}

/// The tool's local values for one sync, given by JS; the ones a sync wrote go back through `Secrets`.
struct Local {
    values: BTreeMap<String, Zeroizing<String>>,
    written: BTreeSet<String>,
}

impl Local {
    fn new(ids: Vec<String>, values: Vec<String>) -> Result<Local, String> {
        if ids.len() != values.len() {
            return Err("ids and values differ in length".into());
        }
        let values = ids.into_iter().zip(values.into_iter().map(Zeroizing::new)).collect();
        Ok(Local { values, written: BTreeSet::new() })
    }
}

impl LocalValues for Local {
    fn get(&self, id: &str) -> Option<Zeroizing<String>> {
        self.values.get(id).cloned()
    }
    fn set(&mut self, id: &str, value: &str) {
        self.values.insert(id.to_owned(), Zeroizing::new(value.to_owned()));
        self.written.insert(id.to_owned());
    }
}

/// Every marked item is the session's to sync: the plugin's scopes come with M6.
fn every(_: &MarkedItem) -> bool {
    true
}

/// What a sync borrows besides the state.
struct Keys<H: Host> {
    client: Client<Ports<H>, Ports<H>>,
    notifications: String,
    unlocked: Unlocked,
    allowed: Organizations,
    unmarked: UnmarkedCache,
}

struct Open<H: Host> {
    keys: Keys<H>,
    state: DeviceState,
}

pub struct Session<H: Host> {
    ports: Ports<H>,
    ns: &'static Namespace,
    open: Option<Open<H>>,
}

impl<H: Host> Session<H> {
    /// `namespace` is `"obsidian"` or `"bwss"`.
    pub fn new(host: Rc<H>, namespace: &str) -> Result<Self, String> {
        let ns = match namespace {
            "obsidian" => &Namespace::OBSIDIAN,
            "bwss" => &Namespace::BWSS,
            _ => return Err("unknown namespace".into()),
        };
        Ok(Session { ports: Ports(host), ns, open: None })
    }

    fn port(&self) -> Ports<H> {
        Ports(self.ports.0.clone())
    }

    pub async fn device_id(&self) -> Result<String, String> {
        profile::device_id(&self.ports, &self.ports).await.map_err(text)
    }

    pub async fn accept_kdf(&self, kdf: &str, origin: &str) -> Result<(), String> {
        profile::accept_kdf(&self.ports, parse::<Kdf>(kdf)?.into(), origin).await.map_err(text)
    }

    pub async fn accept_security_version(&self, version: u64) -> Result<(), String> {
        profile::accept_security_version(&self.ports, version).await.map_err(text)
    }

    /// A client for the profile's server, not logged in, and the identity origin.
    async fn client(&self, p: &Profile) -> Result<(Client<Ports<H>, Ports<H>>, String, String), String> {
        let urls = resolve_server_urls(&p.server).map_err(text)?;
        let origin = origin_of(&urls.identity).map_err(text)?;
        let notifications = urls.notifications.clone();
        let device = DeviceInfo {
            identifier: self.device_id().await?,
            name: p.device_name.clone(),
            device_type: p.device_type,
            client_name: p.client_name.clone(),
            client_version: p.client_version.clone(),
        };
        let client = Client::new(self.port(), self.port(), urls, device).map_err(text)?;
        Ok((client, origin, notifications))
    }

    /// Logs in with the API key, then unlocks (`profile::unlock`). Locks first.
    pub async fn unlock(
        &mut self,
        profile_json: &str,
        client_secret: Zeroizing<String>,
        password: Zeroizing<String>,
    ) -> Result<String, String> {
        self.lock();
        let p: Profile = parse(profile_json)?;
        let (mut client, origin, notifications) = self.client(&p).await?;
        let key = ApiKey { origin, client_id: p.client_id, client_secret };
        let allowed = p.organizations.into();
        let (ports, ns) = (&self.ports, self.ns);
        let unlocked = profile::unlock(&mut client, ports, &key, &p.email, password, ports, ports, ns, &allowed)
            .await
            .map_err(text)?;
        self.open(client, notifications, unlocked, allowed).await
    }

    /// Unlocks from the profile's `cachedSync` without the network (`profile::unlock_cached`); the client stays
    /// logged out. Locks first.
    pub async fn unlock_cached(&mut self, profile_json: &str, password: Zeroizing<String>) -> Result<String, String> {
        self.lock();
        let p: Profile = parse(profile_json)?;
        let (client, origin, notifications) = self.client(&p).await?;
        let cached = CachedSync { sync: p.cached_sync, prelogin_kdf: p.prelogin_kdf.map(Into::into), email: p.email };
        let allowed = p.organizations.into();
        let (ports, ns) = (&self.ports, self.ns);
        let unlocked =
            profile::unlock_cached(cached, ports, &origin, password, ports, ports, ns, &allowed).await.map_err(text)?;
        self.open(client, notifications, unlocked, allowed).await
    }

    async fn open(
        &mut self,
        client: Client<Ports<H>, Ports<H>>,
        notifications: String,
        unlocked: Unlocked,
        allowed: Organizations,
    ) -> Result<String, String> {
        let raw = Storage::load(&self.ports, STATE).await.map_err(text)?;
        let raw: Value = raw.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let device_id = self.device_id().await?;
        let state = parse_plugin_state(&raw, self.ns, || device_id);
        let summary = json!({
            "userKeyId": unlocked.user_key_id(),
            "securityVersion": unlocked.security_version,
            "orgProblems": unlocked.org_problems.iter().map(problem).collect::<Vec<_>>(),
            "warnings": unlocked.warnings.iter().map(warning).collect::<Vec<_>>(),
        });
        let unmarked = UnmarkedCache::default();
        self.open = Some(Open { keys: Keys { client, notifications, unlocked, allowed, unmarked }, state });
        Ok(summary.to_string())
    }

    /// Drops the keys and the client, which wipes them.
    pub fn lock(&mut self) {
        self.open = None;
    }

    /// Plans one pass (`sync::plan_pass`) over the local values `ids[i]` = `values[i]`; applies nothing.
    pub async fn plan_pass(&mut self, options: &str, ids: Vec<String>, values: Vec<String>) -> Result<String, String> {
        let open = self.open.as_mut().ok_or(LOCKED)?;
        let o: SyncOptions = parse(options)?;
        let local = Local::new(ids, values)?;
        let mut ctx = context(&mut open.keys, self.ns, &self.ports, &o);
        let plan = sync::plan_pass(&mut ctx, &open.state, &local).await.map_err(text)?;
        let actions: Vec<Value> = plan.actions.iter().map(action).collect();
        Ok(json!({ "actions": actions, "massClear": plan.mass_clear }).to_string())
    }

    /// One sync (`sync::run_sync`). The state, and the local values it wrote, are saved even when it failed partway.
    pub async fn run_sync(&mut self, options: &str, ids: Vec<String>, values: Vec<String>) -> Result<String, String> {
        let open = self.open.as_mut().ok_or(LOCKED)?;
        let o: SyncOptions = parse(options)?;
        let mut local = Local::new(ids, values)?;
        let mut ctx = context(&mut open.keys, self.ns, &self.ports, &o);
        let report = sync::run_sync(&mut ctx, &mut open.state, &mut local, |_| {}, || false).await;
        let saved = save(&self.ports, &open.state, &local).await;
        let report = report.map_err(text)?;
        saved?;
        Ok(report_json(&report).to_string())
    }

    /// Keeps the hub up (`api::run_hub`) until `stop`, calling `on_change` when the vault changed elsewhere.
    pub async fn run_hub(&self, on_change: impl FnMut(), stop: impl Fn() -> bool) -> Result<(), String> {
        let open = self.open.as_ref().ok_or(LOCKED)?;
        let mut hub = Hub::new(HubOptions::default(), open.state.device_id.clone());
        let k = &open.keys;
        // shortcut: an expired token is not renewed here, so the attempt fails until the next sync renews it.
        let url = async || k.client.access_token().map(|t| hub_url(&k.notifications, t));
        api::run_hub(&self.ports, &self.ports, url, &mut hub, on_change, stop).await;
        Ok(())
    }
}

fn context<'a, H: Host>(
    open: &'a mut Keys<H>,
    ns: &'a Namespace,
    rng: &'a Ports<H>,
    o: &SyncOptions,
) -> SyncContext<'a, Ports<H>, Ports<H>, Ports<H>> {
    SyncContext {
        client: &mut open.client,
        ns,
        keys: &open.unlocked.keys,
        rng,
        allowed: &open.allowed,
        policy: o.policy.into(),
        accept_rollback: o.accept_rollback,
        overrides: &NO_OVERRIDES,
        answers: &NO_ANSWERS,
        applies: &every,
        upload_folder: None,
        unmarked: &mut open.unmarked,
    }
}

async fn save<H: Host>(ports: &Ports<H>, state: &DeviceState, local: &Local) -> Result<(), String> {
    Storage::save(ports, STATE, to_plugin_json(state).to_string().as_bytes()).await.map_err(text)?;
    for (id, value) in local.values.iter().filter(|(id, _)| local.written.contains(*id)) {
        Secrets::save(ports, id, value).await.map_err(text)?;
    }
    Ok(())
}

pub(crate) fn problem(p: &OrgProblem) -> Value {
    json!({ "organization": p.organization, "reason": p.reason })
}

/// The warning's numbers and source; never a key.
pub(crate) fn warning(w: &UnlockWarning) -> String {
    format!("{w:?}")
}

pub(crate) fn action(a: &Action) -> Value {
    match a {
        Action::Pull(id) => json!({ "kind": "pull", "id": id }),
        Action::Push { id, confirmed } => json!({ "kind": "push", "id": id, "confirmed": confirmed }),
        Action::Create(id) => json!({ "kind": "create", "id": id }),
        Action::Adopt(id) => json!({ "kind": "adopt", "id": id }),
        Action::ClearLocal(id) => json!({ "kind": "clear-local", "id": id }),
        Action::Forget(id) => json!({ "kind": "forget", "id": id }),
        Action::Conflict { id, kind } => json!({ "kind": "conflict", "id": id, "conflict": kind.code() }),
    }
}

pub(crate) fn report_json(r: &SyncReport) -> Value {
    let conflicts: Vec<Value> = r.conflicts.iter().map(|c| json!({ "id": c.id, "kind": c.kind.code() })).collect();
    let errors: Vec<Value> = r.errors.iter().map(|e| json!({ "id": e.id, "error": e.error.to_string() })).collect();
    json!({
        "pulled": r.pulled, "pushed": r.pushed, "created": r.created, "cleared": r.cleared,
        "conflicts": conflicts, "errors": errors, "passes": r.passes, "keptChanging": r.kept_changing,
    })
}
