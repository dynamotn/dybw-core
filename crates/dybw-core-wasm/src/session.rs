//! A profile's session for the JS host. The keys, the client and the device's sync state (the planner's base) stay
//! here; JS gets results as JSON text and errors as [`Error`]s, which carry no value. The state is saved through `Storage`
//! as the plugin's JSON (spec §7). Unstable: M6 may reshape it.

use crate::error::Error;
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
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use zeroize::Zeroizing;

/// The storage key of the device's sync state.
pub const STATE: &str = "sync-state";
/// The warning of an unlock that found a saved sync state it cannot read; the state starts over.
pub const STATE_UNREADABLE: &str = "the saved sync state is unreadable: it starts over";

static NO_OVERRIDES: BTreeMap<String, ConflictOverride> = BTreeMap::new();
static NO_ANSWERS: BTreeMap<String, (HistoryQuestion, HistoryAnswer)> = BTreeMap::new();

fn parse<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T, Error> {
    Ok(serde_json::from_str(json)?)
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
    /// The identity origin the API key was entered for; `unlock` refuses to send it anywhere else.
    #[serde(default)]
    api_origin: String,
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
    /// `values` is already wrapped: the caller does it before any check that could drop them.
    fn new(ids: Vec<String>, values: Vec<Zeroizing<String>>) -> Result<Local, Error> {
        if ids.len() != values.len() {
            return Err(Error::invalid("ids and values differ in length"));
        }
        Ok(Local { values: ids.into_iter().zip(values).collect(), written: BTreeSet::new() })
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

/// Moves each value into `Zeroizing` before anything else can drop it.
fn wrap(values: Vec<String>) -> Vec<Zeroizing<String>> {
    values.into_iter().map(Zeroizing::new).collect()
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

/// Every method takes `&self` and no borrow outlives a synchronous step, so `lock` can run at any time, even from
/// a callback of a running call, and never throws. A call that needs the keys takes them out of `open` and puts them
/// back only if `lock` did not run meanwhile (`generation` changed); otherwise they are dropped, which wipes them.
pub struct Session<H: Host> {
    ports: Ports<H>,
    ns: &'static Namespace,
    open: Cell<Option<Open<H>>>,
    generation: Cell<u64>,
    /// A call has the keys out.
    busy: Cell<bool>,
}

impl<H: Host> Session<H> {
    /// `namespace` is `"obsidian"` or `"bwss"`.
    pub fn new(host: Rc<H>, namespace: &str) -> Result<Self, Error> {
        let ns = match namespace {
            "obsidian" => &Namespace::OBSIDIAN,
            "bwss" => &Namespace::BWSS,
            _ => return Err(Error::invalid("unknown namespace")),
        };
        let (open, generation, busy) = (Cell::new(None), Cell::new(0), Cell::new(false));
        Ok(Session { ports: Ports(host), ns, open, generation, busy })
    }

    fn port(&self) -> Ports<H> {
        Ports(self.ports.0.clone())
    }

    /// Why there are no keys to hand out.
    fn absent(&self) -> Error {
        if self.busy.get() { Error::busy() } else { Error::locked() }
    }

    /// Takes the keys out for one call, with the generation to put them back under.
    fn take(&self) -> Result<(Open<H>, u64), Error> {
        let open = self.open.take().ok_or_else(|| self.absent())?;
        self.busy.set(true);
        Ok((open, self.generation.get()))
    }

    /// Puts the keys back, unless `lock` ran since `take`: then they are dropped here.
    fn put(&self, open: Open<H>, generation: u64) {
        if self.generation.get() == generation {
            self.busy.set(false);
            self.open.set(Some(open));
        }
    }

    /// `f` on the keys, without keeping them.
    fn peek<T>(&self, f: impl FnOnce(&Open<H>) -> T) -> Option<T> {
        let open = self.open.take();
        let out = open.as_ref().map(f);
        self.open.set(open);
        out
    }

    pub async fn device_id(&self) -> Result<String, Error> {
        Ok(profile::device_id(&self.ports, &self.ports).await?)
    }

    pub async fn accept_kdf(&self, kdf: &str, origin: &str) -> Result<(), Error> {
        Ok(profile::accept_kdf(&self.ports, parse::<Kdf>(kdf)?.into(), origin).await?)
    }

    pub async fn accept_security_version(&self, version: u64) -> Result<(), Error> {
        Ok(profile::accept_security_version(&self.ports, version).await?)
    }

    /// The user's acknowledgement of a self-hosted identity origin (ADR 0018), for a host whose `http` follows
    /// redirects.
    pub async fn acknowledge_origin(&self, origin: &str) -> Result<(), Error> {
        Ok(profile::acknowledge_origin(&self.ports, origin).await?)
    }

    pub async fn forget_origin(&self, origin: &str) -> Result<(), Error> {
        Ok(profile::forget_origin(&self.ports, origin).await?)
    }

    /// The acknowledged origins, a JSON list.
    pub async fn acknowledged_origins(&self) -> Result<String, Error> {
        Ok(json!(profile::acknowledged_origins(&self.ports).await?).to_string())
    }

    /// A client for the profile's server, not logged in, with this server's acknowledgement (ADR 0018; the others
    /// are dropped), and the identity origin.
    async fn client(&self, p: &Profile) -> Result<(Client<Ports<H>, Ports<H>>, String, String), Error> {
        let urls = resolve_server_urls(&p.server)?;
        let origin = origin_of(&urls.identity)?;
        let notifications = urls.notifications.clone();
        let device = DeviceInfo {
            identifier: self.device_id().await?,
            name: p.device_name.clone(),
            device_type: p.device_type,
            client_name: p.client_name.clone(),
            client_version: p.client_version.clone(),
        };
        let acknowledged = profile::acknowledged_for(&self.ports, &origin).await?;
        let client = Client::new(self.port(), self.port(), urls, device)?.with_acknowledged(acknowledged);
        Ok((client, origin, notifications))
    }

    /// Logs in with the API key, then unlocks (`profile::unlock`). Locks first; a `lock` while it runs wins. The
    /// key goes only to the profile's `apiOrigin`: another identity origin is refused with `wrong-origin`.
    pub async fn unlock(
        &self,
        profile_json: &str,
        client_secret: Zeroizing<String>,
        password: Zeroizing<String>,
    ) -> Result<String, Error> {
        let generation = self.lock();
        let p: Profile = parse(profile_json)?;
        let (mut client, origin, notifications) = self.client(&p).await?;
        let key = ApiKey { origin: p.api_origin, client_id: p.client_id, client_secret };
        let allowed = p.organizations.into();
        let (ports, ns) = (&self.ports, self.ns);
        let unlocked = profile::unlock(&mut client, ports, &key, &p.email, password, ports, ports, ns, &allowed)
            .await
            .map_err(|e| Error::from(e).at(&origin))?;
        self.open(client, notifications, unlocked, allowed, generation).await
    }

    /// Unlocks from the profile's `cachedSync` without the network (`profile::unlock_cached`); the client stays
    /// logged out. Locks first; a `lock` while it runs wins.
    pub async fn unlock_cached(&self, profile_json: &str, password: Zeroizing<String>) -> Result<String, Error> {
        let generation = self.lock();
        let p: Profile = parse(profile_json)?;
        let (client, origin, notifications) = self.client(&p).await?;
        let cached = CachedSync { sync: p.cached_sync, prelogin_kdf: p.prelogin_kdf.map(Into::into), email: p.email };
        let allowed = p.organizations.into();
        let (ports, ns) = (&self.ports, self.ns);
        let unlocked = profile::unlock_cached(cached, ports, &origin, password, ports, ports, ns, &allowed)
            .await
            .map_err(|e| Error::from(e).at(&origin))?;
        self.open(client, notifications, unlocked, allowed, generation).await
    }

    async fn open(
        &self,
        client: Client<Ports<H>, Ports<H>>,
        notifications: String,
        unlocked: Unlocked,
        allowed: Organizations,
        generation: u64,
    ) -> Result<String, Error> {
        let raw = Storage::load(&self.ports, STATE).await?;
        // `None` saved nothing; `Some(None)` saved something that is not JSON, which is reported, not hidden.
        let parsed: Option<Option<Value>> = raw.map(|b| serde_json::from_slice(&b).ok());
        let unreadable = matches!(parsed, Some(None));
        let device_id = self.device_id().await?;
        let state = parse_plugin_state(&parsed.flatten().unwrap_or_default(), self.ns, || device_id);
        let mut warnings: Vec<String> = unlocked.warnings.iter().map(warning).collect();
        warnings.extend(unreadable.then(|| STATE_UNREADABLE.to_owned()));
        let summary = json!({
            "userKeyId": unlocked.user_key_id(),
            "securityVersion": unlocked.security_version,
            "orgProblems": unlocked.org_problems.iter().map(problem).collect::<Vec<_>>(),
            "warnings": warnings,
        });
        if self.generation.get() != generation {
            return Err(Error::locked());
        }
        let unmarked = UnmarkedCache::default();
        self.open.set(Some(Open { keys: Keys { client, notifications, unlocked, allowed, unmarked }, state }));
        Ok(summary.to_string())
    }

    /// Drops the keys and the client, which wipes them; a call that has them out drops them when it ends, and a
    /// running sync or hub stops at its next check. Answers the new generation.
    pub fn lock(&self) -> u64 {
        let generation = self.generation.get().wrapping_add(1);
        self.generation.set(generation);
        self.busy.set(false);
        drop(self.open.take());
        generation
    }

    /// Plans one pass (`sync::plan_pass`) over the local values `ids[i]` = `values[i]`; applies nothing.
    pub async fn plan_pass(&self, options: &str, ids: Vec<String>, values: Vec<String>) -> Result<String, Error> {
        let values = wrap(values);
        let o: SyncOptions = parse(options)?;
        let local = Local::new(ids, values)?;
        let (mut open, generation) = self.take()?;
        let plan = {
            let mut ctx = context(&mut open.keys, self.ns, &self.ports, &o);
            sync::plan_pass(&mut ctx, &open.state, &local).await
        };
        self.put(open, generation);
        let plan = plan?;
        let actions: Vec<Value> = plan.actions.iter().map(action).collect();
        Ok(json!({ "actions": actions, "massClear": plan.mass_clear }).to_string())
    }

    /// One sync (`sync::run_sync`), stopped by `lock`. The values it wrote, then the state, are saved even when it
    /// failed partway, until `lock` runs: a newer sync may have saved since, and these values without
    /// their state would be pushed over the newer ones. What it pulled is pulled again; what it pushed is adopted.
    pub async fn run_sync(&self, options: &str, ids: Vec<String>, values: Vec<String>) -> Result<String, Error> {
        let values = wrap(values);
        let o: SyncOptions = parse(options)?;
        let mut local = Local::new(ids, values)?;
        let (mut open, generation) = self.take()?;
        let before = open.state.clone();
        let report = {
            let mut ctx = context(&mut open.keys, self.ns, &self.ports, &o);
            let locked = || self.generation.get() != generation;
            sync::run_sync(&mut ctx, &mut open.state, &mut local, |_| {}, locked).await
        };
        let saved = self.save(generation, &mut open.state, &before, &local).await;
        self.put(open, generation);
        let report = report?;
        saved?;
        Ok(report_json(&report).to_string())
    }

    /// Saves the values the sync wrote, then the state. A value that could not be saved keeps its base entry and
    /// its queued create from before the sync, so the state never records a pull the host does not hold (the next
    /// sync would push the old value over the newer one). Answers the first failure. Each save first checks that
    /// `lock` has not run since `generation` and stops at the first that finds it has: a newer sync may have saved.
    async fn save(
        &self,
        generation: u64,
        state: &mut DeviceState,
        before: &DeviceState,
        local: &Local,
    ) -> Result<(), Error> {
        let live = || if self.generation.get() == generation { Ok(()) } else { Err(Error::locked()) };
        let mut failed = Ok(());
        for (id, value) in local.values.iter().filter(|(id, _)| local.written.contains(*id)) {
            live()?;
            if let Err(e) = Secrets::save(&self.ports, id, value).await {
                state.base.remove(id);
                state.base.extend(before.base.get_key_value(id).map(|(k, v)| (k.clone(), v.clone())));
                // Only a pull writes a value, and it dropped the id from the queue: put back what was queued.
                let scope = before.pending_scopes.get_key_value(id).map(|(k, v)| (k.clone(), v.clone()));
                state.pending_scopes.extend(scope);
                state.pending_creates.extend(before.pending_creates.iter().filter(|p| *p == id).cloned());
                failed = failed.and(Err(e.into()));
            }
        }
        live()?;
        Storage::save(&self.ports, STATE, to_plugin_json(state).to_string().as_bytes()).await?;
        failed
    }

    /// Keeps the hub up (`api::run_hub`) until `stop` or `lock`, calling `on_change` when the vault changed
    /// elsewhere. It holds no key: it reads the access token for each attempt.
    pub async fn run_hub(&self, on_change: impl FnMut(), stop: impl Fn() -> bool) -> Result<(), Error> {
        let device_id = self.peek(|o| o.state.device_id.clone()).ok_or_else(|| self.absent())?;
        let generation = self.generation.get();
        let mut hub = Hub::new(HubOptions::default(), device_id);
        // shortcut: an expired token is not renewed here, so the attempt fails until the next sync renews it.
        let url =
            async || self.peek(|o| o.keys.client.access_token().map(|t| hub_url(&o.keys.notifications, t))).flatten();
        let stopped = || self.generation.get() != generation || stop();
        api::run_hub(&self.ports, &self.ports, url, &mut hub, on_change, stopped).await;
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
