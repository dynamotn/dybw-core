//! A profile's session for the JS host. The keys, the client and the device's sync state (the planner's base) stay
//! here; JS gets results as JSON text and errors as [`Error`]s, which carry no value. The state is saved through `Storage`
//! as the plugin's JSON (spec §7). Unstable: M6 may reshape it.

use crate::error::Error;
use crate::host::Host;
use crate::ports::Ports;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::api::{self, ApiKey, Client, DeviceInfo, Hub, HubOptions, hub_url, origin_of, resolve_server_urls};
use dybw_core::crypto::{KdfParams, SymmetricKey};
use dybw_core::ports::{Secrets, Storage};
use dybw_core::profile::{self, CachedSync, KdfSource, UnlockWarning, Unlocked};
use dybw_core::sync::{
    self, Action, ConflictKind, ConflictOverride, DeviceState, LocalValues, SyncContext, SyncReport, item_scope,
    parse_plugin_state, scope_applies, to_plugin_json,
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

pub(crate) const KINDS: [ConflictKind; 5] = [
    ConflictKind::BothChanged,
    ConflictKind::LocalUnsynced,
    ConflictKind::DeletedRemotely,
    ConflictKind::OrganizationClaim,
    ConflictKind::OrganizationPush,
];
pub(crate) const QUESTIONS: [HistoryQuestion; 2] = [HistoryQuestion::FirstWriteBack, HistoryQuestion::EvictsForeign];
pub(crate) const ANSWERS: [(&str, HistoryAnswer); 2] =
    [("write-to-login", HistoryAnswer::WriteToLogin), ("keep-separate", HistoryAnswer::KeepSeparate)];

/// The one of `all` whose code is `code`.
pub(crate) fn by_code<T: Copy>(all: &[T], name: impl Fn(T) -> &'static str, code: &str) -> Result<T, Error> {
    all.iter().copied().find(|t| name(*t) == code).ok_or_else(|| Error::invalid("unknown option value"))
}

/// The user's decision about one conflict: it holds only while the conflict is still of `kind`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Override {
    policy: Policy,
    kind: String,
}

/// The user's answer to one history question (ADR 0016): it covers only `question`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Answered {
    question: String,
    answer: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncOptions {
    #[serde(default)]
    policy: Policy,
    /// Every rollback; `acceptRollbacks` names them one by one instead.
    #[serde(default)]
    accept_rollback: bool,
    /// By cipher id: the rollbacks the user was shown and accepted; the others stay held.
    #[serde(default)]
    accept_rollbacks: BTreeSet<String>,
    /// By secret id.
    #[serde(default)]
    overrides: BTreeMap<String, Override>,
    /// By secret id.
    #[serde(default)]
    answers: BTreeMap<String, Answered>,
    /// The vault this sync is for: an item scoped `vault:<name>` syncs only there.
    #[serde(default)]
    vault_name: String,
    #[serde(default)]
    upload_folder: Option<String>,
}

/// `SyncOptions` in the core's types.
struct Options {
    policy: sync::Policy,
    accept_rollback: bool,
    accept_rollbacks: BTreeSet<String>,
    overrides: BTreeMap<String, ConflictOverride>,
    answers: BTreeMap<String, (HistoryQuestion, HistoryAnswer)>,
    vault_name: String,
    upload_folder: Option<String>,
}

impl TryFrom<SyncOptions> for Options {
    type Error = Error;
    fn try_from(o: SyncOptions) -> Result<Self, Error> {
        let mut overrides = BTreeMap::new();
        for (id, v) in o.overrides {
            overrides.insert(
                id,
                ConflictOverride { policy: v.policy.into(), kind: by_code(&KINDS, ConflictKind::code, &v.kind)? },
            );
        }
        let mut answers = BTreeMap::new();
        for (id, a) in o.answers {
            let question = by_code(&QUESTIONS, HistoryQuestion::code, &a.question)?;
            answers.insert(id, (question, by_code(&ANSWERS, |(c, _)| c, &a.answer)?.1));
        }
        let (policy, accept_rollback) = (o.policy.into(), o.accept_rollback);
        Ok(Options {
            policy,
            accept_rollback,
            accept_rollbacks: o.accept_rollbacks,
            overrides,
            answers,
            vault_name: o.vault_name,
            upload_folder: o.upload_folder,
        })
    }
}

/// An upload's scope from `"global"`, `"vault:<name>"` or `"device"`: a device scope is always this device's.
fn upload_scope(scope: &str, device_id: &str) -> Result<String, Error> {
    let s = scope.trim();
    if s == "global" || s.strip_prefix("vault:").is_some_and(|n| !n.is_empty()) {
        Ok(s.to_owned())
    } else if s == "device" || s.starts_with("device:") {
        Ok(format!("device:{device_id}"))
    } else {
        Err(Error::invalid("unknown scope"))
    }
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

/// What a sync borrows besides the state.
struct Keys<H: Host> {
    client: Client<Ports<H>, Ports<H>>,
    unlocked: Unlocked,
    allowed: Organizations,
    unmarked: UnmarkedCache,
}

struct Open<H: Host> {
    keys: Keys<H>,
    state: DeviceState,
}

/// What `run_hub` reads, kept beside the keys so the hub keeps running while a call has them out. Set by `open`,
/// dropped by `lock`.
struct HubKeys<H: Host> {
    device_id: String,
    notifications: String,
    /// The hub's own twin of the client (`Client::twin`), so it renews its token while a call has the keys out.
    /// `None` while the hub has it out.
    client: Option<Client<Ports<H>, Ports<H>>>,
}

/// Every method takes `&self` and no borrow outlives a synchronous step, so `lock` can run at any time, even from
/// a callback of a running call, and never throws. A call that needs the keys takes them out of `open` and puts them
/// back only if `lock` did not run meanwhile (`generation` changed); otherwise they are dropped, which wipes them.
pub struct Session<H: Host> {
    ports: Ports<H>,
    ns: &'static Namespace,
    open: Cell<Option<Open<H>>>,
    hub: Cell<Option<HubKeys<H>>>,
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
        let (open, hub, generation, busy) = (Cell::new(None), Cell::new(None), Cell::new(0), Cell::new(false));
        Ok(Session { ports: Ports(host), ns, open, hub, generation, busy })
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

    /// `f` on the hub's keys, without keeping them.
    fn with_hub<T>(&self, f: impl FnOnce(&mut HubKeys<H>) -> T) -> Option<T> {
        let mut hub = self.hub.take();
        let out = hub.as_mut().map(f);
        self.hub.set(hub);
        out
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

    /// Withdraws an acknowledgement. It takes effect at the next unlock: the host locks the session when the user
    /// withdraws it.
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

    /// `unlock` with the user key `exportUserKey` gave, base64, instead of the password (`profile::unlock_with_key`):
    /// the same login and `/sync`, no KDF. A key that does not open the account's private key is `wrong-password`
    /// and saves nothing; one that is not base64 or no key at all is `invalid`, before any request.
    pub async fn unlock_with_key(
        &self,
        profile_json: &str,
        client_secret: Zeroizing<String>,
        user_key: Zeroizing<String>,
    ) -> Result<String, Error> {
        let generation = self.lock();
        let bytes =
            Zeroizing::new(B64.decode(user_key.as_bytes()).map_err(|_| Error::invalid("the key is not base64"))?);
        drop(user_key);
        let user = SymmetricKey::from_bytes(&bytes)?;
        drop(bytes);
        let p: Profile = parse(profile_json)?;
        let (mut client, _, notifications) = self.client(&p).await?;
        let key = ApiKey { origin: p.api_origin, client_id: p.client_id, client_secret };
        let allowed = p.organizations.into();
        let (ports, ns) = (&self.ports, self.ns);
        let unlocked = profile::unlock_with_key(&mut client, ports, &key, user, ports, ns, &allowed).await?;
        self.open(client, notifications, unlocked, allowed, generation).await
    }

    /// The user key, base64, for `unlockWithKey`; `locked` (or `busy`) without the keys. One of the secrets spec §6.2
    /// lets cross as a JS string: the plugin asks for it only when the user turned "remember unlock" on.
    pub fn export_user_key(&self) -> Result<String, Error> {
        let key = |o: &Open<H>| B64.encode(o.keys.unlocked.keys.user.to_bytes());
        self.peek(key).ok_or_else(|| self.absent())
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
        let twin = Some(client.twin(self.port(), self.port()));
        self.hub.set(Some(HubKeys { device_id: state.device_id.clone(), notifications, client: twin }));
        self.open.set(Some(Open { keys: Keys { client, unlocked, allowed, unmarked }, state }));
        Ok(summary.to_string())
    }

    /// Drops the keys and the client, which wipes them; a call that has them out drops them when it ends, and a
    /// running sync or hub stops at its next check. Answers the new generation.
    pub fn lock(&self) -> u64 {
        let generation = self.generation.get().wrapping_add(1);
        self.generation.set(generation);
        self.busy.set(false);
        drop(self.open.take());
        drop(self.hub.take());
        generation
    }

    /// Plans one pass (`sync::plan_pass`) over the local values `ids[i]` = `values[i]`; applies nothing.
    pub async fn plan_pass(&self, options: &str, ids: Vec<String>, values: Vec<String>) -> Result<String, Error> {
        let values = wrap(values);
        let o = Options::try_from(parse::<SyncOptions>(options)?)?;
        let local = Local::new(ids, values)?;
        let (mut open, generation) = self.take()?;
        let device_id = open.state.device_id.clone();
        let applies = |m: &_| scope_applies(item_scope(self.ns, m), &o.vault_name, &device_id);
        let plan = {
            let mut ctx = context(&mut open.keys, self.ns, &self.ports, &o, &applies);
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
        let o = Options::try_from(parse::<SyncOptions>(options)?)?;
        let mut local = Local::new(ids, values)?;
        let (mut open, generation) = self.take()?;
        let before = open.state.clone();
        let device_id = open.state.device_id.clone();
        let applies = |m: &_| scope_applies(item_scope(self.ns, m), &o.vault_name, &device_id);
        let report = {
            let mut ctx = context(&mut open.keys, self.ns, &self.ports, &o, &applies);
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
        self.save_state(generation, state).await?;
        failed
    }

    /// Saves the state, unless `lock` ran since `generation`.
    async fn save_state(&self, generation: u64, state: &DeviceState) -> Result<(), Error> {
        if self.generation.get() != generation {
            return Err(Error::locked());
        }
        Ok(Storage::save(&self.ports, STATE, to_plugin_json(state).to_string().as_bytes()).await?)
    }

    /// Queues the local secret `id` for upload by the next sync, with `scope` (`upload_scope`). The host checks that
    /// it holds a value for `id`. A failed save keeps the id queued in memory: the next successful save writes it, as
    /// the plugin does today.
    pub async fn queue_upload(&self, id: &str, scope: &str) -> Result<(), Error> {
        let device_id = self.with_hub(|h| h.device_id.clone()).ok_or_else(Error::locked)?;
        (self.ns.id_rule)(id).map_err(|_| Error::invalid("not a secret id this tool syncs"))?;
        let scope = upload_scope(scope, &device_id)?;
        let (mut open, generation) = self.take()?;
        if !open.state.pending_creates.iter().any(|p| p == id) {
            open.state.pending_creates.push(id.to_owned());
        }
        open.state.pending_scopes.insert(id.to_owned(), scope);
        let saved = self.save_state(generation, &open.state).await;
        self.put(open, generation);
        saved
    }

    /// The ids the state holds, JSON `{"base": [ids], "pendingCreates": [ids]}`.
    pub fn synced_ids(&self) -> Result<String, Error> {
        let ids = |o: &Open<H>| json!({ "base": o.state.base.keys().collect::<Vec<_>>(), "pendingCreates": o.state.pending_creates });
        self.peek(|o| ids(o).to_string()).ok_or_else(|| self.absent())
    }

    /// Forgets what was synced and queued, keeping the device id: the session's state when unlocked, else the saved
    /// one. `busy` while a call has the keys out.
    pub async fn reset_state(&self) -> Result<(), Error> {
        match self.take() {
            Ok((mut open, generation)) => {
                open.state = open.state.reset();
                let saved = self.save_state(generation, &open.state).await;
                self.put(open, generation);
                saved
            }
            Err(e) if e.code() == crate::error::BUSY => Err(e),
            Err(_) => {
                // Stops an unlock in flight, which would load the state from before the reset; an unlock that ends
                // before the save makes the reset refuse with `locked` instead.
                let generation = self.lock();
                let device_id = self.device_id().await?;
                let raw = Storage::load(&self.ports, STATE).await?;
                let saved = raw.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
                let state = parse_plugin_state(&saved, self.ns, || device_id).reset();
                self.save_state(generation, &state).await
            }
        }
    }

    /// Keeps the hub up (`api::run_hub`) until `stop` or `lock`, calling `on_change` when the vault changed
    /// elsewhere. It holds no vault key: its URLs come from its twin of the client, which renews an expired or refused
    /// token through the same gated login (ADR 0018), so it keeps running during a sync. It takes the twin out only
    /// for one attempt and puts it back only if `lock` did not run meanwhile.
    pub async fn run_hub(&self, on_change: impl FnMut(), stop: impl Fn() -> bool) -> Result<(), Error> {
        let device_id = self.with_hub(|h| h.device_id.clone()).ok_or_else(Error::locked)?;
        let generation = self.generation.get();
        let mut hub = Hub::new(HubOptions::default(), device_id);
        let url = async |renew| {
            let (mut client, base) = self.with_hub(|h| Some((h.client.take()?, h.notifications.clone()))).flatten()?;
            let url = client.hub_token(renew).await.ok().map(|t| hub_url(&base, t));
            // After a `lock` the twin is dropped here, which wipes it, and nothing is opened.
            let live = self.generation.get() == generation;
            if live {
                self.with_hub(|h| h.client = Some(client));
            }
            url.filter(|_| live)
        };
        let stopped = || self.generation.get() != generation || stop();
        api::run_hub(&self.ports, &self.ports, url, &mut hub, on_change, stopped).await;
        Ok(())
    }
}

fn context<'a, H: Host>(
    open: &'a mut Keys<H>,
    ns: &'a Namespace,
    rng: &'a Ports<H>,
    o: &'a Options,
    applies: &'a dyn Fn(&MarkedItem) -> bool,
) -> SyncContext<'a, Ports<H>, Ports<H>, Ports<H>> {
    SyncContext {
        client: &mut open.client,
        ns,
        keys: &open.unlocked.keys,
        rng,
        allowed: &open.allowed,
        policy: o.policy,
        accept_rollback: o.accept_rollback,
        accepted_rollbacks: &o.accept_rollbacks,
        overrides: &o.overrides,
        answers: &o.answers,
        applies,
        upload_folder: o.upload_folder.clone(),
        unmarked: &mut open.unmarked,
    }
}

pub(crate) fn problem(p: &OrgProblem) -> Value {
    json!({ "organization": p.organization, "reason": p.reason })
}

/// The warning as a sentence for the notice: the KDF's numbers and source; never a key.
pub(crate) fn warning(w: &UnlockWarning) -> String {
    let UnlockWarning::KdfBelowFloor { params, kdf_source } = w;
    let source = match kdf_source {
        KdfSource::SyncUnlockData => "sync unlock data",
        KdfSource::Prelogin => "prelogin",
    };
    let kdf = match *params {
        KdfParams::Pbkdf2 { iterations } => format!("PBKDF2 {iterations} iterations"),
        KdfParams::Argon2id { iterations, memory_mib, parallelism } => {
            format!("Argon2id {iterations} iterations, {memory_mib} MiB, parallelism {parallelism}")
        }
    };
    format!("The KDF parameters are below the recommended floor: {kdf} (from {source}).")
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

/// The sync's report. Organization names are raw, as their owners set them: JS sanitizes them before showing them.
pub(crate) fn report_json(r: &SyncReport) -> Value {
    let p = &r.skipped;
    let pairs = |v: &[(String, String)]| v.iter().map(|(id, c)| json!({ "id": id, "cipherId": c })).collect::<Vec<_>>();
    let conflicts: Vec<Value> = r
        .conflicts
        .iter()
        .map(|c| {
            json!({
                "id": c.id, "kind": c.kind.code(), "label": c.label, "organization": c.organization,
                "organizationName": c.organization_name,
            })
        })
        .collect();
    let errors: Vec<Value> = r.errors.iter().map(|e| json!({ "id": e.id, "error": e.error.to_string() })).collect();
    let questions: Vec<Value> =
        p.questions.iter().map(|q| json!({ "id": q.id, "label": q.label, "question": q.question.code() })).collect();
    let features: Vec<Value> =
        p.unknown_features.iter().map(|(c, f)| json!({ "cipherId": c, "features": f })).collect();
    let duplicates: Vec<Value> = p
        .duplicates
        .iter()
        .map(|d| json!({ "id": d.id, "kept": d.kept, "left": d.left, "boundKept": d.bound_kept }))
        .collect();
    let skipped: Vec<Value> = p.skipped.iter().map(|(c, why)| json!({ "cipherId": c, "reason": why.code() })).collect();
    json!({
        "pulled": r.pulled, "pushed": r.pushed, "created": r.created, "cleared": r.cleared,
        "conflicts": conflicts, "errors": errors, "passes": r.passes, "keptChanging": r.kept_changing,
        "questions": questions, "rollbacks": pairs(&p.rollbacks), "unknownFeatures": features, "held": pairs(&p.held),
        "readOnly": pairs(&p.read_only), "unreadable": p.unreadable, "duplicates": duplicates, "skipped": skipped,
        "warnings": warnings(r),
    })
}

/// One line of the core's text per kind of thing the user should know about, with counts only.
fn warnings(r: &SyncReport) -> Vec<String> {
    let p = &r.skipped;
    let lines = [
        (usize::from(r.kept_changing), "secrets kept changing during the sync: sync again later"),
        (
            p.rollbacks.len(),
            "synced secrets came back older from Bitwarden: kept until you accept the server's versions",
        ),
        (p.unknown_features.len(), "items need a newer version of this tool: left alone"),
        (p.held.len(), "synced secrets can no longer be used here: kept as they are"),
        (p.read_only.len(), "secrets changed here are in items you cannot edit: not uploaded"),
        (p.unreadable.len(), "items could not be decrypted"),
        (p.duplicates.len(), "ids are on more than one item: one item is used for each"),
    ];
    lines.into_iter().filter(|(n, _)| *n > 0).map(|(n, text)| format!("{n} {text}")).collect()
}
