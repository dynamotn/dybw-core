//! The sync passes against a stateful fake server: the plugin's `engine.test.ts`, and the pass and action cases of
//! `sync.test.ts` and `organizations.test.ts`.

use super::engine::{apply_pass, scope_of};
use super::*;
use crate::api::{ApiKey, Client, DeviceInfo, resolve_server_urls};
use crate::crypto::{MarkScheme, Marker, SymmetricKey};
use crate::ports::{Http, HttpRequest, HttpResponse, Method, PortError};
use crate::testing::{FixedClock, SeededRandom, block_on};
use crate::vault::scan::{MarkedItem, Scan, SkipReason, scan};
use crate::vault::write::WriteError;
use crate::vault::{Keys, Namespace, Organizations};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use zeroize::Zeroizing;

const OUT_OF_DATE: &str = "The client copy of this cipher is out of date. Resubmit with the current revision date.";
const ORG: &str = "org-a";
const BLOB: &str = r#"{"format_version":1,"wrapped_cek":"2.x","envelope":"y"}"#;

type Hook = Box<dyn FnMut(&str, &mut World)>;

#[derive(Default)]
struct World {
    ciphers: Vec<Value>,
    folders: Vec<Value>,
    revision: u32,
    log: Vec<String>,
    fail_sync: bool,
    fail_folders: bool,
    /// Runs before every update is looked at, as the plugin's `beforeUpdate`.
    before_update: Option<Hook>,
}

impl World {
    fn next_revision(&mut self) -> String {
        self.revision += 1;
        format!("2026-05-01T{:02}:{:02}:00.000Z", self.revision / 60, self.revision % 60)
    }

    fn cipher(&mut self, id: &str) -> &mut Value {
        self.ciphers.iter_mut().find(|c| c["id"] == id).unwrap()
    }

    /// Moves the cipher to the trash.
    fn trash(&mut self, id: &str) {
        let rev = self.next_revision();
        let c = self.cipher(id);
        c["deletedDate"] = json!(rev);
        c["revisionDate"] = json!(rev);
    }

    fn bump(&mut self, id: &str) {
        let rev = self.next_revision();
        self.cipher(id)["revisionDate"] = json!(rev);
    }

    fn count(&self, line: &str) -> usize {
        self.log.iter().filter(|l| *l == line).count()
    }
}

#[derive(Clone, Default)]
struct Server(Rc<RefCell<World>>);

fn reply(status: u16, body: &Value) -> Result<HttpResponse, PortError> {
    Ok(HttpResponse { status, body: Zeroizing::new(body.to_string().into_bytes()) })
}

impl Http for Server {
    fn refuses_redirects(&self) -> bool {
        true
    }

    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        let path = req.url.split_once("example.org").unwrap().1.split('?').next().unwrap().to_owned();
        // The token request is a form, everything else JSON.
        let body: Value = req.body.as_deref().and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
        let mut w = self.0.borrow_mut();
        w.log.push(format!("{:?} {path}", req.method));
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match (req.method, segments.as_slice()) {
            (Method::Post, ["identity", "connect", "token"]) => {
                reply(200, &json!({ "access_token": "t", "expires_in": 3600 }))
            }
            (Method::Get, ["api", "sync"]) if w.fail_sync => reply(500, &json!({ "message": "down" })),
            (Method::Get, ["api", "sync"]) => reply(
                200,
                &json!({ "profile": { "id": "u1", "key": "2.uk" }, "folders": w.folders, "ciphers": w.ciphers }),
            ),
            (Method::Get, ["api", "ciphers", id]) => match w.ciphers.iter().find(|c| c["id"] == *id) {
                Some(c) => reply(200, c),
                None => reply(404, &json!({ "message": "not found" })),
            },
            (Method::Put, ["api", "ciphers", id]) => {
                let id = (*id).to_owned();
                if let Some(mut hook) = w.before_update.take() {
                    hook(&id, &mut w);
                    w.before_update = Some(hook);
                }
                let rev = w.next_revision();
                let Some(current) = w.ciphers.iter_mut().find(|c| c["id"] == id) else {
                    return reply(404, &json!({ "message": "not found" }));
                };
                if body["lastKnownRevisionDate"] != current["revisionDate"] {
                    return reply(400, &json!({ "message": OUT_OF_DATE }));
                }
                for (k, v) in body.as_object().unwrap() {
                    current[k] = v.clone();
                }
                current["revisionDate"] = json!(rev);
                reply(200, current)
            }
            (Method::Post, ["api", "ciphers"]) => {
                let mut c = body;
                c["id"] = json!(format!("new{}", w.ciphers.len()));
                c["revisionDate"] = json!(w.next_revision());
                c["creationDate"] = json!("2026-04-01T00:00:00.000Z");
                c["deletedDate"] = Value::Null;
                w.ciphers.push(c.clone());
                reply(200, &c)
            }
            (Method::Post, ["api", "folders"]) if w.fail_folders => reply(500, &json!({ "message": "down" })),
            (Method::Post, ["api", "folders"]) => {
                let folder = json!({ "id": "folder-new", "name": body["name"] });
                w.folders.push(folder.clone());
                reply(200, &folder)
            }
            _ => reply(404, &json!({ "message": "not faked" })),
        }
    }
}

/// The plugin's secret storage.
#[derive(Clone, Default)]
struct Store(Rc<RefCell<BTreeMap<String, String>>>);

impl LocalValues for Store {
    fn get(&self, id: &str) -> Option<Zeroizing<String>> {
        self.0.borrow().get(id).map(|v| Zeroizing::new(v.clone()))
    }
    fn set(&mut self, id: &str, value: &str) {
        self.0.borrow_mut().insert(id.into(), value.into());
    }
}

impl Store {
    fn put(&self, id: &str, value: &str) {
        self.0.borrow_mut().insert(id.into(), value.into());
    }
    fn value(&self, id: &str) -> Option<String> {
        self.0.borrow().get(id).cloned()
    }
    fn remove(&self, id: &str) {
        self.0.borrow_mut().remove(id);
    }
}

/// A marked secure note (or another type) to put on the server.
struct Spec<'s> {
    id: &'s str,
    value: &'s str,
    org: bool,
    edit: bool,
    ty: u64,
    extra: &'s [(&'s str, &'s str)],
    created: &'s str,
}

impl<'s> Spec<'s> {
    fn new(id: &'s str, value: &'s str) -> Self {
        Spec { id, value, org: false, edit: true, ty: 2, extra: &[], created: "2025-01-01T00:00:00.000Z" }
    }
}

struct Rig {
    server: Server,
    client: Client<Server, FixedClock>,
    keys: Keys,
    org_key: SymmetricKey,
    rng: SeededRandom,
    ns: &'static Namespace,
    store: Store,
    state: DeviceState,
    policy: Policy,
    overrides: BTreeMap<String, ConflictOverride>,
    allowed: Organizations,
    folder: Option<String>,
    cancelled: Rc<Cell<bool>>,
    applies: Box<dyn Fn(&MarkedItem) -> bool>,
    saves: Rc<Cell<usize>>,
}

fn base(cipher: &str, value_fp: String) -> BaseEntry {
    BaseEntry {
        cipher_id: cipher.into(),
        revision_date: "r0".into(),
        fingerprint: value_fp,
        scope: None,
        push_confirmed: false,
    }
}

impl Rig {
    fn new(ns: &'static Namespace) -> Self {
        let rng = SeededRandom::new(21);
        let user = SymmetricKey::generate(&rng).unwrap();
        let org = SymmetricKey::generate(&rng).unwrap();
        let org_key = SymmetricKey::from_bytes(&org.to_bytes()).unwrap();
        let scheme = if ns.name == "bwss" { MarkScheme::Bwss } else { MarkScheme::Obsidian };
        let keys = Keys { marker: Marker::new(&user, scheme), user, orgs: BTreeMap::from([(ORG.to_owned(), org)]) };
        let server = Server::default();
        let device = DeviceInfo {
            identifier: "d".into(),
            name: "d".into(),
            device_type: 8,
            client_name: "t".into(),
            client_version: "0".into(),
        };
        let urls = resolve_server_urls("https://bw.example.org").unwrap();
        let mut client = Client::new(server.clone(), FixedClock { now_ms: 1_000 }, urls, device).unwrap();
        let key = ApiKey {
            origin: "https://bw.example.org".into(),
            client_id: "user.x".into(),
            client_secret: Zeroizing::new("s".into()),
        };
        block_on(client.login(&key)).unwrap();
        Rig {
            server,
            client,
            keys,
            org_key,
            rng,
            ns,
            store: Store::default(),
            state: DeviceState::new("d1".into()),
            policy: Policy::Ask,
            overrides: BTreeMap::new(),
            allowed: Organizations::All,
            folder: None,
            cancelled: Rc::default(),
            applies: Box::new(|_| true),
            saves: Rc::default(),
        }
    }

    fn obsidian() -> Self {
        Rig::new(&Namespace::OBSIDIAN)
    }

    fn world(&self) -> std::cell::RefMut<'_, World> {
        self.server.0.borrow_mut()
    }

    fn enc(&self, key: &SymmetricKey, s: &str) -> String {
        key.encrypt_str(s, &self.rng).unwrap()
    }

    fn add_spec(&self, spec: &Spec) -> String {
        let key = if spec.org { &self.org_key } else { &self.keys.user };
        let mut fields = vec![
            json!({ "type": 0, "name": self.enc(key, &self.ns.field("id")), "value": self.enc(key, spec.id) }),
            json!({ "type": 1, "name": self.enc(key, &self.ns.field("password")), "value": self.enc(key, spec.value) }),
        ];
        for (n, v) in spec.extra {
            fields.push(json!({ "type": 0, "name": self.enc(key, n), "value": self.enc(key, v) }));
        }
        let mut w = self.world();
        let id = format!("c{}", w.ciphers.len() + 1);
        let rev = w.next_revision();
        w.ciphers.push(json!({
            "id": id, "type": spec.ty, "organizationId": if spec.org { json!(ORG) } else { Value::Null },
            "folderId": null, "name": self.enc(key, spec.id), "notes": null, "secureNote": { "type": 0 },
            "fields": fields, "passwordHistory": [], "revisionDate": rev, "creationDate": spec.created,
            "deletedDate": null, "edit": spec.edit, "viewPassword": true,
        }));
        id
    }

    fn add(&self, id: &str, value: &str) -> String {
        self.add_spec(&Spec::new(id, value))
    }

    fn add_org(&self, id: &str, value: &str) -> String {
        self.add_spec(&Spec { org: true, ..Spec::new(id, value) })
    }

    /// The secret value another client reads from the item.
    fn remote(&self, cipher_id: &str) -> String {
        let c = self.world().cipher(cipher_id).clone();
        let Scan::Marked(m) = scan(&c, self.ns, &self.keys, &Organizations::All) else { panic!("not marked") };
        String::from_utf8(m.value.to_vec()).unwrap()
    }

    /// Another client edits the value.
    fn edit_remote(&self, cipher_id: &str, value: &str) {
        let org = !self.world().cipher(cipher_id)["organizationId"].is_null();
        let v = self.enc(if org { &self.org_key } else { &self.keys.user }, value);
        let mut w = self.world();
        w.cipher(cipher_id)["fields"][1]["value"] = json!(v);
        w.bump(cipher_id);
    }

    fn on_update(&self, hook: impl FnMut(&str, &mut World) + 'static) {
        self.world().before_update = Some(Box::new(hook));
    }

    fn fp(&self, id: &str, value: &str) -> String {
        self.keys.marker.mark_b64(id, value)
    }

    fn sync(&mut self) -> Result<SyncReport, SyncError> {
        let (cancelled, saves) = (self.cancelled.clone(), self.saves.clone());
        let mut ctx = SyncContext {
            client: &mut self.client,
            ns: self.ns,
            keys: &self.keys,
            rng: &self.rng,
            allowed: &self.allowed,
            policy: self.policy,
            overrides: &self.overrides,
            applies: &*self.applies,
            upload_folder: self.folder.clone(),
        };
        let save = move |_: &DeviceState| saves.set(saves.get() + 1);
        block_on(run_sync(&mut ctx, &mut self.state, &mut self.store.clone(), save, move || cancelled.get()))
    }

    fn ok(&mut self) -> SyncReport {
        self.sync().unwrap()
    }

    fn sync_with(&mut self, id: &str, policy: Policy, kind: ConflictKind) -> SyncReport {
        self.overrides = BTreeMap::from([(id.to_owned(), ConflictOverride { policy, kind })]);
        let r = self.ok();
        self.overrides.clear();
        r
    }

    fn plan(&mut self) -> PassPlan {
        let mut ctx = SyncContext {
            client: &mut self.client,
            ns: self.ns,
            keys: &self.keys,
            rng: &self.rng,
            allowed: &self.allowed,
            policy: self.policy,
            overrides: &self.overrides,
            applies: &*self.applies,
            upload_folder: self.folder.clone(),
        };
        block_on(plan_pass(&mut ctx, &self.state, &self.store)).unwrap()
    }

    /// One pass whose plan `edit` changes first: actions the planner should never return.
    fn sync_edited(&mut self, edit: impl FnOnce(&mut Vec<Action>)) -> SyncReport {
        let mut plan = self.plan();
        edit(&mut plan.actions);
        let mut ctx = SyncContext {
            client: &mut self.client,
            ns: self.ns,
            keys: &self.keys,
            rng: &self.rng,
            allowed: &self.allowed,
            policy: self.policy,
            overrides: &self.overrides,
            applies: &*self.applies,
            upload_folder: self.folder.clone(),
        };
        let mut report = SyncReport::default();
        let mut store = self.store.clone();
        block_on(apply_pass(&mut ctx, &mut self.state, &mut store, plan, &mut report, &mut |_| {}, &|| false)).unwrap();
        report
    }
}

fn nothing_moved(r: &SyncReport) -> bool {
    r.pulled.is_empty() && r.pushed.is_empty() && r.created.is_empty() && r.cleared.is_empty() && r.conflicts.is_empty()
}

fn conflict(id: &str, kind: ConflictKind, organization: Option<&str>) -> Conflict {
    Conflict { id: id.into(), kind, organization: organization.map(String::from) }
}

fn errors(r: &SyncReport) -> Vec<(String, String)> {
    r.errors.iter().map(|e| (e.id.clone(), e.error.to_string())).collect()
}

// --- passes ---

#[test]
fn pulls_new_items_then_does_nothing_on_the_next_sync() {
    let mut r = Rig::obsidian();
    r.add("b-second", "2");
    let first = r.add("a-first", "1");
    let report = r.ok();
    assert_eq!(report.pulled, ["a-first", "b-second"]);
    assert_eq!((report.passes, report.kept_changing, report.errors.is_empty()), (1, false, true));
    assert_eq!(r.store.value("a-first").as_deref(), Some("1"));
    let entry = &r.state.base["a-first"];
    assert_eq!((entry.cipher_id.as_str(), entry.scope.as_deref()), (first.as_str(), Some("global")));
    assert_eq!(entry.fingerprint, r.fp("a-first", "1"));
    // State is saved after every action.
    assert_eq!(r.saves.get(), 2);
    let again = r.ok();
    assert!(nothing_moved(&again) && again.errors.is_empty());
}

#[test]
fn pushes_a_local_edit_and_records_it_as_the_base() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v1");
    r.ok();
    r.store.put("k", "v2");
    let report = r.ok();
    assert_eq!(report.pushed, ["k"]);
    assert_eq!(r.remote(&c), "v2");
    let entry = &r.state.base["k"];
    assert_eq!(entry.fingerprint, r.fp("k", "v2"));
    assert_eq!(entry.revision_date, r.world().cipher(&c)["revisionDate"].as_str().unwrap());
    assert!(!entry.push_confirmed);
    assert!(nothing_moved(&r.ok()));
}

#[test]
fn adopts_an_equal_value_and_a_revision_only_change_without_moving_anything() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "same");
    // Queued for upload, but Bitwarden already holds the same value: bound, and no longer queued.
    r.store.put("k", "same");
    r.state.pending_creates = vec!["k".into()];
    r.state.pending_scopes.insert("k".into(), "global".into());
    let report = r.ok();
    assert!(nothing_moved(&report));
    assert_eq!(r.state.base["k"].cipher_id, c);
    assert!(r.state.pending_creates.is_empty() && r.state.pending_scopes.is_empty());
    // Renamed or moved in Bitwarden: only the revision changes.
    r.world().bump(&c);
    assert!(nothing_moved(&r.ok()));
    assert_eq!(r.state.base["k"].revision_date, r.world().cipher(&c)["revisionDate"].as_str().unwrap());
}

#[test]
fn reports_conflicts_and_resolves_them_per_secret() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v1");
    r.ok();
    r.store.put("k", "local");
    r.edit_remote(&c, "remote");
    assert_eq!(r.ok().conflicts, [conflict("k", ConflictKind::BothChanged, None)]);
    assert_eq!(r.store.value("k").as_deref(), Some("local"));
    assert_eq!(r.sync_with("k", Policy::PreferLocal, ConflictKind::BothChanged).pushed, ["k"]);
    assert_eq!(r.remote(&c), "local");
}

#[test]
fn never_overwrites_a_never_synced_local_value() {
    let mut r = Rig::obsidian();
    r.add("shared-id", "remote");
    r.policy = Policy::PreferLocal;
    r.store.put("shared-id", "someone else's");
    assert_eq!(r.ok().conflicts, [conflict("shared-id", ConflictKind::LocalUnsynced, None)]);
    assert_eq!(r.store.value("shared-id").as_deref(), Some("someone else's"));
}

#[test]
fn uploads_a_queued_secret_with_its_scope_into_the_oldest_upload_folder() {
    let mut r = Rig::obsidian();
    let (secrets, other) = (r.enc(&r.keys.user, "Secrets"), r.enc(&r.keys.user, "Other"));
    r.world().folders = vec![
        json!({ "id": "f2", "name": secrets }),
        json!({ "id": "f0", "name": other }),
        json!({ "id": "f9", "name": "2.not|an|encstring" }),
        json!({ "id": "f1", "name": secrets }),
    ];
    r.folder = Some(" Secrets ".into());
    r.store.put("dev", "x");
    r.state.pending_creates = vec!["dev".into()];
    r.state.pending_scopes.insert("dev".into(), "device:d1".into());
    let report = r.ok();
    assert_eq!(report.created, ["dev"]);
    let created = r.world().ciphers[0].clone();
    assert_eq!(created["folderId"], "f1");
    assert_eq!(created["organizationId"], Value::Null);
    let Scan::Marked(m) = scan(&created, r.ns, &r.keys, &Organizations::None) else { panic!("not marked") };
    assert_eq!(m.value.as_slice(), b"x");
    assert_eq!(scope_of(r.ns, &m), "device:d1");
    let entry = &r.state.base["dev"];
    assert_eq!((entry.cipher_id.as_str(), entry.scope.as_deref()), ("new0", Some("device:d1")));
    assert_eq!(entry.fingerprint, r.fp("dev", "x"));
    assert!(r.state.pending_creates.is_empty() && r.state.pending_scopes.is_empty());
    assert_eq!(r.world().count("Post /api/folders"), 0);
}

#[test]
fn creates_the_upload_folder_once_when_it_is_missing() {
    let mut r = Rig::obsidian();
    r.folder = Some("New".into());
    for id in ["a", "b"] {
        r.store.put(id, "v");
        r.state.pending_creates.push(id.into());
    }
    assert_eq!(r.ok().created, ["a", "b"]);
    let w = r.world();
    assert_eq!(w.count("Post /api/folders"), 1);
    assert!(w.ciphers.iter().all(|c| c["folderId"] == "folder-new"));
}

#[test]
fn uploads_with_the_global_scope_and_no_folder_when_neither_is_known() {
    let mut r = Rig::obsidian();
    r.folder = Some("  ".into());
    r.store.put("k", "v");
    r.state.pending_creates = vec!["k".into()];
    r.state.pending_scopes.insert("k".into(), "planet:mars".into());
    assert_eq!(r.ok().created, ["k"]);
    let created = r.world().ciphers[0].clone();
    assert_eq!(created["folderId"], Value::Null);
    let Scan::Marked(m) = scan(&created, r.ns, &r.keys, &Organizations::None) else { panic!("not marked") };
    assert!(m.tool_fields.is_empty());
    assert_eq!(r.state.base["k"].scope.as_deref(), Some("global"));
    assert_eq!(r.world().count("Post /api/folders"), 0);
}

#[test]
fn keeps_the_scope_when_a_deleted_secret_is_uploaded_again() {
    let mut r = Rig::obsidian();
    let c = r.add_spec(&Spec { extra: &[("obsidian:scope", "vault:Notes")], ..Spec::new("dev", "x") });
    r.ok();
    assert_eq!(r.state.base["dev"].scope.as_deref(), Some("vault:Notes"));
    r.world().trash(&c);
    r.store.put("dev", "edited");
    assert_eq!(r.ok().conflicts, [conflict("dev", ConflictKind::DeletedRemotely, None)]);
    let report = r.sync_with("dev", Policy::PreferLocal, ConflictKind::DeletedRemotely);
    assert_eq!(report.created, ["dev"]);
    let created = r.world().ciphers.last().unwrap().clone();
    assert_ne!(created["id"], json!(c));
    let Scan::Marked(m) = scan(&created, r.ns, &r.keys, &Organizations::None) else { panic!("not marked") };
    assert_eq!(scope_of(r.ns, &m), "vault:Notes");
}

#[test]
fn clears_a_secret_deleted_in_bitwarden() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v");
    r.add("other", "o");
    r.ok();
    r.world().trash(&c);
    assert_eq!(r.ok().cleared, ["k"]);
    assert_eq!(r.store.value("k").as_deref(), Some(""));
    assert!(!r.state.base.contains_key("k"));
}

#[test]
fn stops_syncing_an_item_once_its_marker_is_removed() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v");
    r.add("other", "o");
    r.ok();
    {
        let mut w = r.world();
        let fields = w.cipher(&c)["fields"].as_array().unwrap()[1..].to_vec();
        w.cipher(&c)["fields"] = json!(fields);
        w.bump(&c);
    }
    assert_eq!(r.ok().cleared, ["k"]);
}

#[test]
fn forgets_a_secret_gone_from_both_sides_and_a_queued_upload_whose_value_is_gone() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v");
    r.add("pad", "p");
    r.ok();
    r.world().trash(&c);
    r.store.remove("k");
    r.state.pending_creates.push("queued".into());
    r.state.pending_scopes.insert("queued".into(), "device:".into());
    let report = r.ok();
    assert!(nothing_moved(&report) && report.errors.is_empty());
    assert_eq!(r.state.base.keys().collect::<Vec<_>>(), ["pad"]);
    assert!(r.state.pending_creates.is_empty() && r.state.pending_scopes.is_empty());
}

#[test]
fn refuses_to_clear_most_or_half_of_the_secrets_at_once() {
    for gone in [3, 2] {
        let mut r = Rig::obsidian();
        let ids: Vec<String> = ["k1", "k2", "k3", "k4"].iter().map(|k| r.add(k, "v")).collect();
        r.ok();
        for c in &ids[..gone] {
            r.world().trash(c);
        }
        assert_eq!(r.plan().mass_clear, Some((gone, 4)));
        r.world().log.clear();
        let err = r.sync().unwrap_err();
        assert!(matches!(err, SyncError::MassClear { clears, base: 4 } if clears == gone), "{err}");
        assert!(err.to_string().starts_with(&format!("{gone} of 4 synced secrets would be cleared")), "{err}");
        assert_eq!(r.store.value("k1").as_deref(), Some("v"));
        assert_eq!(r.state.base.len(), 4);
        assert_eq!(r.world().log, ["Get /api/sync"]);
    }
}

#[test]
fn still_clears_one_secret_deleted_on_its_own() {
    let mut r = Rig::obsidian();
    let c = r.add("k1", "v");
    r.add("k2", "v");
    r.ok();
    r.world().trash(&c);
    assert_eq!(r.plan().mass_clear, None);
    assert_eq!(r.ok().cleared, ["k1"]);
}

#[test]
fn stops_before_the_next_action_once_cancelled() {
    let mut r = Rig::obsidian();
    let first = r.add("a-first", "1");
    let second = r.add("b-second", "1");
    r.ok();
    let second_rev = r.state.base["b-second"].revision_date.clone();
    r.store.put("a-first", "2");
    r.store.put("b-second", "2");
    // Locked while the first upload is on its way.
    let cancelled = r.cancelled.clone();
    r.on_update(move |_, _| cancelled.set(true));
    r.saves.set(0);
    assert!(matches!(r.sync(), Err(SyncError::Cancelled)));
    assert_eq!((r.remote(&first), r.remote(&second)), ("2".into(), "1".into()));
    assert_eq!(r.state.base["b-second"].revision_date, second_rev);
    assert_eq!(r.state.base["a-first"].fingerprint, r.fp("a-first", "2"));
    assert_eq!(r.saves.get(), 1);
}

#[test]
fn a_sync_cancelled_while_reading_writes_nothing() {
    let mut r = Rig::obsidian();
    r.add("k", "v");
    r.cancelled.set(true);
    assert!(matches!(r.sync(), Err(SyncError::Cancelled)));
    assert_eq!(r.store.value("k"), None);
    assert_eq!(r.world().log, ["Post /identity/connect/token", "Get /api/sync"]);
}

#[test]
fn a_sync_that_cannot_read_the_vault_fails() {
    let mut r = Rig::obsidian();
    r.world().fail_sync = true;
    assert!(matches!(r.sync(), Err(SyncError::Api(_))));
}

#[test]
fn an_edit_racing_with_the_push_is_retried_by_the_writer_in_the_same_pass() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v1");
    r.ok();
    r.store.put("k", "mine");
    let raced = Rc::new(Cell::new(false));
    let (flag, id) = (raced.clone(), c.clone());
    r.on_update(move |to, w| {
        if !flag.get() && to == id {
            flag.set(true);
            w.bump(to);
        }
    });
    let report = r.ok();
    assert_eq!((report.passes, report.pushed.as_slice()), (1, ["k".to_owned()].as_slice()));
    assert_eq!(r.remote(&c), "mine");
}

#[test]
fn gives_up_after_three_passes_when_an_item_keeps_changing_under_the_push() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v1");
    r.ok();
    r.store.put("k", "mine");
    r.on_update(|to, w| w.bump(to));
    let report = r.ok();
    assert_eq!((report.passes, report.kept_changing), (MAX_PASSES, true));
    assert!(report.pushed.is_empty() && report.errors.is_empty());
    assert_eq!(r.remote(&c), "v1");
    assert_eq!(r.store.value("k").as_deref(), Some("mine"));
    assert_eq!(r.world().count(&format!("Put /api/ciphers/{c}")), MAX_PASSES * ATTEMPTS);
}

#[test]
fn a_push_meeting_a_changed_value_after_the_refetch_is_a_both_changed_conflict() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v1");
    r.ok();
    r.store.put("k", "mine");
    let theirs = r.enc(&r.keys.user, "theirs");
    let done = Rc::new(Cell::new(false));
    let flag = done.clone();
    r.on_update(move |to, w| {
        if !flag.replace(true) {
            w.cipher(to)["fields"][1]["value"] = json!(theirs);
            w.bump(to);
        }
    });
    let report = r.ok();
    assert_eq!(report.conflicts, [conflict("k", ConflictKind::BothChanged, None)]);
    assert!(report.pushed.is_empty() && report.errors.is_empty());
    assert_eq!(report.passes, 1);
    assert_eq!(r.remote(&c), "theirs");
    assert_eq!(r.store.value("k").as_deref(), Some("mine"));
}

#[test]
fn a_push_whose_item_went_away_meanwhile_takes_another_pass() {
    for removed in [false, true] {
        let mut r = Rig::obsidian();
        let c = r.add("k", "v1");
        r.add("pad", "p");
        r.ok();
        r.store.put("k", "mine");
        let done = Rc::new(Cell::new(false));
        let flag = done.clone();
        r.on_update(move |to, w| {
            if !flag.replace(true) {
                if removed {
                    w.ciphers.retain(|c| c["id"] != to);
                } else {
                    w.trash(to);
                }
            }
        });
        let report = r.ok();
        if removed {
            // Deleted for good: the write itself is refused (404), reported as the plugin does.
            assert_eq!(report.passes, 1);
            assert!(matches!(report.errors[0].error, ApplyError::Write(SyncWriteError::Api(_))));
            assert_eq!(r.ok().conflicts, [conflict("k", ConflictKind::DeletedRemotely, None)]);
        } else {
            // Trashed: the refetch shows it, and the next pass sees a deletion.
            assert_eq!(report.passes, 2);
            assert_eq!(report.conflicts, [conflict("k", ConflictKind::DeletedRemotely, None)]);
            assert!(report.errors.is_empty());
        }
        assert_eq!(r.world().ciphers.iter().filter(|x| x["id"] == json!(c)).count(), usize::from(!removed));
    }
}

#[test]
fn does_not_clear_a_secret_edited_while_the_sync_is_running() {
    let mut r = Rig::obsidian();
    let first = r.add("a-first", "1");
    let gone = r.add("b-gone", "1");
    r.ok();
    r.store.put("a-first", "pushed");
    r.world().trash(&gone);
    let store = r.store.clone();
    r.on_update(move |to, _| {
        if to == first {
            store.put("b-gone", "typed meanwhile");
        }
    });
    let report = r.ok();
    assert!(report.cleared.is_empty());
    assert_eq!(report.passes, 2);
    assert_eq!(r.store.value("b-gone").as_deref(), Some("typed meanwhile"));
    assert_eq!(report.conflicts, [conflict("b-gone", ConflictKind::DeletedRemotely, None)]);
}

#[test]
fn does_not_overwrite_a_local_edit_made_while_the_sync_is_running() {
    let mut r = Rig::obsidian();
    let first = r.add("a-first", "1");
    let second = r.add("b-second", "1");
    r.ok();
    r.store.put("a-first", "pushed");
    r.edit_remote(&second, "remote");
    let store = r.store.clone();
    r.on_update(move |to, _| {
        if to == first {
            store.put("b-second", "typed meanwhile");
        }
    });
    let report = r.ok();
    assert_eq!(r.store.value("b-second").as_deref(), Some("typed meanwhile"));
    assert_eq!(report.conflicts.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["b-second"]);
}

#[test]
fn reports_what_a_push_could_not_write_and_goes_on() {
    let mut r = Rig::obsidian();
    let big = r.add("big", "v");
    let small = r.add("small", "v");
    r.ok();
    r.store.put("big", &"y".repeat(8_000));
    r.store.put("small", "w");
    let report = r.ok();
    assert_eq!(report.pushed, ["small"]);
    assert_eq!(errors(&report), [("big".to_owned(), "the value is too long for a Bitwarden item".to_owned())]);
    assert!(matches!(report.errors[0].error, ApplyError::Write(SyncWriteError::Write(WriteError::TooLong))));
    assert!(!format!("{:?}", report.errors).contains("yyyy"));
    assert_eq!((r.remote(&big), r.remote(&small)), ("v".into(), "w".into()));
}

#[test]
fn reports_an_upload_whose_folder_cannot_be_created() {
    let mut r = Rig::obsidian();
    r.world().fail_folders = true;
    r.folder = Some("Secrets".into());
    r.store.put("k", "v");
    r.state.pending_creates = vec!["k".into()];
    let report = r.ok();
    assert!(report.created.is_empty());
    assert!(matches!(report.errors[0].error, ApplyError::Write(SyncWriteError::Api(_))));
    assert_eq!(r.state.pending_creates, ["k"]);
}

#[test]
fn reports_a_binary_value_the_local_copies_cannot_hold() {
    let mut r = Rig::new(&Namespace::BWSS);
    r.add_spec(&Spec { extra: &[("bwss:encoding", "base64")], ..Spec::new("bin", "/w==") });
    let report = r.ok();
    assert!(report.pulled.is_empty());
    assert!(matches!(report.errors[0].error, ApplyError::NotText));
    assert_eq!(r.store.value("bin"), None);
}

// --- what a pass leaves out ---

#[test]
fn reports_skipped_and_duplicate_items_of_the_last_pass() {
    let mut r = Rig::obsidian();
    let card = r.add_spec(&Spec { ty: 3, ..Spec::new("card", "v") });
    let older = r.add_spec(&Spec { created: "2024-01-01T00:00:00.000Z", ..Spec::new("dup", "old") });
    let newer = r.add("dup", "new");
    let report = r.ok();
    assert_eq!(report.pulled, ["dup"]);
    assert_eq!(r.store.value("dup").as_deref(), Some("old"));
    assert_eq!(report.skipped.skipped, [(card, SkipReason::WrongType)]);
    let d = &report.skipped.duplicates[0];
    assert_eq!((d.kept.as_str(), d.left.as_slice()), (older.as_str(), [newer].as_slice()));
}

#[test]
fn leaves_out_items_that_do_not_apply_before_picking_a_duplicate() {
    let mut r = Rig::obsidian();
    r.add_spec(&Spec {
        created: "2024-01-01T00:00:00.000Z",
        extra: &[("obsidian:scope", "vault:Other")],
        ..Spec::new("dup", "elsewhere")
    });
    r.add("dup", "here");
    r.applies = Box::new(|m| m.tool_fields.is_empty());
    let report = r.ok();
    assert_eq!(report.pulled, ["dup"]);
    assert_eq!(r.store.value("dup").as_deref(), Some("here"));
    assert!(report.skipped.duplicates.is_empty());
}

#[test]
fn keeps_a_synced_secret_whose_item_can_no_longer_be_used() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "v");
    r.add("other", "o");
    r.ok();
    // Rewritten as a blob by a newer client: held, never cleared, never pushed to.
    {
        let mut w = r.world();
        w.cipher(&c)["data"] = json!(BLOB);
        w.bump(&c);
    }
    let report = r.ok();
    assert!(report.cleared.is_empty());
    assert_eq!(report.skipped.held, [("k".to_owned(), c.clone())]);
    assert_eq!(r.store.value("k").as_deref(), Some("v"));
    assert_eq!(r.state.base["k"].cipher_id, c);
    r.store.put("k", "w");
    let report = r.ok();
    assert!(nothing_moved(&report) && report.errors.is_empty());
    // Re-scoped away from this device: also kept.
    r.world().cipher(&c).as_object_mut().unwrap().remove("data");
    r.applies = Box::new(|m| m.id != "k");
    let report = r.ok();
    assert!(report.cleared.is_empty());
    assert_eq!(report.skipped.held, [("k".to_owned(), c)]);
}

#[test]
fn neither_adopts_nor_reports_a_new_blob_item() {
    let mut r = Rig::obsidian();
    let c = r.add("fresh", "v");
    r.world().cipher(&c)["data"] = json!(BLOB);
    let report = r.ok();
    assert!(nothing_moved(&report));
    assert!(report.skipped.skipped.is_empty() && report.skipped.held.is_empty());
    assert_eq!(r.store.value("fresh"), None);
}

// --- organization items (§9) ---

#[test]
fn organization_items_are_pulled_only_when_enabled() {
    let mut r = Rig::obsidian();
    r.add_org("team-token", "t0k3n");
    r.allowed = Organizations::None;
    let report = r.ok();
    assert!(report.pulled.is_empty() && report.skipped.skipped.is_empty());
    r.allowed = Organizations::All;
    assert_eq!(r.ok().pulled, ["team-token"]);
    assert_eq!(r.store.value("team-token").as_deref(), Some("t0k3n"));
}

#[test]
fn pushes_to_an_organization_item_once_confirmed_then_without_asking() {
    let mut r = Rig::obsidian();
    let c = r.add_org("team-token", "old");
    r.ok();
    r.store.put("team-token", "one");
    assert_eq!(r.ok().conflicts, [conflict("team-token", ConflictKind::OrganizationPush, Some(ORG))]);
    let report = r.sync_with("team-token", Policy::PreferLocal, ConflictKind::OrganizationPush);
    assert_eq!(report.pushed, ["team-token"]);
    assert_eq!(r.remote(&c), "one");
    assert!(r.state.base["team-token"].push_confirmed);
    // A pull from the same item keeps the confirmation.
    r.edit_remote(&c, "two");
    assert_eq!(r.ok().pulled, ["team-token"]);
    assert!(r.state.base["team-token"].push_confirmed);
    r.store.put("team-token", "three");
    let report = r.ok();
    assert!(report.conflicts.is_empty());
    assert_eq!(report.pushed, ["team-token"]);
    assert_eq!(r.remote(&c), "three");
}

#[test]
fn takes_the_organization_value_when_the_first_push_is_declined() {
    let mut r = Rig::obsidian();
    let c = r.add_org("team-token", "theirs");
    r.ok();
    r.store.put("team-token", "mine");
    let report = r.sync_with("team-token", Policy::PreferRemote, ConflictKind::OrganizationPush);
    assert_eq!(report.pulled, ["team-token"]);
    assert_eq!(r.store.value("team-token").as_deref(), Some("theirs"));
    assert_eq!(r.remote(&c), "theirs");
}

#[test]
fn a_confirmation_belongs_to_the_one_item_it_was_given_for() {
    let mut r = Rig::obsidian();
    let c = r.add_org("team-token", "theirs");
    r.state
        .base
        .insert("team-token".into(), BaseEntry { push_confirmed: true, ..base("c-other", r.fp("team-token", "x")) });
    r.store.put("team-token", "theirs");
    // A claim taken from another cipher: pulled, and not confirmed for this one.
    r.sync_with("team-token", Policy::PreferRemote, ConflictKind::OrganizationClaim);
    assert_eq!(r.state.base["team-token"].cipher_id, c);
    assert!(!r.state.base["team-token"].push_confirmed);
}

#[test]
fn only_pulls_items_the_organization_does_not_let_this_account_edit() {
    let mut r = Rig::obsidian();
    let c = r.add_spec(&Spec { org: true, edit: false, ..Spec::new("read-only", "v") });
    r.ok();
    r.store.put("read-only", "changed here");
    // Asked first: a read-only item is reported instead of asking.
    let report = r.ok();
    assert!(report.conflicts.is_empty() && report.errors.is_empty());
    assert_eq!(report.skipped.read_only, [("read-only".to_owned(), c.clone())]);
    // Even once confirmed.
    let report = r.sync_with("read-only", Policy::PreferLocal, ConflictKind::OrganizationPush);
    assert!(report.pushed.is_empty() && report.errors.is_empty());
    assert_eq!(report.skipped.read_only, [("read-only".to_owned(), c.clone())]);
    assert_eq!(r.remote(&c), "v");
    assert_eq!(r.store.value("read-only").as_deref(), Some("changed here"));
}

#[test]
fn never_uploads_a_pending_secret_into_an_organization_item_claiming_its_id() {
    let mut r = Rig::obsidian();
    r.policy = Policy::PreferLocal;
    r.store.put("my-token", "private");
    r.state.pending_creates = vec!["my-token".into()];
    let planted = r.add_org("my-token", "planted");
    assert_eq!(r.ok().conflicts, [conflict("my-token", ConflictKind::OrganizationClaim, Some(ORG))]);
    let kept = r.sync_with("my-token", Policy::PreferLocal, ConflictKind::OrganizationClaim);
    assert_eq!(kept.created, ["my-token"]);
    assert_eq!(r.remote(&planted), "planted");
    assert_eq!(r.remote("new1"), "private");
    let again = r.ok();
    assert!(nothing_moved(&again));
}

// --- actions the planner should never return (engine.test.ts) ---

#[test]
fn ignores_a_pull_push_or_adopt_for_an_id_it_read_no_item_for() {
    let mut r = Rig::obsidian();
    r.add("real", "v");
    r.store.put("ghost", "local");
    let report = r.sync_edited(|a| {
        a.extend([Action::Pull("ghost".into()), Action::Push { id: "ghost".into(), confirmed: false }]);
        a.push(Action::Adopt("ghost".into()));
    });
    assert_eq!(report.pulled, ["real"]);
    assert!(report.pushed.is_empty() && report.errors.is_empty());
    assert_eq!(r.store.value("ghost").as_deref(), Some("local"));
    assert!(!r.state.base.contains_key("ghost"));
    assert_eq!(r.world().ciphers.len(), 1);
}

#[test]
fn never_pushes_or_creates_for_a_secret_this_device_does_not_hold() {
    let mut r = Rig::obsidian();
    let c = r.add("k", "remote");
    r.ok();
    let rev = r.world().cipher(&c)["revisionDate"].clone();
    r.store.remove("k");
    // The planner restores it (a pull); a push read from the same missing value must do nothing.
    let report = r.sync_edited(|a| {
        a.insert(0, Action::Push { id: "k".into(), confirmed: false });
        a.insert(0, Action::Create("k".into()));
    });
    assert!(report.pushed.is_empty() && report.created.is_empty() && report.errors.is_empty());
    assert_eq!(r.world().cipher(&c)["revisionDate"], rev);
    assert_eq!(r.store.value("k").as_deref(), Some("remote"));
}

#[test]
fn refuses_to_push_to_an_organization_item_the_secret_was_not_synced_with_even_confirmed() {
    let mut r = Rig::obsidian();
    let personal = r.add("api-key", "mine");
    r.add("pad", "p");
    r.ok();
    r.world().trash(&personal);
    let planted = r.add_org("api-key", "planted");
    r.store.put("api-key", "edited");
    let report = r.sync_edited(|a| {
        for x in a.iter_mut().filter(|x| matches!(x, Action::Conflict { id, .. } if id == "api-key")) {
            *x = Action::Push { id: "api-key".into(), confirmed: true };
        }
    });
    assert!(report.pushed.is_empty());
    assert_eq!(
        errors(&report),
        [(
            "api-key".to_owned(),
            "refusing to upload to an organization item this secret was not synced with".to_owned()
        )]
    );
    assert_eq!(r.remote(&planted), "planted");
    assert_eq!(r.state.base["api-key"].cipher_id, personal);
}

#[test]
fn refuses_the_first_push_to_an_organization_item_without_confirmation() {
    let mut r = Rig::obsidian();
    let c = r.add_org("team-token", "theirs");
    r.ok();
    r.store.put("team-token", "mine");
    let report = r.sync_edited(|a| {
        for x in a.iter_mut() {
            *x = Action::Push { id: "team-token".into(), confirmed: false };
        }
    });
    assert!(report.pushed.is_empty());
    assert_eq!(
        errors(&report),
        [("team-token".to_owned(), "refusing to upload to an organization item without your confirmation".to_owned())]
    );
    assert_eq!(r.remote(&c), "theirs");
    assert!(!r.state.base["team-token"].push_confirmed);
}

#[test]
fn conflict_codes_and_error_texts_carry_no_value() {
    let codes: Vec<&str> = [
        ConflictKind::BothChanged,
        ConflictKind::LocalUnsynced,
        ConflictKind::DeletedRemotely,
        ConflictKind::OrganizationClaim,
        ConflictKind::OrganizationPush,
    ]
    .map(ConflictKind::code)
    .to_vec();
    assert_eq!(
        codes,
        ["both-changed", "local-unsynced", "deleted-remotely", "organization-claim", "organization-push"]
    );
    assert_eq!(ApplyError::NotText.to_string(), "the value is not text");
    assert_eq!(SyncError::Cancelled.to_string(), "Bitwarden was locked during the sync");
}
