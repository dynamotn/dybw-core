//! The writer against a scripted server: the retry on "out of date" (§6.5), `StillChanging`, and the delete steps
//! of bwss `runner.rs`.

use super::*;
use crate::api::{ApiError, ApiKey, Client, DeviceInfo, resolve_server_urls};
use crate::crypto::{MarkScheme, Marker, SymmetricKey};
use crate::ports::{Http, HttpRequest, HttpResponse, Method, PortError};
use crate::testing::{FixedClock, SeededRandom, block_on};
use crate::vault::scan::{Scan, ValueSource, scan};
use crate::vault::write::{FieldSet, NewItem, Patch, ValueChange, WriteError};
use crate::vault::{Keys, Namespace, Organizations, Uninspectable};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use zeroize::Zeroizing;

const B: &Namespace = &Namespace::BWSS;
const OUT_OF_DATE: &str = "The client copy of this cipher is out of date. Resubmit with the current revision date.";

/// What the scripted server answers to the next request.
enum Reply {
    Json(u16, Value),
    /// The request body back, plus the server's `id` and `revisionDate` (what a real update answers).
    Echo,
}

#[derive(Clone, Default)]
struct Fake {
    log: Rc<RefCell<Vec<String>>>,
    replies: Rc<RefCell<VecDeque<Reply>>>,
}

impl Http for Fake {
    fn refuses_redirects(&self) -> bool {
        true
    }
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        let path = req.url.split_once("/api").map_or(req.url.as_str(), |(_, p)| p).to_owned();
        self.log.borrow_mut().push(format!("{:?} {path}", req.method));
        let reply = self.replies.borrow_mut().pop_front().ok_or_else(|| PortError("no reply queued".into()))?;
        let (status, body) = match reply {
            Reply::Json(status, body) => (status, body),
            Reply::Echo => {
                let mut body: Value = serde_json::from_slice(req.body.as_deref().map_or(&[][..], Vec::as_slice))
                    .map_err(|_| PortError("not JSON".into()))?;
                body["id"] = json!(if req.method == Method::Post { "created" } else { "c1" });
                body["revisionDate"] = json!("2026-03-03T00:00:00Z");
                (200, body)
            }
        };
        Ok(HttpResponse { status, body: Zeroizing::new(body.to_string().into_bytes()) })
    }
}

struct Rig {
    client: Client<Fake, FixedClock>,
    fake: Fake,
    keys: Keys,
    other: SymmetricKey,
    rng: SeededRandom,
}

impl Rig {
    fn new() -> Self {
        let rng = SeededRandom::new(11);
        let user = SymmetricKey::generate(&rng).unwrap();
        let other = SymmetricKey::generate(&rng).unwrap();
        let keys = Keys { marker: Marker::new(&user, MarkScheme::Bwss), user, orgs: BTreeMap::new() };
        let fake = Fake::default();
        let device = DeviceInfo {
            identifier: "d".into(),
            name: "d".into(),
            device_type: 8,
            client_name: "t".into(),
            client_version: "0".into(),
        };
        let urls = resolve_server_urls("https://bw.example.org").unwrap();
        let mut client = Client::new(fake.clone(), FixedClock { now_ms: 0 }, urls, device).unwrap();
        let key = ApiKey {
            origin: "https://bw.example.org".into(),
            client_id: "user.x".into(),
            client_secret: Zeroizing::new("s".into()),
        };
        fake.reply(200, json!({ "access_token": "t", "expires_in": 3600 }));
        block_on(client.login(&key)).unwrap();
        fake.reply(200, json!({ "profile": { "id": "user-1", "key": "2.uk" }, "folders": [], "ciphers": [] }));
        block_on(client.sync()).unwrap();
        fake.log.borrow_mut().clear();
        Rig { client, fake, keys, other, rng }
    }

    fn enc(&self, key: &SymmetricKey, s: &str) -> Value {
        json!(key.encrypt_str(s, &self.rng).unwrap())
    }

    /// A secure note c1 with these `(name, value, hidden)` fields and revision `rev`.
    fn note_under(&self, key: &SymmetricKey, rev: &str, fields: &[(&str, &str, bool)]) -> Value {
        let fields: Vec<Value> = fields
            .iter()
            .map(|(n, v, h)| json!({ "type": u64::from(*h), "name": self.enc(key, n), "value": self.enc(key, v) }))
            .collect();
        json!({
            "id": "c1", "type": 2, "organizationId": null, "folderId": null, "revisionDate": rev,
            "name": self.enc(key, "Note"), "notes": null, "secureNote": { "type": 0 },
            "passwordHistory": [], "fields": fields,
        })
    }

    fn note(&self, rev: &str, fields: &[(&str, &str, bool)]) -> Value {
        self.note_under(&self.keys.user, rev, fields)
    }

    /// The tool's own item: `bwss:id` x, value `secret` in `bwss:password`.
    fn bare(&self, rev: &str, secret: &str) -> Value {
        self.note(rev, &[("bwss:id", "x", false), ("bwss:password", secret, true)])
    }

    fn patch_for(&self, cipher: &Value, secret: &[u8]) -> Patch {
        let Scan::Marked(m) = scan(cipher, B, &self.keys, &Organizations::All) else { panic!("not marked") };
        Patch {
            id: m.id.clone(),
            cipher_id: Some(m.cipher_id.clone()),
            base_revision: m.revision_date.clone(),
            set: vec![FieldSet { name: "bwss:label".into(), value: Zeroizing::new("l".into()), hidden: false }],
            remove: Vec::new(),
            value: ValueChange::Set {
                source: ValueSource::Field,
                secret: Zeroizing::new(secret.to_vec()),
                base_mark: m.mark,
                owned: false,
            },
        }
    }

    fn update(&mut self, cipher: &Value, patch: &Patch) -> Result<Option<Value>, SyncWriteError> {
        block_on(update(&mut self.client, B, &self.keys, &self.rng, 1_000, cipher, patch))
    }

    fn delete(&mut self, cipher: &Value) -> Result<DeleteOutcome, SyncWriteError> {
        block_on(delete(&mut self.client, B, &self.keys, &self.rng, cipher))
    }

    fn log(&self) -> Vec<String> {
        self.fake.log.borrow().clone()
    }
}

impl Fake {
    fn reply(&self, status: u16, body: Value) {
        self.replies.borrow_mut().push_back(Reply::Json(status, body));
    }
    fn out_of_date(&self) {
        self.reply(400, json!({ "message": OUT_OF_DATE }));
    }
    fn echo(&self) {
        self.replies.borrow_mut().push_back(Reply::Echo);
    }
}

#[test]
fn update_sends_once_and_returns_the_reply() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    r.fake.echo();
    let reply = r.update(&c, &patch).unwrap().unwrap();
    assert_eq!(reply["revisionDate"], "2026-03-03T00:00:00Z");
    assert_eq!(reply["lastKnownRevisionDate"], "2026-01-01T00:00:00Z");
    assert_eq!(r.log(), ["Put /ciphers/c1"]);
}

#[test]
fn out_of_date_reapplies_the_patch_to_the_fresh_copy() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    r.fake.out_of_date();
    r.fake.reply(200, r.bare("2026-02-02T00:00:00Z", "old"));
    r.fake.echo();
    let reply = r.update(&c, &patch).unwrap().unwrap();
    assert_eq!(reply["lastKnownRevisionDate"], "2026-02-02T00:00:00Z");
    assert_eq!(r.log(), ["Put /ciphers/c1", "Get /ciphers/c1", "Put /ciphers/c1"]);
}

#[test]
fn out_of_date_forever_gives_up_after_three() {
    // Review Focus 5: 3 PUTs and 2 GETs, then StillChanging; nothing else is sent.
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    for _ in 0..ATTEMPTS {
        r.fake.out_of_date();
        r.fake.reply(200, r.bare("2026-02-02T00:00:00Z", "old"));
    }
    assert!(matches!(r.update(&c, &patch), Err(SyncWriteError::StillChanging)));
    assert_eq!(
        r.log(),
        ["Put /ciphers/c1", "Get /ciphers/c1", "Put /ciphers/c1", "Get /ciphers/c1", "Put /ciphers/c1"]
    );
    // The patch is intact: the caller can queue it.
    assert!(matches!(patch.value, ValueChange::Set { .. }));
}

#[test]
fn refetch_404_is_gone() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    r.fake.out_of_date();
    r.fake.reply(404, json!({ "message": "not found" }));
    assert!(matches!(r.update(&c, &patch), Err(SyncWriteError::Write(WriteError::Gone))));
    assert_eq!(r.log(), ["Put /ciphers/c1", "Get /ciphers/c1"]);
}

#[test]
fn refetch_failure_other_than_404_is_an_api_error() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    r.fake.out_of_date();
    r.fake.reply(500, json!({}));
    assert!(matches!(r.update(&c, &patch), Err(SyncWriteError::Api(ApiError::Http { status: 500, .. }))));
}

#[test]
fn fresh_copy_with_another_value_ends_the_retry() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    r.fake.out_of_date();
    r.fake.reply(200, r.bare("2026-02-02T00:00:00Z", "someone else's"));
    assert!(matches!(r.update(&c, &patch), Err(SyncWriteError::Write(WriteError::SourceChanged))));
    assert_eq!(r.log(), ["Put /ciphers/c1", "Get /ciphers/c1"]);
}

#[test]
fn fresh_copy_without_the_marker_ends_the_retry() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    r.fake.out_of_date();
    r.fake.reply(200, r.note("2026-02-02T00:00:00Z", &[("pin", "1", false)]));
    assert!(matches!(r.update(&c, &patch), Err(SyncWriteError::Write(WriteError::Unmarked))));
}

#[test]
fn other_rejections_are_not_retried() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    r.fake.reply(500, json!({ "message": "boom" }));
    assert!(matches!(r.update(&c, &patch), Err(SyncWriteError::Api(ApiError::Http { status: 500, .. }))));
    assert_eq!(r.log(), ["Put /ciphers/c1"]);
}

#[test]
fn a_write_that_cannot_be_built_sends_nothing() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    let gone = {
        let mut g = c.clone();
        g["deletedDate"] = json!("2026-02-02T00:00:00Z");
        g
    };
    assert!(matches!(r.update(&gone, &patch), Err(SyncWriteError::Write(WriteError::Gone))));
    assert!(r.log().is_empty());
}

fn new_item() -> NewItem {
    NewItem {
        id: "x".into(),
        value: Zeroizing::new(b"v".to_vec()),
        name: "Note".into(),
        folder_id: None,
        tool_fields: vec![],
    }
}

#[test]
fn create_posts_the_new_item() {
    let mut r = Rig::new();
    r.fake.echo();
    let reply = block_on(create(&mut r.client, B, &r.keys, &r.rng, &new_item())).unwrap();
    assert_eq!(reply["id"], "created");
    assert_eq!(reply["type"], 2);
    assert_eq!(r.log(), ["Post /ciphers"]);
}

#[test]
fn create_errors_pass_through() {
    let mut r = Rig::new();
    let mut too_long = new_item();
    too_long.value = Zeroizing::new(vec![b'a'; 20_000]);
    assert!(matches!(
        block_on(create(&mut r.client, B, &r.keys, &r.rng, &too_long)),
        Err(SyncWriteError::Write(WriteError::TooLong))
    ));
    r.fake.reply(500, json!({}));
    assert!(matches!(
        block_on(create(&mut r.client, B, &r.keys, &r.rng, &new_item())),
        Err(SyncWriteError::Api(ApiError::Http { status: 500, .. }))
    ));
}

#[test]
fn delete_strips_then_trashes_a_bare_item() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "s");
    r.fake.echo();
    r.fake.reply(200, json!({}));
    assert!(matches!(r.delete(&c).unwrap(), DeleteOutcome::Trashed));
    assert_eq!(r.log(), ["Put /ciphers/c1", "Put /ciphers/c1/delete"]);
}

#[test]
fn delete_keeps_an_item_with_foreign_content() {
    let mut r = Rig::new();
    let c =
        r.note("2026-01-01T00:00:00Z", &[("bwss:id", "x", false), ("bwss:password", "s", true), ("pin", "1", false)]);
    r.fake.echo();
    assert!(matches!(r.delete(&c).unwrap(), DeleteOutcome::KeptForeign));
    assert_eq!(r.log(), ["Put /ciphers/c1"]);
}

#[test]
fn delete_keeps_an_item_whose_reply_cannot_be_read() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "s");
    let unreadable = r.note_under(&r.other, "2026-03-03T00:00:00Z", &[("bwss:id", "x", false)]);
    r.fake.reply(200, unreadable);
    assert!(matches!(r.delete(&c).unwrap(), DeleteOutcome::Unreadable(WriteError::Crypto(_))));
    assert_eq!(r.log(), ["Put /ciphers/c1"]);
}

#[test]
fn delete_leaves_a_stripped_item_when_the_trash_fails() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "s");
    r.fake.echo();
    r.fake.reply(500, json!({}));
    assert!(matches!(r.delete(&c).unwrap(), DeleteOutcome::Stripped { trash: ApiError::Http { status: 500, .. } }));
    // the cause is kept for any failure, not only a server error
    let mut r = Rig::new();
    r.fake.echo();
    r.fake.reply(401, json!({}));
    assert!(matches!(r.delete(&c).unwrap(), DeleteOutcome::Stripped { trash: ApiError::Http { status: 401, .. } }));
}

#[test]
fn delete_of_what_is_not_the_tools_does_nothing() {
    let mut r = Rig::new();
    let unmarked = r.note("2026-01-01T00:00:00Z", &[("pin", "1", false)]);
    assert!(matches!(r.delete(&unmarked).unwrap(), DeleteOutcome::Nothing));
    let mut trashed = r.bare("2026-01-01T00:00:00Z", "s");
    trashed["deletedDate"] = json!("2026-02-02T00:00:00Z");
    assert!(matches!(r.delete(&trashed).unwrap(), DeleteOutcome::Nothing));
    assert!(r.log().is_empty());
}

#[test]
fn delete_of_an_unreadable_item_is_held() {
    let mut r = Rig::new();
    let c = r.note_under(&r.other, "2026-01-01T00:00:00Z", &[("bwss:id", "x", false)]);
    assert!(matches!(r.delete(&c), Err(SyncWriteError::Write(WriteError::Uninspectable(Uninspectable::FieldNames)))));
    assert!(r.log().is_empty());
}

#[test]
fn delete_starts_over_on_the_fresh_copy() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "s");
    r.fake.out_of_date();
    r.fake.reply(200, r.bare("2026-02-02T00:00:00Z", "s"));
    r.fake.echo();
    r.fake.reply(200, json!({}));
    assert!(matches!(r.delete(&c).unwrap(), DeleteOutcome::Trashed));
    assert_eq!(r.log(), ["Put /ciphers/c1", "Get /ciphers/c1", "Put /ciphers/c1", "Put /ciphers/c1/delete"]);
}

#[test]
fn delete_is_done_when_the_item_left_meanwhile() {
    let mut gone = Rig::new();
    let c = gone.bare("2026-01-01T00:00:00Z", "s");
    gone.fake.out_of_date();
    gone.fake.reply(404, json!({}));
    assert!(matches!(gone.delete(&c).unwrap(), DeleteOutcome::Nothing));

    // Re-marked elsewhere (another `bwss:id`) or no longer the tool's: it has left the keyring.
    for fields in [vec![("pin", "1", false)], vec![("bwss:id", "y", false)]] {
        let mut r = Rig::new();
        r.fake.out_of_date();
        r.fake.reply(200, r.note("2026-02-02T00:00:00Z", &fields));
        assert!(matches!(r.delete(&c).unwrap(), DeleteOutcome::Nothing));
        assert_eq!(r.log(), ["Put /ciphers/c1", "Get /ciphers/c1"]);
    }
}

#[test]
fn delete_gives_up_after_three_and_other_errors_pass() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "s");
    for _ in 0..ATTEMPTS {
        r.fake.out_of_date();
        r.fake.reply(200, r.bare("2026-02-02T00:00:00Z", "s"));
    }
    assert!(matches!(r.delete(&c), Err(SyncWriteError::StillChanging)));
    assert_eq!(r.log().len(), 5);

    let mut r = Rig::new();
    r.fake.reply(500, json!({}));
    assert!(matches!(r.delete(&c), Err(SyncWriteError::Api(ApiError::Http { status: 500, .. }))));
}

#[test]
fn delete_without_a_revision_is_held_and_sends_nothing() {
    // strip refuses a copy it cannot base the write on.
    let mut r = Rig::new();
    let mut c = r.bare("2026-01-01T00:00:00Z", "s");
    c.as_object_mut().unwrap().remove("revisionDate");
    assert!(matches!(r.delete(&c), Err(SyncWriteError::Write(WriteError::Uninspectable(Uninspectable::Value)))));
    assert!(r.log().is_empty());
}

fn keep_patch(r: &Rig, c: &Value) -> Patch {
    Patch { value: ValueChange::Keep, set: vec![], remove: vec![], ..r.patch_for(c, b"x") }
}

#[test]
fn an_empty_patch_sends_nothing() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    assert!(r.update(&c, &keep_patch(&r, &c)).unwrap().is_none());
    assert!(r.log().is_empty());
    // a patch that only removes, or only sets a tool field, is a change
    r.fake.echo();
    let remove = Patch { remove: vec!["bwss:label".into()], ..keep_patch(&r, &c) };
    assert!(r.update(&c, &remove).unwrap().is_some());
    r.fake.echo();
    let set = Patch { set: r.patch_for(&c, b"x").set, ..keep_patch(&r, &c) };
    assert!(r.update(&c, &set).unwrap().is_some());
}

#[test]
fn a_cipher_without_an_id_is_refused_before_sending() {
    let mut r = Rig::new();
    let c = r.bare("2026-01-01T00:00:00Z", "old");
    let patch = r.patch_for(&c, b"new");
    for bad in [json!(null), json!("")] {
        let mut anon = c.clone();
        anon["id"] = bad;
        assert!(matches!(r.update(&anon, &patch), Err(SyncWriteError::MissingId)));
        assert!(matches!(r.delete(&anon), Err(SyncWriteError::MissingId)));
    }
    anon_without_key(&mut r, &c, &patch);
    assert!(r.log().is_empty());
}

fn anon_without_key(r: &mut Rig, c: &Value, patch: &Patch) {
    let mut anon = c.clone();
    anon.as_object_mut().unwrap().remove("id");
    assert!(matches!(r.update(&anon, patch), Err(SyncWriteError::MissingId)));
}

#[test]
fn a_refetched_trashed_or_blob_copy_writes_nothing() {
    let mut trashed = r_bare("2026-02-02T00:00:00Z");
    trashed["deletedDate"] = json!("2026-02-03T00:00:00Z");
    let mut blob = r_bare("2026-02-02T00:00:00Z");
    blob["data"] = json!("{\"format_version\":1}");
    for fresh in [trashed, blob] {
        let blob_copy = fresh.get("data").is_some();
        // update: Gone for a trashed copy, held for a blob; the second PUT is never sent
        let mut r = Rig::new();
        let c = r.bare("2026-01-01T00:00:00Z", "old");
        let patch = r.patch_for(&c, b"new");
        r.fake.out_of_date();
        r.fake.reply(200, fresh.clone());
        match r.update(&c, &patch) {
            Err(SyncWriteError::Write(WriteError::Gone)) if !blob_copy => {}
            Err(SyncWriteError::Write(WriteError::Uninspectable(Uninspectable::NewerFormat))) if blob_copy => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(r.log(), ["Put /ciphers/c1", "Get /ciphers/c1"]);

        // delete: a trashed copy has left the keyring; a blob copy is held
        let mut r = Rig::new();
        r.fake.out_of_date();
        r.fake.reply(200, fresh);
        match r.delete(&c) {
            Ok(DeleteOutcome::Nothing) if !blob_copy => {}
            Err(SyncWriteError::Write(WriteError::Uninspectable(Uninspectable::NewerFormat))) if blob_copy => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(r.log(), ["Put /ciphers/c1", "Get /ciphers/c1"]);
    }
}

fn r_bare(rev: &str) -> Value {
    Rig::new().bare(rev, "old")
}
