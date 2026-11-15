//! The vault client's writers against a scripted server: each refetches first, an out-of-date copy or answer is
//! refused without a retry (§6.5), and a trash never purges.

use super::write_tests::Rig;
use super::*;
use crate::api::ApiError;
use crate::testing::block_on;
use crate::vault::client::{ClientEdit, NewEntry, NewKind};
use crate::vault::write::WriteError;
use serde_json::json;
use zeroize::Zeroizing;

const REV: &str = "2026-01-01T00:00:00Z";

fn rename(to: &str) -> ClientEdit {
    ClientEdit { base_revision: REV.into(), name: Some(Zeroizing::new(to.into())), ..ClientEdit::default() }
}

impl Rig {
    fn client_update(&mut self, edit: &ClientEdit) -> Result<Option<serde_json::Value>, SyncWriteError> {
        block_on(client_update(&mut self.client, &self.keys.user, &self.keys.orgs, &self.rng, 1_000, "c1", edit))
    }

    fn client_trash(&mut self, base: &str) -> Result<(), SyncWriteError> {
        block_on(client_trash(&mut self.client, &self.keys.user, &self.keys.orgs, "c1", base))
    }
}

#[test]
fn a_create_posts_a_personal_item() {
    let mut r = Rig::new();
    let entry = NewEntry {
        name: Zeroizing::new("N".into()),
        notes: Zeroizing::default(),
        folder_id: None,
        kind: NewKind::SecureNote,
    };
    r.fake.echo();
    let reply = block_on(client_create(&mut r.client, &r.keys.user, 0, &r.rng, &entry)).unwrap();
    assert_eq!(
        (&reply["id"], &reply["organizationId"], &reply["encryptedFor"]),
        (&json!("created"), &json!(null), &json!("user-1"))
    );
    assert_eq!(r.log(), ["Post /ciphers"]);
    let empty = NewEntry { name: Zeroizing::default(), ..entry };
    let refused = block_on(client_create(&mut r.client, &r.keys.user, 0, &r.rng, &empty));
    assert!(matches!(refused, Err(SyncWriteError::Write(WriteError::NameRequired))));
    assert_eq!(r.log().len(), 1, "nothing sent");
}

#[test]
fn an_edit_is_applied_to_the_copy_fetched_first() {
    let mut r = Rig::new();
    let c = r.note(REV, &[("bwss:id", "x", false)]);
    r.fake.reply(200, c.clone());
    r.fake.echo();
    let reply = r.client_update(&rename("New")).unwrap().unwrap();
    assert_eq!(r.log(), ["Get /ciphers/c1", "Put /ciphers/c1"]);
    assert_eq!(reply["fields"], c["fields"], "the marker passes through");
    assert_eq!(reply["lastKnownRevisionDate"], json!(REV));
    // The same name: nothing is sent after the fetch.
    r.fake.reply(200, c);
    assert!(r.client_update(&rename("Note")).unwrap().is_none());
    assert_eq!(r.log().len(), 3);
}

#[test]
fn an_edit_out_of_date_is_refused_never_reapplied() {
    let mut r = Rig::new();
    // The server's copy moved on since the edit was planned.
    r.fake.reply(200, r.note("2026-02-02T00:00:00Z", &[]));
    assert!(matches!(r.client_update(&rename("New")), Err(SyncWriteError::Write(WriteError::OutOfDate))));
    assert_eq!(r.log(), ["Get /ciphers/c1"]);
    // It moves on between the fetch and the write: the server's refusal is the same refusal.
    r.fake.reply(200, r.note(REV, &[]));
    r.fake.out_of_date();
    assert!(matches!(r.client_update(&rename("New")), Err(SyncWriteError::Write(WriteError::OutOfDate))));
    assert_eq!(r.log().len(), 3, "no refetch, no second write");
}

#[test]
fn a_gone_item_or_a_server_error_ends_an_edit() {
    let mut r = Rig::new();
    r.fake.reply(404, json!({}));
    assert!(matches!(r.client_update(&rename("New")), Err(SyncWriteError::Write(WriteError::Gone))));
    r.fake.reply(500, json!({}));
    assert!(matches!(r.client_update(&rename("New")), Err(SyncWriteError::Api(ApiError::Http { status: 500, .. }))));
    r.fake.reply(200, r.note(REV, &[]));
    r.fake.reply(500, json!({}));
    assert!(matches!(r.client_update(&rename("New")), Err(SyncWriteError::Api(ApiError::Http { status: 500, .. }))));
}

#[test]
fn a_trash_moves_the_current_copy_to_the_trash() {
    let mut r = Rig::new();
    r.fake.reply(200, r.note(REV, &[]));
    r.fake.reply(200, json!({}));
    r.client_trash(REV).unwrap();
    assert_eq!(r.log(), ["Get /ciphers/c1", "Put /ciphers/c1/delete"]);
    // Planned on another revision, or already in the trash: nothing is sent.
    r.fake.reply(200, r.note(REV, &[]));
    assert!(matches!(r.client_trash("2025-01-01T00:00:00Z"), Err(SyncWriteError::Write(WriteError::OutOfDate))));
    let mut trashed = r.note(REV, &[]);
    trashed["deletedDate"] = json!("2026-03-03T00:00:00Z");
    r.fake.reply(200, trashed);
    assert!(matches!(r.client_trash(REV), Err(SyncWriteError::Write(WriteError::Gone))));
    r.fake.reply(404, json!({}));
    assert!(matches!(r.client_trash(REV), Err(SyncWriteError::Write(WriteError::Gone))));
    assert_eq!(r.log().len(), 5);
}
