#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use dybw_core::api::{ApiKey, Client, DeviceInfo, origin_of, resolve_server_urls};
use dybw_core::crypto::SymmetricKey;
use dybw_core::testing::{FixedClock, SeededRandom, block_on};
use dybw_vectors::canonical::{NOW, canonicalize, drop_tool_defined};
use dybw_vectors::keys::account_keys;
use dybw_vectors::server::{Sent, VectorServer, urls};
use dybw_vectors::vectors_dir;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[test]
fn scenario_keys_load() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    assert!(keys.orgs.is_empty());
    assert!(keys.profile["key"].as_str().unwrap().starts_with("2."));
    let keys = account_keys(&dir, "org", true);
    assert_eq!(keys.orgs.keys().collect::<Vec<_>>(), ["org-a", "org-b"]);
    // The profile carries the private key wrapped under the user key, and the organizations' wrapped keys.
    let wrapped = keys.profile["privateKey"].as_str().unwrap();
    assert!(keys.user.decrypt_pkcs8(wrapped).is_ok());
    assert_eq!(keys.profile["organizations"][0]["key"].as_str().unwrap().split('.').next(), Some("4"));
}

fn client(server: VectorServer) -> Client<VectorServer, FixedClock> {
    let device = DeviceInfo {
        identifier: "vectors-device".into(),
        name: "vectors".into(),
        device_type: 8,
        client_name: "cli".into(),
        client_version: "0".into(),
    };
    Client::new(server, FixedClock { now_ms: 0 }, urls(), device).unwrap()
}

fn api_key() -> ApiKey {
    ApiKey {
        origin: origin_of(&resolve_server_urls("https://vectors.invalid").unwrap().identity).unwrap(),
        client_id: "vectors".into(),
        client_secret: Zeroizing::new("vectors".into()),
    }
}

#[test]
fn server_serves_routes_and_records_writes() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    let cipher = json!({ "id": "c1", "name": "n", "revisionDate": "2026-01-01T00:00:00.000Z" });
    let server = VectorServer::new(keys.profile, vec![cipher], keys.prelogin);
    let mut api = client(server.clone());
    block_on(async {
        assert!(matches!(
            api.prelogin("x").await.unwrap(),
            dybw_core::crypto::KdfParams::Pbkdf2 { iterations: 600_000 }
        ));
        api.login(&api_key()).await.unwrap();
        let sync = api.sync().await.unwrap();
        assert_eq!(sync["ciphers"][0]["id"], "c1");
        assert_eq!(api.get_cipher("c1").await.unwrap()["name"], "n");
        assert_eq!(
            api.get_cipher("nope").await.unwrap_err().to_string(),
            "HTTP 404 (server says: not faked: GET /api/ciphers/nope)"
        );
        let made = api.create_folder("2.x").await.unwrap();
        assert_eq!(made["id"], "folder-created");
        let body = json!({ "name": "2.y", "x1": 1 }).as_object().unwrap().clone();
        let put = api.update_cipher("c1", body.clone()).await.unwrap();
        assert_eq!((put["id"].as_str(), put["revisionDate"].as_str()), (Some("c1"), Some("2026-12-01T00:00:00.000Z")));
        assert_eq!(put["name"], "2.y");
        let post = api.create_cipher(body).await.unwrap();
        assert_eq!(post["id"], "cipher-created");
        api.trash_cipher("c1").await.unwrap();
    });
    let sent = server.sent.borrow();
    assert_eq!(sent.len(), 3);
    assert!(matches!(&sent[0], Sent::Put { cipher, .. } if cipher == "c1"));
    assert!(matches!(&sent[1], Sent::Post { .. }));
    assert!(matches!(&sent[2], Sent::Trash { cipher } if cipher == "c1"));
}

#[test]
fn fresh_rejects_the_first_put_and_serves_the_new_copy() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    let server = VectorServer::new(keys.profile, vec![json!({ "id": "c1", "name": "old" })], keys.prelogin);
    *server.fresh.borrow_mut() = Some(json!({ "id": "c1", "name": "fresh" }));
    let mut api = client(server.clone());
    block_on(async {
        api.login(&api_key()).await.unwrap();
        api.sync().await.unwrap();
        let err = api.update_cipher("c1", serde_json::Map::new()).await.unwrap_err();
        assert!(err.is_out_of_date(), "{err}");
        assert_eq!(api.get_cipher("c1").await.unwrap()["name"], "fresh");
        api.update_cipher("c1", serde_json::Map::new()).await.unwrap();
    });
    assert_eq!(server.sent.borrow().len(), 1, "the rejected write is not recorded");
    assert_eq!(server.rejected.get(), 1);
}

#[test]
fn canonicalize_decrypts_with_the_item_key_and_marks_now() {
    let dir = vectors_dir().unwrap();
    let keys = account_keys(&dir, "pbkdf2", false);
    let rng = SeededRandom::new(7);
    let item = SymmetricKey::generate(&rng).unwrap();
    let enc = |s: &str| Value::String(item.encrypt_str(s, &rng).unwrap());
    let body = json!({
        "type": 1, "name": enc("nm"), "notes": null, "folderId": null, "organizationId": null,
        "key": keys.user.encrypt(&item.to_bytes(), &rng).unwrap(),
        "login": { "username": enc("u"), "password": enc("p"), "uris": [{ "uri": enc("https://a.invalid") }], "totp": null },
        "passwordHistory": [{ "password": enc("old") }],
        "fields": [{ "name": enc("bwss:id"), "value": enc("alpha"), "type": 0 }, { "name": enc("bwss:x"), "value": null, "type": 1 }],
        "lastKnownRevisionDate": NOW, "xKeep": 1, "other": 2,
    });
    let sent = Sent::Put { cipher: "c1".into(), body };
    let got = canonicalize(&sent, &keys.user, &BTreeMap::new()).unwrap();
    assert_eq!(got["name"], "nm");
    assert_eq!(got["login"]["passwordHistory"], json!(["old"]));
    assert_eq!(got["login"]["uris"], json!(["https://a.invalid"]));
    assert_eq!(got["lastKnownRevisionDate"], "<now>");
    assert_eq!((got["hasItemKey"].as_bool(), &got["extra"]), (Some(true), &json!({ "xKeep": 1 })));
    // Only a POST loses its name and tool-defined fields.
    assert_eq!(drop_tool_defined(got.clone(), "bwss"), got);
    let mut post = got.clone();
    post["method"] = json!("POST");
    let post = drop_tool_defined(post, "bwss");
    assert!(post.get("name").is_none());
    assert_eq!(post["fields"].as_array().unwrap().len(), 1);
    assert_eq!(
        canonicalize(&Sent::Trash { cipher: "c1".into() }, &keys.user, &BTreeMap::new()).unwrap(),
        json!({ "method": "trash", "cipher": "c1" })
    );
    // A wrong key is an error, not a panic.
    let other = SymmetricKey::generate(&rng).unwrap();
    assert!(canonicalize(&sent, &other, &BTreeMap::new()).is_err());
}
