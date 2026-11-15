//! `vault::client` beyond the vectors (`vectors/src/write/client/`): every refusal, the byte-for-byte pass-through of
//! a field-level and a blob edit, URI entries, the shapes of a create, and the blob parts the generator never writes.

// The parent's imports come with it: keys, `Cbor`, `OpenBlob`, `json!`, base64 and SHA-256.
use super::*;
use crate::testing::SeededRandom;
use crate::vault::blob;
use crate::vault::blob_tests::{Bx, t, tampered, versioned};

/// 2099-09-09T09:09:09.999Z, the vectors' frozen clock.
const NOW: i64 = 4_092_628_149_999;
const NOW_ISO: &str = "2099-09-09T09:09:09.999Z";
const REV: &str = "2026-01-02T03:04:05.000Z";
const RESPONSE_ONLY: [&str; 12] = [
    "id",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "object",
    "edit",
    "viewPassword",
    "permissions",
    "collectionIds",
    "attachments",
    "organizationUseTotp",
    "data",
];

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn uri(u: &str, m: Option<u64>) -> NewUri {
    NewUri { uri: z(u), match_type: m }
}

fn base() -> ClientEdit {
    ClientEdit { base_revision: REV.into(), ..ClientEdit::default() }
}

struct Cx {
    rng: SeededRandom,
    user: SymmetricKey,
    orgs: BTreeMap<String, SymmetricKey>,
}

fn cx() -> Cx {
    let rng = SeededRandom::new(5);
    let user = SymmetricKey::generate(&rng).unwrap();
    let org = SymmetricKey::generate(&rng).unwrap();
    Cx { rng, user, orgs: BTreeMap::from([("org1".to_owned(), org)]) }
}

/// The plaintext of an EncString, `None` for null.
fn d(key: &SymmetricKey, v: &Value) -> Option<String> {
    v.as_str().map(|s| key.decrypt_str(s).unwrap().as_str().to_owned())
}

impl Cx {
    fn e(&self, key: &SymmetricKey, s: &str) -> Value {
        json!(key.encrypt_str(s, &self.rng).unwrap())
    }

    fn org(&self) -> &SymmetricKey {
        &self.orgs["org1"]
    }

    /// A login with its own key under `owner`, marked by two tools, with unknown keys everywhere. Returns the
    /// cipher and its item key.
    fn login(&self, owner: &SymmetricKey, org: Option<&str>) -> (Value, SymmetricKey) {
        let item = SymmetricKey::generate(&self.rng).unwrap();
        let e = |s: &str| self.e(&item, s);
        let cipher = json!({
            "id": "c1", "type": 1, "organizationId": org, "folderId": "f1", "revisionDate": REV,
            "creationDate": "2025-01-01T00:00:00.000Z", "deletedDate": null, "object": "cipherDetails",
            "edit": true, "viewPassword": true, "permissions": { "delete": true }, "collectionIds": ["col1"],
            "attachments": [{ "id": "a1" }], "organizationUseTotp": true, "favorite": true, "reprompt": 1,
            "key": owner.encrypt_as(&item.to_bytes(), ContentFormat::LegacyKey, &self.rng).unwrap(),
            "name": e("Mail"), "notes": e("user notes"),
            "login": {
                "username": e("me"), "password": e("old-pw"), "passwordRevisionDate": "2020-01-01T00:00:00.000Z",
                "totp": e("JBSWY3DPEHPK3PXP"), "fido2Credentials": [{ "credentialId": "x" }],
                "autofillOnPageLoad": null,
                "uris": [
                    { "uri": e("https://a.invalid"), "match": null, "uriChecksum": e("chk-a"), "xKeep": 1 },
                    { "uri": e("https://b.invalid"), "match": 3 },
                ],
            },
            "passwordHistory": [{ "password": e("older"), "lastUsedDate": "2021-01-01T00:00:00.000Z" }],
            "fields": [
                { "type": 0, "name": e("bwss:id"), "value": e("x"), "linkedId": null },
                { "type": 1, "name": e("obsidian:password"), "value": e("tool-secret"), "linkedId": null },
                { "type": 0, "name": e("plain"), "value": e("v"), "linkedId": null },
            ],
            "xUnknown": { "a": [1, 2] },
        });
        (cipher, item)
    }

    /// A field-level secure note under the user key, without its part, with these `(name, value)` fields.
    fn note(&self, fields: &[(Option<&str>, &str)]) -> Value {
        let fields: Vec<Value> = fields
            .iter()
            .map(
                |(n, v)| json!({ "type": 0, "name": n.map(|n| self.e(&self.user, n)), "value": self.e(&self.user, v) }),
            )
            .collect();
        json!({
            "id": "n1", "type": 2, "organizationId": null, "folderId": null, "revisionDate": REV,
            "name": self.e(&self.user, "Note"), "notes": self.e(&self.user, "held"), "secureNote": null,
            "fields": fields,
        })
    }

    fn edit(&self, c: &Value, e: &ClientEdit) -> Result<Option<Map<String, Value>>, WriteError> {
        edit(c, e, &self.user, &self.orgs, &self.rng, NOW)
    }
}

/// Every key of `cipher` but the response-only ones and `except` is in `body`, unchanged.
fn passes_through(cipher: &Value, body: &Map<String, Value>, except: &[&str]) {
    for (k, v) in cipher.as_object().unwrap() {
        if except.contains(&k.as_str()) {
            continue;
        }
        if RESPONSE_ONLY.contains(&k.as_str()) {
            assert!(!body.contains_key(k), "{k} is response-only");
        } else {
            assert_eq!(body.get(k), Some(v), "{k}");
        }
    }
}

#[test]
fn a_password_change_pushes_the_old_one_and_keeps_everything_else() {
    let cx = cx();
    let (c, item) = cx.login(&cx.user, None);
    let e = ClientEdit { password: Some(z("new-pw")), ..base() };
    let body = cx.edit(&c, &e).unwrap().unwrap();
    passes_through(&c, &body, &["login", "passwordHistory"]);
    assert_eq!(body["lastKnownRevisionDate"], json!(REV));
    let login = body["login"].as_object().unwrap();
    for (k, v) in c["login"].as_object().unwrap() {
        if !["password", "passwordRevisionDate"].contains(&k.as_str()) {
            assert_eq!(login[k], *v, "login.{k}");
        }
    }
    assert_eq!(d(&item, &login["password"]).as_deref(), Some("new-pw"));
    assert_eq!(login["passwordRevisionDate"], json!(NOW_ISO));
    // The old password moves as it was, still encrypted, in front of the history.
    let history = body["passwordHistory"].as_array().unwrap();
    assert_eq!(history[0], json!({ "password": c["login"]["password"], "lastUsedDate": NOW_ISO }));
    assert_eq!(history[1], c["passwordHistory"][0]);
    assert_eq!(history.len(), 2);
}

#[test]
fn name_notes_username_and_folder_change_and_clear() {
    let cx = cx();
    let (c, item) = cx.login(&cx.user, None);
    let e = ClientEdit {
        name: Some(z("New name")),
        notes: Some(z("")),
        username: Some(z("")),
        folder_id: Some(None),
        ..base()
    };
    let body = cx.edit(&c, &e).unwrap().unwrap();
    passes_through(&c, &body, &["name", "notes", "login", "folderId"]);
    assert_eq!(d(&item, &body["name"]).as_deref(), Some("New name"));
    assert_eq!(
        (&body["notes"], &body["login"]["username"], &body["folderId"]),
        (&json!(null), &json!(null), &json!(null))
    );
    assert_eq!(body["login"]["password"], c["login"]["password"], "no history push without a password change");
    let e = ClientEdit {
        notes: Some(z("new notes")),
        username: Some(z("you")),
        folder_id: Some(Some("f2".into())),
        ..base()
    };
    let body = cx.edit(&c, &e).unwrap().unwrap();
    assert_eq!(d(&item, &body["notes"]).as_deref(), Some("new notes"));
    assert_eq!(d(&item, &body["login"]["username"]).as_deref(), Some("you"));
    assert_eq!(body["folderId"], json!("f2"));
}

#[test]
fn an_edit_to_the_values_already_there_sends_nothing() {
    let cx = cx();
    let (c, _) = cx.login(&cx.user, None);
    let e = ClientEdit {
        name: Some(z("Mail")),
        notes: Some(z("user notes")),
        username: Some(z("me")),
        password: Some(z("old-pw")),
        uris: Some(vec![uri("https://a.invalid", None), uri("https://b.invalid", Some(3))]),
        folder_id: Some(Some("f1".into())),
        ..base()
    };
    assert!(cx.edit(&c, &e).unwrap().is_none());
    assert!(cx.edit(&c, &base()).unwrap().is_none());
}

#[test]
fn a_folder_move_alone_is_sent() {
    let cx = cx();
    let (c, _) = cx.login(&cx.user, None);
    let body = cx.edit(&c, &ClientEdit { folder_id: Some(Some("f2".into())), ..base() }).unwrap().unwrap();
    passes_through(&c, &body, &["folderId"]);
    assert_eq!(body["folderId"], json!("f2"));
}

#[test]
fn uris_keep_unchanged_entries_and_checksum_new_ones() {
    let cx = cx();
    let (c, item) = cx.login(&cx.user, None);
    let e = ClientEdit {
        uris: Some(vec![
            uri("https://b.invalid", Some(3)),
            uri("", Some(9)),
            uri("https://c.invalid", Some(4)),
            uri("https://a.invalid", Some(1)),
        ]),
        ..base()
    };
    let body = cx.edit(&c, &e).unwrap().unwrap();
    let uris = body["login"]["uris"].as_array().unwrap();
    assert_eq!(uris.len(), 3, "the empty URI is none");
    assert_eq!(uris[0], c["login"]["uris"][1], "kept as the server sent it");
    let sum = |u: &str| B64.encode(Sha256::digest(u.as_bytes()));
    for (entry, (text, kind)) in uris[1..].iter().zip([("https://c.invalid", 4), ("https://a.invalid", 1)]) {
        assert_eq!(d(&item, &entry["uri"]).as_deref(), Some(text));
        assert_eq!(entry["match"], json!(kind), "a new match is a new entry");
        assert_eq!(d(&item, &entry["uriChecksum"]), Some(sum(text)));
        assert!(entry.get("xKeep").is_none());
    }
    // As long as the old list, one URI changed: only that entry is new.
    let e = ClientEdit { uris: Some(vec![uri("https://a.invalid", None), uri("https://d.invalid", None)]), ..base() };
    let uris = cx.edit(&c, &e).unwrap().unwrap()["login"]["uris"].clone();
    assert_eq!(uris[0], c["login"]["uris"][0]);
    assert_eq!(d(&item, &uris[1]["uri"]).as_deref(), Some("https://d.invalid"));
    // A shorter list, and an emptied one.
    let e = ClientEdit { uris: Some(vec![uri("https://a.invalid", None)]), ..base() };
    assert_eq!(cx.edit(&c, &e).unwrap().unwrap()["login"]["uris"], json!([c["login"]["uris"][0]]));
    let body = cx.edit(&c, &ClientEdit { uris: Some(vec![uri("", None)]), ..base() }).unwrap().unwrap();
    assert_eq!(body["login"]["uris"], json!(null));
}

#[test]
fn a_bad_match_or_an_oversize_part_is_refused() {
    let cx = cx();
    let (c, _) = cx.login(&cx.user, None);
    let long = |n: usize| Some(z(&"x".repeat(n)));
    for (e, err) in [
        (ClientEdit { uris: Some(vec![uri("https://a.invalid", Some(6))]), ..base() }, WriteError::BadUriMatch),
        (ClientEdit { uris: Some(vec![uri(&"u".repeat(10_000), None)]), ..base() }, WriteError::TooLong),
        (ClientEdit { name: long(1_000), ..base() }, WriteError::TooLong),
        (ClientEdit { name: Some(z(" \t")), ..base() }, WriteError::NameRequired),
        (ClientEdit { notes: long(10_000), ..base() }, WriteError::TooLong),
        (ClientEdit { username: long(1_000), ..base() }, WriteError::TooLong),
        (ClientEdit { password: long(5_000), ..base() }, WriteError::TooLong),
    ] {
        assert_eq!(cx.edit(&c, &e).unwrap_err(), err);
    }
}

#[test]
fn the_copy_must_be_live_current_editable_and_readable() {
    let cx = cx();
    let (c, _) = cx.login(&cx.user, None);
    let with = |k: &str, v: Value| {
        let mut c = c.clone();
        c[k] = v;
        c
    };
    let mut no_revision = c.clone();
    no_revision.as_object_mut().unwrap().remove("revisionDate");
    let (org_item, _) = cx.login(cx.org(), Some("org1"));
    let mut read_only = org_item.clone();
    read_only["edit"] = json!(false);
    let mut other_org = org_item.clone();
    other_org["organizationId"] = json!("org2");
    let bx = Bx::new();
    let mut org_blob = bx.sealed_with(&bx.keys.orgs["org1"], &versioned(Cbor::Map(vec![])), json!(1));
    org_blob["organizationId"] = json!("org1");
    org_blob["revisionDate"] = json!(REV);
    for (cipher, err) in [
        (with("deletedDate", json!("2026-02-02T00:00:00.000Z")), WriteError::Gone),
        (with("revisionDate", json!("2026-01-02T03:04:06.000Z")), WriteError::OutOfDate),
        (no_revision, WriteError::OutOfDate),
        (with("notes", json!("x".repeat(1024 * 1024))), WriteError::Uninspectable(Uninspectable::TooLarge)),
        (read_only, WriteError::ReadOnly),
        (other_org, WriteError::Uninspectable(Uninspectable::OrganizationKeyMissing)),
        (org_blob, WriteError::Uninspectable(Uninspectable::NewerFormat)),
    ] {
        let e = ClientEdit { name: Some(z("x")), ..base() };
        assert_eq!(cx.edit(&cipher, &e).unwrap_err(), err);
        assert_eq!(check_trash(&cipher, REV, &cx.user, &cx.orgs).unwrap_err(), err);
    }
    check_trash(&c, REV, &cx.user, &cx.orgs).unwrap();
    check_trash(&org_item, REV, &cx.user, &cx.orgs).unwrap();
}

#[test]
fn an_organization_item_is_written_under_its_key() {
    let cx = cx();
    let (c, item) = cx.login(cx.org(), Some("org1"));
    let e = ClientEdit { username: Some(z("team")), password: Some(z("team-pw")), ..base() };
    let body = cx.edit(&c, &e).unwrap().unwrap();
    passes_through(&c, &body, &["login", "passwordHistory"]);
    assert_eq!(body["organizationId"], json!("org1"));
    assert_eq!(cx.org().decrypt_key(body["key"].as_str().unwrap()).unwrap().to_bytes(), item.to_bytes());
    assert_eq!(d(&item, &body["login"]["username"]).as_deref(), Some("team"));
    assert_eq!(d(&item, &body["login"]["password"]).as_deref(), Some("team-pw"));
    // A hidden password is never changed: its old value would land in the history.
    let mut hidden = c.clone();
    hidden["viewPassword"] = json!(false);
    assert_eq!(cx.edit(&hidden, &e).unwrap_err(), WriteError::PasswordHidden);
    assert!(cx.edit(&hidden, &ClientEdit { username: Some(z("team")), ..base() }).unwrap().is_some());
}

#[test]
fn only_a_login_has_a_username_a_password_and_uris() {
    let cx = cx();
    let note = cx.note(&[]);
    for e in [
        ClientEdit { username: Some(z("u")), ..base() },
        ClientEdit { password: Some(z("p")), ..base() },
        ClientEdit { uris: Some(Vec::new()), ..base() },
    ] {
        assert_eq!(cx.edit(&note, &e).unwrap_err(), WriteError::NotALogin);
    }
    // A note's name changes, and its missing part is sent (§6.3).
    let body = cx.edit(&note, &ClientEdit { name: Some(z("Renamed")), ..base() }).unwrap().unwrap();
    assert_eq!(d(&cx.user, &body["name"]).as_deref(), Some("Renamed"));
    assert_eq!((&body["secureNote"], &body["passwordHistory"]), (&json!({ "type": 0 }), &json!([])));
    passes_through(&note, &body, &["name", "secureNote"]);
}

#[test]
fn notes_a_tool_holds_its_secret_in_are_not_edited() {
    let cx = cx();
    let held = cx.note(&[(Some("plain"), "v"), (Some("bwss:location"), " notes ")]);
    assert_eq!(
        cx.edit(&held, &ClientEdit { notes: Some(z("mine")), ..base() }).unwrap_err(),
        WriteError::NotesHeldByTool
    );
    assert!(cx.edit(&held, &ClientEdit { notes: Some(z("held")), ..base() }).unwrap().is_none(), "unchanged");
    assert!(cx.edit(&held, &ClientEdit { name: Some(z("Renamed")), ..base() }).unwrap().is_some());
    // Only a first `<ns>:location` that says `notes` holds them.
    let free = cx.note(&[
        (Some("obsidian:location"), " "),
        (Some("obsidian:location"), "notes"),
        (Some(":location"), "notes"),
        (Some("bwss:locations"), "notes"),
        (Some("bwss:location"), "elsewhere"),
        (None, "notes"),
    ]);
    let body = cx.edit(&free, &ClientEdit { notes: Some(z("mine")), ..base() }).unwrap().unwrap();
    assert_eq!(d(&cx.user, &body["notes"]).as_deref(), Some("mine"));
    assert_eq!(body["fields"], free["fields"]);
}

#[test]
fn a_login_without_its_part_gets_one() {
    let cx = cx();
    let mut c = cx.note(&[]);
    c["type"] = json!(1);
    c["login"] = json!(null);
    let body = cx.edit(&c, &ClientEdit { username: Some(z("me")), ..base() }).unwrap().unwrap();
    let login = &body["login"];
    assert_eq!(d(&cx.user, &login["username"]).as_deref(), Some("me"));
    assert_eq!((&login["password"], &login["uris"], &login["totp"]), (&json!(null), &json!(null), &json!(null)));
}

#[test]
fn a_broken_clock_key_or_field_name_is_an_error() {
    let cx = cx();
    let (c, _) = cx.login(&cx.user, None);
    let e = ClientEdit { name: Some(z("x")), ..base() };
    assert_eq!(edit(&c, &e, &cx.user, &cx.orgs, &cx.rng, i64::MAX).unwrap_err(), WriteError::BadClock);
    let mut bad_key = c.clone();
    bad_key["key"] = json!("2.AAAA|AAAA|AAAA");
    assert!(matches!(cx.edit(&bad_key, &e), Err(WriteError::Crypto(_))));
    let mut bad_name = c.clone();
    bad_name["fields"][0]["name"] = json!("2.AAAA|AAAA|AAAA");
    assert!(matches!(cx.edit(&bad_name, &e), Err(WriteError::Crypto(_))));
    assert!(matches!(cx.edit(&bad_key, &ClientEdit { password: Some(z("p")), ..base() }), Err(WriteError::Crypto(_))));
}

#[test]
fn each_refusal_has_its_vector_code() {
    for (e, code) in [
        (WriteError::Gone, "gone"),
        (WriteError::ReadOnly, "read-only"),
        (WriteError::OutOfDate, "out-of-date"),
        (WriteError::NotALogin, "not-a-login"),
        (WriteError::PasswordHidden, "password-hidden"),
        (WriteError::NotesHeldByTool, "notes-held-by-tool"),
        (WriteError::NameRequired, "name-required"),
        (WriteError::BadUriMatch, "bad-uri-match"),
    ] {
        assert_eq!(e.code(), Some(code));
    }
}

#[test]
fn errors_carry_no_value() {
    let cx = cx();
    let (c, _) = cx.login(&cx.user, None);
    for e in [
        ClientEdit { password: Some(z(&"secret-pw".repeat(600))), ..base() },
        ClientEdit { base_revision: "x".into(), password: Some(z("secret-pw")), ..base() },
    ] {
        let err = cx.edit(&c, &e).unwrap_err();
        assert!(!format!("{err} {err:?}").contains("secret-pw"));
    }
}

/// A personal blob login: two tools' fields, an unknown key, two URIs (one with an unknown key) and a history.
fn blob_login(bx: &Bx) -> Value {
    let field = |n: &str, v: &str| {
        Cbor::Map(vec![(t("name"), t(n)), (t("value"), t(v)), (t("type"), Cbor::Uint(0)), (t("linkedId"), Cbor::Null)])
    };
    let content = Cbor::Map(vec![
        (t("name"), t("Blob")),
        (t("notes"), t("blob notes")),
        (
            t("typeData"),
            Cbor::Map(vec![
                (t("type"), t("login")),
                (t("username"), t("me")),
                (t("password"), t("old-pw")),
                (t("passwordRevisionDate"), Cbor::Null),
                (
                    t("uris"),
                    Cbor::Array(vec![
                        Cbor::Map(vec![
                            (t("uri"), t("https://a.invalid")),
                            (t("match"), Cbor::Null),
                            (t("xU"), t("kept")),
                        ]),
                        Cbor::Map(vec![(t("uri"), t("https://b.invalid")), (t("match"), Cbor::Uint(2))]),
                    ]),
                ),
                (t("totp"), Cbor::Null),
            ]),
        ),
        (t("fields"), Cbor::Array(vec![field("bwss:id", "x"), field("obsidian:id", "y")])),
        (
            t("passwordHistory"),
            Cbor::Array(vec![Cbor::Map(vec![(t("password"), t("older")), (t("lastUsedDate"), Cbor::Null)])]),
        ),
        (t("xKeep"), Cbor::Array(vec![t("a"), Cbor::Uint(1)])),
    ]);
    let mut c = bx.cipher(content);
    c["revisionDate"] = json!(REV);
    c["folderId"] = json!("f1");
    c["xOuter"] = json!(true);
    c
}

/// The blob a body sends, opened with the cipher's item key.
fn sent_blob(c: &Value, body: &Map<String, Value>, user: &SymmetricKey) -> OpenBlob {
    let mut sent = Value::Object(body.clone());
    sent["type"] = c["type"].clone();
    open_blob(&sent, user).unwrap()
}

#[test]
fn a_blob_edit_reseals_the_whole_item_and_keeps_what_it_does_not_change() {
    let bx = Bx::new();
    let c = blob_login(&bx);
    let e = ClientEdit {
        name: Some(z("Renamed")),
        notes: Some(z("")),
        username: Some(z("you")),
        password: Some(z("new-pw")),
        uris: Some(vec![uri("https://a.invalid", None), uri("https://c.invalid", Some(5))]),
        folder_id: Some(Some("f2".into())),
        ..base()
    };
    let body = edit(&c, &e, &bx.keys.user, &bx.keys.orgs, &bx.rng, NOW).unwrap().unwrap();
    passes_through(&c, &body, &["folderId", "data"]);
    assert_eq!((&body["folderId"], &body["lastKnownRevisionDate"]), (&json!("f2"), &json!(REV)));
    for k in ["name", "notes", "login", "fields", "passwordHistory"] {
        assert_eq!(body[k], json!(null), "{k}");
    }
    assert_ne!(body["data"], c["data"]);
    let before = open_blob(&c, &bx.keys.user).unwrap();
    let after = sent_blob(&c, &body, &bx.keys.user);
    assert_eq!((after.name(), after.notes()), (Some("Renamed"), None));
    assert_eq!((after.login_username(), after.login_password()), (Some("you"), Some("new-pw")));
    let typed = after.get("typeData").unwrap();
    assert_eq!(blob::get(typed, "passwordRevisionDate"), Some(&t(NOW_ISO)));
    let Some(Cbor::Array(uris)) = blob::get(typed, "uris") else { panic!("no URIs") };
    let Some(Cbor::Array(old_uris)) = blob::get(before.get("typeData").unwrap(), "uris") else { panic!() };
    assert_eq!(uris[0], old_uris[0], "kept as it was");
    assert!(uris[1] == Cbor::Map(vec![(t("uri"), t("https://c.invalid")), (t("match"), Cbor::Uint(5))]));
    let Some(Cbor::Array(history)) = after.get("passwordHistory") else { panic!("no history") };
    assert!(history[0] == Cbor::Map(vec![(t("password"), t("old-pw")), (t("lastUsedDate"), t(NOW_ISO))]));
    assert_eq!(history.len(), 2);
    for k in ["fields", "xKeep"] {
        assert!(after.get(k) == before.get(k), "{k}");
    }
    // Nothing to change: nothing sent; an emptied URI list is null.
    let same = ClientEdit { name: Some(z("Blob")), uris: Some(vec![]), ..base() };
    let body = edit(&c, &same, &bx.keys.user, &bx.keys.orgs, &bx.rng, NOW).unwrap().unwrap();
    let after = sent_blob(&c, &body, &bx.keys.user);
    assert!(blob::get(after.get("typeData").unwrap(), "uris") == Some(&Cbor::Null));
    assert!(
        edit(&c, &ClientEdit { name: Some(z("Blob")), ..base() }, &bx.keys.user, &bx.keys.orgs, &bx.rng, NOW)
            .unwrap()
            .is_none()
    );
    // A folder move alone re-seals the blob as it was.
    let moved = ClientEdit { folder_id: Some(Some("f3".into())), ..base() };
    let body = edit(&c, &moved, &bx.keys.user, &bx.keys.orgs, &bx.rng, NOW).unwrap().unwrap();
    assert_eq!(body["folderId"], json!("f3"));
    assert_eq!(sent_blob(&c, &body, &bx.keys.user).login_password(), Some("old-pw"));
    let broken = tampered(&c);
    let e = ClientEdit { name: Some(z("x")), ..base() };
    assert_eq!(
        edit(&broken, &e, &bx.keys.user, &bx.keys.orgs, &bx.rng, NOW).unwrap_err(),
        WriteError::Uninspectable(Uninspectable::Blob)
    );
}

fn uri_texts(parts: &impl Parts) -> Vec<(String, Option<u64>)> {
    parts.uris().unwrap().into_iter().map(|(u, m)| (u.as_str().to_owned(), m)).collect()
}

/// The parts a blob may lack, which `open_blob` lets through for a type other than a login.
#[test]
fn blob_parts_fill_in_what_is_missing() {
    let bx = Bx::new();
    let mut c = bx.cipher(Cbor::Map(vec![
        (t("name"), t("Bank")),
        (t("typeData"), Cbor::Map(vec![(t("type"), t("bankAccount")), (t("uris"), t("no list"))])),
    ]));
    c["type"] = json!(9);
    c["revisionDate"] = json!(REV);
    let body = edit(&c, &ClientEdit { notes: Some(z("n")), ..base() }, &bx.keys.user, &bx.keys.orgs, &bx.rng, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(sent_blob(&c, &body, &bx.keys.user).notes(), Some("n"));
    // Below the cipher: a blob with no `typeData` gets a login's, and a match that is no number reads as none.
    let mut empty = OpenBlob(vec![]);
    empty.set_login_text("username", "me").unwrap();
    let Some(Cbor::Map(typed)) = empty.get("typeData") else { panic!("no typeData") };
    assert!(typed[0] == (t("type"), t("login")));
    assert_eq!(empty.login_username(), Some("me"));
    let odd = OpenBlob(vec![(
        t("typeData"),
        Cbor::Map(vec![(t("uris"), Cbor::Array(vec![Cbor::Map(vec![(t("uri"), t("u")), (t("match"), t("one"))])]))]),
    )]);
    assert_eq!(uri_texts(&odd), vec![("u".to_owned(), None)]);
}

#[test]
fn a_create_is_a_personal_field_level_login() {
    let cx = cx();
    let entry = NewEntry {
        name: z("Site"),
        notes: z("some notes"),
        folder_id: Some("f1".into()),
        kind: NewKind::Login(NewLogin {
            username: z("me"),
            password: z("pw"),
            totp: z("JBSWY3DPEHPK3PXP"),
            uris: vec![uri("https://a.invalid", Some(0)), uri("", None)],
        }),
    };
    let body = create(&entry, &cx.user, 0, &cx.rng).unwrap();
    let k = &cx.user;
    assert_eq!(
        (&body["type"], &body["organizationId"], &body["folderId"], &body["key"]),
        (&json!(1), &json!(null), &json!("f1"), &json!(null))
    );
    assert_eq!((&body["favorite"], &body["reprompt"], &body["secureNote"]), (&json!(false), &json!(0), &json!(null)));
    assert_eq!((&body["fields"], &body["passwordHistory"]), (&json!([]), &json!([])));
    assert_eq!((d(k, &body["name"]), d(k, &body["notes"])), (Some("Site".into()), Some("some notes".into())));
    let login = &body["login"];
    assert_eq!(d(k, &login["username"]).as_deref(), Some("me"));
    assert_eq!(d(k, &login["password"]).as_deref(), Some("pw"));
    assert_eq!(d(k, &login["totp"]).as_deref(), Some("JBSWY3DPEHPK3PXP"));
    let uris = login["uris"].as_array().unwrap();
    assert_eq!(uris.len(), 1);
    assert_eq!((d(k, &uris[0]["uri"]).as_deref(), &uris[0]["match"]), (Some("https://a.invalid"), &json!(0)));
    assert!(login.get("passwordRevisionDate").is_none(), "a new password has no revision");
    // The least a login is: a name.
    let bare = NewEntry {
        name: z("Bare"),
        notes: z(""),
        folder_id: None,
        kind: NewKind::Login(NewLogin { username: z(""), password: z(""), totp: z(""), uris: vec![] }),
    };
    let body = create(&bare, &cx.user, 0, &cx.rng).unwrap();
    assert_eq!(body["notes"], json!(null));
    assert_eq!(body["login"], json!({ "username": null, "password": null, "uris": null, "totp": null }));
}

#[test]
fn a_create_is_a_secure_note_and_a_blob_on_a_version_2_account() {
    let cx = cx();
    let note = NewEntry { name: z("N"), notes: z("text"), folder_id: None, kind: NewKind::SecureNote };
    let body = create(&note, &cx.user, 1, &cx.rng).unwrap();
    assert_eq!((&body["type"], &body["login"], &body["secureNote"]), (&json!(2), &json!(null), &json!({ "type": 0 })));
    assert_eq!(d(&cx.user, &body["notes"]).as_deref(), Some("text"));

    let login = NewEntry {
        name: z("L"),
        notes: z(""),
        folder_id: None,
        kind: NewKind::Login(NewLogin {
            username: z("me"),
            password: z("pw"),
            totp: z(""),
            uris: vec![uri("https://a.invalid", None)],
        }),
    };
    for (entry, kind) in [(&note, "secureNote"), (&login, "login")] {
        let body = create(entry, &cx.user, 2, &cx.rng).unwrap();
        for k in ["name", "notes", "login", "secureNote", "fields", "passwordHistory", "organizationId"] {
            assert_eq!(body[k], json!(null), "{k}");
        }
        let blob = open_blob(&Value::Object(body.clone()), &cx.user).unwrap();
        let typed = blob.get("typeData").unwrap();
        assert_eq!(blob::get(typed, "type"), Some(&t(kind)));
        assert_eq!(blob.name(), Some(entry.name.as_str()));
    }
    let body = create(&login, &cx.user, 2, &cx.rng).unwrap();
    let blob = open_blob(&Value::Object(body), &cx.user).unwrap();
    assert_eq!((blob.login_username(), blob.login_password(), blob.notes()), (Some("me"), Some("pw"), None));
    assert_eq!(uri_texts(&blob), vec![("https://a.invalid".to_owned(), None)]);
}

#[test]
fn a_create_is_refused_as_an_edit_would_be() {
    let cx = cx();
    let login = |name: &str, password: &str, totp: &str, m: Option<u64>| NewEntry {
        name: z(name),
        notes: z(""),
        folder_id: None,
        kind: NewKind::Login(NewLogin {
            username: z(""),
            password: z(password),
            totp: z(totp),
            uris: vec![uri("u", m)],
        }),
    };
    for (entry, err) in [
        (login("", "", "", None), WriteError::NameRequired),
        (login("n", &"p".repeat(5_000), "", None), WriteError::TooLong),
        (login("n", "", &"t".repeat(1_000), None), WriteError::TooLong),
        (login("n", "", "", Some(7)), WriteError::BadUriMatch),
    ] {
        for version in [0, 2] {
            let got = create(&entry, &cx.user, version, &cx.rng).map(|_| ());
            // A blob measures plaintext: only the field-level body is over Bitwarden's encrypted limits.
            if version == 2 && err == WriteError::TooLong {
                assert!(got.is_ok());
            } else {
                assert_eq!(got.unwrap_err(), err);
            }
        }
    }
}
