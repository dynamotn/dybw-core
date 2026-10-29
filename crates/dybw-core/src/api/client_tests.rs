use super::*;
use crate::ports::{HttpResponse, PortError};
use crate::testing::block_on;
use serde_json::json;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

type Sent = Rc<RefCell<Vec<HttpRequest>>>;
type Replies = Rc<RefCell<VecDeque<Result<HttpResponse, PortError>>>>;

struct Fake {
    sent: Sent,
    replies: Replies,
}

impl Http for Fake {
    fn refuses_redirects(&self) -> bool {
        true
    }
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        self.sent.borrow_mut().push(req);
        self.replies.borrow_mut().pop_front().unwrap_or_else(|| Err(PortError("no reply queued".into())))
    }
}

struct Rig {
    client: Client<Fake>,
    sent: Sent,
    replies: Replies,
}

type Seen = (Method, String, Vec<(String, String)>, Option<Vec<u8>>);

impl Rig {
    fn new() -> Self {
        let sent = Sent::default();
        let replies = Replies::default();
        let device = DeviceInfo { identifier: "dev-1".into(), name: "Test device".into(), device_type: 21 };
        let urls = resolve_server_urls("https://bw.example.org").unwrap();
        Rig { client: Client::new(Fake { sent: sent.clone(), replies: replies.clone() }, urls, device), sent, replies }
    }
    fn reply(&self, status: u16, body: &str) {
        self.replies
            .borrow_mut()
            .push_back(Ok(HttpResponse { status, body: Zeroizing::new(body.as_bytes().to_vec()) }));
    }
    fn login(&mut self) {
        self.reply(200, r#"{"access_token":"tok","expires_in":3600}"#);
        block_on(self.client.login(&key())).unwrap();
    }
    fn synced(&mut self) {
        self.login();
        self.reply(200, r#"{"Profile":{"Id":"user-1"},"Folders":[]}"#);
        block_on(self.client.sync()).unwrap();
    }
    fn last(&self) -> Seen {
        let sent = self.sent.borrow();
        let r = sent.last().unwrap();
        (r.method, r.url.clone(), r.headers.clone(), r.body.as_ref().map(|b| b.to_vec()))
    }
}

fn key() -> ApiKey {
    ApiKey {
        origin: "https://bw.example.org".into(),
        client_id: "user.x".into(),
        client_secret: Zeroizing::new("s3cret-value".into()),
    }
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn json_body(b: Option<Vec<u8>>) -> Value {
    serde_json::from_slice(&b.unwrap()).unwrap()
}

#[test]
fn resolve_urls() {
    let u = resolve_server_urls("").unwrap();
    assert_eq!(
        (u.api.as_str(), u.identity.as_str(), u.notifications.as_str()),
        ("https://api.bitwarden.com", "https://identity.bitwarden.com", "https://notifications.bitwarden.com")
    );
    assert_eq!(resolve_server_urls(" https://bitwarden.com ").unwrap(), u);
    let eu = resolve_server_urls("https://vault.bitwarden.eu").unwrap();
    assert_eq!(eu.notifications, "https://notifications.bitwarden.eu");
    assert_eq!(resolve_server_urls("https://bitwarden.eu/x").unwrap(), eu);
    let own = resolve_server_urls("https://bw.example.org/vault/?q=1#f").unwrap();
    assert_eq!(own.api, "https://bw.example.org/vault/api");
    assert_eq!(own.identity, "https://bw.example.org/vault/identity");
    assert_eq!(own.notifications, "https://bw.example.org/vault/notifications");
    assert_eq!(resolve_server_urls("http://127.0.0.1:8080").unwrap().identity, "http://127.0.0.1:8080/identity");
    assert_eq!(resolve_server_urls("http://localhost:8080").unwrap().api, "http://localhost:8080/api");
    assert_eq!(resolve_server_urls("http://[::1]:8080").unwrap().api, "http://[::1]:8080/api");
    for bad in ["http://bw.example.org", "ftp://localhost", "mailto:a@b.c"] {
        assert!(resolve_server_urls(bad).unwrap_err().to_string().contains("https://"), "{bad}");
    }
    let e = resolve_server_urls("https://u:hunter2@bw.example.org").unwrap_err().to_string();
    assert!(e.contains("credentials") && !e.contains("hunter2"));
    for bad in ["https://:hunter2@bw.example.org", "https://u@bw.example.org"] {
        assert!(resolve_server_urls(bad).unwrap_err().to_string().contains("credentials"), "{bad}");
    }
    let e = resolve_server_urls("https://u:hunter2@[bad").unwrap_err().to_string();
    assert!(e.starts_with("unexpected response: invalid server URL") && !e.contains("hunter2"));
}

#[test]
fn origins_are_scheme_host_and_port() {
    assert_eq!(origin_of("https://bw.example.org/vault/identity").unwrap(), "https://bw.example.org");
    assert_eq!(origin_of("http://127.0.0.1:80/identity").unwrap(), "http://127.0.0.1");
    assert_eq!(origin_of("HTTPS://BW.Example.org:443/x").unwrap(), "https://bw.example.org");
    assert!(matches!(origin_of("not a url"), Err(ApiError::Protocol(_))));
}

#[test]
fn normalize_keys_lowercases_first_letter_recursively() {
    assert_eq!(normalize_keys(json!({ "": 1, "AbC": 2 })), json!({ "": 1, "abC": 2 }));
    let v = normalize_keys(json!({ "Profile": { "Key": "k" }, "Ciphers": [{ "RevisionDate": "d" }], "N": 1 }));
    assert_eq!(v, json!({ "profile": { "key": "k" }, "ciphers": [{ "revisionDate": "d" }], "n": 1 }));
}

#[test]
fn login_sends_client_credentials() {
    let mut rig = Rig::new();
    rig.login();
    let (method, url, headers, body) = rig.last();
    assert_eq!((method, url.as_str()), (Method::Post, "https://bw.example.org/identity/connect/token"));
    assert_eq!(header(&headers, "Content-Type"), Some("application/x-www-form-urlencoded; charset=utf-8"));
    assert_eq!(header(&headers, "Device-Type"), Some("21"));
    assert_eq!(header(&headers, "Bitwarden-Client-Name"), Some("Test device"));
    assert!(header(&headers, "Bitwarden-Client-Version").is_some());
    assert!(header(&headers, "Authorization").is_none());
    let form: Vec<(String, String)> =
        url::form_urlencoded::parse(&body.unwrap()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get("grant_type"), Some("client_credentials"));
    assert_eq!(get("scope"), Some("api"));
    assert_eq!(get("client_id"), Some("user.x"));
    assert_eq!(get("client_secret"), Some("s3cret-value"));
    assert_eq!(get("deviceType"), Some("21"));
    assert_eq!(get("deviceIdentifier"), Some("dev-1"));
    assert_eq!(get("deviceName"), Some("Test device"));
    assert_eq!(rig.client.access_token(), Some("tok"));

    rig.reply(200, r#"{"Profile":{"Id":"u"}}"#);
    block_on(rig.client.sync()).unwrap();
    let (method, url, headers, body) = rig.last();
    assert_eq!((method, url.as_str()), (Method::Get, "https://bw.example.org/api/sync?excludeDomains=true"));
    assert_eq!(header(&headers, "Authorization"), Some("Bearer tok"));
    assert!(header(&headers, "Content-Type").is_none() && body.is_none());
}

#[test]
fn login_refuses_answers_without_a_token() {
    for body in ["not json", "null", r#"{"token_type":"Bearer"}"#, r#"{"access_token":5}"#] {
        let mut rig = Rig::new();
        rig.reply(200, body);
        let e = block_on(rig.client.login(&key())).unwrap_err();
        assert!(matches!(&e, ApiError::Protocol(m) if m == "no access token"), "{e}");
        assert_eq!(rig.client.access_token(), None);
    }
    let mut rig = Rig::new();
    rig.reply(400, r#"{"error_description":"invalid_client"}"#);
    let e = block_on(rig.client.login(&key())).unwrap_err();
    assert_eq!(e.to_string(), "HTTP 400 (server says: invalid_client)");
    assert!(!format!("{e:?}").contains("s3cret-value"));
}

#[test]
fn api_key_bound_to_origin() {
    let mut rig = Rig::new();
    let other = ApiKey { origin: "https://identity.bitwarden.com".into(), ..key() };
    let e = block_on(rig.client.login(&other)).unwrap_err();
    assert!(matches!(e, ApiError::WrongOrigin) && !e.is_transient() && !e.to_string().is_empty());
    assert!(rig.sent.borrow().is_empty(), "no request may leave");
}

#[test]
fn a_bad_identity_url_sends_nothing() {
    let mut rig = Rig::new();
    rig.client.urls.identity = "not a url".into();
    assert!(matches!(block_on(rig.client.login(&key())), Err(ApiError::Protocol(_))));
    assert!(rig.sent.borrow().is_empty());
}

#[test]
fn api_key_debug_is_redacted() {
    let out = format!("{:?}", key());
    assert!(!out.contains("s3cret-value") && out.contains("<redacted>") && out.contains("user.x"));
}

#[test]
fn errors_shaped() {
    let rig = Rig::new();
    rig.reply(400, &json!({ "message": "x".repeat(300) }).to_string());
    let e = block_on(rig.client.prelogin("a@b.c")).unwrap_err();
    let ApiError::Http { status: 400, message } = &e else { panic!("{e:?}") };
    assert_eq!(message.chars().count(), 201);
    assert!(message.ends_with('…') && message.starts_with("xxx"));

    let ood = ApiError::Http { status: 400, message: "The cipher you are updating is Out Of Date.".into() };
    assert!(ood.is_out_of_date());
    assert!(!ApiError::Http { status: 500, message: "out of date".into() }.is_out_of_date());
    assert!(!ApiError::Http { status: 400, message: "bad".into() }.is_out_of_date());
    assert!(!ApiError::Network("out of date".into()).is_out_of_date());

    let http = |status| ApiError::Http { status, message: String::new() };
    assert!(http(429).is_transient() && http(503).is_transient() && ApiError::Network("x".into()).is_transient());
    assert!(ApiError::NotSynced.is_transient());
    assert!(!http(400).is_transient() && !http(404).is_transient());
    for e in [ApiError::Protocol("x".into()), ApiError::NotLoggedIn, ApiError::TooLarge, ApiError::WrongOrigin] {
        assert!(!e.is_transient());
    }
    assert_eq!(http(404).to_string(), "HTTP 404");
    assert_eq!(ApiError::Network("down".into()).to_string(), "network error: down");
    for e in [ApiError::NotLoggedIn, ApiError::TooLarge, ApiError::NotSynced] {
        assert!(!e.to_string().is_empty());
    }
}

fn shaped(body: Value) -> String {
    let rig = Rig::new();
    rig.reply(400, &body.to_string());
    match block_on(rig.client.prelogin("a")).unwrap_err() {
        ApiError::Http { message, .. } => message,
        e => panic!("{e:?}"),
    }
}

#[test]
fn server_text_is_joined_cleaned_and_clipped() {
    let m = shaped(json!({ "ErrorModel": { "Message": "The cipher is out of date." } }));
    assert_eq!(m, "The cipher is out of date.");
    let m = shaped(
        json!({ "error_description": "bad\n\ncreds", "message": "try\tagain", "validationErrors": { "Name": ["x"] } }),
    );
    assert_eq!(m, r#"bad creds try again {"name":["x"]}"#);
    assert_eq!(shaped(json!({ "message": 42, "error_description": null })), "");
    let m = shaped(json!({
        "message": "bad\u{1b}[31mred\u{1b}[0m\nnext\u{7} \u{9b}2Jx \u{1b}]0;title\u{7}end \u{1b}(Bok\u{85}\u{1b}"
    }));
    assert_eq!(m, "badred next x end ok");
    let m = shaped(json!({ "message": "use\u{202e}gnorw\u{202c} \u{200b}x\u{feff}y\u{ad}z\u{2066}!\u{2069}\u{2028}" }));
    assert_eq!(m, "usegnorw xyz!");
    let rare = "\u{600}\u{61c}\u{6dd}\u{70f}\u{890}\u{8e2}\u{180e}\u{fff9}\u{110bd}\u{110cd}\u{13430}\u{1bca0}\u{1d173}\u{e0001}\u{e0020}";
    assert_eq!(shaped(json!({ "message": format!("a{rare}b") })), "ab");
    let m = shaped(json!({ "message": "a\u{1b}ébc \u{1b}\u{1b}[1mx \u{1b}\nz" }));
    assert_eq!(m, "aébc x z");
    let m = shaped(json!({ "message": "a\u{1b}P1q\u{1b}\\b \u{9d}x\u{9c}c \u{90}dcs\u{7}d \u{1b}]never" }));
    assert_eq!(m, "ab c d");
    let m = shaped(json!({ "message": "a\u{1b}]x\u{1b}y\u{7}z" }));
    assert_eq!(m, "az");
    let m = shaped(json!({ "message": format!("{}{}", "\u{1b}[1m".repeat(300), "a".repeat(250)) }));
    assert_eq!(m, format!("{}…", "a".repeat(200)));
}

#[test]
fn bodies_that_are_not_json_give_only_the_status() {
    for body in ["<html>Bad gateway</html>", "", "null", "[1]"] {
        let rig = Rig::new();
        rig.reply(502, body);
        let e = block_on(rig.client.prelogin("a")).unwrap_err();
        assert_eq!(e.to_string(), "HTTP 502", "{body}");
    }
}

#[test]
fn put_reply_is_normalized() {
    let mut rig = Rig::new();
    rig.synced();
    rig.reply(200, r#"{"Id":"c1","RevisionDate":"d","Login":{"Username":"u"},"Fields":[{"Name":"n"}]}"#);
    let v = block_on(rig.client.update_cipher("c1", Map::new())).unwrap();
    assert_eq!(
        v,
        json!({ "id": "c1", "revisionDate": "d", "login": { "username": "u" }, "fields": [{ "name": "n" }] })
    );
    rig.reply(200, r#"{"Id":"c2"}"#);
    assert_eq!(block_on(rig.client.create_cipher(Map::new())).unwrap(), json!({ "id": "c2" }));
    rig.reply(200, r#"{"Id":"c3","Name":"2.n"}"#);
    assert_eq!(block_on(rig.client.get_cipher("c3")).unwrap(), json!({ "id": "c3", "name": "2.n" }));
    rig.reply(200, r#"{"Id":"f1"}"#);
    assert_eq!(block_on(rig.client.create_folder("2.enc")).unwrap(), json!({ "id": "f1" }));
}

#[test]
fn prelogin_parses_both_kdfs() {
    let rig = Rig::new();
    rig.reply(200, r#"{"Kdf":0,"KdfIterations":600000}"#);
    assert_eq!(block_on(rig.client.prelogin("a@b.c")).unwrap(), KdfParams::Pbkdf2 { iterations: 600_000 });
    let (method, url, headers, body) = rig.last();
    assert_eq!((method, url.as_str()), (Method::Post, "https://bw.example.org/identity/accounts/prelogin"));
    assert_eq!(header(&headers, "Content-Type"), Some("application/json"));
    assert_eq!(json_body(body), json!({ "email": "a@b.c" }));
    rig.reply(200, r#"{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4}"#);
    let want = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
    assert_eq!(block_on(rig.client.prelogin("a@b.c")).unwrap(), want);
    rig.reply(200, r#"{"Kdf":1,"KdfIterations":3,"KdfMemory":64,"KdfParallelism":4}"#);
    assert_eq!(block_on(rig.client.prelogin("a@b.c")).unwrap(), want);
    // Missing parameters stay zero for validation to reject.
    rig.reply(200, r#"{"kdf":1,"kdfIterations":3}"#);
    let zero = KdfParams::Argon2id { iterations: 3, memory_mib: 0, parallelism: 0 };
    assert_eq!(block_on(rig.client.prelogin("a@b.c")).unwrap(), zero);
    rig.reply(200, r#"{"kdf":0}"#);
    assert_eq!(block_on(rig.client.prelogin("a@b.c")).unwrap(), KdfParams::Pbkdf2 { iterations: 0 });
    for body in [r#"{"kdf":7,"kdfIterations":1}"#, "{}", "", r#"{"kdf":4294967296}"#] {
        rig.reply(200, body);
        assert!(matches!(block_on(rig.client.prelogin("a")), Err(ApiError::Protocol(_))), "{body}");
    }
}

#[test]
fn calls_need_a_login_and_send_nothing_without() {
    let mut rig = Rig::new();
    let c = &mut rig.client;
    assert!(matches!(block_on(c.sync()), Err(ApiError::NotLoggedIn)));
    assert!(matches!(block_on(c.get_cipher("x")), Err(ApiError::NotLoggedIn)));
    assert!(matches!(block_on(c.create_cipher(Map::new())), Err(ApiError::NotLoggedIn)));
    assert!(matches!(block_on(c.update_cipher("x", Map::new())), Err(ApiError::NotLoggedIn)));
    assert!(matches!(block_on(c.trash_cipher("x")), Err(ApiError::NotLoggedIn)));
    assert!(matches!(block_on(c.create_folder("x")), Err(ApiError::NotLoggedIn)));
    assert!(matches!(block_on(c.revision_date()), Err(ApiError::NotLoggedIn)));
    assert!(c.access_token().is_none() && rig.sent.borrow().is_empty());
}

#[test]
fn writes_name_their_owner_and_encode_ids() {
    let mut rig = Rig::new();
    rig.login();
    let body: Map<String, Value> = serde_json::from_value(json!({ "name": "2.n" })).unwrap();
    assert!(matches!(block_on(rig.client.create_cipher(body.clone())), Err(ApiError::NotSynced)));
    assert!(matches!(block_on(rig.client.update_cipher("c", body.clone())), Err(ApiError::NotSynced)));
    assert_eq!(rig.sent.borrow().len(), 1, "only the login went out");

    rig.reply(200, r#"{"Profile":{"Id":"user-1"}}"#);
    block_on(rig.client.sync()).unwrap();
    rig.reply(200, "{}");
    block_on(rig.client.create_cipher(body.clone())).unwrap();
    let (method, url, headers, sent) = rig.last();
    assert_eq!((method, url.as_str()), (Method::Post, "https://bw.example.org/api/ciphers"));
    assert_eq!(header(&headers, "Content-Type"), Some("application/json"));
    assert_eq!(json_body(sent), json!({ "name": "2.n", "encryptedFor": "user-1" }));

    rig.reply(200, "{}");
    block_on(rig.client.update_cipher("a b/c+d", body)).unwrap();
    let (method, url, _, _) = rig.last();
    assert_eq!((method, url.as_str()), (Method::Put, "https://bw.example.org/api/ciphers/a%20b%2Fc%2Bd"));

    rig.reply(200, "");
    block_on(rig.client.trash_cipher("a/b")).unwrap();
    let (method, url, headers, body) = rig.last();
    assert_eq!((method, url.as_str()), (Method::Put, "https://bw.example.org/api/ciphers/a%2Fb/delete"));
    assert!(body.is_none() && header(&headers, "Content-Type").is_none());

    rig.reply(200, "{}");
    block_on(rig.client.create_folder("2.enc")).unwrap();
    let (_, url, _, body) = rig.last();
    assert_eq!(url, "https://bw.example.org/api/folders");
    assert_eq!(json_body(body), json!({ "name": "2.enc" }));
}

#[test]
fn sync_needs_a_profile_id() {
    let mut rig = Rig::new();
    rig.login();
    for body in ["{}", "", r#"{"Profile":{"Id":5}}"#] {
        rig.reply(200, body);
        let r = block_on(rig.client.sync());
        assert!(matches!(&r, Err(ApiError::Protocol(m)) if m == "sync response has no profile"), "{body}");
    }
    rig.reply(200, r#"{"Profile":{"Id":"u"},"Ciphers":[{"Id":"c"}]}"#);
    assert_eq!(block_on(rig.client.sync()).unwrap()["ciphers"][0]["id"], "c");
}

#[test]
fn revision_date_is_raw_text() {
    let mut rig = Rig::new();
    rig.login();
    rig.reply(200, " 1700000000000\n");
    assert_eq!(block_on(rig.client.revision_date()).unwrap(), "1700000000000");
    let (method, url, _, _) = rig.last();
    assert_eq!((method, url.as_str()), (Method::Get, "https://bw.example.org/api/accounts/revision-date"));
    rig.replies.borrow_mut().push_back(Ok(HttpResponse { status: 200, body: Zeroizing::new(vec![b'4', 0xff, b'2']) }));
    assert_eq!(block_on(rig.client.revision_date()).unwrap(), "4\u{fffd}2");
}

#[test]
fn network_failures_carry_the_port_text() {
    let rig = Rig::new();
    let e = block_on(rig.client.prelogin("a")).unwrap_err();
    assert!(matches!(&e, ApiError::Network(m) if m == "no reply queued") && e.is_transient());
}

#[test]
fn responses_over_the_limit_are_refused() {
    assert_eq!(MAX_BODY, 256 * 1024 * 1024);
    for status in [200, 400] {
        let mut rig = Rig::new();
        rig.client.body_limit = 8;
        rig.reply(status, "123456789");
        assert!(matches!(block_on(rig.client.prelogin("a")), Err(ApiError::TooLarge)));
        rig.reply(status, "12345678");
        assert!(!matches!(block_on(rig.client.prelogin("a")), Err(ApiError::TooLarge)));
    }
}
