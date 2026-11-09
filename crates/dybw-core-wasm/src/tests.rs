use crate::host::{Host, RSA_KEY_ERROR, RecvFuture};
use crate::ports::Ports;
use dybw_core::crypto::{AwsLcRsa, NativeArgon2};
use dybw_core::ports::{
    Argon2Input, Clock, EventSocket, Events, Frame, Http, HttpRequest, KdfRunner, Method, OaepHash, Random, RsaOaep,
    Secrets, Storage,
};
use dybw_core::testing::block_on;
use dybw_vectors::server::VectorServer;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use zeroize::Zeroizing;

type Recv = Option<Result<Frame, String>>;
type HttpCall = (String, String, Vec<(String, String)>, Option<Vec<u8>>);
type RsaCall = (Vec<u8>, String, Vec<u8>);
type KdfCall = (Vec<u8>, [u8; 32], u32, u32, u32);

/// Records every call; `fail` makes each fallible method answer `Err("boom")`.
#[derive(Default)]
struct MockHost {
    fail: Cell<bool>,
    random_short: Cell<bool>,
    random_lens: RefCell<Vec<usize>>,
    http_seen: RefCell<Vec<HttpCall>>,
    http_answer: RefCell<(u16, Vec<u8>)>,
    store: RefCell<HashMap<String, Vec<u8>>>,
    secrets: RefCell<HashMap<String, String>>,
    kdf_seen: RefCell<Vec<KdfCall>>,
    kdf_len: Cell<usize>,
    rsa_seen: RefCell<Vec<RsaCall>>,
    rsa_error: RefCell<Option<String>>,
    /// Like the JS side: a frame goes to the oldest pending `recv` promise, else waits in the queue.
    waiting: RefCell<VecDeque<Rc<RefCell<Option<Recv>>>>>,
    queued: RefCell<VecDeque<Recv>>,
    recv_calls: Cell<usize>,
    sent: RefCell<Vec<(u32, Frame)>>,
    closed: RefCell<Vec<u32>>,
    slept: RefCell<Vec<u64>>,
    logged: RefCell<Vec<String>>,
    refuses: Cell<bool>,
    /// `http` answers `Pending` this many times first, like a request still in flight.
    hold: Cell<usize>,
    /// Only `secret_save` fails.
    fail_secret_save: Cell<bool>,
    /// When set, `http` is this fake Bitwarden server.
    server: RefCell<Option<VectorServer>>,
    /// `argon2id` and `rsa_oaep_decrypt` compute for real (`NativeArgon2`, `AwsLcRsa`), with the host's texts.
    real: Cell<bool>,
}

impl MockHost {
    fn deliver(&self, r: Recv) {
        match self.waiting.borrow_mut().pop_front() {
            Some(slot) => *slot.borrow_mut() = Some(r),
            None => self.queued.borrow_mut().push_back(r),
        }
    }
    fn check(&self) -> Result<(), String> {
        if self.fail.get() { Err("boom".into()) } else { Ok(()) }
    }
}

impl Host for MockHost {
    fn now_ms(&self) -> i64 {
        1_700_000_000_000
    }
    async fn sleep_ms(&self, ms: u64) {
        self.slept.borrow_mut().push(ms);
    }
    fn refuses_redirects(&self) -> bool {
        self.refuses.get()
    }
    fn random(&self, len: usize) -> Result<Vec<u8>, String> {
        self.check()?;
        self.random_lens.borrow_mut().push(len);
        Ok(vec![7; len - usize::from(self.random_short.get())])
    }
    async fn http(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), String> {
        self.check()?;
        poll_fn(|cx| match self.hold.get() {
            0 => Poll::Ready(()),
            n => {
                self.hold.set(n - 1);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        self.http_seen.borrow_mut().push((method.into(), url.into(), headers.to_vec(), body.map(<[u8]>::to_vec)));
        let server = self.server.borrow().clone();
        if let Some(server) = server {
            let method = [("GET", Method::Get), ("POST", Method::Post)].into_iter().find(|m| m.0 == method);
            let req = HttpRequest {
                method: method.map_or(Method::Put, |m| m.1),
                url: url.into(),
                headers: headers.to_vec(),
                body: body.map(|b| Zeroizing::new(b.to_vec())),
                max_body: usize::MAX,
            };
            let res = server.send(req).await.map_err(|e| e.0)?;
            return Ok((res.status, res.body));
        }
        let (status, body) = self.http_answer.borrow().clone();
        Ok((status, Zeroizing::new(body)))
    }
    async fn storage_load(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        self.check()?;
        Ok(self.store.borrow().get(key).cloned())
    }
    async fn storage_save(&self, key: &str, value: &[u8]) -> Result<(), String> {
        self.check()?;
        self.store.borrow_mut().insert(key.into(), value.into());
        Ok(())
    }
    async fn storage_remove(&self, key: &str) -> Result<(), String> {
        self.check()?;
        self.store.borrow_mut().remove(key);
        Ok(())
    }
    async fn secret_load(&self, key: &str) -> Result<Option<Zeroizing<String>>, String> {
        self.check()?;
        Ok(self.secrets.borrow().get(key).cloned().map(Zeroizing::new))
    }
    async fn secret_save(&self, key: &str, value: &str) -> Result<(), String> {
        self.check()?;
        if self.fail_secret_save.get() {
            return Err("no secret storage".into());
        }
        self.secrets.borrow_mut().insert(key.into(), value.into());
        Ok(())
    }
    async fn secret_remove(&self, key: &str) -> Result<(), String> {
        self.check()?;
        self.secrets.borrow_mut().remove(key);
        Ok(())
    }
    async fn argon2id(
        &self,
        password: &[u8],
        salt: &[u8; 32],
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        self.check()?;
        if self.real.get() {
            let input = Argon2Input {
                password: Zeroizing::new(password.into()),
                salt: *salt,
                iterations,
                memory_kib,
                parallelism,
            };
            let out = NativeArgon2.argon2id(input).await.map_err(|e| e.0)?;
            return Ok(Zeroizing::new(out.to_vec()));
        }
        self.kdf_seen.borrow_mut().push((password.into(), *salt, iterations, memory_kib, parallelism));
        Ok(Zeroizing::new(vec![9; self.kdf_len.get()]))
    }
    async fn rsa_oaep_decrypt(
        &self,
        pkcs8: &[u8],
        hash: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        if self.real.get() {
            let hash = if hash == "SHA-1" { OaepHash::Sha1 } else { OaepHash::Sha256 };
            let out = AwsLcRsa.decrypt(pkcs8, hash, ciphertext).await;
            return out.map_err(|e| e.0.replace("the account's private key cannot be read", RSA_KEY_ERROR));
        }
        self.rsa_seen.borrow_mut().push((pkcs8.into(), hash.into(), ciphertext.into()));
        self.rsa_error.borrow().clone().map_or(Ok(Zeroizing::new(b"plain".to_vec())), Err)
    }
    async fn socket_open(&self, url: &str) -> Result<u32, String> {
        self.check()?;
        Ok(u32::try_from(url.len()).unwrap_or_default())
    }
    async fn socket_send(&self, id: u32, frame: Frame) -> Result<(), String> {
        self.check()?;
        self.sent.borrow_mut().push((id, frame));
        Ok(())
    }
    fn socket_recv(&self, _id: u32) -> RecvFuture {
        self.recv_calls.set(self.recv_calls.get() + 1);
        let slot = Rc::new(RefCell::new(self.queued.borrow_mut().pop_front()));
        if slot.borrow().is_none() {
            self.waiting.borrow_mut().push_back(slot.clone());
        }
        Box::pin(poll_fn(move |_| slot.borrow_mut().take().map_or(Poll::Pending, Poll::Ready)))
    }
    fn socket_close(&self, id: u32) {
        self.closed.borrow_mut().push(id);
    }
    fn log(&self, message: &str) {
        self.logged.borrow_mut().push(message.into());
    }
}

fn ports() -> Ports<MockHost> {
    Ports(Rc::new(MockHost::default()))
}

fn err<T>(r: Result<T, dybw_core::ports::PortError>) -> String {
    r.err().map(|e| e.to_string()).unwrap_or_default()
}

#[test]
fn random_fills_large_buffers_in_chunks() {
    let p = ports();
    let mut buf = vec![0u8; 200_000];
    assert!(p.fill(&mut buf).is_ok());
    assert_eq!(*p.0.random_lens.borrow(), [65_536, 65_536, 65_536, 3_392]);
    assert!(buf.iter().all(|&b| b == 7));

    p.0.random_short.set(true);
    assert_eq!(err(p.fill(&mut buf)), "the host returned the wrong number of random bytes");
    p.0.fail.set(true);
    assert_eq!(err(p.fill(&mut buf)), "boom");
}

fn request(method: Method, max_body: usize) -> HttpRequest {
    HttpRequest {
        method,
        url: "https://x/y".into(),
        headers: vec![("A".into(), "b".into())],
        body: Some(Zeroizing::new(b"in".to_vec())),
        max_body,
    }
}

#[test]
fn http_refuses_a_body_over_max_body() {
    let p = ports();
    *p.0.http_answer.borrow_mut() = (200, vec![1; 11]);
    assert_eq!(err(block_on(p.send(request(Method::Get, 10)))), "the response is larger than 10 bytes");
    assert_eq!(block_on(p.send(request(Method::Get, 11))).map(|r| r.body.len()).ok(), Some(11));
    p.0.fail.set(true);
    assert_eq!(err(block_on(p.send(request(Method::Get, 11)))), "boom");
}

#[test]
fn http_passes_method_headers_and_bytes() {
    let p = ports();
    assert!(!p.refuses_redirects());
    p.0.refuses.set(true);
    assert!(p.refuses_redirects());
    *p.0.http_answer.borrow_mut() = (201, b"out".to_vec());
    for m in [Method::Get, Method::Post, Method::Put] {
        let res = block_on(p.send(request(m, 100))).ok();
        assert_eq!(res.map(|r| (r.status, r.body.to_vec())), Some((201, b"out".to_vec())));
    }
    let seen = p.0.http_seen.borrow();
    let methods: Vec<_> = seen.iter().map(|c| c.0.as_str()).collect();
    assert_eq!(methods, ["GET", "POST", "PUT"]);
    let call = (String::from("GET"), String::from("https://x/y"), vec![("A".into(), "b".into())], Some(b"in".to_vec()));
    assert_eq!(seen.first(), Some(&call));
    drop(seen);

    let mut no_body = request(Method::Get, 100);
    no_body.body = None;
    assert!(block_on(p.send(no_body)).is_ok());
    assert_eq!(p.0.http_seen.borrow().last().map(|c| c.3.clone()), Some(None));
}

#[test]
fn rsa_maps_hash_names_and_error_texts() {
    let p = ports();
    let out = block_on(p.decrypt(b"key", OaepHash::Sha1, b"ct")).ok();
    assert_eq!(out.as_deref().map(Vec::as_slice), Some(&b"plain"[..]));
    assert!(block_on(p.decrypt(b"key", OaepHash::Sha256, b"ct")).is_ok());
    let hashes: Vec<_> = p.0.rsa_seen.borrow().iter().map(|c| c.1.clone()).collect();
    assert_eq!(hashes, ["SHA-1", "SHA-256"]);
    assert_eq!(p.0.rsa_seen.borrow().first(), Some(&(b"key".to_vec(), "SHA-1".into(), b"ct".to_vec())));

    *p.0.rsa_error.borrow_mut() = Some(RSA_KEY_ERROR.into());
    assert_eq!(err(block_on(p.decrypt(b"k", OaepHash::Sha1, b"c"))), "the account's private key cannot be read");
    *p.0.rsa_error.borrow_mut() = Some("OperationError: secret detail".into());
    assert_eq!(err(block_on(p.decrypt(b"k", OaepHash::Sha1, b"c"))), "organization key decryption failed");
}

#[test]
fn a_dropped_recv_keeps_its_frame() {
    let p = ports();
    let mut socket = block_on(p.connect("wss://h")).ok().unwrap_or_else(|| unreachable!());
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut recv = pin!(socket.recv());
        assert!(recv.as_mut().poll(&mut cx).is_pending());
        // The JS promise resolves with the frame; the hub's timer drops the Rust future before polling it again.
        p.0.deliver(Some(Ok(Frame::Text("hello".into()))));
    }
    assert_eq!(block_on(socket.recv()).map(|r| r.ok()), Some(Some(Frame::Text("hello".into()))));
    assert_eq!(p.0.recv_calls.get(), 1, "the in-flight host recv was reused, not restarted");

    p.0.deliver(Some(Err("socket broke".into())));
    p.0.deliver(None);
    assert_eq!(block_on(socket.recv()).map(err), Some("socket broke".into()));
    assert!(block_on(socket.recv()).is_none());
    assert_eq!(p.0.recv_calls.get(), 3);

    assert!(block_on(socket.send(Frame::Binary(vec![1]))).is_ok());
    assert_eq!(*p.0.sent.borrow(), [(7, Frame::Binary(vec![1]))]);
    block_on(socket.close());
    assert_eq!(*p.0.closed.borrow(), [7]);

    p.0.fail.set(true);
    assert_eq!(err(block_on(socket.send(Frame::Text("x".into())))), "boom");
    assert_eq!(err(block_on(p.connect("wss://h"))), "boom");
}

fn kdf_input() -> Argon2Input {
    Argon2Input {
        password: Zeroizing::new(b"pw".to_vec()),
        salt: [3; 32],
        iterations: 3,
        memory_kib: 65_536,
        parallelism: 4,
    }
}

#[test]
fn argon2_input_reaches_the_host_and_output_is_32_bytes() {
    let p = ports();
    p.0.kdf_len.set(32);
    assert_eq!(block_on(p.argon2id(kdf_input())).ok().map(|k| *k), Some([9; 32]));
    assert_eq!(p.0.kdf_seen.borrow().first(), Some(&(b"pw".to_vec(), [3; 32], 3, 65_536, 4)));

    p.0.kdf_len.set(31);
    assert_eq!(err(block_on(p.argon2id(kdf_input()))), "argon2id did not return 32 bytes");
    p.0.fail.set(true);
    assert_eq!(err(block_on(p.argon2id(kdf_input()))), "boom");
}

#[test]
fn storage_and_secrets_round_trip() {
    let p = ports();
    block_on(async {
        assert!(Storage::save(&p, "k", b"v").await.is_ok());
        assert_eq!(Storage::load(&p, "k").await.ok(), Some(Some(b"v".to_vec())));
        assert!(Storage::remove(&p, "k").await.is_ok());
        assert_eq!(Storage::load(&p, "k").await.ok(), Some(None));

        assert!(Secrets::save(&p, "s", &Zeroizing::new("pw".into())).await.is_ok());
        let loaded = Secrets::load(&p, "s").await.ok().flatten();
        assert_eq!(loaded.as_deref().map(String::as_str), Some("pw"));
        assert!(Secrets::remove(&p, "s").await.is_ok());
        assert!(Secrets::load(&p, "s").await.ok().is_some_and(|s| s.is_none()));

        p.0.fail.set(true);
        assert_eq!(err(Storage::load(&p, "k").await), "boom");
        assert_eq!(err(Storage::save(&p, "k", b"v").await), "boom");
        assert_eq!(err(Storage::remove(&p, "k").await), "boom");
        assert_eq!(err(Secrets::load(&p, "s").await), "boom");
        assert_eq!(err(Secrets::save(&p, "s", &Zeroizing::new("pw".into())).await), "boom");
        assert_eq!(err(Secrets::remove(&p, "s").await), "boom");
    });
}

#[test]
fn clock_and_sleep_forward() {
    let p = ports();
    assert_eq!(p.now_ms(), 1_700_000_000_000);
    block_on(p.sleep_ms(250));
    assert_eq!(*p.0.slept.borrow(), [250]);
    p.0.log("hello");
    assert_eq!(*p.0.logged.borrow(), ["hello"]);
}

#[test]
fn a_dropped_socket_is_closed() {
    let p = ports();
    drop(block_on(p.connect("wss://h")));
    assert_eq!(*p.0.closed.borrow(), [7]);

    let mut socket = block_on(p.connect("wss://hh")).ok().unwrap_or_else(|| unreachable!());
    block_on(socket.close());
    block_on(socket.close());
    drop(socket);
    assert_eq!(*p.0.closed.borrow(), [7, 8], "closed once");
}

// ---- Session ----

#[expect(clippy::indexing_slicing, reason = "tests")]
mod session {
    use super::MockHost;
    use crate::session::{BUSY, LOCKED, STATE, STATE_UNREADABLE, Session, action, problem, report_json, warning};
    use dybw_core::crypto::{AwsLcRsa, KdfParams};
    use dybw_core::profile::{KdfSource, UnlockWarning};
    use dybw_core::sync::{Action, ActionError, ApplyError, Conflict, ConflictKind, SyncReport};
    use dybw_core::testing::block_on;
    use dybw_core::vault::Organizations;
    use dybw_vectors::server::VectorServer;
    use dybw_vectors::{Files, vectors_dir};
    use serde_json::{Value, json};
    use std::cell::Cell;
    use std::future::Future;
    use std::pin::pin;
    use std::rc::Rc;
    use std::task::{Context, Waker};
    use zeroize::Zeroizing;

    fn files() -> Files {
        Files::from_dir(&vectors_dir().unwrap_or_default()).unwrap_or_else(|e| panic!("{e}"))
    }

    fn account(name: &str) -> Value {
        serde_json::from_str(files().get(&format!("accounts/{name}.json")).unwrap_or_default()).unwrap_or_default()
    }

    /// A host serving account `name` with `ciphers`.
    fn host(name: &str, ciphers: Vec<Value>) -> Rc<MockHost> {
        let keys = block_on(dybw_vectors::keys::account_keys(&files(), name, false, &AwsLcRsa));
        let host = Rc::new(MockHost::default());
        host.refuses.set(true);
        *host.server.borrow_mut() = Some(VectorServer::new(keys.profile, ciphers, keys.prelogin));
        host
    }

    fn profile(name: &str) -> String {
        json!({
            "server": "https://vectors.invalid", "email": account(name)["email"], "clientId": "vectors",
            "deviceName": "test", "deviceType": 8, "clientName": "cli", "clientVersion": "0",
        })
        .to_string()
    }

    fn password(name: &str) -> Zeroizing<String> {
        Zeroizing::new(account(name)["password"].as_str().unwrap_or_default().to_owned())
    }

    fn session(host: &Rc<MockHost>) -> Session<MockHost> {
        Session::new(host.clone(), "obsidian").unwrap_or_else(|e| panic!("{e}"))
    }

    fn unlock(s: &Session<MockHost>, name: &str) -> Result<Value, String> {
        let out = block_on(s.unlock(&profile(name), Zeroizing::new("vectors".into()), password(name)))?;
        Ok(serde_json::from_str(&out).unwrap_or_default())
    }

    fn plan(s: &Session<MockHost>, ids: &[&str], values: &[&str]) -> Result<Value, String> {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
        let out = block_on(s.plan_pass("{}", own(ids), own(values)))?;
        Ok(serde_json::from_str(&out).unwrap_or_default())
    }

    #[test]
    fn a_session_unlocks_and_locks() {
        let host = host("cose-v2", vec![]);
        let s = session(&host);
        let summary = unlock(&s, "cose-v2");
        let summary = summary.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(summary["securityVersion"], 2);
        assert_eq!(summary["userKeyId"].as_str().map(str::len), Some(22));
        assert_eq!(summary["orgProblems"], json!([]));
        assert_eq!(plan(&s, &[], &[]), Ok(json!({ "actions": [], "massClear": null })));

        s.lock();
        assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()));
        assert_eq!(block_on(s.run_sync("{}", vec![], vec![])), Err(LOCKED.into()));
        assert_eq!(block_on(s.run_hub(|| {}, || false)), Err(LOCKED.into()));

        // A refused unlock leaves it locked.
        assert_eq!(unlock(&s, "cose-v2").map(|_| ()), Ok(()));
        let wrong = block_on(s.unlock(&profile("cose-v2"), Zeroizing::new("v".into()), Zeroizing::new("no".into())));
        assert_eq!(wrong, Err("wrong master password".into()));
        assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()));
    }

    #[test]
    fn the_planner_state_survives_through_storage() {
        let raw = files().get("generated/obsidian/sync/pull-new.json").unwrap_or_default().to_owned();
        let scenario: Value = serde_json::from_str(&raw).unwrap_or_default();
        let ciphers = scenario["ciphers"].as_array().cloned().unwrap_or_default();
        let host = host("pbkdf2", ciphers);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let expected = json!({ "actions": [{ "kind": "pull", "id": "alpha" }], "massClear": null });
        assert_eq!(plan(&s, &[], &[]), Ok(expected));
        let report = block_on(s.run_sync(r#"{"policy":"prefer-remote"}"#, vec![], vec![]));
        let report: Value = serde_json::from_str(&report.unwrap_or_else(|e| panic!("{e}"))).unwrap_or_default();
        assert_eq!(report["pulled"], json!(["alpha"]));
        assert_eq!(report["passes"], 1);
        assert!(host.store.borrow().contains_key(STATE));
        let value = host.secrets.borrow().get("alpha").cloned().unwrap_or_default();
        assert!(!value.is_empty(), "the pulled value went to the host's secrets");
        drop(s);

        // A new session plans from the saved base: the value is in sync, nothing to do.
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert_eq!(plan(&s, &["alpha"], &[&value]), Ok(json!({ "actions": [], "massClear": null })));
        // The same device id as before.
        assert_eq!(block_on(s.device_id()), block_on(session(&host).device_id()));
    }

    #[test]
    fn the_password_never_reaches_the_host() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let pw = password("pbkdf2");
        let has = |b: &[u8]| b.windows(pw.len()).any(|w| w == pw.as_bytes());
        // No host call, storage or secret got a copy of it. This cannot see WASM memory: that the session's
        // `Zeroizing` is wiped on drop is zeroize's guarantee, and the glue's copies are covered in bindings.rs.
        for (_, url, headers, body) in host.http_seen.borrow().iter() {
            assert!(!has(url.as_bytes()) && !headers.iter().any(|(_, v)| has(v.as_bytes())));
            assert!(!body.as_deref().is_some_and(has));
        }
        assert!(host.store.borrow().values().all(|v| !has(v)));
        assert!(host.secrets.borrow().values().all(|v| !has(v.as_bytes())));
        assert!(host.kdf_seen.borrow().is_empty() && host.logged.borrow().is_empty());
    }

    #[test]
    fn unlock_cached_runs_offline() {
        let keys = block_on(dybw_vectors::keys::account_keys(&files(), "pbkdf2", false, &AwsLcRsa));
        let host = Rc::new(MockHost::default());
        host.refuses.set(true);
        let s = session(&host);
        let mut p: Value = serde_json::from_str(&profile("pbkdf2")).unwrap_or_default();
        p["cachedSync"] = json!({ "profile": keys.profile, "folders": [], "ciphers": [] });
        p["preloginKdf"] = json!({ "type": "pbkdf2", "iterations": 600_000 });
        p["organizations"] = json!("all");
        let out = block_on(s.unlock_cached(&p.to_string(), password("pbkdf2")));
        assert!(out.is_ok_and(|o| o.contains("\"securityVersion\":0")));
        assert!(host.http_seen.borrow().is_empty());
        // The client is logged out: a sync fails, and the state is saved anyway.
        assert_eq!(plan(&s, &[], &[]), Err("not logged in".into()));
        assert_eq!(block_on(s.run_sync("{}", vec![], vec![])), Err("not logged in".into()));
        assert!(host.store.borrow().contains_key(STATE));
    }

    #[test]
    fn device_and_profile_answers() {
        let host = Rc::new(MockHost::default());
        assert!(Session::new(host.clone(), "bwss").is_ok());
        assert_eq!(Session::new(host.clone(), "x").err(), Some("unknown namespace".into()));
        let s = session(&host);
        let id = block_on(s.device_id()).unwrap_or_default();
        assert_eq!(id.len(), 36);

        assert_eq!(block_on(s.accept_kdf(r#"{"type":"pbkdf2","iterations":600000}"#, "https://o")), Ok(()));
        assert!(host.store.borrow().contains_key("kdf-pin"));
        let low = block_on(s.accept_kdf(r#"{"type":"argon2id","iterations":1,"memory":64,"parallelism":4}"#, "o"));
        assert!(low.is_err_and(|e| e.contains("out of range")));
        assert!(block_on(s.accept_kdf("{", "o")).is_err());
        assert_eq!(block_on(s.accept_security_version(3)), Ok(()));
        assert_eq!(host.store.borrow().get("security-version").map(Vec::as_slice), Some(&b"3"[..]));

        // Every refusal before the network names the problem.
        assert!(block_on(s.unlock("{", Zeroizing::default(), Zeroizing::default())).is_err());
        let mut p: Value = serde_json::from_str(&profile("pbkdf2")).unwrap_or_default();
        p["server"] = json!("http://example.com");
        let out = block_on(s.unlock_cached(&p.to_string(), Zeroizing::default()));
        assert!(out.is_err_and(|e| e.contains("https://")));
        p["server"] = json!("https://vectors.invalid");
        p["deviceName"] = json!("a\nb");
        let out = block_on(s.unlock_cached(&p.to_string(), Zeroizing::default()));
        assert!(out.is_err_and(|e| e.contains("control characters")));
        assert!(block_on(s.unlock_cached("{", Zeroizing::default())).is_err());
        // The redirect-following host is refused before credentials leave.
        let out = block_on(s.unlock(&profile("pbkdf2"), Zeroizing::default(), Zeroizing::default()));
        assert!(out.is_err_and(|e| e.contains("redirect")));

        host.fail.set(true);
        assert_eq!(block_on(s.device_id()), Err("host port failed: boom".into()));
        assert!(block_on(s.unlock(&profile("pbkdf2"), Zeroizing::default(), Zeroizing::default())).is_err());
    }

    #[test]
    fn sync_inputs_are_checked() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert_eq!(plan(&s, &["a"], &[]), Err("ids and values differ in length".into()));
        assert!(block_on(s.run_sync("{", vec![], vec![])).is_err());
        assert!(block_on(s.run_sync("{}", vec!["a".into()], vec![])).is_err());
        let rollback = block_on(s.plan_pass(r#"{"policy":"prefer-local","acceptRollback":true}"#, vec![], vec![]));
        assert!(rollback.is_ok());
        host.fail.set(true);
        let failed = block_on(s.run_sync("{}", vec![], vec![]));
        assert!(failed.is_err_and(|e| e.contains("boom")));
        host.fail.set(false);
        // The host is back: the next sync runs.
        assert!(block_on(s.run_sync("{}", vec![], vec![])).is_ok());
    }

    #[test]
    fn options_map_to_the_core() {
        use crate::session::{Kdf, Orgs, Policy};
        let kdf = |j: &str| serde_json::from_str::<Kdf>(j).ok().map(KdfParams::from);
        assert_eq!(kdf(r#"{"type":"pbkdf2","iterations":5}"#), Some(KdfParams::Pbkdf2 { iterations: 5 }));
        let argon = KdfParams::Argon2id { iterations: 1, memory_mib: 2, parallelism: 3 };
        assert_eq!(kdf(r#"{"type":"argon2id","iterations":1,"memory":2,"parallelism":3}"#), Some(argon));
        let orgs = |j: &str| serde_json::from_str::<Orgs>(j).ok().map(Organizations::from);
        assert!(matches!(orgs(r#""none""#), Some(Organizations::None)));
        assert!(matches!(orgs(r#""all""#), Some(Organizations::All)));
        assert!(matches!(orgs(r#"{"only":["o"]}"#), Some(Organizations::Only(ids)) if ids.contains("o")));
        let policy = |j: &str| serde_json::from_str::<Policy>(j).ok().map(dybw_core::sync::Policy::from);
        assert_eq!(policy(r#""ask""#), Some(dybw_core::sync::Policy::Ask));
        assert_eq!(policy(r#""prefer-remote""#), Some(dybw_core::sync::Policy::PreferRemote));
        assert_eq!(policy(r#""prefer-local""#), Some(dybw_core::sync::Policy::PreferLocal));
    }

    #[test]
    fn results_are_json() {
        let id = || String::from("a");
        let kinds: Vec<Value> = [
            Action::Pull(id()),
            Action::Push { id: id(), confirmed: true },
            Action::Create(id()),
            Action::Adopt(id()),
            Action::ClearLocal(id()),
            Action::Forget(id()),
            Action::Conflict { id: id(), kind: ConflictKind::BothChanged },
        ]
        .iter()
        .map(|a| action(a)["kind"].clone())
        .collect();
        assert_eq!(kinds, ["pull", "push", "create", "adopt", "clear-local", "forget", "conflict"]);
        assert_eq!(action(&Action::Conflict { id: id(), kind: ConflictKind::BothChanged })["conflict"], "both-changed");

        let conflict = Conflict {
            id: id(),
            kind: ConflictKind::LocalUnsynced,
            organization: None,
            organization_name: None,
            label: id(),
        };
        let report = SyncReport {
            conflicts: vec![conflict],
            errors: vec![ActionError { id: id(), error: ApplyError::NotText }],
            ..SyncReport::default()
        };
        let p = dybw_core::vault::OrgProblem { organization: "o".into(), reason: "r".into() };
        assert_eq!(problem(&p), json!({ "organization": "o", "reason": "r" }));
        let below = UnlockWarning::KdfBelowFloor {
            params: KdfParams::Pbkdf2 { iterations: 5_000 },
            kdf_source: KdfSource::Prelogin,
        };
        assert!(warning(&below).contains("5000"));
        let r = report_json(&report);
        assert_eq!(r["conflicts"], json!([{ "id": "a", "kind": "local-unsynced" }]));
        assert_eq!(r["errors"], json!([{ "id": "a", "error": "the value is not text" }]));
    }

    #[test]
    fn the_hub_connects_until_stopped() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let polls = Cell::new(0);
        let stop = || {
            polls.set(polls.get() + 1);
            polls.get() > 3
        };
        assert_eq!(block_on(s.run_hub(|| {}, stop)), Ok(()));
        // One socket opened on the hub URL (its id is the URL's length), then closed.
        assert_eq!(host.closed.borrow().len(), 1);
        assert!(!host.sent.borrow().is_empty());
    }

    fn pull_new() -> Vec<Value> {
        let raw = files().get("generated/obsidian/sync/pull-new.json").unwrap_or_default().to_owned();
        let scenario: Value = serde_json::from_str(&raw).unwrap_or_default();
        scenario["ciphers"].as_array().cloned().unwrap_or_default()
    }

    #[test]
    fn values_are_checked_after_they_are_wrapped() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        let one = || vec![String::from("v")];
        assert_eq!(block_on(s.plan_pass("{}", vec!["a".into()], one())), Err(LOCKED.into()));
        assert_eq!(block_on(s.run_sync("{}", vec!["a".into()], one())), Err(LOCKED.into()));
        assert_eq!(block_on(s.plan_pass("{}", vec![], one())), Err("ids and values differ in length".into()));
        assert!(block_on(s.run_sync("{", vec![], one())).is_err());
    }

    #[test]
    fn a_failed_secret_save_keeps_the_pull_out_of_the_state() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.fail_secret_save.set(true);
        assert_eq!(block_on(s.run_sync("{}", vec![], vec![])), Err("no secret storage".into()));
        let saved = host.store.borrow().get(STATE).cloned().unwrap_or_default();
        let saved: Value = serde_json::from_slice(&saved).unwrap_or_default();
        assert_eq!(saved["base"], json!({}), "the base does not record a pull the host does not hold");
        // The value is still missing here, so the next sync pulls it again, in this session and in a new one.
        let pull = json!({ "actions": [{ "kind": "pull", "id": "alpha" }], "massClear": null });
        assert_eq!(plan(&s, &[], &[]), Ok(pull.clone()));
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert_eq!(plan(&s, &[], &[]), Ok(pull));
    }

    #[test]
    fn a_failed_secret_save_keeps_the_old_base() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert!(block_on(s.run_sync("{}", vec![], vec![])).is_ok());
        let old = host.secrets.borrow().get("alpha").cloned().unwrap_or_default();
        // The item changed in Bitwarden; the new value cannot be saved here.
        let raw = files().get("generated/obsidian/sync/pull-remote-change.json").unwrap_or_default().to_owned();
        let changed: Value = serde_json::from_str(&raw).unwrap_or_default();
        let keys = block_on(dybw_vectors::keys::account_keys(&files(), "pbkdf2", false, &AwsLcRsa));
        let ciphers = changed["ciphers"].as_array().cloned().unwrap_or_default();
        *host.server.borrow_mut() = Some(VectorServer::new(keys.profile, ciphers, keys.prelogin));
        host.fail_secret_save.set(true);
        let local = || (vec![String::from("alpha")], vec![old.clone()]);
        let (ids, values) = local();
        assert!(block_on(s.run_sync("{}", ids, values)).is_err());
        let saved = host.store.borrow().get(STATE).cloned().unwrap_or_default();
        let saved: Value = serde_json::from_slice(&saved).unwrap_or_default();
        assert_eq!(saved["base"]["alpha"]["revisionDate"], "2026-01-01T00:00:00.000Z", "the base from before");
        // The old value is still the local one: the next sync pulls the new value, it never pushes the old one.
        let pull = json!({ "actions": [{ "kind": "pull", "id": "alpha" }], "massClear": null });
        assert_eq!(plan(&s, &["alpha"], &[&old]), Ok(pull));
    }

    #[test]
    fn a_failed_secret_save_keeps_the_pending_create() {
        let host = host("pbkdf2", pull_new());
        // A create queued earlier for `alpha`; the pull of the remote `alpha` drops it, unless its save fails.
        let queued = json!({
            "version": 1, "deviceId": "d", "base": {}, "pendingCreates": ["alpha"], "pendingScopes": { "alpha": "global" },
        });
        host.store.borrow_mut().insert(STATE.into(), queued.to_string().into_bytes());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.fail_secret_save.set(true);
        assert_eq!(block_on(s.run_sync("{}", vec![], vec![])), Err("no secret storage".into()));
        let saved = host.store.borrow().get(STATE).cloned().unwrap_or_default();
        let saved: Value = serde_json::from_slice(&saved).unwrap_or_default();
        assert_eq!(saved["pendingCreates"], json!(["alpha"]));
        assert_eq!(saved["pendingScopes"], json!({ "alpha": "global" }));
    }

    #[test]
    fn a_sync_stopped_by_lock_never_overwrites_a_newer_state() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let mut old = pin!(s.run_sync("{}", vec![], vec![]));
        assert!(old.as_mut().poll(&mut cx).is_pending());
        s.lock();
        // A newer session pulls `alpha` and saves its state while the old sync still waits on the host.
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert!(block_on(s.run_sync("{}", vec![], vec![])).is_ok());
        let newer = host.store.borrow().get(STATE).cloned();
        assert!(newer.as_deref().is_some_and(|b| String::from_utf8_lossy(b).contains("alpha")));
        assert_eq!(block_on(old), Err("Bitwarden was locked during the sync".into()));
        assert_eq!(host.store.borrow().get(STATE).cloned(), newer, "the stopped sync saved nothing");
    }

    #[test]
    fn lock_wins_over_a_running_hub() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let calls = Cell::new(0);
        // JS calls `lock` from a callback while the hub runs; its own stop never answers true.
        let stop = || {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                s.lock();
            }
            false
        };
        assert_eq!(block_on(s.run_hub(|| {}, stop)), Ok(()));
        assert_eq!(calls.get(), 3, "the hub stopped at its first check after lock");
        assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()));
        assert_eq!(block_on(s.run_hub(|| {}, || false)), Err(LOCKED.into()));
    }

    #[test]
    fn lock_wins_over_a_running_sync() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let mut sync = pin!(s.run_sync("{}", vec![], vec![]));
        assert!(sync.as_mut().poll(&mut cx).is_pending());
        // A second call while the first has the keys is refused, not thrown.
        assert_eq!(plan(&s, &[], &[]), Err(BUSY.into()));
        assert_eq!(block_on(s.run_hub(|| {}, || true)), Err(BUSY.into()));
        s.lock();
        assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()));
        // The sync stops before applying anything, and its keys are dropped, not put back.
        assert_eq!(block_on(sync), Err("Bitwarden was locked during the sync".into()));
        assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()));
        assert!(host.secrets.borrow().is_empty());
    }

    #[test]
    fn lock_wins_over_a_running_unlock() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let (pw, profile) = (password("pbkdf2"), profile("pbkdf2"));
        let mut unlocking = pin!(s.unlock(&profile, Zeroizing::new("v".into()), pw));
        assert!(unlocking.as_mut().poll(&mut cx).is_pending());
        s.lock();
        assert_eq!(block_on(unlocking), Err(LOCKED.into()));
        assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()));
    }

    #[test]
    fn an_unreadable_state_is_reported() {
        let host = host("pbkdf2", vec![]);
        host.store.borrow_mut().insert(STATE.into(), b"{not json".to_vec());
        let s = session(&host);
        let summary = unlock(&s, "pbkdf2").unwrap_or_default();
        assert_eq!(summary["warnings"], json!([STATE_UNREADABLE]));
    }
}

/// The real crypto behind the mock answers with the host's texts.
#[test]
fn the_mock_computes_for_real() {
    let p = ports();
    p.0.real.set(true);
    for hash in [OaepHash::Sha1, OaepHash::Sha256] {
        assert_eq!(err(block_on(p.decrypt(b"not a key", hash, b"c"))), "the account's private key cannot be read");
    }
    let mut input = kdf_input();
    input.memory_kib = 64;
    assert_eq!(block_on(p.argon2id(input)).map(|k| k.len()).ok(), Some(32));
    let mut input = kdf_input();
    input.memory_kib = 0;
    assert!(block_on(p.argon2id(input)).is_err());
}

#[cfg(feature = "vectors")]
#[expect(clippy::indexing_slicing, reason = "tests")]
mod vectors {
    use super::{MockHost, Ports};
    use crate::vectors::{cbor_json, msg_is, run_known_answers_json, run_vectors_json, unb64, unhex};
    use dybw_core::api::Msg;
    use dybw_core::crypto::{AwsLcRsa, Cbor};
    use dybw_core::testing::block_on;
    use dybw_vectors::{Files, Kind, run_all, vectors_dir};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    fn files() -> Files {
        Files::from_dir(&vectors_dir().unwrap_or_default()).unwrap_or_else(|e| panic!("{e}"))
    }

    fn real() -> Ports<MockHost> {
        let host = MockHost::default();
        host.real.set(true);
        Ports(Rc::new(host))
    }

    fn parse(json: &str) -> Value {
        serde_json::from_str(json).unwrap_or_default()
    }

    /// Every file of the vectors, with `rel` replaced by `text`.
    fn with(rel: &str, text: &str) -> Files {
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        let dir = vectors_dir().unwrap_or_default();
        for sub in ["generated", "accounts", "crypto"] {
            let root = dir.join(sub);
            let all = Files::from_dir(&root).unwrap_or_else(|e| panic!("{e}"));
            for name in walk(&root) {
                map.insert(format!("{sub}/{name}"), all.get(&name).unwrap_or_default().to_owned());
            }
        }
        map.insert(rel.into(), text.into());
        Files::from_map(map)
    }

    fn walk(dir: &std::path::Path) -> Vec<String> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let (path, name) = (entry.path(), entry.file_name().to_string_lossy().into_owned());
            if path.is_dir() {
                out.extend(walk(&path).into_iter().map(|n| format!("{name}/{n}")));
            } else {
                out.push(name);
            }
        }
        out
    }

    #[test]
    fn every_vector_runs_over_the_host() {
        let files = files();
        let out = parse(&block_on(run_vectors_json(&files, &real())));
        assert_eq!(out["failures"], json!([]));
        let mut native = 0;
        for ns in ["bwss", "obsidian"] {
            for kind in Kind::ALL {
                native += block_on(run_all(&files, ns, kind, &AwsLcRsa)).len();
            }
        }
        assert_eq!(out["results"].as_array().map(Vec::len), Some(native));
        assert!(native >= 211, "{native}");
    }

    #[test]
    fn a_vector_that_fails_is_reported() {
        let files = Files::from_map(BTreeMap::from([("generated/bwss/a.json".to_owned(), "{".to_owned())]));
        let out = parse(&block_on(run_vectors_json(&files, &real())));
        assert_eq!(out["results"].as_array().map(Vec::len), Some(3), "one entry per kind");
        assert!(out["results"][0][1].as_str().is_some_and(|e| e.starts_with("generated/bwss/a.json: ")));
        assert_eq!(out["failures"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn the_known_answers_pass_over_the_host() {
        let out = parse(&block_on(run_known_answers_json(&files(), &real())));
        let names = ["pbkdf2", "argon2id", "cose", "sdk", "msgpack", "marks"];
        assert_eq!(out, json!({ "results": names.map(|n| json!([n, null])), "failures": [] }));
    }

    fn answers(files: &Files) -> Vec<String> {
        let out = parse(&block_on(run_known_answers_json(files, &real())));
        out["failures"].as_array().into_iter().flatten().map(|f| f.as_str().unwrap_or_default().to_owned()).collect()
    }

    #[test]
    fn missing_files_fail_every_known_answer() {
        let failures = answers(&Files::from_map(BTreeMap::new()));
        assert_eq!(failures.len(), 6);
        assert!(failures[0].starts_with("pbkdf2: crypto/vectors.json is missing"), "{failures:?}");
        let broken = answers(&with("crypto/vectors.json", "{"));
        assert!(broken[0].starts_with("pbkdf2: EOF"), "{broken:?}");
        let account = answers(&with("accounts/pbkdf2.json", "{}"));
        assert_eq!(account, ["marks: malformed encrypted string or key"]);
    }

    /// Changes `pointer` of `rel` to `value` and answers the failures.
    fn tampered(rel: &str, pointer: &str, value: Value) -> Vec<String> {
        let mut v: Value = serde_json::from_str(files().get(rel).unwrap_or_default()).unwrap_or_default();
        if let Some(slot) = v.pointer_mut(pointer) {
            *slot = value;
        }
        answers(&with(rel, &v.to_string()))
    }

    #[test]
    fn a_wrong_answer_names_what_differs() {
        let cases = [
            ("crypto/vectors.json", "/pbkdf2/masterKey", json!("AAAA"), "pbkdf2: masterKey differs"),
            ("crypto/vectors.json", "/argon2id/stretched", json!("AAAA"), "argon2id: stretched differs"),
            ("crypto/vectors.json", "/pbkdf2/masterPasswordHash", json!("x"), "pbkdf2: hash differs"),
            ("crypto/vectors.json", "/encStrings", json!([]), "pbkdf2: an empty list"),
            ("crypto/cose-vectors.json", "/accounts/0/texts/0/plain", json!("x"), "cose: text differs"),
            ("crypto/cose-vectors.json", "/accounts/0/privateKey/pkcs8", json!("AAAA"), "cose: pkcs8 differs"),
            ("crypto/cose-vectors.json", "/accounts/0/itemKeys/0/key", json!("AAAA"), "cose: itemKey differs"),
            ("crypto/cose-vectors.json", "/accounts/0/itemKeys/0/fieldPlain", json!("x"), "cose: field differs"),
            ("crypto/sdk-m3.json", "/v1/card/plaintext", json!(null), "sdk: card differs"),
            ("crypto/sdk-m3.json", "/v1", json!({}), "sdk: an empty object"),
            ("crypto/sdk-m3.json", "/sealed/plaintext", json!(null), "sdk: sealed differs"),
            ("crypto/msgpack.json", "/0/expected", json!("x"), "msgpack: "),
            ("crypto/marks.json", "/0/mark", json!("x"), "marks: mark differs"),
        ];
        for (rel, pointer, value, want) in cases {
            let got = tampered(rel, pointer, value);
            assert!(got.len() == 1 && got[0].starts_with(want), "{rel}{pointer}: {got:?}");
        }
        // A key, an envelope or a msgpack that cannot be read names the crypto error.
        let bad_key = tampered("crypto/cose-vectors.json", "/accounts/0/userKey", json!("AAAA"));
        assert_eq!(bad_key, ["cose: malformed encrypted string or key"]);
        let bad_blob = tampered("crypto/sdk-m3.json", "/sealed/TEST_VECTOR_SEALED_BLOB/value", json!("{"));
        assert!(bad_blob[0].starts_with("sdk: EOF"), "{bad_blob:?}");
        let bad_hex = tampered("crypto/msgpack.json", "/0/hex", json!(""));
        assert_eq!(bad_hex, ["msgpack: truncated MessagePack data"]);
    }

    #[test]
    fn base64_and_hex_decode() {
        assert_eq!(unb64("TWFu"), b"Man");
        assert_eq!(unb64("TWE="), b"Ma");
        assert_eq!(unb64("TQ=="), b"M");
        assert_eq!(unb64("+/+/"), [0xfb, 0xff, 0xbf]);
        assert_eq!(unb64("az09"), [0x6b, 0x3d, 0x3d]);
        assert_eq!(unb64("T"), b"");
        assert_eq!(unhex("00fFzz7"), [0, 255, 0]);
    }

    #[test]
    fn cbor_becomes_json() {
        let map = Cbor::Map(vec![
            (Cbor::text("a"), Cbor::Array(vec![Cbor::Uint(1), Cbor::Nint(0), Cbor::Nint(u64::MAX)])),
            (Cbor::Uint(7), Cbor::Bool(true)),
            (Cbor::text("n"), Cbor::Null),
            (Cbor::text("b"), Cbor::bytes(vec![1])),
        ]);
        let want = json!({ "a": [1, -1, i64::MIN], "7": true, "n": null, "b": "<bytes>" });
        assert_eq!(cbor_json(&map), want);
    }

    #[test]
    fn msgpack_values_match_only_their_json() {
        let yes = [
            (Msg::Nil, json!(null)),
            (Msg::Bool(true), json!(true)),
            (Msg::Int(-3), json!(-3)),
            (Msg::Float(1.5), json!(1.5)),
            (Msg::Str("s".into()), json!("s")),
            (Msg::Array(vec![Msg::Nil]), json!([null])),
            (Msg::Map(vec![("k".into(), Msg::Nil)]), json!({ "k": null })),
            (Msg::Bin(vec![1, 2]), json!({ "$bin": "0102" })),
            (Msg::Int(1 << 70), json!({ "$big": (1_i128 << 70).to_string() })),
            (Msg::Timestamp { seconds: 2, nanos: 5_000_000 }, json!({ "$date": 2005 })),
        ];
        for (m, j) in &yes {
            assert!(msg_is(m, j), "{m:?}");
        }
        let no = [
            (Msg::Int(1), json!(1.5)),
            (Msg::Array(vec![Msg::Nil]), json!([])),
            (Msg::Array(vec![Msg::Nil]), json!([true])),
            (Msg::Map(vec![("k".into(), Msg::Nil)]), json!({})),
            (Msg::Map(vec![("k".into(), Msg::Nil)]), json!({ "j": null })),
            (Msg::Map(vec![("k".into(), Msg::Nil)]), json!({ "k": true })),
            (Msg::Bin(vec![1]), json!("01")),
            (Msg::Ext(1, vec![]), json!(null)),
        ];
        for (m, j) in &no {
            assert!(!msg_is(m, j), "{m:?}");
        }
    }
}
