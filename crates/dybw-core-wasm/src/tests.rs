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
    /// `socket_open` refuses this many times first, like a server refusing the token; `opens` counts the calls.
    refused_opens: Cell<usize>,
    opens: Cell<usize>,
    sent: RefCell<Vec<(u32, Frame)>>,
    closed: RefCell<Vec<u32>>,
    slept: RefCell<Vec<u64>>,
    logged: RefCell<Vec<String>>,
    refuses: Cell<bool>,
    /// `http` answers `Pending` this many times first, like a request still in flight.
    hold: Cell<usize>,
    /// Only `secret_save` fails.
    fail_secret_save: Cell<bool>,
    /// The `secret_save` call with this number (from 1) answers `Pending` once; `secret_saves` counts the calls.
    hold_secret_save: Cell<usize>,
    secret_saves: Cell<usize>,
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
        self.secret_saves.set(self.secret_saves.get() + 1);
        let mut hold = self.secret_saves.get() == self.hold_secret_save.get();
        poll_fn(|cx| {
            if !std::mem::take(&mut hold) {
                return Poll::Ready(());
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await;
        if self.fail_secret_save.get() {
            return Err("port".into());
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
        self.opens.set(self.opens.get() + 1);
        if self.refused_opens.get() > 0 {
            self.refused_opens.set(self.refused_opens.get() - 1);
            return Err("refused".into());
        }
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
    use crate::error::{BUSY, Error, INVALID, LOCKED, WRONG_PASSWORD};
    use crate::session::{STATE, STATE_UNREADABLE, Session, action, problem, report_json, warning};
    use dybw_core::crypto::{AwsLcRsa, ContentFormat, KdfParams};
    use dybw_core::profile::{KdfSource, UnlockWarning};
    use dybw_core::sync::{Action, ActionError, ApplyError, Conflict, ConflictKind, PassReport, Question, SyncReport};
    use dybw_core::testing::block_on;
    use dybw_core::vault::Organizations;
    use dybw_core::vault::scan::{Duplicate, SkipReason};
    use dybw_core::vault::write::HistoryQuestion;
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
        Files::from_dir(&vectors_dir().unwrap_or_default()).unwrap_or_else(|e| panic!("{e:?}"))
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

    const ORIGIN: &str = "https://vectors.invalid";

    fn profile(name: &str) -> String {
        json!({
            "server": ORIGIN, "email": account(name)["email"], "apiOrigin": ORIGIN, "clientId": "vectors",
            "deviceName": "test", "deviceType": 8, "clientName": "cli", "clientVersion": "0",
        })
        .to_string()
    }

    fn code(e: Error) -> String {
        e.code().to_owned()
    }

    fn message(e: Error) -> String {
        e.message().to_owned()
    }

    fn password(name: &str) -> Zeroizing<String> {
        Zeroizing::new(account(name)["password"].as_str().unwrap_or_default().to_owned())
    }

    fn session(host: &Rc<MockHost>) -> Session<MockHost> {
        Session::new(host.clone(), "obsidian").unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn unlock(s: &Session<MockHost>, name: &str) -> Result<Value, Error> {
        let out = block_on(s.unlock(&profile(name), Zeroizing::new("vectors".into()), password(name)))?;
        Ok(serde_json::from_str(&out).unwrap_or_default())
    }

    fn plan(s: &Session<MockHost>, ids: &[&str], values: &[&str]) -> Result<Value, String> {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
        let out = block_on(s.plan_pass("{}", own(ids), own(values))).map_err(code)?;
        Ok(serde_json::from_str(&out).unwrap_or_default())
    }

    #[test]
    fn a_session_unlocks_and_locks() {
        let host = host("cose-v2", vec![]);
        let s = session(&host);
        let summary = unlock(&s, "cose-v2");
        let summary = summary.unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(summary["securityVersion"], 2);
        assert_eq!(summary["userKeyId"].as_str().map(str::len), Some(22));
        assert_eq!(summary["orgProblems"], json!([]));
        assert_eq!(plan(&s, &[], &[]), Ok(json!({ "actions": [], "massClear": null })));

        s.lock();
        assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()));
        assert_eq!(block_on(s.run_sync("{}", vec![], vec![])).map_err(code), Err(LOCKED.into()));
        assert_eq!(block_on(s.run_hub(|| {}, || false)).map_err(code), Err(LOCKED.into()));

        // A refused unlock leaves it locked.
        assert_eq!(unlock(&s, "cose-v2").map(|_| ()), Ok(()));
        let wrong = block_on(s.unlock(&profile("cose-v2"), Zeroizing::new("v".into()), Zeroizing::new("no".into())));
        assert_eq!(wrong.map_err(code), Err("wrong-password".into()));
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
        let report: Value = serde_json::from_str(&report.unwrap_or_else(|e| panic!("{e:?}"))).unwrap_or_default();
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
        let wrong = block_on(s.unlock_cached(&p.to_string(), Zeroizing::new("no".into())));
        assert_eq!(wrong.map_err(code), Err("wrong-password".into()));
        let out = block_on(s.unlock_cached(&p.to_string(), password("pbkdf2")));
        assert!(out.is_ok_and(|o| o.contains("\"securityVersion\":0")));
        assert!(host.http_seen.borrow().is_empty());
        // The client is logged out: a sync fails, and the state is saved anyway.
        assert_eq!(plan(&s, &[], &[]), Err("api".into()));
        assert_eq!(block_on(s.run_sync("{}", vec![], vec![])).map_err(message), Err("not logged in".into()));
        assert!(host.store.borrow().contains_key(STATE));
    }

    #[test]
    fn device_and_profile_answers() {
        let host = Rc::new(MockHost::default());
        assert!(Session::new(host.clone(), "bwss").is_ok());
        assert_eq!(Session::new(host.clone(), "x").err().map(message), Some("unknown namespace".into()));
        let s = session(&host);
        let id = block_on(s.device_id()).unwrap_or_default();
        assert_eq!(id.len(), 36);

        assert_eq!(block_on(s.accept_kdf(r#"{"type":"pbkdf2","iterations":600000}"#, "https://o")), Ok(()));
        assert!(host.store.borrow().contains_key("kdf-pin"));
        let low = block_on(s.accept_kdf(r#"{"type":"argon2id","iterations":1,"memory":64,"parallelism":4}"#, "o"));
        assert!(low.is_err_and(|e| e.code() == INVALID && e.message().contains("out of range")));
        assert!(block_on(s.accept_kdf("{", "o")).is_err());
        assert_eq!(block_on(s.accept_security_version(3)), Ok(()));
        assert_eq!(host.store.borrow().get("security-version").map(Vec::as_slice), Some(&b"3"[..]));

        // Every refusal before the network names the problem.
        assert!(block_on(s.unlock("{", Zeroizing::default(), Zeroizing::default())).is_err());
        let mut p: Value = serde_json::from_str(&profile("pbkdf2")).unwrap_or_default();
        p["server"] = json!("http://example.com");
        let out = block_on(s.unlock_cached(&p.to_string(), Zeroizing::default()));
        assert!(out.is_err_and(|e| e.code() == INVALID && e.message().contains("https://")));
        p["server"] = json!("https://vectors.invalid");
        p["deviceName"] = json!("a\nb");
        let out = block_on(s.unlock_cached(&p.to_string(), Zeroizing::default()));
        assert!(out.is_err_and(|e| e.code() == INVALID && e.message().contains("control characters")));
        assert!(block_on(s.unlock_cached("{", Zeroizing::default())).is_err());
        // The redirect-following host is refused before credentials leave.
        let out = block_on(s.unlock(&profile("pbkdf2"), Zeroizing::default(), Zeroizing::default()));
        assert!(out.is_err_and(|e| e.code() == "origin-not-acknowledged" && e.message().contains("redirect")));

        host.fail.set(true);
        assert_eq!(block_on(s.device_id()).map_err(message), Err("host port failed: boom".into()));
        assert!(block_on(s.unlock(&profile("pbkdf2"), Zeroizing::default(), Zeroizing::default())).is_err());
    }

    #[test]
    fn sync_inputs_are_checked() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert_eq!(plan(&s, &["a"], &[]), Err(INVALID.into()));
        assert!(block_on(s.run_sync("{", vec![], vec![])).is_err());
        assert!(block_on(s.run_sync("{}", vec!["a".into()], vec![])).is_err());
        let rollback = block_on(s.plan_pass(r#"{"policy":"prefer-local","acceptRollback":true}"#, vec![], vec![]));
        assert!(rollback.is_ok());
        host.fail.set(true);
        let failed = block_on(s.run_sync("{}", vec![], vec![]));
        assert!(failed.is_err_and(|e| e.code() == "api" && e.message().contains("boom")));
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
        assert_eq!(
            warning(&below),
            "The KDF parameters are below the recommended floor: PBKDF2 5000 iterations (from prelogin)."
        );
        let argon = UnlockWarning::KdfBelowFloor {
            params: KdfParams::Argon2id { iterations: 2, memory_mib: 16, parallelism: 1 },
            kdf_source: KdfSource::SyncUnlockData,
        };
        assert_eq!(
            warning(&argon),
            "The KDF parameters are below the recommended floor: Argon2id 2 iterations, 16 MiB, parallelism 1 (from sync unlock data)."
        );
        let r = report_json(&report);
        let conflict = json!({ "id": "a", "kind": "local-unsynced", "label": "a", "organization": null, "organizationName": null });
        assert_eq!(r["conflicts"], json!([conflict]));
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
        assert_eq!(block_on(s.plan_pass("{}", vec!["a".into()], one())).map_err(code), Err(LOCKED.into()));
        assert_eq!(block_on(s.run_sync("{}", vec!["a".into()], one())).map_err(code), Err(LOCKED.into()));
        let differ = block_on(s.plan_pass("{}", vec![], one())).map_err(message);
        assert_eq!(differ, Err("ids and values differ in length".into()));
        assert!(block_on(s.run_sync("{", vec![], one())).is_err());
    }

    #[test]
    fn a_failed_secret_save_keeps_the_pull_out_of_the_state() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.fail_secret_save.set(true);
        assert_eq!(block_on(s.run_sync("{}", vec![], vec![])).map_err(code), Err("port".into()));
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
        assert_eq!(block_on(s.run_sync("{}", vec![], vec![])).map_err(code), Err("port".into()));
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
        assert_eq!(block_on(old).map_err(message), Err("Bitwarden was locked during the sync".into()));
        assert_eq!(host.store.borrow().get(STATE).cloned(), newer, "the stopped sync saved nothing");
    }

    /// Locks while the `at`-th of the three pulled values is being saved; answers the saved secrets' ids and
    /// whether the state was saved.
    fn lock_during_save(at: usize) -> (Vec<String>, bool) {
        let raw = files().get("generated/obsidian/sync/multi-id-sorted.json").unwrap_or_default().to_owned();
        let scenario: Value = serde_json::from_str(&raw).unwrap_or_default();
        let host = host("pbkdf2", scenario["ciphers"].as_array().cloned().unwrap_or_default());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.hold_secret_save.set(at);
        let mut cx = Context::from_waker(Waker::noop());
        let mut sync = pin!(s.run_sync("{}", vec![], vec![]));
        assert!(sync.as_mut().poll(&mut cx).is_pending());
        s.lock();
        assert_eq!(block_on(sync).map_err(code), Err(LOCKED.into()));
        let mut saved: Vec<String> = host.secrets.borrow().keys().cloned().collect();
        saved.sort();
        (saved, host.store.borrow().contains_key(STATE))
    }

    #[test]
    fn a_lock_during_the_saves_stops_them() {
        // The save in flight completes; nothing after it starts.
        assert_eq!(lock_during_save(1), (vec!["alpha".into()], false));
        assert_eq!(lock_during_save(3), (vec!["alpha".into(), "beta".into(), "gamma".into()], false));
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
        assert_eq!(block_on(s.run_hub(|| {}, || false)).map_err(code), Err(LOCKED.into()));
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
        s.lock();
        assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()));
        // The sync stops before applying anything, and its keys are dropped, not put back.
        assert_eq!(block_on(sync).map_err(message), Err("Bitwarden was locked during the sync".into()));
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
        assert_eq!(block_on(unlocking).map_err(code), Err(LOCKED.into()));
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

    /// `profile_json` with `key` set to `value`.
    fn with(profile_json: &str, key: &str, value: Value) -> String {
        let mut p: Value = serde_json::from_str(profile_json).unwrap_or_default();
        p[key] = value;
        p.to_string()
    }

    fn unlock_with(s: &Session<MockHost>, profile_json: &str, name: &str) -> Result<String, Error> {
        block_on(s.unlock(profile_json, Zeroizing::new("vectors".into()), password(name)))
    }

    #[test]
    fn an_api_key_for_another_origin_is_refused() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        let other = with(&profile("pbkdf2"), "apiOrigin", json!("https://identity.bitwarden.com"));
        let e = unlock_with(&s, &other, "pbkdf2").err();
        assert_eq!(e.as_ref().map(Error::code), Some("wrong-origin"));
        assert_eq!(e.map(message), Some("the API key belongs to another server".into()));
        // A profile without `apiOrigin` names no server, so the key goes nowhere.
        let mut none: Value = serde_json::from_str(&profile("pbkdf2")).unwrap_or_default();
        none.as_object_mut().map(|p| p.remove("apiOrigin"));
        assert_eq!(unlock_with(&s, &none.to_string(), "pbkdf2").map_err(code), Err("wrong-origin".into()));
        assert!(host.http_seen.borrow().is_empty(), "no request may leave");
        assert!(unlock(&s, "pbkdf2").is_ok(), "the origin it was entered for logs in");
    }

    #[test]
    fn a_self_hosted_origin_needs_an_acknowledgement_when_the_host_follows_redirects() {
        let host = host("pbkdf2", vec![]);
        host.refuses.set(false);
        let s = session(&host);
        let e = unlock(&s, "pbkdf2").err();
        assert_eq!(e.as_ref().map(Error::code), Some("origin-not-acknowledged"));
        assert_eq!(e.as_ref().and_then(|e| e.field("origin")), Some(&json!(ORIGIN)));
        assert!(host.http_seen.borrow().is_empty(), "no request may leave, not even /connect/token");

        assert_eq!(block_on(s.acknowledged_origins()), Ok("[]".into()));
        assert_eq!(block_on(s.acknowledge_origin("https://other.invalid")), Ok(()));
        assert_eq!(block_on(s.acknowledge_origin(&format!("{ORIGIN}/identity"))), Ok(()));
        let both = r#"["https://other.invalid","https://vectors.invalid"]"#;
        assert_eq!(block_on(s.acknowledged_origins()), Ok(both.into()));
        for bad in ["no url", "file:///etc/passwd", "data:text/plain,x", "http://vectors.invalid"] {
            assert_eq!(block_on(s.acknowledge_origin(bad)).map_err(code), Err(INVALID.into()), "{bad}");
        }
        assert!(unlock(&s, "pbkdf2").is_ok(), "the acknowledged origin logs in");
        assert!(plan(&s, &[], &[]).is_ok());
        // The unlock dropped the other server's acknowledgement.
        assert_eq!(block_on(s.acknowledged_origins()), Ok(format!(r#"["{ORIGIN}"]"#)));

        assert_eq!(block_on(s.forget_origin(ORIGIN)), Ok(()));
        assert_eq!(block_on(s.acknowledged_origins()), Ok("[]".into()));
        assert_eq!(unlock(&s, "pbkdf2").map_err(code), Err("origin-not-acknowledged".into()));

        host.fail.set(true);
        assert_eq!(block_on(s.acknowledged_origins()).map_err(code), Err("port".into()));
        assert_eq!(block_on(s.acknowledge_origin(ORIGIN)).map_err(code), Err("port".into()));
        assert_eq!(block_on(s.forget_origin(ORIGIN)).map_err(code), Err("port".into()));
    }

    /// A remembered key is no way around ADR 0018: the API key would leave the same way.
    #[test]
    fn a_key_unlock_needs_the_acknowledgement_too() {
        let host = host("pbkdf2", vec![]);
        host.refuses.set(false);
        let e = key_unlock(&session(&host), "pbkdf2", &user_key_b64("pbkdf2")).err();
        assert_eq!(e.as_ref().map(Error::code), Some("origin-not-acknowledged"));
        assert_eq!(e.as_ref().and_then(|e| e.field("origin")), Some(&json!(ORIGIN)));
        assert!(host.http_seen.borrow().is_empty(), "no request may leave, not even /connect/token");
    }

    #[test]
    fn a_rejection_reaches_js_as_json() {
        let host = host("pbkdf2", vec![]);
        let e = block_on(session(&host).plan_pass("{}", vec![], vec![])).err().map(String::from);
        let e: Value = serde_json::from_str(&e.unwrap_or_default()).unwrap_or_default();
        assert_eq!(e, json!({ "code": "locked", "message": "Bitwarden is locked" }));
    }

    #[test]
    fn a_weakened_kdf_names_both_kdfs_and_the_origin() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(block_on(s.accept_kdf(r#"{"type":"pbkdf2","iterations":700000}"#, ORIGIN)).is_ok());
        let e = unlock(&s, "pbkdf2").err().unwrap_or_else(Error::locked);
        assert_eq!(e.code(), "kdf-weakened");
        assert_eq!(e.field("pinned"), Some(&json!({ "type": "pbkdf2", "iterations": 700_000 })));
        assert_eq!(e.field("offered"), Some(&json!({ "type": "pbkdf2", "iterations": 600_000 })));
        assert_eq!(e.field("source"), Some(&json!("prelogin")));
        assert_eq!(e.field("origin"), Some(&json!(ORIGIN)));
        assert!(e.message().contains("weaker"));
        // `offered` and `origin` are what `acceptKdf` takes: accepting them unlocks.
        let (offered, origin) = (e.field("offered").map(Value::to_string), e.field("origin").and_then(Value::as_str));
        assert!(block_on(s.accept_kdf(&offered.unwrap_or_default(), origin.unwrap_or_default())).is_ok());
        assert!(unlock(&s, "pbkdf2").is_ok());
    }

    #[test]
    fn an_unreadable_kdf_pin_is_its_own_code() {
        let host = host("pbkdf2", vec![]);
        host.store.borrow_mut().insert("kdf-pin".into(), b"{".to_vec());
        assert_eq!(unlock(&session(&host), "pbkdf2").map_err(code), Err("kdf-pin-unreadable".into()));
    }

    #[test]
    fn a_security_downgrade_names_both_versions() {
        let host = host("cose-v2", vec![]);
        let s = session(&host);
        assert!(block_on(s.accept_security_version(5)).is_ok());
        let e = unlock(&s, "cose-v2").err().unwrap_or_else(Error::locked);
        assert_eq!(e.code(), "security-downgrade");
        assert_eq!((e.field("seen"), e.field("offered")), (Some(&json!(5)), Some(&json!(2))));
    }

    #[test]
    fn a_security_state_fault_is_named() {
        let host = host("cose", vec![]);
        let e = unlock(&session(&host), "cose").err().unwrap_or_else(Error::locked);
        assert_eq!((e.code(), e.field("fault")), ("security-state", Some(&json!("missing"))));
    }

    fn key_unlock(s: &Session<MockHost>, name: &str, key: &str) -> Result<Value, Error> {
        let (secret, key) = (Zeroizing::new("vectors".into()), Zeroizing::new(key.into()));
        let out = block_on(s.unlock_with_key(&profile(name), secret, key))?;
        Ok(serde_json::from_str(&out).unwrap_or_default())
    }

    fn user_key_b64(name: &str) -> String {
        account(name)["userKey"].as_str().unwrap_or_default().to_owned()
    }

    /// `host`, with a private key under a COSE user key (no account file has one).
    fn host_with_private_key(name: &str) -> Rc<MockHost> {
        let keys = block_on(dybw_vectors::keys::account_keys(&files(), name, false, &AwsLcRsa));
        let rng = dybw_core::testing::SeededRandom::new(5);
        let mut profile = keys.profile;
        profile["privateKey"] = json!(keys.user.encrypt_as(b"pkcs8", ContentFormat::Pkcs8, &rng).ok());
        let host = Rc::new(MockHost::default());
        host.refuses.set(true);
        *host.server.borrow_mut() = Some(VectorServer::new(profile, vec![], keys.prelogin));
        host
    }

    #[test]
    fn a_remembered_key_unlocks_again() {
        for (name, host) in [("org", host("org", vec![])), ("cose-v2", host_with_private_key("cose-v2"))] {
            let s = session(&host);
            assert_eq!(s.export_user_key().map_err(code), Err(LOCKED.into()), "{name}");
            let summary = unlock(&s, name).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            let key = s.export_user_key().unwrap_or_default();
            assert_eq!(key, user_key_b64(name), "{name}: the plugin's format, base64 of the padded key");
            s.lock();
            assert_eq!(s.export_user_key().map_err(code), Err(LOCKED.into()), "{name}");
            let pin = host.store.borrow().get("kdf-pin").cloned();
            host.http_seen.borrow_mut().clear();
            let again = key_unlock(&s, name, &key).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            for field in ["userKeyId", "securityVersion", "orgProblems"] {
                assert_eq!(again[field], summary[field], "{name}: {field}");
            }
            let urls: Vec<String> = host.http_seen.borrow().iter().map(|c| c.1.clone()).collect();
            assert!(urls.len() == 2 && urls.iter().all(|u| !u.contains("prelogin")), "{name}: {urls:?}");
            assert_eq!(host.store.borrow().get("kdf-pin").cloned(), pin, "{name}: the KDF pin is untouched");
            assert_eq!(plan(&s, &[], &[]), Ok(json!({ "actions": [], "massClear": null })), "{name}");
            assert_eq!(s.export_user_key(), Ok(key), "{name}");
            s.lock();
        }
    }

    /// A key that no longer opens the private key (another account's, or one from before a rotation) is
    /// `wrong-password`; a key that is no key is `invalid` before any request. Neither changes what is stored.
    #[test]
    fn a_wrong_remembered_key_is_refused_and_changes_nothing() {
        let host = host("org", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "org").is_ok());
        s.lock();
        let stored = host.store.borrow().clone();
        for other in ["pbkdf2", "cose-v2"] {
            let e = key_unlock(&s, "org", &user_key_b64(other)).err().unwrap_or_else(Error::locked);
            assert_eq!((e.code(), e.message()), (WRONG_PASSWORD, "wrong master password"), "{other}");
            assert_eq!(*host.store.borrow(), stored, "{other}");
            assert_eq!(plan(&s, &[], &[]), Err(LOCKED.into()), "{other}");
        }
        host.http_seen.borrow_mut().clear();
        for bad in ["not base64!", "AAAA", ""] {
            assert_eq!(key_unlock(&s, "org", bad).map_err(code), Err(INVALID.into()), "{bad:?}");
        }
        assert!(host.http_seen.borrow().is_empty());
        assert_eq!(*host.store.borrow(), stored);
        // A key unlock locks first, as a password unlock does.
        assert!(unlock(&s, "org").is_ok());
        assert_eq!(key_unlock(&s, "org", "AAAA").map_err(code), Err(INVALID.into()));
        assert_eq!(s.export_user_key().map_err(code), Err(LOCKED.into()));
        // The profile's `apiOrigin` and the security state are checked as for a password.
        let other = with(&profile("org"), "apiOrigin", json!("https://identity.bitwarden.com"));
        let key = Zeroizing::new(user_key_b64("org"));
        let e = block_on(s.unlock_with_key(&other, Zeroizing::new("vectors".into()), key)).map_err(code);
        assert_eq!(e, Err("wrong-origin".into()));
        assert!(block_on(s.accept_security_version(2)).is_ok());
        let e = key_unlock(&s, "org", &user_key_b64("org")).map_err(code);
        assert_eq!(e, Err("security-downgrade".into()));
    }

    #[test]
    fn export_user_key_is_busy_while_a_call_has_the_keys() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.hold.set(1);
        let mut cx = Context::from_waker(Waker::noop());
        let mut syncing = pin!(s.run_sync("{}", vec![], vec![]));
        assert!(syncing.as_mut().poll(&mut cx).is_pending());
        assert_eq!(s.export_user_key().map_err(code), Err(BUSY.into()));
        assert!(block_on(syncing).is_ok());
        assert_eq!(s.export_user_key(), Ok(user_key_b64("pbkdf2")));
    }

    /// Every core variant the options name has a code the session takes back to it: a new variant fails to compile
    /// in `next_*` until it is listed here, then fails the round trip until the session lists it.
    #[test]
    fn every_core_kind_question_and_answer_round_trips() {
        use crate::session::{ANSWERS, KINDS, QUESTIONS, by_code};
        use dybw_core::vault::write::HistoryAnswer;
        fn next_kind(k: Option<ConflictKind>) -> Option<ConflictKind> {
            use ConflictKind::*;
            match k {
                None => Some(BothChanged),
                Some(BothChanged) => Some(LocalUnsynced),
                Some(LocalUnsynced) => Some(DeletedRemotely),
                Some(DeletedRemotely) => Some(OrganizationClaim),
                Some(OrganizationClaim) => Some(OrganizationPush),
                Some(OrganizationPush) => None,
            }
        }
        fn next_question(q: Option<HistoryQuestion>) -> Option<HistoryQuestion> {
            match q {
                None => Some(HistoryQuestion::FirstWriteBack),
                Some(HistoryQuestion::FirstWriteBack) => Some(HistoryQuestion::EvictsForeign),
                Some(HistoryQuestion::EvictsForeign) => None,
            }
        }
        fn next_answer(a: Option<HistoryAnswer>) -> Option<HistoryAnswer> {
            match a {
                None => Some(HistoryAnswer::WriteToLogin),
                Some(HistoryAnswer::WriteToLogin) => Some(HistoryAnswer::KeepSeparate),
                Some(HistoryAnswer::KeepSeparate) => None,
            }
        }
        let kinds: Vec<_> = std::iter::successors(next_kind(None), |k| next_kind(Some(*k))).collect();
        let questions: Vec<_> = std::iter::successors(next_question(None), |q| next_question(Some(*q))).collect();
        let answers: Vec<_> = std::iter::successors(next_answer(None), |a| next_answer(Some(*a))).collect();
        assert_eq!((kinds.len(), questions.len(), answers.len()), (KINDS.len(), QUESTIONS.len(), ANSWERS.len()));
        let s = session(&host("pbkdf2", vec![]));
        // Options are read before the keys: a code the session takes answers `locked`, any other `invalid`.
        let option = |o: Value| block_on(s.plan_pass(&o.to_string(), vec![], vec![])).map_err(code);
        for k in kinds {
            assert_eq!(by_code(&KINDS, ConflictKind::code, k.code()), Ok(k));
            let o = json!({ "overrides": { "a": { "policy": "ask", "kind": k.code() } } });
            assert_eq!(option(o), Err(LOCKED.into()), "{k:?}");
        }
        for q in questions {
            assert_eq!(by_code(&QUESTIONS, HistoryQuestion::code, q.code()), Ok(q));
        }
        for a in answers {
            let (code, _) = ANSWERS.iter().copied().find(|(_, x)| *x == a).unwrap_or_else(|| panic!("{a:?}"));
            assert_eq!(by_code(&ANSWERS, |(c, _)| c, code).map(|(_, x)| x), Ok(a));
            for q in QUESTIONS {
                let o = json!({ "answers": { "a": { "question": q.code(), "answer": code } } });
                assert_eq!(option(o), Err(LOCKED.into()), "{q:?} {a:?}");
            }
        }
        let unknown = json!({ "overrides": { "a": { "policy": "ask", "kind": "no-such-kind" } } });
        assert_eq!(option(unknown), Err(INVALID.into()));
    }

    #[test]
    fn a_mass_clear_counts_the_clears() {
        let raw = files().get("generated/obsidian/sync/multi-id-sorted.json").unwrap_or_default().to_owned();
        let scenario: Value = serde_json::from_str(&raw).unwrap_or_default();
        let host = host("pbkdf2", scenario["ciphers"].as_array().cloned().unwrap_or_default());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert!(block_on(s.run_sync("{}", vec![], vec![])).is_ok());
        let (ids, values): (Vec<String>, Vec<String>) = host.secrets.borrow().clone().into_iter().unzip();
        // Every synced item disappeared from Bitwarden.
        let keys = block_on(dybw_vectors::keys::account_keys(&files(), "pbkdf2", false, &AwsLcRsa));
        *host.server.borrow_mut() = Some(VectorServer::new(keys.profile, vec![], keys.prelogin));
        let e = block_on(s.run_sync("{}", ids, values)).err().unwrap_or_else(Error::locked);
        assert_eq!((e.code(), e.field("clears"), e.field("base")), ("mass-clear", Some(&json!(3)), Some(&json!(3))));
    }

    #[test]
    fn an_http_failure_carries_its_status() {
        let host = Rc::new(MockHost::default());
        host.refuses.set(true);
        *host.http_answer.borrow_mut() = (500, Vec::new());
        let e = unlock(&session(&host), "pbkdf2").err().unwrap_or_else(Error::locked);
        assert_eq!((e.code(), e.field("status")), ("api", Some(&json!(500))));
    }

    #[test]
    fn a_failed_port_is_its_own_code() {
        let host = Rc::new(MockHost::default());
        host.fail.set(true);
        assert_eq!(block_on(session(&host).device_id()).map_err(code), Err("port".into()));
        assert_eq!(block_on(session(&host).accept_security_version(1)).map_err(code), Err("port".into()));
    }

    #[test]
    fn every_core_error_maps_to_a_code() {
        use dybw_core::api::ApiError;
        use dybw_core::crypto::CryptoError;
        use dybw_core::profile::{ProfileError, SecurityFault};
        let api = |e: ApiError| Error::from(e).code().to_owned();
        assert_eq!(api(ApiError::Http { status: 404, message: String::new() }), "api");
        for e in [
            ApiError::Network("n".into()),
            ApiError::Protocol("p".into()),
            ApiError::RedirectsNotRefused,
            ApiError::NotLoggedIn,
            ApiError::TooLarge,
            ApiError::NotSynced,
        ] {
            assert_eq!(api(e), "api");
        }
        assert_eq!(api(ApiError::Invalid("i".into())), INVALID);
        assert_eq!(api(ApiError::WrongOrigin), "wrong-origin");
        let refused = Error::from(ApiError::OriginNotAcknowledged { origin: "https://o".into() });
        assert_eq!((refused.code(), refused.field("origin")), ("origin-not-acknowledged", Some(&json!("https://o"))));
        assert_eq!(Error::from(ApiError::TooLarge).field("status"), None);

        let crypto = |e: CryptoError| Error::from(ProfileError::Crypto(e)).code().to_owned();
        assert_eq!(crypto(CryptoError::Port("p".into())), "port");
        for e in [CryptoError::Malformed, CryptoError::BadMac, CryptoError::Kdf("k".into()), CryptoError::WrongKey] {
            assert_eq!(crypto(e), INVALID);
        }
        assert_eq!(Error::from(ProfileError::IncompleteUnlockData).code(), INVALID);
        assert_eq!(Error::from(ProfileError::Api(ApiError::WrongOrigin)).code(), "wrong-origin");

        let fault = |f| Error::from(ProfileError::SecurityState(f)).field("fault").cloned();
        assert_eq!(fault(SecurityFault::Invalid), Some(json!("invalid")));
        assert_eq!(fault(SecurityFault::StoredUnreadable), Some(json!("stored-unreadable")));

        let argon = KdfParams::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        let weak = ProfileError::KdfWeakened { pinned: argon, offered: argon, kdf_source: KdfSource::SyncUnlockData };
        let weak = Error::from(weak).at("https://o");
        let expected = json!({ "type": "argon2id", "iterations": 3, "memory": 64, "parallelism": 4 });
        assert_eq!(weak.field("pinned"), Some(&expected));
        assert_eq!(weak.field("source"), Some(&json!("sync-unlock-data")));
        assert_eq!(weak.field("origin"), Some(&json!("https://o")));
        // Only a weakened KDF takes the origin.
        assert_eq!(Error::busy().at("https://o"), Error::busy());
    }

    fn scenario(name: &str) -> Value {
        let raw = files().get(&format!("generated/obsidian/sync/{name}.json")).unwrap_or_default().to_owned();
        serde_json::from_str(&raw).unwrap_or_default()
    }

    fn ciphers(scenario: &Value) -> Vec<Value> {
        scenario["ciphers"].as_array().cloned().unwrap_or_default()
    }

    /// The scenario's `device` as the plugin's saved state of device `d`, fingerprints marked from the plaintext.
    fn seed_state(host: &MockHost, scenario: &Value) {
        let keys = block_on(dybw_vectors::keys::account_keys(&files(), "pbkdf2", false, &AwsLcRsa));
        let marker = keys.into_keys(&dybw_core::vault::Namespace::OBSIDIAN).marker;
        let base: serde_json::Map<String, Value> = scenario["device"]["base"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(id, e)| {
                let fingerprint = marker.mark_b64(id, e["value"].as_str().unwrap_or_default());
                let entry =
                    json!({ "cipherId": e["cipher"], "revisionDate": e["revisionDate"], "fingerprint": fingerprint });
                (id.clone(), entry)
            })
            .collect();
        let state = json!({ "version": 1, "deviceId": "d", "base": base, "pendingCreates": [], "pendingScopes": {} });
        host.store.borrow_mut().insert(STATE.into(), state.to_string().into_bytes());
    }

    fn json_of(out: Result<String, Error>) -> Result<Value, String> {
        Ok(serde_json::from_str(&out.map_err(code)?).unwrap_or_default())
    }

    fn saved_state(host: &MockHost) -> Value {
        serde_json::from_slice(&host.store.borrow().get(STATE).cloned().unwrap_or_default()).unwrap_or_default()
    }

    #[test]
    fn an_override_changes_the_plan_for_its_kind_only() {
        let host = host("org", ciphers(&scenario("org-claim-with-local-asks")));
        host.real.set(true);
        let s = session(&host);
        let p = with(&profile("org"), "organizations", json!("all"));
        let summary = unlock_with(&s, &p, "org");
        assert!(summary.as_ref().is_ok_and(|s| s.contains(r#""orgProblems":[]"#)), "{summary:?}");
        let planned = |options: Value| {
            let options = options.to_string();
            json_of(block_on(s.plan_pass(&options, vec!["alpha".into()], vec!["shared-secret".into()])))
                .map(|p| p["actions"].clone())
        };
        let asked = json!([{ "kind": "conflict", "id": "alpha", "conflict": "organization-claim" }]);
        assert_eq!(planned(json!({})), Ok(asked.clone()));
        let take = |kind: &str| json!({ "overrides": { "alpha": { "policy": "prefer-remote", "kind": kind } } });
        assert_eq!(planned(take("organization-claim")), Ok(json!([{ "kind": "pull", "id": "alpha" }])));
        // A decision about another kind of conflict is not this one's.
        assert_eq!(planned(take("both-changed")), Ok(asked));
        assert_eq!(planned(take("no-such-kind")), Err(INVALID.into()));
        let report = json_of(block_on(s.run_sync("{}", vec!["alpha".into()], vec!["shared-secret".into()])));
        let conflict = json!({
            "id": "alpha", "kind": "organization-claim", "label": "Login c1", "organization": "org-a",
            "organizationName": "Org A",
        });
        assert_eq!(report.map(|r| r["conflicts"].clone()), Ok(json!([conflict])));
    }

    #[test]
    fn accept_rollbacks_takes_only_the_revisions_shown_and_accept_rollback_all() {
        let grouped = scenario("rollback-grouped");
        let host = host("pbkdf2", ciphers(&grouped));
        seed_state(&host, &grouped);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let (ids, values) = (vec!["alpha", "beta", "gamma"], vec!["o1", "o2", "o3"]);
        let sync = |options: Value| {
            let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
            json_of(block_on(s.run_sync(&options.to_string(), own(&ids), own(&values)))).unwrap_or_default()
        };
        const SHOWN: &str = "2026-01-01T00:00:00.000Z";
        let held = |id: &str, c: &str| json!({ "id": id, "cipherId": c, "revisionDate": SHOWN });
        let report = sync(json!({}));
        assert_eq!(report["rollbacks"], json!([held("alpha", "c1"), held("beta", "c2"), held("gamma", "c3")]));
        // c2 at a revision the user was not shown stays held.
        let report = sync(json!({ "acceptRollbacks": { "c1": SHOWN, "c2": "2025-12-01T00:00:00.000Z" } }));
        assert_eq!(report["pulled"], json!(["alpha"]));
        assert_eq!(report["rollbacks"], json!([held("beta", "c2"), held("gamma", "c3")]), "not taken unseen");
        let report = sync(json!({ "acceptRollback": true, "acceptRollbacks": {} }));
        assert_eq!((&report["pulled"], &report["rollbacks"]), (&json!(["beta", "gamma"]), &json!([])));
        let refused = block_on(s.run_sync(r#"{"acceptRollbacks":["c1"]}"#, vec![], vec![]));
        assert_eq!(refused.map_err(code), Err(INVALID.into()), "cipher ids to revision dates, nothing else");
    }

    #[test]
    fn an_answer_covers_only_the_question_it_was_given_for() {
        let pushed = scenario("history-question-holds-push");
        let host = host("pbkdf2", ciphers(&pushed));
        seed_state(&host, &pushed);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let sync = |options: Value| {
            let options = options.to_string();
            json_of(block_on(s.run_sync(&options, vec!["alpha".into()], vec!["new-secret".into()]))).unwrap_or_default()
        };
        let report = sync(json!({}));
        assert_eq!(report["pushed"], json!([]));
        let label = report["questions"][0]["label"].clone();
        assert!(label.is_string());
        let question = json!([{ "id": "alpha", "label": label, "question": "first-write-back" }]);
        assert_eq!(report["questions"], question);
        // ADR 0016: an answer to another question does not cover this one.
        let answer = |q: &str| json!({ "answers": { "alpha": { "question": q, "answer": "write-to-login" } } });
        let report = sync(answer("evicts-foreign-history"));
        assert_eq!((&report["pushed"], &report["questions"]), (&json!([]), &question));
        let report = sync(answer("first-write-back"));
        assert_eq!((&report["pushed"], &report["questions"]), (&json!(["alpha"]), &json!([])));
        let keep = json!({ "answers": { "alpha": { "question": "first-write-back", "answer": "keep-separate" } } });
        assert!(block_on(s.plan_pass(&keep.to_string(), vec![], vec![])).is_ok());
    }

    #[test]
    fn options_take_the_vault_and_the_upload_folder() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let options = json!({ "vaultName": "Notes", "uploadFolder": "Secrets", "policy": "ask" }).to_string();
        let plan = json_of(block_on(s.plan_pass(&options, vec![], vec![])));
        assert_eq!(plan.map(|p| p["actions"].clone()), Ok(json!([{ "kind": "pull", "id": "alpha" }])));
        let unknown = block_on(s.plan_pass(r#"{"massClear":true}"#, vec![], vec![]));
        assert_eq!(unknown.map_err(code), Err(INVALID.into()));
        for bad in [
            json!({ "answers": { "a": { "question": "first-write-back", "answer": "cancel" } } }),
            json!({ "answers": { "a": { "question": "why", "answer": "keep-separate" } } }),
        ] {
            let out = block_on(s.plan_pass(&bad.to_string(), vec![], vec![]));
            assert_eq!(out.map_err(code), Err(INVALID.into()), "{bad}");
        }
    }

    #[test]
    fn every_report_field_reaches_js() {
        let pair = || vec![(String::from("a"), String::from("c"))];
        let conflict = Conflict {
            id: "a".into(),
            kind: ConflictKind::OrganizationPush,
            organization: Some("org".into()),
            organization_name: Some("Org <b>".into()),
            label: "GitHub".into(),
        };
        let duplicate = Duplicate { id: "a".into(), kept: "c".into(), left: vec!["d".into()], bound_kept: true };
        let report = SyncReport {
            pulled: vec!["p".into()],
            pushed: vec!["u".into()],
            created: vec!["n".into()],
            cleared: vec!["x".into()],
            conflicts: vec![conflict],
            skipped: PassReport {
                skipped: vec![("c".into(), SkipReason::NewerFormat)],
                duplicates: vec![duplicate],
                unknown_features: vec![("c".into(), vec!["dybw:x".into()])],
                held: pair(),
                rollbacks: vec![("a".into(), "c".into(), "2026-01-01".into())],
                read_only: pair(),
                unreadable: vec!["c".into()],
                questions: vec![Question {
                    id: "a".into(),
                    question: HistoryQuestion::EvictsForeign,
                    label: "GitHub".into(),
                }],
            },
            errors: vec![ActionError { id: "a".into(), error: ApplyError::NotText }],
            passes: 3,
            kept_changing: true,
        };
        let pair = json!([{ "id": "a", "cipherId": "c" }]);
        let r = report_json(&report);
        let want = json!({
            "pulled": ["p"], "pushed": ["u"], "created": ["n"], "cleared": ["x"],
            "errors": [{ "id": "a", "error": "the value is not text" }], "passes": 3, "keptChanging": true,
            "conflicts": [{
                "id": "a", "kind": "organization-push", "label": "GitHub", "organization": "org",
                "organizationName": "Org <b>",
            }],
            "questions": [{ "id": "a", "label": "GitHub", "question": "evicts-foreign-history" }],
            "rollbacks": [{ "id": "a", "cipherId": "c", "revisionDate": "2026-01-01" }], "held": pair, "readOnly": pair,
            "unknownFeatures": [{ "cipherId": "c", "features": ["dybw:x"] }],
            "unreadable": ["c"],
            "duplicates": [{ "id": "a", "kept": "c", "left": ["d"], "boundKept": true }],
            "skipped": [{ "cipherId": "c", "reason": "newer-format" }],
            "warnings": r["warnings"],
        });
        assert_eq!(r, want);
        assert_eq!(r["warnings"].as_array().map(Vec::len), Some(7), "{}", r["warnings"]);
        assert_eq!(report_json(&SyncReport::default())["warnings"], json!([]));
        // A conflict without an organization names none.
        let r = report_json(&SyncReport { conflicts: vec![conflict_without_org()], ..SyncReport::default() });
        assert_eq!(
            (&r["conflicts"][0]["organization"], &r["conflicts"][0]["organizationName"]),
            (&Value::Null, &Value::Null)
        );
    }

    fn conflict_without_org() -> Conflict {
        Conflict {
            id: "a".into(),
            kind: ConflictKind::BothChanged,
            organization: None,
            organization_name: None,
            label: "a".into(),
        }
    }

    #[test]
    fn the_hub_keeps_running_during_a_sync() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let mut sync = pin!(s.run_sync("{}", vec![], vec![]));
        assert!(sync.as_mut().poll(&mut cx).is_pending());
        let polls = Cell::new(0);
        let stop = || {
            polls.set(polls.get() + 1);
            polls.get() > 3
        };
        assert_eq!(block_on(s.run_hub(|| {}, stop)), Ok(()), "not busy");
        // It connected with its twin's token.
        assert_eq!(host.closed.borrow().len(), 1);
        let report = json_of(block_on(sync)).unwrap_or_default();
        assert_eq!(report["pulled"], json!(["alpha"]));
        // And again after the sync.
        polls.set(0);
        assert_eq!(block_on(s.run_hub(|| {}, stop)), Ok(()));
        assert_eq!(host.closed.borrow().len(), 2);
    }

    fn token_requests(host: &MockHost) -> usize {
        host.http_seen.borrow().iter().filter(|c| c.1.ends_with("/connect/token")).count()
    }

    #[test]
    fn the_hub_renews_a_refused_token_while_a_sync_has_the_keys() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let logins = token_requests(&host);
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let mut sync = pin!(s.run_sync("{}", vec![], vec![]));
        assert!(sync.as_mut().poll(&mut cx).is_pending());
        host.refused_opens.set(1);
        let polls = Cell::new(0);
        let stop = || {
            polls.set(polls.get() + 1);
            polls.get() > 3
        };
        assert_eq!(block_on(s.run_hub(|| {}, stop)), Ok(()));
        assert_eq!(token_requests(&host), logins + 1, "its twin logged in again, through the same gate");
        assert_eq!((host.opens.get(), host.closed.borrow().len()), (2, 1), "then connected at once");
        let report = json_of(block_on(sync)).unwrap_or_default();
        assert_eq!(report["pulled"], json!(["alpha"]), "the sync was never busy");
        // The twin was put back: the next hub needs no login.
        polls.set(0);
        assert_eq!(block_on(s.run_hub(|| {}, stop)), Ok(()));
        assert_eq!((token_requests(&host), host.opens.get()), (logins + 1, 3));
    }

    #[test]
    fn lock_during_the_hubs_renewal_drops_its_twin_and_opens_nothing() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.refused_opens.set(1);
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let mut hub = pin!(s.run_hub(|| {}, || false));
        assert!(hub.as_mut().poll(&mut cx).is_pending(), "renewing");
        s.lock();
        assert_eq!(block_on(hub), Ok(()));
        assert_eq!(host.opens.get(), 1, "only the refused open");
        // A new unlock gets a twin of its own.
        assert!(unlock(&s, "pbkdf2").is_ok());
        let polls = Cell::new(0);
        assert_eq!(
            block_on(s.run_hub(
                || {},
                || {
                    polls.set(polls.get() + 1);
                    polls.get() > 3
                }
            )),
            Ok(())
        );
        assert_eq!((host.opens.get(), host.closed.borrow().len()), (2, 1));
    }

    #[test]
    fn lock_stops_a_hub_running_during_a_sync() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let mut sync = pin!(s.run_sync("{}", vec![], vec![]));
        assert!(sync.as_mut().poll(&mut cx).is_pending());
        let calls = Cell::new(0);
        let stop = || {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                s.lock();
            }
            false
        };
        assert_eq!(block_on(s.run_hub(|| {}, stop)), Ok(()));
        assert_eq!(calls.get(), 3, "the hub stopped at its first check after lock");
        assert_eq!(block_on(s.run_hub(|| {}, || false)).map_err(code), Err(LOCKED.into()));
        assert_eq!(block_on(sync).map_err(code), Err(LOCKED.into()));
        assert!(host.secrets.borrow().is_empty(), "nothing ran with the old keys");
    }

    #[test]
    fn uploads_are_queued_with_their_scope() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert_eq!(block_on(s.queue_upload("k", "global")).map_err(code), Err(LOCKED.into()));
        assert_eq!(s.synced_ids().map_err(code), Err(LOCKED.into()));
        assert!(unlock(&s, "pbkdf2").is_ok());
        let device = block_on(s.device_id()).unwrap_or_default();
        assert_eq!(block_on(s.queue_upload("k", "global")), Ok(()));
        assert_eq!(block_on(s.queue_upload("v", " vault:Notes ")), Ok(()));
        assert_eq!(block_on(s.queue_upload("d", "device")), Ok(()));
        // Queued again with another scope: listed once, with the new scope.
        assert_eq!(block_on(s.queue_upload("k", "device:someone-else")), Ok(()));
        for (id, scope) in [("k", "planet:mars"), ("k", "vault:"), ("bad id", "global"), ("obsidian:x", "global")] {
            assert_eq!(block_on(s.queue_upload(id, scope)).map_err(code), Err(INVALID.into()), "{id} {scope}");
        }
        let own = format!("device:{device}");
        let saved = saved_state(&host);
        assert_eq!(saved["pendingCreates"], json!(["k", "v", "d"]));
        assert_eq!(saved["pendingScopes"], json!({ "k": own, "v": "vault:Notes", "d": own }));
        assert_eq!(json_of(s.synced_ids()), Ok(json!({ "base": [], "pendingCreates": ["k", "v", "d"] })));
        host.fail.set(true);
        assert_eq!(block_on(s.queue_upload("k", "global")).map_err(code), Err("port".into()));
    }

    #[test]
    fn reset_state_works_locked_or_unlocked_but_not_while_busy() {
        let host = host("pbkdf2", pull_new());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert!(block_on(s.run_sync("{}", vec![], vec![])).is_ok());
        assert!(block_on(s.queue_upload("k", "global")).is_ok());
        let ids = json_of(s.synced_ids()).unwrap_or_default();
        assert_eq!((&ids["base"], &ids["pendingCreates"]), (&json!(["alpha"]), &json!(["k"])));

        // While a sync has the keys.
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let mut sync = pin!(s.run_sync("{}", vec![], vec![]));
        assert!(sync.as_mut().poll(&mut cx).is_pending());
        assert_eq!(block_on(s.reset_state()).map_err(code), Err(BUSY.into()));
        assert_eq!(s.synced_ids().map_err(code), Err(BUSY.into()));
        assert_eq!(block_on(s.queue_upload("k", "global")).map_err(code), Err(BUSY.into()));
        assert!(block_on(sync).is_ok());

        let device = saved_state(&host)["deviceId"].clone();
        assert_eq!(block_on(s.reset_state()), Ok(()));
        assert_eq!(json_of(s.synced_ids()), Ok(json!({ "base": [], "pendingCreates": [] })));
        let empty = json!({ "version": 1, "deviceId": device, "base": {}, "pendingCreates": [], "pendingScopes": {} });
        assert_eq!(saved_state(&host), empty);

        // Locked: the saved state is reset, keeping its device id.
        assert!(block_on(s.queue_upload("k", "global")).is_ok());
        s.lock();
        assert_eq!(block_on(s.reset_state()), Ok(()));
        assert_eq!(saved_state(&host), empty);
        // Nothing saved yet, or unreadable: a fresh state for this device.
        let fresh = Rc::new(MockHost::default());
        fresh.store.borrow_mut().insert(STATE.into(), b"{".to_vec());
        let s = session(&fresh);
        assert_eq!(block_on(s.reset_state()), Ok(()));
        assert_eq!(saved_state(&fresh)["deviceId"], json!(block_on(s.device_id()).unwrap_or_default()));
        fresh.fail.set(true);
        assert_eq!(block_on(s.reset_state()).map_err(code), Err("port".into()));
    }

    #[test]
    fn a_locked_reset_wins_over_an_unlock_in_flight() {
        let pushed = scenario("history-question-holds-push");
        let host = host("pbkdf2", ciphers(&pushed));
        seed_state(&host, &pushed);
        let s = session(&host);
        host.hold.set(2);
        let mut cx = Context::from_waker(Waker::noop());
        let (pw, profile) = (password("pbkdf2"), profile("pbkdf2"));
        let mut unlocking = pin!(s.unlock(&profile, Zeroizing::new("v".into()), pw));
        assert!(unlocking.as_mut().poll(&mut cx).is_pending());
        assert_eq!(block_on(s.reset_state()), Ok(()));
        // The unlock would load the state from before the reset: it is stopped instead.
        assert_eq!(block_on(unlocking).map_err(code), Err(LOCKED.into()));
        assert_eq!(saved_state(&host)["base"], json!({}));
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert_eq!(json_of(s.synced_ids()), Ok(json!({ "base": [], "pendingCreates": [] })));
    }

    /// `pull-new`'s item under the cipher id `cipher` and the secret id `id`, scoped `scope`.
    fn scoped(cipher: &str, id: &str, scope: &str) -> Value {
        let keys = block_on(dybw_vectors::keys::account_keys(&files(), "pbkdf2", false, &AwsLcRsa));
        let rng = dybw_core::testing::SeededRandom::new(1);
        let enc = |t: &str| keys.user.encrypt_str(t, &rng).unwrap_or_default();
        let mut c = pull_new()[0].clone();
        c["id"] = json!(cipher);
        c["fields"][0]["value"] = json!(enc(id));
        let field = json!({ "name": enc("obsidian:scope"), "value": enc(scope), "type": 0 });
        if let Some(f) = c["fields"].as_array_mut() {
            f.push(field);
        }
        c
    }

    #[test]
    fn an_item_applies_by_its_vault_and_device_scope() {
        let mut ciphers = pull_new();
        ciphers.extend([
            scoped("c2", "other", "vault:Other"),
            scoped("c3", "notes", "vault:Notes"),
            scoped("c4", "mine", "device:d"),
            scoped("c5", "theirs", "device:e"),
        ]);
        let host = host("pbkdf2", ciphers);
        let state = json!({ "version": 1, "deviceId": "d", "base": {}, "pendingCreates": [], "pendingScopes": {} });
        host.store.borrow_mut().insert(STATE.into(), state.to_string().into_bytes());
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        let plan = json_of(block_on(s.plan_pass(r#"{"vaultName":"Notes"}"#, vec![], vec![])));
        let pulls = ["alpha", "mine", "notes"].map(|id| json!({ "kind": "pull", "id": id }));
        assert_eq!(plan.map(|p| p["actions"].clone()), Ok(json!(pulls)));
    }

    #[test]
    fn a_create_goes_to_the_upload_folder() {
        let host = host("pbkdf2", vec![]);
        let s = session(&host);
        assert!(unlock(&s, "pbkdf2").is_ok());
        assert_eq!(block_on(s.queue_upload("new", "global")), Ok(()));
        let options = r#"{"uploadFolder":"Secrets"}"#;
        let report = json_of(block_on(s.run_sync(options, vec!["new".into()], vec!["v".into()])));
        assert_eq!(report.map(|r| r["created"].clone()), Ok(json!(["new"])));
        let seen = host.http_seen.borrow();
        let posted = |path: &str| seen.iter().find(|(m, u, _, _)| m == "POST" && u.ends_with(path)).cloned();
        assert!(posted("/api/folders").is_some(), "the folder was created");
        let body = posted("/api/ciphers").and_then(|(_, _, _, b)| b).unwrap_or_default();
        let body: Value = serde_json::from_slice(&body).unwrap_or_default();
        assert_eq!(body["folderId"], "folder-created");
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
    use crate::vectors::{
        cbor_json, msg_is, panic_for_test, run_known_answers_json, run_perf_json, run_vectors_json, unb64, unhex,
    };
    use dybw_core::api::Msg;
    use dybw_core::crypto::{AwsLcRsa, Cbor};
    use dybw_core::testing::block_on;
    use dybw_vectors::{Files, Kind, run_all, vectors_dir};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    fn files() -> Files {
        Files::from_dir(&vectors_dir().unwrap_or_default()).unwrap_or_else(|e| panic!("{e:?}"))
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
            let all = Files::from_dir(&root).unwrap_or_else(|e| panic!("{e:?}"));
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
    fn the_timings_run_over_the_host() {
        // The mock's clock stands still: every timing is 0.
        let out = parse(&block_on(run_perf_json(&files(), &real())));
        let rows = json!([["pbkdf2-600k", 0, null], ["decrypt-1000-of-5000", 0, null], ["plan-10000", 0, null]]);
        assert_eq!(out, json!({ "results": rows }));
    }

    #[test]
    fn a_timing_that_fails_is_reported() {
        let kat = files().get("crypto/vectors.json").unwrap_or_default().replace("600000", "1");
        let files = Files::from_map(BTreeMap::from([("crypto/vectors.json".to_owned(), kat)]));
        let out = parse(&block_on(run_perf_json(&files, &real())));
        let errors = json!([
            ["pbkdf2-600k", 0, "iterations differs"],
            ["decrypt-1000-of-5000", 0, "generated/obsidian/sync/pull-new.json is missing"],
            ["plan-10000", 0, null]
        ]);
        assert_eq!(out["results"], errors);
    }

    #[test]
    #[should_panic(expected = "secret-sentinel")]
    fn panic_for_test_panics() {
        panic_for_test("secret-sentinel");
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
        assert_eq!(unb64("TWE="), Ok(b"Ma".to_vec()));
        assert_eq!(unb64("+/+/"), Ok(vec![0xfb, 0xff, 0xbf]));
        assert_eq!(unb64("TWE"), Err("not base64".into()));
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
