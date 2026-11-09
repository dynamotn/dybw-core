use crate::host::{Host, RSA_KEY_ERROR, RecvFuture};
use crate::ports::Ports;
use dybw_core::ports::{
    Argon2Input, Clock, EventSocket, Events, Frame, Http, HttpRequest, KdfRunner, Method, OaepHash, Random, RsaOaep,
    Secrets, Storage,
};
use dybw_core::testing::block_on;
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
        self.http_seen.borrow_mut().push((method.into(), url.into(), headers.to_vec(), body.map(<[u8]>::to_vec)));
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
        self.kdf_seen.borrow_mut().push((password.into(), *salt, iterations, memory_kib, parallelism));
        Ok(Zeroizing::new(vec![9; self.kdf_len.get()]))
    }
    async fn rsa_oaep_decrypt(
        &self,
        pkcs8: &[u8],
        hash: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
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
