//! Host ports: what the core needs from its host (design §6.2). Not `Send`, so one core runs on tokio and in WASM.
#![expect(async_fn_in_trait, reason = "design §6.2: ports are not Send, so one core runs on tokio and in WASM")]

use std::fmt;
use zeroize::Zeroizing;

/// A host failure. The text never carries a secret.
#[derive(Debug)]
pub struct PortError(pub String);

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PortError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
}

pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Zeroizing<Vec<u8>>>,
}

pub struct HttpResponse {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
}

pub trait Http {
    /// Whether the host refuses to follow redirects (ADR 0018, handled in M6).
    fn refuses_redirects(&self) -> bool;
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError>;
}

pub trait Storage {
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, PortError>;
    async fn save(&self, key: &str, data: &[u8]) -> Result<(), PortError>;
    async fn remove(&self, key: &str) -> Result<(), PortError>;
}

pub trait Secrets {
    async fn load(&self, key: &str) -> Result<Option<Zeroizing<String>>, PortError>;
    async fn save(&self, key: &str, data: &Zeroizing<String>) -> Result<(), PortError>;
    async fn remove(&self, key: &str) -> Result<(), PortError>;
}

pub trait Clock {
    fn now_ms(&self) -> i64;
    async fn sleep_ms(&self, ms: u64);
}

pub trait Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), PortError>;
}

pub struct Argon2Input {
    pub password: Zeroizing<Vec<u8>>,
    pub salt: [u8; 32],
    pub iterations: u32,
    pub memory_kib: u32,
    pub parallelism: u32,
}

pub trait KdfRunner {
    async fn argon2id(&self, input: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError>;
}

pub enum Frame {
    Text(String),
    Binary(Vec<u8>),
}

pub trait EventSocket {
    async fn send(&mut self, frame: Frame) -> Result<(), PortError>;
    async fn recv(&mut self) -> Option<Result<Frame, PortError>>;
    async fn close(&mut self);
}

pub trait Events {
    type Socket: EventSocket;
    async fn connect(&self, url: &str) -> Result<Self::Socket, PortError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepHash {
    Sha1,
    Sha256,
}

pub trait RsaOaep {
    async fn decrypt(&self, pkcs8: &[u8], hash: OaepHash, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, PortError>;
}

pub trait Prompter {
    async fn secret(&self, prompt: &str) -> Result<Option<Zeroizing<String>>, PortError>;
}

pub trait Confirmer {
    async fn confirm(&self, question: &str) -> Result<bool, PortError>;
}

/// Declared only; implemented with ADR 0006 (design §5).
pub trait Protector {}

#[cfg(all(test, feature = "testing"))]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::testing::block_on;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Fake(Rc<RefCell<Vec<HttpRequest>>>);

    impl Http for Fake {
        fn refuses_redirects(&self) -> bool {
            true
        }
        async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
            self.0.borrow_mut().push(req);
            Ok(HttpResponse { status: 200, body: Default::default() })
        }
    }

    #[test]
    fn ports_run_without_send() {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let fake = Fake(seen.clone());
        let req = HttpRequest { method: Method::Get, url: "https://x/y".into(), headers: vec![], body: None };
        assert!(fake.refuses_redirects());
        assert_eq!(block_on(fake.send(req)).unwrap().status, 200);
        assert_eq!(seen.borrow().first().unwrap().url, "https://x/y");
        assert_eq!(PortError("boom".into()).to_string(), "boom");
    }
}
