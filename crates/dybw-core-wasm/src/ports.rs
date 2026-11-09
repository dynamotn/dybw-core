//! The core's ports over a [`Host`]. Every buffer that held a secret is kept in `Zeroizing`, so it is wiped on drop.

use crate::host::{Host, RSA_KEY_ERROR, RecvFuture};
use dybw_core::ports::{
    Argon2Input, Clock, EventSocket, Events, Frame, Http, HttpRequest, HttpResponse, KdfRunner, Method, OaepHash,
    PortError, Random, RsaOaep, Secrets, Storage,
};
use std::rc::Rc;
use zeroize::Zeroizing;

/// The `getRandomValues` limit per call.
const RANDOM_CHUNK: usize = 65_536;

/// Every core port, implemented on one host.
pub struct Ports<H: Host>(pub Rc<H>);

impl<H: Host> Http for Ports<H> {
    fn refuses_redirects(&self) -> bool {
        self.0.refuses_redirects()
    }
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        let method = match req.method {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
        };
        let (status, body) = self
            .0
            .http(method, &req.url, &req.headers, req.body.as_deref().map(Vec::as_slice))
            .await
            .map_err(PortError)?;
        // The host cannot stream: it checks the length after the fact, then this drop wipes it.
        if body.len() > req.max_body {
            return Err(PortError(format!("the response is larger than {} bytes", req.max_body)));
        }
        Ok(HttpResponse { status, body })
    }
}

impl<H: Host> Storage for Ports<H> {
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, PortError> {
        self.0.storage_load(key).await.map_err(PortError)
    }
    async fn save(&self, key: &str, data: &[u8]) -> Result<(), PortError> {
        self.0.storage_save(key, data).await.map_err(PortError)
    }
    async fn remove(&self, key: &str) -> Result<(), PortError> {
        self.0.storage_remove(key).await.map_err(PortError)
    }
}

impl<H: Host> Secrets for Ports<H> {
    async fn load(&self, key: &str) -> Result<Option<Zeroizing<String>>, PortError> {
        self.0.secret_load(key).await.map_err(PortError)
    }
    async fn save(&self, key: &str, data: &Zeroizing<String>) -> Result<(), PortError> {
        self.0.secret_save(key, data).await.map_err(PortError)
    }
    async fn remove(&self, key: &str) -> Result<(), PortError> {
        self.0.secret_remove(key).await.map_err(PortError)
    }
}

impl<H: Host> Clock for Ports<H> {
    fn now_ms(&self) -> i64 {
        self.0.now_ms()
    }
    async fn sleep_ms(&self, ms: u64) {
        self.0.sleep_ms(ms).await;
    }
}

impl<H: Host> Random for Ports<H> {
    fn fill(&self, buf: &mut [u8]) -> Result<(), PortError> {
        for chunk in buf.chunks_mut(RANDOM_CHUNK) {
            let bytes = Zeroizing::new(self.0.random(chunk.len()).map_err(PortError)?);
            if bytes.len() != chunk.len() {
                return Err(PortError("the host returned the wrong number of random bytes".into()));
            }
            chunk.copy_from_slice(&bytes);
        }
        Ok(())
    }
}

impl<H: Host> KdfRunner for Ports<H> {
    async fn argon2id(&self, input: Argon2Input) -> Result<Zeroizing<[u8; 32]>, PortError> {
        let out = self
            .0
            .argon2id(&input.password, &input.salt, input.iterations, input.memory_kib, input.parallelism)
            .await
            .map_err(PortError)?;
        <[u8; 32]>::try_from(out.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| PortError("argon2id did not return 32 bytes".into()))
    }
}

impl<H: Host> RsaOaep for Ports<H> {
    async fn decrypt(&self, pkcs8: &[u8], hash: OaepHash, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, PortError> {
        let hash = match hash {
            OaepHash::Sha1 => "SHA-1",
            OaepHash::Sha256 => "SHA-256",
        };
        // The same texts as `AwsLcRsa`; the host's own text is dropped.
        self.0.rsa_oaep_decrypt(pkcs8, hash, ciphertext).await.map_err(|e| {
            PortError(
                if e == RSA_KEY_ERROR {
                    "the account's private key cannot be read"
                } else {
                    "organization key decryption failed"
                }
                .into(),
            )
        })
    }
}

/// A host socket. Keeps the host's in-flight `recv` across calls (D11): a dropped `recv` loses no frame. Closed on
/// drop unless `close` already ran.
pub struct JsSocket<H: Host> {
    host: Rc<H>,
    id: u32,
    pending: Option<RecvFuture>,
    closed: bool,
}

impl<H: Host> JsSocket<H> {
    fn shut(&mut self) {
        self.pending = None;
        if !self.closed {
            self.closed = true;
            self.host.socket_close(self.id);
        }
    }
}

impl<H: Host> Drop for JsSocket<H> {
    fn drop(&mut self) {
        self.shut();
    }
}

impl<H: Host> EventSocket for JsSocket<H> {
    async fn send(&mut self, frame: Frame) -> Result<(), PortError> {
        self.host.socket_send(self.id, frame).await.map_err(PortError)
    }
    async fn recv(&mut self) -> Option<Result<Frame, PortError>> {
        let (host, id) = (&self.host, self.id);
        let out = self.pending.get_or_insert_with(|| host.socket_recv(id)).as_mut().await;
        self.pending = None;
        out.map(|r| r.map_err(PortError))
    }
    async fn close(&mut self) {
        self.shut();
    }
}

impl<H: Host> Events for Ports<H> {
    type Socket = JsSocket<H>;
    async fn connect(&self, url: &str) -> Result<JsSocket<H>, PortError> {
        let id = self.0.socket_open(url).await.map_err(PortError)?;
        Ok(JsSocket { host: self.0.clone(), id, pending: None, closed: false })
    }
}
