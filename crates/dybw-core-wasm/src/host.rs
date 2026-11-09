//! What the JS host provides: one method per JS port call, bytes and strings only. `bindings` (wasm32) implements it
//! on the JS `ports` object; tests implement it with a mock.

use dybw_core::ports::Frame;
use std::future::Future;
use std::pin::Pin;

/// The host's answer to `socket_recv`.
pub type RecvFuture = Pin<Box<dyn Future<Output = Option<Result<Frame, String>>>>>;

/// A host call that fails answers `Err` with a text that never carries a secret.
///
/// Owned `Vec<u8>` parameters (request bodies, passwords) may hold secrets: the host wipes them once used.
#[expect(async_fn_in_trait, reason = "the JS host is single-threaded: not Send, like the core's ports")]
pub trait Host {
    fn now_ms(&self) -> i64;
    async fn sleep_ms(&self, ms: u64);
    /// `len` random bytes from one JS call (`len` ≤ 65 536, the `getRandomValues` limit).
    fn random(&self, len: usize) -> Result<Vec<u8>, String>;
    /// The whole response as `(status, body)`, without following redirects where the host can refuse them.
    async fn http(
        &self,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String>;
    async fn storage_load(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    async fn storage_save(&self, key: &str, value: &[u8]) -> Result<(), String>;
    async fn storage_remove(&self, key: &str) -> Result<(), String>;
    async fn secret_load(&self, key: &str) -> Result<Option<String>, String>;
    async fn secret_save(&self, key: &str, value: &str) -> Result<(), String>;
    async fn secret_remove(&self, key: &str) -> Result<(), String>;
    async fn argon2id(
        &self,
        password: Vec<u8>,
        salt: [u8; 32],
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    ) -> Result<Vec<u8>, String>;
    /// `hash` is `"SHA-1"` or `"SHA-256"`. Fails with exactly `"key"` when the PKCS#8 key cannot be imported; any
    /// other error text means the decryption failed (neither text reaches the core).
    async fn rsa_oaep_decrypt(&self, pkcs8: &[u8], hash: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String>;
    /// Opens a socket and answers its id.
    async fn socket_open(&self, url: &str) -> Result<u32, String>;
    async fn socket_send(&self, id: u32, frame: Frame) -> Result<(), String>;
    /// The next frame, `None` once closed. Taking a frame off the host's queue happens only when this future
    /// resolves, so a future that is kept and polled again never loses one.
    fn socket_recv(&self, id: u32) -> RecvFuture;
    fn socket_close(&self, id: u32);
    fn log(&self, message: &str);
}
