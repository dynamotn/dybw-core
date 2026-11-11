//! What the JS host provides: one method per JS port call, bytes and strings only. `bindings` (wasm32) implements it
//! on the JS `ports` object; tests implement it with a mock.

use dybw_core::ports::Frame;
use std::future::Future;
use std::pin::Pin;
use zeroize::Zeroizing;

/// The text `rsa_oaep_decrypt` fails with when the PKCS#8 key cannot be imported.
pub const RSA_KEY_ERROR: &str = "key";

/// The exact text `secret_save` fails with when it refuses to write because the user changed the local value since
/// the sync began: the sync keeps the user's value and its base and reports it in `kept`, so the next sync sees both
/// sides changed. Any other text is a failed save.
pub const LOCAL_CHANGED: &str = "local-changed";

/// The host's answer to `socket_recv`.
pub type RecvFuture = Pin<Box<dyn Future<Output = Option<Result<Frame, String>>>>>;

/// A host call that fails answers `Err` with a text that never includes a URL, a body or a secret.
///
/// Secrets go in borrowed, so Rust keeps the only owned copy and wipes it. Across wasm-bindgen a borrowed slice
/// reaches JS as a view into wasm memory that dies on `memory.grow`: the JS port copies it before its first `await`
/// and wipes that copy once used. Secret answers come back in `Zeroizing`, wrapped at the earliest point.
#[expect(async_fn_in_trait, reason = "the JS host is single-threaded: not Send, like the core's ports")]
pub trait Host {
    fn now_ms(&self) -> i64;
    async fn sleep_ms(&self, ms: u64);
    /// Whether `http` refuses redirects (`fetch` with `redirect: "error"`); the plugin's `requestUrl` cannot (ADR
    /// 0018), and the core then refuses to send credentials.
    fn refuses_redirects(&self) -> bool;
    /// `len` random bytes from one JS call (`len` ≤ 65 536, the `getRandomValues` limit).
    fn random(&self, len: usize) -> Result<Vec<u8>, String>;
    /// The whole response as `(status, body)`, without following redirects where the host can refuse them. The host
    /// must bound the request with a timeout: the keys a running call holds outlive a `lock` until it settles.
    async fn http(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), String>;
    async fn storage_load(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    async fn storage_save(&self, key: &str, value: &[u8]) -> Result<(), String>;
    async fn storage_remove(&self, key: &str) -> Result<(), String>;
    async fn secret_load(&self, key: &str) -> Result<Option<Zeroizing<String>>, String>;
    /// Fails with exactly [`LOCAL_CHANGED`] to refuse a write over a value the user changed since the sync began.
    async fn secret_save(&self, key: &str, value: &str) -> Result<(), String>;
    async fn secret_remove(&self, key: &str) -> Result<(), String>;
    async fn argon2id(
        &self,
        password: &[u8],
        salt: &[u8; 32],
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    ) -> Result<Zeroizing<Vec<u8>>, String>;
    /// `hash` is `"SHA-1"` or `"SHA-256"`. Fails with exactly [`RSA_KEY_ERROR`] when the PKCS#8 key cannot be imported; any
    /// other error text means the decryption failed (neither text reaches the core).
    async fn rsa_oaep_decrypt(&self, pkcs8: &[u8], hash: &str, ciphertext: &[u8])
    -> Result<Zeroizing<Vec<u8>>, String>;
    /// Opens a socket and answers its id.
    async fn socket_open(&self, url: &str) -> Result<u32, String>;
    async fn socket_send(&self, id: u32, frame: Frame) -> Result<(), String>;
    /// The next frame, `None` once closed.
    ///
    /// The socket invariant, which keeps a frame from being lost when the hub's timer wins:
    /// - A frame leaves the host's queue only when the promise of this call resolves with it, never when the call is
    ///   made; so a future that is kept and polled again never loses one.
    /// - The hub (`api::run_hub`) polls `recv` before its timer, so a frame that is ready is taken before a deadline
    ///   is served, and it never keeps two `recv`s alive: `JsSocket` holds the one unresolved promise across the
    ///   hub's turns and asks again only once it resolved. The host therefore serves one waiting `recv` per socket.
    ///
    /// `hub_tests::run_hub_polls_recv_before_its_timer_and_keeps_one_recv_alive` pins the hub's half.
    fn socket_recv(&self, id: u32) -> RecvFuture;
    fn socket_close(&self, id: u32);
    fn log(&self, message: &str);
}
