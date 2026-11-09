//! The JS boundary, wasm32 only: the host's duck-typed `ports` object as a [`Host`], and the exports. Forwards
//! only: what they call is covered by the native tests, this file by the WASM harness.
//!
//! Zeroization (D14): a secret export parameter is an owned `String`, which the glue copies into WASM memory and
//! hands over (never `&str`, which it frees unwiped); no export returns a secret. Residue can escape: for a string
//! that is not ASCII, `passStringToWasm0` writes the ASCII prefix into a buffer of the string's UTF-16 length, then
//! `realloc`s it twice (grow, then shrink to the UTF-8 length), and either move frees the old chunk unwiped: the
//! prefix, or the whole value (accepted in D14). A secret that must not leave that residue can come in as a
//! `Uint8Array` copied into `Zeroizing` with `copy_to`.
//! Imports follow the [`Host`] contract: secrets go out as borrowed views, secret answers are copied straight into
//! `Zeroizing`. Every answer is type-checked: a host that answers the wrong type gets an error, never a default.

use crate::host::{Host, RecvFuture};
#[cfg(feature = "vectors")]
use crate::ports::Ports;
use crate::session::Session;
use dybw_core::ports::Frame;
use js_sys::{Array, Function, Promise, Uint8Array};
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use zeroize::Zeroizing;

#[wasm_bindgen]
extern "C" {
    /// The host's `ports` object.
    #[derive(Clone)]
    pub type HostPorts;
    #[wasm_bindgen(method, js_name = nowMs)]
    fn js_now_ms(this: &HostPorts) -> f64;
    #[wasm_bindgen(method, js_name = sleepMs)]
    fn js_sleep_ms(this: &HostPorts, ms: f64) -> Promise;
    #[wasm_bindgen(method, js_name = refusesRedirects)]
    fn js_refuses_redirects(this: &HostPorts) -> bool;
    #[wasm_bindgen(method, catch, js_name = random)]
    fn js_random(this: &HostPorts, len: u32) -> Result<Vec<u8>, JsValue>;
    /// Resolves to `[status, Uint8Array]`; `headers` is JSON `[[name, value], …]`.
    #[wasm_bindgen(method, js_name = http)]
    fn js_http(this: &HostPorts, method: &str, url: &str, headers: &str, body: Option<&[u8]>) -> Promise;
    /// Resolves to a `Uint8Array`, or `null` or `undefined` when missing.
    #[wasm_bindgen(method, js_name = storageLoad)]
    fn js_storage_load(this: &HostPorts, key: &str) -> Promise;
    #[wasm_bindgen(method, js_name = storageSave)]
    fn js_storage_save(this: &HostPorts, key: &str, value: &[u8]) -> Promise;
    #[wasm_bindgen(method, js_name = storageRemove)]
    fn js_storage_remove(this: &HostPorts, key: &str) -> Promise;
    /// Resolves to a string, or `null` or `undefined` when missing.
    #[wasm_bindgen(method, js_name = secretLoad)]
    fn js_secret_load(this: &HostPorts, key: &str) -> Promise;
    #[wasm_bindgen(method, js_name = secretSave)]
    fn js_secret_save(this: &HostPorts, key: &str, value: &str) -> Promise;
    #[wasm_bindgen(method, js_name = secretRemove)]
    fn js_secret_remove(this: &HostPorts, key: &str) -> Promise;
    /// Resolves to a `Uint8Array`.
    #[wasm_bindgen(method, js_name = argon2id)]
    fn js_argon2id(
        this: &HostPorts,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    ) -> Promise;
    /// Resolves to a `Uint8Array`; rejects with exactly `"key"` when the key cannot be imported.
    #[wasm_bindgen(method, js_name = rsaOaepDecrypt)]
    fn js_rsa_oaep_decrypt(this: &HostPorts, pkcs8: &[u8], hash: &str, ciphertext: &[u8]) -> Promise;
    /// Resolves to the socket's id.
    #[wasm_bindgen(method, js_name = socketOpen)]
    fn js_socket_open(this: &HostPorts, url: &str) -> Promise;
    /// `frame` is a string or a `Uint8Array`.
    #[wasm_bindgen(method, js_name = socketSend)]
    fn js_socket_send(this: &HostPorts, id: u32, frame: JsValue) -> Promise;
    /// Resolves to the next frame (string or `Uint8Array`), `null` once closed; rejects on a socket error.
    #[wasm_bindgen(method, js_name = socketRecv)]
    fn js_socket_recv(this: &HostPorts, id: u32) -> Promise;
    #[wasm_bindgen(method, js_name = socketClose)]
    fn js_socket_close(this: &HostPorts, id: u32);
    #[wasm_bindgen(method, js_name = log)]
    fn js_log(this: &HostPorts, message: &str);
}

/// A rejection's text: an `Error`'s message, a string, or a fixed text.
fn message(e: JsValue) -> String {
    e.dyn_ref::<js_sys::Error>()
        .map_or_else(|| e.as_string().unwrap_or_else(|| "host error".into()), |e| e.message().into())
}

async fn wait(p: Promise) -> Result<JsValue, String> {
    JsFuture::from(p).await.map_err(message)
}

/// A `Uint8Array`'s bytes, copied once into WASM memory.
fn bytes(v: JsValue) -> Result<Zeroizing<Vec<u8>>, String> {
    v.dyn_into::<Uint8Array>().map(|a| Zeroizing::new(a.to_vec())).map_err(|_| "host answered no Uint8Array".into())
}

/// A number the host answered, as an integer.
fn number(v: &JsValue, what: &str) -> Result<f64, String> {
    v.as_f64().filter(|n| n.fract() == 0.0 && *n >= 0.0).ok_or_else(|| format!("host answered no {what}"))
}

impl Host for HostPorts {
    fn now_ms(&self) -> i64 {
        self.js_now_ms() as i64
    }
    async fn sleep_ms(&self, ms: u64) {
        let _ = JsFuture::from(self.js_sleep_ms(ms as f64)).await;
    }
    fn refuses_redirects(&self) -> bool {
        self.js_refuses_redirects()
    }
    fn random(&self, len: usize) -> Result<Vec<u8>, String> {
        self.js_random(u32::try_from(len).unwrap_or(u32::MAX)).map_err(message)
    }
    async fn http(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), String> {
        let headers = Zeroizing::new(serde_json::to_string(headers).unwrap_or_default());
        let answer = wait(self.js_http(method, url, &headers, body)).await?;
        let answer = answer.dyn_into::<Array>().map_err(|_| "host answered no [status, body]")?;
        let status = u16::try_from(number(&answer.get(0), "status")? as u64).map_err(|_| "host answered no status")?;
        Ok((status, bytes(answer.get(1))?))
    }
    async fn storage_load(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let v = wait(self.js_storage_load(key)).await?;
        if v.is_null_or_undefined() { Ok(None) } else { bytes(v).map(|b| Some(b.to_vec())) }
    }
    async fn storage_save(&self, key: &str, value: &[u8]) -> Result<(), String> {
        wait(self.js_storage_save(key, value)).await.map(drop)
    }
    async fn storage_remove(&self, key: &str) -> Result<(), String> {
        wait(self.js_storage_remove(key)).await.map(drop)
    }
    async fn secret_load(&self, key: &str) -> Result<Option<Zeroizing<String>>, String> {
        let v = wait(self.js_secret_load(key)).await?;
        if v.is_null_or_undefined() {
            Ok(None)
        } else {
            v.as_string().map(|s| Some(Zeroizing::new(s))).ok_or("host answered no string".into())
        }
    }
    async fn secret_save(&self, key: &str, value: &str) -> Result<(), String> {
        wait(self.js_secret_save(key, value)).await.map(drop)
    }
    async fn secret_remove(&self, key: &str) -> Result<(), String> {
        wait(self.js_secret_remove(key)).await.map(drop)
    }
    async fn argon2id(
        &self,
        password: &[u8],
        salt: &[u8; 32],
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        bytes(wait(self.js_argon2id(password, salt, iterations, memory_kib, parallelism)).await?)
    }
    async fn rsa_oaep_decrypt(
        &self,
        pkcs8: &[u8],
        hash: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        bytes(wait(self.js_rsa_oaep_decrypt(pkcs8, hash, ciphertext)).await?)
    }
    async fn socket_open(&self, url: &str) -> Result<u32, String> {
        let id = number(&wait(self.js_socket_open(url)).await?, "socket id")?;
        u32::try_from(id as u64).map_err(|_| "host answered no socket id".into())
    }
    async fn socket_send(&self, id: u32, frame: Frame) -> Result<(), String> {
        let frame = match frame {
            Frame::Text(t) => JsValue::from(t),
            Frame::Binary(b) => Uint8Array::from(b.as_slice()).into(),
        };
        wait(self.js_socket_send(id, frame)).await.map(drop)
    }
    fn socket_recv(&self, id: u32) -> RecvFuture {
        let next = JsFuture::from(self.js_socket_recv(id));
        Box::pin(async move {
            match next.await {
                Ok(v) if v.is_null() => None,
                Ok(v) => Some(match v.as_string() {
                    Some(t) => Ok(Frame::Text(t)),
                    None => bytes(v).map(|b| Frame::Binary(b.to_vec())),
                }),
                Err(e) => Some(Err(message(e))),
            }
        })
    }
    fn socket_close(&self, id: u32) {
        self.js_socket_close(id);
    }
    fn log(&self, message: &str) {
        self.js_log(message);
    }
}

thread_local! {
    /// Where the panic hook reports: the hook must be `Send`, a JS object is not.
    static PANIC_LOG: RefCell<Option<HostPorts>> = const { RefCell::new(None) };
}

/// Installs the panic hook: it reports where the panic happened through `ports.log`, never its message (which could
/// name a value). A panic traps the instance; the host drops it and starts locked.
#[wasm_bindgen]
pub fn init(ports: HostPorts) {
    PANIC_LOG.with(|l| *l.borrow_mut() = Some(ports));
    std::panic::set_hook(Box::new(|info| {
        let at = info.location().map(|l| format!(" at {}:{}", l.file(), l.line())).unwrap_or_default();
        PANIC_LOG.with(|l| l.borrow().as_ref().map(|p| p.js_log(&format!("dybw-core-wasm panicked{at}"))));
    }));
}

/// A profile's session; see [`Session`]. Unstable: M6 may reshape it. Results are JSON text, errors reject with a
/// message. Secrets come in as owned strings; local values as `ids[i]` = `values[i]`.
#[wasm_bindgen]
pub struct WasmSession(Session<HostPorts>);

#[wasm_bindgen]
impl WasmSession {
    #[wasm_bindgen(constructor)]
    pub fn new(ports: HostPorts, namespace: &str) -> Result<WasmSession, String> {
        Session::new(Rc::new(ports), namespace).map(WasmSession)
    }
    pub async fn unlock(&self, profile: &str, client_secret: String, password: String) -> Result<String, String> {
        self.0.unlock(profile, Zeroizing::new(client_secret), Zeroizing::new(password)).await
    }
    #[wasm_bindgen(js_name = unlockCached)]
    pub async fn unlock_cached(&self, profile: &str, password: String) -> Result<String, String> {
        self.0.unlock_cached(profile, Zeroizing::new(password)).await
    }
    /// Never throws: every method takes `&self`, so no wasm-bindgen borrow can refuse it.
    pub fn lock(&self) {
        self.0.lock();
    }
    #[wasm_bindgen(js_name = deviceId)]
    pub async fn device_id(&self) -> Result<String, String> {
        self.0.device_id().await
    }
    #[wasm_bindgen(js_name = acceptKdf)]
    pub async fn accept_kdf(&self, kdf: &str, origin: &str) -> Result<(), String> {
        self.0.accept_kdf(kdf, origin).await
    }
    #[wasm_bindgen(js_name = acceptSecurityVersion)]
    pub async fn accept_security_version(&self, version: u64) -> Result<(), String> {
        self.0.accept_security_version(version).await
    }
    #[wasm_bindgen(js_name = planPass)]
    pub async fn plan_pass(&self, options: &str, ids: Vec<String>, values: Vec<String>) -> Result<String, String> {
        self.0.plan_pass(options, ids, values).await
    }
    #[wasm_bindgen(js_name = runSync)]
    pub async fn run_sync(&self, options: &str, ids: Vec<String>, values: Vec<String>) -> Result<String, String> {
        self.0.run_sync(options, ids, values).await
    }
    /// Runs until `stop()` answers true or `lock` runs.
    #[wasm_bindgen(js_name = runHub)]
    pub async fn run_hub(&self, on_change: Function, stop: Function) -> Result<(), String> {
        let stopped = || stop.call0(&JsValue::NULL).is_ok_and(|v| v.is_truthy());
        self.0.run_hub(|| drop(on_change.call0(&JsValue::NULL)), stopped).await
    }
}

/// The vector files JS read (`path -> text`); an entry that is not two strings is no file, so its run reports it
/// missing.
#[cfg(feature = "vectors")]
fn vector_files(map: &js_sys::Map) -> dybw_vectors::Files {
    let mut files = std::collections::BTreeMap::new();
    map.for_each(&mut |text, path| drop(path.as_string().zip(text.as_string()).map(|(p, t)| files.insert(p, t))));
    dybw_vectors::Files::from_map(files)
}

/// See [`crate::vectors::run_vectors_json`].
#[cfg(feature = "vectors")]
#[wasm_bindgen(js_name = runVectors)]
pub async fn run_vectors(files: js_sys::Map, ports: HostPorts) -> String {
    crate::vectors::run_vectors_json(&vector_files(&files), &Ports(Rc::new(ports))).await
}

/// See [`crate::vectors::run_known_answers_json`].
#[cfg(feature = "vectors")]
#[wasm_bindgen(js_name = runKnownAnswers)]
pub async fn run_known_answers(files: js_sys::Map, ports: HostPorts) -> String {
    crate::vectors::run_known_answers_json(&vector_files(&files), &Ports(Rc::new(ports))).await
}
