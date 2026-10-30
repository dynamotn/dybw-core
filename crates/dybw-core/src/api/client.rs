//! Minimal Bitwarden REST client over the `Http` port: prelogin, API-key login, sync, folder and cipher writes.
//! Ciphers stay JSON values, so an edit passes every field this client does not model back to the server.

use crate::crypto::KdfParams;
use crate::ports::{Clock, Http, HttpRequest, Method};
use serde_json::{Map, Value, json};
use url::Url;
use zeroize::Zeroizing;

/// Largest response body read (bwss's limit).
pub const MAX_BODY: usize = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("network error: {0}")]
    Network(String),
    #[error("HTTP {status}{}", if .message.is_empty() { String::new() } else { format!(" (server says: {})", .message) })]
    Http { status: u16, message: String },
    #[error("unexpected response: {0}")]
    Protocol(String),
    /// A rejected input (server URL, device info); the text is shown as it is.
    #[error("{0}")]
    Invalid(String),
    /// The HTTP adapter would follow a redirect, which could carry the API key or token to another host.
    #[error("the HTTP client follows redirects; refusing to send credentials")]
    RedirectsNotRefused,
    #[error("not logged in")]
    NotLoggedIn,
    #[error("the response is larger than the limit")]
    TooLarge,
    #[error("the API key belongs to another server")]
    WrongOrigin,
    /// A write before this session's first `/sync`: it can be sent after the next one (bwss `NotSynced`).
    #[error("sync before writing ciphers")]
    NotSynced,
}

impl ApiError {
    /// The server rejected an edit because the cipher changed elsewhere.
    pub fn is_out_of_date(&self) -> bool {
        matches!(self, ApiError::Http { status: 400, message } if message.to_lowercase().contains("out of date"))
    }

    /// "Try again later" rather than "this request is wrong".
    pub fn is_transient(&self) -> bool {
        match self {
            ApiError::Network(_) | ApiError::NotSynced => true,
            ApiError::Http { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrls {
    pub api: String,
    pub identity: String,
    pub notifications: String,
}

/// Maps a vault URL to the API, identity and notifications endpoints.
pub fn resolve_server_urls(server_url: &str) -> Result<ServerUrls, ApiError> {
    let trimmed = server_url.trim();
    let raw = if trimmed.is_empty() { "https://vault.bitwarden.com" } else { trimmed };
    // The text is not echoed: the URL may hold a password.
    let url = Url::parse(raw).map_err(|e| ApiError::Invalid(format!("invalid server URL: {e}")))?;
    let host = url.host_str().unwrap_or_default();
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ApiError::Protocol(
            "the server URL must use https:// (plain http is only allowed for localhost)".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ApiError::Invalid("the server URL must not contain credentials".into()));
    }
    let cloud = |tld: &str| ServerUrls {
        api: format!("https://api.bitwarden.{tld}"),
        identity: format!("https://identity.bitwarden.{tld}"),
        notifications: format!("https://notifications.bitwarden.{tld}"),
    };
    Ok(match host {
        "vault.bitwarden.com" | "bitwarden.com" => cloud("com"),
        "vault.bitwarden.eu" | "bitwarden.eu" => cloud("eu"),
        _ => {
            let base = format!("{}{}", url.origin().ascii_serialization(), url.path()).trim_end_matches('/').to_owned();
            ServerUrls {
                api: format!("{base}/api"),
                identity: format!("{base}/identity"),
                notifications: format!("{base}/notifications"),
            }
        }
    })
}

/// Bitwarden used to answer in PascalCase (older Vaultwarden still does); every response goes through this.
pub fn normalize_keys(value: Value) -> Value {
    match value {
        Value::Array(a) => Value::Array(a.into_iter().map(normalize_keys).collect()),
        Value::Object(o) => Value::Object(
            o.into_iter()
                .map(|(k, v)| {
                    let mut c = k.chars();
                    let key = match c.next() {
                        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
                        None => k,
                    };
                    (key, normalize_keys(v))
                })
                .collect(),
        ),
        v => v,
    }
}

/// `scheme://host[:port]` of `url`, the unit an API key is bound to.
pub fn origin_of(url: &str) -> Result<String, ApiError> {
    Url::parse(url)
        .map(|u| u.origin().ascii_serialization())
        .map_err(|e| ApiError::Invalid(format!("invalid URL: {e}")))
}

pub struct ApiKey {
    /// The only identity origin this key may be sent to.
    pub origin: String,
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("origin", &self.origin)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub identifier: String,
    pub name: String,
    /// The server's `DeviceType` number.
    pub device_type: u8,
    /// `Bitwarden-Client-Name`, supplied by the tool.
    pub client_name: String,
    /// `Bitwarden-Client-Version`, supplied by the tool.
    pub client_version: String,
}

struct Session {
    token: Zeroizing<String>,
    /// Clock time (ms) after which the token is renewed: a minute before the server's expiry.
    renew_at_ms: i64,
    key: ApiKey,
}

pub struct Client<H: Http, C: Clock> {
    http: H,
    clock: C,
    urls: ServerUrls,
    device: DeviceInfo,
    session: Option<Session>,
    user_id: Option<String>,
    /// `MAX_BODY`; tests lower it.
    body_limit: usize,
}

impl<H: Http, C: Clock> Client<H, C> {
    /// Refuses device info with control characters: it becomes header values.
    pub fn new(http: H, clock: C, urls: ServerUrls, device: DeviceInfo) -> Result<Self, ApiError> {
        let texts = [&device.identifier, &device.name, &device.client_name, &device.client_version];
        if texts.iter().any(|t| t.chars().any(char::is_control)) {
            return Err(ApiError::Invalid("device info must not contain control characters".into()));
        }
        Ok(Client { http, clock, urls, device, session: None, user_id: None, body_limit: MAX_BODY })
    }

    /// The client's clock, in Unix milliseconds.
    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    /// The bearer token while it is valid, for the hub URL.
    pub fn access_token(&self) -> Option<&str> {
        let s = self.session.as_ref().filter(|s| self.clock.now_ms() < s.renew_at_ms)?;
        Some(s.token.as_str())
    }

    /// Refuses to send credentials through a client that follows redirects, then renews a token that is
    /// within a minute of expiry with the stored API key.
    async fn ensure_login(&mut self) -> Result<(), ApiError> {
        if !self.http.refuses_redirects() {
            return Err(ApiError::RedirectsNotRefused);
        }
        let s = self.session.as_ref().ok_or(ApiError::NotLoggedIn)?;
        if self.clock.now_ms() >= s.renew_at_ms {
            let key = ApiKey {
                origin: s.key.origin.clone(),
                client_id: s.key.client_id.clone(),
                client_secret: Zeroizing::new(s.key.client_secret.as_str().to_owned()),
            };
            self.login(&key).await?;
        }
        Ok(())
    }

    /// Sends one request and returns the body of a 2xx answer.
    async fn call(
        &self,
        method: Method,
        url: String,
        mut headers: Vec<(String, String)>,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        headers.push(("Bitwarden-Client-Name".into(), self.device.client_name.clone()));
        headers.push(("Bitwarden-Client-Version".into(), self.device.client_version.clone()));
        headers.push(("Device-Type".into(), self.device.device_type.to_string()));
        let res = self
            .http
            .send(HttpRequest { method, url, headers, body, max_body: self.body_limit })
            .await
            .map_err(|e| ApiError::Network(e.0))?;
        if res.body.len() > self.body_limit {
            return Err(ApiError::TooLarge);
        }
        if !(200..300).contains(&res.status) {
            return Err(ApiError::Http { status: res.status, message: describe_error(&parse_json(&res.body)) });
        }
        Ok(res.body)
    }

    /// An authenticated call with an optional JSON body; the answer is parsed and normalized.
    async fn authed(&mut self, method: Method, path: &str, body: Option<Value>) -> Result<Value, ApiError> {
        self.authed_raw(method, path, body).await.map(|b| parse_json(&b))
    }

    async fn authed_raw(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        self.ensure_login().await?;
        let token = self.session.as_ref().map(|s| s.token.as_str()).unwrap_or_default();
        let mut headers = vec![("Authorization".to_owned(), format!("Bearer {token}"))];
        let body = body.map(|b| {
            headers.push(("Content-Type".into(), "application/json".into()));
            Zeroizing::new(b.to_string().into_bytes())
        });
        self.call(method, format!("{}{path}", self.urls.api), headers, body).await
    }

    pub async fn prelogin(&self, email: &str) -> Result<KdfParams, ApiError> {
        let body = Zeroizing::new(json!({ "email": email }).to_string().into_bytes());
        let headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        let url = format!("{}/accounts/prelogin", self.urls.identity);
        let res = parse_json(&self.call(Method::Post, url, headers, Some(body)).await?);
        let num = |k: &str| res.get(k).and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok());
        match num("kdf") {
            Some(0) => Ok(KdfParams::Pbkdf2 { iterations: num("kdfIterations").unwrap_or(0) }),
            Some(1) => Ok(KdfParams::Argon2id {
                iterations: num("kdfIterations").unwrap_or(0),
                memory_mib: num("kdfMemory").unwrap_or(0),
                parallelism: num("kdfParallelism").unwrap_or(0),
            }),
            other => Err(ApiError::Protocol(format!("unsupported KDF type {other:?}"))),
        }
    }

    /// Logs in with a personal API key. It authenticates only; decrypting still needs the master password.
    ///
    /// The key is bound to the identity origin it was entered for: another origin is refused before any request.
    pub async fn login(&mut self, key: &ApiKey) -> Result<(), ApiError> {
        if key.origin != origin_of(&self.urls.identity)? {
            return Err(ApiError::WrongOrigin);
        }
        if !self.http.refuses_redirects() {
            return Err(ApiError::RedirectsNotRefused);
        }
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "client_credentials")
            .append_pair("scope", "api")
            .append_pair("client_id", &key.client_id)
            .append_pair("client_secret", key.client_secret.as_str())
            .append_pair("deviceType", &self.device.device_type.to_string())
            .append_pair("deviceIdentifier", &self.device.identifier)
            .append_pair("deviceName", &self.device.name);
        let body = Zeroizing::new(form.finish().into_bytes());
        let headers = vec![("Content-Type".to_owned(), "application/x-www-form-urlencoded; charset=utf-8".to_owned())];
        let url = format!("{}/connect/token", self.urls.identity);
        let res = parse_json(&self.call(Method::Post, url, headers, Some(body)).await?);
        // Moved out of the parsed value, so no second copy of the token is left behind.
        let (token, expires_in) = match res {
            Value::Object(mut m) => (m.remove("access_token"), m.get("expires_in").and_then(Value::as_u64)),
            _ => (None, None),
        };
        let Some(Value::String(token)) = token else {
            return Err(ApiError::Protocol("no access token".into()));
        };
        // Renewed a minute before the server's expiry, but never sooner than a minute from now.
        let ttl_s = expires_in.unwrap_or(3600).saturating_sub(60).max(60);
        let ttl_ms = i64::try_from(ttl_s).unwrap_or(i64::MAX).saturating_mul(1000);
        let renew_at_ms = self.clock.now_ms().saturating_add(ttl_ms);
        let key = ApiKey {
            origin: key.origin.clone(),
            client_id: key.client_id.clone(),
            client_secret: Zeroizing::new(key.client_secret.as_str().to_owned()),
        };
        self.session = Some(Session { token: Zeroizing::new(token), renew_at_ms, key });
        Ok(())
    }

    /// `/sync`, with missing `folders` and `ciphers` as empty lists. A response without a profile id or an
    /// account key is refused.
    pub async fn sync(&mut self) -> Result<Value, ApiError> {
        let mut body = self.authed(Method::Get, "/sync?excludeDomains=true", None).await?;
        let text = |p: &str| body.pointer(p).and_then(Value::as_str).filter(|t| !t.is_empty());
        let id = text("/profile/id").ok_or_else(|| ApiError::Protocol("sync response has no profile".into()))?;
        let id = id.to_owned();
        if text("/profile/key").or(text("/userDecryption/masterPasswordUnlock/masterKeyEncryptedUserKey")).is_none() {
            return Err(ApiError::Protocol("sync response has no account key".into()));
        }
        // The profile id above proves `body` is an object.
        for map in body.as_object_mut().into_iter() {
            for list in ["folders", "ciphers"] {
                let slot = map.entry(list).or_insert(Value::Null);
                if slot.is_null() {
                    *slot = json!([]);
                }
            }
        }
        self.user_id = Some(id);
        Ok(body)
    }

    /// The account's revision date as the server sends it (a number or a string), as raw text: it is only compared.
    pub async fn revision_date(&mut self) -> Result<String, ApiError> {
        let body = self.authed_raw(Method::Get, "/accounts/revision-date", None).await?;
        Ok(String::from_utf8_lossy(&body).trim().to_owned())
    }

    pub async fn get_cipher(&mut self, id: &str) -> Result<Value, ApiError> {
        self.authed(Method::Get, &format!("/ciphers/{}", enc(id)), None).await
    }

    pub async fn create_folder(&mut self, encrypted_name: &str) -> Result<Value, ApiError> {
        self.authed(Method::Post, "/folders", Some(json!({ "name": encrypted_name }))).await
    }

    fn with_owner(&self, mut body: Map<String, Value>) -> Result<Value, ApiError> {
        // Required by Vaultwarden 1.37+, optional on bitwarden.com.
        let owner = self.user_id.clone().ok_or(ApiError::NotSynced)?;
        body.insert("encryptedFor".into(), Value::String(owner));
        Ok(Value::Object(body))
    }

    pub async fn create_cipher(&mut self, body: Map<String, Value>) -> Result<Value, ApiError> {
        self.ensure_login().await?;
        self.authed(Method::Post, "/ciphers", Some(self.with_owner(body)?)).await
    }

    pub async fn update_cipher(&mut self, id: &str, body: Map<String, Value>) -> Result<Value, ApiError> {
        self.ensure_login().await?;
        self.authed(Method::Put, &format!("/ciphers/{}", enc(id)), Some(self.with_owner(body)?)).await
    }

    /// Moves the cipher to the trash, where any Bitwarden client can restore it.
    pub async fn trash_cipher(&mut self, id: &str) -> Result<(), ApiError> {
        self.authed(Method::Put, &format!("/ciphers/{}/delete", enc(id)), None).await.map(|_| ())
    }
}

/// A body as JSON with normalized keys; anything else is `Null`.
fn parse_json(body: &[u8]) -> Value {
    serde_json::from_slice(body).map(normalize_keys).unwrap_or(Value::Null)
}

/// A path segment, percent-encoded (a space is `%20`, not `+`).
fn enc(segment: &str) -> String {
    url::form_urlencoded::byte_serialize(segment.as_bytes()).collect::<String>().replace('+', "%20")
}

/// Characters that are not controls but change what text looks like (Unicode Cf and the line separators).
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{890}'..='\u{891}' | '\u{8e2}'
        | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}'
        | '\u{13430}'..='\u{1343f}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}' | '\u{e0001}'
        | '\u{e0020}'..='\u{e007f}')
}

type Chars<'a> = std::iter::Peekable<std::str::Chars<'a>>;

/// Skips a control string up to BEL, C1 ST or `ESC \`.
fn skip_string(chars: &mut Chars<'_>) {
    while let Some(c) = chars.next() {
        if c == '\u{7}' || c == '\u{9c}' || (c == '\u{1b}' && chars.next_if_eq(&'\\').is_some()) {
            return;
        }
    }
}

/// Skips a CSI sequence up to its final byte.
fn skip_csi(chars: &mut Chars<'_>) {
    for c in chars.by_ref() {
        if ('@'..='~').contains(&c) {
            return;
        }
    }
}

/// `text` without terminal escapes and invisible characters; other controls become a space.
fn strip_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.peek() {
                Some('[') => {
                    chars.next();
                    skip_csi(&mut chars);
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    chars.next();
                    skip_string(&mut chars);
                }
                // Intermediate bytes, then a final byte (`ESC ( B`), or a final byte alone (`ESC c`).
                Some('\u{20}'..='\u{7e}') => {
                    while chars.next_if(|c| ('\u{20}'..='\u{2f}').contains(c)).is_some() {}
                    chars.next_if(|c| ('\u{30}'..='\u{7e}').contains(c));
                }
                // A lone ESC goes alone; what follows is text.
                _ => {}
            },
            '\u{9b}' => skip_csi(&mut chars),
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => skip_string(&mut chars),
            c if is_invisible(c) => {}
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Server text is untrusted: short, one line, no control characters.
fn describe_error(body: &Value) -> String {
    let mut parts = Vec::new();
    for p in ["/error_description", "/message", "/errorModel/message"] {
        if let Some(s) = body.pointer(p).and_then(Value::as_str) {
            parts.push(s.to_owned());
        }
    }
    if let Some(v) = body.get("validationErrors") {
        parts.push(v.to_string());
    }
    let text = strip_controls(&parts.join(" ")).split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() > 200 { text.chars().take(200).collect::<String>() + "…" } else { text }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
#[path = "client_tests.rs"]
mod tests;
