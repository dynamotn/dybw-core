//! A fake Bitwarden server behind the core's real `Client`: port of the plugin's `VectorServer`.

use dybw_core::api::{ServerUrls, resolve_server_urls};
use dybw_core::ports::{Http, HttpRequest, HttpResponse, Method, PortError};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use zeroize::Zeroizing;

pub const SERVER: &str = "https://vectors.invalid";
/// What the server answers to every write (README "Delete": the `PUT` body as sent, plus `id` and this date).
pub const SERVER_REVISION: &str = "2026-12-01T00:00:00.000Z";
const OUT_OF_DATE: &str = "The client copy of this cipher is out of date. Resubmit with the current revision date.";

pub fn urls() -> ServerUrls {
    // A constant, valid URL.
    resolve_server_urls(SERVER).unwrap_or_else(|e| panic!("{e}"))
}

/// A cipher write the server accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum Sent {
    Post { body: Value },
    Put { cipher: String, body: Value },
    Trash { cipher: String },
}

/// Clones share their state, so a test keeps one after handing the other to a `Client`.
#[derive(Clone)]
pub struct VectorServer {
    profile: Rc<Value>,
    prelogin: Rc<Value>,
    ciphers: Rc<RefCell<Vec<Value>>>,
    /// Writes the server accepted, in order.
    pub sent: Rc<RefCell<Vec<Sent>>>,
    /// Updates rejected as out of date.
    pub rejected: Rc<Cell<u32>>,
    /// The cipher served after the next update is rejected as out of date (data model §6.5).
    pub fresh: Rc<RefCell<Option<Value>>>,
}

fn json_response(status: u16, body: &Value) -> Result<HttpResponse, PortError> {
    Ok(HttpResponse { status, body: Zeroizing::new(body.to_string().into_bytes()) })
}

fn id_of(cipher: &Value) -> Option<&str> {
    cipher.get("id").or_else(|| cipher.get("Id")).and_then(Value::as_str)
}

impl VectorServer {
    pub fn new(profile: Value, ciphers: Vec<Value>, prelogin: Value) -> Self {
        VectorServer {
            profile: Rc::new(profile),
            prelogin: Rc::new(prelogin),
            ciphers: Rc::new(RefCell::new(ciphers)),
            sent: Rc::default(),
            rejected: Rc::default(),
            fresh: Rc::default(),
        }
    }

    fn update(&self, id: &str, body: Value) -> Result<HttpResponse, PortError> {
        if let Some(fresh) = self.fresh.borrow_mut().take() {
            self.rejected.set(self.rejected.get() + 1);
            let mut all = self.ciphers.borrow_mut();
            match all.iter_mut().find(|c| id_of(c) == id_of(&fresh)) {
                Some(slot) => *slot = fresh,
                None => all.push(fresh),
            }
            return json_response(400, &json!({ "message": OUT_OF_DATE }));
        }
        self.sent.borrow_mut().push(Sent::Put { cipher: id.to_owned(), body: body.clone() });
        json_response(200, &reply(body, id))
    }
}

/// The body as sent, plus the server's `id` and `revisionDate`.
fn reply(mut body: Value, id: &str) -> Value {
    if let Some(o) = body.as_object_mut() {
        o.insert("id".into(), json!(id));
        o.insert("revisionDate".into(), json!(SERVER_REVISION));
    }
    body
}

impl Http for VectorServer {
    fn refuses_redirects(&self) -> bool {
        true
    }

    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, PortError> {
        let rest = req.url.strip_prefix(SERVER).unwrap_or(&req.url);
        let path = rest.split(['?', '#']).next().unwrap_or(rest);
        let body = || -> Result<Value, PortError> {
            let raw = req.body.as_deref().map_or(&[][..], Vec::as_slice);
            serde_json::from_slice(raw).map_err(|_| PortError("request body is not JSON".into()))
        };
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        match (req.method, segments.as_slice()) {
            (Method::Post, ["identity", "connect", "token"]) => {
                json_response(200, &json!({ "access_token": "vectors-token", "expires_in": 3600 }))
            }
            (Method::Post, ["identity", "accounts", "prelogin"]) => json_response(200, &self.prelogin),
            (Method::Get, ["api", "sync"]) => json_response(
                200,
                &json!({ "profile": *self.profile, "folders": [], "ciphers": *self.ciphers.borrow() }),
            ),
            (Method::Get, ["api", "ciphers", id]) => {
                match self.ciphers.borrow().iter().find(|c| id_of(c) == Some(*id)) {
                    Some(c) => json_response(200, c),
                    None => json_response(404, &json!({ "message": format!("not faked: GET {path}") })),
                }
            }
            (Method::Post, ["api", "folders"]) => {
                json_response(200, &json!({ "id": "folder-created", "name": body()?.get("name") }))
            }
            (Method::Post, ["api", "ciphers"]) => {
                let body = body()?;
                self.sent.borrow_mut().push(Sent::Post { body: body.clone() });
                json_response(200, &reply(body, "cipher-created"))
            }
            (Method::Put, ["api", "ciphers", id, "delete"]) => {
                self.sent.borrow_mut().push(Sent::Trash { cipher: (*id).to_owned() });
                Ok(HttpResponse { status: 200, body: Zeroizing::default() })
            }
            (Method::Put, ["api", "ciphers", id]) => self.update(id, body()?),
            _ => json_response(404, &json!({ "message": format!("not faked: {:?} {path}", req.method) })),
        }
    }
}
