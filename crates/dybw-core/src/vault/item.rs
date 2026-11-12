//! A vault client's read of one item (ADR 0025): one cipher of any type, decrypted whole into zeroizing memory, or
//! only what `list` shows. A personal blob is opened whole (ADR 0021); an organization blob is held, as a scan holds
//! it. A trashed cipher opens like any other: the caller decides whether to show it.

use super::blob::{find, open_blob, text};
use super::fields::item_key;
use super::scan::{Uninspectable, is_blob, organization, too_large};
use crate::crypto::{Cbor, SymmetricKey};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

/// A decrypted string the cipher may leave out or send as `null`.
pub type Text = Option<Zeroizing<String>>;

/// Every part of one decrypted cipher. No `Clone`; `Debug` shows only the id and type; every text is wiped on drop.
pub struct Item {
    pub id: String,
    /// The cipher type: 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key; any other reads as [`Data::Unknown`].
    pub kind: u64,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    /// `reprompt` other than 0: the master password is asked again before any value (ADR 0025).
    pub reprompt: bool,
    pub name: Zeroizing<String>,
    pub notes: Text,
    pub data: Data,
    pub fields: Vec<Field>,
    /// Past login passwords, newest first, as the server keeps them.
    pub history: Vec<PastPassword>,
}

/// What `list` shows of an item (ADR 0025): its name and user decrypted, nothing else.
pub struct Summary {
    pub id: String,
    pub kind: u64,
    pub folder_id: Option<String>,
    pub name: Zeroizing<String>,
    /// A login's username; `None` for every other type.
    pub user: Text,
}

/// The part of an item its type gives.
pub enum Data {
    Login(Login),
    SecureNote,
    Card(Card),
    Identity(Box<Identity>),
    SshKey(SshKey),
    /// A type this core does not know: its name, notes, fields and history are still read.
    Unknown,
}

pub struct Login {
    pub username: Text,
    pub password: Text,
    pub totp: Text,
    pub uris: Vec<Uri>,
}

pub struct Uri {
    pub uri: Text,
    /// Bitwarden's match type (0 domain ... 5 never); `None` is the account's default.
    pub match_type: Option<u64>,
}

pub struct Card {
    pub cardholder_name: Text,
    pub brand: Text,
    pub number: Text,
    pub exp_month: Text,
    pub exp_year: Text,
    pub code: Text,
}

pub struct Identity {
    pub title: Text,
    pub first_name: Text,
    pub middle_name: Text,
    pub last_name: Text,
    pub address1: Text,
    pub address2: Text,
    pub address3: Text,
    pub city: Text,
    pub state: Text,
    pub postal_code: Text,
    pub country: Text,
    pub company: Text,
    pub email: Text,
    pub phone: Text,
    pub ssn: Text,
    pub username: Text,
    pub passport_number: Text,
    pub license_number: Text,
}

pub struct SshKey {
    pub private_key: Text,
    pub public_key: Text,
    pub fingerprint: Text,
}

pub struct Field {
    pub name: Text,
    pub value: Text,
    /// 0 text, 1 hidden, 2 boolean, 3 linked.
    pub kind: u64,
    /// For a linked field, the id of the item part it shows.
    pub linked_id: Option<u64>,
}

pub struct PastPassword {
    pub password: Text,
    pub last_used: Option<String>,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item").field("id", &self.id).field("kind", &self.kind).finish_non_exhaustive()
    }
}

impl fmt::Debug for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Summary").field("id", &self.id).field("kind", &self.kind).finish_non_exhaustive()
    }
}

/// Each known type's part: the field-level cipher's key, which is also the blob's `typeData.type`.
fn part_name(kind: u64) -> Option<&'static str> {
    match kind {
        1 => Some("login"),
        2 => Some("secureNote"),
        3 => Some("card"),
        4 => Some("identity"),
        5 => Some("sshKey"),
        _ => None,
    }
}

/// One map of a cipher: field-level JSON with the key its strings are encrypted under, or a map of an opened blob.
#[derive(Clone, Copy)]
enum Node<'a> {
    Json(&'a Value, &'a SymmetricKey),
    Cbor(&'a [(Cbor, Cbor)]),
}

static NULL: Value = Value::Null;

impl<'a> Node<'a> {
    /// The map at `key`; an empty one when absent.
    fn at(self, key: &str) -> Node<'a> {
        match self {
            Node::Json(v, k) => Node::Json(v.get(key).unwrap_or(&NULL), k),
            Node::Cbor(m) => Node::Cbor(map_of(find(m, key))),
        }
    }

    /// The string at `key`, decrypted. Absent or not a string is `None`; one that does not decrypt is `Value`.
    fn text(self, key: &str) -> Result<Text, Uninspectable> {
        match self {
            Node::Json(v, k) => v
                .get(key)
                .and_then(Value::as_str)
                .map(|s| k.decrypt_str(s).map_err(|_| Uninspectable::Value))
                .transpose(),
            Node::Cbor(m) => Ok(text(find(m, key)).map(|t| Zeroizing::new(t.to_owned()))),
        }
    }

    /// A plain string the server does not encrypt (a date).
    fn plain(self, key: &str) -> Option<String> {
        match self {
            Node::Json(v, _) => v.get(key).and_then(Value::as_str).map(str::to_owned),
            Node::Cbor(m) => text(find(m, key)).map(str::to_owned),
        }
    }

    fn num(self, key: &str) -> Option<u64> {
        match self {
            Node::Json(v, _) => v.get(key).and_then(Value::as_u64),
            Node::Cbor(m) => match find(m, key) {
                Some(Cbor::Uint(n)) => Some(*n),
                _ => None,
            },
        }
    }

    /// The maps of the list at `key`, in order; an entry that is no map reads as an empty one.
    fn list(self, key: &str) -> Vec<Node<'a>> {
        match self {
            Node::Json(v, k) => v
                .get(key)
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .map(|e| Node::Json(e, k))
                .collect(),
            Node::Cbor(m) => match find(m, key) {
                Some(Cbor::Array(a)) => a.iter().map(|e| Node::Cbor(map_of(Some(e)))).collect(),
                _ => Vec::new(),
            },
        }
    }
}

fn map_of(v: Option<&Cbor>) -> &[(Cbor, Cbor)] {
    if let Some(Cbor::Map(m)) = v { m } else { &[] }
}

/// Runs `read` on the cipher's top map and its type's part, under the right key: the owner's (the user's, or the
/// organization's in `orgs`) and the item's own. A personal blob is opened, and wiped once `read` returns.
fn with_nodes<T>(
    cipher: &Value,
    user: &SymmetricKey,
    orgs: &BTreeMap<String, SymmetricKey>,
    read: impl FnOnce(Node, Node) -> Result<T, Uninspectable>,
) -> Result<T, Uninspectable> {
    if too_large(cipher) {
        return Err(Uninspectable::TooLarge);
    }
    let part = part_name(kind(cipher));
    let org = organization(cipher);
    if is_blob(cipher) {
        // The SDK never seals an organization item as a blob: one is held, never decrypted (ADR 0021).
        if org.is_some() {
            return Err(Uninspectable::NewerFormat);
        }
        let blob = open_blob(cipher, user)?;
        let top = Node::Cbor(&blob.0);
        let typed = top.at("typeData");
        // A known type's `typeData` must be that type's, or its parts would read as absent.
        if part.is_some_and(|p| typed.plain("type").as_deref() != Some(p)) {
            return Err(Uninspectable::Blob);
        }
        return read(top, typed);
    }
    let owner = match org {
        None => user,
        Some(o) => orgs.get(o.as_str().unwrap_or_default()).ok_or(Uninspectable::OrganizationKeyMissing)?,
    };
    let key = item_key(cipher, owner).map_err(|_| Uninspectable::ItemKey)?;
    let top = Node::Json(cipher, &key);
    read(top, top.at(part.unwrap_or_default()))
}

fn kind(cipher: &Value) -> u64 {
    cipher.get("type").and_then(Value::as_u64).unwrap_or_default()
}

/// A string the server keeps in plaintext (ids).
fn plain(cipher: &Value, key: &str) -> Option<String> {
    cipher.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Decrypts every part of one cipher: `user` opens personal items and blobs, `orgs` (the unlocked organizations,
/// by id) organization items. A failure is the reason only, never a partial item or a decrypted text.
pub fn open(cipher: &Value, user: &SymmetricKey, orgs: &BTreeMap<String, SymmetricKey>) -> Result<Item, Uninspectable> {
    let kind = kind(cipher);
    with_nodes(cipher, user, orgs, |top, t| {
        let data = match kind {
            1 => Data::Login(Login {
                username: t.text("username")?,
                password: t.text("password")?,
                totp: t.text("totp")?,
                uris: t
                    .list("uris")
                    .into_iter()
                    .map(|u| Ok(Uri { uri: u.text("uri")?, match_type: u.num("match") }))
                    .collect::<Result<_, _>>()?,
            }),
            2 => Data::SecureNote,
            3 => Data::Card(Card {
                cardholder_name: t.text("cardholderName")?,
                brand: t.text("brand")?,
                number: t.text("number")?,
                exp_month: t.text("expMonth")?,
                exp_year: t.text("expYear")?,
                code: t.text("code")?,
            }),
            4 => Data::Identity(Box::new(Identity {
                title: t.text("title")?,
                first_name: t.text("firstName")?,
                middle_name: t.text("middleName")?,
                last_name: t.text("lastName")?,
                address1: t.text("address1")?,
                address2: t.text("address2")?,
                address3: t.text("address3")?,
                city: t.text("city")?,
                state: t.text("state")?,
                postal_code: t.text("postalCode")?,
                country: t.text("country")?,
                company: t.text("company")?,
                email: t.text("email")?,
                phone: t.text("phone")?,
                ssn: t.text("ssn")?,
                username: t.text("username")?,
                passport_number: t.text("passportNumber")?,
                license_number: t.text("licenseNumber")?,
            })),
            5 => Data::SshKey(SshKey {
                private_key: t.text("privateKey")?,
                public_key: t.text("publicKey")?,
                // The server's name; a blob's `typeData` says `fingerprint`.
                fingerprint: match top {
                    Node::Json(..) => t.text("keyFingerprint")?,
                    Node::Cbor(_) => t.text("fingerprint")?,
                },
            }),
            _ => Data::Unknown,
        };
        let fields = top
            .list("fields")
            .into_iter()
            .map(|f| {
                Ok(Field {
                    name: f.text("name")?,
                    value: f.text("value")?,
                    kind: f.num("type").unwrap_or_default(),
                    linked_id: f.num("linkedId"),
                })
            })
            .collect::<Result<_, _>>()?;
        let history = top
            .list("passwordHistory")
            .into_iter()
            .map(|h| Ok(PastPassword { password: h.text("password")?, last_used: h.plain("lastUsedDate") }))
            .collect::<Result<_, _>>()?;
        Ok(Item {
            id: plain(cipher, "id").unwrap_or_default(),
            kind,
            organization_id: plain(cipher, "organizationId"),
            folder_id: plain(cipher, "folderId"),
            reprompt: cipher.get("reprompt").and_then(Value::as_u64).is_some_and(|r| r != 0),
            name: top.text("name")?.unwrap_or_default(),
            notes: top.text("notes")?,
            data,
            fields,
            history,
        })
    })
}

/// What `list` shows (ADR 0025): the name and a login's username are decrypted, nothing else. A blob is opened whole,
/// as nothing smaller exists (ADR 0021), and wiped before this returns.
pub fn summary(
    cipher: &Value,
    user: &SymmetricKey,
    orgs: &BTreeMap<String, SymmetricKey>,
) -> Result<Summary, Uninspectable> {
    let kind = kind(cipher);
    with_nodes(cipher, user, orgs, |top, t| {
        Ok(Summary {
            id: plain(cipher, "id").unwrap_or_default(),
            kind,
            folder_id: plain(cipher, "folderId"),
            name: top.text("name")?.unwrap_or_default(),
            user: if kind == 1 { t.text("username")? } else { None },
        })
    })
}
