//! The writer: port of bwss `run_patch` and `run_delete` (`src/backend/runner.rs`) without bwss's state lock.

use crate::api::{ApiError, Client};
use crate::ports::{Clock, Http, Random};
use crate::vault::scan::{Scan, organization, read_only, scan, trashed};
use crate::vault::write::{
    NewItem, Patch, ValueChange, WriteError, WriteRecord, apply, has_foreign_content, new_item, strip,
};
use crate::vault::{Keys, Namespace, Organizations};
use serde_json::Value;
#[cfg(feature = "vault-client")]
use {
    crate::crypto::SymmetricKey,
    crate::vault::client::{ClientEdit, NewEntry},
    std::collections::BTreeMap,
};

/// Sends per write: the first one and up to two re-applications after an out-of-date rejection (bwss).
pub const ATTEMPTS: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum SyncWriteError {
    #[error(transparent)]
    Write(#[from] WriteError),
    #[error(transparent)]
    Api(#[from] ApiError),
    /// Every attempt was rejected as out of date; nothing else was sent and the change is still the caller's.
    #[error("the item keeps changing elsewhere")]
    StillChanging,
    /// The cipher has no server id, so no request can name it; nothing was sent.
    #[error("the cipher has no id")]
    MissingId,
    /// The refetched copy moved to another organization (or out of one), or its edit right changed: the checks the
    /// change was made under no longer hold, so nothing more was sent (§9).
    #[error("the item changed owner or edit rights elsewhere")]
    OwnerChanged,
}

/// What a delete did to the item (§8.2).
#[derive(Debug)]
pub enum DeleteOutcome {
    /// Stripped, and moved to the trash.
    Trashed,
    /// Stripped; what is left is the user's, so the item stays.
    KeptForeign,
    /// Stripped, but moving it to the trash failed (`trash`); it stays as a bare item.
    Stripped { trash: ApiError },
    /// Stripped, but the server's reply could not be scanned, so it was not trashed.
    Unreadable(WriteError),
    /// Not the tool's (any more): nothing was sent, or nothing is left to do.
    Nothing,
}

/// The cipher's own server id; a cipher without one cannot be addressed.
fn cipher_id(cipher: &Value) -> Result<String, SyncWriteError> {
    match cipher.get("id").and_then(Value::as_str) {
        Some(id) if !id.is_empty() => Ok(id.to_owned()),
        _ => Err(SyncWriteError::MissingId),
    }
}

/// Who owns the cipher and whether this account may edit it, as the scan decides both.
fn owner(cipher: &Value) -> (Option<&Value>, bool) {
    (organization(cipher), read_only(cipher))
}

/// The server's current copy; `None` when it is gone (404).
async fn refetch<H: Http, C: Clock>(client: &mut Client<H, C>, id: &str) -> Result<Option<Value>, ApiError> {
    match client.get_cipher(id).await {
        Err(ApiError::Http { status: 404, .. }) => Ok(None),
        other => other.map(Some),
    }
}

/// Applies `patch` to `cipher` and sends it. When the server says the copy is out of date, the same patch is
/// applied to a refetched copy (§6.5): `SourceChanged`, `Gone` and `Unmarked` end it, and at most `ATTEMPTS` writes
/// are sent in all. `now_ms` dates a replaced login password; `record` is this device's record of the item (ADR
/// 0016, see `apply`). Returns the server's reply with the mark of the value written to `login.password` (for
/// `record_write`), or `None` for an empty patch or a value the copy already holds, which sends nothing (a PUT would bump the revision date and look
/// like an edit to other devices).
#[expect(clippy::too_many_arguments, reason = "the writer's inputs, each the caller's")]
pub async fn update<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    ns: &Namespace,
    keys: &Keys,
    record: &WriteRecord,
    rng: &impl Random,
    now_ms: i64,
    cipher: &Value,
    patch: &Patch,
) -> Result<Option<(Value, Option<[u8; 32]>)>, SyncWriteError> {
    if matches!(patch.value, ValueChange::Keep)
        && patch.set.is_empty()
        && patch.remove.is_empty()
        && patch.append_lines.is_empty()
    {
        return Ok(None);
    }
    let id = cipher_id(cipher)?;
    let mut current = cipher.clone();
    for attempt in 1..=ATTEMPTS {
        let applied = apply(&current, patch, ns, keys, record, rng, now_ms)?;
        // The copy already holds the value: nothing is sent.
        let Some(body) = applied.body else { return Ok(None) };
        match client.update_cipher(&id, body).await {
            Err(e) if e.is_out_of_date() => {
                if attempt < ATTEMPTS {
                    let fresh = refetch(client, &id).await?.ok_or(WriteError::Gone)?;
                    // The caller checked the owner and edit right of the copy it read (§9); a copy that changed
                    // either is another decision, never re-applied to. With the same owner, `apply` reading it with
                    // every organization is no wider than the caller's own read was.
                    if owner(&fresh) != owner(cipher) {
                        return Err(SyncWriteError::OwnerChanged);
                    }
                    current = fresh;
                }
            }
            sent => return Ok(Some((sent?, applied.wrote_login))),
        }
    }
    Err(SyncWriteError::StillChanging)
}

/// Creates a new item (§6.2). Returns the server's reply.
pub async fn create<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    ns: &Namespace,
    keys: &Keys,
    rng: &impl Random,
    item: &NewItem,
) -> Result<Value, SyncWriteError> {
    Ok(client.create_cipher(new_item(item, ns, keys, rng)?).await?)
}

/// A vault client's create (`vault::client::create`): a personal login or secure note. Returns the server's reply.
#[cfg(feature = "vault-client")]
pub async fn client_create<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    user: &SymmetricKey,
    security_version: u64,
    rng: &impl Random,
    entry: &NewEntry,
) -> Result<Value, SyncWriteError> {
    Ok(client.create_cipher(crate::vault::client::create(entry, user, security_version, rng)?).await?)
}

/// The server's copy of `cipher_id` for a vault client's write; one that is gone is `Gone`.
#[cfg(feature = "vault-client")]
async fn current<H: Http, C: Clock>(client: &mut Client<H, C>, cipher_id: &str) -> Result<Value, SyncWriteError> {
    Ok(refetch(client, cipher_id).await?.ok_or(WriteError::Gone)?)
}

/// A vault client's edit (`vault::client::edit`) of `cipher_id`, applied to the server's current copy, fetched first
/// so every part the edit does not change passes through as the server holds it now (§6.3). A copy at another
/// revision than `edit.base_revision`, or a server that answers out of date, is `OutOfDate`: nothing is re-applied,
/// the user decides again on the new copy (§6.5). Returns the server's reply, or `None` when the edit changes
/// nothing, which sends nothing.
#[cfg(feature = "vault-client")]
pub async fn client_update<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    user: &SymmetricKey,
    orgs: &BTreeMap<String, SymmetricKey>,
    rng: &impl Random,
    now_ms: i64,
    cipher_id: &str,
    edit: &ClientEdit,
) -> Result<Option<Value>, SyncWriteError> {
    let fresh = current(client, cipher_id).await?;
    let Some(body) = crate::vault::client::edit(&fresh, edit, user, orgs, rng, now_ms)? else { return Ok(None) };
    match client.update_cipher(cipher_id, body).await {
        Err(e) if e.is_out_of_date() => Err(WriteError::OutOfDate.into()),
        sent => Ok(Some(sent?)),
    }
}

/// A vault client's `remove`: moves `cipher_id` to the trash, never purges it, once the server's current copy passes
/// `vault::client::check_trash` at `base_revision`.
#[cfg(feature = "vault-client")]
pub async fn client_trash<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    user: &SymmetricKey,
    orgs: &BTreeMap<String, SymmetricKey>,
    cipher_id: &str,
    base_revision: &str,
) -> Result<(), SyncWriteError> {
    let fresh = current(client, cipher_id).await?;
    crate::vault::client::check_trash(&fresh, base_revision, user, orgs)?;
    Ok(client.trash_cipher(cipher_id).await?)
}

/// The tool's `{ns}:id` when `cipher` is a live, readable item of the tool (and, with `want`, that item).
fn marked_id(cipher: &Value, ns: &Namespace, keys: &Keys, want: Option<&str>) -> Result<Option<String>, WriteError> {
    if trashed(cipher) {
        return Ok(None);
    }
    match scan(cipher, ns, keys, &Organizations::All) {
        Scan::Marked(m) if want.is_none_or(|w| m.id == w) => Ok(Some(m.id.clone())),
        Scan::Uninspectable(why) => Err(WriteError::Uninspectable(why)),
        _ => Ok(None),
    }
}

/// Deletes the tool's item `expected_id` (§8.2): strips the tool's fields and saves, then trashes the item only when the
/// server's reply holds nothing of the user's. An out-of-date answer starts over from the strip on the refetched
/// copy; an item that left the tool meanwhile (gone, trashed, unmarked, re-marked) is `Nothing`, and one that changed
/// owner or edit right is `OwnerChanged`, as in `update`. A reply that cannot
/// be read (`Unreadable`) or a trash that fails (`Stripped`) leaves the stripped item in the vault, and says why.
pub async fn delete<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    ns: &Namespace,
    keys: &Keys,
    rng: &impl Random,
    cipher: &Value,
    expected_id: &str,
) -> Result<DeleteOutcome, SyncWriteError> {
    // A cipher that now carries another `{ns}:id` is another item: nothing is sent (bwss `run_delete`).
    if marked_id(cipher, ns, keys, Some(expected_id))?.is_none() {
        return Ok(DeleteOutcome::Nothing);
    }
    let id = cipher_id(cipher)?;
    let mut current = cipher.clone();
    for attempt in 1..=ATTEMPTS {
        let body = strip(&current, ns, keys, rng)?;
        match client.update_cipher(&id, body).await {
            Ok(reply) => {
                return Ok(match has_foreign_content(&reply, ns, keys) {
                    Err(e) => DeleteOutcome::Unreadable(e),
                    Ok(true) => DeleteOutcome::KeptForeign,
                    Ok(false) => match client.trash_cipher(&id).await {
                        Ok(()) => DeleteOutcome::Trashed,
                        Err(trash) => DeleteOutcome::Stripped { trash },
                    },
                });
            }
            Err(e) if e.is_out_of_date() => {
                if attempt < ATTEMPTS {
                    current = match refetch(client, &id).await? {
                        Some(c) if marked_id(&c, ns, keys, Some(expected_id))?.is_some() => c,
                        _ => return Ok(DeleteOutcome::Nothing),
                    };
                    // Read with every organization: still marked is not still the caller's to strip (§9).
                    if owner(&current) != owner(cipher) {
                        return Err(SyncWriteError::OwnerChanged);
                    }
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(SyncWriteError::StillChanging)
}
