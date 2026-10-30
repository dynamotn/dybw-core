//! The writer: port of bwss `run_patch` and `run_delete` (`src/backend/runner.rs`) without bwss's state lock.

use crate::api::{ApiError, Client};
use crate::ports::{Clock, Http, Random};
use crate::vault::scan::{Scan, scan, trashed};
use crate::vault::write::{NewItem, Patch, ValueChange, WriteError, apply, has_foreign_content, new_item, strip};
use crate::vault::{Keys, Namespace, Organizations};
use serde_json::Value;

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

/// The server's current copy; `None` when it is gone (404).
async fn refetch<H: Http, C: Clock>(client: &mut Client<H, C>, id: &str) -> Result<Option<Value>, ApiError> {
    match client.get_cipher(id).await {
        Err(ApiError::Http { status: 404, .. }) => Ok(None),
        other => other.map(Some),
    }
}

/// Applies `patch` to `cipher` and sends it. When the server says the copy is out of date, the same patch is
/// applied to a refetched copy (§6.5): `SourceChanged`, `Gone` and `Unmarked` end it, and at most `ATTEMPTS` writes
/// are sent in all. `now_ms` dates a replaced login password. Returns the server's reply, or `None` for an empty
/// patch, which sends nothing (a PUT would bump the revision date and look like an edit to other devices).
pub async fn update<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    ns: &Namespace,
    keys: &Keys,
    rng: &impl Random,
    now_ms: i64,
    cipher: &Value,
    patch: &Patch,
) -> Result<Option<Value>, SyncWriteError> {
    if matches!(patch.value, ValueChange::Keep) && patch.set.is_empty() && patch.remove.is_empty() {
        return Ok(None);
    }
    let id = cipher_id(cipher)?;
    let mut current = cipher.clone();
    for attempt in 1..=ATTEMPTS {
        let body = apply(&current, patch, ns, keys, rng, now_ms)?;
        match client.update_cipher(&id, body).await {
            Err(e) if e.is_out_of_date() => {
                if attempt < ATTEMPTS {
                    current = refetch(client, &id).await?.ok_or(WriteError::Gone)?;
                }
            }
            sent => return Ok(Some(sent?)),
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

/// Deletes the tool's item (§8.2): strips the tool's fields and saves, then trashes the item only when the
/// server's reply holds nothing of the user's. An out-of-date answer starts over from the strip on the refetched
/// copy; an item that left the tool meanwhile (gone, trashed, unmarked, re-marked) is `Nothing`. A reply that cannot
/// be read (`Unreadable`) or a trash that fails (`Stripped`) leaves the stripped item in the vault, and says why.
pub async fn delete<H: Http, C: Clock>(
    client: &mut Client<H, C>,
    ns: &Namespace,
    keys: &Keys,
    rng: &impl Random,
    cipher: &Value,
) -> Result<DeleteOutcome, SyncWriteError> {
    let Some(marker_id) = marked_id(cipher, ns, keys, None)? else { return Ok(DeleteOutcome::Nothing) };
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
                        Some(c) if marked_id(&c, ns, keys, Some(&marker_id))?.is_some() => c,
                        _ => return Ok(DeleteOutcome::Nothing),
                    };
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(SyncWriteError::StillChanging)
}
