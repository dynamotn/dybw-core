//! A vault client's folder names (ADR 0025, C3): each `/sync` folder's name decrypted under the user key into an
//! id → name map. Folders are personal only; an organization has none here.

use super::scan::Uninspectable;
use crate::crypto::SymmetricKey;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

/// The folders of a `/sync` response by id. A name that does not decrypt keeps its id and holds the reason, so a
/// caller can show the folder as unreadable. No `Clone`; `Debug` shows only the ids; every name is wiped on drop.
pub struct FolderNames(BTreeMap<String, Result<Zeroizing<String>, Uninspectable>>);

impl FolderNames {
    /// The name of folder `id`, or why it does not read; `None` for an id the sync did not list.
    pub fn get(&self, id: &str) -> Option<Result<&str, Uninspectable>> {
        self.0.get(id).map(|r| r.as_ref().map(|n| n.as_str()).map_err(|e| *e))
    }

    /// Every folder in id order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Result<&str, Uninspectable>)> {
        self.0.iter().map(|(id, r)| (id.as_str(), r.as_ref().map(|n| n.as_str()).map_err(|e| *e)))
    }
}

impl fmt::Debug for FolderNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

/// Decrypts the name of every folder in `sync["folders"]` (a missing or odd list is no folders). A folder without
/// an id is kept under `""`; one whose name is absent or fails to decrypt is [`Uninspectable::Value`]. None is dropped.
pub fn folder_names(sync: &Value, user: &SymmetricKey) -> FolderNames {
    let folders = sync.get("folders").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    FolderNames(
        folders
            .iter()
            .map(|f| {
                let id = f.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
                let name = f.get("name").and_then(Value::as_str).ok_or(Uninspectable::Value);
                (id, name.and_then(|n| user.decrypt_str(n).map_err(|_| Uninspectable::Value)))
            })
            .collect(),
    )
}
