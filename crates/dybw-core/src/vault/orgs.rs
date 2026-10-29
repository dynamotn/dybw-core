//! Organization keys (data model §9, design §6.9): port of the plugin's `unlockOrganizationKeys`.

use super::Organizations;
use crate::crypto::{SymmetricKey, unwrap_org_key};
use crate::ports::RsaOaep;
use serde_json::Value;
use std::collections::BTreeMap;

/// An organization whose key could not be unwrapped; its items scan as `OrganizationKeyMissing`. The reason is a
/// fixed text or a `CryptoError` message, never key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgProblem {
    pub organization: String,
    pub reason: String,
}

const NO_PRIVATE_KEY: &str = "the account has no private key to read organization keys";

fn text<'v>(v: &'v Value, pointer: &str) -> Option<&'v str> {
    v.pointer(pointer).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Unwraps the keys of the enabled, confirmed organizations `allowed` names; the others are never unwrapped.
/// Every failure is a problem of that organization, never an abort.
pub async fn unlock_organizations(
    profile: &Value,
    user: &SymmetricKey,
    rsa: &impl RsaOaep,
    allowed: &Organizations,
) -> (BTreeMap<String, SymmetricKey>, Vec<OrgProblem>) {
    let mut keys = BTreeMap::new();
    let mut problems = Vec::new();
    let orgs: Vec<(&str, &str)> = profile
        .get("organizations")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|o| o.get("enabled") != Some(&Value::Bool(false)))
        .filter_map(|o| Some((text(o, "/id")?, text(o, "/key")?)))
        .filter(|(id, _)| allowed.allows(id))
        .collect();
    if orgs.is_empty() {
        return (keys, problems);
    }
    let wrapped = text(profile, "/privateKey")
        .or_else(|| text(profile, "/accountKeys/publicKeyEncryptionKeyPair/wrappedPrivateKey"));
    let private = match wrapped {
        None => Err(NO_PRIVATE_KEY.to_owned()),
        Some(w) => user.decrypt_pkcs8(w).map_err(|e| format!("the account's private key: {e}")),
    };
    for (id, wrapped) in orgs {
        let result = match &private {
            Err(reason) => Err(reason.clone()),
            Ok(der) => unwrap_org_key(wrapped, der, rsa).await.map_err(|e| e.to_string()),
        };
        match result {
            Ok(key) => {
                keys.insert(id.to_owned(), key);
            }
            Err(reason) => problems.push(OrgProblem { organization: id.to_owned(), reason }),
        }
    }
    (keys, problems)
}
