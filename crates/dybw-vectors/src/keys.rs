//! The fixed accounts of `vectors/accounts/`, unlocked by the core's own code.

use crate::Files;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::crypto::{
    ContentFormat, Marker, SymmetricKey, unwrap_org_key, unwrap_signing_key, verify_security_state,
};
use dybw_core::ports::RsaOaep;
use dybw_core::testing::SeededRandom;
use dybw_core::vault::{Keys, Namespace};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct ScenarioKeys {
    pub user: SymmetricKey,
    /// Organization id to key; empty unless the scenario enables organizations.
    pub orgs: BTreeMap<String, SymmetricKey>,
    /// The `/sync` profile the fake server serves.
    pub profile: Value,
    /// The server's answer to prelogin for this account's KDF.
    pub prelogin: Value,
    /// The account's security state version: 0 without a signed state.
    pub security_version: u64,
}

impl ScenarioKeys {
    /// Moves the keys into the core's `Keys`, with the namespace's value marker; nothing is cloned.
    pub fn into_keys(self, ns: &Namespace) -> Keys {
        let marker = Marker::new(&self.user, ns.marks);
        Keys { user: self.user, orgs: self.orgs, marker, security_version: self.security_version }
    }
}

fn text<'a>(v: &'a Value, key: &str, what: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_else(|| panic!("{what}: no {key}"))
}

fn b64(s: &str, what: &str) -> Vec<u8> {
    B64.decode(s).unwrap_or_else(|e| panic!("{what}: {e}"))
}

/// Loads account `name`: the user key from `userKey`; with `organizations`, each organization's key is unwrapped by
/// the core (RSA-OAEP under the account's private key) and checked against the plain `key` of the account file.
/// Panics on a broken account file: nothing in a run works without it.
pub async fn account_keys(files: &Files, name: &str, organizations: bool, rsa: &impl RsaOaep) -> ScenarioKeys {
    let path = format!("accounts/{name}.json");
    let raw = files.get(&path).unwrap_or_else(|| panic!("{path}: not found"));
    let account: Value = serde_json::from_str(raw).unwrap_or_else(|e| panic!("{path}: {e}"));
    let user = SymmetricKey::from_bytes(&b64(text(&account, "userKey", name), name))
        .unwrap_or_else(|e| panic!("{name}: userKey: {e}"));

    // Only the vectors' fixed seed; never key material outside tests.
    let rng = SeededRandom::new(0x0076_6563_746f_7273);
    let orgs_list = account.get("organizations").and_then(Value::as_array).cloned().unwrap_or_default();
    let (wrapped_private, pkcs8) = match account.get("privateKey").and_then(Value::as_str) {
        Some(der) => {
            let der = b64(der, name);
            let wrapped =
                user.encrypt_as(&der, ContentFormat::Pkcs8, &rng).unwrap_or_else(|e| panic!("{name}: privateKey: {e}"));
            (Some(wrapped), Some(der))
        }
        None => (None, None),
    };

    let mut orgs = BTreeMap::new();
    if organizations {
        for org in &orgs_list {
            let id = text(org, "id", name);
            let der = pkcs8.as_deref().unwrap_or_else(|| panic!("{name}: organizations without a privateKey"));
            let key = unwrap_org_key(text(org, "wrapped", name), der, rsa)
                .await
                .unwrap_or_else(|e| panic!("{name}: organization {id}: {e}"));
            assert_eq!(
                key.to_bytes().as_slice(),
                b64(text(org, "key", name), name).as_slice(),
                "{name}: organization {id}: the unwrapped key differs from the account file"
            );
            orgs.insert(id.to_owned(), key);
        }
    }

    let mut profile = json!({
        "id": "vectors-user",
        "email": text(&account, "email", name),
        "key": text(&account, "profileKey", name),
        "privateKey": wrapped_private,
        "organizations": orgs_list.iter().map(|o| json!({
            "id": text(o, "id", name), "name": text(o, "name", name), "key": text(o, "wrapped", name), "enabled": true,
        })).collect::<Vec<_>>(),
    });
    if let (Some(account_keys), Some(p)) = (account.pointer("/profile/accountKeys"), profile.as_object_mut()) {
        p.insert("accountKeys".into(), account_keys.clone());
    }
    // Verified with the key derived from the wrapped signing key; the server's `securityVersion` is never read.
    let security_version = match account.pointer("/profile/accountKeys") {
        Some(keys) => {
            let wrapped = keys.pointer("/signatureKeyPair/wrappedSigningKey").and_then(Value::as_str);
            let signing = unwrap_signing_key(&user, wrapped.unwrap_or_else(|| panic!("{name}: no wrappedSigningKey")))
                .unwrap_or_else(|e| panic!("{name}: wrappedSigningKey: {e}"));
            let state = keys.pointer("/securityState/securityState").and_then(Value::as_str);
            verify_security_state(&signing, state.unwrap_or_else(|| panic!("{name}: no securityState")))
                .unwrap_or_else(|e| panic!("{name}: securityState: {e}"))
        }
        None => 0,
    };
    let kdf = account.get("kdf").unwrap_or_else(|| panic!("{name}: no kdf"));
    let num = |k: &str| kdf.get(k).cloned().unwrap_or(Value::Null);
    let prelogin = match kdf.get("type").and_then(Value::as_str) {
        Some("pbkdf2") => json!({ "kdf": 0, "kdfIterations": num("iterations") }),
        Some("argon2id") => json!({
            "kdf": 1, "kdfIterations": num("iterations"), "kdfMemory": num("memory"),
            "kdfParallelism": num("parallelism"),
        }),
        other => panic!("{name}: unknown kdf {other:?}"),
    };
    ScenarioKeys { user, orgs, profile, prelogin, security_version }
}
