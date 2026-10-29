//! The fixed accounts of `vectors/accounts/`, unlocked by the core's own code.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use dybw_core::crypto::{AwsLcRsa, ContentFormat, SymmetricKey, unwrap_org_key};
use dybw_core::testing::{SeededRandom, block_on};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

pub struct ScenarioKeys {
    pub user: SymmetricKey,
    /// Organization id to key; empty unless the scenario enables organizations.
    pub orgs: BTreeMap<String, SymmetricKey>,
    /// The `/sync` profile the fake server serves.
    pub profile: Value,
    /// The server's answer to prelogin for this account's KDF.
    pub prelogin: Value,
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
pub fn account_keys(dir: &Path, name: &str, organizations: bool) -> ScenarioKeys {
    let path = dir.join("accounts").join(format!("{name}.json"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let account: Value = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
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
            let key = block_on(unwrap_org_key(text(org, "wrapped", name), der, &AwsLcRsa))
                .unwrap_or_else(|e| panic!("{name}: organization {id}: {e}"));
            assert_eq!(
                key.to_bytes().as_slice(),
                b64(text(org, "key", name), name).as_slice(),
                "{name}: organization {id}: the unwrapped key differs from the account file"
            );
            orgs.insert(id.to_owned(), key);
        }
    }

    let profile = json!({
        "id": "vectors-user",
        "email": text(&account, "email", name),
        "key": text(&account, "profileKey", name),
        "privateKey": wrapped_private,
        "organizations": orgs_list.iter().map(|o| json!({
            "id": text(o, "id", name), "name": text(o, "name", name), "key": text(o, "wrapped", name), "enabled": true,
        })).collect::<Vec<_>>(),
    });
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
    ScenarioKeys { user, orgs, profile, prelogin }
}
