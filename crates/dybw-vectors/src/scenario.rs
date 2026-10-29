//! The generated scenario format of `vectors/README.md`. `deny_unknown_fields` everywhere, so a format change fails
//! loudly instead of being ignored.

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub spec: String,
    pub sections: Vec<String>,
    pub account: String,
    pub namespace: String,
    pub generator: String,
    #[serde(default)]
    pub options: Options,
    /// Server-shaped ciphers, kept as JSON: the core's own code reads them.
    pub ciphers: Vec<Value>,
    #[serde(default)]
    pub device: Option<Device>,
    /// Cipher id to the device's local value; `None` is no local value.
    #[serde(default)]
    pub local: Option<BTreeMap<String, Option<String>>>,
    #[serde(default)]
    pub operation: Option<Operation>,
    pub expect: Expect,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    pub organizations: bool,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    #[default]
    Ask,
    PreferRemote,
    PreferLocal,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Device {
    pub base: BTreeMap<String, BaseEntry>,
    pub pending_creates: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BaseEntry {
    pub cipher: String,
    pub revision_date: Option<String>,
    pub value: String,
    #[serde(default)]
    pub push_confirmed: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Operation {
    #[serde(rename_all = "camelCase")]
    SetValue {
        id: String,
        value: String,
        #[serde(default)]
        fresh: Option<Value>,
    },
    #[serde(rename_all = "camelCase")]
    Create {
        id: String,
        value: String,
        folder_id: Option<String>,
        #[serde(default)]
        fresh: Option<Value>,
    },
    #[serde(rename_all = "camelCase")]
    Delete {
        id: String,
        #[serde(default)]
        fresh: Option<Value>,
    },
}

impl Operation {
    /// The cipher the server returns on the refetch after an out-of-date rejection.
    pub fn fresh(&self) -> Option<&Value> {
        match self {
            Operation::SetValue { fresh, .. } | Operation::Create { fresh, .. } | Operation::Delete { fresh, .. } => {
                fresh.as_ref()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    #[serde(default)]
    pub read: Option<ReadExpect>,
    #[serde(default)]
    pub write: Option<WriteExpect>,
    #[serde(default)]
    pub plan: Option<Vec<PlanEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadExpect {
    pub items: Vec<ExpectedItem>,
    pub skipped: Vec<Skipped>,
    pub uninspectable: Vec<String>,
    #[serde(default)]
    pub duplicates: Option<Vec<Duplicate>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedItem {
    pub cipher: String,
    pub id: String,
    pub value: String,
    pub source: String,
    #[serde(default)]
    pub attributes: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Skipped {
    pub cipher: String,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Duplicate {
    pub id: String,
    pub kept: String,
    pub left: Vec<String>,
}

/// Either the canonical requests (decrypted bodies, kept as JSON: compared by deep equality) or an error code.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum WriteExpect {
    Requests(WriteRequests),
    Error(WriteError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteRequests {
    pub requests: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteError {
    pub error: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEntry {
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub conflict: Option<String>,
}
