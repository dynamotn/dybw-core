//! The generated scenario format of `vectors/README.md`. `deny_unknown_fields` everywhere, so a format change fails
//! loudly instead of being ignored.

use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Options {
    #[serde(default)]
    pub organizations: bool,
    #[serde(default)]
    pub policy: Policy,
    #[serde(default)]
    pub accept_rollback: bool,
    /// The server the client talks to (ADR 0018).
    #[serde(default)]
    pub server: Server,
    /// The host's HTTP follows redirects (`Http::refuses_redirects` is `false`).
    #[serde(default)]
    pub follows_redirects: bool,
    /// Identity origins acknowledged on the device.
    #[serde(default)]
    pub acknowledged: BTreeSet<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Server {
    /// The fake server at `server::SERVER`.
    #[default]
    SelfHosted,
    /// The fake server as Bitwarden cloud US (`server::CLOUD`).
    Cloud,
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
    /// Plaintext values this device wrote to `login.password`, newest first (ignored until the core keeps records).
    #[serde(default)]
    pub written: Vec<String>,
    #[serde(default)]
    pub write_back_confirmed: bool,
}

/// How the tool's questions are answered (README, `operation`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Answer {
    #[default]
    WriteToLogin,
    KeepSeparate,
    Unanswered,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Operation {
    #[serde(rename_all = "camelCase")]
    SetValue {
        id: String,
        value: String,
        #[serde(default)]
        append_lines: Vec<AppendLines>,
        #[serde(default)]
        fresh: Option<Value>,
        #[serde(default)]
        answer: Answer,
    },
    #[serde(rename_all = "camelCase")]
    Create {
        id: String,
        value: String,
        folder_id: Option<String>,
        #[serde(default)]
        fresh: Option<Value>,
        #[serde(default)]
        answer: Answer,
    },
    #[serde(rename_all = "camelCase")]
    Delete {
        id: String,
        #[serde(default)]
        fresh: Option<Value>,
        #[serde(default)]
        answer: Answer,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendLines {
    pub name: String,
    pub lines: Vec<String>,
    pub hidden: bool,
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
    /// One cipher opened whole, and summarized, by a vault client (`vault::item`).
    #[serde(default)]
    pub open: Option<Vec<OpenExpect>>,
}

/// The opened item as plaintext JSON, or the reason it does not open. `summary`, when absent, is the item's (its
/// type, name, a login's username, its folder), or the same error.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenExpect {
    pub cipher: String,
    #[serde(default)]
    pub item: Option<Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub summary: Option<Value>,
}

/// The scan of a read, or the error that stopped it with the requests that were sent first.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ReadExpect {
    Items(ReadItems),
    Refused(ReadRefused),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRefused {
    pub error: String,
    /// `METHOD /path` of each request sent, in order.
    pub sent: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadItems {
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
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Duplicate {
    pub id: String,
    pub kept: String,
    pub left: Vec<String>,
    #[serde(default)]
    pub bound_kept: bool,
}

/// Either the canonical requests (decrypted bodies, kept as JSON: compared by deep equality) or an error code.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum WriteExpect {
    Requests(WriteRequests),
    Error(WriteError),
    Question(WriteQuestion),
}

/// Nothing was sent: the tool must ask this question first.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteQuestion {
    pub question: String,
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
