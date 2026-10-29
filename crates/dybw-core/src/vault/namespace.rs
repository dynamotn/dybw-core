//! A tool's namespace and the presets of `namespaces.md`.

use crate::crypto::MarkScheme;

/// The value encodings a namespace implements (data model §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encodings {
    /// Text only: every non-blank `{ns}:encoding` is `unknown-encoding`.
    None,
    Base64,
}

/// Why an `{ns}:id` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdProblem {
    Invalid,
    Reserved,
}

/// A public struct, so a later tool defines its own without a core release.
#[derive(Debug, Clone, Copy)]
pub struct Namespace {
    pub name: &'static str,
    pub encodings: Encodings,
    /// Checks the trimmed, non-blank `{ns}:id`.
    pub id_rule: fn(&str) -> Result<(), IdProblem>,
    pub marks: MarkScheme,
}

impl Namespace {
    pub const BWSS: Namespace =
        Namespace { name: "bwss", encodings: Encodings::Base64, id_rule: bwss_id, marks: MarkScheme::Bwss };
    pub const OBSIDIAN: Namespace =
        Namespace { name: "obsidian", encodings: Encodings::None, id_rule: obsidian_id, marks: MarkScheme::Obsidian };

    /// The tool field `{ns}:{name}`.
    pub fn field(&self, name: &str) -> String {
        format!("{}:{name}", self.name)
    }
}

/// Any non-blank id; `_collections` is the collection registry note.
fn bwss_id(id: &str) -> Result<(), IdProblem> {
    match id.trim() {
        "" => Err(IdProblem::Invalid),
        "_collections" => Err(IdProblem::Reserved),
        _ => Ok(()),
    }
}

/// `^[a-z0-9]+(?:-[a-z0-9]+)*$` (SecretStorage.setSecret); the plugin's own credential prefixes are reserved.
fn obsidian_id(id: &str) -> Result<(), IdProblem> {
    let segment = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !id.split('-').all(segment) {
        return Err(IdProblem::Invalid);
    }
    if ["keychain-bitwarden-", "bitwarden-secrets-"].iter().any(|p| id.starts_with(p)) {
        return Err(IdProblem::Reserved);
    }
    Ok(())
}
