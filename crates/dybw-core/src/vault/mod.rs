//! Read rules of the data model: namespaces, discovery and the value source (§2–§5), duplicates (§7) and
//! organization keys (§9, design §6.9).

pub mod fields;
pub mod namespace;
pub mod orgs;
pub mod scan;

pub use namespace::{Encodings, IdProblem, Namespace};
pub use orgs::{OrgProblem, unlock_organizations};
pub use scan::{Duplicate, MarkedItem, Scan, ScanReport, SkipReason, Uninspectable, ValueSource, scan, scan_vault};

use crate::crypto::{Marker, SymmetricKey};
use std::collections::{BTreeMap, BTreeSet};

/// Which organizations' items a tool reads (opt-in, design §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Organizations {
    None,
    All,
    Only(BTreeSet<String>),
}

impl Organizations {
    pub fn allows(&self, organization: &str) -> bool {
        match self {
            Organizations::None => false,
            Organizations::All => true,
            Organizations::Only(ids) => ids.contains(organization),
        }
    }
}

/// The keys a scan needs: the user key, the unlocked organizations' keys and the namespace's value marker.
#[derive(Debug)]
pub struct Keys {
    pub user: SymmetricKey,
    pub orgs: BTreeMap<String, SymmetricKey>,
    pub marker: Marker,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod scan_tests;

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod orgs_tests;
