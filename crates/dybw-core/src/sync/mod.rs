//! Sync rules: the writer with its out-of-date retry (data model §6.5).

mod write;

pub use write::{ATTEMPTS, DeleteOutcome, SyncWriteError, create, delete, update};

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod write_tests;
