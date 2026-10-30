//! Sync rules: the writer with its out-of-date retry (data model §6.5).

mod queue;
mod write;

pub use queue::{FlushReport, Op, enqueue, flush};
pub use write::{ATTEMPTS, DeleteOutcome, SyncWriteError, create, delete, update};

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod write_tests;

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod queue_tests;
