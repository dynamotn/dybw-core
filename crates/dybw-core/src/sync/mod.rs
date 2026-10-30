//! Sync rules: the writer with its out-of-date retry (data model §6.5).

mod plan;
mod queue;
mod state;
mod write;

pub use plan::{Action, BaseEntry, ConflictKind, ConflictOverride, PlanInput, Policy, RemoteEntry, plan_sync};
pub use queue::{FlushReport, Op, enqueue, flush};
pub use state::{DeviceState, parse_plugin_state, to_plugin_json};
pub use write::{ATTEMPTS, DeleteOutcome, SyncWriteError, create, delete, update};

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod write_tests;

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod queue_tests;

#[cfg(test)]
mod plan_tests;

#[cfg(test)]
#[expect(clippy::indexing_slicing, reason = "tests")]
mod state_tests;
