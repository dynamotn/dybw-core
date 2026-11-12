//! Host ports for dybw-core: what the core asks of a native host (HTTP,
//! files, time, randomness, the Argon2id KDF, the notifications socket).

pub mod clock;
pub mod events;
pub mod http;
pub mod kdf;
pub mod random;
pub mod storage;

use dybw_core::ports::PortError;

/// The error of a blocking task that never finished (it panicked or was cancelled).
pub(crate) fn task_failed<E>(message: &'static str) -> impl FnOnce(E) -> PortError {
    move |_| PortError(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_task_reports_its_message() {
        assert_eq!(task_failed::<()>("the task failed")(()).0, "the task failed");
    }
}
