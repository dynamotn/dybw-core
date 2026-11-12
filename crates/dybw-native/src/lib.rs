//! Native host code for dybw-core, shared by the dybw CLI and bwss: the host
//! ports, the pinentry client, and the ADR 0008 config (key registry,
//! parser, trusted-program rule).
//!
//! Unix only: the trust rule reads file owners and modes.

pub mod config;
pub mod fsutil;
pub mod ports;
pub mod prompter;
