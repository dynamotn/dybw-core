//! Shared core of bwss and the Obsidian plugin.
#![forbid(unsafe_code)]

pub mod api;
pub mod crypto;
pub mod ports;
#[cfg(feature = "testing")]
pub mod testing;
pub mod vault;
