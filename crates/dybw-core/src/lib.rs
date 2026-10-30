//! Shared core of bwss and the Obsidian plugin.
#![forbid(unsafe_code)]

pub mod api;
pub mod crypto;
pub mod ports;
pub mod profile;
pub mod sync;
#[cfg(feature = "testing")]
pub mod testing;
pub mod vault;
