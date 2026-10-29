//! The Bitwarden server API: wire formats first, the client and the hub follow.

mod client;
mod hub;
mod msgpack;

pub use client::{ApiError, ApiKey, Client, DeviceInfo, ServerUrls, normalize_keys, origin_of, resolve_server_urls};
pub use hub::{Hub, HubOptions, HubOut, hub_url, run_hub};
pub use msgpack::{Msg, MsgPackError, decode_msgpack, split_signalr_frames};

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]
mod msgpack_tests;

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod hub_tests;
