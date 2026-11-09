//! dybw-core for `wasm32-unknown-unknown`: every core port implemented over one [`host::Host`] trait, which mirrors
//! the duck-typed JS `ports` object. Unstable: M6 may reshape it.
#![forbid(unsafe_code)]

#[cfg(target_arch = "wasm32")]
mod bindings;
pub mod host;
pub mod ports;
pub mod session;
#[cfg(feature = "vectors")]
pub mod vectors;

#[cfg(test)]
mod tests;
