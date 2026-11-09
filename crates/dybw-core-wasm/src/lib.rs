//! dybw-core for `wasm32-unknown-unknown`: every core port implemented over one [`host::Host`] trait, which mirrors
//! the duck-typed JS `ports` object. Unstable: M6 may reshape it.
//!
//! Size budget: the module built without `vectors` (`scripts/build-wasm.sh`, `wasm-opt -Oz`), as base64, plus its
//! glue after esbuild minify must stay within 1 179 648 bytes (1.125 MiB); `js/test/size.test.ts` enforces it.
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
