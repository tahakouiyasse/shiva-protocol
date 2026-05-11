//! sg-ebpf — eBPF Loader & XDP Ingestion Layer for Project Shifting Ghost
//!
//! # Safety policy
//!
//! `#![deny(unsafe_code)]` is active crate-wide.
//! The only permitted `unsafe` are the two `unsafe impl aya::Pod` in `map.rs`,
//! each guarded by `#[allow(unsafe_code)]` with a written safety justification.
//! All other modules contain zero `unsafe` blocks.
//!
//! `forbid` is intentionally NOT used: it cannot be overridden by `#[allow]`
//! at item level, which would make the `unsafe impl Pod` impossible to compile.
//! The practical effect is identical — any new unguarded `unsafe` is a compile error.

#![deny(unsafe_code)]
#![allow(warnings)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::too_many_lines)]
#![deny(clippy::recursive)]

pub mod caps;
pub mod loader;
pub mod map;

#[cfg(test)]
mod tests;

pub use caps::{verify_capabilities, CapabilityError};
pub use loader::{EbpfLoader, LoadError};
pub use map::{BpfMaps, FpParams, MapError};