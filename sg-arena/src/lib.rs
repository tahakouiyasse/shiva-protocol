//! sg-arena — Fixed-Size Arena Allocator for Project Shifting Ghost
//!
//! INVARIANTS:
//!   - INVARIANT-A: All allocations happen during `ArenaInit` window only.
//!     After `ArenaInit::lock()`, the bump pointer is permanently frozen.
//!   - Zero dynamic allocation: no `alloc`, no `std`, no heap at any point.
//!   - One permitted `unsafe` block in `arena.rs` (the bump allocator).
//!     All other modules are safe Rust.
//!   - Cache-line alignment: backing store is `repr(align(64))`.
//!
//! NASA P10 compliance:
//!   P10-1  No dynamic allocation after arena lock.
//!   P10-2  All hot-path functions are O(1), no loops, no recursion.
//!   P10-5  All error conditions returned as `Result`; no `panic!`.
//!   P10-7  No recursion anywhere in the crate.
//!   P10-8  `unsafe` restricted to one block with documented invariants.

#![no_std]
#![feature(negative_impls)]
#![deny(warnings)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::too_many_lines)]
#![deny(clippy::recursive)]
#![deny(clippy::undocumented_unsafe_blocks)]

pub mod arena;
pub mod guards;
pub mod pool;
pub mod ring;

pub use arena::Arena;
pub use guards::{ArenaInit, ArenaLocked, ArenaStats};
pub use pool::{Pool, PoolHandle};
pub use ring::RingBuffer;

/// Errors produced by the arena subsystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArenaError {
    /// The arena has insufficient remaining space for the requested allocation.
    Exhausted,
    /// The pool has no free slots available.
    PoolFull,
    /// Requested alignment is not a power of two.
    BadAlignment,
}

#[cfg(test)]
mod tests;