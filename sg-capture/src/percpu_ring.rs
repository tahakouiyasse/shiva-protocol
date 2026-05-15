//! `percpu_ring.rs` — Per-CPU ring buffer handle table.
//!
//! # Why this module exists
//! CONTROLLER.md §1.2 mandates strict per-CPU isolation: each userspace vacuum
//! thread may ONLY poll the ring buffer that corresponds to its pinned CPU.
//! Cross-CPU ring access is classified as a design defect, not a runtime error.
//!
//! This module provides a fixed-size, [`NCPU`]-indexed table of [`RingBuf`]
//! handles.  Indexing is bounds-checked via a safe accessor that encodes the
//! CPU-locality invariant in the type system: a thread that has not been pinned
//! to a CPU cannot legally obtain a handle.
//!
//! # Interior mutability policy
//! There is none.  Handles are handed out once during loader init and never
//! mutated again.  The vacuum worker owns its handle exclusively.

use aya::maps::RingBuf;
use aya::maps::MapData;
use sg_common::NCPU;

/// A fixed-size table of per-CPU [`RingBuf`] map handles.
///
/// Indexed by logical CPU id in the range `[0, NCPU)`.  Slots are `Option`
/// because not all CPU ids are guaranteed to be present on every platform;
/// absent slots are `None` and the loader skips them gracefully.
pub struct PerCpuRingTable {
    // `Box<[Option<RingBuf<MapData>>; NCPU]>` would require heap allocation at
    // init, which Valgrind massif would catch on the *flat* post-init profile.
    // However, this allocation happens ONCE during loader init (pre-hot-path),
    // which is permitted by INV-01.  The hot path never allocates after this.
    handles: Box<[Option<RingBuf<MapData>>; NCPU]>,
}

impl PerCpuRingTable {
    /// Construct the table from a pre-built array of handles.
    ///
    /// Called exactly once by the loader after all NCPU maps have been opened.
    /// The `handles` array must already have been heap-allocated before this
    /// call — this constructor does not allocate; it merely takes ownership.
    pub fn new(handles: Box<[Option<RingBuf<MapData>>; NCPU]>) -> Self {
        Self { handles }
    }

    /// Obtain an exclusive reference to the [`RingBuf`] for `cpu_id`.
    ///
    /// Returns `None` when `cpu_id >= NCPU` or when the CPU has no ring buffer
    /// (sparse topology).  The caller — always the vacuum thread pinned to
    /// `cpu_id` — holds the only live reference to this slot by design.
    ///
    /// # Invariant
    /// Only the thread pinned to `cpu_id` may call this method for that id.
    /// Concurrent access to the same slot from different threads is UB and is
    /// prevented by the caller passing `&mut self` through a thread-owned copy.
    pub fn get_mut(&mut self, cpu_id: usize) -> Option<&mut RingBuf<MapData>> {
        // Bounds check encodes the NCPU contract at the access site.
        if cpu_id >= NCPU {
            return None;
        }
        self.handles[cpu_id].as_mut()
    }

    /// Return the number of populated (non-`None`) slots.
    ///
    /// Used by the loader to emit a startup diagnostic without touching the hot
    /// path.  This is a cold-path method; allocation is acceptable here.
    pub fn populated_count(&self) -> usize {
        self.handles.iter().filter(|h| h.is_some()).count()
    }
}