//! Typestate guards that enforce the single-allocation-window invariant.
//!
//! `ArenaInit`  — pre-lock; allocation is permitted; `!Send`
//! `ArenaLocked`— post-lock; allocation is impossible; `Send + Sync`

use crate::arena::Arena;
use crate::ArenaError;
use sg_common::traits::ArenaAllocator;

// ─── STATS ────────────────────────────────────────────────────────────────────

/// Snapshot of arena usage at the moment `lock()` was called.
#[derive(Clone, Copy, Debug)]
pub struct ArenaStats {
    pub allocated_bytes: usize,
    pub remaining_bytes: usize,
    pub capacity_bytes:  usize,
}

// ─── ArenaInit ────────────────────────────────────────────────────────────────

/// Pre-lock arena handle.  Allocation is only possible while this type exists.
///
/// `!Send`: must not cross thread boundaries.  This makes the single-threaded
/// init window a compile-time invariant rather than a runtime assertion.
pub struct ArenaInit {
    pub(crate) arena: Arena,
}

// Explicitly opt out of Send.  This is safe because we never want ArenaInit
// to be sent to another thread — the allocator is single-threaded by design.
impl !Send for ArenaInit {}

impl ArenaAllocator for ArenaInit {
    type Error = ArenaError;

    /// Allocate `n` elements of type `T` from the arena.  O(1).
    ///
    /// Returns `Err(ArenaError::Exhausted)` if insufficient space remains.
    #[inline]
    fn alloc_slice<T: Copy>(&mut self, n: usize) -> Result<&'static mut [T], Self::Error> {
        self.arena.alloc_slice::<T>(n)
    }

    /// Remaining free bytes in the arena.
    
    #[inline]
    fn remaining_bytes(&self) -> usize {
        self.arena.remaining_bytes()
    }

    /// Total allocated bytes since init.
    
    #[inline]
    fn allocated_bytes(&self) -> usize {
        self.arena.allocated_bytes()
    }
}

impl ArenaInit {
    /// Consume `ArenaInit` and produce an `ArenaLocked`.
    ///
    /// After this call, allocation is permanently unavailable.  The bump
    /// pointer is frozen.  `ArenaLocked` is `Send + Sync` and may be passed
    /// to other threads for statistics queries.
    
    pub fn lock(self) -> ArenaLocked {
        ArenaLocked {
            stats: self.arena.stats(),
        }
    }
}

// ─── ArenaLocked ─────────────────────────────────────────────────────────────

/// Post-lock arena handle.  Immutable statistics only; no allocation.
pub struct ArenaLocked {
    pub(crate) stats: ArenaStats,
}

// SAFETY: ArenaLocked contains only a plain `ArenaStats` (Copy integers).
// No raw pointers, no mutability.  Safe to send and share across threads.
unsafe impl Send for ArenaLocked {}
unsafe impl Sync for ArenaLocked {}

impl ArenaLocked {
    /// Returns a snapshot of arena usage captured at lock time.
    
    #[inline]
    pub fn stats(&self) -> ArenaStats {
        self.stats
    }

    /// Remaining free bytes at the moment the arena was locked.
    
    #[inline]
    pub fn remaining_bytes(&self) -> usize {
        self.stats.remaining_bytes
    }

    /// Total allocated bytes at the moment the arena was locked.
    
    #[inline]
    pub fn allocated_bytes(&self) -> usize {
        self.stats.allocated_bytes
    }
}