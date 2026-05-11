//! Linear bump allocator.
//!
//! One `unsafe` block is permitted in this module — the pointer arithmetic
//! for carving slices from the static backing store.

use core::mem;
use core::sync::atomic::{AtomicUsize, Ordering};
use sg_common::ARENA_SIZE_BYTES;

use crate::{ArenaError, ArenaInit, ArenaStats};

// ─── BACKING STORE ────────────────────────────────────────────────────────────
//
// `repr(align(64))` satisfies the 64-byte cache-line alignment requirement.
// The struct wrapper is necessary because Rust does not allow an alignment
// attribute directly on a naked array.

#[repr(align(64))]
struct AlignedBacking {
    #[allow(dead_code)]
    bytes: [u8; ARENA_SIZE_BYTES],
}

// SAFETY: ARENA_BACKING is accessed exclusively through the bump pointer
// inside `Arena`, which is constructed exactly once via `Arena::init()`.
// The `static mut` is never accessed directly; all access is mediated by
// the single `*mut u8` base pointer stored in `Arena`.  Once `ArenaInit`
// is consumed by `ArenaInit::lock()`, the bump pointer is frozen and no
// further mutation is possible.  The single-threaded init window guarantee
// is enforced at the type level: `ArenaInit` is `!Send`.
static mut ARENA_BACKING: AlignedBacking = AlignedBacking {
    bytes: [0u8; ARENA_SIZE_BYTES],
};

// Monotonically increasing bump offset shared between `alloc_slice` calls.
// Written only during the `ArenaInit` window (single-threaded by !Send).
// Read (for stats) after `lock()` via `ArenaLocked`.
static BUMP: AtomicUsize = AtomicUsize::new(0);

// ─── ARENA ────────────────────────────────────────────────────────────────────

/// Raw arena handle.  Constructed once; used only within `arena.rs`.
pub struct Arena {
    /// Pointer to `ARENA_BACKING.bytes[0]`.
    base: *mut u8,
    /// Total capacity — always `ARENA_SIZE_BYTES`.
    cap: usize,
}

// The raw pointer is only ever used during the single-threaded init window.
// After lock, no mutation occurs.
unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

impl Arena {
    /// Construct the arena from the static backing store.
    ///
    /// # Panics
    /// Never.  All error conditions are returned as `ArenaError`.
    ///
    /// This function must be called exactly once before any other arena
    /// operation.  Calling it a second time is safe but wastes the existing
    /// allocation state (BUMP is shared and monotonic).
    #[must_use]
    pub fn init() -> ArenaInit {
        // SAFETY: We take a raw pointer to ARENA_BACKING.bytes.  This is the
        // sole reference to the static mut; no other code path touches
        // ARENA_BACKING directly.  The pointer is valid for the lifetime of
        // the process.  Aliasing is prevented because BUMP is monotonically
        // increasing and alloc_slice is only reachable while ArenaInit is
        // alive (it is !Send and consumed by lock()).
        // Au lieu de créer une référence, on accède directement au pointeur de l'adresse statique
        let base = core::ptr::addr_of_mut!(ARENA_BACKING).cast::<u8>();
        ArenaInit {
            arena: Arena {
                base,
                cap: ARENA_SIZE_BYTES,
            },
        }
    }

    /// Allocate a contiguous slice of `n` elements of type `T`.
    ///
    /// Alignment is bumped to `align_of::<T>()`.  O(1).  No loops.
    #[inline]
    pub(crate) fn alloc_slice<T: Copy>(
        &self,
        n: usize,
    ) -> Result<&'static mut [T], ArenaError> {
        let align = mem::align_of::<T>();
        let size  = mem::size_of::<T>();

        // Alignment must be a power of two (guaranteed by Rust's layout rules,
        // but we assert defensively for NASA P10).
        if !align.is_power_of_two() {
            return Err(ArenaError::BadAlignment);
        }

        // Atomically compute and advance the bump pointer.
        // We use a compare-exchange loop because alloc_slice might (in future)
        // be called from concurrent contexts; the !Send guard on ArenaInit
        // prevents this today, but the atomic makes the operation correct
        // regardless.
        let total_bytes = n.checked_mul(size).ok_or(ArenaError::Exhausted)?;

        let mut current = BUMP.load(Ordering::Relaxed);
        loop {
            // Align the current offset upward.
            let mask        = align - 1;
            let aligned     = current.wrapping_add(mask) & !mask;
            let next        = aligned.checked_add(total_bytes).ok_or(ArenaError::Exhausted)?;

            if next > self.cap {
                return Err(ArenaError::Exhausted);
            }

            match BUMP.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // SAFETY: `aligned` is within `[0, cap)` and `next ≤ cap`.
                    // `base.add(aligned)` is therefore within the allocation of
                    // ARENA_BACKING.  The region `[aligned, next)` is unique:
                    // the bump pointer was advanced atomically so no concurrent
                    // call can overlap this region.  T is Copy (no Drop), so
                    // treating the uninitialized bytes as zeroed `MaybeUninit<T>`
                    // and casting to `T` is valid because the backing array was
                    // zero-initialised at link time (`[0u8; ARENA_SIZE_BYTES]`).
                    // The returned lifetime is 'static because ARENA_BACKING is
                    // a `static mut` that lives for the entire process lifetime.
                    let ptr = unsafe {
                        self.base.add(aligned).cast::<T>()
                    };
                    // SAFETY: ptr is aligned, non-null, and points to `n`
                    // consecutive initialised (zero) elements of type T.
                    // The slice is exclusively owned by the caller because the
                    // bump pointer has advanced past this region.
                    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, n) };
                    return Ok(slice);
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns remaining free bytes.
    #[must_use]
    #[inline]
    pub(crate) fn remaining_bytes(&self) -> usize {
        let used = BUMP.load(Ordering::Acquire);
        self.cap.saturating_sub(used)
    }

    /// Returns total allocated bytes.
    #[must_use]
    #[inline]
    pub(crate) fn allocated_bytes(&self) -> usize {
        BUMP.load(Ordering::Acquire)
    }

    /// Snapshot of current allocation statistics.
    #[must_use]
    #[inline]
    pub(crate) fn stats(&self) -> ArenaStats {
        let used = BUMP.load(Ordering::Acquire);
        ArenaStats {
            allocated_bytes: used,
            remaining_bytes: self.cap.saturating_sub(used),
            capacity_bytes:  self.cap,
        }
    }
}