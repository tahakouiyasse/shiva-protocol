//! Typed object pool with automatic slot return on drop.
//!
//! `Pool<T>` wraps two arena-allocated slices:
//!   - `slots`:     the actual `T` objects.
//!   - `free_list`: a stack of available slot indices, each an `AtomicUsize`.
//!
//! Free-list discipline:
//!   - `alloc()` pops the top of the free list in O(1).
//!   - `PoolHandle<T>::drop()` pushes the slot index back in O(1).
//!   - Pool exhaustion returns `None`; never blocks, never panics.
//!
//! `SENTINEL` (usize::MAX) marks an empty free-list entry.

use core::sync::atomic::{AtomicUsize, Ordering};

const SENTINEL: usize = usize::MAX;

/// Typed object pool backed by arena storage.
pub struct Pool<T: Copy + Default> {
    slots:     *mut T,
    free_list: *const AtomicUsize,
    free_head: AtomicUsize,
    cap:       usize,
}

// SAFETY: Both raw pointers point into the process-lifetime ARENA_BACKING.
// Pool<T> is Send + Sync because all mutations go through AtomicUsize
// operations.  `T: Copy` ensures no Drop logic is silently lost.
unsafe impl<T: Copy + Send + Default> Send for Pool<T> {}
unsafe impl<T: Copy + Sync + Default> Sync for Pool<T> {}

impl<T: Copy + Default> Pool<T> {
    /// Construct a `Pool<T>` from two arena-allocated slices.
    ///
    /// `slots` and `free_list` must have been obtained from `ArenaInit::alloc_slice`
    /// and must have the same length.
    ///
    /// All `slots` are initialised to `T::default()`.  The free list is
    /// pre-populated with indices `0..cap` in order.
    pub fn new(
    slots:     &'static mut [T],
    free_list: &'static mut [usize],
) -> Self {
    let cap = slots.len();

    // Initialise la free-list comme tableau de usize bruts.
    for (i, entry) in free_list.iter_mut().enumerate() {
        *entry = if i + 1 < cap { i + 1 } else { SENTINEL };
    }

    for slot in slots.iter_mut() {
        *slot = T::default();
    }

    // SAFETY: AtomicUsize a exactement le même layout mémoire que usize.
    // Le slice est arena-backed (lifetime 'static). Aucun autre code
    // n'accède à ce slice après ce cast.
    let free_list_ptr = unsafe {
        core::slice::from_raw_parts_mut(
            free_list.as_mut_ptr() as *mut AtomicUsize,
            cap,
        )
    };

    Self {
        slots:     slots.as_mut_ptr(),
        free_list: free_list_ptr.as_ptr(),
        free_head: AtomicUsize::new(if cap > 0 { 0 } else { SENTINEL }),
        cap,
    }
}

    /// Allocate a slot from the pool.
    ///
    /// Returns `None` if the pool is exhausted.  O(1). No loops. No allocation.
    #[must_use]
    #[inline]
    pub fn alloc(&self) -> Option<PoolHandle<T>> {
        // Pop from the free-list stack.
        let idx = self.pop_free()?;
        Some(PoolHandle {
            pool: self as *const Pool<T>,
            idx,
        })
    }

    /// Returns total pool capacity.
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Pop the top free-list index.  Returns `None` if exhausted.
    #[inline]
    fn pop_free(&self) -> Option<usize> {
        let mut head = self.free_head.load(Ordering::Acquire);
        loop {
            if head == SENTINEL {
                return None;
            }
            // SAFETY: `head < cap` (SENTINEL terminates the chain).  The
            // free_list slice lives for 'static (arena-backed).
            let next = unsafe { (*self.free_list.add(head)).load(Ordering::Acquire) };
            match self.free_head.compare_exchange_weak(
                head,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(head),
                Err(observed) => head = observed,
            }
        }
    }

    /// Push an index back onto the free-list stack.
    #[inline]
    fn push_free(&self, idx: usize) {
        let mut head = self.free_head.load(Ordering::Acquire);
        loop {
            // SAFETY: `idx < cap` — guaranteed by `PoolHandle` construction.
            unsafe { (*self.free_list.add(idx)).store(head, Ordering::Relaxed) };
            match self.free_head.compare_exchange_weak(
                head,
                idx,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => head = observed,
            }
        }
    }

    /// Mutable access to a slot by index.  Used by `PoolHandle`.
    ///
    /// # Safety
    /// `idx` must be a valid index previously popped from the free list.
    #[inline]
    unsafe fn slot_mut(&self, idx: usize) -> *mut T {
        // SAFETY: caller guarantees idx < cap and the slot is exclusively owned.
        unsafe { self.slots.add(idx) }
    }
}

// ─── PoolHandle ───────────────────────────────────────────────────────────────

/// RAII guard for a borrowed pool slot.
///
/// `Deref`/`DerefMut` provide transparent access to the underlying `T`.
/// On `drop`, the slot index is returned to the pool's free list automatically.
pub struct PoolHandle<T: Copy + Default> {
    pub(crate) pool: *const Pool<T>,
    pub(crate) idx: usize,
}

// SAFETY: T: Copy + Send implies Pool<T>: Send.  The pointer is to a
// process-lifetime static.  PoolHandle is logically an exclusive borrow.
unsafe impl<T: Copy + Send + Default> Send for PoolHandle<T> {}

impl<T: Copy + Default> PoolHandle<T> {
    /// Returns the slot index within the pool.
    #[must_use]
    #[inline]
    pub fn index(&self) -> usize {
        self.idx
    }

    /// Returns a shared reference to the slot value.
    #[must_use]
    #[inline]
    pub fn get(&self) -> &T {
        // SAFETY: The handle holds exclusive ownership of `self.idx`.
        // The pool pointer is valid for 'static.
        unsafe { &*(*self.pool).slot_mut(self.idx) }
    }

    /// Returns a mutable reference to the slot value.
    #[must_use]
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: Same as `get`; additionally, `&mut self` prevents
        // simultaneous borrows of the same handle.
        unsafe { &mut *(*self.pool).slot_mut(self.idx) }
    }
}

impl<T: Copy + Default> Drop for PoolHandle<T> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: `self.pool` is a valid, process-lifetime pointer constructed
        // in `Pool::alloc`.  `self.idx` is the index previously popped from
        // the free list; returning it here is always correct.
        unsafe { (*self.pool).push_free(self.idx) };
    }
}