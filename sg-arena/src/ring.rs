//! SPSC ring buffer backed by arena-allocated storage.
//!
//! `RingBuffer` wraps a `&'static mut [PacketHeader]` carved from the arena
//! and provides O(1), allocation-free push/pop with overwrite-on-full semantics.
//!
//! Thread safety:
//!   - `push` must only be called from Thread 1 (the producer).
//!   - `pop`  must only be called from Thread 2 (the consumer).
//!   - `head` is owned by the consumer; `tail` is owned by the producer.
//!   - Atomic orderings: Release on write, Acquire on read — establishes
//!     happens-before between producer writes and consumer reads.

use core::sync::atomic::{AtomicUsize, Ordering};
use sg_common::{traits::PacketRing, PacketHeader};

/// SPSC ring buffer over an arena-allocated `PacketHeader` slice.
///
/// `cap` is the length of the backing slice.  The usable capacity is `cap - 1`
/// because one slot is sacrificed to distinguish "full" from "empty".
pub struct RingBuffer {
    data: *mut PacketHeader,
    head: AtomicUsize, // written by consumer
    tail: AtomicUsize, // written by producer
    cap:  usize,
}

// SAFETY: `data` is a pointer into ARENA_BACKING — a process-lifetime static.
// SPSC discipline (T1 pushes, T2 pops) is enforced by the calling convention
// documented in Part V of the Orchestration Document.  The atomics provide
// the necessary happens-before guarantees for cross-thread visibility.
unsafe impl Send for RingBuffer {}
unsafe impl Sync for RingBuffer {}

impl RingBuffer {
    /// Construct a new `RingBuffer` from an arena-allocated slice.
    ///
    /// The slice must have been obtained from `ArenaInit::alloc_slice`.
    
    pub fn new(backing: &'static mut [PacketHeader]) -> Self {
        let cap = backing.len();
        let ptr = backing.as_mut_ptr();
        Self {
            data: ptr,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            cap,
        }
    }
}

impl PacketRing for RingBuffer {
    /// Push a `PacketHeader` into the ring.
    ///
    /// If the ring is full, the oldest entry is overwritten (the head advances).
    /// Returns `true` if no overwrite occurred, `false` if an entry was dropped.
    ///
    /// O(1). No loops. No allocation.
    
    #[inline]
    fn push(&self, pkt: PacketHeader) -> bool {
        let tail    = self.tail.load(Ordering::Relaxed);
        let next    = (tail + 1) % self.cap;
        let head    = self.head.load(Ordering::Acquire);
        let overwrite = next == head;

        if overwrite {
            // Advance head to drop the oldest entry.
            let new_head = (head + 1) % self.cap;
            self.head.store(new_head, Ordering::Release);
        }

        // SAFETY: `tail < cap` (invariant maintained by the modulo), and
        // `data` is a valid, aligned pointer to `cap` elements.  We have
        // exclusive write access to `data[tail]` because only the producer
        // advances `tail`, and the consumer only reads slots behind `head`.
        unsafe { self.data.add(tail).write(pkt) };
        self.tail.store(next, Ordering::Release);

        !overwrite
    }

    /// Pop the oldest `PacketHeader` from the ring.
    ///
    /// Returns `None` if the ring is empty.  O(1). No loops. No allocation.
    
    #[inline]
    fn pop(&self) -> Option<PacketHeader> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        if head == tail {
            return None;
        }

        // SAFETY: `head < cap` (invariant maintained by the modulo), and
        // `data` is a valid pointer.  The slot at `head` was written by the
        // producer before `tail` was advanced with Release ordering, which
        // this Acquire load observes.
        let pkt = unsafe { self.data.add(head).read() };
        let next_head = (head + 1) % self.cap;
        self.head.store(next_head, Ordering::Release);

        Some(pkt)
    }

    /// Returns the number of items currently in the ring.
    
    #[inline]
    fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if tail >= head {
            tail - head
        } else {
            self.cap - head + tail
        }
    }

    /// Returns `true` if the ring is empty.
    
    #[inline]
    fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head == tail
    }
}