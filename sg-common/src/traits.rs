//! sg-common/src/traits.rs
//!
//! Contractual interfaces for the three Nuclear Pillar crates.
//! All traits are defined here and imported by implementing crates.
//! No allocations. No std. Zero dynamic dispatch in hot path.

use crate::{Alert, EbpfEvent, FlowKey, FlowScore, PacketHeader};

// ─── EbpfSource ───────────────────────────────────────────────────────────────

/// Maximum events drained per call — P10-2 bound.
pub const MAX_DRAIN_EVENTS: usize = 1_024;

/// TRAIT: EbpfSource
/// Implemented by: sg-ebpf (loader + correlator)
///
/// Contract: Provides a zero-copy view into the eBPF ringbuf.
/// The implementation owns the ringbuf memory (mmap'd from kernel).
/// Callers receive a &EbpfEvent slice — no data is moved.
///
/// P10-2: `drain_events` must process at most MAX_DRAIN_EVENTS per call.
/// P10-5: All errors must be returned, never silently dropped.
pub trait EbpfSource {
    type Error;

    /// Returns a fixed-size batch of available events.
    /// Non-blocking: returns &[] if no events are pending.
    /// MUST NOT allocate. MUST NOT block.
    #[must_use]
    fn drain_events<'a>(
        &'a self,
        out: &'a mut [EbpfEvent; MAX_DRAIN_EVENTS],
    ) -> Result<&'a [EbpfEvent], Self::Error>;

    /// Returns the cumulative count of events dropped by the kernel ringbuf.
    /// Monitored by P5-OT-04: must stay below 0.1% of total events.
    #[must_use]
    fn ringbuf_drop_count(&self) -> u64;

    /// Writes a source IP to the BPF deny map (for flood.rs auto-block).
    /// Idempotent. Error must be logged by caller; never panic.
    fn write_deny_map(&self, src_ip: u32) -> Result<(), Self::Error>;

    /// Writes fingerprint spoof params for a SCAN-flagged flow.
    fn write_fingerprint_map(&self, key: FlowKey) -> Result<(), Self::Error>;
}

// ─── ArenaAllocator ───────────────────────────────────────────────────────────

/// TRAIT: ArenaAllocator
/// Implemented by: sg-arena
///
/// Contract: Linear bump allocator over a 256 MiB static buffer.
/// After `lock()` is called (Arena transitions to ArenaLocked),
/// alloc_slice becomes permanently unavailable — enforced at type level.
/// All methods that allocate are only on ArenaInit (pre-lock type).
pub trait ArenaAllocator {
    type Error;

    /// Allocate a contiguous slice of `n` elements of type `T` from the arena.
    /// Returns a `&'static mut [T]` — lifetime is the process lifetime.
    /// O(1). Fails if remaining arena space is insufficient.
    ///
    /// # Safety contract (for sg-arena's one permitted unsafe block)
    /// - `T` must be `Copy` (no Drop).
    /// - Returned slice is exclusively owned by the caller.
    /// - No two calls may return overlapping regions (guaranteed by bump pointer).
    fn alloc_slice<T: Copy>(&mut self, n: usize) -> Result<&'static mut [T], Self::Error>;

    /// Returns remaining free bytes in the arena.
    #[must_use]
    fn remaining_bytes(&self) -> usize;

    /// Returns total allocated bytes since init.
    #[must_use]
    fn allocated_bytes(&self) -> usize;
}

// ─── PacketRing ───────────────────────────────────────────────────────────────

/// TRAIT: PacketRing
/// Implemented by: sg-arena::ring (the SPSC ring buffer)
///
/// Contract: Single-Producer Single-Consumer lock-free ring.
/// Push is called by Thread 1 (capture). Pop is called by Thread 2 (analysis).
/// Overwrite-on-full semantics — oldest packet is silently dropped.
/// All operations are O(1), no loops, no allocation.
pub trait PacketRing {
    /// Push a packet header into the ring. Returns false if overwrite occurred.
    /// Thread 1 only. Non-blocking.
    #[must_use]
    fn push(&self, pkt: PacketHeader) -> bool;

    /// Pop the oldest packet. Returns None if ring is empty.
    /// Thread 2 only. Non-blocking.
    #[must_use]
    fn pop(&self) -> Option<PacketHeader>;

    /// Returns the number of items currently in the ring.
    #[must_use]
    fn len(&self) -> usize;

    /// Returns true if the ring is empty.
    #[must_use]
    fn is_empty(&self) -> bool;
}

// ─── ScoringPipeline ─────────────────────────────────────────────────────────

/// TRAIT: ScoringPipeline
/// Implemented by: sg-bellman (Phase 2, but interface defined now)
///
/// Contract: Accepts a batch of scored sub-results, emits an Alert or None.
/// Zero allocation. Must complete within 5ms budget (T2 latency contract).
pub trait ScoringPipeline {
    type Error;

    /// Compute the Bellman composite score from sub-scores.
    /// Returns Some(Alert) if score exceeds threshold, None otherwise.
    /// Missing sub-score → substitute baseline mean (never NaN-propagate).
    #[must_use]
    fn score(&self, flow: FlowKey, sub: FlowScore) -> Result<Option<Alert>, Self::Error>;
}

// ─── EntropyScanner ──────────────────────────────────────────────────────────

/// TRAIT: EntropyScanner
/// Implemented by: sg-entropy (Phase 2)
///
/// Contract: Computes Shannon entropy over a bounded packet window.
/// Input is always a borrowed slice from arena memory — no copies.
/// Output is a normalised f32 in [0.0, 1.0].
/// All operations O(n) with bounded n — no recursion (P10-7).
pub trait EntropyScanner {
    type Error;

    /// Compute normalised Shannon entropy H(X) over the packet byte distribution.
    /// `window` is a slice of at most BUCKET_MAX_PACKETS headers.
    /// Returns Err if window is empty.
    #[must_use]
    fn scan(&self, window: &[PacketHeader]) -> Result<f32, Self::Error>;
}

// ─── MemoryProvider ──────────────────────────────────────────────────────────

/// TRAIT: MemoryProvider
/// Implemented by: sg-arena (post-lock stat queries)
///
/// Contract: Read-only view into arena memory statistics.
/// Available after Arena::lock() returns ArenaLocked.
/// No mutation, no allocation, no panic.
pub trait MemoryProvider {
    /// Total arena capacity in bytes (always ARENA_SIZE_BYTES).
    #[must_use]
    fn capacity(&self) -> usize;

    /// Bytes consumed by completed allocations.
    #[must_use]
    fn used(&self) -> usize;

    /// Bytes available for future allocations (always 0 after lock in hot path).
    #[must_use]
    fn free(&self) -> usize;
}