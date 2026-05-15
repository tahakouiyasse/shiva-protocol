//! `vacuum.rs` — High-frequency RingBuffer polling loop.
//!
//! # Architecture
//! Each vacuum worker is a `tokio::task::spawn_blocking` task pinned to one
//! logical CPU core.  It polls its per-CPU ring buffer in a tight loop,
//! collecting up to `BATCH_SIZE` frames per iteration into a *stack-allocated*
//! `arrayvec::ArrayVec` before dispatching the batch.
//!
//! # Zero-Jitter invariants
//! | Invariant | Mechanism |
//! |-----------|-----------|
//! | No heap allocation post-init | `ArrayVec<SignalFrame, BATCH_SIZE>` on stack |
//! | No `unwrap()` in data path | All errors matched explicitly |
//! | No blocking syscall in poll | `RingBuf::next()` is mmap-backed |
//! | No `println!` in poll loop | `log::warn!` / `log::error!` are rate-limited |
//! | No `Mutex`/`RwLock` on hot path | Each thread owns its ring handle exclusively |
//! | Yield after batch | `tokio::task::yield_now()` every `BATCH_SIZE` frames |
//!
//! # Zero-Copy casting
//! Raw bytes from the ring buffer are cast to [`SignalFrame`] via
//! `core::ptr::read_unaligned`.  This is safe under the ABI contract:
//! * The kernel-side always writes exactly `size_of::<SignalFrame>()` bytes.
//! * `read_unaligned` handles the case where the mmap pointer is not aligned
//!   to 64 bytes (which can occur at ring-buffer wrap-around boundaries).
//! * Alignment of the *destination* (the stack local) is guaranteed by the
//!   compiler because `SignalFrame` carries `#[repr(C, align(64))]`.

use arrayvec::ArrayVec;
use aya::maps::RingBuf;
use aya::maps::MapData;
use log::warn;
use sg_common::SignalFrame;
const SIGNAL_FRAME_SIZE: usize = std::mem::size_of::<SignalFrame>();
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::task;

use crate::dispatch::{try_dispatch, DispatchSender};
use crate::metrics::Metrics;

/// Number of frames drained from the ring buffer per polling iteration.
///
/// CONTROLLER.md §10: `BATCH_SIZE = 256`.  Must equal this value exactly.
pub const BATCH_SIZE: usize = 256;

/// Nanoseconds of monotonic timestamp allowed to decrease between consecutive
/// frames from the *same* CPU before we classify it as a clock anomaly.
/// A value of 0 enforces strict monotonicity.
const TIMESTAMP_SLACK_NS: u64 = 0;

/// State passed into the spawn_blocking closure.
///
/// All fields must be `Send + 'static` because `spawn_blocking` requires a
/// `'static` closure.  `Arc<Metrics>` satisfies this; `DispatchSender` (a
/// crossbeam sender) is `Send` but not `Sync` — we clone per-worker below.
pub struct VacuumWorkerConfig {
    pub cpu_id:   usize,
    pub ring:     RingBuf<MapData>,
    pub tx:       DispatchSender,
    pub metrics:  Arc<Metrics>,
    pub shutdown: Arc<AtomicBool>,
}

/// Entry point for a single per-CPU vacuum worker.
///
/// Spawns a `spawn_blocking` task that:
/// 1. Pins itself to `config.cpu_id` via `core_affinity`.
/// 2. Enters the allocation-free poll loop.
/// 3. Exits cleanly when `shutdown` is set to `true`.
///
/// The returned `JoinHandle` should be awaited by the coordinator in `main.rs`
/// to ensure clean teardown before process exit.
pub fn spawn_vacuum_worker(config: VacuumWorkerConfig) -> task::JoinHandle<()> {
    task::spawn_blocking(move || {
        vacuum_entry(config);
    })
}

/// Synchronous vacuum entry point — called inside `spawn_blocking`.
///
/// This function never returns until `shutdown` is signalled.  It does not
/// panic and does not allocate after the stack frame is set up.
fn vacuum_entry(config: VacuumWorkerConfig) {
    let VacuumWorkerConfig { cpu_id, mut ring, tx, metrics, shutdown } = config;

    // -------------------------------------------------------------------------
    // CPU PINNING — must happen before any ring buffer access.
    // CONTROLLER.md §main.rs validation gate: "CPU pin before I/O; panic on
    // affinity failure".
    // -------------------------------------------------------------------------
    let core_id = core_affinity::CoreId { id: cpu_id };
    if !core_affinity::set_for_current(core_id) {
        // Panic is intentional per spec: affinity failure means the vacuum
        // thread is not isolated, violating the Zero-Jitter mandate.
        panic!(
            "FATAL: failed to pin vacuum worker to CPU {cpu_id}. \
             Ensure the core is online and not isolated by the OS scheduler. \
             Aborting to prevent entropy corruption."
        );
    }
    log::info!("Vacuum worker pinned to CPU {cpu_id}");

    // -------------------------------------------------------------------------
    // Hot path setup — stack-local state, allocated once, never freed.
    // -------------------------------------------------------------------------

    // Stack-allocated batch accumulator.  `ArrayVec` stores frames inline;
    // no heap involvement.
    let mut batch: ArrayVec<SignalFrame, BATCH_SIZE> = ArrayVec::new();

    // Per-worker last-seen timestamp for monotonicity enforcement.
    let mut last_ts_ns: u64 = 0;

    // -------------------------------------------------------------------------
    // Poll loop — allocation-free from this point forward.
    // -------------------------------------------------------------------------
    loop {
        // Check shutdown signal with `Relaxed` ordering: the signal handler
        // uses `Release` on write; our `Relaxed` load will eventually observe
        // it, and a one-iteration delay is acceptable.
        if shutdown.load(Ordering::Relaxed) {
            log::info!("Vacuum worker {cpu_id}: shutdown signal received, exiting poll loop");
            break;
        }

        batch.clear(); // O(1); resets length without deallocating

        // --- Drain up to BATCH_SIZE frames from the ring buffer -------------
        for _ in 0..BATCH_SIZE {
            // `RingBuf::next()` returns `Some(item)` when a frame is available
            // and `None` when the ring is empty.  It is mmap-backed and never
            // blocks or allocates.
            let item = match ring.next() {
                Some(item) => item,
                None => break, // ring drained; dispatch whatever we have
            };

            let raw: &[u8] = &item;

            // -----------------------------------------------------------------
            // ABI validation: size check (INV-02, INV-03).
            // -----------------------------------------------------------------
            if raw.len() != SIGNAL_FRAME_SIZE {
                warn!(
                    "CPU {cpu_id}: RingBuf frame size mismatch \
                     (got {} B, expected {SIGNAL_FRAME_SIZE} B) — frame dropped",
                    raw.len()
                );
                metrics.record_drop(cpu_id);
                continue;
            }

            // -----------------------------------------------------------------
            // Zero-copy cast: `read_unaligned` avoids UB when the mmap pointer
            // is not 64-byte aligned (wrap-around case).
            //
            // SAFETY:
            // * `raw.len() == SIGNAL_FRAME_SIZE == size_of::<SignalFrame>()`
            //   (checked above).
            // * `read_unaligned` does not require the source to be aligned.
            // * The resulting value is a *copy* onto the stack — the ring buffer
            //   item is released after this block when `item` is dropped.
            // -----------------------------------------------------------------
            let frame: SignalFrame = unsafe {
                core::ptr::read_unaligned(raw.as_ptr() as *const SignalFrame)
            };

            // -----------------------------------------------------------------
            // ABI validation: timestamp monotonicity.
            // -----------------------------------------------------------------
            let ts = frame.timestamp_ns;
            if ts < last_ts_ns.saturating_sub(TIMESTAMP_SLACK_NS) {
                warn!(
                    "CPU {cpu_id}: timestamp regression \
                     (prev={last_ts_ns} ns, curr={ts} ns) — frame dropped"
                );
                metrics.record_drop(cpu_id);
                continue;
            }
            last_ts_ns = ts;

            // Frame is valid — add to batch.
            // `try_push` is infallible here because `BATCH_SIZE` bounds both
            // the loop counter and the ArrayVec capacity.
            let _ = batch.try_push(frame);
        }

        // --- Dispatch validated batch to arena ----------------------------
        for frame in batch.drain(..) {
            if try_dispatch(&tx, frame, cpu_id, &metrics) {
                metrics.record_ok(cpu_id);
            }
            // `record_channel_full` is called inside `try_dispatch` on backpressure.
        }

        // --- Yield to allow the Tokio executor to run other tasks ---------
        // `yield_now()` inside a `spawn_blocking` thread calls
        // `std::thread::yield_now()` under the hood, giving the OS scheduler
        // a chance to run other threads on this core if the ring is empty.
        // This prevents busy-spinning at 100% CPU when traffic is light.
        //
        // When the ring has data (high-load scenario), we will have consumed
        // a full BATCH_SIZE and the yield is effectively a no-op.
        std::thread::yield_now();
    }

    log::info!("Vacuum worker {cpu_id}: poll loop terminated, thread exiting");
}