//! `dispatch.rs` — Bridge from the vacuum layer to `sg-arena`.
//!
//! # Role in the pipeline
//! The vacuum thread produces validated [`SignalFrame`]s at line rate.  The
//! arena consumer (entropy engine) processes them in a separate thread.  This
//! module defines the channel types and the helper that sends a frame without
//! blocking the vacuum loop.
//!
//! # Channel choice: crossbeam bounded
//! `crossbeam_channel::bounded` is used instead of `tokio::sync::mpsc` for
//! the following reasons:
//!
//! * The vacuum thread runs inside `spawn_blocking` and must not `.await`.
//!   A `tokio::sync::mpsc::Sender::send` is async; its blocking sibling
//!   `blocking_send` can park the thread, introducing the very jitter we
//!   are engineered to eliminate.
//! * `crossbeam::Sender::try_send` is lock-free and wait-free on the fast
//!   path (ring buffer has space) — it never blocks, never parks, never
//!   allocates.  On backpressure, it returns `Err(TrySendError::Full)` which
//!   the vacuum loop handles by incrementing the `channel_full` metric and
//!   dropping the frame — consistent with INV-01's zero-allocation mandate.
//!
//! # Capacity
//! `DISPATCH_CAPACITY` is sized to absorb a burst of 4× `BATCH_SIZE` frames
//! before the arena consumer must keep up.  At 100 Mpps across 32 CPUs, each
//! CPU sends ~3.125 Mpps; a 1024-frame buffer absorbs ~327 µs of burst.

use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use sg_common::SignalFrame;

use crate::metrics::Metrics;
use crate::vacuum::BATCH_SIZE;

/// Dispatch channel capacity in frames.
///
/// Must be a power of two (crossbeam enforces this for its ring-buffer back-end).
/// 4 × BATCH_SIZE × number-of-CPUs-per-channel = 4 × 256 = 1024.
pub const DISPATCH_CAPACITY: usize = BATCH_SIZE * 4;

/// Type alias for the producer end — held by the vacuum thread.
pub type DispatchSender = Sender<SignalFrame>;

/// Type alias for the consumer end — held by the arena worker.
pub type DispatchReceiver = Receiver<SignalFrame>;

/// Create a matched `(DispatchSender, DispatchReceiver)` pair.
///
/// Called once during init.  After this the sender is moved into the vacuum
/// thread and the receiver into the arena worker; no further allocation occurs.
pub fn dispatch_channel() -> (DispatchSender, DispatchReceiver) {
    bounded(DISPATCH_CAPACITY)
}

/// Attempt to send a frame to the arena; record metrics on backpressure.
///
/// This is the **only** function that may be called on the hot vacuum path for
/// dispatch.  It is:
/// * **Allocation-free** — `try_send` does not allocate.
/// * **Non-blocking** — returns immediately on `Full`.
/// * **Panic-free** — `Disconnected` means the arena died; we log and continue
///   so that the vacuum loop can be shut down cleanly by the signal handler.
///
/// # Returns
/// `true` if the frame was dispatched, `false` if it was dropped (either due
/// to a full channel or a disconnected receiver).
#[inline(always)]
pub fn try_dispatch(
    tx:      &DispatchSender,
    frame:   SignalFrame,
    cpu_id:  usize,
    metrics: &Metrics,
) -> bool {
    match tx.try_send(frame) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            // Backpressure: the arena consumer is lagging.  Drop this frame and
            // record the event.  The vacuum loop never stalls.
            metrics.record_channel_full(cpu_id);
            false
        }
        Err(TrySendError::Disconnected(_)) => {
            // The arena worker has exited (likely due to shutdown).  We do not
            // log here because this can fire thousands of times per second in
            // the shutdown window — logging would itself become a perf hazard.
            // The shutdown handler will stop the vacuum loop shortly.
            false
        }
    }
}