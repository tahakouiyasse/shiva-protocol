//! `sg-capture` — CYBER-SIGNAL userspace vacuum engine.
//!
//! # Startup sequence
//! 1. Parse CLI arguments (interface name, optional worker count).
//! 2. Initialise `env_logger` for userspace telemetry.
//! 3. Call [`loader::load_and_attach`] to load `sg-ebpf` and attach XDP.
//!    Returns `(LoadedProbe, Vec<Option<RingBuf<MapData>>>)`.
//! 4. Iterate over ring handles; for each populated slot:
//!    a. Create a bounded `dispatch_channel` pair.
//!    b. Spawn a no-op arena consumer thread to drain the receiver end,
//!       preventing back-pressure from capping throughput in the absence of
//!       a live `sg-arena` instance.
//!    c. Spawn a [`VacuumWorkerConfig`] via [`spawn_vacuum_worker`].
//! 5. `anyhow::bail!` if no workers were spawned — prevents silent idle.
//! 6. Spawn the metrics reporter thread.
//! 7. Install SIGINT / SIGTERM handlers via Tokio.
//! 8. Await signal; set `shutdown = true` and join all vacuum workers.
//! 9. Call [`loader::detach`] to cleanly remove the XDP hook.
//!
//! # CONTROLLER.md compliance
//! * `tokio::task::spawn_blocking` is used for every vacuum worker (§Mandate §1).
//! * CPU affinity is set *inside* the blocking task, before any ring I/O
//!   (§main.rs validation gate).
//! * `panic!` on affinity failure (§3.6 gate: "panic on affinity failure").
//! * One worker per populated CPU ring, up to `worker_count` (§1.2).
//! * No `unwrap()` outside of truly-fatal init paths.
//!
//! # Fix applied (Audit REJECT → GREEN_LIT path)
//! The previous revision contained an unconditional `continue` in both arms of
//! the worker-spawn `match`, leaving `join_handles` permanently empty and
//! spawning zero vacuum workers.  This revision replaces that loop with a clean
//! `into_iter().enumerate()` over the owned handle `Vec` returned by the loader,
//! eliminating the borrow-checker conflict that motivated the broken stub.

use std::env;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::{Context, Result};
use log::info;
use sg_common::NCPU;
use tokio::signal::unix::{signal, SignalKind};

mod dispatch;
mod loader;
mod metrics;
mod percpu_ring;
mod vacuum;

use dispatch::dispatch_channel;
use loader::{detach, load_and_attach};
use metrics::{spawn_reporter, Metrics};
use vacuum::{spawn_vacuum_worker, VacuumWorkerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // -------------------------------------------------------------------------
    // Logging initialisation — must be first so that loader and aya-log have a
    // working sink from the very first message.
    // -------------------------------------------------------------------------
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // -------------------------------------------------------------------------
    // CLI: parse network interface name from first argument.
    // -------------------------------------------------------------------------
    let iface = env::args()
        .nth(1)
        .context("Usage: sg-capture <interface> [optional-worker-count]")?;

    // Optional: override the number of vacuum workers (useful for testing on
    // machines with fewer than NCPU cores).  Defaults to NCPU.
    let worker_count: usize = env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(NCPU)
        .min(NCPU);

    info!(
        "sg-capture starting | interface={iface} | workers={worker_count} | NCPU={NCPU}"
    );

    // -------------------------------------------------------------------------
    // Load eBPF object, attach XDP hook, and obtain owned ring handles.
    //
    // `ring_handles` is `Vec<Option<RingBuf<MapData>>>` of length NCPU.
    // Each populated slot holds the exclusively-owned handle for that CPU's
    // ring buffer.  Consuming it here (`.into_iter()`) transfers ownership
    // into each vacuum worker without any borrow-checker conflict.
    // -------------------------------------------------------------------------
    let (probe, ring_handles) = load_and_attach(&iface)
        .with_context(|| format!("failed to load and attach eBPF probe on `{iface}`"))?;

    info!(
        "eBPF probe live | {}/{} CPU rings populated",
        ring_handles.iter().filter(|h| h.is_some()).count(),
        NCPU,
    );

    // -------------------------------------------------------------------------
    // Shared state: metrics + shutdown flag.
    // -------------------------------------------------------------------------
    let metrics  = Arc::new(Metrics::new());
    let shutdown = Arc::new(AtomicBool::new(false));

    // -------------------------------------------------------------------------
    // Metrics reporter watch channel.
    // Sending `true` signals the reporter to exit its loop cleanly.
    // -------------------------------------------------------------------------
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // -------------------------------------------------------------------------
    // Spawn vacuum workers — one per populated CPU ring.
    //
    // For each populated ring handle:
    //   1. Create a bounded dispatch channel pair.
    //   2. Spawn a no-op arena consumer std::thread to drain the receiver end.
    //      This prevents back-pressure from stalling the vacuum loop in the
    //      absence of a live sg-arena instance.  In a full integration, `rx`
    //      would be handed to the corresponding arena shard instead.
    //   3. Construct VacuumWorkerConfig and spawn the blocking vacuum task.
    // -------------------------------------------------------------------------
    let mut join_handles = Vec::with_capacity(worker_count);

    for (cpu_id, ring_opt) in ring_handles
        .into_iter()
        .enumerate()
        .take(worker_count)
    {
        // Skip absent (offline / sparse topology) CPU slots.
        let ring = match ring_opt {
            Some(r) => r,
            None => {
                log::info!("CPU {cpu_id}: no ring buffer handle — skipping worker");
                continue;
            }
        };

        // Create a bounded dispatch channel for this CPU's pipeline segment.
        // The sender moves into the vacuum worker; the receiver moves into the
        // no-op consumer below.
        let (tx, rx) = dispatch_channel();

        // No-op arena consumer — drains frames to prevent channel back-pressure
        // from artificially throttling the vacuum loop.  Named for diagnostics.
        //
        // In a production deployment this thread is replaced by the sg-arena
        // shard for this CPU, which receives `rx` via the integration hand-off.
        std::thread::Builder::new()
            .name(format!("arena-consumer-{cpu_id}"))
            .spawn(move || {
                // Drain until the sender (vacuum worker) hangs up on shutdown.
                // `recv()` returns `Err` when all senders are dropped, which
                // happens when the vacuum worker exits its poll loop.
                while rx.recv().is_ok() {
                    // Intentional no-op.  A real arena shard would process the
                    // SignalFrame here (entropy scoring, event emission, etc.).
                }
                log::debug!("arena-consumer-{cpu_id}: receiver drained, thread exiting");
            })
            .with_context(|| {
                format!("failed to spawn arena consumer thread for CPU {cpu_id}")
            })?;

        // Construct the vacuum worker configuration and spawn the blocking task.
        join_handles.push(spawn_vacuum_worker(VacuumWorkerConfig {
            cpu_id,
            ring,
            tx,
            metrics:  Arc::clone(&metrics),
            shutdown: Arc::clone(&shutdown),
        }));

        log::info!("Vacuum worker spawned for CPU {cpu_id}");
    }

    // -------------------------------------------------------------------------
    // Safety check: bail immediately if no workers were spawned.
    //
    // This can happen when all NCPU ring slots are None (e.g. the eBPF object
    // was compiled for a different CPU topology, or `worker_count` was 0).
    // Proceeding with an empty join_handles would cause sg-capture to silently
    // idle — accepting the XDP hook cost but capturing nothing.
    // -------------------------------------------------------------------------
    if join_handles.is_empty() {
        // Detach the XDP hook before bailing so we don't leave the interface
        // dirty on an error exit.
        if let Err(e) = detach(probe) {
            log::error!(
                "XDP detach during error-exit failed: {e:?}; \
                 run `ip link set {iface} xdp off` manually"
            );
        }
        anyhow::bail!(
            "No vacuum workers were spawned: all {worker_count} requested CPU \
             ring slot(s) are absent in the eBPF object.  Verify the eBPF map \
             names (`SIGNAL_RING_{{cpu_id}}`) and the CPU topology on this host."
        );
    }

    info!(
        "Vacuum workers active: {}/{} CPUs",
        join_handles.len(),
        worker_count,
    );

    // -------------------------------------------------------------------------
    // Metrics reporter — a single `std::thread`, not a Tokio task.
    // Spawned after the worker count safety check to avoid starting the reporter
    // on a path that bails before any capture occurs.
    // -------------------------------------------------------------------------
    spawn_reporter(Arc::clone(&metrics), shutdown_rx);

    // -------------------------------------------------------------------------
    // Signal handling — SIGINT and SIGTERM trigger graceful shutdown.
    // -------------------------------------------------------------------------
    let mut sigint  = signal(SignalKind::interrupt())
        .context("failed to install SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;

    tokio::select! {
        _ = sigint.recv()  => { info!("SIGINT received — initiating graceful shutdown"); }
        _ = sigterm.recv() => { info!("SIGTERM received — initiating graceful shutdown"); }
    }

    // -------------------------------------------------------------------------
    // Shutdown sequence.
    // -------------------------------------------------------------------------

    // 1. Signal vacuum workers to stop.  Release ordering ensures that the
    //    store is visible to all vacuum threads before they next check the flag.
    shutdown.store(true, Ordering::Release);

    // 2. Signal metrics reporter to stop.
    //    Ignore send errors: the reporter may have already exited.
    let _ = shutdown_tx.send(true);

    // 3. Await all vacuum workers.
    for handle in join_handles {
        if let Err(e) = handle.await {
            log::error!("Vacuum worker panicked during shutdown: {e:?}");
        }
    }
    info!("All vacuum workers joined");

    // 4. Detach XDP hook — restores interface to its original (unhooked) state.
    detach(probe)
        .with_context(|| {
            format!(
                "XDP detach on `{iface}` failed; \
                 run `ip link set {iface} xdp off` manually"
            )
        })?;

    info!("sg-capture shutdown complete");
    Ok(())
}