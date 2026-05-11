//! sg-ebpf/src/caps.rs
//!
//! Linux capability verification — P1-EC-09 compliance.
//!
//! The eBPF loader requires two capabilities:
//!   * `CAP_BPF`       — load and manage eBPF programs and maps (kernel 5.8+)
//!   * `CAP_NET_ADMIN` — attach XDP programs to network interfaces
//!
//! `verify_capabilities()` is the **first** function called by `EbpfLoader::load()`.
//! Any missing capability returns a typed `Err` immediately — no attempt is made
//! to load eBPF objects without the required privileges.
//!
//! P10-5: all error conditions are returned, never panicked.
//! P10-8: no unsafe code.

use std::io;
use thiserror::Error;

/// Errors produced by capability verification.
///
/// Each variant maps to a single, actionable operator remediation step.
#[derive(Debug, Error)]
pub enum CapabilityError {
    /// The process lacks `CAP_BPF`.
    ///
    /// Remediation: run with `sudo` or grant the binary `CAP_BPF` via
    /// `setcap cap_bpf+ep /path/to/binary`.
    #[error(
        "missing CAP_BPF — run as root or: setcap cap_bpf+ep <binary>  \
         (see `man 7 capabilities`)"
    )]
    MissingCapBpf,

    /// The process lacks `CAP_NET_ADMIN`.
    ///
    /// Remediation: grant `CAP_NET_ADMIN` or run with `sudo`.
    #[error(
        "missing CAP_NET_ADMIN — XDP attachment requires this capability  \
         (see `man 7 capabilities`)"
    )]
    MissingCapNetAdmin,

    /// The OS capability check itself failed (e.g. unsupported kernel).
    #[error("capability check failed: {0}")]
    CheckFailed(#[from] io::Error),
}

/// Verify all capabilities required by the eBPF loader before any load attempt.
///
/// Checks are performed in dependency order:
///   1. `CAP_BPF`       — required for program/map operations.
///   2. `CAP_NET_ADMIN` — required for XDP attachment.
///
/// Returns `Ok(())` only when **both** capabilities are present.
/// Returns `Err` on the **first** missing or unverifiable capability.
///
/// This function is O(1) and does not allocate.
///
/// # Errors
///
/// * `CapabilityError::MissingCapBpf`       — process does not hold `CAP_BPF`.
/// * `CapabilityError::MissingCapNetAdmin`  — process does not hold `CAP_NET_ADMIN`.
/// * `CapabilityError::CheckFailed(e)`      — the capability check syscall failed.
pub fn verify_capabilities() -> Result<(), CapabilityError> {
    use caps::{CapSet, Capability};

    // ── CAP_BPF ──────────────────────────────────────────────────────────────
    // `caps::has_cap` returns `Err` if the kernel does not support the
    // capability API (extremely old kernels); we map that to `CheckFailed`.
    let has_bpf = caps::has_cap(None, CapSet::Effective, Capability::CAP_BPF)
        .map_err(|e| CapabilityError::CheckFailed(io::Error::new(io::ErrorKind::Other, e)))?;

    if !has_bpf {
        return Err(CapabilityError::MissingCapBpf);
    }

    // ── CAP_NET_ADMIN ─────────────────────────────────────────────────────────
    let has_net_admin =
        caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_ADMIN)
            .map_err(|e| CapabilityError::CheckFailed(io::Error::new(io::ErrorKind::Other, e)))?;

    if !has_net_admin {
        return Err(CapabilityError::MissingCapNetAdmin);
    }

    Ok(())
}

// ─── Testable shim ───────────────────────────────────────────────────────────
//
// Unit tests cannot grant capabilities to themselves.  We expose a thin
// injectable version so tests can simulate any capability state.

/// A capability checker injectable for testing.
///
/// In production code, use `verify_capabilities()` directly.
/// In tests, use `verify_with_checker(mock_fn)` to simulate absent caps.
pub fn verify_with_checker<F>(checker: F) -> Result<(), CapabilityError>
where
    F: Fn() -> Result<(bool, bool), std::io::Error>,
{
    let (has_bpf, has_net_admin) =
        checker().map_err(CapabilityError::CheckFailed)?;

    if !has_bpf {
        return Err(CapabilityError::MissingCapBpf);
    }
    if !has_net_admin {
        return Err(CapabilityError::MissingCapNetAdmin);
    }
    Ok(())
}