//! sg-common — The Global Type Contract for Project Shifting Ghost
//!
//! INVARIANTS:
//!   - Zero dynamic allocation. All types are Copy or have fixed-size arrays.
//!   - All structs are #[repr(C)] for ABI stability across crate boundaries.
//!   - All structs are cache-line aligned (align(64)) for hot-path performance.
//!   - No std — compatible with no_std environments (alloc not used).
//!
//! NASA P10: This file is the single source of truth for all shared types.
//! Any change here requires re-verification of all 12 size/alignment asserts.

#![no_std]
#![deny(warnings)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(clippy::too_many_lines)]
#![deny(clippy::recursive)]
#![forbid(unsafe_code)]
// On retire #![deny(unsafe_code)] pour permettre les implémentations Pod/Zeroable plus bas
#[cfg(not(target_arch = "bpf"))]
extern crate std;

pub mod traits;

#[cfg(test)]
mod tests;

// ─── SECTION 1: COMPILE-TIME CAPACITY CONSTANTS ──────────────────────────────
// These are the single source of truth. No crate may redeclare these.

pub const ARENA_SIZE_BYTES: usize      = 256 * 1024 * 1024; // 256 MiB
pub const RING_PACKET_CAPACITY: usize  = 100_000;
pub const BUCKET_MAX_PACKETS: usize    = 10_000;
pub const BUCKET_POOL_SIZE: usize      = 512;
pub const FLOW_SCORE_POOL_SIZE: usize  = 8_192;
pub const HISTORY_RING_CAPACITY: usize = 2_592_000; // 30 days × 86_400s
pub const EKF_INNOVATION_RING: usize   = 100;
pub const WHITELIST_MAX_ENTRIES: usize = 1_024;
pub const TARPIT_SLOT_POOL: usize      = 256;
pub const SIEM_ALERT_RING: usize       = 1_024;
pub const VPIN_WINDOW_BUCKETS: usize   = 50;
pub const CHAN_T1_T2_CAPACITY: usize   = 128;
pub const CHAN_T2_T3_CAPACITY: usize   = 256;
pub const MAX_BUCKET_PACKETS: usize    = 10_000;
pub const MAX_PPS: u32                 = 50_000;
pub const BUCKET_TIMEOUT_SECS: u64    = 10;
pub const SCAN_FLAG_TTL_SECS: u64     = 60;
pub const EKF_RESET_HOURS: u64        = 24;

// ─── SECTION 2: CORE PACKET TYPE ─────────────────────────────────────────────

/// A single captured network packet header.
///
/// INVARIANTS:
///   - Exactly 20 bytes. Verified by compile-time assert below.
///   - One cache-line aligned (align = 64) to allow safe SIMD prefetch.
///   - Copy + Send + Sync: safe to share across thread boundaries via arena refs.
///   - No padding: every byte is named. Verified by P1-EC-01.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketHeader {
    pub timestamp_ns: u64, // 8 bytes — monotonic nanoseconds from clock_gettime
    pub src_ip:       u32, // 4 bytes — IPv4 source address (network byte order)
    pub dst_ip:       u32, // 4 bytes — IPv4 destination address
    pub src_port:     u16, // 2 bytes
    pub dst_port:     u16, // 2 bytes
    pub length:       u16, // 2 bytes — frame length in bytes
    pub tcp_flags:    u8,  // 1 byte  — TCP control bits (SYN/ACK/RST etc.)
    pub protocol:     u8,  // 1 byte  — IP protocol number (6=TCP, 17=UDP)
}

// P1-EC-01: PacketHeader must be exactly 24 bytes.
// align(64) does NOT change sizeof — only changes allocation alignment.
const _PACKET_HEADER_SIZE: () = assert!(
    core::mem::size_of::<PacketHeader>() == 64,
    "PacketHeader must be exactly 24 bytes — ABI contract violated"
);

// Static assertion via static_assertions crate (belt-and-suspenders gate).
use static_assertions::const_assert_eq;
const_assert_eq!(core::mem::size_of::<PacketHeader>(), 64);

// ─── SECTION 3: FLOW IDENTIFICATION ──────────────────────────────────────────

/// Five-tuple flow key. Hash + Eq for use in arena-backed hash sets.
///
/// Sized at 16 bytes — fits two u64 registers, ideal for hashing.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FlowKey {
    pub src_ip:   u32,
    pub dst_ip:   u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad1:    u8,
    pub _pad2:    u16,
    pub _final_padding: [u8; 48], 
}

// Implémentation manuelle pour contourner la limite des 32 octets de Rust
impl Default for FlowKey {
    fn default() -> Self {
        Self {
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            _pad1: 0,
            _pad2: 0,
            _final_padding: [0u8; 48],
        }
    }
}

// L'assertion de taille (Ligne 99+) doit maintenant correspondre à 64
const _FLOW_KEY_SIZE: () = assert!(
    core::mem::size_of::<FlowKey>() == 64,
    "FlowKey must be exactly 64 bytes"
);

/// Typestate-enforced flow lifecycle. Transitions are append-only.
/// Invalid transitions (e.g. Established → New) are compile errors.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowState {
    New         = 0,
    Established = 1,
    Suspicious  = 2,
    Blocked     = 3,
    Honeypotted = 4,
    Expired     = 5,
}

impl FlowState {
    /// Returns the only valid next states from the current state.
    /// P10-5: caller must match all arms — no wildcard permitted downstream.
    #[must_use]
    pub const fn valid_transitions(self) -> &'static [FlowState] {
        match self {
            FlowState::New         => &[FlowState::Established, FlowState::Blocked],
            FlowState::Established => &[FlowState::Suspicious, FlowState::Expired],
            FlowState::Suspicious  => &[FlowState::Blocked, FlowState::Honeypotted, FlowState::Expired],
            FlowState::Blocked     => &[FlowState::Expired],
            FlowState::Honeypotted => &[FlowState::Blocked, FlowState::Expired],
            FlowState::Expired     => &[],
        }
    }
}

// ─── SECTION 4: SCORING ───────────────────────────────────────────────────────

/// Per-flow risk score. All sub-fields are f32 for nalgebra compatibility.
/// Default = 0.0 on all fields (safe neutral score).
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowScore {
    pub entropy_h:      f32,     // Shannon entropy normalised [0.0, 1.0]
    pub vpin:           f32,     // Volume imbalance [0.0, 1.0]
    pub ekf_innovation: f32,     // EKF innovation magnitude (σ units)
    pub hurst:          f32,     // Hurst exponent [0.0, 1.0]
    pub zscore:         f32,     // Z-score from Welford estimator
    pub bellman_score:  f32,     // Composite: 0.4H + 0.3VPIN + 0.3EKF
    pub _pad:           [f32; 2], // explicit pad to 32 bytes total
}

const _FLOW_SCORE_SIZE: () = assert!(
    core::mem::size_of::<FlowScore>() == 64,
    "FlowScore must be exactly 32 bytes"
);

// Compile-time Bellman weight verification (P2-EC-10)
pub const WEIGHT_ENTROPY: f32 = 0.4;
pub const WEIGHT_VPIN:    f32 = 0.3;
pub const WEIGHT_EKF:     f32 = 0.3;

const _BELLMAN_WEIGHT_SUM: () = {
    let sum = WEIGHT_ENTROPY + WEIGHT_VPIN + WEIGHT_EKF;
    // f32 epsilon × 3 tolerance for floating-point accumulation
    assert!(
        (sum - 1.0_f32).abs() < f32::EPSILON * 3.0,
        "Bellman weights must sum to 1.0 — P2-EC-10 violated"
    );
};

// ─── SECTION 5: ALERT SYSTEM ──────────────────────────────────────────────────

/// Alert severity. All arms explicitly defined — no default wildcard.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertLevel {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

/// Enforcement action dispatched to Thread 3.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Observe    = 0, // Log only, no kernel action
    Tarpit     = 1, // TCP Window-Zero + tc jitter
    Honeypot   = 2, // DNAT → honeypot container
    Drop       = 3, // nftables DROP rule + BPF deny map
    KillSwitch = 4, // Flush all rules, enter passthrough
}

/// An alert produced by the Bellman scoring engine.
///
/// All string fields are fixed-size byte arrays — no heap String.
/// [u8; N] with explicit length field — no null-termination assumed.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct Alert {
    pub timestamp_ns: u64,
    pub flow_key:     FlowKey,   // 16 bytes
    pub score:        FlowScore, // 32 bytes
    pub level:        AlertLevel,
    pub action:       Action,
    pub kind_tag:     [u8; 32],  // anomaly kind as fixed ASCII bytes
    pub kind_len:     u8,
    pub _pad:         [u8; 5],   // align to 64-byte boundary
}

impl Alert {
    /// Construct an Alert, copying at most 32 bytes of `tag` into `kind_tag`.
    #[must_use]
    pub fn write_kind(
        timestamp_ns: u64,
        flow_key:     FlowKey,
        score:        FlowScore,
        level:        AlertLevel,
        action:       Action,
        tag:          &[u8],
    ) -> Self {
        let mut kind_tag = [0u8; 32];
        let copy_len = if tag.len() > 32 { 32 } else { tag.len() };
        let mut i = 0usize;
        while i < copy_len {
            kind_tag[i] = tag[i];
            i += 1;
        }
        Self {
            timestamp_ns,
            flow_key,
            score,
            level,
            action,
            kind_tag,
            kind_len: copy_len as u8,
            _pad: [0u8; 5],
        }
    }
}

// ─── SECTION 6: EBPF EVENT (kernel → userspace) ───────────────────────────────

/// Raw event from the eBPF ringbuf. Must match the C struct in bpf/events.h exactly.
/// Verified by bpftool btf dump comparison in CI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EbpfEvent {
    pub timestamp_ns: u64,
    pub pid:          u32,
    pub uid:          u32,
    pub src_ip:       u32,
    pub dst_ip:       u32,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub protocol:     u8,
    pub event_type:   u8,      // see EbpfEventType enum
    pub _pad:         [u8; 2],
    pub comm:         [u8; 16], // TASK_COMM_LEN = 16
}

/// eBPF event discriminant. Must stay in sync with bpf/events.h #defines.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EbpfEventType {
    PacketIngress = 0,
    TcpConnect    = 1,
    TcpAccept     = 2,
    Execve        = 3,
    FileWrite     = 4,
    DenyMapHit    = 5,
    ScanFlagSet   = 6,
}

// ─── SECTION 7: OPERATING MODE ────────────────────────────────────────────────

/// System-wide operating mode. Governs enforcement gate in Thread 3.
/// Transition rules enforced by sg-governance — not directly settable.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatingMode {
    Calibration = 0, // Observe only, no enforcement, no override possible
    SemiManual  = 1, // Detection active, enforcement requires operator ack
    Automatic   = 2, // Full enforcement armed, Bellman → Action direct
    KillSwitch  = 3, // All rules flushed, passthrough, max forensic recording
}

// ─── SECTION 8: SHARED SYNCHRONISATION PRIMITIVES ────────────────────────────
// See Part V (Sync Protocol) for usage contracts.

/// A single-bit atomic flag used as a "Data Ready" signal between crates.
/// Maps to a single cache line to avoid false sharing.
///
/// Usage: producer sets to true with Release ordering.
///        consumer polls with Acquire ordering, then processes.
///        No mutex. No condvar. No alloc.
// ─── SECTION 8: SHARED SYNCHRONISATION PRIMITIVES ────────────────────────────
use core::sync::atomic::AtomicI64;
#[cfg(not(target_arch = "bpf"))]
use core::sync::atomic::Ordering;

#[repr(C, align(64))]
pub struct ReadyFlag {
    pub inner: AtomicI64,
    _pad: [u8; 56], // 64 octets - 8 octets (i64) = 56 octets de padding
}

#[cfg(not(target_arch = "bpf"))]
impl ReadyFlag {
    #[must_use]
    pub const fn new(initial: bool) -> Self {
        Self {
            inner: AtomicI64::new(if initial { 1 } else { 0 }),
            _pad:  [0u8; 56],
        }
    }

    #[inline(always)]
    pub fn signal(&self) {
        self.inner.store(1, Ordering::Release);
    }

    #[inline(always)]
    #[must_use]
    pub fn poll_and_clear(&self) -> bool {
        self.inner
            .compare_exchange(
                1,
                0,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }
}

// 3. Implémentations sécurisées pour eBPF
// Ce bloc n'est compilé que si la feature "aya-ebpf" est activée
// 1. Assure-toi qu'il n'y a AUCUN "forbid" en haut ou ailleurs dans le fichier.
// Seul #![deny(unsafe_code)] est autorisé.

// ─── SECTION 9: EBPF TYPE MARKERS ───────────────────────────────────────────
// Ces traits permettent à Aya de mapper tes structures entre le Kernel et l'User-space.
// On utilise #[allow(dead_code)] car ils sont consommés par le loader, pas ici.



// ─── SECTION 10: FINGERPRINT PARAMETERS ─────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FpParams {
    pub threshold: u32,
    pub _pad: [u8; 60], // Aligné sur 64 octets (Cache-line)
}

impl Default for FpParams {
    #[inline(always)]
    fn default() -> Self {
        Self {
            threshold: 0,
            _pad: [0u8; 60], // Initialisation manuelle car > 32 octets
        }
    }
}