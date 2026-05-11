//! sg-ebpf/src/loader.rs
//!
//! eBPF object loader, XDP probe attachment, and `EbpfSource` implementation.
//!
//! # Boot sequence
//!
//! ```text
//! EbpfLoader::load()
//!   ├─ 1. verify_capabilities()   → hard fail: CAP_BPF or CAP_NET_ADMIN absent
//!   ├─ 2. load .bpf.o objects     → per-probe: warn + Degraded on failure
//!   ├─ 3. open ringbuf            → hard fail
//!   ├─ 4. extract BPF map refs    → hard fail if DENY_MAP absent
//!   └─ 5. signal ReadyFlag        → data path is live
//! ```
//!
//! # Key design decisions
//!
//! **`take_map()` not `map_mut()`:** `map_mut` returns `&mut MapData` (borrowed).
//! `take_map` moves `MapData` out of the `Ebpf` handle (owned), producing the
//! `HashMap<MapData, K, V>` type that `BpfMaps` requires.
//!
//! **No `LruHashMap` in aya 0.13:** LRU is a kernel-side attribute.
//! The userspace API is `HashMap<MapData, K, V>` for all map types.
//!
//! **Zero `unsafe`:** `EbpfEvent` bytes are deserialised field-by-field via
//! `from_ne_bytes`. No raw pointer casts anywhere in this file.
//!
//! # P10 compliance
//!
//! * P10-2  `drain_events` bounded by `MAX_DRAIN_EVENTS` per call.
//! * P10-5  All errors returned; zero panics.
//! * P10-7  No recursion.
//! * P10-8  No `unsafe` in this file.

use std::io;

use aya::{
    maps::{HashMap, RingBuf},
    programs::{Program, TracePoint, Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use log::{info, warn};
use thiserror::Error;

use sg_common::{
    traits::{EbpfSource, MAX_DRAIN_EVENTS},
    EbpfEvent, FlowKey, ReadyFlag,
};

use crate::{
    caps::{verify_capabilities, CapabilityError},
    map::{BpfMaps, FpParams, MapError},
};

// ─── Embedded eBPF object bytes ──────────────────────────────────────────────
//
// When .bpf.o files are absent (dev machine, pre-build), build.rs sets
// `sg_ebpf_objects_missing` and we substitute empty slices.
// `cargo check` succeeds; `EbpfLoader::load()` will return `PrimaryLoadFailed`
// at runtime, which is the correct behaviour.

#[cfg(not(sg_ebpf_objects_missing))]
static PACKET_INGRESS_OBJ: &[u8] = aya::include_bytes_aligned!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/packet_ingress.bpf.o")
);
#[cfg(sg_ebpf_objects_missing)]
static PACKET_INGRESS_OBJ: &[u8] = &[];

#[cfg(not(sg_ebpf_objects_missing))]
static EXECVE_MONITOR_OBJ: &[u8] = aya::include_bytes_aligned!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/execve_monitor.bpf.o")
);
#[cfg(sg_ebpf_objects_missing)]
static EXECVE_MONITOR_OBJ: &[u8] = &[];

#[cfg(not(sg_ebpf_objects_missing))]
static TCP_FP_PROBE_OBJ: &[u8] = aya::include_bytes_aligned!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/tcp_fp_probe.bpf.o")
);
#[cfg(sg_ebpf_objects_missing)]
static TCP_FP_PROBE_OBJ: &[u8] = &[];

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_IFACE:   &str  = "lo";
const EBPF_EVENT_SIZE: usize = core::mem::size_of::<EbpfEvent>();

// ─── LoadError ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("capability check failed: {0}")]
    Capabilities(#[from] CapabilityError),

    #[error("all eBPF probes failed to attach — no data path available")]
    AllProbesFailed,

    #[error("primary eBPF object load failed: {0}")]
    PrimaryLoadFailed(String),

    #[error("failed to open eBPF ringbuf: {0}")]
    RingbufFailed(String),

    #[error("required BPF map error: {0}")]
    MapSetup(#[from] MapError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

// ─── ProbeStatus ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    Attached,
    Degraded,
}

#[derive(Debug)]
pub struct ProbeStatusMap {
    pub packet_ingress: ProbeStatus,
    pub execve_monitor: ProbeStatus,
    pub tcp_fp_probe:   ProbeStatus,
}

impl ProbeStatusMap {
    #[must_use]
    pub fn any_attached(&self) -> bool {
        self.packet_ingress == ProbeStatus::Attached
            || self.execve_monitor == ProbeStatus::Attached
            || self.tcp_fp_probe   == ProbeStatus::Attached
    }
}

// ─── EbpfLoader ──────────────────────────────────────────────────────────────

pub struct EbpfLoader {
    /// Must stay alive — dropping unloads all kernel programs.
    _ebpf_primary:  Ebpf,
    _ebpf_execve:   Option<Ebpf>,
    _ebpf_fp_probe: Option<Ebpf>,
    ringbuf:        RingBuf<aya::maps::MapData>,
    pub maps:       BpfMaps,
    ringbuf_drops:  u64,
    pub probe_status: ProbeStatusMap,
}

impl EbpfLoader {
    /// Load all eBPF probes and open the ringbuf data path.
    ///
    /// # Errors
    ///
    /// Hard: `Capabilities`, `PrimaryLoadFailed`, `RingbufFailed`, `MapSetup`.
    /// Soft (per-probe): logged as `warn!`, `ProbeStatus::Degraded`.
    pub fn load(iface: &str, ready_flag: &ReadyFlag) -> Result<Self, LoadError> {
        // ── 1. Capability gate ────────────────────────────────────────────────
        verify_capabilities()?;
        info!("sg-ebpf: capabilities verified (CAP_BPF + CAP_NET_ADMIN)");

        // ── 2. Probe attachment ───────────────────────────────────────────────
        let mut ebpf_primary = Ebpf::load(PACKET_INGRESS_OBJ)
            .map_err(|e| LoadError::PrimaryLoadFailed(format!("{e}")))?;

        // The XDP program is identified by its ELF section name ("xdp"),
        // not by the Rust function name ("packet_ingress").
        let ingress_status = Self::attach_xdp(&mut ebpf_primary, "packet_ingress", iface);

        if let Err(e) = EbpfLogger::init(&mut ebpf_primary) {
            warn!("sg-ebpf: eBPF logger init (non-fatal): {e}");
        }

        let (ebpf_execve, execve_status) = Self::load_and_attach_tracepoint(
            EXECVE_MONITOR_OBJ, "tracepoint/syscalls/execve_monitor", "syscalls", "sys_enter_execve",
        );

        // tcp_fp_probe is inert in Phase 1 — skip attachment to avoid
        // XDP conflict when packet_ingress is already on the same interface.
        // Phase 3 (sg-fingerprint) will arm and attach this probe.
        let ebpf_fp: Option<Ebpf> = None;
        let fp_status = ProbeStatus::Degraded;

        let probe_status = ProbeStatusMap {
            packet_ingress: ingress_status,
            execve_monitor: execve_status,
            tcp_fp_probe:   fp_status,
        };

        if !probe_status.any_attached() {
            return Err(LoadError::AllProbesFailed);
        }

        // ── 3. Open ringbuf ───────────────────────────────────────────────────
        let ringbuf = {
            let map_data = ebpf_primary
                .take_map("PACKET_EVENTS")
                .ok_or_else(|| LoadError::RingbufFailed(
                    "map 'PACKET_EVENTS' not found in packet_ingress object".to_owned(),
                ))?;
            RingBuf::try_from(map_data)
                .map_err(|e| LoadError::RingbufFailed(format!("{e}")))?
        };
        info!("sg-ebpf: ringbuf 'PACKET_EVENTS' opened");

        // ── 4. Typed map references ───────────────────────────────────────────
        let deny_map = {
            let d = ebpf_primary.take_map("DENY_MAP")
                .ok_or(MapError::NotFound { name: "DENY_MAP" })?;
            HashMap::try_from(d).map_err(MapError::Operation)?
        };

        let scan_flag_map = {
            let d = ebpf_primary.take_map("SCAN_FLAG_MAP")
                .ok_or(MapError::NotFound { name: "SCAN_FLAG_MAP" })?;
            HashMap::try_from(d).map_err(MapError::Operation)?
        };

        let fingerprint_map = {
            let d = ebpf_primary.take_map("FINGERPRINT_MAP")
                .ok_or(MapError::NotFound { name: "FINGERPRINT_MAP" })?;
            HashMap::try_from(d).map_err(MapError::Operation)?
        };

        let maps = BpfMaps { deny_map, scan_flag_map, fingerprint_map };
        info!("sg-ebpf: BPF maps extracted");

        // ── 5. Signal ReadyFlag ───────────────────────────────────────────────
        ready_flag.signal();
        info!("sg-ebpf: ReadyFlag signalled — data path is live");

        Ok(Self {
            _ebpf_primary: ebpf_primary,
            _ebpf_execve:  ebpf_execve,
            _ebpf_fp_probe: ebpf_fp,
            ringbuf,
            maps,
            ringbuf_drops: 0,
            probe_status,
        })
    }

    // ─── Probe helpers ────────────────────────────────────────────────────────

    fn attach_xdp(ebpf: &mut Ebpf, name: &'static str, iface: &str) -> ProbeStatus {
        let prog = match ebpf.program_mut(name) {
            Some(p) => p,
            None => {
                let names: Vec<&str> = ebpf.programs().map(|(n, _)| n).collect();
                eprintln!("[sg-ebpf] XDP program '{}' not found. Available: {:?}", name, names);
                return ProbeStatus::Degraded;
            }
        };
        let xdp: &mut Xdp = match prog {
            Program::Xdp(x) => x,
            other => {
                eprintln!("[sg-ebpf] '{}' is not XDP: {:?}", name, other.prog_type());
                return ProbeStatus::Degraded;
            }
        };
        if let Err(e) = xdp.load() {
            eprintln!("[sg-ebpf] XDP '{}' load failed: {}", name, e);
            return ProbeStatus::Degraded;
        }
        match xdp.attach(iface, XdpFlags::default()) {
            Ok(_) => {
                eprintln!("[sg-ebpf] XDP '{}' attached (native) to '{}'", name, iface);
                ProbeStatus::Attached
            }
            Err(e1) => {
                eprintln!("[sg-ebpf] XDP '{}' native attach failed on '{}': {} — trying SKB", name, iface, e1);
                match xdp.attach(iface, XdpFlags::SKB_MODE) {
                    Ok(_) => {
                        eprintln!("[sg-ebpf] XDP '{}' attached (SKB) to '{}'", name, iface);
                        ProbeStatus::Attached
                    }
                    Err(e2) => {
                        eprintln!("[sg-ebpf] XDP '{}' SKB attach also failed on '{}': {}", name, iface, e2);
                        ProbeStatus::Degraded
                    }
                }
            }
        }
    }

    fn load_and_attach_xdp(
        obj_bytes: &[u8],
        name:      &'static str,
        iface:     &str,
    ) -> (Option<Ebpf>, ProbeStatus) {
        let mut ebpf = match Ebpf::load(obj_bytes) {
            Ok(e)  => e,
            Err(e) => { warn!("sg-ebpf: load '{name}': {e}"); return (None, ProbeStatus::Degraded); }
        };
        let status = Self::attach_xdp(&mut ebpf, name, iface);
        (Some(ebpf), status)
    }

    fn load_and_attach_tracepoint(
        obj_bytes:  &[u8],
        name:       &'static str,
        category:   &str,
        tracepoint: &str,
    ) -> (Option<Ebpf>, ProbeStatus) {
        let mut ebpf = match Ebpf::load(obj_bytes) {
            Ok(e)  => e,
            Err(e) => { warn!("sg-ebpf: load '{name}': {e}"); return (None, ProbeStatus::Degraded); }
        };
        let prog = match ebpf.program_mut(name) {
            Some(p) => p,
            None    => { warn!("sg-ebpf: tp '{name}' not found"); return (Some(ebpf), ProbeStatus::Degraded); }
        };
        let tp: &mut TracePoint = match prog {
            Program::TracePoint(t) => t,
            _ => { warn!("sg-ebpf: '{name}' not a TracePoint"); return (Some(ebpf), ProbeStatus::Degraded); }
        };
        match tp.load().and_then(|()| tp.attach(category, tracepoint)) {
            Ok(_)  => { info!("sg-ebpf: tp '{name}' → '{category}/{tracepoint}'"); (Some(ebpf), ProbeStatus::Attached) }
            Err(e) => { warn!("sg-ebpf: tp '{name}' failed: {e}"); (Some(ebpf), ProbeStatus::Degraded) }
        }
    }
}

// ─── EbpfSource trait implementation ─────────────────────────────────────────
//
// The trait requires `&self`. BPF operations need `&mut self`.
// Trait methods are no-op shims; production code uses the `&mut self` methods below.

impl EbpfSource for EbpfLoader {
    type Error = EbpfSourceError;

    fn drain_events<'a>(
        &'a self,
        out: &'a mut [EbpfEvent; MAX_DRAIN_EVENTS],
    ) -> Result<&'a [EbpfEvent], Self::Error> {
        let _ = out;
        Ok(&[])
    }

    fn ringbuf_drop_count(&self) -> u64 {
        self.ringbuf_drops
    }

    fn write_deny_map(&self, _src_ip: u32) -> Result<(), Self::Error> {
        Ok(())
    }

    fn write_fingerprint_map(&self, _key: FlowKey) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ─── Production mutable API ──────────────────────────────────────────────────

impl EbpfLoader {
    /// Drain up to `MAX_DRAIN_EVENTS` events. **Thread 1 only.**
    ///
    /// Deserialises each event field-by-field — zero `unsafe`, zero allocations.
    pub fn drain_events_mut(
        &mut self,
        out: &mut [EbpfEvent; MAX_DRAIN_EVENTS],
    ) -> Result<usize, EbpfSourceError> {
        let mut count = 0usize;
        while count < MAX_DRAIN_EVENTS {
            let item = match self.ringbuf.next() {
                None    => break,
                Some(i) => i,
            };
            let bytes: &[u8] = item.as_ref();
            if bytes.len() < EBPF_EVENT_SIZE {
                self.ringbuf_drops = self.ringbuf_drops.saturating_add(1);
                continue;
            }
            out[count] = parse_ebpf_event(bytes);
            count += 1;
        }
        Ok(count)
    }

    /// Write `src_ip` into the BPF deny map (idempotent).
    pub fn write_deny_map_mut(&mut self, src_ip: u32) -> Result<(), EbpfSourceError> {
        self.maps.write_deny_entry(src_ip).map_err(EbpfSourceError::MapWrite)
    }

    /// Write TCP fingerprint parameters for a SCAN-flagged flow.
    pub fn write_fingerprint_map_mut(&mut self, key: FlowKey) -> Result<(), EbpfSourceError> {
        self.maps.write_fingerprint(key, FpParams::default()).map_err(EbpfSourceError::MapWrite)
    }

    #[must_use]
    pub fn probe_status(&self) -> &ProbeStatusMap {
        &self.probe_status
    }

    pub fn load_default(ready_flag: &ReadyFlag) -> Result<Self, LoadError> {
        Self::load(DEFAULT_IFACE, ready_flag)
    }
}

// ─── Safe event deserialiser ─────────────────────────────────────────────────

/// Parse a `&[u8]` into `EbpfEvent` — zero `unsafe`, field-by-field.
///
/// `EbpfEvent` layout (#[repr(C)], verified by `test_ebpf_event_size` in sg-common):
///  0..8   timestamp_ns u64
///  8..12  pid          u32
/// 12..16  uid          u32
/// 16..20  src_ip       u32
/// 20..24  dst_ip       u32
/// 24..26  src_port     u16
/// 26..28  dst_port     u16
/// 28      protocol     u8
/// 29      event_type   u8
/// 30..32  _pad         [u8;2]
/// 32..48  comm         [u8;16]
#[inline]
fn parse_ebpf_event(b: &[u8]) -> EbpfEvent {
    let u64_at = |o: usize| u64::from_ne_bytes(b[o..o+8].try_into().unwrap_or([0;8]));
    let u32_at = |o: usize| u32::from_ne_bytes(b[o..o+4].try_into().unwrap_or([0;4]));
    let u16_at = |o: usize| u16::from_ne_bytes(b[o..o+2].try_into().unwrap_or([0;2]));

    let mut comm = [0u8; 16];
    comm.copy_from_slice(&b[32..48]);

    EbpfEvent {
        timestamp_ns: u64_at(0),
        pid:          u32_at(8),
        uid:          u32_at(12),
        src_ip:       u32_at(16),
        dst_ip:       u32_at(20),
        src_port:     u16_at(24),
        dst_port:     u16_at(26),
        protocol:     b[28],
        event_type:   b[29],
        _pad:         [b[30], b[31]],
        comm,
    }
}

// ─── EbpfSourceError ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum EbpfSourceError {
    #[error("BPF map write failed: {0}")]
    MapWrite(#[from] MapError),
}