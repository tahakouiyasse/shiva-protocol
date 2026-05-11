//! sg-ebpf/src/map.rs
//!
//! Typed BPF map write API.
//!
//! # Orphan rule & aya::Pod
//!
//! `aya::HashMap::insert` requires `K: aya::Pod`.
//! `aya::Pod` is a foreign trait; `FlowKey` is a foreign type (sg-common).
//! Implementing a foreign trait on a foreign type violates the orphan rule (E0117).
//!
//! Solution: `BpfFlowKey` — a local ABI-mirror of `FlowKey` — implements
//! `aya::Pod` legally (local type, foreign trait = OK).
//! Conversion `FlowKey → BpfFlowKey` happens at the call boundary.
//!
//! # aya 0.13
//!
//! No `LruHashMap` struct exists in aya 0.13 userspace.
//! All map handles are `HashMap<MapData, K, V>`.

use std::io;
use thiserror::Error;

use aya::maps::{HashMap, MapData};
use sg_common::FlowKey;

// ─── Local BPF types (Pod-implementing) ──────────────────────────────────────

/// ABI mirror of `sg_common::FlowKey` — used as BPF map key.
///
/// Layout is identical to `FlowKey` (#[repr(C)], same fields, same order).
/// Must stay in sync with `FlowKey` in sg-common/src/lib.rs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfFlowKey {
    pub src_ip:   u32,
    pub dst_ip:   u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad:     [u8; 3],
}

#[allow(unsafe_code)]
// SAFETY: BpfFlowKey is #[repr(C)], all fields are primitives (u32/u16/u8/[u8;3]).
// Every bit-pattern is a valid value — no invariants. Copy + 'static satisfied.
unsafe impl aya::Pod for BpfFlowKey {}

impl From<FlowKey> for BpfFlowKey {
    fn from(k: FlowKey) -> Self {
        Self {
            src_ip:   k.src_ip,
            dst_ip:   k.dst_ip,
            src_port: k.src_port,
            dst_port: k.dst_port,
            protocol: k.protocol,
            _pad:     [0u8; 3],
        }
    }
}

/// TCP fingerprint parameters — BPF map value, inert until Phase 3.
///
/// Must match the C struct in `bpf/tcp_fp_probe.h` (8 bytes, #[repr(C)]).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FpParams {
    pub window_size: u16,
    pub ttl:         u8,
    pub df_bit:      u8,
    pub _reserved:   [u8; 4],
}

#[allow(unsafe_code)]
// SAFETY: FpParams is #[repr(C)], all fields are primitives.
// Every bit-pattern is valid — no invariants. Copy + 'static satisfied.
unsafe impl aya::Pod for FpParams {}

// ─── MapError ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MapError {
    #[error("BPF map '{name}' not found in loaded object")]
    NotFound { name: &'static str },

    #[error("BPF map operation failed: {0}")]
    Operation(#[from] aya::maps::MapError),

    #[error("I/O error during map operation: {0}")]
    Io(#[from] io::Error),
}

// ─── BpfMaps ─────────────────────────────────────────────────────────────────

/// All typed BPF map handles, constructed once via `ebpf.take_map()`.
pub struct BpfMaps {
    /// LRU deny map: src_ip (u32) → drop flag (u8).
    pub deny_map:       HashMap<MapData, u32, u8>,
    /// SCAN-flagged flows: BpfFlowKey → expiry_ns (u64).
    pub scan_flag_map:  HashMap<MapData, BpfFlowKey, u64>,
    /// TCP fingerprint params (Phase 3 — inert in Phase 1).
    pub fingerprint_map: HashMap<MapData, BpfFlowKey, FpParams>,
}

impl BpfMaps {
    /// Write `src_ip` into the deny map (idempotent).
    pub fn write_deny_entry(&mut self, src_ip: u32) -> Result<(), MapError> {
        self.deny_map
            .insert(src_ip, 1u8, 0)
            .map_err(MapError::Operation)
    }

    /// Remove `src_ip` from the deny map. No-op if absent.
    pub fn remove_deny_entry(&mut self, src_ip: u32) -> Result<(), MapError> {
        self.deny_map
            .remove(&src_ip)
            .map_err(MapError::Operation)
    }

    /// Flag a flow as SCAN-detected with a nanosecond expiry timestamp.
    pub fn write_scan_flag(&mut self, key: FlowKey, expiry_ns: u64) -> Result<(), MapError> {
        self.scan_flag_map
            .insert(BpfFlowKey::from(key), expiry_ns, 0)
            .map_err(MapError::Operation)
    }

    /// Remove a SCAN flag entry. No-op if absent.
    pub fn clear_scan_flag(&mut self, key: FlowKey) -> Result<(), MapError> {
        self.scan_flag_map
            .remove(&BpfFlowKey::from(key))
            .map_err(MapError::Operation)
    }

    /// Write TCP fingerprint parameters. Inert until Phase 3 arms the probe.
    pub fn write_fingerprint(&mut self, key: FlowKey, params: FpParams) -> Result<(), MapError> {
        self.fingerprint_map
            .insert(BpfFlowKey::from(key), params, 0)
            .map_err(MapError::Operation)
    }
}