//! XDP packet ingress program — sg-ebpf hot path.
//!
//! This program is attached to the primary network interface by
//! `sg-ebpf::loader` and runs in the kernel's XDP hook for every
//! ingress packet.
//!
//! # What this program does
//!
//! 1. Parse Ethernet → IPv4 → TCP/UDP/ICMP.
//! 2. Extract `PacketHeader` fields (src_ip, dst_ip, ports, flags, etc.).
//! 3. Check `DENY_MAP`: if the source IP is listed, return `XDP_DROP`.
//! 4. Check `SCAN_FLAG_MAP`: if the flow is flagged, set event_type accordingly.
//! 5. Write an `EbpfEvent` into the `PACKET_EVENTS` ringbuf.
//! 6. Return `XDP_PASS` (we observe; enforcement is policy-driven).
//!
//! # Cache-line write discipline
//!
//! Every `EbpfEvent` write targets a single 48-byte slot in the ringbuf.
//! The ringbuf allocates each reservation on an 8-byte boundary.
//! The XDP program writes all fields in a single `bpf_ringbuf_submit` call,
//! preventing partial-write false-sharing across cache lines.
//!
//! # Verifier constraints
//!
//! - All pointer arithmetic is bounds-checked before dereference.
//! - No loops: the parser is a straight-line sequence of `if data + N > data_end { return XDP_PASS }`.
//! - No stack frames larger than 512 bytes.
//! - No function calls that increase stack depth (inline helpers only).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruHashMap, RingBuf},
    programs::XdpContext,
};
// ─── Shared map declarations ─────────────────────────────────────────────────
//
// These map names must exactly match the strings used in `sg-ebpf::loader`
// for `ebpf.map_mut("NAME")` calls.

/// Ringbuf for kernel→userspace event delivery.  1 MiB capacity.
/// Sized to hold ~21,845 `EbpfEvent` structs (48 bytes each).
#[map(name = "PACKET_EVENTS")]
static mut PACKET_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

/// LRU deny map: src_ip (u32) → drop flag (u8).
/// Populated by `sg-ebpf::loader::write_deny_map_mut()`.
/// Checked by this XDP program before passing a packet.
#[map(name = "DENY_MAP")]
static mut DENY_MAP: LruHashMap<u32, u8> = LruHashMap::with_max_entries(65536, 0);

/// SCAN flag map: FlowKey → expiry_ns (u64).
/// An entry here causes `event_type` to be set to `ScanFlagSet` (6).
#[map(name = "SCAN_FLAG_MAP")]
static mut SCAN_FLAG_MAP: LruHashMap<FlowKey5Tuple, u64> =
    LruHashMap::with_max_entries(8192, 0);

// ─── Fingerprint map (Phase 3 — inert in Phase 1) ────────────────────────────
/// TCP fingerprint parameter map.  Written by userspace; read by `tcp_fp_probe`.
/// Declared here so the map object is present in the loaded ELF.
#[map(name = "FINGERPRINT_MAP")]
static mut FINGERPRINT_MAP: LruHashMap<FlowKey5Tuple, FpParams> =
    LruHashMap::with_max_entries(4096, 0);

// ─── Inline C struct representations ─────────────────────────────────────────
//
// These must match sg-common's types byte-for-byte.
// Verified by `bpftool btf dump` comparison in CI.

/// Five-tuple flow key — must match `sg_common::FlowKey` ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct FlowKey5Tuple {
    src_ip:   u32,
    dst_ip:   u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _pad:     [u8; 3],
}

/// Inert fingerprint params — must match `sg_ebpf::map::FpParams` ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct FpParams {
    window_size: u16,
    ttl:         u8,
    df_bit:      u8,
    _reserved:   [u8; 4],
}

/// eBPF event written to `PACKET_EVENTS` — must match `sg_common::EbpfEvent`.
///
/// Size: 8+4+4+4+4+2+2+1+1+2+16 = 48 bytes.
/// Verified by `test_ebpf_event_size` in `sg-common`.
#[repr(C)]
struct EbpfEvent {
    timestamp_ns: u64,
    pid:          u32,
    uid:          u32,
    src_ip:       u32,
    dst_ip:       u32,
    src_port:     u16,
    dst_port:     u16,
    protocol:     u8,
    event_type:   u8,
    _pad:         [u8; 2],
    comm:         [u8; 16],
}

// ─── Protocol constants ───────────────────────────────────────────────────────
const ETH_HDR_LEN:  usize = 14;
const ETH_P_IP:     u16   = 0x0800_u16.to_be();
const IPPROTO_TCP:  u8    = 6;
const IPPROTO_UDP:  u8    = 17;
const IPPROTO_ICMP: u8    = 1;

// eBPF event type discriminants — must match `sg_common::EbpfEventType`.
const EVENT_PACKET_INGRESS: u8 = 0;
const EVENT_SCAN_FLAG_SET:  u8 = 6;

// ─── XDP entry point ─────────────────────────────────────────────────────────

/// XDP ingress program attached to the primary interface by `sg-ebpf::loader`.
///
/// Returns `XDP_DROP` for deny-listed source IPs; `XDP_PASS` otherwise.
/// The event is always written to the ringbuf before the forwarding decision,
/// so userspace sees the packet regardless of the drop outcome.
#[xdp]
pub fn packet_ingress(ctx: XdpContext) -> u32 {
    match try_packet_ingress(&ctx) {
        Ok(action) => action,
        // Verifier-safe error handling: always pass on parse error.
        // We prefer false-negative (missed event) over XDP_ABORTED.
        Err(_) => xdp_action::XDP_PASS,
    }
}

// ─── Core parsing logic ───────────────────────────────────────────────────────

#[inline(always)]
fn try_packet_ingress(ctx: &XdpContext) -> Result<u32, ()> {
    let data     = ctx.data()     as usize;
    let data_end = ctx.data_end() as usize;

    // ── Ethernet header ──────────────────────────────────────────────────────
    if data + ETH_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS); // too short to be valid
    }

    // Ethernet type is at offset 12–13 (big-endian u16).
    let eth_type = unsafe {
        *((data + 12) as *const u16)
    };

    if eth_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS); // ignore non-IPv4
    }

    // ── IPv4 header ──────────────────────────────────────────────────────────
    let ip_start = data + ETH_HDR_LEN;

    // Minimum IPv4 header: 20 bytes.
    if ip_start + 20 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // IHL field (bits 0–3 of the first byte, in 32-bit words).
    let ihl_byte = unsafe { *(ip_start as *const u8) };
    let ihl      = ((ihl_byte & 0x0F) as usize) * 4;

    if ihl < 20 || ip_start + ihl > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let total_length = u16::from_be(unsafe { *((ip_start + 2) as *const u16) }) as usize;
    let protocol     = unsafe { *((ip_start + 9) as *const u8) };
    let src_ip       = u32::from_be(unsafe { *((ip_start + 12) as *const u32) });
    let dst_ip       = u32::from_be(unsafe { *((ip_start + 16) as *const u32) });

    // ── Deny map check ───────────────────────────────────────────────────────
    // O(1) LRU hash lookup. If the source IP is in the deny list, drop immediately.
    let is_denied = unsafe { (*core::ptr::addr_of_mut!(DENY_MAP)).get(&src_ip).is_some() };
    if is_denied {
        // Still emit an event so userspace can count deny-map hits.
        emit_event(ctx, src_ip, dst_ip, 0, 0, 0, 0, protocol, EVENT_PACKET_INGRESS);
        return Ok(xdp_action::XDP_DROP);
    }

    // ── Transport layer parsing ───────────────────────────────────────────────
    let transport_start = ip_start + ihl;
    let (src_port, dst_port, tcp_flags) =
        parse_transport(ctx, transport_start, data_end, protocol)?;

    // ── Scan flag check ───────────────────────────────────────────────────────
    let flow_key = FlowKey5Tuple {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        _pad: [0u8; 3],
    };

    let event_type = if unsafe { (*core::ptr::addr_of_mut!(SCAN_FLAG_MAP)).get(&flow_key).is_some() } {
        EVENT_SCAN_FLAG_SET
    } else {
        EVENT_PACKET_INGRESS
    };

    // ── Emit event ───────────────────────────────────────────────────────────
    emit_event(
        ctx,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_flags,
        total_length as u16,
        protocol,
        event_type,
    );

    Ok(xdp_action::XDP_PASS)
}

// ─── Transport parser ─────────────────────────────────────────────────────────

/// Parse TCP/UDP/ICMP and return (src_port, dst_port, tcp_flags).
///
/// Returns `(0, 0, 0)` for ICMP (no ports) and unrecognised protocols.
/// Bounds-checked: returns `Err(())` if the packet is truncated.
#[inline(always)]
fn parse_transport(
    _ctx:            &XdpContext,
    transport_start: usize,
    data_end:        usize,
    protocol:        u8,
) -> Result<(u16, u16, u8), ()> {
    match protocol {
        IPPROTO_TCP => {
            // TCP minimum header: 20 bytes.
            if transport_start + 20 > data_end {
                return Err(());
            }
            let src_port  = u16::from_be(unsafe { *((transport_start    ) as *const u16) });
            let dst_port  = u16::from_be(unsafe { *((transport_start + 2) as *const u16) });
            // TCP flags byte is at offset 13 from the TCP header start.
            let tcp_flags = unsafe { *((transport_start + 13) as *const u8) };
            Ok((src_port, dst_port, tcp_flags))
        }
        IPPROTO_UDP => {
            // UDP header: 8 bytes minimum.
            if transport_start + 8 > data_end {
                return Err(());
            }
            let src_port = u16::from_be(unsafe { *((transport_start    ) as *const u16) });
            let dst_port = u16::from_be(unsafe { *((transport_start + 2) as *const u16) });
            Ok((src_port, dst_port, 0u8))
        }
        IPPROTO_ICMP => {
            // ICMP has no ports; we record zeros.
            Ok((0u16, 0u16, 0u8))
        }
        _ => {
            // Unknown protocol: pass with zero ports.
            Ok((0u16, 0u16, 0u8))
        }
    }
}

// ─── Ringbuf emission ─────────────────────────────────────────────────────────

/// Write an `EbpfEvent` into `PACKET_EVENTS`.
///
/// Uses `bpf_ringbuf_reserve` + `bpf_ringbuf_submit` (via Aya's `reserve`/`submit`)
/// for atomic, zero-copy kernel→userspace transfer.
///
/// If the ringbuf is full, Aya increments the kernel-side drop counter; userspace
/// reads this via `EbpfLoader::ringbuf_drop_count()`.
#[inline(always)]
fn emit_event(
    _ctx:        &XdpContext,
    src_ip:     u32,
    dst_ip:     u32,
    src_port:   u16,
    dst_port:   u16,
    tcp_flags:  u8,
    _length:    u16,
    protocol:   u8,
    event_type: u8,
) {
    // `reserve` returns None if the ringbuf is full — that's fine; the kernel
    // drop counter is incremented automatically.
    let Some(mut entry) = (unsafe { 
        (*core::ptr::addr_of_mut!(PACKET_EVENTS)).reserve::<EbpfEvent>(0) 
    }) else {
        return;
    };

    let ev = entry.as_mut_ptr();

    // Populate the event.  All fields are written before `submit`.
    //
    // NOTE: bpf_get_current_pid_tgid, bpf_get_current_uid_gid, and
    // bpf_get_current_comm are FORBIDDEN in XDP programs — the verifier
    // rejects them because XDP runs at driver level with no task context.
    // pid/uid/comm are set to 0; they are filled by the tracepoint probes
    // (execve_monitor, tcp_connect) which run in process context.
    unsafe {
        (*ev).timestamp_ns = bpf_ktime_get_ns();
        (*ev).pid          = 0u32;   // not available in XDP context
        (*ev).uid          = 0u32;   // not available in XDP context
        (*ev).src_ip       = src_ip;
        (*ev).dst_ip       = dst_ip;
        (*ev).src_port     = src_port;
        (*ev).dst_port     = dst_port;
        (*ev).protocol     = protocol;
        (*ev).event_type   = event_type;
        (*ev)._pad         = [0u8; 2];
        (*ev).comm         = [0u8; 16]; // not available in XDP context
    }

    // Ignore unused tcp_flags in the event struct (not in EbpfEvent by design —
    // tcp_flags are part of PacketHeader extracted by the capture layer).
    let _ = tcp_flags;

    // Submit atomically — the userspace ringbuf consumer sees a complete event.
    entry.submit(0);
}

// ─── BPF helper stubs ────────────────────────────────────────────────────────
//
// Aya-bpf exposes these as safe wrappers; we call them here.

#[inline(always)]
unsafe fn bpf_ktime_get_ns() -> u64 {
    aya_ebpf::helpers::bpf_ktime_get_ns()
}

// bpf_get_current_pid_tgid / uid_gid / comm are NOT defined here:
// they are forbidden in XDP programs (no task context at driver level).

// ─── Panic handler (required for no_std) ─────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The eBPF verifier rejects programs with reachable panic paths.
    // This handler satisfies the linker; it should never be reached.
    loop {}
}