//! XDP TCP fingerprint probe — inert until Phase 3 (`sg-fingerprint`).
//!
//! This probe is **loaded and attached** by `sg-ebpf::loader` in Phase 1
//! so that the eBPF verifier validates it now, before Phase 3 arms it.
//!
//! In Phase 1 the probe is a pure observer: it reads `FINGERPRINT_MAP`
//! and emits events but takes no enforcement action.
//!
//! Phase 3 (`sg-fingerprint`) will:
//!   - Populate `FINGERPRINT_MAP` with target parameters.
//!   - Upgrade the probe to respond with spoofed TCP Window-Zero + jitter.
//!
//! The probe is attached to the loopback interface (`lo`) in Phase 1 to
//! minimise risk while the verifier validates the program structure.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{LruHashMap, RingBuf},
    programs::XdpContext,
};

/// Shared fingerprint map — written by `sg-ebpf::loader::write_fingerprint_map_mut`.
#[map(name = "FINGERPRINT_MAP")]
static FINGERPRINT_MAP: LruHashMap<FlowKey5Tuple, FpParams> =
    LruHashMap::with_max_entries(4096, 0);

/// Shared ringbuf — same instance as `packet_ingress`.
#[map(name = "PACKET_EVENTS")]
static PACKET_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

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

#[repr(C)]
#[derive(Clone, Copy)]
struct FpParams {
    window_size: u16,
    ttl:         u8,
    df_bit:      u8,
    _reserved:   [u8; 4],
}

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

// Note: event type 6 = ScanFlagSet; re-use to mark fingerprint probe hits.
const EVENT_SCAN_FLAG_SET: u8 = 6;

/// XDP fingerprint probe — observe only in Phase 1.
#[xdp]
pub fn tcp_fp_probe(ctx: XdpContext) -> u32 {
    match try_tcp_fp_probe(&ctx) {
        Ok(action) => action,
        Err(_)     => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_tcp_fp_probe(ctx: &XdpContext) -> Result<u32, ()> {
    let data     = ctx.data()     as usize;
    let data_end = ctx.data_end() as usize;

    // Minimum Ethernet + IP + TCP: 14 + 20 + 20 = 54 bytes.
    if data + 54 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Ethernet type check (offset 12).
    let eth_type = unsafe { *((data + 12) as *const u16) };
    if eth_type != 0x0008_u16 { // 0x0800 big-endian = 0x0008 little-endian
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_start = data + 14;
    let protocol = unsafe { *((ip_start + 9) as *const u8) };
    if protocol != 6 { // TCP only
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip   = u32::from_be(unsafe { *((ip_start + 12) as *const u32) });
    let dst_ip   = u32::from_be(unsafe { *((ip_start + 16) as *const u32) });
    let ihl      = ((unsafe { *(ip_start as *const u8) } & 0x0F) as usize) * 4;
    let tcp_start = ip_start + ihl;

    if tcp_start + 4 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_port = u16::from_be(unsafe { *((tcp_start    ) as *const u16) });
    let dst_port = u16::from_be(unsafe { *((tcp_start + 2) as *const u16) });

    let key = FlowKey5Tuple { src_ip, dst_ip, src_port, dst_port, protocol, _pad: [0; 3] };

    // Check fingerprint map — if present, emit an event (Phase 3 enforcement here).
    if unsafe { FINGERPRINT_MAP.get(&key).is_some() } {
        if let Some(mut entry) = PACKET_EVENTS.reserve::<EbpfEvent>(0) {
            let ev = entry.as_mut_ptr();
            unsafe {
                (*ev).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
                (*ev).pid          = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;
                (*ev).uid          = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
                (*ev).src_ip       = src_ip;
                (*ev).dst_ip       = dst_ip;
                (*ev).src_port     = src_port;
                (*ev).dst_port     = dst_port;
                (*ev).protocol     = protocol;
                (*ev).event_type   = EVENT_SCAN_FLAG_SET;
                (*ev)._pad         = [0u8; 2];
                if let Ok(comm) = aya_ebpf::helpers::bpf_get_current_comm() {
                    (*ev).comm = comm;
                }
            }
            entry.submit(0);
        }
    }

    // Phase 1: always pass.  Phase 3 will return XDP_DROP or XDP_TX here.
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}