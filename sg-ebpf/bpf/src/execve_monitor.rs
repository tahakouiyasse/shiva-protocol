//! eBPF tracepoint: `syscalls/sys_enter_execve`
//!
//! Fires on every `execve(2)` syscall.
//! Emits `EbpfEvent { event_type: Execve (3) }` into `PACKET_EVENTS`.
//!
//! Lateral movement and command-injection attacks typically involve
//! unexpected `execve` calls from network-facing processes.  This probe
//! gives `sg-bellman` a cross-layer signal to correlate with network anomalies.

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

#[map(name = "PACKET_EVENTS")]
static PACKET_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

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
    event_type:   u8,   // 3 = Execve
    _pad:         [u8; 2],
    comm:         [u8; 16],
}

const EVENT_EXECVE: u8 = 3;

#[tracepoint(name = "execve_monitor", category = "syscalls")]
pub fn execve_monitor(ctx: TracePointContext) -> i64 {
    match try_execve_monitor(&ctx) {
        Ok(rc) => rc,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_execve_monitor(_ctx: &TracePointContext) -> Result<i64, ()> {
    let Some(mut entry) = PACKET_EVENTS.reserve::<EbpfEvent>(0) else {
        return Err(());
    };

    let ev = entry.as_mut_ptr();

    unsafe {
        (*ev).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        (*ev).pid          = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;
        (*ev).uid          = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
        (*ev).src_ip       = 0;
        (*ev).dst_ip       = 0;
        (*ev).src_port     = 0;
        (*ev).dst_port     = 0;
        (*ev).protocol     = 0;
        (*ev).event_type   = EVENT_EXECVE;
        (*ev)._pad         = [0u8; 2];
        if let Ok(comm) = aya_ebpf::helpers::bpf_get_current_comm() {
            (*ev).comm = comm;
        }
    }

    entry.submit(0);
    Ok(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}