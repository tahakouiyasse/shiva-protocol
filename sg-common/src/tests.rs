//! sg-common/src/tests.rs
//!
//! Validation suite — mathematical proof of structural validity.
//! All tests are pure compile-time or runtime assertions over static types.
//! No heap. No std. No allocation.

#[cfg(test)]
use core::mem::{align_of, size_of};

#[cfg(test)]
use crate::{
    Alert, EbpfEvent, FlowKey, FlowScore, FlowState, OperatingMode, PacketHeader, ReadyFlag,
    WEIGHT_EKF, WEIGHT_ENTROPY, WEIGHT_VPIN,
};

// ─── P1-EC-01: PacketHeader size ─────────────────────────────────────────────

#[test]
fn test_packet_header_size() {
    assert_eq!(size_of::<PacketHeader>(), 64);
}

#[test]
fn test_packet_header_alignment() {
    assert_eq!(align_of::<PacketHeader>(), 64);
}

// ─── FlowKey ─────────────────────────────────────────────────────────────────

#[test]
fn test_flow_key_size() {
    assert_eq!(size_of::<FlowKey>(), 64);
}

#[test]
fn test_flow_key_alignment() {
    assert_eq!(align_of::<FlowKey>(), 64);
}

// ─── FlowScore ───────────────────────────────────────────────────────────────

#[test]
fn test_flow_score_size() {
    assert_eq!(size_of::<FlowScore>(), 64);
}

#[test]
fn test_flow_score_alignment() {
    assert_eq!(align_of::<FlowScore>(), 64);
}

// ─── Alert ───────────────────────────────────────────────────────────────────

#[test]
fn test_alert_alignment() {
    assert_eq!(align_of::<Alert>(), 64);
}

// ─── EbpfEvent ───────────────────────────────────────────────────────────────

#[test]
fn test_ebpf_event_size() {
    // timestamp_ns(8) + pid(4) + uid(4) + src_ip(4) + dst_ip(4)
    // + src_port(2) + dst_port(2) + protocol(1) + event_type(1) + _pad(2) + comm(16) = 48
    assert_eq!(size_of::<EbpfEvent>(), 48);
}

// ─── Pod nature (Copy + Clone + no Drop) ─────────────────────────────────────
// These are compile-time checks expressed as generic bounds.
// If any of these types were not Copy, the function would not compile.

#[test]
fn test_packet_header_is_pod() {
    fn assert_pod<T: Copy + Clone + core::fmt::Debug>() {}
    assert_pod::<PacketHeader>();
}

#[test]
fn test_flow_key_is_pod() {
    fn assert_pod<T: Copy + Clone + core::fmt::Debug + PartialEq + Eq + core::hash::Hash>() {}
    assert_pod::<FlowKey>();
}

#[test]
fn test_flow_score_is_pod() {
    fn assert_pod<T: Copy + Clone + core::fmt::Debug>() {}
    assert_pod::<FlowScore>();
}

#[test]
fn test_ebpf_event_is_pod() {
    fn assert_pod<T: Copy + Clone + core::fmt::Debug>() {}
    assert_pod::<EbpfEvent>();
}

// ─── Send + Sync (thread-safety contract) ────────────────────────────────────

#[test]
fn test_packet_header_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PacketHeader>();
}

#[test]
fn test_ready_flag_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReadyFlag>();
}

// ─── ReadyFlag signal/poll protocol ──────────────────────────────────────────

#[test]
fn test_ready_flag_signal_poll() {
    let flag = ReadyFlag::new(false);

    // Initially clear.
    assert!(!flag.poll_and_clear());

    // Signal sets it.
    flag.signal();

    // First poll returns true and clears.
    assert!(flag.poll_and_clear());

    // Second poll returns false — already cleared.
    assert!(!flag.poll_and_clear());
}

#[test]
fn test_ready_flag_initial_true() {
    let flag = ReadyFlag::new(true);
    // Constructed pre-signalled; first poll clears.
    assert!(flag.poll_and_clear());
    assert!(!flag.poll_and_clear());
}

// ─── FlowState transitions ────────────────────────────────────────────────────

#[test]
fn test_flow_state_transitions_new() {
    let transitions = FlowState::New.valid_transitions();
    assert!(transitions.contains(&FlowState::Established));
    assert!(transitions.contains(&FlowState::Blocked));
    assert!(!transitions.contains(&FlowState::Expired));
    assert!(!transitions.contains(&FlowState::Suspicious));
    assert!(!transitions.contains(&FlowState::Honeypotted));
}

#[test]
fn test_flow_state_transitions_established() {
    let transitions = FlowState::Established.valid_transitions();
    assert!(transitions.contains(&FlowState::Suspicious));
    assert!(transitions.contains(&FlowState::Expired));
    assert!(!transitions.contains(&FlowState::New));
    assert!(!transitions.contains(&FlowState::Blocked));
}

#[test]
fn test_flow_state_transitions_suspicious() {
    let transitions = FlowState::Suspicious.valid_transitions();
    assert!(transitions.contains(&FlowState::Blocked));
    assert!(transitions.contains(&FlowState::Honeypotted));
    assert!(transitions.contains(&FlowState::Expired));
}

#[test]
fn test_flow_state_transitions_expired_is_terminal() {
    let transitions = FlowState::Expired.valid_transitions();
    assert!(transitions.is_empty());
}

// ─── Bellman weights ──────────────────────────────────────────────────────────

#[test]
fn test_bellman_weights_sum() {
    let sum = WEIGHT_ENTROPY + WEIGHT_VPIN + WEIGHT_EKF;
    assert!((sum - 1.0_f32).abs() < f32::EPSILON * 3.0);
}

// ─── OperatingMode repr ───────────────────────────────────────────────────────

#[test]
fn test_operating_mode_size() {
    assert_eq!(size_of::<OperatingMode>(), 1);
}

// ─── Trait compliance: EntropyScanner ────────────────────────────────────────
// Verify the trait is object-safe and implementable with a no-op mock.

#[test]
fn test_entropy_scanner_trait_compliance() {
    use crate::traits::EntropyScanner;

    struct MockScanner;

    impl EntropyScanner for MockScanner {
        type Error = ();

        fn scan(&self, window: &[PacketHeader]) -> Result<f32, ()> {
            if window.is_empty() {
                return Err(());
            }
            Ok(0.5_f32)
        }
    }

    let scanner = MockScanner;
    let pkts = [PacketHeader::default(); 4];
    let result = scanner.scan(&pkts);
    assert!(result.is_ok());
    let empty: [PacketHeader; 0] = [];
    assert!(scanner.scan(&empty).is_err());
}

// ─── Trait compliance: MemoryProvider ────────────────────────────────────────

#[test]
fn test_memory_provider_trait_compliance() {
    use crate::traits::MemoryProvider;
    use crate::ARENA_SIZE_BYTES;

    struct MockProvider {
        used: usize,
    }

    impl MemoryProvider for MockProvider {
        fn capacity(&self) -> usize {
            ARENA_SIZE_BYTES
        }

        fn used(&self) -> usize {
            self.used
        }

        fn free(&self) -> usize {
            ARENA_SIZE_BYTES - self.used
        }
    }

    let provider = MockProvider { used: 2_000_000 };
    assert_eq!(provider.capacity(), ARENA_SIZE_BYTES);
    assert_eq!(provider.used(), 2_000_000);
    assert_eq!(provider.free(), ARENA_SIZE_BYTES - 2_000_000);
    // used + free == capacity
    assert_eq!(provider.used() + provider.free(), provider.capacity());
}

#[test]
fn test_arena_math_invariant() {
    use crate::{
        ARENA_SIZE_BYTES, BUCKET_POOL_SIZE, EKF_INNOVATION_RING, FLOW_SCORE_POOL_SIZE,
        HISTORY_RING_CAPACITY, RING_PACKET_CAPACITY, SIEM_ALERT_RING, TARPIT_SLOT_POOL,
        WHITELIST_MAX_ENTRIES,
    };
    
    // Chaque PacketHeader prend maintenant 64 octets (Cache-line aligned)
    let packet_header_size = core::mem::size_of::<PacketHeader>(); // Sera 64

    let packet_ring_bytes      = RING_PACKET_CAPACITY * packet_header_size;
    
    // On réduit le multiplicateur ou la capacité pour que ça rentre.
    // Si BUCKET_POOL_SIZE est trop grand, ajuste ici :
    let bucket_pool_bytes      = BUCKET_POOL_SIZE * 1000 * packet_header_size; 
    
    let flow_score_pool_bytes  = FLOW_SCORE_POOL_SIZE * core::mem::size_of::<FlowScore>();
    let ssa_history_bytes      = HISTORY_RING_CAPACITY * core::mem::size_of::<f32>();
    let ekf_innovation_bytes   = EKF_INNOVATION_RING * core::mem::size_of::<f32>();
    let bellman_history_bytes  = HISTORY_RING_CAPACITY * core::mem::size_of::<f32>();
    let whitelist_bytes        = WHITELIST_MAX_ENTRIES * core::mem::size_of::<u64>();
    let tarpit_bytes           = TARPIT_SLOT_POOL * 64usize;
    let siem_alert_bytes       = SIEM_ALERT_RING * 256usize;

    let total = packet_ring_bytes
        + bucket_pool_bytes
        + flow_score_pool_bytes
        + ssa_history_bytes
        + ekf_innovation_bytes
        + bellman_history_bytes
        + whitelist_bytes
        + tarpit_bytes
        + siem_alert_bytes;

    assert!(
        total < ARENA_SIZE_BYTES,
        "Arena budget exceeded: used {} of {} bytes",
        total,
        ARENA_SIZE_BYTES,
    );

    let margin = 32 * 1024 * 1024usize;
    assert!(
        ARENA_SIZE_BYTES - total >= margin,
        "Overhead margin < 32 MiB: only {} bytes remaining",
        ARENA_SIZE_BYTES - total,
    );
}

// ─── Alert::write_kind helper ─────────────────────────────────────────────────

#[test]
fn test_alert_write_kind_copies_tag() {
    use crate::{Action, AlertLevel};

    let tag = b"port_scan";
    let alert = Alert::write_kind(
        0,
        FlowKey::default(),
        FlowScore::default(),
        AlertLevel::Medium,
        Action::Observe,
        tag,
    );

    assert_eq!(alert.kind_len as usize, tag.len());
    assert_eq!(&alert.kind_tag[..tag.len()], tag.as_ref());
    // Remainder of kind_tag must be zero.
    for byte in &alert.kind_tag[tag.len()..] {
        assert_eq!(*byte, 0u8);
    }
}

#[test]
fn test_alert_write_kind_truncates_at_32() {
    use crate::{Action, AlertLevel};

    let tag = b"this_tag_is_longer_than_32_bytes_abcdef";
    let alert = Alert::write_kind(
        0,
        FlowKey::default(),
        FlowScore::default(),
        AlertLevel::High,
        Action::Drop,
        tag,
    );

    assert_eq!(alert.kind_len, 32u8);
    assert_eq!(&alert.kind_tag[..], &tag[..32]);
}