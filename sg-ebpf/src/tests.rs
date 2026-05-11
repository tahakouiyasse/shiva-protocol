//! sg-ebpf/src/tests.rs

#[cfg(test)]
mod tests {
    use sg_common::{traits::MAX_DRAIN_EVENTS, EbpfEvent, FlowKey, ReadyFlag};

    use crate::{
        caps::{verify_with_checker, CapabilityError},
        map::FpParams,
    };

    // ── P1-EC-09 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_cap_bpf_absent_clean_error() {
        match verify_with_checker(|| Ok((false, true))) {
            Err(CapabilityError::MissingCapBpf) => {}
            other => panic!("expected MissingCapBpf, got: {other:?}"),
        }
    }

    #[test]
    fn test_cap_net_admin_absent_clean_error() {
        match verify_with_checker(|| Ok((true, false))) {
            Err(CapabilityError::MissingCapNetAdmin) => {}
            other => panic!("expected MissingCapNetAdmin, got: {other:?}"),
        }
    }

    #[test]
    fn test_cap_check_io_failure() {
        match verify_with_checker(|| {
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"))
        }) {
            Err(CapabilityError::CheckFailed(_)) => {}
            other => panic!("expected CheckFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_cap_all_present_returns_ok() {
        assert!(verify_with_checker(|| Ok((true, true))).is_ok());
    }

    // ── DEGR ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_loader_degraded_mode() {
        use crate::loader::{ProbeStatus, ProbeStatusMap};
        let s = ProbeStatusMap {
            packet_ingress: ProbeStatus::Attached,
            execve_monitor: ProbeStatus::Degraded,
            tcp_fp_probe:   ProbeStatus::Degraded,
        };
        assert!(s.any_attached());
    }

    #[test]
    fn test_loader_all_degraded_none_attached() {
        use crate::loader::{ProbeStatus, ProbeStatusMap};
        let s = ProbeStatusMap {
            packet_ingress: ProbeStatus::Degraded,
            execve_monitor: ProbeStatus::Degraded,
            tcp_fp_probe:   ProbeStatus::Degraded,
        };
        assert!(!s.any_attached());
    }

    // ── DRAIN ────────────────────────────────────────────────────────────────

    #[test]
    fn test_ringbuf_drain_bounded_returns_empty_slice() {
        use sg_common::traits::EbpfSource;

        struct MockSource;
        impl EbpfSource for MockSource {
            type Error = ();
            fn drain_events<'a>(&'a self, out: &'a mut [EbpfEvent; MAX_DRAIN_EVENTS])
                -> Result<&'a [EbpfEvent], ()> { let _ = out; Ok(&[]) }
            fn ringbuf_drop_count(&self) -> u64 { 0 }
            fn write_deny_map(&self, _: u32) -> Result<(), ()> { Ok(()) }
            fn write_fingerprint_map(&self, _: FlowKey) -> Result<(), ()> { Ok(()) }
        }

        let mut out = [EbpfEvent::default(); MAX_DRAIN_EVENTS];
        let slice = MockSource.drain_events(&mut out).expect("must not error");
        assert!(slice.is_empty());
    }

    #[test]
    fn test_drain_events_bounded_by_max() {
        use sg_common::traits::EbpfSource;

        struct FullSource { event: EbpfEvent }
        impl EbpfSource for FullSource {
            type Error = ();
            fn drain_events<'a>(&'a self, out: &'a mut [EbpfEvent; MAX_DRAIN_EVENTS])
                -> Result<&'a [EbpfEvent], ()> {
                for s in out.iter_mut() { *s = self.event; }
                Ok(&out[..MAX_DRAIN_EVENTS])
            }
            fn ringbuf_drop_count(&self) -> u64 { 0 }
            fn write_deny_map(&self, _: u32) -> Result<(), ()> { Ok(()) }
            fn write_fingerprint_map(&self, _: FlowKey) -> Result<(), ()> { Ok(()) }
        }

        let mut out = [EbpfEvent::default(); MAX_DRAIN_EVENTS];

// 1. On crée d'abord l'objet source dans une variable nommée
        let mut source = FullSource { event: EbpfEvent::default() };

// 2. On appelle drain_events sur cette variable
        let slice = source.drain_events(&mut out).expect("must not error");

// 3. Maintenant l'assertion est valide car 'source' est toujours en vie
        assert!(slice.len() <= MAX_DRAIN_EVENTS);
    }

    // ── IDEM ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_fp_params_default_is_inert() {
        let p = FpParams::default();
        assert_eq!(p.window_size, 0);
        assert_eq!(p.ttl,         0);
        assert_eq!(p.df_bit,      0);
        assert_eq!(p._reserved,   [0u8; 4]);
    }

    #[test]
    fn test_fp_params_size() {
        assert_eq!(core::mem::size_of::<FpParams>(), 8);
    }

    // ── SYNC ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_ready_flag_signal_and_clear() {
        let flag = ReadyFlag::new(false);
        assert!(!flag.poll_and_clear());
        flag.signal();
        assert!(flag.poll_and_clear());
        assert!(!flag.poll_and_clear());
    }

    // ── STRUCT ───────────────────────────────────────────────────────────────

    #[test]
    fn test_ebpf_event_default_is_zero() {
        let ev = EbpfEvent::default();
        assert_eq!(ev.timestamp_ns, 0);
        assert_eq!(ev.pid,          0);
        assert_eq!(ev.uid,          0);
        assert_eq!(ev.src_ip,       0);
        assert_eq!(ev.dst_ip,       0);
        assert_eq!(ev.src_port,     0);
        assert_eq!(ev.dst_port,     0);
        assert_eq!(ev.protocol,     0);
        assert_eq!(ev.event_type,   0);
        assert_eq!(ev._pad,         [0u8; 2]);
        assert_eq!(ev.comm,         [0u8; 16]);
    }

    // ── P1-EC-08 (hardware, ignored) ─────────────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires CAP_BPF + CAP_NET_ADMIN — run as root on Debian 13 target"]
    fn test_ebpf_probes_load() {
        use crate::loader::{EbpfLoader, LoadError, ProbeStatus};

        // Initialise env_logger so warn!/info! from loader.rs appear on stderr.
        let _ = env_logger::builder().is_test(true).try_init();

        let flag = ReadyFlag::new(false);

        let loader = match EbpfLoader::load("lo", &flag) {
            Ok(l)  => l,
            Err(LoadError::AllProbesFailed) => {
                // Try every available interface to find one that accepts XDP.
                let ifaces = ["lo", "wlo1", "eth0", "ens3", "enp2s0"];
                let mut found = None;
                for iface in &ifaces {
                    let f2 = ReadyFlag::new(false);
                    eprintln!("P1-EC-08: trying interface '{iface}'");
                    match EbpfLoader::load(iface, &f2) {
                        Ok(l)  => { found = Some(l); break; }
                        Err(e) => eprintln!("  → failed: {e}"),
                    }
                }
                found.expect("P1-EC-08: no interface accepted XDP — check kernel support")
            }
            Err(e) => panic!("EbpfLoader::load() failed (P1-EC-08): {e}"),
        };

        assert_eq!(
            loader.probe_status().packet_ingress,
            ProbeStatus::Attached,
            "packet_ingress must be Attached (P1-EC-08)"
        );
        assert!(flag.poll_and_clear(), "ReadyFlag must be signalled");
    }
}