use std::{env, path::PathBuf};

fn main() {
    // Declare the custom cfg name so rustc's check-cfg lint accepts it.
    // Must appear before any `rustc-cfg` emission for the same name.
    println!("cargo::rustc-check-cfg=cfg(sg_ebpf_objects_missing)");

    println!("cargo:rerun-if-changed=bpf/");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"),
    );
    let bpf_dir = manifest_dir.join("bpf");

    let objects = [
        "packet_ingress.bpf.o",
        "execve_monitor.bpf.o",
        "tcp_fp_probe.bpf.o",
    ];

    let mut missing = false;
    for obj in &objects {
        let path = bpf_dir.join(obj);
        if !path.exists() {
            println!("cargo:warning=eBPF object not found: {}", path.display());
            println!("cargo:warning=Run the BPF build step to produce it.");
            missing = true;
        }
    }

    if missing {
        println!("cargo:rustc-cfg=sg_ebpf_objects_missing");
    }
}