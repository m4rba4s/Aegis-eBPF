//! Build script for aegis-cli
//!
//! Embeds pre-compiled eBPF bytecode into the binary for single-file distribution.
//! If eBPF objects are not found, the binary will require external files at runtime.

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo about custom cfg flags
    println!("cargo::rustc-check-cfg=cfg(embedded_xdp)");
    println!("cargo::rustc-check-cfg=cfg(embedded_tc)");
    // Re-run if eBPF objects change
    println!("cargo:rerun-if-changed=../target/bpfel-unknown-none/release/aegis");
    println!("cargo:rerun-if-changed=../target/bpfel-unknown-none/release/aegis-tc");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap();

    // Check for XDP eBPF object
    let xdp_path = workspace_root.join("target/bpfel-unknown-none/release/aegis");
    if xdp_path.exists() {
        let canonical = xdp_path.canonicalize().unwrap();
        println!("cargo:rustc-env=AEGIS_XDP_OBJ={}", canonical.display());
        println!("cargo:rustc-cfg=embedded_xdp");
        eprintln!("build.rs: Found XDP object at {}", canonical.display());
    } else {
        eprintln!("build.rs: XDP object not found at {:?}, embedding disabled", xdp_path);
    }

    // Check for TC eBPF object
    let tc_path = workspace_root.join("target/bpfel-unknown-none/release/aegis-tc");
    if tc_path.exists() {
        let canonical = tc_path.canonicalize().unwrap();
        println!("cargo:rustc-env=AEGIS_TC_OBJ={}", canonical.display());
        println!("cargo:rustc-cfg=embedded_tc");
        eprintln!("build.rs: Found TC object at {}", canonical.display());
    } else {
        eprintln!("build.rs: TC object not found at {:?}, embedding disabled", tc_path);
    }
}
