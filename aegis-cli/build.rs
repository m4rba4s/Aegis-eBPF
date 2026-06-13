//! Build script for aegis-cli
//!
//! Embeds pre-compiled eBPF bytecode into the binary for single-file distribution.
//! If eBPF objects are not found, the binary will require external files at runtime.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_string())
        .filter(|output| !output.is_empty())
}

fn resolve_target_dir(workspace_root: &Path) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR").map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        Some(path) => workspace_root.join(path),
        None => workspace_root.join("target"),
    }
}

fn main() {
    // Tell cargo about custom cfg flags
    println!("cargo::rustc-check-cfg=cfg(embedded_xdp)");
    println!("cargo::rustc-check-cfg=cfg(embedded_tc)");
    // Re-run if eBPF objects change
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
    println!("cargo:rerun-if-env-changed=AEGIS_REQUIRE_EMBEDDED");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap();
    let target_dir = resolve_target_dir(workspace_root);
    let require_embedded = env::var_os("AEGIS_REQUIRE_EMBEDDED").is_some();

    // Check for XDP eBPF object
    let xdp_path = target_dir.join("bpfel-unknown-none/release/aegis");
    println!("cargo:rerun-if-changed={}", xdp_path.display());
    if xdp_path.exists() {
        let canonical = xdp_path.canonicalize().unwrap();
        println!("cargo:rustc-env=AEGIS_XDP_OBJ={}", canonical.display());
        println!("cargo:rustc-cfg=embedded_xdp");
        eprintln!("build.rs: Found XDP object at {}", canonical.display());
    } else {
        assert!(
            !require_embedded,
            "release build requires the XDP object at {}",
            xdp_path.display()
        );
        eprintln!(
            "build.rs: XDP object not found at {:?}, embedding disabled",
            xdp_path
        );
    }

    // Check for TC eBPF object
    let tc_path = target_dir.join("bpfel-unknown-none/release/aegis-tc");
    println!("cargo:rerun-if-changed={}", tc_path.display());
    if tc_path.exists() {
        let canonical = tc_path.canonicalize().unwrap();
        println!("cargo:rustc-env=AEGIS_TC_OBJ={}", canonical.display());
        println!("cargo:rustc-cfg=embedded_tc");
        eprintln!("build.rs: Found TC object at {}", canonical.display());
    } else {
        assert!(
            !require_embedded,
            "release build requires the TC object at {}",
            tc_path.display()
        );
        eprintln!(
            "build.rs: TC object not found at {:?}, embedding disabled",
            tc_path
        );
    }

    // ── Build metadata for --version ──────────────────────────
    let mut git_hash =
        command_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let worktree_dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| !output.stdout.is_empty());
    if worktree_dirty {
        git_hash.push_str("-dirty");
    }
    println!("cargo:rustc-env=AEGIS_GIT_HASH={}", git_hash);

    let build_date = env::var("SOURCE_DATE_EPOCH")
        .ok()
        .filter(|value| value.parse::<u64>().is_ok())
        .or_else(|| command_output("git", &["show", "-s", "--format=%cI", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=AEGIS_BUILD_DATE={}", build_date);

    let rustc_ver = command_output("rustc", &["--version"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=AEGIS_RUSTC={}", rustc_ver);

    println!("cargo:rerun-if-changed=../proto/aegis.proto");
    tonic_build::compile_protos("../proto/aegis.proto").unwrap();
}
