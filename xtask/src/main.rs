//! Aegis Build Tasks
//!
//! Build automation for eBPF programs.
//! IMPORTANT: All outputs go to workspace target/ directory for consistency.

use std::process::Command;
use std::path::PathBuf;
use std::env;
use clap::Parser;

#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: CommandOpts,
}

#[derive(Parser)]
enum CommandOpts {
    /// Build XDP firewall eBPF program
    BuildEbpf(BuildEbpfOpts),
    /// Build TC egress eBPF program
    BuildTc(BuildTcOpts),
    /// Build both XDP and TC programs
    BuildAll(BuildAllOpts),
    /// Clean all build artifacts
    Clean,
}

#[derive(Parser)]
pub struct BuildEbpfOpts {
    #[clap(long, default_value = "debug")]
    pub profile: String,
}

#[derive(Parser)]
pub struct BuildTcOpts {
    #[clap(long, default_value = "debug")]
    pub profile: String,
}

#[derive(Parser)]
pub struct BuildAllOpts {
    #[clap(long, default_value = "debug")]
    pub profile: String,
}

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();
    match opts.command {
        CommandOpts::BuildEbpf(opts) => build_ebpf(opts),
        CommandOpts::BuildTc(opts) => build_tc(opts),
        CommandOpts::BuildAll(opts) => {
            println!("🔨 Building all eBPF programs...\n");
            build_ebpf(BuildEbpfOpts { profile: opts.profile.clone() })?;
            println!();
            build_tc(BuildTcOpts { profile: opts.profile })?;
            println!("\n✅ All eBPF programs built successfully!");
            Ok(())
        }
        CommandOpts::Clean => {
            println!("🧹 Cleaning build artifacts...");
            let workspace_root = get_workspace_root()?;
            let status = Command::new("cargo")
                .current_dir(&workspace_root)
                .args(["clean"])
                .status()?;
            if status.success() {
                println!("✅ Clean complete");
            }
            Ok(())
        }
    }
}

fn build_ebpf(opts: BuildEbpfOpts) -> anyhow::Result<()> {
    let workspace_root = get_workspace_root()?;
    let crate_dir = workspace_root.join("aegis-ebpf");
    build_bpf_crate(&crate_dir, &workspace_root, &opts.profile, "aegis-ebpf", "aegis")
}

fn build_tc(opts: BuildTcOpts) -> anyhow::Result<()> {
    let workspace_root = get_workspace_root()?;
    let crate_dir = workspace_root.join("aegis-tc");
    build_bpf_crate(&crate_dir, &workspace_root, &opts.profile, "aegis-tc", "aegis-tc")
}

fn get_workspace_root() -> anyhow::Result<PathBuf> {
    // Try to find workspace root by looking for Cargo.toml with [workspace]
    let mut current = env::current_dir()?;

    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml)?;
            if content.contains("[workspace]") {
                return Ok(current);
            }
        }

        if !current.pop() {
            // Fallback: assume we're in xtask, go up one level
            return Ok(env::current_dir()?.parent().unwrap_or(&env::current_dir()?).to_path_buf());
        }
    }
}

fn build_bpf_crate(
    crate_dir: &PathBuf,
    workspace_root: &PathBuf,
    profile: &str,
    name: &str,
    bin_name: &str,
) -> anyhow::Result<()> {
    let target = "bpfel-unknown-none";
    let target_dir = workspace_root.join("target");

    println!("📦 Building {} ...", name);
    println!("   Crate:      {}", crate_dir.display());
    println!("   Target dir: {}", target_dir.display());
    println!("   Profile:    {}", profile);

    // Build arguments
    let mut args = vec![
        "+nightly".to_string(),
        "build".to_string(),
        "-Zbuild-std=core".to_string(),
        "--target".to_string(),
        target.to_string(),
        "--target-dir".to_string(),
        target_dir.to_string_lossy().to_string(),
    ];

    if profile == "release" {
        args.push("--release".to_string());
    }

    let status = Command::new("cargo")
        .current_dir(crate_dir)
        .args(&args)
        .status()?;

    if !status.success() {
        anyhow::bail!("❌ Failed to build {}", name);
    }

    // Verify output exists
    let profile_dir = if profile == "release" { "release" } else { "debug" };
    let output_path = target_dir
        .join(target)
        .join(profile_dir)
        .join(bin_name);

    if output_path.exists() {
        println!("✅ {} built successfully", name);
        println!("   Output: {}", output_path.display());
    } else {
        println!("⚠️  Build succeeded but output not found at expected path");
        println!("   Expected: {}", output_path.display());
    }

    Ok(())
}
