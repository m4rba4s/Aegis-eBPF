//! Aegis Build Tasks
//!
//! Build automation for eBPF programs.
//! Outputs follow CARGO_TARGET_DIR when configured, otherwise workspace target/.

use clap::Parser;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    #[clap(long, default_value = "release")]
    pub profile: String,
}

#[derive(Parser)]
pub struct BuildTcOpts {
    #[clap(long, default_value = "release")]
    pub profile: String,
}

#[derive(Parser)]
pub struct BuildAllOpts {
    #[clap(long, default_value = "release")]
    pub profile: String,
}

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();
    match opts.command {
        CommandOpts::BuildEbpf(opts) => build_ebpf(opts),
        CommandOpts::BuildTc(opts) => build_tc(opts),
        CommandOpts::BuildAll(opts) => {
            println!("🔨 Building all eBPF programs...\n");
            build_ebpf(BuildEbpfOpts {
                profile: opts.profile.clone(),
            })?;
            println!();
            build_tc(BuildTcOpts {
                profile: opts.profile,
            })?;
            println!("\n✅ All eBPF programs built successfully!");
            Ok(())
        }
        CommandOpts::Clean => {
            println!("🧹 Cleaning build artifacts...");
            let workspace_root = get_workspace_root()?;
            let target_dir = resolve_target_dir(
                &workspace_root,
                env::var_os("CARGO_TARGET_DIR").map(PathBuf::from),
            );
            let status = Command::new("cargo")
                .current_dir(&workspace_root)
                .arg("clean")
                .arg("--target-dir")
                .arg(&target_dir)
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
    build_bpf_crate(
        &crate_dir,
        &workspace_root,
        &opts.profile,
        "aegis-ebpf",
        "aegis",
    )
}

fn build_tc(opts: BuildTcOpts) -> anyhow::Result<()> {
    let workspace_root = get_workspace_root()?;
    let crate_dir = workspace_root.join("aegis-tc");
    build_bpf_crate(
        &crate_dir,
        &workspace_root,
        &opts.profile,
        "aegis-tc",
        "aegis-tc",
    )
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
            return Ok(env::current_dir()?
                .parent()
                .unwrap_or(&env::current_dir()?)
                .to_path_buf());
        }
    }
}

fn resolve_target_dir(workspace_root: &Path, configured: Option<PathBuf>) -> PathBuf {
    match configured {
        Some(path) if path.is_absolute() => path,
        Some(path) => workspace_root.join(path),
        None => workspace_root.join("target"),
    }
}

fn build_bpf_crate(
    crate_dir: &Path,
    workspace_root: &Path,
    profile: &str,
    name: &str,
    bin_name: &str,
) -> anyhow::Result<()> {
    let target = "bpfel-unknown-none";
    let target_dir = resolve_target_dir(
        workspace_root,
        env::var_os("CARGO_TARGET_DIR").map(PathBuf::from),
    );

    println!("📦 Building {} ...", name);
    println!("   Crate:      {}", crate_dir.display());
    println!("   Target dir: {}", target_dir.display());
    println!("   Profile:    {}", profile);

    // Build arguments
    let mut args = vec![
        "build".to_string(),
        "--locked".to_string(),
        "-Zbuild-std=core".to_string(),
        "--target".to_string(),
        target.to_string(),
        "--target-dir".to_string(),
        target_dir.to_string_lossy().to_string(),
    ];

    if profile == "release" {
        args.push("--release".to_string());
    }

    // Assemble RUSTFLAGS: always include -Cdebuginfo=2 for BTF generation.
    // bpf-linker converts DWARF → BTF; without it xdpdump/bpftool fail.
    // We use CARGO_ENCODED_RUSTFLAGS (0x1f-separated) to avoid conflicts
    // with any outer RUSTFLAGS the caller may have set.
    // NOTE: CARGO_ENCODED_RUSTFLAGS overrides .cargo/config.toml [target.*.rustflags],
    // so we must include -Clink-arg=--btf here as well.
    let mut rustflags = vec![
        "-Cdebuginfo=2".to_string(),
        "-Clink-arg=--btf".to_string(),
    ];

    // Preserve any existing CARGO_ENCODED_RUSTFLAGS from the environment
    if let Ok(existing) = env::var("CARGO_ENCODED_RUSTFLAGS") {
        for flag in existing.split('\x1f') {
            let flag = flag.trim();
            if !flag.is_empty()
                && !flag.starts_with("-Cdebuginfo")
                && flag != "-Clink-arg=--btf"
            {
                rustflags.push(flag.to_string());
            }
        }
    }

    let status = Command::new("cargo")
        .current_dir(crate_dir)
        .args(&args)
        .env("CARGO_ENCODED_RUSTFLAGS", rustflags.join("\x1f"))
        // Clear RUSTFLAGS to prevent interference (CARGO_ENCODED_RUSTFLAGS takes precedence)
        .env_remove("RUSTFLAGS")
        .status()?;


    if !status.success() {
        anyhow::bail!("❌ Failed to build {}", name);
    }

    // Verify output exists
    let profile_dir = if profile == "release" {
        "release"
    } else {
        "debug"
    };
    let output_path = target_dir.join(target).join(profile_dir).join(bin_name);

    if output_path.exists() {
        println!("✅ {} built successfully", name);
        println!("   Output: {}", output_path.display());
    } else {
        println!("⚠️  Build succeeded but output not found at expected path");
        println!("   Expected: {}", output_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::resolve_target_dir;
    use std::path::{Path, PathBuf};

    #[test]
    fn target_dir_defaults_to_workspace_target() {
        assert_eq!(
            resolve_target_dir(Path::new("/workspace"), None),
            PathBuf::from("/workspace/target")
        );
    }

    #[test]
    fn target_dir_resolves_relative_to_workspace() {
        assert_eq!(
            resolve_target_dir(
                Path::new("/workspace"),
                Some(PathBuf::from("build/release"))
            ),
            PathBuf::from("/workspace/build/release")
        );
    }

    #[test]
    fn target_dir_preserves_absolute_path() {
        assert_eq!(
            resolve_target_dir(
                Path::new("/workspace"),
                Some(PathBuf::from("/tmp/aegis-target"))
            ),
            PathBuf::from("/tmp/aegis-target")
        );
    }
}
