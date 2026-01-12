use std::process::Command;
use std::path::PathBuf;
use clap::Parser;

#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: CommandOpts,
}

#[derive(Parser)]
enum CommandOpts {
    BuildEbpf(BuildEbpfOpts),
    BuildTc(BuildTcOpts),
    BuildAll(BuildAllOpts),
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
            build_ebpf(BuildEbpfOpts { profile: opts.profile.clone() })?;
            build_tc(BuildTcOpts { profile: opts.profile })
        }
    }
}

fn build_ebpf(opts: BuildEbpfOpts) -> anyhow::Result<()> {
    let dir = PathBuf::from("aegis-ebpf");
    build_bpf_crate(&dir, &opts.profile, "aegis-ebpf")
}

fn build_tc(opts: BuildTcOpts) -> anyhow::Result<()> {
    let dir = PathBuf::from("aegis-tc");
    build_bpf_crate(&dir, &opts.profile, "aegis-tc")
}

fn build_bpf_crate(dir: &PathBuf, profile: &str, name: &str) -> anyhow::Result<()> {
    let target = "bpfel-unknown-none";
    let profile_arg = if profile == "release" { "--release" } else { "" };
    
    // BPF target requires building core from source
    let mut args = vec!["+nightly", "build", "-Zbuild-std=core", "--target", target];
    if !profile_arg.is_empty() {
        args.push(profile_arg);
    }

    println!("Building {} ...", name);
    let status = Command::new("cargo")
        .current_dir(dir)
        .args(&args)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build {}", name);
    }
    println!("✅ {} built successfully", name);
    Ok(())
}

