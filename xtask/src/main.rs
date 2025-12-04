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
}

#[derive(Parser)]
pub struct BuildEbpfOpts {
    #[clap(long, default_value = "debug")]
    pub profile: String,
}

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();
    match opts.command {
        CommandOpts::BuildEbpf(opts) => build_ebpf(opts),
    }
}

fn build_ebpf(opts: BuildEbpfOpts) -> anyhow::Result<()> {
    let dir = PathBuf::from("aegis-ebpf");
    let target = "bpfel-unknown-none";
    let profile_arg = if opts.profile == "release" { "--release" } else { "" };
    
    let mut args = vec!["+nightly", "build", "--target", target];
    if !profile_arg.is_empty() {
        args.push(profile_arg);
    }

    let status = Command::new("cargo")
        .current_dir(&dir)
        .args(&args)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build ebpf program");
    }
    Ok(())
}
