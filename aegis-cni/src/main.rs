//! Aegis CNI Plugin — Kubernetes per-pod eBPF firewall
//!
//! Implements the CNI specification (v0.4.0+):
//!   - ADD:   Attach XDP program to pod veth, apply pod-specific policy
//!   - DEL:   Detach XDP program from pod veth
//!   - CHECK: Verify XDP attachment is healthy
//!   - VERSION: Report supported CNI versions
//!
//! Usage: Called by kubelet via CNI chain. Config read from stdin,
//! environment variables provide container ID, netns, and interface name.
//!
//! Design: This is a **chain plugin** — it does not configure networking,
//! it only attaches/detaches the Aegis XDP firewall to existing interfaces.

mod cni;

use std::io::{self, Read};

fn main() {
    let command = std::env::var("CNI_COMMAND").unwrap_or_default();
    let container_id = std::env::var("CNI_CONTAINERID").unwrap_or_default();
    let netns = std::env::var("CNI_NETNS").unwrap_or_default();
    let ifname = std::env::var("CNI_IFNAME").unwrap_or_default();

    // Read CNI config from stdin
    let mut stdin_buf = String::new();
    let _ = io::stdin().read_to_string(&mut stdin_buf);

    let result = match command.as_str() {
        "ADD" => cni::handle_add(&container_id, &netns, &ifname, &stdin_buf),
        "DEL" => cni::handle_del(&container_id, &netns, &ifname),
        "CHECK" => cni::handle_check(&container_id, &netns, &ifname),
        "VERSION" => cni::handle_version(),
        _ => Err(anyhow::anyhow!("unknown CNI command: {}", command)),
    };

    match result {
        Ok(output) => {
            println!("{}", output);
        }
        Err(e) => {
            let err = cni::cni_error(100, &format!("{}", e));
            eprintln!("{}", err);
            println!("{}", err);
            std::process::exit(1);
        }
    }
}
