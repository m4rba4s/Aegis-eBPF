#  Aegis: eBPF Security Matrix

> **High-Performance XDP Firewall & Traffic Analyzer written in Rust.**
> *Zero-overhead packet filtering, TUI dashboard, and heuristic intrusion detection.*

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/built_with-Rust-red.svg)
![eBPF](https://img.shields.io/badge/tech-eBPF%2FXDP-green.svg)

## Screenshot

![Preview](https://i.ibb.co/6Rr7FPHC/1111.png)

## Overview

**Aegis** is a next-generation firewall built on **eBPF (Extended Berkeley Packet Filter)** and **XDP (eXpress Data Path)**. It operates at the earliest possible point in the networking stack (driver level), allowing it to drop malicious traffic before the OS kernel even processes it.

Unlike traditional firewalls (iptables/nftables), Aegis is:
-   **Blazing Fast**: Handles millions of packets per second (Mpps).
-   **Safe**: Verified by the kernel verifier to ensure system stability.
-   **Interactive**: Features a cyberpunk-style TUI for real-time monitoring.

##  Features

-   **XDP Packet Filtering**: Drop packets at the NIC driver level.
-   **Interactive TUI**: Real-time dashboard with active connections, logs, and "Space-to-Ban" mechanics.
-   **Heuristic Analysis**: Automatically detects and drops suspicious scans:
    -   Xmas Tree Scans (FIN+URG+PSH)
    -   Null Scans
    -   Illegal Flag Combinations (SYN+FIN)
-   **Geolocation**: Instant Country/City lookup for connected IPs.
-   **Persistence**: Save and restore rules to YAML.
-   **Portability**: Statically linked (Rustls), runs on any Linux Kernel 5.8+ with BTF.

##  Installation

### Prerequisites
-   Linux Kernel **>= 5.8**
-   BTF Support (`/sys/kernel/btf/vmlinux` must exist)
-   Rust Toolchain (stable)

### Build
```bash
# 1. Install dependencies (Fedora/RHEL)
sudo dnf install elfutils-libelf-devel zlib-devel

# 2. Build eBPF and User-space CLI
cargo build --release
```

## 🎮 Usage

### 1. Interactive TUI (Recommended)
Launch the tactical dashboard:
```bash
sudo ./target/release/aegis-cli --iface <INTERFACE> tui
```
*   **Up/Down**: Navigate connections.
*   **Space**: Ban/Unblock selected IP.
*   **q**: Exit to REPL.

### 2. CLI / REPL Mode
```bash
sudo ./target/release/aegis-cli --iface eth0 load
```
Inside the REPL:
-   `block 1.2.3.4` - Block an IP.
-   `block 1.2.3.4 80 6` - Block IP on Port 80 (TCP).
-   `list` - Show active rules.
-   `save` / `restore` - Manage configuration.

##  Architecture

-   **Kernel Space (`aegis-ebpf`)**:
    -   Written in Rust (Aya).
    -   Parses TCP/IP headers.
    -   Enforces `BLOCKLIST` (LPM Trie / HashMap).
    -   Streams `EVENTS` via PerfEventArray.
-   **User Space (`aegis-cli`)**:
    -   Loads BPF programs.
    -   Manages maps.
    -   Renders TUI (`ratatui`).
    -   Handles GeoIP and logging.

## ⚠️ Disclaimer
This tool is intended for **defensive security research** and **system hardening**. The author is not responsible for any misuse.

---
*Crafted with 💀 by Mindlock*
