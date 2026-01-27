# ⛨ Aegis: eBPF Security Matrix

> **High-Performance XDP/TC Firewall & Traffic Analyzer written in Rust.**
> *Zero-overhead packet filtering, stateful connection tracking, and heuristic intrusion detection.*

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/built_with-Rust-red.svg)
![eBPF](https://img.shields.io/badge/tech-eBPF%2FXDP%2FTC-green.svg)

## Screenshot

![Preview](https://i.ibb.co/MxCSqHP5/20250801-112625.png)

## Overview

**Aegis** is a next-generation firewall built on **eBPF (Extended Berkeley Packet Filter)**, **XDP (eXpress Data Path)**, and **TC (Traffic Control)**. It operates at the earliest possible point in the networking stack, filtering both ingress and egress traffic before the OS kernel processes it.

### Why Aegis?

| Feature | iptables/nftables | Aegis |
|---------|-------------------|-------|
| Packet processing | Kernel netfilter | XDP (driver level) |
| Performance | ~1M pps | **10M+ pps** |
| Egress filtering | Yes | Yes (TC) |
| Connection tracking | Conntrack module | **Native eBPF** |
| Real-time TUI | No | **Yes** |
| Memory safety | C | **Rust** |

## Features

### Core
- **XDP Ingress Filtering** — Drop packets at NIC driver level
- **TC Egress Filtering** — Block outbound connections to malicious destinations
- **Stateful Connection Tracking** — Native eBPF conntrack (no kernel module)
- **CIDR Blocklists** — LPM Trie for efficient prefix matching

### Detection
- **Port Scan Detection** — Bitmap-based unique port tracking
- **SYN Flood Protection** — Token bucket rate limiting
- **TCP Anomaly Detection**:
  - Xmas Tree Scans (FIN+URG+PSH)
  - Null Scans (no flags)
  - SYN+FIN (illegal combination)

### Interface
- **Interactive TUI** — Real-time dashboard with tabs:
  - Connections view with geo-location
  - Live statistics with sparklines
  - Security event log
- **Module Hotkeys** — Toggle protection modules on-the-fly
- **Space-to-Ban** — One-key IP blocking

## Installation

### Prerequisites
- Linux Kernel **>= 5.8** with BTF support
- Rust Toolchain (nightly for eBPF)
- `bpf-linker` installed

### Quick Install
```bash
# Clone
git clone https://github.com/m4rba4s/Aegis-eBPF.git
cd Aegis-eBPF

# Build
cargo run -p xtask -- build-all --profile release
cargo build --release -p aegis-cli

# Install system-wide
sudo ./install.sh
```

### Manual Build
```bash
# Build eBPF programs (XDP + TC)
cargo run -p xtask -- build-all --profile release

# Build CLI
cargo build --release -p aegis-cli

# Run directly
sudo ./target/release/aegis-cli \
  --ebpf-path ./target/bpfel-unknown-none/release/aegis \
  --tc-path ./target/bpfel-unknown-none/release/aegis-tc \
  -i eth0 tui
```

## Usage

### TUI Mode (Recommended)
```bash
sudo aegis-cli -i wg0-mullvad tui
sudo aegis-cli -i eth0 tui
sudo aegis-cli -i eth0 --no-tc tui  # XDP only, no egress filtering
```

**Controls:**
| Key | Action |
|-----|--------|
| `Tab` | Switch tabs (Connections → Stats → Logs) |
| `↑/↓` or `j/k` | Navigate list |
| `Space` | Block/Unblock selected IP |
| `1-5` | Toggle modules (PortScan, RateLimit, Threats, ConnTrack, ScanDetect) |
| `6` | Toggle verbose logging |
| `0` | Toggle ALL modules |
| `q` | Quit |

### Daemon Mode
```bash
# Run as systemd service
sudo aegis-cli -i eth0 daemon
```

### CLI Mode
```bash
sudo aegis-cli -i eth0 load
# Then use commands:
# block 1.2.3.4
# unblock 1.2.3.4
# list
# save / restore
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    KERNEL SPACE                         │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐     ┌─────────────┐                   │
│  │  aegis-ebpf │     │  aegis-tc   │                   │
│  │   (XDP)     │     │ (TC Egress) │                   │
│  │  INGRESS    │     │  EGRESS     │                   │
│  └──────┬──────┘     └──────┬──────┘                   │
│         │                   │                           │
│         └───────┬───────────┘                           │
│                 ▼                                       │
│  ┌─────────────────────────────────────────────────┐   │
│  │              SHARED BPF MAPS                     │   │
│  │  BLOCKLIST | CONN_TRACK | CONFIG | STATS | ...   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼ PerfEventArray
┌─────────────────────────────────────────────────────────┐
│                    USER SPACE                           │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │              aegis-cli (Rust/Tokio)              │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────────┐  │   │
│  │  │   TUI   │  │  Event  │  │  Map Management │  │   │
│  │  │(ratatui)│  │  Loop   │  │  (aya)          │  │   │
│  │  └─────────┘  └─────────┘  └─────────────────┘  │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Roadmap

### In Progress
- [ ] **CO-RE (Compile Once, Run Everywhere)** — BTF-based portability across kernel versions
- [ ] **Pinned Maps** — Shared state between XDP and TC via `/sys/fs/bpf/`
- [ ] **IPv6 Support** — Full dual-stack filtering

### Planned
- [ ] **Threat Feed Integration** — Auto-update from Spamhaus, AbuseIPDB, etc.
- [ ] **Web Dashboard** — Optional REST API + web UI
- [ ] **Prometheus Metrics** — Export stats for Grafana
- [ ] **eBPF-based DPI** — Deep packet inspection for protocol detection
- [ ] **Kubernetes CNI Plugin** — Network policy enforcement

## Project Structure

```
Aegis-eBPF/
├── aegis-common/    # Shared types (Single Source of Truth)
│   └── src/lib.rs   # PacketLog, Stats, FlowKey, ConnTrack*, etc.
├── aegis-ebpf/      # XDP ingress program
│   └── src/main.rs  # Packet filtering, rate limiting, scan detection
├── aegis-tc/        # TC egress program
│   └── src/main.rs  # Outbound connection blocking
├── aegis-cli/       # Userspace controller
│   ├── src/main.rs  # Program loader, event handler
│   └── src/tui/     # Terminal UI (ratatui)
├── xtask/           # Build automation
└── deploy/          # Systemd service files
```

## Contributing

PRs welcome! Please ensure:
1. `cargo fmt` passes
2. `cargo clippy` has no warnings
3. eBPF programs compile with `cargo run -p xtask -- build-all`

## Disclaimer

This tool is intended for **defensive security research** and **system hardening**. The author is not responsible for any misuse.

---
*Crafted with ⚡&❤️*
