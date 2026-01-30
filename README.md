# Aegis: eBPF Security Matrix

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
| Deployment | Multiple packages | **Single binary** |

## Features

### Core
- **XDP Ingress Filtering** — Drop packets at NIC driver level
- **TC Egress Filtering** — Block outbound connections to malicious destinations
- **Stateful Connection Tracking** — Native eBPF conntrack (no kernel module)
- **CIDR Blocklists** — LPM Trie for efficient prefix matching
- **IPv4 + IPv6 Support** — Dual-stack filtering

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

### Deployment
- **Single Binary** — eBPF bytecode embedded, no external files needed
- **Multi-Distro Support** — Fedora, Ubuntu, Debian, Arch, Alpine, and more
- **Auto XDP Mode** — Automatic fallback from driver to SKB mode
- **Systemd Integration** — Hardened service file included

## Installation

### Prerequisites
- Linux Kernel **>= 5.4** (5.8+ recommended for CAP_BPF)
- Root privileges (for eBPF loading)

### Quick Install (Recommended)

```bash
# Clone and install
git clone https://github.com/m4rba4s/Aegis-Portable-Demo.git
cd Aegis-Portable-Demo
sudo ./install.sh
```

The installer will:
- Detect your distro and install dependencies
- Build from source (or use pre-built if available)
- Install systemd service
- Create config directories

### Run Without Installing

```bash
# Build
cargo run -p xtask -- build-all --profile release
cargo build --release -p aegis-cli

# Run (eBPF is embedded in binary)
sudo ./target/release/aegis-cli -i eth0 tui
```

### Docker Build

```bash
# Build release binaries in Docker
docker build --output=dist .

# Outputs:
# dist/aegis-cli     - Main binary (eBPF embedded)
# dist/aegis         - Standalone XDP object (optional)
# dist/aegis-tc      - Standalone TC object (optional)
```

## Usage

### TUI Mode (Recommended)
```bash
sudo aegis-cli -i eth0 tui
sudo aegis-cli -i wg0 tui           # VPN interface
sudo aegis-cli -i eth0 --no-tc tui  # XDP only, no egress filtering
```

**Controls:**
| Key | Action |
|-----|--------|
| `Tab` | Switch tabs (Connections / Stats / Logs) |
| `↑/↓` or `j/k` | Navigate list |
| `Space` | Block/Unblock selected IP |
| `1-5` | Toggle modules (PortScan, RateLimit, Threats, ConnTrack, ScanDetect) |
| `6` | Toggle verbose logging |
| `0` | Toggle ALL modules |
| `q` | Quit |

### Daemon Mode
```bash
# Start as background service
sudo systemctl start aegis@eth0

# Or run directly
sudo aegis-cli -i eth0 daemon
```

### CLI Mode
```bash
sudo aegis-cli -i eth0 load
# Interactive commands:
# block 1.2.3.4
# unblock 1.2.3.4
# list
# save / restore
```

### Override Embedded eBPF (Advanced)
```bash
# Use custom eBPF objects instead of embedded
sudo aegis-cli \
  --ebpf-path /custom/path/aegis.o \
  --tc-path /custom/path/aegis-tc.o \
  -i eth0 tui
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      KERNEL SPACE                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐           ┌─────────────┐                  │
│  │  aegis-ebpf │           │  aegis-tc   │                  │
│  │   (XDP)     │           │ (TC Egress) │                  │
│  │  INGRESS    │           │  EGRESS     │                  │
│  └──────┬──────┘           └──────┬──────┘                  │
│         │                         │                          │
│         └──────────┬──────────────┘                          │
│                    ▼                                         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                SHARED BPF MAPS                       │    │
│  │  BLOCKLIST | CONN_TRACK | CONFIG | STATS | FEEDS    │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼ PerfEventArray
┌─────────────────────────────────────────────────────────────┐
│                      USER SPACE                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │            aegis-cli (Rust/Tokio)                    │    │
│  │  ┌──────────────────────────────────────────────┐   │    │
│  │  │  EMBEDDED eBPF BYTECODE (XDP + TC objects)   │   │    │
│  │  └──────────────────────────────────────────────┘   │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────────────┐     │    │
│  │  │   TUI   │  │  Event  │  │  Map Management │     │    │
│  │  │(ratatui)│  │  Loop   │  │  (aya)          │     │    │
│  │  └─────────┘  └─────────┘  └─────────────────┘     │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
Aegis-eBPF/
├── aegis-common/       # Shared types (Single Source of Truth)
│   └── src/lib.rs      # PacketLog, Stats, FlowKey, constants
├── aegis-ebpf/         # XDP ingress program
│   └── src/main.rs     # Packet filtering, rate limiting, scan detection
├── aegis-tc/           # TC egress program
│   └── src/main.rs     # Outbound connection blocking
├── aegis-cli/          # Userspace controller
│   ├── build.rs        # Embeds eBPF bytecode at compile time
│   ├── src/main.rs     # Program loader, event handler
│   ├── src/tui/        # Terminal UI (ratatui)
│   ├── src/compat.rs   # Kernel capability detection
│   └── src/feeds/      # Threat feed parser/downloader
├── xtask/              # Build automation
├── deploy/             # Systemd service files
├── Dockerfile          # Reproducible builds
└── install.sh          # Multi-distro installer
```

## Supported Distributions

| Distro | Package Manager | Init System | Status |
|--------|-----------------|-------------|--------|
| Fedora | dnf | systemd | Tested |
| Ubuntu/Debian | apt | systemd | Tested |
| Arch Linux | pacman | systemd | Tested |
| Alpine | apk | openrc | Supported |
| RHEL/CentOS | dnf/yum | systemd | Supported |
| openSUSE | zypper | systemd | Supported |

## Roadmap

### Completed
- [x] XDP ingress filtering
- [x] TC egress filtering
- [x] Connection tracking
- [x] Port scan detection
- [x] Rate limiting
- [x] IPv6 support (basic)
- [x] Single binary distribution
- [x] Multi-distro installer

### In Progress
- [ ] IPv6 extension header security checks
- [ ] Threat feed auto-update

### Planned
- [ ] Web Dashboard (REST API + web UI)
- [ ] Prometheus metrics export
- [ ] Kubernetes CNI plugin
- [ ] eBPF-based DPI

## Contributing

PRs welcome! Please ensure:
1. `cargo fmt` passes
2. `cargo clippy` has no warnings
3. eBPF programs compile with `cargo run -p xtask -- build-all`

## Disclaimer

This tool is intended for **defensive security research** and **system hardening**. The author is not responsible for any misuse.

## License

MIT

---
*Crafted with Rust & eBPF*
