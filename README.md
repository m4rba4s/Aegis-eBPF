# Aegis: eBPF Security Matrix
![Logo](https://i.ibb.co/xS3StSws/000aqaqaqaqaqaq.png)
> **Experimental Rust/Aya XDP + TC firewall and traffic analyzer.**
> *Low-overhead packet filtering with release evidence still pending for production claims.*

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/built_with-Rust-red.svg)
![eBPF](https://img.shields.io/badge/tech-eBPF%2FXDP%2FTC-green.svg)

## Screenshot

![Preview](https://i.ibb.co/nqssBwBC/111111111111111111111111.png)

![Preview](https://i.ibb.co/Y7rRSymR/aegis2.png)

![Preview](https://i.ibb.co/4gF0MLMp/aegis1.png)

## Overview

**Aegis** is a Rust/Aya firewall built on **eBPF (Extended Berkeley Packet Filter)**, **XDP (eXpress Data Path)**, and **TC (Traffic Control)**. It filters ingress and egress traffic early in the networking stack, with runtime support bounded by the evidence matrix in `docs/PORTABILITY.md`.

### Why Aegis?

| Feature | iptables/nftables | Aegis |
|---------|-------------------|-------|
| Packet processing | Kernel netfilter | XDP (driver level) |
| Performance | Measured by deployment | **Benchmark pending** ¹ |
| Egress filtering | Yes | Yes (TC) |
| Connection tracking | Conntrack module | **Experimental eBPF state tracking** |
| Real-time TUI | No | **Yes** |
| Memory safety | C | **Rust** |
| Deployment | Multiple packages | **Single binary** |

> ¹ *No measured throughput claim is made for this release candidate. Benchmark results require archived kernel, NIC/driver, XDP mode, CPU, packet-size, rule-count, and raw command output evidence.*

## Current Release Status

- **Non-privileged gates**: passing on latest local validation; rerun before every tag.
- **Privileged verifier/load/attach**: pending for the current release candidate.
- **Packet replay matrix**: pending for the current release candidate.
- **Stress replay**: pending for the current release candidate.
- **Production tag**: blocked until privileged lab evidence is archived.

## Features Status & Claims

To maintain transparency as a security tool, features are strictly categorized by their current validation status:

### Implemented (Release Evidence Pending)
- **XDP Ingress Filtering** — Policy path implemented for NIC-driver/SKB attach modes; current release requires privileged verifier/load/attach and replay evidence before production claims.
- **TC Egress Filtering** — Egress policy path implemented; current release requires TC attach and replay evidence before production claims.
- **IPv4 + IPv6 Basic Filtering** — Dual-stack support with strict IP/CIDR blocklists
- **IP Allowlist** — Trusted IPs bypass checks
- **CIDR Blocklists** — LPM Trie matching

### Experimental (Beta)
- **Stateful Connection Tracking** — Native eBPF conntrack (currently tracks SYN/ACK state, no deep stream reassembly)
- **Dynamic Auto-Ban** — Userspace threat mitigation loop
- **Port Scan Detection** — Bitmap-based unique port tracking with auto-ban
- **SYN Flood Protection** — Token bucket rate limiting at XDP layer

### Theoretical / Benchmark Pending
- **Throughput** — XDP driver mode is expected to be low overhead, but no pps number is claimed without benchmark artifacts.

### Planned v2 (Deferred / Stubbed)
- **TLS ClientHello Fingerprinting** — Native eBPF TLS payload extraction for JA3 scoring (map exists, DPI deferred to v2)
- **Heuristic Intrusion Detection** — Advanced protocol anomaly detection beyond basic TCP flags
- **IPv6 Extension Header Coverage** — Limited today; exact/CIDR IPv6 policy paths exist, while full extension-header replay coverage is pending.
- **VLAN / QinQ Payload Parsing** — Currently fails-closed (drops all tagged frames)

### Interface
- **Interactive TUI** (fd-isolated — zero stdout pollution):
  - Connections view with **offline GeoIP** lookup (MaxMind GeoLite2)
  - Live statistics with sparklines (packets/sec, drops/sec)
  - Security event log
  - ISP/Geo/Country display per connection
- **Module Hotkeys** — Toggle PortScan, RateLimit, Threats, ConnTrack, ScanDetect, Verbose on-the-fly
- **Space-to-Ban** — One-key IP blocking from connections list
- **Daemon Mode** — Background operation with stdout log printer
- **JSON Logging** — Machine-readable output for SIEM integration
- **Shell Completions** — bash, zsh, fish, PowerShell, elvish

### Operations
- **TOML Config File** — `/etc/aegis/config.toml` for persistent settings
- **Threat Feeds** — Download and load CIDR blocklists from public sources
- **Save/Restore** — Persist and reload block rules
- **Status Command** — Query running daemon state via pinned BPF maps
- **Single Binary** — eBPF bytecode embedded, no external files
- **Installer Scripts** — documented for the current release matrix in `docs/PORTABILITY.md`
- **Auto XDP Mode** — Automatic fallback from driver to SKB mode
- **Systemd Integration** — Hardened service file with `CAP_BPF` + `CAP_NET_ADMIN`

## Release Status

Production release claims require archived verifier/load/attach/detach logs and packet replay artifacts. Build/test success alone is not firewall enforcement proof.

- Portability matrix: [`docs/PORTABILITY.md`](docs/PORTABILITY.md)
- Release validation: [`docs/RELEASE_VALIDATION.md`](docs/RELEASE_VALIDATION.md)
- Troubleshooting and rollback: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)

## Installation

### Prerequisites
- Linux Kernel **>= 5.4** (5.8+ recommended for CAP_BPF)
- Root privileges (for eBPF loading)

### Quick Install (Recommended)

### One-Line Install (SSH/Remote)
```bash
curl -sSfL https://github.com/m4rba4s/Aegis-eBPF/releases/download/v4.3.0-rc.1/install.sh -o install.sh
sha256sum install.sh
sudo bash install.sh --check
```

### Manual Install
```bash
# Clone and install
git clone https://github.com/m4rba4s/Aegis-eBPF.git
cd Aegis-eBPF
sudo ./install.sh
```

The installer will:
- Detect your distro and install dependencies
- Build from source (or use pre-built if available)
- Install both XDP and TC eBPF objects
- Install systemd service when available
- Create config directories

TC egress is required by default. `--no-tc` is an explicit ingress-only waiver.

### Run Without Installing

```bash
# Build
cargo run -p xtask -- build-all --profile release
cargo build --release -p aegis-cli

# Run (eBPF is embedded in binary)
sudo ./target/release/aegis-cli -i eth0 tui
```

### Docker Build (Portable Static Binary)

```bash
# Build fully static musl binary for the documented x86_64 Linux release matrix
docker build --output=dist .

# Outputs:
# dist/aegis-cli     - Static binary (eBPF embedded, no glibc dependency)
# dist/aegis         - Standalone XDP object (optional)
# dist/aegis-tc      - Standalone TC object (optional)
```

The Docker build produces a **statically linked musl binary**. Static linking
removes the glibc dependency, but it does not prove kernel, XDP, or TC runtime
support. Distribution support is evidence-bound; see
[docs/PORTABILITY.md](docs/PORTABILITY.md).

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

### Rule File
`aegis.yaml` supports ingress source blocks and TC egress destination blocks:
```yaml
rules:
  - ip: 198.51.100.10
    port: 443
    proto: tcp

egress_rules:
  - ip: 203.0.113.20
  - ip: 2001:db8::20

egress_cidrs:
  - cidr: 203.0.113.0/24
  - cidr: 2001:db8:bad::/48
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
│  │                BPF MAPS / RING BUFFERS               │    │
│  │  BLOCKLIST | CONFIG | STATS | FEEDS | TC CONN_TRACK │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼ BPF RingBuf
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
│   └── src/lib.rs      # PacketLog, Stats, FlowKey, threat/reason constants
├── aegis-ebpf/         # XDP ingress program (no_std, eBPF target)
│   └── src/main.rs     # Packet filtering, rate limiting, scan detection, TLS parsing
├── aegis-tc/           # TC egress program
│   └── src/main.rs     # Outbound connection blocking
├── aegis-cli/          # Userspace controller
│   ├── build.rs        # Embeds eBPF bytecode at compile time
│   ├── src/main.rs     # Application bootstrapper
│   ├── src/event_loop.rs # MPSC Lock-Free Perf Event consumers
│   ├── src/loader.rs   # eBPF/TC program lifecycles
│   ├── src/map_manager.rs # Map pinning, sizing, and threat feeds
│   ├── src/conntrack_gc.rs # Ktime-synced map garbage collection
│   ├── src/tui/        # Terminal UI (ratatui, fd-isolated)
│   ├── src/config.rs   # TOML config parser
│   ├── src/geo.rs      # Offline GeoIP (MaxMind GeoLite2)
│   ├── src/compat.rs   # Kernel capability detection
│   └── src/feeds/      # Threat feed parser/downloader
├── guide/              # Operational & Architectural Engineering Guides
├── deploy/             # Systemd service files
├── Dockerfile          # Reproducible builds
└── install.sh          # Multi-distro installer
```

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
