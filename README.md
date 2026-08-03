# Aegis: eBPF Security Matrix
![Logo](https://i.ibb.co/xS3StSws/000aqaqaqaqaqaq.png)
> **Production-ready Rust/Aya XDP + TC firewall and traffic analyzer.**
> *Low-overhead packet filtering with verified runtime matrices and fuzzed parsers.*

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/built_with-Rust-red.svg)
![eBPF](https://img.shields.io/badge/tech-eBPF%2FXDP%2FTC-green.svg)

## Screenshot

![Preview](https://i.ibb.co/nqssBwBC/111111111111111111111111.png)

![Preview](https://i.ibb.co/Y7rRSymR/aegis2.png)

![Preview](https://i.ibb.co/4gF0MLMp/aegis1.png)

## Overview

**Aegis** is a Rust/Aya firewall built on **eBPF (Extended Berkeley Packet Filter)**, **XDP (eXpress Data Path)**, and **TC (Traffic Control)**. It filters ingress and egress traffic early in the networking stack.

## Portability

Aegis is distributed as a **statically linked single binary** with the eBPF bytecode embedded directly inside it.
- **Zero Dependencies**: You do not need `clang`, `llvm`, `bcc`, or `kernel-headers` on the deployment target.
- **Drop-in Execution**: The binary loads the pre-compiled eBPF object directly into the kernel using Aya.
- **Kernel Support**: Linux Kernel >= 5.4 (5.8+ recommended for CAP_BPF). See `docs/PORTABILITY.md` for the full matrix.


> ¹ *No measured throughput claim is made for this release candidate. Benchmark results require archived kernel, NIC/driver, XDP mode, CPU, packet-size, rule-count, and raw command output evidence.*

## Current Release Status (v4.3.0)

- **Non-privileged gates**: passing.
- **Privileged verifier/load/attach**: proven for v4.3.0.
- **Packet replay matrix**: proven 18/18 cases for v4.3.0.
- **Stress replay**: proven with sustained load for v4.3.0.
- **Production tag**: v4.3.0 is validated for General Availability (GA).

## Features Status & Claims

To maintain transparency as a security tool, features are strictly categorized by their current validation status:

### Implemented (Validated)
- **XDP Ingress Filtering** — Policy path implemented and verified for NIC-driver/SKB attach modes.
- **TC Egress Filtering** — Egress policy path implemented and verified.
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
- **Policy replacement** — Validate complete TOML/YAML files and restart the
  service. Live hot reload is disabled for this release candidate because
  entry-by-entry BPF map replacement is not atomic for packet processing.
- **Status Command** — Query running daemon state via pinned BPF maps
- **Single Binary** — eBPF bytecode embedded, no external files
- **Installer Scripts** — documented for the current release matrix in `docs/PORTABILITY.md`
- **Auto XDP Mode** — Automatic fallback from driver to SKB mode
- **Systemd Integration** — Hardened service file with `CAP_BPF` + `CAP_NET_ADMIN`

## Release Status

Production release claims are backed by archived verifier/load/attach/detach logs, packet replay artifacts, and extensive fuzzing campaigns.

- Portability matrix: [`docs/PORTABILITY.md`](docs/PORTABILITY.md)
- Release validation: [`docs/RELEASE_VALIDATION.md`](docs/RELEASE_VALIDATION.md)
- Known limitations: [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md)
- Troubleshooting and rollback: [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)

## Installation

### Prerequisites
- Linux Kernel **>= 5.4** (5.8+ recommended for CAP_BPF)
- Root privileges (for eBPF loading)

### Immutable Release Install

No `v4.3.0-rc.1` release asset is currently published. Do not use an assumed
release URL. After a release tag has passed the documented gates, download the
versioned bundle and its checksum file:

```bash
version="<published-version>"
bundle="aegis-${version}-x86_64-linux-musl.tar.gz"
base="https://github.com/m4rba4s/Aegis-eBPF/releases/download/v${version}"

curl -fLO "${base}/${bundle}"
curl -fLO "${base}/SHA256SUMS"
grep " ${bundle}$" SHA256SUMS | sha256sum -c -
gh attestation verify "${bundle}" -R m4rba4s/Aegis-eBPF
tar -xzf "${bundle}"
sudo ./install.sh --check
sudo ./install.sh --install-only
```

### Development Build From Source
```bash
git clone https://github.com/m4rba4s/Aegis-eBPF.git
cd Aegis-eBPF
sudo ./install.sh
```

The source path follows the checked-out revision and is not an immutable
release installation.

The installer will:
- Detect your distro and install dependencies
- Build from source (or use pre-built if available)
- Install both XDP and TC eBPF objects
- Install systemd service when available
- Create config directories

TC egress is required by default. `--no-tc` is an explicit ingress-only waiver.

Policy files are not applied live in this release candidate. After validating a
complete replacement, restart the instance:

```bash
sudo systemctl restart aegis@eth0
```

### Run Without Installing

```bash
# Build
cargo run --locked -p xtask -- build-all --profile release
cargo build --locked --release -p aegis-cli

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
3. eBPF programs compile with `cargo run --locked -p xtask -- build-all`

## Disclaimer

This tool is intended for **defensive security research** and **system hardening**. The author is not responsible for any misuse.

## License

MIT

---
*Crafted with Rust & eBPF*
