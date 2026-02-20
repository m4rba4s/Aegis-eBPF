# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2025-02-19

### Added
- **XDP ingress filtering** — drop packets at NIC driver level
- **TC egress filtering** — block outbound to malicious destinations
- **Stateful connection tracking** — native eBPF conntrack
- **CIDR blocklists** — LPM Trie for efficient prefix matching
- **IPv4 + IPv6 dual-stack** filtering
- **Port scan detection** — bitmap-based unique port tracking
- **SYN flood protection** — token bucket rate limiting
- **TCP anomaly detection** — Xmas, Null, SYN+FIN scans
- **Interactive TUI** — real-time dashboard with geo-location, sparklines, module hotkeys
- **Single binary distribution** — eBPF bytecode embedded at compile time
- **Multi-distro installer** — Fedora, Ubuntu, Debian, Arch, Alpine, RHEL, openSUSE
- **Multi-init support** — systemd, OpenRC, SysVinit
- **Threat feed integration** — download and load IP blocklists
- **CI pipeline** — build, lint, audit, verify on every push

### Security
- IPv6 extension header bypass fixed (fail-closed policy)
- Debug ELF header leak removed from production builds
- Feed download size limited to 10 MB
- Auto-ban hardened: dedup + 512 entry cap
- Entropy detection disabled by default (breaks TLS/SSH)
- Systemd service hardened with CapabilityBoundingSet
- Interface name validated against IFNAMSIZ
- Dockerfile build runs as non-root user

## [Unreleased]
- Threat feed auto-update scheduler
- Web dashboard (REST API)
- Prometheus metrics export
