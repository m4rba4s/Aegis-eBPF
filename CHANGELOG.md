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

## [3.0.0] — 2026-03-23

### Added
- **JA3/JA4 TLS fingerprinting** — detect C2 by TLS ClientHello hash (Cobalt Strike, Sliver, Havoc, etc.)
- **Alert webhooks** — Slack, PagerDuty, generic HTTP POST (SIEM/Splunk/ELK)
- **Config hot-reload** — update BPF module toggles and blocklist rules without restart
- **PCAP forensics** — write suspect packets to libpcap files with auto-rotation
- **IP reputation scoring** — multi-feed aggregator (blocklist, allowlist, CIDR, AbuseIPDB)
- **24h stats history** — in-memory ring buffer for time-series dashboard charts
- **DPI suspect queue** — non-blocking deep packet inspection via perf buffer
- **Kubernetes CNI plugin** — per-pod XDP firewall with DaemonSet + RBAC

### Security
- DPI auto-block: ≥80% confidence threats automatically inserted into BPF BLOCKLIST
- Known-bad JA3 database: 12 C2 framework fingerprints
- Write API endpoints gated by `X-Aegis-Token` header

## [2.0.0] — 2026-03-22

### Added
- **REST API** — 7 JSON endpoints on :9100 (stats, blocklist CRUD, config, feeds, GeoIP)
- **Web dashboard** — embedded SPA with dark theme, live auto-refresh, block/unblock controls
- **Per-CPU stats caching** — 1s TTL via tokio RwLock
- **GeoIP country blocking** — dynamic CIDR loading from ipdeny.com
- **eBPF CO-RE validation** — BTF debug info preserved for cross-kernel portability
- **Tracing migration** — structured JSON logging via tracing-subscriber
- **Prometheus /metrics** — standard Prometheus scrape endpoint
- **Man pages** — auto-generated via clap_mangen
- **RPM/DEB packaging** — build-packages.sh script
- **Systemd timer** — threat feed auto-refresh

### Security
- Entropy detection gated behind config toggle (avoids TLS/SSH false positives)
- API token validation for all write operations
- YAML/TOML bomb protection (1MB file size limit)
