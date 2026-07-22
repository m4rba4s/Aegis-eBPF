# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v4.3.0-rc.1] - 2026-07-22

### Added
- **Install:** Added `check_rp_filter()` advisory in `install.sh` for source validation preflight.
- **Testing:** Added scapy scripts for operator and lab testing (`ipv6_fragment_bypass.py`, `ipv6_rh0_bypass.py`, `ipv4_spoof_cgnat.py`).

### Fixed
- **Security (P0-1):** Closed IPv6 Fragment Header bypass by dropping all fragments (fail-closed) at XDP/TC layer.
- **Security (P0-2):** Closed RH0 (Routing Header Type 0) bypass (RFC 5095) by enforcing drops on `routing_type == 0`.
- **Security (P1-1):** Trimmed spoofable whitelist; CGNAT (100.64/10) and loopback (127/8) are no longer trusted by default.
- **UI/Telemetry:** Display actual `conntrack_entries` correctly across JSON API, CLI, and TUI instead of the always-zero `conntrack_hits`.
- **Documentation:** Fixed stale `BLOCKLIST` capacity comment in event-loop code.
- **Documentation:** Corrected misleading comments flagged by red-team audit in eBPF source.

### Changed
- **Refactoring:** Modernized telemetry API to expose real `conntrack_entries` as a gauge, while maintaining `conntrack_hits` at 0 for backward compatibility.
- **Architecture:** Labeled `conntrack` explicitly as a telemetry-only sink across surfaces (not a security control).
- **Testing:** Hardened ABI canary tests to verify struct sizes and field offsets, preventing silent memory drifts between userspace and eBPF.

### Known Limitations
- IPv6 fragmented traffic is intentionally dropped (fail-closed).
- VLAN/QinQ frames are fail-closed (not parsed).
- Live policy hot reload is disabled (requires service restart).

> **Note:** This release candidate contains source fixes for P0 vulnerabilities, but runtime validation of eBPF drops is currently failing and pending investigation of the eBPF loader/cache. Do not use in production until runtime DROP is verified.
