#!/usr/bin/env python3
# =============================================================================
# Aegis v4.3.0-rc.1 regression: spoofed CGNAT/loopback whitelist bypass (P1-1)
# =============================================================================
#
# WHAT THIS CHECKS
#   Before the v4.3.0-rc.1 hardening, the XDP ingress datapath auto-whitelisted
#   (XDP_PASS, before any deny check) any packet whose source was in:
#     10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
#     100.64.0.0/10 (CGNAT), 127.0.0.0/8 (loopback).
#
#   On an internet-facing interface, CGNAT and loopback are NOT trust
#   boundaries — an attacker who spoofs a source in 100.64.x.x or 127.x.x.x
#   bypassed every deny rule. The fix removes 100.64/10 and 127/8 from the
#   hard-coded whitelist; true RFC1918 (10/8, 172.16/12, 192.168/16) is kept.
#
#   NOTE: aegis-cli/src/map_manager.rs additionally sets CFG_SKIP_WHITELIST=1
#   on non-virtual (public) interfaces, but that is a userspace heuristic; this
#   script validates the BPF-level trim directly.
#
# PREREQUISITES (operator-run, NOT CI)
#   - A lab machine with Aegis loaded on an internet-facing interface (IFACE).
#   - root (or CAP_NET_RAW + CAP_BPF).
#   - scapy:  pip install scapy
#   - rp_filter should be loose/off on the test NIC so the kernel does not drop
#     the spoofed packet before XDP sees it (production should keep rp_filter=1).
#
# EXPECTED RESULT
#   - The spoofed 100.64.x.x packet is NOT whitelisted; it proceeds to the
#     blocklist/CIDR checks. If a deny rule matches, it is DROP'd; otherwise it
#     falls through to default policy. Either way it is NOT auto-PASS'd.
#   - To make the assertion deterministic, add 100.64.0.1 to BLOCKLIST first;
#     then the packet MUST be DROP'd with THREAT_BLOCKLIST (6),
#     REASON_MANUAL_BLOCK (3).
#
# GREP TARGETS (in aegis event stream / trace_pipe)
#   For the deterministic variant (blocklist seeded):
#     threat_type=6  (THREAT_BLOCKLIST)
#     reason=3       (REASON_MANUAL_BLOCK)
#   The regression signal is the ABSENCE of a REASON_WHITELIST (1) pass for a
#   100.64.x.x source.
#
# USAGE
#   sudo IFACE=eth0 python3 ipv4_spoof_cgnat.py
#
# =============================================================================

import os
import sys

try:
    from scapy.all import IP, TCP, Ether, sendp
except ImportError:
    sys.exit("scapy not installed: pip install scapy")

IFACE = os.environ.get("IFACE", "eth0")
# 100.65.0.1 is inside 100.64.0.0/10 (CGNAT) and is the spoofed source that
# used to be auto-whitelisted. Use a private target on the test segment.
SPOOFED_SRC = os.environ.get("SPOOFED_SRC", "100.65.0.1")
TARGET_ADDR = os.environ.get("TARGET_ADDR", "192.0.2.1")  # TEST-NET-1, RFC 5737


def main() -> int:
    pkt = (
        Ether()
        / IP(src=SPOOFED_SRC, dst=TARGET_ADDR)
        / TCP(sport=31337, dport=22, flags="S")
    )
    print(f"[*] IFACE={IFACE}")
    print(f"[*] sending 1 spoofed IPv4/TCP SYN: {SPOOFED_SRC} -> {TARGET_ADDR}:22")
    print(f"[*] {SPOOFED_SRC} is in 100.64.0.0/10 (CGNAT).")
    print(f"[*] EXPECTED: NOT auto-whitelisted (no REASON_WHITELIST=1 pass).")
    print(f"[*] If {SPOOFED_SRC} is in BLOCKLIST, expect THREAT_BLOCKLIST (6) drop.")
    sendp(pkt, iface=IFACE, verbose=True, count=1)
    print("[*] sent. Verify in the event stream:")
    print("      - Regression PRESENT if you see REASON_WHITELIST (1) for this src.")
    print("      - Fix confirmed if this src is NOT whitelisted (blocklist drop or default).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
