#!/usr/bin/env python3
# =============================================================================
# Aegis v4.3.0-rc.1 regression: IPv6 Fragment Header bypass (P0-1)
# =============================================================================
#
# WHAT THIS CHECKS
#   Before the v4.3.0-rc.1 hardening, an attacker could prepend an IPv6 Fragment
#   Header (frag_off=0, M=0) to an otherwise-blocked IPv6/TCP packet and bypass
#   every L4 rule, because both BPF datapaths (aegis-ebpf XDP, aegis-tc TC)
#   returned XDP_PASS / TC_ACT_OK unconditionally on NEXTHDR_FRAGMENT (44).
#
#   The fix is fail-closed DROP for ALL fragments, mirroring the IPv4 path's
#   0x3FFF mask. This script crafts the bypass packet and asserts the DROP.
#
# PREREQUISITES (operator-run, NOT CI)
#   - A lab machine with Aegis loaded on an interface (IFACE below).
#   - root (or CAP_NET_RAW + CAP_BPF).
#   - scapy:  pip install scapy
#   - A blocklist entry covering the SOURCE IPv6 used below, OR rely on the
#     default fail-closed behavior (any fragment is dropped regardless of
#     blocklist). To also exercise the blocklist path, add the src to
#     BLOCKLIST_IPV6 via the TUI/CLI first.
#
# EXPECTED RESULT
#   - The crafted packet is DROPPED at XDP (ingress).
#   - The event log shows a THREAT_IPV6_FRAGMENT (22) drop with reason
#     REASON_IPV6_POLICY (8) on HOOK_XDP (1).
#
# GREP TARGETS (in aegis event stream / trace_pipe)
#   threat_type=22  (THREAT_IPV6_FRAGMENT)
#   reason=8        (REASON_IPV6_POLICY)
#
# USAGE
#   sudo IFACE=eth0 TARGET_ADDR=2001:db8::1 python3 ipv6_fragment_bypass.py
#
# =============================================================================

import os
import sys

try:
    from scapy.all import IPv6, IPv6ExtHdrFragment, TCP, Ether, sendp
except ImportError:
    sys.exit("scapy not installed: pip install scapy")

IFACE = os.environ.get("IFACE", "eth0")
# A source address that is NOT in any allowlist. The fail-closed fragment drop
# fires regardless of blocklist membership, so the exact value is not critical;
# use a TEST-NET IPv6 (2001:db8::/32, RFC 3849) to avoid hitting real hosts.
SRC_ADDR = os.environ.get("SRC_ADDR", "2001:db8:dead::1")
TARGET_ADDR = os.environ.get("TARGET_ADDR", "2001:db8:dead::2")


def main() -> int:
    # IPv6/TCP with a Fragment Header prepended. frag_off=0, M=0 is the exact
    # shape that used to bypass every rule. After the fix it is DROPPED.
    pkt = (
        Ether()
        / IPv6(src=SRC_ADDR, dst=TARGET_ADDR)
        / IPv6ExtHdrFragment(nh=6, offset=0, m=0)  # nh=6 -> TCP follows
        / TCP(sport=31337, dport=22, flags="S")
    )

    print(f"[*] IFACE={IFACE}")
    print(f"[*] sending 1 IPv6/Fragment/TCP SYN: {SRC_ADDR} -> {TARGET_ADDR}:22")
    print(f"[*] EXPECTED: XDP DROP, threat_type=22 (THREAT_IPV6_FRAGMENT)")
    sendp(pkt, iface=IFACE, verbose=True, count=1)
    print("[*] sent. Verify the drop in the aegis event stream:")
    print("      - TUI: a drop event with THREAT_IPV6_FRAGMENT")
    print("      - logs: grep for 'threat_type' 22, 'reason' 8")
    print("[*] If the packet was NOT dropped, the P0-1 regression is present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
