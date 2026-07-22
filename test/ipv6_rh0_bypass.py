#!/usr/bin/env python3
# =============================================================================
# Aegis v4.3.0-rc.1 regression: IPv6 Routing Header Type 0 / RH0 (P0-2)
# =============================================================================
#
# WHAT THIS CHECKS
#   RFC 5095 (Dec 2007) mandates that compliant IPv6 nodes MUST silently
#   discard packets containing a Routing Header with routing_type == 0 (RH0),
#   a known amplification and address-spoofing vector. Before the v4.3.0-rc.1
#   hardening, Aegis treated NEXTHADR_ROUTING generically via Ipv6ExtHdr and
#   never read the routing_type byte, so RH0 packets reached L4 processing.
#
#   The fix reads routing_type bounds-checked and DROPs when it equals
#   ROUTING_TYPE_0 (0). RH2 (Mobile IPv6) and SRH pass through unchanged.
#
# PREREQUISITES (operator-run, NOT CI)
#   - A lab machine with Aegis loaded on an interface (IFACE below).
#   - root (or CAP_NET_RAW + CAP_BPF).
#   - scapy:  pip install scapy
#
# EXPECTED RESULT
#   - The RH0 packet is DROPPED at XDP (ingress).
#   - The event log shows THREAT_IPV6_ROUTING_TYPE0 (21) with reason
#     REASON_IPV6_POLICY (8) on HOOK_XDP (1).
#   - A companion packet with a Routing Header type != 0 (e.g. type=2, RH2)
#     is NOT dropped by this branch (it is walked past generically).
#
# GREP TARGETS (in aegis event stream / trace_pipe)
#   threat_type=21  (THREAT_IPV6_ROUTING_TYPE0)
#   reason=8        (REASON_IPV6_POLICY)
#
# USAGE
#   sudo IFACE=eth0 TARGET_ADDR=2001:db8::2 python3 ipv6_rh0_bypass.py
#
# =============================================================================

import os
import sys

try:
    from scapy.all import IPv6, IPv6ExtHdrRouting, TCP, Ether, sendp, Raw
except ImportError:
    sys.exit("scapy not installed: pip install scapy")

IFACE = os.environ.get("IFACE", "eth0")
SRC_ADDR = os.environ.get("SRC_ADDR", "2001:db8:dead::1")
TARGET_ADDR = os.environ.get("TARGET_ADDR", "2001:db8:dead::2")


def build_rh0_packet(routing_type: int) -> bytes:
    # IPv6/TCP with a Routing Header. scapy's IPv6ExtHdrRouting lets us set the
    # type byte directly; the address list is the routing segment list.
    # For RH0 (type=0) the segments are IPv6 addresses. We carry one dummy
    # segment so the header is well-formed; the exact segments are irrelevant
    # because Aegis drops purely on routing_type == 0 before touching them.
    pkt = (
        Ether()
        / IPv6(src=SRC_ADDR, dst=TARGET_ADDR)
        / IPv6ExtHdrRouting(
            nh=6,           # next header = TCP
            type=routing_type,
            segleft=0,
            addresses=["2001:db8:beef::1"],
        )
        / TCP(sport=31337, dport=22, flags="S")
    )
    return pkt


def main() -> int:
    print(f"[*] IFACE={IFACE}")

    # --- RH0 (routing_type == 0): MUST be dropped ---
    rh0 = build_rh0_packet(routing_type=0)
    print(f"[*] sending 1 IPv6/RH0/TCP: {SRC_ADDR} -> {TARGET_ADDR}:22")
    print(f"[*] EXPECTED: XDP DROP, threat_type=21 (THREAT_IPV6_ROUTING_TYPE0)")
    sendp(rh0, iface=IFACE, verbose=True, count=1)

    # --- RH2 (routing_type == 2): NOT dropped by the RH0 branch ---
    rh2 = build_rh0_packet(routing_type=2)
    print(f"[*] sending 1 IPv6/RH2/TCP (control): should NOT trigger the RH0 drop")
    sendp(rh2, iface=IFACE, verbose=True, count=1)

    print("[*] sent. Verify:")
    print("      - RH0 packet: drop event with THREAT_IPV6_ROUTING_TYPE0 (21)")
    print("      - RH2 packet: no RH0 drop (passed or handled by other rules)")
    print("[*] If the RH0 packet was NOT dropped, the P0-2 regression is present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
