#!/usr/bin/env python3
"""High-performance packet generator for Aegis XDP vs nftables benchmarks.

Runs inside a network namespace.  Pre-builds raw Ethernet frames once, then
blasts them via AF_PACKET in a tight loop.  Reports per-second JSON stats to
stdout so the orchestrator can parse them.

Usage (from orchestrator):
    ip netns exec bench-ns python3 bench_traffic_gen.py \
        --iface bench-peer0 --scenario pass --duration 30
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import struct
import sys
import time
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Packet construction helpers (no scapy at runtime — pure struct.pack)
# ---------------------------------------------------------------------------

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
IPPROTO_TCP = 6
IPPROTO_UDP = 17

DST_MAC = b"\xaa\xbb\xcc\xdd\xee\x01"  # arbitrary; veth accepts anything
SRC_MAC = b"\xaa\xbb\xcc\xdd\xee\x02"


def _eth(etype: int = ETH_P_IP) -> bytes:
    return DST_MAC + SRC_MAC + struct.pack("!H", etype)


def _ip_hdr(
    src: str, dst: str, proto: int, payload_len: int, ident: int = 0x1234
) -> bytes:
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total_len = 20 + payload_len
    # version=4, ihl=5, tos=0, total_len, ident, flags=0x4000 (DF), ttl=64
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0x4000, 64, proto, 0, src_b, dst_b,
    )
    # compute checksum
    words = struct.unpack("!10H", hdr)
    s = sum(words)
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    chksum = ~s & 0xFFFF
    hdr = hdr[:10] + struct.pack("!H", chksum) + hdr[12:]
    return hdr


def _udp(src_port: int, dst_port: int, payload: bytes = b"\x00" * 18) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHH2s", src_port, dst_port, length, b"\x00\x00") + payload


def _tcp_syn(src_port: int, dst_port: int) -> bytes:
    """Minimal 20-byte TCP SYN header (no options)."""
    seq = 0x41414141
    ack = 0
    offset_flags = (5 << 12) | 0x002  # data offset=5, SYN flag
    window = 65535
    return struct.pack(
        "!HHIIHHH2s",
        src_port, dst_port, seq, ack, offset_flags, window, 0, b"\x00\x00",
    )


# ---------------------------------------------------------------------------
# Scenario packet builders
# ---------------------------------------------------------------------------

# Host IPs (must match orchestrator topology)
HOST_IP = "10.88.0.1"
PEER_IP = "10.88.0.2"
BLOCKED_EXACT_IP = "198.51.100.10"
BLOCKED_CIDR_IP = "198.51.100.20"


def build_pass_packet() -> bytes:
    """UDP from RFC1918 peer → host.  Should be ACCEPTED by both engines."""
    udp = _udp(12345, 5001)
    ip = _ip_hdr(PEER_IP, HOST_IP, IPPROTO_UDP, len(udp))
    return _eth() + ip + udp


def build_blocked_exact_packet() -> bytes:
    """UDP from exact-blocked IP → host.  Should be DROPPED."""
    udp = _udp(12345, 443)
    ip = _ip_hdr(BLOCKED_EXACT_IP, HOST_IP, IPPROTO_UDP, len(udp))
    return _eth() + ip + udp


def build_blocked_cidr_packet(idx: int = 0) -> bytes:
    """UDP from CIDR-blocked range → host.  Should be DROPPED."""
    # Vary the last octet to exercise the LPM trie
    third = (idx >> 8) & 0xFF
    fourth = idx & 0xFF
    src = f"198.51.{third}.{fourth}" if third < 255 else BLOCKED_CIDR_IP
    udp = _udp(12345, 80)
    ip = _ip_hdr(src, HOST_IP, IPPROTO_UDP, len(udp))
    return _eth() + ip + udp


def build_syn_flood_packet(src_ip: str | None = None) -> bytes:
    """TCP SYN from random source → host:80.  Triggers rate limiter."""
    if src_ip is None:
        src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    syn = _tcp_syn(random.randint(1024, 65535), 80)
    ip = _ip_hdr(src_ip, HOST_IP, IPPROTO_TCP, len(syn))
    return _eth() + ip + syn


def build_mixed_packets(count: int = 100) -> List[bytes]:
    """Build a mixed batch: 70% pass, 20% CIDR block, 10% SYN."""
    pkts: List[bytes] = []
    for i in range(count):
        r = i % 10
        if r < 7:
            pkts.append(build_pass_packet())
        elif r < 9:
            pkts.append(build_blocked_cidr_packet(i))
        else:
            pkts.append(build_syn_flood_packet())
    return pkts


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------


def run_generator(iface: str, scenario: str, duration: int, warmup: int = 5) -> None:
    """Open AF_PACKET, blast pre-built packets, report JSON stats per second."""

    # Build packet set
    if scenario == "pass":
        packets = [build_pass_packet()]
    elif scenario == "block_exact":
        packets = [build_blocked_exact_packet()]
    elif scenario == "block_cidr":
        packets = [build_blocked_cidr_packet(i) for i in range(256)]
    elif scenario == "syn_flood":
        # Pre-build a pool of SYN packets with random sources
        packets = [build_syn_flood_packet() for _ in range(1024)]
    elif scenario == "mixed":
        packets = build_mixed_packets(1000)
    else:
        print(json.dumps({"error": f"unknown scenario: {scenario}"}), flush=True)
        sys.exit(1)

    # Open raw socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))

    total_duration = warmup + duration
    pkt_count = len(packets)
    pkt_idx = 0

    start = time.monotonic()
    interval_start = start
    interval_pkts = 0
    total_sent = 0
    second = 0
    is_warmup = True

    sys.stderr.write(
        f"[gen] scenario={scenario} iface={iface} "
        f"warmup={warmup}s duration={duration}s packets_pool={pkt_count}\n"
    )
    sys.stderr.flush()

    try:
        while True:
            now = time.monotonic()
            elapsed = now - start

            if elapsed >= total_duration:
                break

            # Send packet
            try:
                sock.send(packets[pkt_idx % pkt_count])
                interval_pkts += 1
                total_sent += 1
            except OSError:
                pass  # ENOBUFS — backpressure, skip

            pkt_idx += 1

            # Report every second
            interval_elapsed = now - interval_start
            if interval_elapsed >= 1.0:
                pps = int(interval_pkts / interval_elapsed)
                phase = "warmup" if elapsed < warmup else "measure"

                if phase == "measure" or not is_warmup:
                    record = {
                        "second": second,
                        "pps": pps,
                        "phase": phase,
                        "total_sent": total_sent,
                    }
                    print(json.dumps(record), flush=True)

                if elapsed >= warmup and is_warmup:
                    is_warmup = False
                    # Reset counters for measurement phase
                    total_sent = 0

                interval_start = now
                interval_pkts = 0
                second += 1

    except KeyboardInterrupt:
        pass
    finally:
        # Final partial-second report
        interval_elapsed = time.monotonic() - interval_start
        if interval_elapsed > 0.1 and interval_pkts > 0:
            pps = int(interval_pkts / interval_elapsed)
            print(
                json.dumps(
                    {"second": second, "pps": pps, "phase": "final", "total_sent": total_sent}
                ),
                flush=True,
            )

        sock.close()
        sys.stderr.write(f"[gen] done. total_sent={total_sent}\n")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Aegis benchmark traffic generator")
    ap.add_argument("--iface", required=True, help="Interface to send on")
    ap.add_argument(
        "--scenario",
        required=True,
        choices=["pass", "block_exact", "block_cidr", "syn_flood", "mixed"],
    )
    ap.add_argument("--duration", type=int, default=30, help="Measurement duration (seconds)")
    ap.add_argument("--warmup", type=int, default=5, help="Warmup duration (seconds)")
    args = ap.parse_args()

    run_generator(args.iface, args.scenario, args.duration, args.warmup)


if __name__ == "__main__":
    main()
