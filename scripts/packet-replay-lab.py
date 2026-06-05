#!/usr/bin/env python3
"""Lab-only packet replay for Aegis release validation.

This script is intentionally scoped to the veth/netns names created by
scripts/release-gates.sh. It sends one packet per case and writes structured
logs consumed by the privileged release gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


IPV4_ALLOWED = "10.200.0.2"
IPV4_EXACT_BLOCKED = "198.51.100.10"
IPV4_CIDR_BLOCKED = "198.51.100.20"
IPV6_ALLOWED = "fd00:ae9:1::2"
IPV6_EXACT_BLOCKED = "2001:db8:dead::10"
IPV6_CIDR_BLOCKED = "2001:db8:dead::20"


@dataclass(frozen=True)
class ReplayCase:
    name: str
    packet: str
    expected: str
    spec: Dict[str, object]


CASES: List[ReplayCase] = [
    ReplayCase(
        "ipv4_pass_allowed",
        "egress IPv4 ICMP packet to allowed lab peer",
        "pass",
        {"family": "ipv4", "dst": IPV4_ALLOWED, "proto": "icmp"},
    ),
    ReplayCase(
        "ipv4_drop_exact",
        "egress IPv4 ICMP packet to exact blocked destination",
        "drop",
        {"family": "ipv4", "dst": IPV4_EXACT_BLOCKED, "proto": "icmp"},
    ),
    ReplayCase(
        "ipv4_drop_cidr",
        "egress IPv4 ICMP packet to CIDR blocked destination",
        "drop",
        {"family": "ipv4", "dst": IPV4_CIDR_BLOCKED, "proto": "icmp"},
    ),
    ReplayCase(
        "ipv6_pass_allowed",
        "egress IPv6 ICMP packet to allowed lab peer",
        "pass",
        {"family": "ipv6", "dst": IPV6_ALLOWED, "proto": "icmp6"},
    ),
    ReplayCase(
        "ipv6_drop_exact",
        "egress IPv6 ICMP packet to exact blocked destination",
        "drop",
        {"family": "ipv6", "dst": IPV6_EXACT_BLOCKED, "proto": "icmp6"},
    ),
    ReplayCase(
        "ipv6_drop_cidr",
        "egress IPv6 ICMP packet to CIDR blocked destination",
        "drop",
        {"family": "ipv6", "dst": IPV6_CIDR_BLOCKED, "proto": "icmp6"},
    ),
    ReplayCase(
        "vlan_behavior",
        "egress 802.1Q IPv4 packet; current policy is fail-closed",
        "drop",
        {"family": "ipv4", "dst": IPV4_ALLOWED, "proto": "icmp", "vlan": [100]},
    ),
    ReplayCase(
        "qinq_behavior",
        "egress QinQ IPv4 packet; current policy is fail-closed",
        "drop",
        {"family": "ipv4", "dst": IPV4_ALLOWED, "proto": "icmp", "vlan": [100, 200]},
    ),
    ReplayCase(
        "ipv4_ihl_options_behavior",
        "egress IPv4 packet with options; current policy is fail-closed",
        "drop",
        {"family": "ipv4", "dst": IPV4_ALLOWED, "proto": "icmp", "options": True},
    ),
    ReplayCase(
        "ipv4_fragment_behavior",
        "egress IPv4 fragment; current policy is fail-closed",
        "drop",
        {"family": "ipv4", "dst": IPV4_ALLOWED, "proto": "icmp", "fragment": True},
    ),
    ReplayCase(
        "truncated_tcp_blocked_ipv4_exact",
        "egress truncated TCP packet to exact blocked IPv4 destination",
        "drop",
        {"family": "ipv4", "dst": IPV4_EXACT_BLOCKED, "proto": "tcp_truncated"},
    ),
    ReplayCase(
        "truncated_udp_blocked_ipv4_exact",
        "egress truncated UDP packet to exact blocked IPv4 destination",
        "drop",
        {"family": "ipv4", "dst": IPV4_EXACT_BLOCKED, "proto": "udp_truncated"},
    ),
    ReplayCase(
        "truncated_tcp_blocked_ipv4_cidr",
        "egress truncated TCP packet to CIDR blocked IPv4 destination",
        "drop",
        {"family": "ipv4", "dst": IPV4_CIDR_BLOCKED, "proto": "tcp_truncated"},
    ),
    ReplayCase(
        "truncated_udp_blocked_ipv4_cidr",
        "egress truncated UDP packet to CIDR blocked IPv4 destination",
        "drop",
        {"family": "ipv4", "dst": IPV4_CIDR_BLOCKED, "proto": "udp_truncated"},
    ),
]


def require_scapy():
    try:
        from scapy.all import (  # type: ignore
            Dot1Q,
            Ether,
            ICMP,
            ICMPv6EchoRequest,
            IP,
            IPOption_NOP,
            IPv6,
            Raw,
            conf,
            sendp,
            sniff,
        )
    except ImportError:
        print(
            "missing Python dependency: scapy\n"
            "Install in the lab VM, then rerun:\n"
            "  python3 -m pip install scapy\n"
            "or distro package:\n"
            "  sudo apt-get install python3-scapy\n"
            "  sudo dnf install python3-scapy",
            file=sys.stderr,
        )
        raise SystemExit(127)

    conf.verb = 0
    return Dot1Q, Ether, ICMP, ICMPv6EchoRequest, IP, IPOption_NOP, IPv6, Raw, sendp, sniff


def run_text(cmd: List[str]) -> str:
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.stdout.strip()


def require_lab_name(value: str, label: str) -> None:
    if not value.startswith("aegis-"):
        raise SystemExit(f"{label} must be a lab-scoped aegis-* name, got: {value}")


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("packet replay must run as root inside the disposable lab")


def link_output(iface: str, namespace: str | None = None) -> str:
    cmd = ["ip"]
    if namespace:
        cmd.extend(["-n", namespace])
    cmd.extend(["link", "show", "dev", iface])
    out = run_text(cmd)
    if not out:
        ns_msg = f" in namespace {namespace}" if namespace else ""
        raise SystemExit(f"could not inspect interface {iface}{ns_msg}")
    return out


def mac_for(iface: str, namespace: str | None = None) -> str:
    out = link_output(iface, namespace)
    match = re.search(r"link/ether\s+([0-9a-f:]{17})", out, re.IGNORECASE)
    if not match:
        ns_msg = f" in namespace {namespace}" if namespace else ""
        raise SystemExit(f"could not parse MAC for {iface}{ns_msg}")
    return match.group(1)


def first_line(text: str) -> str:
    line = text.replace("\n", " | ").strip()
    return line[:500] if line else "unavailable"


def build_packet(spec: Dict[str, object], host_mac: str, peer_mac: str):
    Dot1Q, Ether, ICMP, ICMPv6EchoRequest, IP, IPOption_NOP, IPv6, Raw, _, _ = require_scapy()

    pkt = Ether(src=host_mac, dst=peer_mac)
    for vlan_id in spec.get("vlan", []):
        pkt = pkt / Dot1Q(vlan=int(vlan_id))

    family = spec["family"]
    proto = spec["proto"]
    if family == "ipv4":
        ip_kwargs: Dict[str, object] = {
            "src": "10.200.0.1",
            "dst": str(spec["dst"]),
            "ttl": 64,
        }
        if spec.get("options"):
            ip_kwargs["options"] = [IPOption_NOP()]
        if spec.get("fragment"):
            ip_kwargs["flags"] = "MF"
            ip_kwargs["frag"] = 0
        if proto == "tcp_truncated":
            return pkt / IP(proto=6, **ip_kwargs) / Raw(b"\x04\xd2\x00P" + b"\x00" * 9)
        if proto == "udp_truncated":
            return pkt / IP(proto=17, **ip_kwargs) / Raw(b"\x04\xd2\x005"[:3])
        return pkt / IP(**ip_kwargs) / ICMP(id=0xA69, seq=1)

    if family == "ipv6":
        return (
            pkt
            / IPv6(src="fd00:ae9:1::1", dst=str(spec["dst"]), hlim=64)
            / ICMPv6EchoRequest(id=0xA69, seq=1)
        )

    raise SystemExit(f"unknown packet family: {family}")


def write_log(
    out_dir: Path,
    case: ReplayCase,
    observed: str,
    passed: bool,
    command: str,
    counters_before: str,
    counters_after: str,
    xdp_state: str,
    tc_state: str,
    interface: str,
) -> None:
    log_file = out_dir / f"{case.name}.log"
    log_file.write_text(
        "\n".join(
            [
                f"case: {case.name}",
                f"packet: {case.packet}",
                f"expected_verdict: {case.expected}",
                f"observed_verdict: {observed}",
                f"command: {command}",
                f"interface: {interface}",
                f"counters_before: {first_line(counters_before)}",
                f"counters_after: {first_line(counters_after)}",
                f"xdp_state: {first_line(xdp_state)}",
                f"tc_state: {first_line(tc_state)}",
                f"pass: {'true' if passed else 'false'}",
                "",
            ]
        )
    )


def receive_one(args: argparse.Namespace) -> int:
    _, _, _, _, IP, _, IPv6, _, _, sniff = require_scapy()
    spec = json.loads(args.match_json)
    marker = Path(args.marker)

    def matches(pkt) -> bool:
        if spec["family"] == "ipv4":
            return IP in pkt and pkt[IP].dst == spec["dst"]
        if spec["family"] == "ipv6":
            return IPv6 in pkt and pkt[IPv6].dst == spec["dst"]
        return False

    packets = sniff(iface=args.iface, timeout=args.timeout, count=1, lfilter=matches)
    if packets:
        marker.write_text("received\n")
        return 0
    return 1


def run_case(args: argparse.Namespace, case: ReplayCase, host_mac: str, peer_mac: str) -> bool:
    _, _, _, _, _, _, _, _, sendp, _ = require_scapy()
    out_dir = Path(args.out_dir)
    marker = Path(tempfile.mkstemp(prefix=f"{case.name}.", suffix=".seen")[1])
    marker.unlink(missing_ok=True)

    receiver_cmd = [
        "ip",
        "netns",
        "exec",
        args.peer_ns,
        sys.executable,
        str(Path(__file__).resolve()),
        "--receive-one",
        "--iface",
        args.peer_if,
        "--marker",
        str(marker),
        "--match-json",
        json.dumps({"family": case.spec["family"], "dst": case.spec["dst"]}),
        "--timeout",
        str(args.timeout),
    ]
    receiver = subprocess.Popen(receiver_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.2)

    counters_before = run_text(["tc", "-s", "filter", "show", "dev", args.host_if, "egress"])
    xdp_state = run_text(["ip", "-details", "link", "show", "dev", args.host_if])
    tc_state = run_text(["tc", "qdisc", "show", "dev", args.host_if])

    packet = build_packet(case.spec, host_mac, peer_mac)
    command = f"sendp({packet.summary()}, iface={args.host_if}, count=1)"
    sendp(packet, iface=args.host_if, count=1, verbose=False)

    receiver.communicate(timeout=args.timeout + 1)
    counters_after = run_text(["tc", "-s", "filter", "show", "dev", args.host_if, "egress"])

    seen = marker.exists()
    marker.unlink(missing_ok=True)

    observed = "pass" if seen else "drop"
    passed = observed == case.expected
    write_log(
        out_dir,
        case,
        observed,
        passed,
        command,
        counters_before,
        counters_after,
        xdp_state,
        tc_state,
        args.host_if,
    )
    return passed


def run_replay(args: argparse.Namespace) -> int:
    require_root()
    require_lab_name(args.host_if, "host interface")
    require_lab_name(args.peer_ns, "peer namespace")
    require_lab_name(args.peer_if, "peer interface")

    Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    host_mac = mac_for(args.host_if)
    peer_mac = mac_for(args.peer_if, args.peer_ns)

    failed = []
    for case in CASES:
        if not run_case(args, case, host_mac, peer_mac):
            failed.append(case.name)

    if failed:
        print("packet replay failed cases: " + ", ".join(failed), file=sys.stderr)
        return 1

    print(f"packet replay passed {len(CASES)} cases; logs in {args.out_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Aegis lab-only packet replay")
    parser.add_argument("--host-if", default="aegis-host0")
    parser.add_argument("--peer-ns", default="aegis-reltest")
    parser.add_argument("--peer-if", default="aegis-peer0")
    parser.add_argument("--out-dir", default=os.environ.get("AEGIS_PACKET_REPLAY_DIR", "/tmp/aegis-replay"))
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--list-cases", action="store_true")
    parser.add_argument("--receive-one", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--iface", help=argparse.SUPPRESS)
    parser.add_argument("--marker", help=argparse.SUPPRESS)
    parser.add_argument("--match-json", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.list_cases:
        for case in CASES:
            print(case.name)
        return 0

    if args.receive_one:
        if not args.iface or not args.marker or not args.match_json:
            raise SystemExit("--receive-one requires --iface, --marker, and --match-json")
        return receive_one(args)

    return run_replay(args)


if __name__ == "__main__":
    raise SystemExit(main())
