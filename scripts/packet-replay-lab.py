#!/usr/bin/env python3
"""Lab-only packet replay for Aegis release validation.

This script is intentionally scoped to the veth/netns names created by
scripts/release-gates.sh. It sends one packet per case and writes structured
logs consumed by the privileged release gate.
"""

from __future__ import annotations

import argparse
import errno
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
DROP_SEND_ERRNOS = {errno.ENOBUFS}


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
    ReplayCase(
        "xdp_ipv4_pass_allowed",
        "ingress IPv4 ICMP packet from an allowed public source",
        "pass",
        {
            "direction": "ingress",
            "family": "ipv4",
            "src": "203.0.113.2",
            "dst": "10.200.0.1",
            "proto": "icmp",
        },
    ),
    ReplayCase(
        "xdp_ipv4_drop_exact",
        "ingress IPv4 ICMP packet from the exact blocked source",
        "drop",
        {
            "direction": "ingress",
            "family": "ipv4",
            "src": IPV4_EXACT_BLOCKED,
            "dst": "10.200.0.1",
            "proto": "icmp",
        },
    ),
    ReplayCase(
        "xdp_ipv6_fragment_pass",
        "ingress IPv6 first fragment; current policy allows kernel reassembly",
        "pass",
        {
            "direction": "ingress",
            "family": "ipv6",
            "src": "2001:db8:1::2",
            "dst": "fd00:ae9:1::1",
            "proto": "icmp6_fragment",
        },
    ),
    ReplayCase(
        "xdp_ipv6_malformed_extension_drop",
        "ingress IPv6 packet with an out-of-bounds extension-header length",
        "drop",
        {
            "direction": "ingress",
            "family": "ipv6",
            "src": "2001:db8:2::2",
            "dst": "fd00:ae9:1::1",
            "proto": "icmp6_malformed_hop",
        },
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
            IPv6ExtHdrFragment,
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
    return (
        Dot1Q,
        Ether,
        ICMP,
        ICMPv6EchoRequest,
        IP,
        IPOption_NOP,
        IPv6,
        IPv6ExtHdrFragment,
        Raw,
        sendp,
        sniff,
    )


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


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def wait_for_receiver_ready(receiver: subprocess.Popen[str], ready_marker: Path) -> None:
    deadline = time.monotonic() + 2.0
    while not ready_marker.exists():
        if receiver.poll() is not None:
            stdout, stderr = receiver.communicate()
            raise RuntimeError(
                "receiver exited before sniff setup "
                f"rc={receiver.returncode} stdout={first_line(stdout)} stderr={first_line(stderr)}"
            )
        if time.monotonic() >= deadline:
            raise RuntimeError("receiver did not become ready before packet send")
        time.sleep(0.05)
    time.sleep(0.1)


def build_packet(spec: Dict[str, object], host_mac: str, peer_mac: str):
    (
        Dot1Q,
        Ether,
        ICMP,
        ICMPv6EchoRequest,
        IP,
        IPOption_NOP,
        IPv6,
        IPv6ExtHdrFragment,
        Raw,
        _,
        _,
    ) = require_scapy()

    direction = spec.get("direction", "egress")
    if direction == "ingress":
        pkt = Ether(src=peer_mac, dst=host_mac)
    else:
        pkt = Ether(src=host_mac, dst=peer_mac)
    for vlan_id in spec.get("vlan", []):
        pkt = pkt / Dot1Q(vlan=int(vlan_id))

    family = spec["family"]
    proto = spec["proto"]
    if family == "ipv4":
        ip_kwargs: Dict[str, object] = {
            "src": str(spec.get("src", "10.200.0.1")),
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
        ipv6 = IPv6(
            src=str(spec.get("src", "fd00:ae9:1::1")),
            dst=str(spec["dst"]),
            hlim=64,
        )
        if proto == "icmp6_fragment":
            return (
                pkt
                / ipv6
                / IPv6ExtHdrFragment(nh=58, id=0xAE61, offset=0, m=1)
                / ICMPv6EchoRequest(id=0xA69, seq=1)
            )
        if proto == "icmp6_malformed_hop":
            return pkt / IPv6(src=ipv6.src, dst=ipv6.dst, hlim=64, nh=0) / Raw(
                bytes([58, 255]) + bytes(6)
            )
        return pkt / ipv6 / ICMPv6EchoRequest(id=0xA69, seq=1)

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
    error: str = "",
) -> None:
    log_file = out_dir / f"{case.name}.log"
    direction = str(case.spec.get("direction", "egress"))
    hook = "xdp" if direction == "ingress" else "tc_egress"
    lines = [
        f"case: {case.name}",
        f"packet: {case.packet}",
        f"expected_verdict: {case.expected}",
        f"observed_verdict: {observed}",
        f"command: {command}",
        f"direction: {direction}",
        f"hook: {hook}",
        f"interface: {interface}",
        f"counters_before: {first_line(counters_before)}",
        f"counters_after: {first_line(counters_after)}",
        f"xdp_state: {first_line(xdp_state)}",
        f"tc_state: {first_line(tc_state)}",
    ]
    if error:
        lines.append(f"error: {first_line(error)}")
    lines.extend([f"pass: {'true' if passed else 'false'}", ""])
    log_file.write_text(
        "\n".join(lines)
    )


def write_error_log(
    out_dir: Path,
    case: ReplayCase,
    error: str,
) -> None:
    """Write a structured failure log when a case raises an exception."""
    log_file = out_dir / f"{case.name}.log"
    direction = str(case.spec.get("direction", "egress"))
    hook = "xdp" if direction == "ingress" else "tc_egress"
    log_file.write_text(
        "\n".join(
            [
                f"case: {case.name}",
                f"packet: {case.packet}",
                f"expected_verdict: {case.expected}",
                "observed_verdict: unknown",
                "command: error during case execution",
                f"direction: {direction}",
                f"hook: {hook}",
                f"error: {first_line(error)}",
                "pass: false",
                "",
            ]
        )
    )


def temp_marker_path(prefix: str, suffix: str) -> Path:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    os.close(fd)
    return Path(path)


def write_stress_summary(
    out_dir: Path,
    iterations: int,
    failures: List[str],
    duration_seconds: float,
    args: argparse.Namespace,
) -> None:
    command = (
        "python3 scripts/packet-replay-lab.py "
        f"--host-if {args.host_if} "
        f"--peer-ns {args.peer_ns} "
        f"--peer-if {args.peer_if} "
        f"--out-dir {args.out_dir} "
        f"--stress-iterations {iterations}"
    )
    passed = not failures
    out_dir.joinpath("stress-summary.log").write_text(
        "\n".join(
            [
                "case: stress_replay_matrix",
                f"packet: bounded repeated replay of {len(CASES)} required release cases",
                "expected_verdict: every replay case matches its expected verdict",
                f"observed_verdict: {'pass' if passed else 'fail'}",
                f"command: {command}",
                f"stress_iterations: {iterations}",
                f"stress_cases_per_iteration: {len(CASES)}",
                f"stress_total_case_runs: {iterations * len(CASES)}",
                f"duration_seconds: {duration_seconds:.3f}",
                f"failures: {', '.join(failures) if failures else 'none'}",
                f"pass: {'true' if passed else 'false'}",
                "",
            ]
        )
    )


def receive_one(args: argparse.Namespace) -> int:
    _, _, _, _, IP, _, IPv6, _, _, _, sniff = require_scapy()
    spec = json.loads(args.match_json)
    marker = Path(args.marker)

    def matches(pkt) -> bool:
        if spec["family"] == "ipv4":
            return (
                IP in pkt
                and pkt[IP].dst == spec["dst"]
                and ("src" not in spec or pkt[IP].src == spec["src"])
            )
        if spec["family"] == "ipv6":
            return (
                IPv6 in pkt
                and pkt[IPv6].dst == spec["dst"]
                and ("src" not in spec or pkt[IPv6].src == spec["src"])
            )
        return False

    if args.ready_marker:
        Path(args.ready_marker).write_text("ready\n")
    packets = sniff(iface=args.iface, timeout=args.timeout, count=1, lfilter=matches)
    if packets:
        marker.write_text("received\n")
        return 0
    return 1


def send_one(args: argparse.Namespace) -> int:
    if not args.iface or not args.spec_json or not args.host_mac or not args.peer_mac:
        raise SystemExit(
            "--send-one requires --iface, --spec-json, --host-mac, and --peer-mac"
        )
    require_root()
    require_lab_name(args.iface, "send interface")
    spec = json.loads(args.spec_json)
    packet = build_packet(spec, args.host_mac, args.peer_mac)
    *_, sendp, _ = require_scapy()
    sendp(packet, iface=args.iface, count=1, verbose=False)
    return 0


def validate_packets() -> int:
    host_mac = "02:00:00:00:00:01"
    peer_mac = "02:00:00:00:00:02"
    for case in CASES:
        packet = build_packet(case.spec, host_mac, peer_mac)
        raw = bytes(packet)
        if not raw:
            raise SystemExit(f"packet case serialized to zero bytes: {case.name}")
        print(f"{case.name}: {len(raw)} bytes: {packet.summary()}")
    return 0


def run_case(args: argparse.Namespace, case: ReplayCase, host_mac: str, peer_mac: str) -> bool:
    *_, sendp, _ = require_scapy()
    out_dir = Path(args.out_dir)
    marker = temp_marker_path(prefix=f"{case.name}.", suffix=".seen")
    ready_marker = temp_marker_path(prefix=f"{case.name}.", suffix=".ready")
    marker.unlink(missing_ok=True)
    ready_marker.unlink(missing_ok=True)
    receiver: subprocess.Popen[str] | None = None

    try:
        direction = str(case.spec.get("direction", "egress"))
        receive_cmd = [
            sys.executable,
            str(Path(__file__).resolve()),
            "--receive-one",
            "--iface",
            args.peer_if if direction == "egress" else args.host_if,
            "--marker",
            str(marker),
            "--ready-marker",
            str(ready_marker),
            "--match-json",
            json.dumps(
                {
                    key: case.spec[key]
                    for key in ("family", "src", "dst")
                    if key in case.spec
                }
            ),
            "--timeout",
            str(args.timeout),
        ]
        receiver_cmd = (
            ["ip", "netns", "exec", args.peer_ns, *receive_cmd]
            if direction == "egress"
            else receive_cmd
        )
        receiver = subprocess.Popen(receiver_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        wait_for_receiver_ready(receiver, ready_marker)

        counters_before = run_text(["tc", "-s", "filter", "show", "dev", args.host_if, "egress"])
        xdp_state = run_text(["ip", "-details", "link", "show", "dev", args.host_if])
        tc_state = run_text(["tc", "qdisc", "show", "dev", args.host_if])

        packet = build_packet(case.spec, host_mac, peer_mac)
        send_iface = args.host_if if direction == "egress" else args.peer_if
        command = f"sendp({packet.summary()}, iface={send_iface}, direction={direction}, count=1)"
        send_error = ""
        try:
            if direction == "egress":
                sendp(packet, iface=args.host_if, count=1, verbose=False)
            else:
                sender = subprocess.run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        args.peer_ns,
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "--send-one",
                        "--iface",
                        args.peer_if,
                        "--spec-json",
                        json.dumps(case.spec),
                        "--host-mac",
                        host_mac,
                        "--peer-mac",
                        peer_mac,
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if sender.returncode != 0:
                    raise RuntimeError(
                        "sender failed "
                        f"rc={sender.returncode} stdout={first_line(sender.stdout)} "
                        f"stderr={first_line(sender.stderr)}"
                    )
        except OSError as exc:
            if exc.errno not in DROP_SEND_ERRNOS:
                raise
            send_error = f"sendp returned drop-like socket error: {exc}"

        try:
            stdout, stderr = receiver.communicate(timeout=args.timeout + 1)
        except subprocess.TimeoutExpired:
            receiver.kill()
            stdout, stderr = receiver.communicate()
            raise RuntimeError(
                "receiver timed out after packet send "
                f"stdout={first_line(stdout)} stderr={first_line(stderr)}"
            )
        counters_after = run_text(["tc", "-s", "filter", "show", "dev", args.host_if, "egress"])

        if receiver.returncode not in (0, 1):
            raise RuntimeError(
                "receiver failed "
                f"rc={receiver.returncode} stdout={first_line(stdout)} stderr={first_line(stderr)}"
            )

        seen = marker.exists()
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
            send_error,
        )
        return passed
    finally:
        if receiver is not None and receiver.poll() is None:
            receiver.terminate()
            try:
                receiver.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                receiver.kill()
                receiver.communicate()
        marker.unlink(missing_ok=True)
        ready_marker.unlink(missing_ok=True)


def run_stress(args: argparse.Namespace, host_mac: str, peer_mac: str) -> bool:
    failures: List[str] = []
    start = time.monotonic()

    for iteration in range(1, args.stress_iterations + 1):
        for case in CASES:
            try:
                if not run_case(args, case, host_mac, peer_mac):
                    failures.append(f"iteration={iteration}:case={case.name}")
            except Exception as exc:
                failures.append(f"iteration={iteration}:case={case.name}:error={first_line(str(exc))}")
                write_error_log(Path(args.out_dir), case, str(exc))

    duration = time.monotonic() - start
    write_stress_summary(Path(args.out_dir), args.stress_iterations, failures, duration, args)
    return not failures


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
        try:
            if not run_case(args, case, host_mac, peer_mac):
                failed.append(case.name)
        except Exception as exc:
            print(f"case {case.name} raised: {exc}", file=sys.stderr)
            write_error_log(Path(args.out_dir), case, str(exc))
            failed.append(case.name)

    if failed:
        print("packet replay failed cases: " + ", ".join(failed), file=sys.stderr)
        return 1

    if args.stress_iterations > 0 and not run_stress(args, host_mac, peer_mac):
        print(
            f"packet replay stress failed; see {Path(args.out_dir) / 'stress-summary.log'}",
            file=sys.stderr,
        )
        return 1

    if args.stress_iterations > 0:
        print(
            f"packet replay stress passed {args.stress_iterations} iterations; "
            f"summary in {Path(args.out_dir) / 'stress-summary.log'}"
        )

    print(f"packet replay passed {len(CASES)} cases; logs in {args.out_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Aegis lab-only packet replay")
    parser.add_argument("--host-if", default="aegis-host0")
    parser.add_argument("--peer-ns", default="aegis-reltest")
    parser.add_argument("--peer-if", default="aegis-peer0")
    parser.add_argument("--out-dir", default=os.environ.get("AEGIS_PACKET_REPLAY_DIR", "/tmp/aegis-replay"))
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument(
        "--stress-iterations",
        type=non_negative_int,
        default=None,
        help="run a bounded repeated replay matrix after the required one-shot cases",
    )
    parser.add_argument("--list-cases", action="store_true")
    parser.add_argument("--validate-packets", action="store_true")
    parser.add_argument("--receive-one", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--send-one", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--iface", help=argparse.SUPPRESS)
    parser.add_argument("--marker", help=argparse.SUPPRESS)
    parser.add_argument("--ready-marker", help=argparse.SUPPRESS)
    parser.add_argument("--match-json", help=argparse.SUPPRESS)
    parser.add_argument("--spec-json", help=argparse.SUPPRESS)
    parser.add_argument("--host-mac", help=argparse.SUPPRESS)
    parser.add_argument("--peer-mac", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.list_cases:
        for case in CASES:
            print(case.name)
        return 0

    if args.validate_packets:
        return validate_packets()

    if args.receive_one:
        if not args.iface or not args.marker or not args.match_json:
            raise SystemExit("--receive-one requires --iface, --marker, and --match-json")
        return receive_one(args)

    if args.send_one:
        return send_one(args)

    if args.stress_iterations is None:
        try:
            args.stress_iterations = non_negative_int(os.environ.get("AEGIS_STRESS_ITERATIONS", "0"))
        except argparse.ArgumentTypeError as exc:
            parser.error(f"AEGIS_STRESS_ITERATIONS {exc}")

    return run_replay(args)


if __name__ == "__main__":
    raise SystemExit(main())
