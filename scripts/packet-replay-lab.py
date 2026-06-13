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
import struct
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
MAX_STRESS_ITERATIONS = 50


@dataclass(frozen=True)
class ReplayCase:
    name: str
    packet: str
    expected: str
    spec: Dict[str, object]


@dataclass(frozen=True)
class RuntimeMetadata:
    commit: str
    release_version: str
    timestamp: str
    distribution: str
    kernel: str
    architecture: str


@dataclass(frozen=True)
class EvidenceRecord:
    """Structured replay evidence for a single case.

    The release gate treats this as the canonical schema for commit-bound
    packet replay proof. If any field is missing, the artifact is not
    release-grade evidence.
    """

    case: str
    commit: str
    release_version: str
    timestamp: str
    distribution: str
    kernel: str
    architecture: str
    interface: str
    xdp_mode: str
    tc_attached: bool
    packet: str
    expected_verdict: str
    observed_verdict: str
    command: str
    command_output: str
    counter_before: str
    counter_after: str
    input_pcap: str
    capture_pcap: str
    passed: bool


def git_output(args: List[str]) -> str:
    return run_text(["git", *args]).strip()


def runtime_metadata() -> RuntimeMetadata:
    os_release = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    key, value = line.rstrip().split("=", 1)
                    os_release[key] = value.strip().strip('"')
    except OSError:
        pass
    distribution = os_release.get("PRETTY_NAME") or os_release.get("ID") or "unknown"
    release_version = "unknown"
    cargo_toml = Path(__file__).resolve().parent.parent / "aegis-cli" / "Cargo.toml"
    if cargo_toml.exists():
        for line in cargo_toml.read_text(encoding="utf-8").splitlines():
            if line.startswith("version = "):
                release_version = line.split("=", 1)[1].strip().strip('"')
                break
    return RuntimeMetadata(
        commit=git_output(["rev-parse", "HEAD"]),
        release_version=release_version,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        distribution=distribution,
        kernel=run_text(["uname", "-r"]),
        architecture=run_text(["uname", "-m"]),
    )


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
            wrpcap,
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
        wrpcap,
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
    return line if line else "unavailable"


def xdp_mode_from_state(state: str) -> str:
    lowered = state.lower()
    if "xdp" not in lowered:
        return "not_attached"
    if "skb" in lowered or "generic" in lowered:
        return "skb"
    if "driver" in lowered or "drv" in lowered:
        return "driver"
    return "attached"


def tc_attached_from_state(state: str) -> bool:
    lowered = state.lower()
    return "clsact" in lowered and "name tc_egress" in lowered


def write_pcap(path: Path, packet) -> None:
    (_, _, _, _, _, _, _, _, _, _, _, wrpcap) = require_scapy()
    wrpcap(str(path), [packet] if packet is not None else [])


def write_command_output(
    out_dir: Path,
    case: ReplayCase,
    command: str,
    sender_stdout: str,
    sender_stderr: str,
    receiver_stdout: str,
    receiver_stderr: str,
    xdp_state: str,
    tc_state: str,
    counter_before: str,
    counter_after: str,
) -> Path:
    output_path = out_dir / f"{case.name}.command.log"
    output_path.write_text(
        "\n".join(
            [
                f"case: {case.name}",
                f"command: {command}",
                "[sender.stdout]",
                sender_stdout.strip() or "",
                "[sender.stderr]",
                sender_stderr.strip() or "",
                "[receiver.stdout]",
                receiver_stdout.strip() or "",
                "[receiver.stderr]",
                receiver_stderr.strip() or "",
                "[xdp.state]",
                xdp_state.strip() or "",
                "[tc.state]",
                tc_state.strip() or "",
                "[counter.before]",
                counter_before.strip() or "",
                "[counter.after]",
                counter_after.strip() or "",
                "",
            ]
        )
    )
    return output_path


def evidence_fields(log_path: Path) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for raw_line in log_path.read_text(encoding="utf-8").splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields


def transcript_section(transcript: str, name: str) -> str:
    match = re.search(
        rf"^\[{re.escape(name)}\]\n(.*?)(?=^\[|\Z)",
        transcript,
        flags=re.MULTILINE | re.DOTALL,
    )
    return match.group(1).strip() if match else ""


def resolve_artifact_path(log_path: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else log_path.parent / path


def pcap_packet_count(path: Path) -> int:
    """Parse a classic PCAP and return its packet-record count."""

    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"{path}: truncated PCAP global header")

    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    else:
        raise ValueError(f"{path}: unsupported PCAP magic {magic.hex()}")

    _, major, minor, _, _, snaplen, _ = struct.unpack(f"{endian}IHHIIII", data[:24])
    if (major, minor) != (2, 4):
        raise ValueError(f"{path}: unsupported PCAP version {major}.{minor}")
    if snaplen == 0:
        raise ValueError(f"{path}: invalid zero PCAP snaplen")

    offset = 24
    packets = 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError(f"{path}: truncated PCAP packet header")
        _, _, included_len, original_len = struct.unpack(
            f"{endian}IIII", data[offset : offset + 16]
        )
        if included_len > snaplen or included_len > original_len:
            raise ValueError(
                f"{path}: invalid packet lengths incl={included_len} "
                f"orig={original_len} snaplen={snaplen}"
            )
        offset += 16
        packet_end = offset + included_len
        if packet_end > len(data):
            raise ValueError(f"{path}: truncated PCAP packet data")
        offset = packet_end
        packets += 1
    return packets


def canonical_case(name: str) -> ReplayCase:
    for case in CASES:
        if case.name == name:
            return case
    raise SystemExit(f"unknown replay evidence case: {name}")


def validate_log(
    log_path: Path,
    expected_case: str,
    expected_commit: str,
) -> int:
    """Reject partial or cross-commit replay evidence.

    The validator is intentionally strict: it requires the full release
    metadata, a matching full commit SHA, valid attach state, parseable PCAP
    artifacts, and packet observations consistent with the claimed verdict.
    """

    required = {
        "case",
        "commit",
        "release_version",
        "timestamp",
        "distribution",
        "kernel",
        "architecture",
        "interface",
        "xdp_mode",
        "tc_attached",
        "packet",
        "expected_verdict",
        "observed_verdict",
        "command",
        "command_output",
        "counter_before",
        "counter_after",
        "input_pcap",
        "capture_pcap",
        "pass",
    }
    fields = evidence_fields(log_path)
    missing = sorted(required - fields.keys())
    if missing:
        raise SystemExit(f"{log_path}: missing required fields: {', '.join(missing)}")
    if fields["case"] != expected_case:
        raise SystemExit(
            f"{log_path}: case mismatch: expected {expected_case}, got {fields['case']}"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", fields["commit"]):
        raise SystemExit(f"{log_path}: commit must be a full lowercase Git SHA")
    if fields["commit"] != expected_commit:
        raise SystemExit(
            f"{log_path}: commit mismatch: expected {expected_commit}, got {fields['commit']}"
        )
    case = canonical_case(expected_case)
    if fields["release_version"] in {"", "unknown"}:
        raise SystemExit(f"{log_path}: release_version must identify the candidate")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", fields["timestamp"]):
        raise SystemExit(f"{log_path}: timestamp must be UTC ISO-8601")
    for key in ("distribution", "kernel", "architecture", "interface", "packet", "command"):
        if fields[key] in {"", "unknown", "unavailable"}:
            raise SystemExit(f"{log_path}: {key} must be concrete")
    if fields["expected_verdict"] != case.expected:
        raise SystemExit(
            f"{log_path}: expected verdict does not match canonical case "
            f"({fields['expected_verdict']} != {case.expected})"
        )
    if fields["expected_verdict"] != fields["observed_verdict"]:
        raise SystemExit(
            f"{log_path}: expected_verdict != observed_verdict "
            f"({fields['expected_verdict']} != {fields['observed_verdict']})"
        )
    if fields["pass"].lower() != "true":
        raise SystemExit(f"{log_path}: pass must be true for release evidence")
    if fields["xdp_mode"] not in {"attached", "skb", "driver"}:
        raise SystemExit(f"{log_path}: invalid xdp_mode {fields['xdp_mode']}")
    if fields["tc_attached"].lower() != "true":
        raise SystemExit(f"{log_path}: TC must be attached for the release replay matrix")

    before_unavailable = fields["counter_before"] == "unavailable"
    after_unavailable = fields["counter_after"] == "unavailable"
    if before_unavailable != after_unavailable:
        raise SystemExit(f"{log_path}: counter availability is inconsistent")
    direction = str(case.spec.get("direction", "egress"))
    if (
        direction == "egress"
        and not before_unavailable
        and fields["counter_before"] == fields["counter_after"]
    ):
        raise SystemExit(f"{log_path}: egress counter evidence did not change")

    artifacts = {}
    for key in ("input_pcap", "capture_pcap", "command_output"):
        path_text = fields.get(key, "")
        if not path_text:
            raise SystemExit(f"{log_path}: missing {key}")
        path = resolve_artifact_path(log_path, path_text)
        if not path.is_file():
            raise SystemExit(f"{log_path}: {key} does not exist: {path}")
        if path.stat().st_size == 0:
            raise SystemExit(f"{log_path}: {key} is empty: {path}")
        artifacts[key] = path

    transcript = artifacts["command_output"].read_text(
        encoding="utf-8", errors="replace"
    ).strip()
    if not transcript:
        raise SystemExit(f"{log_path}: command_output has no transcript")
    if f"command: {fields['command']}" not in transcript:
        raise SystemExit(f"{log_path}: command_output does not record the claimed command")

    xdp_state = transcript_section(transcript, "xdp.state")
    tc_state = transcript_section(transcript, "tc.state")
    if not xdp_state or not tc_state:
        raise SystemExit(f"{log_path}: command_output is missing attach-state sections")
    transcript_xdp_mode = xdp_mode_from_state(xdp_state)
    if transcript_xdp_mode != fields["xdp_mode"]:
        raise SystemExit(
            f"{log_path}: xdp_mode contradicts command_output "
            f"({fields['xdp_mode']} != {transcript_xdp_mode})"
        )
    if fields["interface"] not in xdp_state:
        raise SystemExit(f"{log_path}: XDP state does not identify the claimed interface")
    if not tc_attached_from_state(tc_state):
        raise SystemExit(f"{log_path}: TC attach claim contradicts command_output")

    try:
        input_packets = pcap_packet_count(artifacts["input_pcap"])
        capture_packets = pcap_packet_count(artifacts["capture_pcap"])
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    if input_packets != 1:
        raise SystemExit(
            f"{log_path}: input PCAP must contain exactly one packet, got {input_packets}"
        )
    if fields["observed_verdict"] == "pass" and capture_packets < 1:
        raise SystemExit(f"{log_path}: pass verdict contradicts empty capture PCAP")
    if fields["observed_verdict"] == "drop" and capture_packets != 0:
        raise SystemExit(
            f"{log_path}: drop verdict contradicts capture PCAP with {capture_packets} packet(s)"
        )
    return 0


def self_test_validator() -> int:
    """Exercise the evidence validator against good and bad artifacts."""

    metadata = runtime_metadata()

    def write_test_pcap(path: Path, packet_count: int) -> None:
        body = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        packet = b"\x00" * 14
        for _ in range(packet_count):
            body.extend(struct.pack("<IIII", 0, 0, len(packet), len(packet)))
            body.extend(packet)
        path.write_bytes(body)

    def write_log(
        out_dir: Path,
        *,
        case: str = "ipv4_pass_allowed",
        commit: str = metadata.commit,
        expected: str = "pass",
        observed: str = "pass",
        passed: str = "true",
        include_input_pcap: bool = True,
        include_capture_pcap: bool = True,
        include_command_output: bool = True,
        counter_before: str = "before: 1",
        counter_after: str = "after: 2",
        xdp_mode: str = "driver",
        tc_attached: str = "true",
        malformed_input_pcap: bool = False,
    ) -> Path:
        input_pcap = out_dir / f"{case}.input.pcap"
        capture_pcap = out_dir / f"{case}.capture.pcap"
        command_output = out_dir / f"{case}.command.log"
        write_test_pcap(input_pcap, 1)
        write_test_pcap(capture_pcap, 1 if observed == "pass" else 0)
        if malformed_input_pcap:
            input_pcap.write_bytes(b"not a pcap")
        xdp_state = {
            "driver": "2: aegis-host0: prog/xdp id 1 driver",
            "skb": "2: aegis-host0: prog/xdp id 1 generic",
            "attached": "2: aegis-host0: prog/xdp id 1",
            "not_attached": "2: aegis-host0: state UP",
        }[xdp_mode]
        tc_state = (
            "qdisc clsact ffff: dev aegis-host0\n1: sched_cls name tc_egress"
            if tc_attached == "true"
            else "qdisc noqueue 0: dev aegis-host0"
        )
        command_output.write_text(
            "\n".join(
                [
                    "command: synthetic command",
                    "[xdp.state]",
                    xdp_state,
                    "[tc.state]",
                    tc_state,
                    "",
                ]
            ),
            encoding="utf-8",
        )
        log_path = out_dir / f"{case}.log"
        lines = [
            f"case: {case}",
            f"commit: {commit}",
            f"release_version: {metadata.release_version}",
            f"timestamp: {metadata.timestamp}",
            f"distribution: {metadata.distribution}",
            f"kernel: {metadata.kernel}",
            f"architecture: {metadata.architecture}",
            "interface: aegis-host0",
            f"xdp_mode: {xdp_mode}",
            f"tc_attached: {tc_attached}",
            "packet: synthetic validator case",
            f"expected_verdict: {expected}",
            f"observed_verdict: {observed}",
            "command: synthetic command",
        ]
        if include_command_output:
            lines.append(f"command_output: {command_output}")
        lines.extend(
            [
                f"counter_before: {counter_before}",
                f"counter_after: {counter_after}",
            ]
        )
        if include_input_pcap:
            lines.append(f"input_pcap: {input_pcap}")
        if include_capture_pcap:
            lines.append(f"capture_pcap: {capture_pcap}")
        lines.extend([f"pass: {passed}", ""])
        log_path.write_text("\n".join(lines), encoding="utf-8")
        return log_path

    with tempfile.TemporaryDirectory(prefix="aegis-validator-selftest.") as tmp:
        out_dir = Path(tmp)
        good = write_log(out_dir)
        assert validate_log(good, "ipv4_pass_allowed", metadata.commit) == 0

        missing = write_log(out_dir)
        missing.write_text(
            missing.read_text(encoding="utf-8").replace("capture_pcap:", "capture_pcap_missing:"),
            encoding="utf-8",
        )
        try:
            validate_log(missing, "ipv4_pass_allowed", metadata.commit)
            raise AssertionError("missing field should fail")
        except SystemExit:
            pass

        wrong_commit = write_log(
            out_dir, commit="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )
        try:
            validate_log(wrong_commit, "ipv4_pass_allowed", metadata.commit)
            raise AssertionError("wrong commit should fail")
        except SystemExit:
            pass

        mismatch = write_log(out_dir, expected="drop", observed="pass")
        try:
            validate_log(mismatch, "ipv4_pass_allowed", metadata.commit)
            raise AssertionError("verdict mismatch should fail")
        except SystemExit:
            pass

        missing_pcap = write_log(out_dir, include_capture_pcap=False)
        try:
            validate_log(missing_pcap, "ipv4_pass_allowed", metadata.commit)
            raise AssertionError("missing capture pcap should fail")
        except SystemExit:
            pass

        stale_counters = write_log(
            out_dir,
            counter_before="same: 1",
            counter_after="same: 1",
        )
        try:
            validate_log(stale_counters, "ipv4_pass_allowed", metadata.commit)
            raise AssertionError("stale counters should fail")
        except SystemExit:
            pass

        no_attach = write_log(out_dir, xdp_mode="not_attached", tc_attached="false")
        try:
            validate_log(no_attach, "ipv4_pass_allowed", metadata.commit)
            raise AssertionError("missing attach state should fail")
        except SystemExit:
            pass

        malformed_pcap = write_log(out_dir, malformed_input_pcap=True)
        try:
            validate_log(malformed_pcap, "ipv4_pass_allowed", metadata.commit)
            raise AssertionError("malformed PCAP should fail")
        except SystemExit:
            pass

        false_pass = write_log(out_dir, passed="false")
        try:
            validate_log(false_pass, "ipv4_pass_allowed", metadata.commit)
            raise AssertionError("pass:false should fail")
        except SystemExit:
            pass

        drop_capture = write_log(
            out_dir,
            case="ipv4_drop_exact",
            expected="drop",
            observed="drop",
            counter_before="unavailable",
            counter_after="unavailable",
        )
        assert validate_log(drop_capture, "ipv4_drop_exact", metadata.commit) == 0

    print("validator self-test passed")
    return 0


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def bounded_stress_iterations(value: str) -> int:
    parsed = non_negative_int(value)
    if parsed > MAX_STRESS_ITERATIONS:
        raise argparse.ArgumentTypeError(
            f"must be at most {MAX_STRESS_ITERATIONS}"
        )
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
    deps = require_scapy()
    Dot1Q, Ether, ICMP, ICMPv6EchoRequest, IP, IPOption_NOP, IPv6, IPv6ExtHdrFragment, Raw = deps[:9]

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
    metadata: RuntimeMetadata,
    observed: str,
    passed: bool,
    command: str,
    command_output: Path,
    counter_before: str,
    counter_after: str,
    xdp_mode: str,
    tc_attached: bool,
    interface: str,
    input_pcap: Path,
    capture_pcap: Path,
    error: str = "",
) -> None:
    log_file = out_dir / f"{case.name}.log"
    lines = [
        f"case: {case.name}",
        f"commit: {metadata.commit}",
        f"release_version: {metadata.release_version}",
        f"timestamp: {metadata.timestamp}",
        f"distribution: {metadata.distribution}",
        f"kernel: {metadata.kernel}",
        f"architecture: {metadata.architecture}",
        f"interface: {interface}",
        f"xdp_mode: {xdp_mode}",
        f"tc_attached: {'true' if tc_attached else 'false'}",
        f"packet: {case.packet}",
        f"expected_verdict: {case.expected}",
        f"observed_verdict: {observed}",
        f"command: {command}",
        f"command_output: {command_output}",
        f"counter_before: {first_line(counter_before)}",
        f"counter_after: {first_line(counter_after)}",
        f"input_pcap: {input_pcap}",
        f"capture_pcap: {capture_pcap}",
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
    metadata: RuntimeMetadata,
    command: str,
    command_output: Path,
    input_pcap: Path,
    capture_pcap: Path,
    interface: str,
    error: str,
) -> None:
    """Write a structured failure log when a case raises an exception."""
    log_file = out_dir / f"{case.name}.log"
    log_file.write_text(
        "\n".join(
            [
                f"case: {case.name}",
                f"commit: {metadata.commit}",
                f"release_version: {metadata.release_version}",
                f"timestamp: {metadata.timestamp}",
                f"distribution: {metadata.distribution}",
                f"kernel: {metadata.kernel}",
                f"architecture: {metadata.architecture}",
                f"interface: {interface}",
                "xdp_mode: unknown",
                "tc_attached: false",
                f"packet: {case.packet}",
                f"expected_verdict: {case.expected}",
                "observed_verdict: unknown",
                f"command: {command}",
                f"command_output: {command_output}",
                "counter_before: unavailable",
                "counter_after: unavailable",
                f"input_pcap: {input_pcap}",
                f"capture_pcap: {capture_pcap}",
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
    metadata: RuntimeMetadata,
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
                f"commit: {metadata.commit}",
                f"release_version: {metadata.release_version}",
                f"timestamp: {metadata.timestamp}",
                f"distribution: {metadata.distribution}",
                f"kernel: {metadata.kernel}",
                f"architecture: {metadata.architecture}",
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
    deps = require_scapy()
    IP, IPv6, sniff = deps[4], deps[6], deps[10]
    spec = json.loads(args.match_json)
    marker = Path(args.marker)
    capture_pcap = Path(args.capture_pcap)

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
    try:
        write_pcap(capture_pcap, packets[0] if packets else None)
    except Exception as exc:
        raise SystemExit(f"failed to write capture pcap {capture_pcap}: {exc}")
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
    sendp = require_scapy()[9]
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


def run_case(
    args: argparse.Namespace,
    case: ReplayCase,
    host_mac: str,
    peer_mac: str,
    metadata: RuntimeMetadata,
) -> bool:
    sendp = require_scapy()[9]
    out_dir = Path(args.out_dir)
    input_pcap = out_dir / f"{case.name}.input.pcap"
    capture_pcap = out_dir / f"{case.name}.capture.pcap"
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
                "--capture-pcap",
                str(capture_pcap),
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
        tc_qdisc_state = run_text(["tc", "qdisc", "show", "dev", args.host_if])
        tc_program_state = run_text(["bpftool", "prog", "show"])
        tc_state = "\n".join([tc_qdisc_state, tc_program_state])
        xdp_mode = xdp_mode_from_state(xdp_state)
        tc_attached = tc_attached_from_state(tc_state)

        packet = build_packet(case.spec, host_mac, peer_mac)
        write_pcap(input_pcap, packet)
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
        command_output = write_command_output(
            out_dir,
            case,
            command,
            "",
            send_error,
            stdout,
            stderr,
            xdp_state,
            tc_state,
            counters_before,
            counters_after,
        )
        write_log(
            out_dir,
            case,
            metadata,
            observed,
            passed,
            command,
            command_output,
            counters_before,
            counters_after,
            xdp_mode,
            tc_attached,
            args.host_if,
            input_pcap,
            capture_pcap,
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
    metadata = runtime_metadata()

    for iteration in range(1, args.stress_iterations + 1):
        for case in CASES:
            try:
                if not run_case(args, case, host_mac, peer_mac, metadata):
                    failures.append(f"iteration={iteration}:case={case.name}")
            except Exception as exc:
                failures.append(f"iteration={iteration}:case={case.name}:error={first_line(str(exc))}")
                write_error_log(
                    Path(args.out_dir),
                    case,
                    metadata,
                    "stress replay matrix",
                    Path(args.out_dir) / f"{case.name}.command.log",
                    Path(args.out_dir) / f"{case.name}.input.pcap",
                    Path(args.out_dir) / f"{case.name}.capture.pcap",
                    args.host_if,
                    str(exc),
                )

    duration = time.monotonic() - start
    write_stress_summary(
        Path(args.out_dir),
        args.stress_iterations,
        failures,
        duration,
        args,
        metadata,
    )
    return not failures


def run_replay(args: argparse.Namespace) -> int:
    require_root()
    require_lab_name(args.host_if, "host interface")
    require_lab_name(args.peer_ns, "peer namespace")
    require_lab_name(args.peer_if, "peer interface")

    Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    metadata = runtime_metadata()
    host_mac = mac_for(args.host_if)
    peer_mac = mac_for(args.peer_if, args.peer_ns)

    failed = []
    for case in CASES:
        try:
            if not run_case(args, case, host_mac, peer_mac, metadata):
                failed.append(case.name)
        except Exception as exc:
            print(f"case {case.name} raised: {exc}", file=sys.stderr)
            write_error_log(
                Path(args.out_dir),
                case,
                metadata,
                "packet replay",
                Path(args.out_dir) / f"{case.name}.command.log",
                Path(args.out_dir) / f"{case.name}.input.pcap",
                Path(args.out_dir) / f"{case.name}.capture.pcap",
                args.host_if,
                str(exc),
            )
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
        type=bounded_stress_iterations,
        default=None,
        help=(
            "run a bounded repeated replay matrix after the required one-shot cases "
            f"(maximum: {MAX_STRESS_ITERATIONS})"
        ),
    )
    parser.add_argument("--list-cases", action="store_true")
    parser.add_argument("--validate-packets", action="store_true")
    parser.add_argument("--receive-one", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--send-one", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--validate-log", help=argparse.SUPPRESS)
    parser.add_argument("--expected-case", help=argparse.SUPPRESS)
    parser.add_argument("--expected-commit", help=argparse.SUPPRESS)
    parser.add_argument("--self-test-validator", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--iface", help=argparse.SUPPRESS)
    parser.add_argument("--marker", help=argparse.SUPPRESS)
    parser.add_argument("--ready-marker", help=argparse.SUPPRESS)
    parser.add_argument("--capture-pcap", help=argparse.SUPPRESS)
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

    if args.validate_log:
        if not args.expected_case or not args.expected_commit:
            raise SystemExit("--validate-log requires --expected-case and --expected-commit")
        return validate_log(Path(args.validate_log), args.expected_case, args.expected_commit)

    if args.self_test_validator:
        return self_test_validator()

    if args.stress_iterations is None:
        try:
            args.stress_iterations = bounded_stress_iterations(
                os.environ.get("AEGIS_STRESS_ITERATIONS", "0")
            )
        except argparse.ArgumentTypeError as exc:
            parser.error(f"AEGIS_STRESS_ITERATIONS {exc}")

    return run_replay(args)


if __name__ == "__main__":
    raise SystemExit(main())
