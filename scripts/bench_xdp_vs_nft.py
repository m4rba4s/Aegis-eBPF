#!/usr/bin/env python3
"""Aegis XDP vs nftables benchmark orchestrator.

Creates an isolated veth/netns topology, runs equivalent rulesets on both
engines, measures pps throughput via AF_PACKET traffic generator, and produces
a structured JSON report.

Must be run as root:
    sudo python3 scripts/bench_xdp_vs_nft.py [--duration 30] [--runs 3] [--cidr-count 1000]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NETNS = "aegis-bench-ns"
HOST_IF = "bench-host0"
PEER_IF = "bench-peer0"
HOST_IP4 = "10.88.0.1"
PEER_IP4 = "10.88.0.2"
HOST_IP6 = "fd88::1"
PEER_IP6 = "fd88::2"

BLOCKED_EXACT_IP = "198.51.100.10"
BLOCKED_CIDR_BASE = "198.51"   # /16 range for populating CIDR sets

SCENARIOS = ["pass", "block_exact", "block_cidr", "syn_flood", "mixed"]

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
TRAFFIC_GEN = SCRIPT_DIR / "bench_traffic_gen.py"

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class RunResult:
    engine: str
    scenario: str
    run_idx: int
    duration_s: int
    pps_samples: List[int] = field(default_factory=list)
    median_pps: int = 0
    mean_pps: int = 0
    stddev_pps: float = 0.0
    total_sent: int = 0
    cpu_percent: float = 0.0


@dataclass
class ScenarioSummary:
    scenario: str
    aegis_median_pps: int = 0
    aegis_stddev: float = 0.0
    nft_median_pps: int = 0
    nft_stddev: float = 0.0
    ratio: float = 0.0  # aegis / nft


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------


def sh(cmd: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, shell=True, check=check, capture_output=capture, text=True,
    )


def sh_out(cmd: str) -> str:
    r = sh(cmd, check=True, capture=True)
    return r.stdout.strip()


# ---------------------------------------------------------------------------
# Topology management
# ---------------------------------------------------------------------------


def topology_up() -> None:
    """Create veth pair + netns."""
    sh(f"ip netns add {NETNS}", check=False)
    sh(f"ip link del {HOST_IF} 2>/dev/null", check=False)

    sh(f"ip link add {HOST_IF} type veth peer name {PEER_IF}")
    sh(f"ip link set {PEER_IF} netns {NETNS}")

    sh(f"ip addr add {HOST_IP4}/24 dev {HOST_IF}")
    sh(f"ip -n {NETNS} addr add {PEER_IP4}/24 dev {PEER_IF}")
    sh(f"ip addr add {HOST_IP6}/64 dev {HOST_IF}")
    sh(f"ip -n {NETNS} addr add {PEER_IP6}/64 dev {PEER_IF}")

    sh(f"ip link set {HOST_IF} up")
    sh(f"ip -n {NETNS} link set {PEER_IF} up")
    sh(f"ip -n {NETNS} link set lo up")

    # Disable GRO/GSO/TSO on veth for consistent small-packet benchmarks
    for feat in ["gro", "gso", "tso"]:
        sh(f"ethtool -K {HOST_IF} {feat} off 2>/dev/null", check=False)
        sh(f"ip netns exec {NETNS} ethtool -K {PEER_IF} {feat} off 2>/dev/null", check=False)

    print(f"[topo] netns={NETNS} host={HOST_IF}/{HOST_IP4} peer={PEER_IF}/{PEER_IP4}")


def topology_down() -> None:
    """Tear down."""
    sh(f"ip link del {HOST_IF} 2>/dev/null", check=False)
    sh(f"ip netns del {NETNS} 2>/dev/null", check=False)


# ---------------------------------------------------------------------------
# CPU measurement
# ---------------------------------------------------------------------------


def read_cpu_jiffies() -> List[int]:
    with open("/proc/stat") as f:
        line = f.readline()  # cpu  user nice system idle ...
    return [int(x) for x in line.split()[1:]]


def cpu_percent(before: List[int], after: List[int]) -> float:
    deltas = [a - b for a, b in zip(after, before)]
    total = sum(deltas)
    if total == 0:
        return 0.0
    idle = deltas[3]  # idle is 4th field
    return 100.0 * (1.0 - idle / total)


# ---------------------------------------------------------------------------
# nftables engine
# ---------------------------------------------------------------------------


def nft_setup(cidr_count: int) -> None:
    """Install equivalent nftables ruleset."""
    # Flush any previous bench table
    sh("nft delete table inet aegis_bench 2>/dev/null", check=False)

    ruleset = textwrap.dedent("""\
        table inet aegis_bench {
            set blocklist_v4 {
                type ipv4_addr;
                elements = { 198.51.100.10 }
            }

            set cidr_blocklist_v4 {
                type ipv4_addr;
                flags interval;
            }

            set allowlist_v4 {
                type ipv4_addr;
            }

            chain ingress {
                type filter hook input priority -200; policy accept;

                # Counters for measurement
                counter packets 0 bytes 0

                # 1. Allowlist bypass
                ip saddr @allowlist_v4 accept

                # 2. RFC1918 auto-trust
                ip saddr 10.0.0.0/8 accept
                ip saddr 172.16.0.0/12 accept
                ip saddr 192.168.0.0/16 accept

                # 3. Exact blocklist
                ip saddr @blocklist_v4 counter drop

                # 4. CIDR blocklist
                ip saddr @cidr_blocklist_v4 counter drop

                # 5. VLAN fail-closed
                ether type 0x8100 drop
                ether type 0x88a8 drop

                # 6. IP options (IHL != 5)
                ip hdrlength != 5 drop

                # 7. Fragment drop
                ip frag-off & 0x3fff != 0 drop

                # 8. TCP length validation (approximate)
                ip protocol tcp ip length < 40 drop

                # 9. TCP scan detection
                tcp flags & (fin|urg|psh) == fin|urg|psh drop
                tcp flags == 0x0 drop
                tcp flags & (syn|fin) == syn|fin drop

                # 10. SYN rate limiting
                tcp flags syn limit rate over 50/second burst 10 packets counter drop
            }
        }
    """)

    # Write and load base ruleset
    with tempfile.NamedTemporaryFile(mode="w", suffix=".nft", delete=False) as f:
        f.write(ruleset)
        f.flush()
        sh(f"nft -f {f.name}")
        os.unlink(f.name)

    # Populate CIDR set with entries
    if cidr_count > 0:
        print(f"[nft] populating CIDR set with {cidr_count} /24 entries...")
        # Build batch of CIDR entries: 198.51.x.0/24
        elements = []
        for i in range(cidr_count):
            third = i & 0xFF
            # Wrap around using different /16 blocks if needed
            prefix_hi = 198 + (i >> 16)
            prefix_lo = 51 + ((i >> 8) & 0xFF)
            if prefix_hi > 223:
                break
            elements.append(f"{prefix_hi}.{prefix_lo}.{third}.0/24")

        # Add in batches of 500 to avoid command-line limits
        batch_size = 500
        for start in range(0, len(elements), batch_size):
            batch = elements[start : start + batch_size]
            elem_str = ", ".join(batch)
            sh(f"nft add element inet aegis_bench cidr_blocklist_v4 {{ {elem_str} }}")

    print(f"[nft] ruleset loaded, {cidr_count} CIDR entries")


def nft_teardown() -> None:
    sh("nft delete table inet aegis_bench 2>/dev/null", check=False)


def nft_get_counters() -> Dict[str, int]:
    """Read nftables counters."""
    try:
        out = sh_out("nft list chain inet aegis_bench ingress")
        # Parse counter lines
        pkt_matches = re.findall(r"counter packets (\d+)", out)
        total = sum(int(x) for x in pkt_matches)
        return {"nft_counter_packets": total}
    except Exception:
        return {"nft_counter_packets": 0}


# ---------------------------------------------------------------------------
# Aegis engine
# ---------------------------------------------------------------------------


def aegis_setup(cidr_count: int) -> Optional[subprocess.Popen]:
    """Attach Aegis to bench-host0 and populate maps."""
    aegis_bin = PROJECT_ROOT / "target" / "release" / "aegis-cli"
    if not aegis_bin.exists():
        print(f"[aegis] ERROR: binary not found at {aegis_bin}")
        print("[aegis] Run: AEGIS_REQUIRE_EMBEDDED=1 cargo build --release -p aegis-cli")
        sys.exit(1)

    # Start aegis in daemon mode.
    # bench-host0 doesn't match veth/tun/docker prefixes, so Aegis
    # auto-disables RFC1918 whitelist (CFG_SKIP_WHITELIST=1).
    proc = subprocess.Popen(
        [str(aegis_bin), "-i", HOST_IF, "daemon"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Give it time to attach XDP + TC
    time.sleep(3)

    if proc.poll() is not None:
        stderr = proc.stderr.read().decode() if proc.stderr else ""
        print(f"[aegis] failed to start: {stderr}")
        sys.exit(1)

    # Populate blocklist via bpftool batch file
    import struct
    import socket

    # Wait for pins to appear
    pin_base = f"/sys/fs/bpf/aegis/{HOST_IF}/abi-v1"
    for _ in range(20):
        if os.path.exists(f"{pin_base}/BLOCKLIST"):
            break
        time.sleep(0.5)

    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        # Add exact block entry: 198.51.100.10, port=0, proto=0
        ip_int = struct.unpack("!I", socket.inet_aton("198.51.100.10"))[0]
        key_hex = " ".join(f"{b:02x}" for b in struct.pack("!I H B B", ip_int, 0, 0, 0))
        val_hex = "02 00 00 00"
        f.write(f"map update pinned {pin_base}/BLOCKLIST key hex {key_hex} value hex {val_hex}\n")

        # Add CIDR entries
        for i in range(cidr_count):
            third = i & 0xFF
            prefix_hi = 198 + (i >> 16)
            prefix_lo = 51 + ((i >> 8) & 0xFF)
            if prefix_hi > 223:
                break
            
            ip_str = f"{prefix_hi}.{prefix_lo}.{third}.0"
            ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
            key_bytes = struct.pack("=I", 24) + struct.pack("!I", ip_int)
            key_hex = " ".join(f"{b:02x}" for b in key_bytes)
            val_hex = "02 04 00 00"
            f.write(f"map update pinned {pin_base}/CIDR_BLOCKLIST key hex {key_hex} value hex {val_hex}\n")

        f.flush()
        sh(f"bpftool batch file {f.name}")
        os.unlink(f.name)

    print(f"[aegis] attached to {HOST_IF}, pid={proc.pid}, maps populated")
    return proc


def aegis_teardown(proc: Optional[subprocess.Popen]) -> None:
    """Detach Aegis."""
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Clean up XDP attachment
    sh(f"ip link set {HOST_IF} xdp off 2>/dev/null", check=False)
    sh(f"tc qdisc del dev {HOST_IF} clsact 2>/dev/null", check=False)
    # Clean up BPF pins
    sh(f"rm -rf /sys/fs/bpf/aegis/{HOST_IF} 2>/dev/null", check=False)

    time.sleep(1)
    print("[aegis] detached and cleaned up")


def aegis_get_stats() -> Dict[str, Any]:
    """Read Aegis STATS map via bpftool."""
    try:
        pin = f"/sys/fs/bpf/aegis/{HOST_IF}/STATS"
        if not os.path.exists(pin):
            return {}
        out = sh_out(f"bpftool map dump pinned {pin} -j 2>/dev/null")
        return json.loads(out) if out else {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Traffic generator runner
# ---------------------------------------------------------------------------


def run_traffic_gen(
    scenario: str, duration: int, warmup: int = 5
) -> List[Dict[str, Any]]:
    """Run the traffic generator inside the netns and collect pps samples."""
    cmd = (
        f"ip netns exec {NETNS} python3 {TRAFFIC_GEN} "
        f"--iface {PEER_IF} --scenario {scenario} "
        f"--duration {duration} --warmup {warmup}"
    )

    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )

    records = []
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                records.append(rec)
            except json.JSONDecodeError:
                pass
    except Exception:
        pass

    proc.wait(timeout=duration + warmup + 30)
    return records


# ---------------------------------------------------------------------------
# Single benchmark run
# ---------------------------------------------------------------------------


def benchmark_run(
    engine: str, scenario: str, run_idx: int, duration: int
) -> RunResult:
    """Execute one benchmark run and return results."""
    result = RunResult(
        engine=engine, scenario=scenario, run_idx=run_idx, duration_s=duration,
    )

    cpu_before = read_cpu_jiffies()

    # Run traffic generator
    records = run_traffic_gen(scenario, duration)

    cpu_after = read_cpu_jiffies()
    result.cpu_percent = round(cpu_percent(cpu_before, cpu_after), 1)

    # Extract measurement-phase pps samples
    pps_samples = [r["pps"] for r in records if r.get("phase") == "measure"]
    result.pps_samples = pps_samples

    if pps_samples:
        result.median_pps = int(statistics.median(pps_samples))
        result.mean_pps = int(statistics.mean(pps_samples))
        result.stddev_pps = round(statistics.stdev(pps_samples), 1) if len(pps_samples) > 1 else 0.0
        result.total_sent = sum(r.get("total_sent", 0) for r in records if r.get("phase") == "final")
        if not result.total_sent:
            result.total_sent = result.mean_pps * duration

    tag = f"[{engine}:{scenario}:run{run_idx}]"
    print(
        f"{tag} median={result.median_pps:,} pps  "
        f"mean={result.mean_pps:,} pps  "
        f"stddev={result.stddev_pps:,.0f}  "
        f"cpu={result.cpu_percent}%  "
        f"samples={len(pps_samples)}"
    )

    return result


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(description="Aegis XDP vs nftables benchmark")
    ap.add_argument("--duration", type=int, default=30, help="Measurement seconds per scenario")
    ap.add_argument("--warmup", type=int, default=5, help="Warmup seconds")
    ap.add_argument("--runs", type=int, default=3, help="Runs per scenario")
    ap.add_argument("--cidr-count", type=int, default=1000, help="CIDR entries to load")
    ap.add_argument(
        "--scenarios",
        nargs="+",
        default=SCENARIOS,
        choices=SCENARIOS,
        help="Scenarios to run",
    )
    ap.add_argument("--output", default=None, help="JSON output file")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("ERROR: must run as root (sudo)")
        sys.exit(1)

    print("=" * 72)
    print("  Aegis XDP vs nftables Benchmark")
    print(f"  duration={args.duration}s  warmup={args.warmup}s  runs={args.runs}")
    print(f"  cidr_entries={args.cidr_count}  scenarios={args.scenarios}")
    print("=" * 72)

    # Collect system info
    kernel = sh_out("uname -r")
    cpu_model = sh_out("lscpu | grep 'Model name' | sed 's/.*: *//'")
    nft_ver = sh_out("nft --version")

    sysinfo = {
        "kernel": kernel,
        "cpu": cpu_model,
        "nftables": nft_ver,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": args.duration,
        "warmup_s": args.warmup,
        "runs": args.runs,
        "cidr_count": args.cidr_count,
        "xdp_mode": "generic (veth)",
    }
    print(f"\n[sys] kernel={kernel} cpu={cpu_model}")

    all_results: List[RunResult] = []

    try:
        # --- Phase 1: nftables ---
        print("\n" + "=" * 72)
        print("  Phase 1: nftables")
        print("=" * 72)

        topology_up()
        nft_setup(args.cidr_count)

        for scenario in args.scenarios:
            for run_idx in range(args.runs):
                result = benchmark_run("nftables", scenario, run_idx, args.duration)
                all_results.append(result)

        nft_teardown()
        topology_down()
        time.sleep(2)

        # --- Phase 2: Aegis XDP ---
        print("\n" + "=" * 72)
        print("  Phase 2: Aegis XDP")
        print("=" * 72)

        topology_up()
        aegis_proc = aegis_setup(args.cidr_count)

        for scenario in args.scenarios:
            for run_idx in range(args.runs):
                result = benchmark_run("aegis", scenario, run_idx, args.duration)
                all_results.append(result)

        aegis_teardown(aegis_proc)
        topology_down()

    except KeyboardInterrupt:
        print("\n[!] interrupted")
    finally:
        # Ensure cleanup
        nft_teardown()
        topology_down()

    # --- Summary ---
    print("\n" + "=" * 72)
    print("  RESULTS SUMMARY")
    print("=" * 72)

    summaries: List[ScenarioSummary] = []

    for scenario in args.scenarios:
        aegis_runs = [r for r in all_results if r.engine == "aegis" and r.scenario == scenario]
        nft_runs = [r for r in all_results if r.engine == "nftables" and r.scenario == scenario]

        s = ScenarioSummary(scenario=scenario)

        if aegis_runs:
            medians = [r.median_pps for r in aegis_runs]
            s.aegis_median_pps = int(statistics.median(medians))
            s.aegis_stddev = round(statistics.stdev(medians), 0) if len(medians) > 1 else 0

        if nft_runs:
            medians = [r.median_pps for r in nft_runs]
            s.nft_median_pps = int(statistics.median(medians))
            s.nft_stddev = round(statistics.stdev(medians), 0) if len(medians) > 1 else 0

        if s.nft_median_pps > 0:
            s.ratio = round(s.aegis_median_pps / s.nft_median_pps, 2)

        summaries.append(s)

    # Print table
    header = f"{'Scenario':<16} {'Aegis (pps)':>14} {'±':>8} {'nftables (pps)':>16} {'±':>8} {'Ratio':>8}"
    print(header)
    print("-" * len(header))

    for s in summaries:
        print(
            f"{s.scenario:<16} "
            f"{s.aegis_median_pps:>14,} "
            f"{s.aegis_stddev:>8,.0f} "
            f"{s.nft_median_pps:>16,} "
            f"{s.nft_stddev:>8,.0f} "
            f"{s.ratio:>7.2f}x"
        )

    # Save JSON report
    report = {
        "system": sysinfo,
        "summaries": [asdict(s) for s in summaries],
        "runs": [asdict(r) for r in all_results],
    }

    output_path = args.output or str(
        PROJECT_ROOT / "docs" / "benchmarks" / "v4.3.0-xdp-vs-nftables.json"
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[report] saved to {output_path}")


if __name__ == "__main__":
    main()
