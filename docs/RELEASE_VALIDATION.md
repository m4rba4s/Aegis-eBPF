# Release Validation

Aegis release validation separates build proof from runtime proof. A successful
non-privileged gate does not prove verifier acceptance, attach success, or
firewall enforcement.

## Non-Privileged Gate

Run on the exact release commit:

```bash
git status --short
git rev-parse --short HEAD

CARGO_HOME=/tmp/aegis-cargo-home ./scripts/release-gates.sh nonpriv
```

`AEGIS_DOC_TARGET_DIR` may be set when the documentation output path must be
stable. If it is omitted, the gate writes `cargo doc` output to a fresh
`/tmp/aegis-doc-target.*` directory, then removes it after the documentation
step, to avoid stale privileged artifacts in `target/doc` and repeated `/tmp`
growth.

Required evidence:

- empty `git status --short`
- release HEAD
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `cargo test --workspace --doc`
- `cargo doc --workspace --all-features --no-deps`
- `cargo run -p xtask -- build-all --profile release`
- release userspace build
- `file` and `llvm-objdump -h` for XDP and TC objects
- `cargo audit -D warnings`
- `cargo deny check`
- CLI command parse for `aegis-cli --iface lo daemon --help`

## Privileged Lab Gate

Run only in a disposable VM or lab host:

```bash
sudo -E AEGIS_PACKET_REPLAY_DIR=/tmp/aegis-replay \
  CARGO_HOME=/tmp/aegis-cargo-home \
  ./scripts/release-gates.sh privileged-lab
```

`AEGIS_PACKET_REPLAY_DIR` is recommended for stable, archiveable evidence
paths. If it is omitted, the privileged gate creates a `/tmp/aegis-replay.*`
directory and prints the selected path. An explicit directory must be new or
empty so stale logs from an earlier run cannot be mixed into release evidence.

Required evidence:

- veth/netns creation for `aegis-host0`, `aegis-peer0`, and `aegis-reltest`
- bpftool diagnostic load logs for XDP and TC objects
- Aya loader daemon log
- XDP attach state
- TC clsact/filter state
- packet replay logs for every required case
- detach/cleanup state

If bpftool load fails but Aya load/attach succeeds, bpftool is diagnostic for
that object format and the release gate must archive both the bpftool failure
and Aya success. If Aya load/attach fails, do not ship.

## Pre-Release Stress Gate

Run this after `privileged-lab` and before cutting a production release
candidate. It is still lab-only and uses the same disposable veth/netns setup;
it does not touch a production NIC.

### Host Resource Stop Rules

Check the virtualization host before starting the disposable VM:

```bash
free -h
awk '/MemAvailable|SwapTotal|SwapFree/ {print}' /proc/meminfo
ps -eo pid,comm,rss,%mem,%cpu --sort=-rss | head -20
```

Do not start or continue the stress gate when any of these conditions is true:

- host `MemAvailable` is below 8 GiB,
- more than 50% of host swap is already used,
- the VM plus active desktop applications consume more than 80% of host RAM,
- a package update, large build, browser workload, or another VM is competing
  for memory or I/O,
- the desktop, SSH session, or VM console starts lagging.

The gate also performs an in-environment preflight. Stress mode requires at
least 4096 MiB `MemAvailable` and refuses more than 75% swap use by default.
`AEGIS_MIN_AVAILABLE_MB` and `AEGIS_MAX_SWAP_USED_PERCENT` may make the limits
stricter. `AEGIS_ALLOW_LOW_RESOURCE_LAB=1` is an explicit waiver and must be
recorded with the evidence; do not use it for release qualification.

```bash
sudo -E AEGIS_PACKET_REPLAY_DIR=/tmp/aegis-replay-stress \
  AEGIS_STRESS_ITERATIONS=25 \
  CARGO_HOME=/tmp/aegis-cargo-home \
  ./scripts/release-gates.sh stress-lab
```

The stress gate repeats the full packet replay matrix for
`AEGIS_STRESS_ITERATIONS` iterations after the required one-shot replay cases.
It is a stability/enforcement stress check, not a throughput benchmark. Do not
publish packets-per-second claims from this gate.

Safety bounds:

- maximum stress iterations: `50`,
- calculated whole-replay watchdog, capped at `7200` seconds,
- `SIGTERM` followed by `SIGKILL` after 30 seconds if replay ignores shutdown,
- resource preflight archived as `resource-preflight.log`.

Stop the run immediately if the host begins swapping heavily, thermal
throttling persists, the VM console stops responding, or cleanup cannot be
verified. A hard-reset run is failed evidence, not a stress PASS.

Required stress evidence:

- `stress-summary.log`
- `case: stress_replay_matrix`
- `stress_iterations: <AEGIS_STRESS_ITERATIONS>`
- `stress_total_case_runs: <iterations * current case count>`
- `pass: true`

The current case count is `18`, obtained from:

```bash
python3 scripts/packet-replay-lab.py --list-cases | wc -l
```

## Packet Replay Artifacts

The replay artifact directory must contain one `.log` per case:

- `ipv4_pass_allowed.log`
- `ipv4_drop_exact.log`
- `ipv4_drop_cidr.log`
- `ipv6_pass_allowed.log`
- `ipv6_drop_exact.log`
- `ipv6_drop_cidr.log`
- `vlan_behavior.log`
- `qinq_behavior.log`
- `ipv4_ihl_options_behavior.log`
- `ipv4_fragment_behavior.log`
- `truncated_tcp_blocked_ipv4_exact.log`
- `truncated_udp_blocked_ipv4_exact.log`
- `truncated_tcp_blocked_ipv4_cidr.log`
- `truncated_udp_blocked_ipv4_cidr.log`

Each log must include:

```text
case: <case_name>
commit: <full-sha>
release_version: <version>
timestamp: <utc-iso8601>
distribution: <os-release>
kernel: <uname -r>
architecture: <uname -m>
interface: <iface>
xdp_mode: <driver|skb|attached|not_attached>
tc_attached: <true|false>
packet: <description>
expected_verdict: pass|drop
observed_verdict: pass|drop|unknown
command: <exact command>
command_output: <path to raw command transcript>
counter_before: <raw counter snapshot>
counter_after: <raw counter snapshot>
input_pcap: <path to generated input pcap>
capture_pcap: <path to generated receiver pcap>
pass: true|false
```

Missing logs, wrong case names, or `pass: false` fail the release gate.

### Replay Scope Notes

- `vlan_behavior` and `qinq_behavior` validate the **fail-closed DROP** policy for 802.1Q and 802.1ad tagged frames. Aegis does not parse VLAN payloads; these cases prove that tagged traffic is rejected.
- `ipv6_pass_allowed`, `ipv6_drop_exact`, and `ipv6_drop_cidr` validate **exact IP and CIDR blocklist** enforcement only. Extension header edge cases (hop-by-hop, routing, fragment, destination options) are **not covered** by the current replay matrix and must not be claimed as tested.
- `ipv4_ihl_options_behavior` and `ipv4_fragment_behavior` validate fail-closed DROP for packets with IP options and IP fragments respectively.

## Replay Driver

The lab replay driver is:

```bash
sudo -E AEGIS_PACKET_REPLAY_DIR=/tmp/aegis-replay \
  python3 scripts/packet-replay-lab.py \
  --host-if aegis-host0 \
  --peer-ns aegis-reltest \
  --peer-if aegis-peer0 \
  --out-dir /tmp/aegis-replay
```

It requires Scapy in the lab VM:

```bash
python3 -m pip install scapy
```

The script refuses non-`aegis-*` lab names by default.

## Release Approval

A release candidate requires:

- no S0/S1 findings
- clean worktree
- non-privileged gate pass on the exact commit
- privileged verifier/load/attach/detach evidence
- packet replay matrix pass
- bounded stress replay matrix pass
- deploy/install start and rollback evidence
- supply-chain gates pass or signed waiver
- documentation that matches the evidence

### Historical v4.2.0 Claim

Commit `0dadb3e` recorded a systemd smoke test, an 18-case privileged lab PASS,
a 25-iteration stress PASS, and archive SHA-256
`1830aac91ef2caa96e5e17a99e06b964c63844b7a9f1b0d7830d29171b567cc8`.
The raw archive is not present or linked as a retrievable release asset in this
repository, so these entries are `historical_unverified`, not current release
evidence. See `ENTERPRISE_QA_REPORT_v4.2.0.md` for the retraction.
