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
- `cargo audit --no-fetch -D warnings`
- `cargo deny check`
- CLI command parse for `aegis-cli --iface lo daemon --help`

## Privileged Lab Gate

Run only in a disposable VM or lab host:

```bash
sudo -E AEGIS_PACKET_REPLAY_DIR=/tmp/aegis-replay \
  CARGO_HOME=/tmp/aegis-cargo-home \
  ./scripts/release-gates.sh privileged-lab
```

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

## Packet Replay Artifacts

`AEGIS_PACKET_REPLAY_DIR` must contain one `.log` per case:

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
packet: <description>
expected_verdict: pass|drop
observed_verdict: pass|drop|unknown
command: <exact command>
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
- deploy/install start and rollback evidence
- supply-chain gates pass or signed waiver
- documentation that matches the evidence
