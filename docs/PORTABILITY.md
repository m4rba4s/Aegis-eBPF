# Aegis Portability Matrix

This matrix is a support contract, not a performance claim. A target becomes
supported only after the listed evidence is archived for the release commit.

| target | xdp mode | tc egress | support level | required evidence |
| --- | --- | --- | --- | --- |
| Fedora latest x86_64 | driver when available, SKB fallback | clsact egress | supported after proof | `release-gates.sh privileged-lab` log plus replay artifacts |
| Ubuntu LTS x86_64 | SKB minimum, driver when available | clsact egress | supported after proof | privileged lab log plus replay artifacts |
| Debian stable x86_64 | SKB minimum, driver when available | clsact egress | supported after proof | privileged lab log plus replay artifacts |
| Arch latest x86_64 | driver when available, SKB fallback | clsact egress | best_effort until repeated | privileged lab log plus replay artifacts |
| arm64 | SKB minimum | clsact egress | unsupported unless tested | native arm64 build, verifier/load/attach, and replay logs |
| veth/netns lab | SKB/generic expected | clsact egress | required release lab | `sudo -E AEGIS_PACKET_REPLAY_DIR=... ./scripts/release-gates.sh privileged-lab` |
| physical NIC | driver preferred, SKB fallback | clsact egress | supported only if tested | NIC/driver/kernel log plus replay or equivalent packet evidence |
| systemd host | same as host target | clsact egress | supported after service proof | install log, `systemctl start/stop/status`, `ip` and `tc` cleanup state |
| Docker build artifact | not a runtime claim | not a runtime claim | build artifact only | `docker build --output=dist .`, checksums |
| Kubernetes DaemonSet | host netns | clsact egress | best_effort unless tested | DaemonSet startup logs plus node replay evidence |

## Requirements

- Linux kernel 5.4 or newer; kernel 5.8 or newer is preferred for `CAP_BPF`.
- `CAP_BPF` and `CAP_NET_ADMIN` for systemd service operation.
- `bpffs` mounted at `/sys/fs/bpf`.
- `ip` and `tc` from iproute2.
- `bpftool` for verifier diagnostics and release evidence.
- TC egress is required by default. `--no-tc` is an explicit ingress-only waiver.

## Claim Rules

- Do not claim arm64 support without native arm64 build and privileged runtime evidence.
- Do not claim XDP driver-mode support on a NIC without driver-mode attach logs.
- Do not claim Kubernetes production support without node-level attach and replay artifacts.
- Do not claim measured throughput without benchmark logs that include kernel, NIC/driver, XDP mode, CPU, packet size, rule count, pass/drop mix, pps, and command.
- VLAN/QinQ (802.1Q/802.1ad) tagged frames are dropped fail-closed. VLAN-aware forwarding is not supported. Do not claim VLAN transparency without bounded parsing proof.
- IPv6 enforcement covers exact IP and CIDR blocklists only. Extension header chain walking is limited to the basic `next_header` field. Do not claim full IPv6 extension header support without replay evidence covering hop-by-hop, routing, fragment, and destination options headers.
