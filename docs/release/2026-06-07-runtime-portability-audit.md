# Verdict

> [!WARNING]
> NONPRIV-VALIDATED / CLEAN TREE / PRODUCTION CLAIM NOT PROVEN

The userspace codebase and eBPF parser shape have been statically reviewed, and non-privileged gates passed in the latest local validation. However, the final privileged lab gate (verifier load, XDP/TC attach, packet replay tests, stress replay, and cleanup proof) has not been archived for the current release candidate. We cannot claim `LAB-VALIDATED ONLY` or `READY FOR TAG, WITH EVIDENCE` until enforcement is proven in a disposable root environment.

# Task Classification

* Class: release-validation
* Risk: high
* Evidence status: Partial (non-privileged validation exists; privileged verifier/runtime evidence pending)

# Confirmed Facts

* Non-privileged Rust gates (cargo check, clippy, fmt, tests) passed in latest local validation.
* Unsafe memory accesses in eBPF (`ptr_at`) use `core::hint::black_box` to preserve bounds-check shape for verifier friendliness, but this remains static-reviewed until kernel verifier/load/replay evidence is archived for the current HEAD.
* The `DPI_EVENTS` ringbuf map is defined, but it is not written to in XDP/TC ingress paths (comment explicitly states "DPI deferred to v2"). This means a DPI ring-buffer overflow bypass is not a current-runtime finding.
* Unsafe blocks accessing raw pointers returned by `ptr_at` are guarded by packet bounds checks against `ctx.data_end()` in the reviewed parser path. Runtime verifier acceptance is still pending.

# Assumptions

* The `aegis` eBPF module loads and passes the kernel verifier on the target OS (kernel > 5.x) – this cannot be confirmed without a privileged `bpf` syscall environment.
* The systemd installer works correctly in a real boot environment without prompting for polkit authentication non-interactively.

# Repository / Architecture Map

* **Userspace**: `aegis-cli`, `aegis-common` (struct definitions), `aegis-cni`, `aegis-tower`.
* **eBPF Space**: `aegis-ebpf` (XDP ingress blocklist, rate limits, conntrack), `aegis-tc` (TC egress blocklist, connection state tracking).
* **Install/CI**: `install.sh` (systemd/openrc/sysvinit), Kubernetes daemonset.
* **Trust Boundaries**: Userspace CLI (`aegis.yaml`) -> BPF Maps -> XDP/TC enforcement points.

# Threat Model

| Surface | Attacker input | Trust boundary | Failure mode | Expected control | Evidence status |
|---------|----------------|----------------|--------------|------------------|-----------------|
| XDP Ingress | Malformed packets, spoofed IPs | Kernel/User BPF Maps | Kernel panic / BPF crash | `ptr_at` bounds checking | Static-reviewed; verifier/replay pending |
| TC Egress | Internal outbound connections | Local system egress | Bypass blocklist | TC hook `tc_egress` | Not proven at runtime |
| DPI Ringbuf | Application layer bytes | Map RingBuffer | Ringbuffer exhaustion | Deferred to v2 | Static-reviewed as unused |
| CLI / Loader | Config `aegis.yaml` | Userspace root execution | Config parsing crash | `serde_yaml` parsing plus tests | Nonpriv-validated |

# Findings

| ID | Severity | Title | Evidence | Impact | Minimal fix | Validation |
|----|----------|-------|----------|--------|-------------|------------|
| AEGIS-S1-001 | S1 | Privileged Enforcement Unverified | Root actions are blocked in CI/Lab | Unverified if eBPF actually drops packets | Deploy to real root disposable host | Run `scripts/release-gates.sh` |
| AEGIS-I-001 | S4 | DPI Code Stubbed | Code comments indicate `DPI_EVENTS` is stubbed for v2 | No current DPI enforcement path; avoid claiming DPI runtime protection | Remove dead map or keep for v2 with explicit docs | N/A |

# Claim vs Evidence Matrix

| Claim | Required evidence | Found evidence | Status | Release impact |
|-------|-------------------|----------------|--------|----------------|
| Production-ready | Runtime traffic logs, attach proof | None | Not proven | Blocked |
| eBPF memory safety / verifier acceptance | `data_end` bound checks plus kernel verifier/load evidence | `ptr_at` implementation uses blackbox; privileged verifier evidence pending | Partial | Blocks production tag |
| Userspace logic | Passing unit tests, clippy | Latest nonpriv validation | Partial | Nonpriv scope only |

# Validation Plan

* Non-privileged: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo run -p xtask build-all`.
* Privileged lab: Attach `aegis-cli` and run `scripts/release-gates.sh privileged-lab`.
* Stress lab: Run `scripts/release-gates.sh stress-lab` with archived replay artifacts.
* Benchmark: Do not benchmark until enforcement is proven.

# Patch Plan

* No Rust/eBPF logic patches are proposed for the current documentation-only scope. The `println!` bug in `aegis-cli` was fixed in the previous commit. The `DPI_EVENTS` map is deferred/stubbed for v2 and must not be described as active DPI enforcement.

# Release Gate

- [x] clean worktree
- [x] nonpriv gate
- [ ] privileged verifier/load/attach
- [ ] replay matrix
- [ ] stress replay
- [ ] install/start/stop/rollback runtime proof for current HEAD
- [x] supply chain

# What To Check Manually

1. Run `scripts/release-gates.sh privileged-lab` in a disposable VM where `sudo` does not require a password to verify actual eBPF verifier/load/attach/detach and packet drops.
2. Run `scripts/release-gates.sh stress-lab` with `AEGIS_STRESS_ITERATIONS=25`.
3. Archive `aegis-daemon.log`, bpftool diagnostic logs, attach/detach/cleanup logs, all replay logs, and `stress-summary.log`.

# Self-Critique

* **Weakest assumption**: That `ptr_at`'s `black_box` pattern will be accepted by the target kernel verifier. This is static-reviewed only until privileged load logs exist.
* **Where this review may be wrong**: The L4 length validation (W-2) in `aegis-ebpf` checks `total_len` from the IPv4 header. If `total_len` is spoofed to be large, it seems vulnerable. However, `ptr_at` for L4 checks against the actual packet's `data_end`. Thus, even if `total_len` is spoofed, the expected behavior is a bounded parse failure for truncated packets; this still needs verifier/runtime replay evidence.
* **How to validate in practice**: Provide a PCAP of truncated packets and run it through `xdp-loader` with `--replay`.
