# Verdict

> [!WARNING]
> LAB-VALIDATED ONLY

The userspace codebase, eBPF parsing bounds, and non-privileged gates pass cleanly. However, the final privileged lab gate (verifier load, XDP/TC attach, and packet replay tests) could not be executed because the current environment does not permit `sudo` operations without an interactive password prompt. We cannot claim `READY FOR TAG, WITH EVIDENCE` until the enforcement is proven in a disposable root environment.

# Task Classification

* Class: release-validation
* Risk: high
* Evidence status: Partial (Userspace validated, privileged tests blocked by lab constraints)

# Confirmed Facts

* Non-privileged Rust gates (cargo check, clippy, fmt, tests) passed.
* Unsafe memory accesses in eBPF (`ptr_at`) correctly utilize `core::hint::black_box` to prevent LLVM bounds-check optimization, ensuring verifier friendliness.
* The `DPI_EVENTS` ringbuf map is defined, but it is not written to in XDP/TC ingress paths (comment explicitly states "DPI deferred to v2"). This means there is no fail-open ring buffer overflow issue.
* Unsafe blocks accessing raw pointers returned by `ptr_at` are fundamentally safe as `ptr_at` verifies the packet bounds against `ctx.data_end()`.

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
| XDP Ingress | Malformed packets, spoofed IPs | Kernel/User BPF Maps | Kernel panic / BPF crash | `ptr_at` bounds checking | Proven statically |
| TC Egress | Internal outbound connections | Local system egress | Bypass blocklist | TC hook `tc_egress` | Not proven at runtime |
| DPI Ringbuf | Application layer bytes | Map RingBuffer | Ringbuffer exhaustion | Deferred to v2 | Proven (unused) |
| CLI / Loader | Config `aegis.yaml` | Userspace root execution | Config parsing crash | `serde_yaml` safe parsing | Proven (tests pass) |

# Findings

| ID | Severity | Title | Evidence | Impact | Minimal fix | Validation |
|----|----------|-------|----------|--------|-------------|------------|
| AEGIS-S1-001 | S1 | Privileged Enforcement Unverified | Root actions are blocked in CI/Lab | Unverified if eBPF actually drops packets | Deploy to real root disposable host | Run `scripts/release-gates.sh` |
| AEGIS-I-001 | S4 | DPI Code Stubbed | Code comments indicate `DPI_EVENTS` is stubbed for v2 | None (Safe) | Remove dead map or keep for v2 | N/A |

# Claim vs Evidence Matrix

| Claim | Required evidence | Found evidence | Status | Release impact |
|-------|-------------------|----------------|--------|----------------|
| Production-ready | Runtime traffic logs, attach proof | None | Not proven | Blocked |
| eBPF Memory Safe | `data_end` bound checks | `ptr_at` implementation uses blackbox | Proven | - |
| Userspace logic | Passing unit tests, clippy | Logs from `task-2000` | Proven | - |

# Validation Plan

* Non-privileged: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo run -p xtask build-all` (Completed).
* Privileged lab: Attach `aegis-cli` and run `scripts/release-gates.sh privileged-lab` (Blocked).
* Benchmark: Do not benchmark until enforcement is proven.

# Patch Plan

* No patches are needed at the architecture or code level for the current non-privileged scope. The `println!` bug in `aegis-cli` was fixed in the previous commit. The `DPI_EVENTS` map is dead code but safe.

# Release Gate

- [x] clean worktree
- [x] nonpriv gate
- [ ] privileged verifier/load/attach
- [ ] replay matrix
- [ ] stress replay
- [x] install/start/stop/rollback (Dry-run tested)
- [x] supply chain

# What To Check Manually

1. Run the `release-gates.sh` script in a disposable VM where `sudo` does not require a password to verify actual eBPF attachment and packet drops.

# Self-Critique

* **Weakest assumption**: That `ptr_at`'s `black_box` trick is sufficient for all kernel versions. Some very old verifiers might still reject it, though it's standard in Aya.
* **Where this review may be wrong**: The L4 length validation (W-2) in `aegis-ebpf` checks `total_len` from the IPv4 header. If `total_len` is spoofed to be large, it seems vulnerable. However, `ptr_at` for L4 *does* check against the actual packet's `data_end`. Thus, even if `total_len` is spoofed, `ptr_at` will safely reject parsing if the packet itself is truncated. This is completely safe.
* **How to validate in practice**: Provide a PCAP of truncated packets and run it through `xdp-loader` with `--replay`.
