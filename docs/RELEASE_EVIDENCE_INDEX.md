# Release Evidence Index

Evidence is valid only when the raw artifact is retrievable and tied to the
exact commit under assessment.

| claim | commit | command | artifact | result | environment |
|---|---|---|---|---|---|
| current non-privileged gate | `4.3.0-rc.1` | `CARGO_TARGET_DIR=target_test cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`, `cargo build --locked --release` | local workspace logs | pass_observed_unarchived | Fedora workstation |
| current standalone verification crate | `4.3.0-rc.1` | included in workspace cargo tests | local workspace logs | pass_observed_unarchived | Fedora workstation |
| current packet serialization matrix | `4.3.0-rc.1` | `python3 scripts/packet-replay-lab.py --validate-packets` | local workspace logs (dry run) | pass_observed_unarchived | Fedora workstation |
| v4.2.0 privileged replay | claimed for `8b2184d` | `./scripts/release-gates.sh privileged-lab` | archive hash recorded, raw archive unavailable | historical_unverified | claimed disposable VM |
| v4.2.0 stress replay | claimed for `8b2184d` | `AEGIS_STRESS_ITERATIONS=25 ./scripts/release-gates.sh stress-lab` | archive hash recorded, raw archive unavailable | historical_unverified | claimed disposable VM |
| current privileged load/attach/replay | `4.3.0-rc.1` | `./scripts/release-gates.sh privileged-lab` | required replay and cleanup logs | not_run | disposable VM required |
| current bounded stress replay | `4.3.0-rc.1` | `AEGIS_STRESS_ITERATIONS=25 ./scripts/release-gates.sh stress-lab` | `stress-summary.log`, `resource-preflight.log`, replay logs | not_run | disposable VM plus host headroom required |
| June 12 host freeze cause | local incident only | journal, sysstat, and PCP archive inspection | `docs/release/2026-06-12-host-freeze-postmortem.md` | host resource exhaustion verified; Aegis causation unknown | Fedora workstation hosting a VM |

The current non-privileged checks (fmt, clippy, tests, release build) pass cleanly on `4.3.0-rc.1`.
However, the privileged lab and stress replay are marked `not_run` due to sandbox constraints (requiring root, veth, bpf, and a disposable VM). Do not authorize a production, enterprise, or stress-tested claim until the privileged gates are completed and artifacts archived.
