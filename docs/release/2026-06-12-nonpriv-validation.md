# Non-Privileged Validation - June 12, 2026

## Scope

- Timestamp: `2026-06-12T12:32:01Z`
- HEAD: `a0c71254de318c60b92e0e66f6c05b193def592a`
- Git description: `v4.2.0-1-ga0c7125-dirty`
- Declared crate version: `4.3.0-rc.1`
- Environment: Fedora workstation, unprivileged execution
- Raw command transcript: not archived

These results apply only to the dirty worktree present during this run. They
are development evidence, not release evidence for a tag or clean commit.

## Observed Checks

| command | observed result |
|---|---|
| `CARGO_HOME=/tmp/aegis-cargo-home CARGO_TARGET_DIR=/tmp/aegis-nonpriv-target ./scripts/release-gates.sh nonpriv` | exit `0` |
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | pass |
| `cargo test --workspace --all-features` | 33 passed, 0 failed |
| `cargo test --workspace --doc` | pass |
| `cargo doc --workspace --all-features --no-deps` | pass |
| `cargo run -p xtask -- build-all --profile release` | XDP and TC objects built |
| `file` and `llvm-objdump -h` on both eBPF objects | valid relocatable eBPF ELF objects with expected program and map sections |
| root `cargo audit -D warnings` | no vulnerability failure |
| `cargo deny check` | advisories, bans, licenses, and sources passed; unmatched-license allowances warned |
| `cargo fmt --manifest-path verification/Cargo.toml -- --check` | pass |
| `cargo clippy --manifest-path verification/Cargo.toml --all-targets --all-features -- -D warnings` | pass |
| `cargo test --manifest-path verification/Cargo.toml` | 17 passed, 0 failed |
| `python3 scripts/packet-replay-lab.py --validate-packets` | all 18 packet cases serialized; no packets transmitted |

The nested lockfile `cargo audit --no-fetch` checks emitted incomplete local
crates.io-index metadata messages for some yanked-package lookups but returned
success and did not report a RustSec vulnerability. This is not a clean raw
supply-chain archive and must be rerun and archived on the clean release
commit.

## Not Proven

- kernel verifier acceptance,
- Aya load,
- XDP or TC attach,
- packet enforcement verdicts,
- cleanup after attach,
- stress stability,
- systemd recovery,
- leak freedom,
- release readiness.

No privileged, network-attach, packet-send, or stress command was run during
this recheck.
