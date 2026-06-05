#!/usr/bin/env bash
set -euo pipefail

# Aegis release gates.
# Non-privileged checks run by default. Privileged XDP/TC runtime validation
# is intentionally opt-in and must be run in a lab VM or disposable host.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run() {
  printf '\n\033[1;34m==> %s\033[0m\n' "$*"
  "$@"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

require_packet_replay_evidence() {
  local evidence_dir="${AEGIS_PACKET_REPLAY_DIR:-}"
  local missing=0
  local cases=(
    ipv4_pass_allowed
    ipv4_drop_exact
    ipv4_drop_cidr
    ipv6_pass_allowed
    ipv6_drop_exact
    ipv6_drop_cidr
    vlan_behavior
    qinq_behavior
    ipv4_ihl_options_behavior
    ipv4_fragment_behavior
    truncated_tcp_blocked_ipv4_exact
    truncated_udp_blocked_ipv4_exact
    truncated_tcp_blocked_ipv4_cidr
    truncated_udp_blocked_ipv4_cidr
  )
  local fields=(
    packet
    expected_verdict
    observed_verdict
    command
  )

  if [[ -z "$evidence_dir" ]]; then
    echo "missing packet replay evidence: set AEGIS_PACKET_REPLAY_DIR to a directory containing required .log artifacts" >&2
    printf 'required packet replay case: %s\n' "${cases[@]}" >&2
    return 1
  fi

  for case_name in "${cases[@]}"; do
    local log_file="$evidence_dir/$case_name.log"

    if [[ ! -s "$log_file" ]]; then
      echo "missing packet replay log for case: $case_name ($log_file)" >&2
      missing=1
      continue
    fi

    if ! grep -Eq "^case:[[:space:]]*$case_name[[:space:]]*$" "$log_file"; then
      echo "packet replay log does not identify case '$case_name': $log_file" >&2
      missing=1
    fi

    for field in "${fields[@]}"; do
      if ! grep -Eq "^$field:[[:space:]]*.+" "$log_file"; then
        echo "packet replay log missing '$field:' for case: $case_name ($log_file)" >&2
        missing=1
      fi
    done

    if ! grep -Eq "^pass:[[:space:]]*true[[:space:]]*$" "$log_file"; then
      echo "packet replay log did not record pass: true for case: $case_name ($log_file)" >&2
      missing=1
    fi
  done

  if [[ $missing -ne 0 ]]; then
    return 1
  fi

  echo "packet replay evidence artifacts present in: $evidence_dir"
}

non_privileged() {
  require_cmd cargo

  run git status --short
  run rustc --version
  run cargo --version
  run cargo metadata --format-version 1 --no-deps >/dev/null

  run cargo fmt --all -- --check
  run cargo clippy --workspace --all-targets --all-features -- -D warnings
  run cargo test --workspace --all-features
  run cargo test --workspace --doc
  run cargo doc --workspace --all-features --no-deps
  run cargo run -p xtask -- build-all --profile release
  run cargo build --release -p aegis-cli -p aegis-cni -p xtask

  require_cmd file
  run file target/bpfel-unknown-none/release/aegis
  run file target/bpfel-unknown-none/release/aegis-tc

  if command -v llvm-objdump >/dev/null 2>&1; then
    run llvm-objdump -h target/bpfel-unknown-none/release/aegis
    run llvm-objdump -h target/bpfel-unknown-none/release/aegis-tc
  else
    echo "llvm-objdump not found; skipping object section dump" >&2
  fi

  if command -v cargo-audit >/dev/null 2>&1; then
    run cargo audit --no-fetch -D warnings
  else
    echo "cargo-audit not installed; install with: cargo install cargo-audit" >&2
    exit 127
  fi

  if command -v cargo-deny >/dev/null 2>&1; then
    run cargo deny check
  else
    echo "cargo-deny not installed; install with: cargo install cargo-deny" >&2
    exit 127
  fi

  run target/release/aegis-cli --iface lo daemon --help >/dev/null
}

privileged_lab() {
  require_cmd bpftool
  require_cmd ip
  require_cmd tc
  require_cmd timeout

  if [[ ${EUID} -ne 0 ]]; then
    echo "privileged lab gate must run as root in a disposable lab VM/host" >&2
    exit 1
  fi

  local ns="aegis-reltest"
  local host_if="aegis-host0"
  local ns_if="aegis-peer0"

  cleanup() {
    set +e
    ip link set "$host_if" xdp off 2>/dev/null
    tc qdisc del dev "$host_if" clsact 2>/dev/null
    ip link del "$host_if" 2>/dev/null
    ip netns del "$ns" 2>/dev/null
  }
  trap cleanup EXIT

  cleanup
  run ip netns add "$ns"
  run ip link add "$host_if" type veth peer name "$ns_if"
  run ip link set "$ns_if" netns "$ns"
  run ip addr add 10.200.0.1/24 dev "$host_if"
  run ip -n "$ns" addr add 10.200.0.2/24 dev "$ns_if"
  run ip link set "$host_if" up
  run ip -n "$ns" link set "$ns_if" up
  run ip -n "$ns" link set lo up

  run bpftool prog load target/bpfel-unknown-none/release/aegis /sys/fs/bpf/aegis-release-xdp type xdp
  rm -f /sys/fs/bpf/aegis-release-xdp

  # Runtime attach through the real loader validates Aya load/attach paths and TC setup.
  # timeout exits non-zero after the smoke window; treat 124 as expected daemon timeout.
  set +e
  timeout 8s target/release/aegis-cli --iface "$host_if" daemon
  local rc=$?
  set -e
  if [[ $rc -ne 0 && $rc -ne 124 ]]; then
    echo "aegis daemon exited unexpectedly during privileged attach smoke: rc=$rc" >&2
    exit "$rc"
  fi

  run ip link show dev "$host_if"
  run tc qdisc show dev "$host_if"
  require_packet_replay_evidence
}

case "${1:-nonpriv}" in
  nonpriv)
    non_privileged
    ;;
  privileged-lab)
    non_privileged
    privileged_lab
    ;;
  *)
    echo "usage: $0 [nonpriv|privileged-lab]" >&2
    exit 2
    ;;
esac
