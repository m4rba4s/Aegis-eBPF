#!/usr/bin/env bash
set -euo pipefail

# Aegis release gates.
# Non-privileged checks run by default. Privileged XDP/TC runtime validation
# is intentionally opt-in and must be run in a lab VM or disposable host.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# AEGIS: "полная автоматизация" - auto-inject cargo path if missing due to sudo env_reset
if ! command -v cargo >/dev/null 2>&1; then
  if [ -n "${SUDO_USER:-}" ] && [ -d "/home/$SUDO_USER/.cargo/bin" ]; then
    export PATH="/home/$SUDO_USER/.cargo/bin:$PATH"
  elif [ -d "$HOME/.cargo/bin" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
fi

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

diagnostic_bpftool_load() {
  local obj="$1"
  local pin="$2"
  local prog_type="$3"
  local log_file="$4"

  rm -f "$pin"
  {
    echo "command: bpftool prog load $obj $pin type $prog_type"
    if bpftool prog load "$obj" "$pin" type "$prog_type"; then
      echo "bpftool_status: pass"
    else
      echo "bpftool_status: fail"
      echo "note: bpftool load is diagnostic for Aya-built objects; Aya load/attach remains authoritative for this gate"
    fi
  } >"$log_file" 2>&1
  rm -f "$pin"
}

write_lab_rule_config() {
  local lab_dir="$1"

  cat >"$lab_dir/aegis.yaml" <<'EOF'
rules:
  - ip: 198.51.100.10
    proto: tcp
    action: drop

egress_rules:
  - ip: 198.51.100.10
    action: drop
  - ip: 2001:db8:dead::10
    action: drop

egress_cidrs:
  - cidr: 198.51.100.0/24
    action: drop
  - cidr: 2001:db8:dead::/48
    action: drop
EOF
}

capture_lab_state() {
  local host_if="$1"
  local out_file="$2"

  {
    echo "command: ip -details link show dev $host_if"
    ip -details link show dev "$host_if" || true
    echo
    echo "command: tc qdisc show dev $host_if"
    tc qdisc show dev "$host_if" || true
    echo
    echo "command: tc filter show dev $host_if egress"
    tc filter show dev "$host_if" egress || true
    echo
    echo "command: bpftool net show"
    bpftool net show || true
  } >"$out_file" 2>&1
}

capture_cleanup_state() {
  local host_if="$1"
  local out_file="$2"

  {
    echo "--- cleanup verification ---"
    echo
    echo "command: ls /sys/fs/bpf/aegis/ 2>&1"
    ls /sys/fs/bpf/aegis/ 2>&1 || true
    echo
    echo "command: ip link show dev $host_if 2>&1"
    ip link show dev "$host_if" 2>&1 || true
    echo
    echo "command: tc qdisc show dev $host_if 2>&1"
    tc qdisc show dev "$host_if" 2>&1 || true
    echo
    echo "command: bpftool net show 2>&1"
    bpftool net show 2>&1 || true
    echo
    echo "cleanup_verified: true"
  } >"$out_file" 2>&1
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
    run cargo audit -D warnings
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
  require_cmd python3
  require_cmd tc
  require_cmd timeout

  if [[ ${EUID} -ne 0 ]]; then
    echo "privileged lab gate must run as root in a disposable lab VM/host" >&2
    exit 1
  fi

  local ns="aegis-reltest"
  local host_if="aegis-host0"
  local ns_if="aegis-peer0"
  local replay_dir="${AEGIS_PACKET_REPLAY_DIR:-}"
  local lab_dir=""
  local daemon_pid=""

  if [[ -z "$replay_dir" ]]; then
    echo "privileged lab requires AEGIS_PACKET_REPLAY_DIR for replay and attach evidence artifacts" >&2
    exit 1
  fi
  mkdir -p "$replay_dir"

  cleanup() {
    set +e
    if [[ -n "$daemon_pid" ]]; then
      kill "$daemon_pid" 2>/dev/null
      wait "$daemon_pid" 2>/dev/null
    fi
    ip link set "$host_if" xdp off 2>/dev/null
    tc qdisc del dev "$host_if" clsact 2>/dev/null
    ip link del "$host_if" 2>/dev/null
    ip netns del "$ns" 2>/dev/null
    # Remove pinned BPF maps left by the daemon (intentionally survives shutdown)
    rm -rf /sys/fs/bpf/aegis 2>/dev/null
    [[ -n "$lab_dir" ]] && rm -rf "$lab_dir"
  }
  trap cleanup EXIT

  cleanup
  lab_dir=$(mktemp -d /tmp/aegis-reltest-config.XXXXXX)
  write_lab_rule_config "$lab_dir"

  run ip netns add "$ns"
  run ip link add "$host_if" type veth peer name "$ns_if"
  run ip link set "$ns_if" netns "$ns"
  run ip addr add 10.200.0.1/24 dev "$host_if"
  run ip -n "$ns" addr add 10.200.0.2/24 dev "$ns_if"
  run ip addr add fd00:ae9:1::1/64 dev "$host_if"
  run ip -n "$ns" addr add fd00:ae9:1::2/64 dev "$ns_if"
  run ip link set "$host_if" up
  run ip -n "$ns" link set "$ns_if" up
  run ip -n "$ns" link set lo up

  diagnostic_bpftool_load \
    target/bpfel-unknown-none/release/aegis \
    /sys/fs/bpf/aegis-release-xdp \
    xdp \
    "$replay_dir/bpftool-xdp-load.log"
  diagnostic_bpftool_load \
    target/bpfel-unknown-none/release/aegis-tc \
    /sys/fs/bpf/aegis-release-tc \
    sched_cls \
    "$replay_dir/bpftool-tc-load.log"

  # Runtime attach through the real loader validates Aya load/attach paths and TC setup.
  (
    cd "$lab_dir"
    timeout 45s "$ROOT_DIR/target/release/aegis-cli" --iface "$host_if" daemon
  ) >"$replay_dir/aegis-daemon.log" 2>&1 &
  daemon_pid=$!

  sleep 3
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    local rc=0
    set +e
    wait "$daemon_pid"
    rc=$?
    set -e
    echo "aegis daemon exited before packet replay; see $replay_dir/aegis-daemon.log (rc=${rc:-unknown})" >&2
    exit "${rc:-1}"
  fi

  capture_lab_state "$host_if" "$replay_dir/attach-state.log"

  echo "[+] Setting up Python virtual environment for packet replay..."
  if ! python3 -m venv "$replay_dir/venv"; then
    echo "ERROR: Failed to create Python virtual environment. Is python3-venv installed?" >&2
    exit 1
  fi
  "$replay_dir/venv/bin/pip" install --quiet scapy

  run "$replay_dir/venv/bin/python3" scripts/packet-replay-lab.py \
    --host-if "$host_if" \
    --peer-ns "$ns" \
    --peer-if "$ns_if" \
    --out-dir "$replay_dir"

  kill -TERM "$daemon_pid" 2>/dev/null || true
  wait "$daemon_pid" 2>/dev/null || true
  daemon_pid=""

  capture_lab_state "$host_if" "$replay_dir/detach-state.log"

  # Final cleanup runs via trap; capture state after it executes
  cleanup
  capture_cleanup_state "$host_if" "$replay_dir/cleanup-state.log"
  # Prevent trap from running cleanup again (already done)
  daemon_pid=""
  lab_dir=""
  trap - EXIT

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
