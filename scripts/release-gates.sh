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
  local case_output=""
  local cases=()
  local fields=(
    packet
    expected_verdict
    observed_verdict
    command
    direction
    hook
  )

  if ! case_output="$(python3 scripts/packet-replay-lab.py --list-cases)"; then
    echo "could not load the canonical packet replay case list" >&2
    return 1
  fi
  mapfile -t cases <<<"$case_output"
  if [[ "${#cases[@]}" -eq 0 ]]; then
    echo "canonical packet replay case list is empty" >&2
    return 1
  fi

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

require_stress_evidence() {
  local expected_iterations="$1"
  local case_output=""
  local cases=()
  local expected_cases_per_iteration=0
  local expected_total_case_runs=0
  local evidence_dir="${AEGIS_PACKET_REPLAY_DIR:-}"
  local log_file="$evidence_dir/stress-summary.log"

  if ! case_output="$(python3 scripts/packet-replay-lab.py --list-cases)"; then
    echo "could not load the canonical packet replay case list" >&2
    return 1
  fi
  mapfile -t cases <<<"$case_output"
  expected_cases_per_iteration="${#cases[@]}"
  expected_total_case_runs=$((expected_iterations * expected_cases_per_iteration))

  if [[ -z "$evidence_dir" ]]; then
    echo "missing stress evidence: set AEGIS_PACKET_REPLAY_DIR to the privileged lab artifact directory" >&2
    return 1
  fi

  if [[ ! -s "$log_file" ]]; then
    echo "missing stress replay summary: $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^case:[[:space:]]*stress_replay_matrix[[:space:]]*$" "$log_file"; then
    echo "stress replay summary has wrong case name: $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^stress_iterations:[[:space:]]*$expected_iterations[[:space:]]*$" "$log_file"; then
    echo "stress replay summary does not record expected iteration count ($expected_iterations): $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^stress_cases_per_iteration:[[:space:]]*$expected_cases_per_iteration[[:space:]]*$" "$log_file"; then
    echo "stress replay summary does not record $expected_cases_per_iteration cases per iteration: $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^stress_total_case_runs:[[:space:]]*$expected_total_case_runs[[:space:]]*$" "$log_file"; then
    echo "stress replay summary does not record expected total case runs ($expected_total_case_runs): $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^failures:[[:space:]]*none[[:space:]]*$" "$log_file"; then
    echo "stress replay summary records failures: $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^pass:[[:space:]]*true[[:space:]]*$" "$log_file"; then
    echo "stress replay summary did not record pass: true: $log_file" >&2
    return 1
  fi

  echo "stress replay evidence artifact present in: $log_file"
}

require_clean_evidence_dir() {
  local evidence_dir="$1"
  local first_entry=""

  if [[ -e "$evidence_dir" && ! -d "$evidence_dir" ]]; then
    echo "privileged lab evidence path exists but is not a directory: $evidence_dir" >&2
    return 1
  fi

  if [[ -d "$evidence_dir" ]]; then
    if ! first_entry="$(find "$evidence_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"; then
      echo "privileged lab could not inspect evidence directory: $evidence_dir" >&2
      return 1
    fi
    if [[ -n "$first_entry" ]]; then
      echo "privileged lab requires a new or empty evidence directory; found: $first_entry" >&2
      echo "choose a run-specific AEGIS_PACKET_REPLAY_DIR to prevent stale evidence mixing" >&2
      return 1
    fi
  fi
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
  local ns="$2"
  local out_file="$3"
  local cleanup_ok=1
  local netns_state=""
  local prog_state=""
  local remaining_pin=""

  if [[ -d /sys/fs/bpf/aegis ]]; then
    if ! remaining_pin="$(find /sys/fs/bpf/aegis -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"; then
      cleanup_ok=0
    fi
  fi
  if [[ -n "$remaining_pin" ]]; then
    cleanup_ok=0
  fi
  if ip link show dev "$host_if" >/dev/null 2>&1; then
    cleanup_ok=0
  fi
  if ! netns_state="$(ip netns list 2>&1)"; then
    cleanup_ok=0
  elif awk '{print $1}' <<<"$netns_state" | grep -Fxq "$ns"; then
    cleanup_ok=0
  fi
  if ! prog_state="$(bpftool prog show 2>&1)"; then
    cleanup_ok=0
  elif grep -Eq 'name (xdp_firewall|tc_egress)' <<<"$prog_state"; then
    cleanup_ok=0
  fi

  {
    echo "--- cleanup verification ---"
    echo
    echo "command: ls /sys/fs/bpf/aegis/ 2>&1"
    ls /sys/fs/bpf/aegis/ 2>&1 || true
    echo
    echo "command: ip link show dev $host_if 2>&1"
    ip link show dev "$host_if" 2>&1 || true
    echo
    echo "command: ip netns list"
    printf '%s\n' "$netns_state"
    echo
    echo "command: tc qdisc show dev $host_if 2>&1"
    tc qdisc show dev "$host_if" 2>&1 || true
    echo
    echo "command: bpftool net show 2>&1"
    bpftool net show 2>&1 || true
    echo
    echo "command: bpftool prog show 2>&1"
    printf '%s\n' "$prog_state"
    echo
    if [[ "$cleanup_ok" -eq 1 ]]; then
      echo "cleanup_verified: true"
    else
      echo "cleanup_verified: false"
    fi
  } >"$out_file" 2>&1

  [[ "$cleanup_ok" -eq 1 ]]
}

cleanup_aegis_lab_pins() {
  local pin_dir="/sys/fs/bpf/aegis"
  local pins=(
    BLOCKLIST
    ALLOWLIST
    STATS
    CONFIG
    BLOCKLIST_IPV6
    ALLOWLIST_IPV6
    CIDR_BLOCKLIST
    CIDR_BLOCKLIST_IPV6
    DPI_EVENTS
    EGRESS_BLOCKLIST
    EGRESS_BLOCKLIST_IPV6
    EGRESS_CIDR_BLOCKLIST
    EGRESS_CIDR_BLOCKLIST_IPV6
    EVENTS
    EVENTS_IPV6
    GLOBAL_SYN_CTR
    PORT_SCAN
    RATE_LIMIT
    CONN_TRACK
    CONN_TRACK_IPV6
  )

  [[ -d "$pin_dir" ]] || return 0
  for pin in "${pins[@]}"; do
    rm -f "$pin_dir/$pin" 2>/dev/null
  done
  rmdir "$pin_dir" 2>/dev/null || true
}

require_clean_privileged_lab_host() {
  local host_if="$1"
  local ns="$2"
  local pin_dir="/sys/fs/bpf/aegis"
  local first_pin=""
  local netns_state=""
  local prog_state=""

  if [[ -d "$pin_dir" ]]; then
    if ! first_pin="$(find "$pin_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"; then
      echo "privileged lab could not inspect Aegis bpffs state under $pin_dir" >&2
      exit 1
    fi
  fi
  if [[ -n "$first_pin" ]]; then
    echo "privileged lab requires a clean Aegis bpffs state; found existing pin: $first_pin" >&2
    echo "run this gate only in a disposable VM/lab host or detach/cleanup the existing Aegis instance first" >&2
    exit 1
  fi

  if ! prog_state="$(bpftool prog show 2>&1)"; then
    echo "privileged lab could not inspect loaded BPF programs: $prog_state" >&2
    exit 1
  fi
  if grep -Eq 'name (xdp_firewall|tc_egress)' <<<"$prog_state"; then
    echo "privileged lab found existing Aegis BPF programs; refusing to touch shared host bpffs state" >&2
    echo "run this gate only in a disposable VM/lab host or detach/cleanup the existing Aegis instance first" >&2
    exit 1
  fi

  if ip link show dev "$host_if" >/dev/null 2>&1; then
    echo "privileged lab found existing interface '$host_if'; refusing to delete shared host state" >&2
    echo "run this gate only in a disposable VM/lab host or remove the stale lab interface first" >&2
    exit 1
  fi

  if ! netns_state="$(ip netns list 2>&1)"; then
    echo "privileged lab could not inspect network namespaces: $netns_state" >&2
    exit 1
  fi
  if awk '{print $1}' <<<"$netns_state" | grep -Fxq "$ns"; then
    echo "privileged lab found existing network namespace '$ns'; refusing to delete shared host state" >&2
    echo "run this gate only in a disposable VM/lab host or remove the stale lab namespace first" >&2
    exit 1
  fi
}

non_privileged() {
  require_cmd cargo
  local doc_target_dir="${AEGIS_DOC_TARGET_DIR:-}"
  local doc_target_is_temporary=0
  local doc_rc=0

  run git status --short
  run rustc --version
  run cargo --version
  run cargo metadata --format-version 1 --no-deps >/dev/null

  run cargo fmt --all -- --check
  run cargo clippy --workspace --all-targets --all-features -- -D warnings
  run cargo test --workspace --all-features
  run cargo test --workspace --doc
  if [[ -z "$doc_target_dir" ]]; then
    doc_target_dir="$(mktemp -d /tmp/aegis-doc-target.XXXXXX)"
    doc_target_is_temporary=1
    echo "AEGIS_DOC_TARGET_DIR not set; writing cargo doc artifacts to: $doc_target_dir" >&2
  fi
  if run cargo doc --workspace --all-features --no-deps --target-dir "$doc_target_dir"; then
    doc_rc=0
  else
    doc_rc=$?
  fi
  if [[ "$doc_target_is_temporary" -eq 1 ]]; then
    rm -rf -- "$doc_target_dir"
  fi
  if [[ "$doc_rc" -ne 0 ]]; then
    return "$doc_rc"
  fi
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
    for lockfile in \
      aegis-cli/fuzz/Cargo.lock \
      aegis-ebpf/Cargo.lock \
      aegis-tc/Cargo.lock \
      aegis-tower/Cargo.lock \
      verification/Cargo.lock \
      verification/fuzz/Cargo.lock; do
      run cargo audit --no-fetch --file "$lockfile" -D warnings
    done
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

  ns="aegis-reltest"
  host_if="aegis-host0"
  ns_if="aegis-peer0"
  replay_dir="${AEGIS_PACKET_REPLAY_DIR:-}"
  stress_iterations="${AEGIS_STRESS_ITERATIONS:-0}"
  lab_dir=""
  daemon_pid=""
  lab_daemon_started=0
  cleanup_state_written=0

  if [[ ! "$stress_iterations" =~ ^[0-9]+$ ]]; then
    echo "AEGIS_STRESS_ITERATIONS must be a non-negative integer, got: $stress_iterations" >&2
    exit 2
  fi

  if [[ -z "$replay_dir" ]]; then
    replay_dir="$(mktemp -d /tmp/aegis-replay.XXXXXX)"
    echo "AEGIS_PACKET_REPLAY_DIR not set; writing replay and attach evidence artifacts to: $replay_dir" >&2
  fi
  require_clean_evidence_dir "$replay_dir"
  export AEGIS_PACKET_REPLAY_DIR="$replay_dir"
  mkdir -p "$replay_dir"
  require_clean_privileged_lab_host "$host_if" "$ns"

  cleanup() {
    set +e
    local pid="${daemon_pid:-}"
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    fi
    ip link set "${host_if:-aegis-host0}" xdp off 2>/dev/null
    tc qdisc del dev "${host_if:-aegis-host0}" clsact 2>/dev/null
    ip link del "${host_if:-aegis-host0}" 2>/dev/null
    ip netns del "${ns:-aegis-reltest}" 2>/dev/null
    if [[ "${lab_daemon_started:-0}" -eq 1 ]]; then
      cleanup_aegis_lab_pins
    fi
    [[ -n "${lab_dir:-}" ]] && rm -rf "$lab_dir"
    set -e
    return 0
  }

  cleanup_and_capture() {
    local rc=$?
    local cleanup_rc=0
    cleanup
    if [[ "${cleanup_state_written:-0}" -eq 0 ]]; then
      capture_cleanup_state \
        "${host_if:-aegis-host0}" \
        "${ns:-aegis-reltest}" \
        "${replay_dir:-/tmp}/cleanup-state.log" || cleanup_rc=$?
      cleanup_state_written=1
    fi
    if [[ "$rc" -eq 0 && "$cleanup_rc" -ne 0 ]]; then
      exit "$cleanup_rc"
    fi
    exit "$rc"
  }
  trap cleanup_and_capture EXIT

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
  # Scale daemon timeout for the XDP+TC replay matrix plus setup overhead.
  local daemon_timeout=$(( 120 + stress_iterations * 30 ))
  (
    cd "$lab_dir"
    timeout "${daemon_timeout}s" "$ROOT_DIR/target/release/aegis-cli" --iface "$host_if" daemon
  ) >"$replay_dir/aegis-daemon.log" 2>&1 &
  daemon_pid=$!
  lab_daemon_started=1

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

  replay_cmd=(
    "$replay_dir/venv/bin/python3"
    scripts/packet-replay-lab.py
    --host-if "$host_if"
    --peer-ns "$ns"
    --peer-if "$ns_if"
    --out-dir "$replay_dir"
  )
  if (( stress_iterations > 0 )); then
    replay_cmd+=(--stress-iterations "$stress_iterations")
  fi
  run "${replay_cmd[@]}"

  kill -TERM "$daemon_pid" 2>/dev/null || true
  wait "$daemon_pid" 2>/dev/null || true
  daemon_pid=""

  capture_lab_state "$host_if" "$replay_dir/detach-state.log"

  # Final cleanup is manual here so replay evidence validation still runs after it.
  cleanup
  cleanup_rc=0
  capture_cleanup_state "$host_if" "$ns" "$replay_dir/cleanup-state.log" || cleanup_rc=$?
  cleanup_state_written=1
  if [[ "$cleanup_rc" -ne 0 ]]; then
    exit "$cleanup_rc"
  fi
  # Prevent trap from running cleanup again (already done)
  daemon_pid=""
  lab_dir=""
  trap - EXIT

  require_packet_replay_evidence
  if (( stress_iterations > 0 )); then
    require_stress_evidence "$stress_iterations"
  fi
}

case "${1:-nonpriv}" in
  nonpriv)
    non_privileged
    exit 0
    ;;
  privileged-lab)
    non_privileged
    rm -rf /sys/fs/bpf/aegis 2>/dev/null || true
    privileged_lab
    ;;
  stress-lab)
    export AEGIS_STRESS_ITERATIONS="${AEGIS_STRESS_ITERATIONS:-25}"
    non_privileged
    rm -rf /sys/fs/bpf/aegis 2>/dev/null || true
    privileged_lab
    ;;
  evidence-only)
    require_cmd python3
    require_packet_replay_evidence
    stress_iterations="${AEGIS_STRESS_ITERATIONS:-0}"
    if [[ ! "$stress_iterations" =~ ^[0-9]+$ ]]; then
      echo "AEGIS_STRESS_ITERATIONS must be a non-negative integer, got: $stress_iterations" >&2
      exit 2
    fi
    if (( stress_iterations > 0 )); then
      require_stress_evidence "$stress_iterations"
    fi
    ;;
  *)
    echo "usage: $0 [nonpriv|privileged-lab|stress-lab|evidence-only]" >&2
    exit 2
    ;;
esac
