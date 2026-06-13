#!/usr/bin/env bash
set -euo pipefail

# Aegis release gates.
# Non-privileged checks run by default. Privileged XDP/TC runtime validation
# is intentionally opt-in and must be run in a lab VM or disposable host.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MAX_STRESS_ITERATIONS=50
MAX_REPLAY_TIMEOUT_SECONDS=7200

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

resolve_cargo_target_dir() {
  local target_dir="${CARGO_TARGET_DIR:-target}"

  if [[ "$target_dir" != /* ]]; then
    target_dir="$ROOT_DIR/$target_dir"
  fi
  printf '%s\n' "$target_dir"
}

configure_repeatable_release_build() {
  local target_dir="$1"
  local separator=$'\x1f'

  if [[ -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
    echo "release-candidate validation requires unset RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS" >&2
    return 1
  fi

  export CARGO_INCREMENTAL=0
  export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${target_dir}=/usr/src/aegis/target${separator}--remap-path-prefix=${ROOT_DIR}=/usr/src/aegis"
}

reject_embedded_path() {
  local artifact="$1"
  local physical_path="$2"

  if grep -Fq -- "$physical_path" < <(strings "$artifact"); then
    echo "release artifact embeds physical build path '$physical_path': $artifact" >&2
    return 1
  fi
}

validate_stress_iterations() {
  local value="$1"

  if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ || "${#value}" -gt 2 ]]; then
    echo "AEGIS_STRESS_ITERATIONS must be an integer from 0 to $MAX_STRESS_ITERATIONS, got: $value" >&2
    return 2
  fi
  if (( 10#$value > MAX_STRESS_ITERATIONS )); then
    echo "AEGIS_STRESS_ITERATIONS exceeds the safety limit ($MAX_STRESS_ITERATIONS): $value" >&2
    return 2
  fi
}

validate_replay_timeout() {
  local value="$1"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ || "${#value}" -gt 4 ]]; then
    echo "AEGIS_REPLAY_TIMEOUT_SECONDS must be an integer from 1 to $MAX_REPLAY_TIMEOUT_SECONDS, got: $value" >&2
    return 2
  fi
  if (( 10#$value > MAX_REPLAY_TIMEOUT_SECONDS )); then
    echo "AEGIS_REPLAY_TIMEOUT_SECONDS exceeds the safety limit ($MAX_REPLAY_TIMEOUT_SECONDS): $value" >&2
    return 2
  fi
}

require_resource_headroom() {
  local mode="$1"
  local min_available_mb="${AEGIS_MIN_AVAILABLE_MB:-}"
  local max_swap_used_percent="${AEGIS_MAX_SWAP_USED_PERCENT:-75}"
  local allow_low_resource="${AEGIS_ALLOW_LOW_RESOURCE_LAB:-0}"
  local mem_total_kb=0
  local mem_available_kb=0
  local swap_total_kb=0
  local swap_free_kb=0
  local swap_used_percent=0
  local failed=0

  if [[ -z "$min_available_mb" ]]; then
    if [[ "$mode" == "stress" ]]; then
      min_available_mb=4096
    else
      min_available_mb=2048
    fi
  fi

  if [[ ! "$min_available_mb" =~ ^[1-9][0-9]*$ ]]; then
    echo "AEGIS_MIN_AVAILABLE_MB must be a positive integer, got: $min_available_mb" >&2
    return 2
  fi
  if [[ ! "$max_swap_used_percent" =~ ^(0|[1-9][0-9]*)$ ]] || (( max_swap_used_percent > 100 )); then
    echo "AEGIS_MAX_SWAP_USED_PERCENT must be an integer from 0 to 100, got: $max_swap_used_percent" >&2
    return 2
  fi

  mem_total_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  mem_available_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
  swap_total_kb="$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)"
  swap_free_kb="$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)"

  if [[ -z "$mem_total_kb" || -z "$mem_available_kb" || -z "$swap_total_kb" || -z "$swap_free_kb" ]]; then
    echo "could not read memory headroom from /proc/meminfo" >&2
    return 1
  fi

  if (( swap_total_kb > 0 )); then
    swap_used_percent=$(( (swap_total_kb - swap_free_kb) * 100 / swap_total_kb ))
  fi

  {
    echo "resource_preflight_mode: $mode"
    echo "timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "mem_total_mb: $((mem_total_kb / 1024))"
    echo "mem_available_mb: $((mem_available_kb / 1024))"
    echo "required_mem_available_mb: $min_available_mb"
    echo "swap_total_mb: $((swap_total_kb / 1024))"
    echo "swap_free_mb: $((swap_free_kb / 1024))"
    echo "swap_used_percent: $swap_used_percent"
    echo "maximum_swap_used_percent: $max_swap_used_percent"
    echo "loadavg: $(cat /proc/loadavg)"
  }

  if (( mem_available_kb < min_available_mb * 1024 )); then
    echo "insufficient memory headroom: need at least ${min_available_mb} MiB MemAvailable" >&2
    failed=1
  fi
  if (( swap_total_kb > 0 && swap_used_percent > max_swap_used_percent )); then
    echo "swap pressure is too high: ${swap_used_percent}% used, maximum is ${max_swap_used_percent}%" >&2
    failed=1
  fi

  if (( failed != 0 )); then
    if [[ "$allow_low_resource" == "1" ]]; then
      echo "WARNING: AEGIS_ALLOW_LOW_RESOURCE_LAB=1 bypassed the resource preflight" >&2
      return 0
    fi
    echo "close memory-heavy applications or resize the disposable VM before running the lab gate" >&2
    return 1
  fi
}

require_packet_replay_evidence() {
  local evidence_dir="${AEGIS_PACKET_REPLAY_DIR:-}"
  local missing=0
  local case_output=""
  local cases=()
  local expected_commit

  expected_commit="$(git rev-parse HEAD 2>/dev/null || true)"

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

    if ! grep -Eq "^case:[[:space:]]*${case_name}[[:space:]]*$" "$log_file"; then
      echo "packet replay log does not identify case '$case_name': $log_file" >&2
      missing=1
    fi

    # Validate the replay artifact as a commit-bound evidence record instead
    # of trusting a bare `pass: true` flag in the log body.
    if ! python3 scripts/packet-replay-lab.py \
      --validate-log "$log_file" \
      --expected-case "$case_name" \
      --expected-commit "$expected_commit"; then
      echo "packet replay log validation failed for case: $case_name ($log_file)" >&2
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
  local expected_commit=""

  expected_commit="$(git rev-parse HEAD 2>/dev/null || true)"

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

  if ! grep -Eq "^commit:[[:space:]]*${expected_commit}[[:space:]]*$" "$log_file"; then
    echo "stress replay summary does not match current commit ($expected_commit): $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^stress_iterations:[[:space:]]*${expected_iterations}[[:space:]]*$" "$log_file"; then
    echo "stress replay summary does not record expected iteration count ($expected_iterations): $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^stress_cases_per_iteration:[[:space:]]*${expected_cases_per_iteration}[[:space:]]*$" "$log_file"; then
    echo "stress replay summary does not record $expected_cases_per_iteration cases per iteration: $log_file" >&2
    return 1
  fi

  if ! grep -Eq "^stress_total_case_runs:[[:space:]]*${expected_total_case_runs}[[:space:]]*$" "$log_file"; then
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
  local pin_dir="/sys/fs/bpf/aegis/${host_if}/abi-v1"
  local marker="/run/aegis/instances/${host_if}/abi-v1/ownership.json"

  # Cleanup evidence is checked against the owned instance directory only.
  if [[ -d "$pin_dir" ]]; then
    if ! remaining_pin="$(find "$pin_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"; then
      cleanup_ok=0
    fi
  fi
  if [[ -n "$remaining_pin" ]]; then
    cleanup_ok=0
  fi
  if [[ -e "$marker" ]]; then
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
    echo "command: find $pin_dir -mindepth 1 -maxdepth 1 -ls 2>&1"
    find "$pin_dir" -mindepth 1 -maxdepth 1 -ls 2>&1 || true
    echo
    echo "command: ls -l $marker 2>&1"
    ls -l "$marker" 2>&1 || true
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
  local host_if="${1:-aegis-host0}"
  local marker="/run/aegis/instances/${host_if}/abi-v1/ownership.json"
  local cleanup_args=(--iface "$host_if" cleanup-pins)
  local cargo_target_dir
  cargo_target_dir="$(resolve_cargo_target_dir)"

  if [[ ! -e "$marker" ]]; then
    cleanup_args+=(--force-orphaned)
  fi
  "$cargo_target_dir/release/aegis-cli" "${cleanup_args[@]}"
}

require_clean_privileged_lab_host() {
  local host_if="$1"
  local ns="$2"
  local pin_dir="/sys/fs/bpf/aegis/${host_if}/abi-v1"
  local marker="/run/aegis/instances/${host_if}/abi-v1/ownership.json"
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
  if [[ -e "$marker" ]]; then
    echo "privileged lab found stale Aegis ownership metadata: $marker" >&2
    echo "inspect the instance and use the explicit cleanup-pins command before retrying" >&2
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
  require_cmd python3
  local doc_target_dir="${AEGIS_DOC_TARGET_DIR:-}"
  local cargo_target_dir
  local doc_target_is_temporary=0
  local doc_rc=0
  cargo_target_dir="$(resolve_cargo_target_dir)"

  run git status --short
  run rustc --version
  run cargo --version
  run cargo metadata --locked --format-version 1 --no-deps >/dev/null
  run cargo metadata --locked --manifest-path verification/Cargo.toml --format-version 1 --no-deps >/dev/null
  run cargo metadata --locked --manifest-path verification/fuzz/Cargo.toml --format-version 1 --no-deps >/dev/null
  run cargo metadata --locked --manifest-path aegis-cli/fuzz/Cargo.toml --format-version 1 --no-deps >/dev/null

  run cargo fmt --all -- --check
  run cargo run --locked -p xtask -- build-all --profile release
  run cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
  run cargo test --locked --workspace --all-features
  run cargo test --locked -p aegis-cli --all-features tests::test_embedded_xdp_elf_valid
  run cargo test --locked -p aegis-cli --all-features tests::test_embedded_tc_elf_valid
  run cargo test --locked -p aegis-cli --all-features tests::test_aya_parse_embedded_xdp
  run cargo test --locked --workspace --doc
  run cargo fmt --manifest-path verification/Cargo.toml --all -- --check
  run cargo clippy --locked --manifest-path verification/Cargo.toml --all-targets --all-features -- -D warnings
  run cargo test --locked --manifest-path verification/Cargo.toml
  run cargo fmt --manifest-path verification/fuzz/Cargo.toml --all -- --check
  run cargo clippy --locked --manifest-path verification/fuzz/Cargo.toml --all-targets --all-features -- -D warnings
  run cargo fmt --manifest-path aegis-cli/fuzz/Cargo.toml --all -- --check
  run cargo clippy --locked --manifest-path aegis-cli/fuzz/Cargo.toml --all-targets --all-features -- -D warnings
  run bash -n install.sh deploy/deploy.sh scripts/build-packages.sh scripts/check-tla.sh scripts/release-gates.sh verify.sh
  run env PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile scripts/packet-replay-lab.py
  run python3 scripts/packet-replay-lab.py --self-test-validator
  local replay_case_count
  replay_case_count="$(python3 scripts/packet-replay-lab.py --list-cases | wc -l)"
  if [[ "$replay_case_count" -ne 18 ]]; then
    echo "packet replay matrix must contain exactly 18 canonical cases, got: $replay_case_count" >&2
    return 1
  fi
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
  run env AEGIS_REQUIRE_EMBEDDED=1 cargo build --locked --release \
    -p aegis-cli \
    -p aegis-cni \
    -p aegis-tower \
    -p xtask

  require_cmd file
  run file "$cargo_target_dir/bpfel-unknown-none/release/aegis"
  run file "$cargo_target_dir/bpfel-unknown-none/release/aegis-tc"

  if command -v llvm-objdump >/dev/null 2>&1; then
    run llvm-objdump -h "$cargo_target_dir/bpfel-unknown-none/release/aegis"
    run llvm-objdump -h "$cargo_target_dir/bpfel-unknown-none/release/aegis-tc"
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

  run "$cargo_target_dir/release/aegis-cli" --iface lo daemon --help >/dev/null
}

release_candidate() {
  require_cmd cargo
  require_cmd git
  require_cmd python3
  require_cmd sha256sum
  require_cmd strings
  require_cmd tee

  local status
  local commit
  local version
  local timestamp
  local artifact_dir
  local cargo_target_dir
  local gate_rc=0
  cargo_target_dir="$(resolve_cargo_target_dir)"

  status="$(git status --short)"
  if [[ -n "$status" ]]; then
    echo "release-candidate validation requires a clean worktree" >&2
    printf '%s\n' "$status" >&2
    return 1
  fi

  configure_repeatable_release_build "$cargo_target_dir"

  commit="$(git rev-parse HEAD)"
  version="$(
    cargo metadata --locked --format-version 1 --no-deps |
      python3 -c 'import json,sys; data=json.load(sys.stdin); print(next(p["version"] for p in data["packages"] if p["name"] == "aegis-cli"))'
  )"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  artifact_dir="$ROOT_DIR/release-artifacts/$version/$commit/$timestamp"
  mkdir -p "$artifact_dir/metadata" "$artifact_dir/build" "$artifact_dir/tests"

  {
    echo "mode: release-candidate"
    echo "version: $version"
    echo "commit: $commit"
    echo "timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "cargo_target_dir: $cargo_target_dir"
    echo "cargo_incremental: $CARGO_INCREMENTAL"
    echo "rust_path_remap_target: /usr/src/aegis/target"
    echo "rust_path_remap_source: /usr/src/aegis"
    echo "command: CARGO_HOME=${CARGO_HOME:-<default>} CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-target} ./scripts/release-gates.sh release-candidate"
  } >"$artifact_dir/metadata/run.txt"
  git describe --tags --always --dirty >"$artifact_dir/metadata/git-describe.txt"
  git status --short >"$artifact_dir/metadata/git-status.txt"
  rustc --version --verbose >"$artifact_dir/metadata/rustc.txt"
  cargo --version --verbose >"$artifact_dir/metadata/cargo.txt"
  uname -a >"$artifact_dir/metadata/uname.txt"
  if [[ -r /etc/os-release ]]; then
    cp /etc/os-release "$artifact_dir/metadata/os-release"
  fi

  set +e
  non_privileged 2>&1 | tee "$artifact_dir/tests/nonpriv.log"
  gate_rc="${PIPESTATUS[0]}"
  set -e
  if [[ "$gate_rc" -ne 0 ]]; then
    echo "release-candidate nonpriv gate failed; artifacts retained at: $artifact_dir" >&2
    return "$gate_rc"
  fi

  for artifact in \
    "$cargo_target_dir/release/aegis-cli" \
    "$cargo_target_dir/release/aegis-cni" \
    "$cargo_target_dir/release/aegis-tower" \
    "$cargo_target_dir/release/xtask"; do
    reject_embedded_path "$artifact" "$cargo_target_dir"
    reject_embedded_path "$artifact" "$ROOT_DIR"
  done

  sha256sum \
    "$cargo_target_dir/bpfel-unknown-none/release/aegis" \
    "$cargo_target_dir/bpfel-unknown-none/release/aegis-tc" \
    "$cargo_target_dir/release/aegis-cli" \
    "$cargo_target_dir/release/aegis-cni" \
    "$cargo_target_dir/release/aegis-tower" \
    "$cargo_target_dir/release/xtask" >"$artifact_dir/build/SHA256SUMS"
  cp "$cargo_target_dir/bpfel-unknown-none/release/aegis" "$artifact_dir/build/aegis"
  cp "$cargo_target_dir/bpfel-unknown-none/release/aegis-tc" "$artifact_dir/build/aegis-tc"
  cp "$artifact_dir/build/SHA256SUMS" "$artifact_dir/build/SHA256SUMS.source-paths"
  (
    cd "$artifact_dir/build"
    sha256sum aegis aegis-tc >SHA256SUMS.archived
    sha256sum -c SHA256SUMS.archived
  )

  echo "release-candidate nonpriv artifacts: $artifact_dir"
  echo "privileged verifier/load/attach/replay/stress evidence is still required"
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
  local cargo_target_dir
  cargo_target_dir="$(resolve_cargo_target_dir)"

  validate_stress_iterations "$stress_iterations"

  if [[ -z "$replay_dir" ]]; then
    replay_dir="$(mktemp -d /tmp/aegis-replay.XXXXXX)"
    echo "AEGIS_PACKET_REPLAY_DIR not set; writing replay and attach evidence artifacts to: $replay_dir" >&2
  fi
  require_clean_evidence_dir "$replay_dir"
  export AEGIS_PACKET_REPLAY_DIR="$replay_dir"
  mkdir -p "$replay_dir"
  if (( stress_iterations > 0 )); then
    require_resource_headroom stress >"$replay_dir/resource-preflight.log"
  else
    require_resource_headroom privileged >"$replay_dir/resource-preflight.log"
  fi
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
      cleanup_aegis_lab_pins "${host_if:-aegis-host0}"
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
    "$cargo_target_dir/bpfel-unknown-none/release/aegis" \
    /sys/fs/bpf/aegis-release-xdp \
    xdp \
    "$replay_dir/bpftool-xdp-load.log"
  diagnostic_bpftool_load \
    "$cargo_target_dir/bpfel-unknown-none/release/aegis-tc" \
    /sys/fs/bpf/aegis-release-tc \
    sched_cls \
    "$replay_dir/bpftool-tc-load.log"

  # Runtime attach through the real loader validates Aya load/attach paths and TC setup.
  # Scale daemon timeout for the XDP+TC replay matrix plus setup overhead.
  local daemon_timeout=$(( 120 + stress_iterations * 30 ))
  (
    cd "$lab_dir"
    timeout "${daemon_timeout}s" "$cargo_target_dir/release/aegis-cli" --iface "$host_if" daemon
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

  local case_output=""
  local replay_cases=()
  local replay_timeout="${AEGIS_REPLAY_TIMEOUT_SECONDS:-}"
  if ! case_output="$(python3 scripts/packet-replay-lab.py --list-cases)"; then
    echo "could not calculate the packet replay watchdog timeout" >&2
    exit 1
  fi
  mapfile -t replay_cases <<<"$case_output"
  if [[ "${#replay_cases[@]}" -eq 0 || -z "${replay_cases[0]}" ]]; then
    echo "canonical packet replay case list is empty" >&2
    exit 1
  fi
  if [[ -z "$replay_timeout" ]]; then
    replay_timeout=$((300 + (stress_iterations + 1) * ${#replay_cases[@]} * 5))
  fi
  validate_replay_timeout "$replay_timeout"
  echo "replay_timeout_seconds: $replay_timeout" >>"$replay_dir/resource-preflight.log"

  run timeout --signal=TERM --kill-after=30s "${replay_timeout}s" "${replay_cmd[@]}"

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
  release-candidate)
    release_candidate
    ;;
  privileged-lab)
    require_resource_headroom privileged
    non_privileged
    privileged_lab
    ;;
  stress-lab)
    export AEGIS_STRESS_ITERATIONS="${AEGIS_STRESS_ITERATIONS:-25}"
    validate_stress_iterations "$AEGIS_STRESS_ITERATIONS"
    require_resource_headroom stress
    non_privileged
    privileged_lab
    ;;
  evidence-only)
    require_cmd python3
    require_packet_replay_evidence
    stress_iterations="${AEGIS_STRESS_ITERATIONS:-0}"
    validate_stress_iterations "$stress_iterations"
    if (( stress_iterations > 0 )); then
      require_stress_evidence "$stress_iterations"
    fi
    ;;
  *)
    echo "usage: $0 [nonpriv|release-candidate|privileged-lab|stress-lab|evidence-only]" >&2
    exit 2
    ;;
esac
