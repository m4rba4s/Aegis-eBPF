#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
stress_test.sh is retired because it used an unbounded hping3 flood and broad
pkill cleanup. It is not release evidence and must not run on a workstation or
shared network.

Use the isolated, bounded replay gate from a disposable VM:

  sudo -E AEGIS_PACKET_REPLAY_DIR=/tmp/aegis-replay-stress \
    AEGIS_STRESS_ITERATIONS=25 \
    CARGO_HOME=/tmp/aegis-cargo-home \
    ./scripts/release-gates.sh stress-lab

See docs/RELEASE_VALIDATION.md for host resource preflight and stop rules.
EOF

exit 2
