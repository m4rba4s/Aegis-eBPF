#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tla_jar="${TLA2TOOLS_JAR:-/tmp/tla2tools.jar}"

if [[ ! -f "$tla_jar" ]]; then
  echo "TLA+ tools jar not found: $tla_jar" >&2
  echo "Set TLA2TOOLS_JAR to a verified tla2tools.jar path." >&2
  exit 1
fi

if ! command -v java >/dev/null 2>&1; then
  echo "java is required to run TLC" >&2
  exit 1
fi

meta_dir="$(mktemp -d /tmp/aegis-tlc.XXXXXX)"
trap 'rm -rf "$meta_dir"' EXIT

cd "$repo_root/verification/tla"
java -XX:+UseParallelGC -cp "$tla_jar" tlc2.TLC \
  -workers 1 \
  -metadir "$meta_dir" \
  -config ConnTrack.cfg \
  ConnTrack.tla
