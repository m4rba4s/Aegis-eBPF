#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${AEGIS_CLI:-$ROOT/target/release/aegis-cli}"

fail() {
    printf 'deployment contract failure: %s\n' "$*" >&2
    exit 1
}

cd "$ROOT"

bash -n install.sh deploy/deploy.sh scripts/build-packages.sh test/distro-matrix.sh

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck install.sh deploy/deploy.sh scripts/build-packages.sh test/distro-matrix.sh
fi

[[ -x deploy/deploy.sh ]] || fail "deploy/deploy.sh is not executable"

if [[ -x "$CLI" ]]; then
    "$CLI" --iface lo daemon --help >/dev/null
    "$CLI" --iface lo --no-tc daemon --help >/dev/null
    "$CLI" --iface eth0 tui --help >/dev/null
    "$CLI" feeds update --help >/dev/null
    "$CLI" feeds load --help >/dev/null
else
    printf 'warning: CLI not found at %s; command-path checks skipped\n' "$CLI" >&2
fi

set +e
invalid_output=$(./install.sh --definitely-invalid 2>&1)
invalid_status=$?
set -e
[[ $invalid_status -eq 2 ]] || fail "unknown installer option returned $invalid_status, expected 2"
grep -q "Unknown option: --definitely-invalid" <<<"$invalid_output" ||
    fail "unknown installer option was not diagnosed"

set +e
check_output=$(./install.sh --check 2>&1)
set -e
if grep -q "must be run as root" <<<"$check_output"; then
    fail "install.sh --check still requires root"
fi

python3 - "$ROOT" <<'PY'
from pathlib import Path
import json
import re
import sys
import tomllib

import yaml

root = Path(sys.argv[1])

unit = (root / "deploy/aegis@.service").read_text()
required_unit = [
    "WorkingDirectory=/etc/aegis",
    "EnvironmentFile=-/etc/aegis/service.env",
    "ExecStart=/usr/local/bin/aegis-cli -i %i daemon",
    "UMask=0077",
]
for value in required_unit:
    if value not in unit:
        raise SystemExit(f"unit missing: {value}")
if "ExecReload=" in unit:
    raise SystemExit("unit advertises unsupported reload behavior")

cap_line = next(
    line for line in unit.splitlines() if line.startswith("CapabilityBoundingSet=")
)
caps = set(cap_line.split("=", 1)[1].split())
required_caps = {
    "CAP_BPF",
    "CAP_NET_ADMIN",
    "CAP_PERFMON",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_SETPCAP",
}
if not required_caps <= caps:
    raise SystemExit(f"unit capabilities missing: {sorted(required_caps - caps)}")
if "CAP_SYS_ADMIN" in caps:
    raise SystemExit("unit grants CAP_SYS_ADMIN")

installer = (root / "install.sh").read_text()
match = re.search(
    r"cat > /etc/systemd/system/aegis@\.service << 'EOF'\n(.*?)\nEOF",
    installer,
    re.S,
)
if not match:
    raise SystemExit("installer systemd unit template not found")
if match.group(1).strip() != unit.strip():
    raise SystemExit("installer and deploy systemd unit templates differ")

rules = yaml.safe_load((root / "deploy/config.yaml").read_text())
if set(rules) != {"rules", "egress_rules", "egress_cidrs", "blocked_countries"}:
    raise SystemExit(f"unexpected rule config keys: {sorted(rules)}")

runtime = tomllib.loads((root / "deploy/config.toml").read_text())
for section in (
    "modules",
    "autoban",
    "feeds",
    "logging",
    "allowlist",
    "webhooks",
    "dpi",
    "fleet",
    "pcap",
):
    if section not in runtime:
        raise SystemExit(f"runtime config section missing: {section}")

daemonset = yaml.safe_load((root / "deploy/kubernetes/daemonset.yaml").read_text())
pod = daemonset["spec"]["template"]["spec"]
container = pod["containers"][0]
if container.get("command") != ["/aegis-cli"]:
    raise SystemExit("DaemonSet entrypoint does not match scratch image")
if container.get("args") != ["--iface", "eth0", "daemon"]:
    raise SystemExit("DaemonSet CLI arguments are invalid")
if container.get("workingDir") != "/etc/aegis":
    raise SystemExit("DaemonSet does not load /etc/aegis/aegis.yaml at startup")
if pod.get("automountServiceAccountToken") is not False:
    raise SystemExit("DaemonSet unnecessarily mounts a Kubernetes API token")

for probe_name in ("livenessProbe", "readinessProbe"):
    probe = container[probe_name]["httpGet"]
    if probe.get("path") != "/health" or probe.get("port") != 9100:
        raise SystemExit(f"DaemonSet {probe_name} does not match the metrics server")
    if probe.get("host") != "127.0.0.1":
        raise SystemExit(
            f"DaemonSet {probe_name} must reach the host-network loopback listener"
        )

security = container["securityContext"]
if security.get("privileged") is True:
    raise SystemExit("DaemonSet is privileged")
kube_caps = set(security["capabilities"]["add"])
required_kube_caps = {"BPF", "NET_ADMIN", "PERFMON", "SETUID", "SETGID", "SETPCAP"}
if not required_kube_caps <= kube_caps:
    raise SystemExit(
        f"DaemonSet capabilities missing: {sorted(required_kube_caps - kube_caps)}"
    )
if "SYS_ADMIN" in kube_caps:
    raise SystemExit("DaemonSet grants SYS_ADMIN")

mount_names = {item["name"] for item in container["volumeMounts"]}
if "cni-bin" in mount_names or "cni-conf" in mount_names:
    raise SystemExit("DaemonSet still claims to install an unshipped CNI binary")

rbac_docs = list(yaml.safe_load_all((root / "deploy/kubernetes/rbac.yaml").read_text()))
rbac_kinds = [doc["kind"] for doc in rbac_docs if doc]
if rbac_kinds != ["Namespace", "ServiceAccount"]:
    raise SystemExit(f"unexpected Kubernetes RBAC resources: {rbac_kinds}")

json.loads((root / "deploy/kubernetes/cni-config.json").read_text())

dockerfile = (root / "Dockerfile").read_text()
if "FROM scratch AS export" not in dockerfile or " /aegis-cli" not in dockerfile:
    raise SystemExit("Docker export contract changed without updating DaemonSet")
PY

printf 'deployment contracts: passed\n'
