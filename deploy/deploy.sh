#!/bin/bash
# Aegis eBPF Firewall - Production Install Script
# Run with sudo: sudo ./deploy.sh [interface]

set -euo pipefail

INTERFACE="${1:-eth0}"
INSTALL_DIR="/usr/local"
CONFIG_DIR="/etc/aegis"
LOG_DIR="/var/log/aegis"
DATA_DIR="/var/lib/aegis"
SERVICE_USER="${AEGIS_SERVICE_USER:-aegis}"
SERVICE_GROUP="${AEGIS_SERVICE_GROUP:-aegis}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLI_SOURCE="$PROJECT_DIR/target/release/aegis-cli"
XDP_SOURCE="$PROJECT_DIR/target/bpfel-unknown-none/release/aegis"
TC_SOURCE="$PROJECT_DIR/target/bpfel-unknown-none/release/aegis-tc"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

ensure_service_account() {
    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        if command -v groupadd >/dev/null 2>&1; then
            groupadd --system "$SERVICE_GROUP"
        elif command -v addgroup >/dev/null 2>&1; then
            addgroup -S "$SERVICE_GROUP"
        else
            fail "groupadd/addgroup is required to create $SERVICE_GROUP"
        fi
    fi

    if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        local nologin_shell
        nologin_shell=$(command -v nologin 2>/dev/null || true)
        [[ -n "$nologin_shell" ]] || nologin_shell="/sbin/nologin"

        if command -v useradd >/dev/null 2>&1; then
            useradd --system --gid "$SERVICE_GROUP" --home-dir "$DATA_DIR" \
                --no-create-home --shell "$nologin_shell" "$SERVICE_USER"
        elif command -v adduser >/dev/null 2>&1; then
            adduser -S -D -H -G "$SERVICE_GROUP" -h "$DATA_DIR" \
                -s "$nologin_shell" "$SERVICE_USER"
        else
            fail "useradd/adduser is required to create $SERVICE_USER"
        fi
    fi

    local service_gid expected_gid
    service_gid=$(id -g "$SERVICE_USER")
    expected_gid=$(getent group "$SERVICE_GROUP" | cut -d: -f3)
    [[ "$service_gid" == "$expected_gid" ]] ||
        fail "service user $SERVICE_USER must use $SERVICE_GROUP as its primary group"
}

install_atomic() {
    local mode="$1"
    local source="$2"
    local destination="$3"
    local temporary="${destination}.new"

    install -m "$mode" "$source" "$temporary"
    mv -f "$temporary" "$destination"
}

echo "AEGIS production deployment"
echo

[[ $EUID -eq 0 ]] || fail "this script must be run as root"
[[ $# -le 1 ]] || fail "usage: $0 [interface]"
[[ -n "$INTERFACE" && ${#INTERFACE} -le 15 ]] ||
    fail "invalid interface '$INTERFACE': Linux interface names are 1-15 characters"
[[ "$INTERFACE" =~ ^[A-Za-z0-9_-]+$ ]] ||
    fail "invalid interface '$INTERFACE': only ASCII letters, digits, '_' and '-' are allowed"

for tool in install ip systemctl getent; do
    command -v "$tool" >/dev/null 2>&1 || fail "required command not found: $tool"
done
[[ -d /run/systemd/system ]] || fail "systemd is not the active init system"
ip link show dev "$INTERFACE" >/dev/null 2>&1 ||
    fail "network interface does not exist: $INTERFACE"

for artifact in "$CLI_SOURCE" "$XDP_SOURCE" "$TC_SOURCE" \
    "$SCRIPT_DIR/aegis@.service" "$SCRIPT_DIR/config.yaml" "$SCRIPT_DIR/config.toml"; do
    [[ -s "$artifact" ]] || fail "required deployment artifact missing or empty: $artifact"
done
[[ -x "$CLI_SOURCE" ]] || fail "CLI artifact is not executable: $CLI_SOURCE"

"$CLI_SOURCE" --iface "$INTERFACE" daemon --help >/dev/null
"$CLI_SOURCE" --iface "$INTERFACE" --no-tc daemon --help >/dev/null
if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze verify "$SCRIPT_DIR/aegis@.service"
fi

echo "Installing Aegis for interface: $INTERFACE"
ensure_service_account
install -d -o root -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$LOG_DIR" "$DATA_DIR"
install -d -o root -g root -m 0755 "$INSTALL_DIR/bin" "$INSTALL_DIR/share/aegis"

install_atomic 0755 "$CLI_SOURCE" "$INSTALL_DIR/bin/aegis-cli"
install_atomic 0644 "$XDP_SOURCE" "$INSTALL_DIR/share/aegis/aegis.o"
install_atomic 0644 "$TC_SOURCE" "$INSTALL_DIR/share/aegis/aegis-tc.o"

if [[ ! -e "$CONFIG_DIR/aegis.yaml" ]]; then
    install -o root -g "$SERVICE_GROUP" -m 0640 \
        "$SCRIPT_DIR/config.yaml" "$CONFIG_DIR/aegis.yaml"
else
    echo "Preserving existing $CONFIG_DIR/aegis.yaml"
fi

if [[ ! -e "$CONFIG_DIR/config.toml" ]]; then
    install -o root -g "$SERVICE_GROUP" -m 0640 \
        "$SCRIPT_DIR/config.toml" "$CONFIG_DIR/config.toml"
    sed -i "s/^interface = .*/interface = \"$INTERFACE\"/" "$CONFIG_DIR/config.toml"
else
    echo "Preserving existing $CONFIG_DIR/config.toml"
fi

{
    printf 'SUDO_UID=%s\n' "$(id -u "$SERVICE_USER")"
    printf 'SUDO_GID=%s\n' "$(id -g "$SERVICE_USER")"
} > "$CONFIG_DIR/service.env"
chown root:"$SERVICE_GROUP" "$CONFIG_DIR/service.env"
chmod 0640 "$CONFIG_DIR/service.env"

install_atomic 0644 "$SCRIPT_DIR/aegis@.service" /etc/systemd/system/aegis@.service
systemctl daemon-reload

unit="aegis@$INTERFACE.service"
if ! systemctl enable --now "$unit"; then
    systemctl disable "$unit" >/dev/null 2>&1 || true
    fail "service failed to start; inspect: journalctl -u '$unit' --no-pager"
fi
if ! systemctl is-active --quiet "$unit"; then
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fail "service did not remain active; inspect: journalctl -u '$unit' --no-pager"
fi

echo
echo "Installation complete"
echo "  CLI:     $INSTALL_DIR/bin/aegis-cli"
echo "  XDP:     $INSTALL_DIR/share/aegis/aegis.o"
echo "  TC:      $INSTALL_DIR/share/aegis/aegis-tc.o"
echo "  Rules:   $CONFIG_DIR/aegis.yaml"
echo "  Runtime: $CONFIG_DIR/config.toml"
echo "  Service: $unit (active)"
