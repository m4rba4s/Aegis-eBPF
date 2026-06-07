#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v bwrap >/dev/null 2>&1; then
    printf 'installer sandbox smoke: skipped (bubblewrap not installed)\n'
    exit 0
fi

for artifact in \
    "$ROOT/target/release/aegis-cli" \
    "$ROOT/target/bpfel-unknown-none/release/aegis" \
    "$ROOT/target/bpfel-unknown-none/release/aegis-tc"; do
    [[ -s "$artifact" ]] || {
        printf 'installer sandbox smoke: missing artifact: %s\n' "$artifact" >&2
        exit 1
    }
done

bwrap \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /etc \
    --tmpfs /tmp \
    --tmpfs /usr/local \
    --tmpfs /usr/share \
    --tmpfs /var \
    --tmpfs /sys/fs/bpf \
    --dir /tmp/host-etc \
    --ro-bind /etc /tmp/host-etc \
    --chdir "$ROOT" \
    --unshare-user \
    --uid 0 \
    --gid 0 \
    --unshare-pid \
    --die-with-parent \
    bash -euo pipefail -c '
        cp /tmp/host-etc/passwd /etc/passwd
        cp /tmp/host-etc/group /etc/group

        export AEGIS_INSTALLER_SOURCE_ONLY=true
        # shellcheck source=../install.sh
        source ./install.sh

        detect_init_system() { echo unknown; }
        check_kernel_version() { :; }
        check_bpf_fs() { :; }
        install_runtime_deps() { :; }
        install_completions() { :; }
        install_geoip_db() { :; }
        install_logrotate() { :; }

        main --install-only --skip-service
        main --install-only --skip-service

        test -x /usr/local/bin/aegis-cli
        test -s /usr/local/share/aegis/aegis.o
        test -s /usr/local/share/aegis/aegis-tc.o
        test -s /etc/aegis/config.toml
        test -s /etc/aegis/aegis.yaml
        test ! -e /etc/systemd/system/aegis@.service

        uninstall_aegis </dev/null
        test ! -e /usr/local/bin/aegis-cli
        test ! -e /usr/local/share/aegis
        test -s /etc/aegis/config.toml
        test -s /etc/aegis/aegis.yaml
    '

printf 'installer sandbox smoke: passed\n'
