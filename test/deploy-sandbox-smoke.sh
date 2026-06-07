#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v bwrap >/dev/null 2>&1; then
    printf 'deploy sandbox smoke: skipped (bubblewrap not installed)\n'
    exit 0
fi

for artifact in \
    "$ROOT/target/release/aegis-cli" \
    "$ROOT/target/bpfel-unknown-none/release/aegis" \
    "$ROOT/target/bpfel-unknown-none/release/aegis-tc"; do
    [[ -s "$artifact" ]] || {
        printf 'deploy sandbox smoke: missing artifact: %s\n' "$artifact" >&2
        exit 1
    }
done

# The inner single-quoted script intentionally defers expansion to the sandbox.
# shellcheck disable=SC2016
bwrap \
    --ro-bind / / \
    --dev /dev \
    --proc /proc \
    --tmpfs /etc \
    --tmpfs /run \
    --tmpfs /tmp \
    --tmpfs /usr/local \
    --tmpfs /var \
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
        mkdir -p /etc/systemd/system /run/systemd/system /tmp/bin

        cat > /tmp/bin/ip <<'"'"'EOF'"'"'
#!/bin/sh
test "$*" = "link show dev lo"
EOF
        cat > /tmp/bin/systemctl <<'"'"'EOF'"'"'
#!/bin/sh
printf "%s\n" "$*" >> /tmp/systemctl.log
if test "$1" = "enable" && test "${FAKE_SYSTEMCTL_START_FAIL:-0}" = "1"; then
    exit 1
fi
exit 0
EOF
        cat > /tmp/bin/systemd-analyze <<'"'"'EOF'"'"'
#!/bin/sh
test "$1" = "verify"
EOF
        chmod +x /tmp/bin/ip /tmp/bin/systemctl /tmp/bin/systemd-analyze
        export PATH="/tmp/bin:$PATH"
        export AEGIS_SERVICE_USER=root
        export AEGIS_SERVICE_GROUP=root

        ./deploy/deploy.sh lo
        test -x /usr/local/bin/aegis-cli
        test -s /usr/local/share/aegis/aegis.o
        test -s /usr/local/share/aegis/aegis-tc.o
        test -s /etc/aegis/aegis.yaml
        test -s /etc/aegis/config.toml
        test -s /etc/aegis/service.env
        test -s /etc/systemd/system/aegis@.service
        grep -q "^interface = \"lo\"$" /etc/aegis/config.toml
        grep -q "^SUDO_UID=0$" /etc/aegis/service.env
        grep -q "^SUDO_GID=0$" /etc/aegis/service.env
        grep -q "^enable --now aegis@lo.service$" /tmp/systemctl.log
        grep -q "^is-active --quiet aegis@lo.service$" /tmp/systemctl.log

        printf "\n# preserved\n" >> /etc/aegis/aegis.yaml
        ./deploy/deploy.sh lo
        grep -q "^# preserved$" /etc/aegis/aegis.yaml

        set +e
        FAKE_SYSTEMCTL_START_FAIL=1 ./deploy/deploy.sh lo >/tmp/deploy-failure.log 2>&1
        status=$?
        set -e
        test "$status" -ne 0
        grep -q "service failed to start" /tmp/deploy-failure.log
        grep -q "^disable aegis@lo.service$" /tmp/systemctl.log
    '

printf 'deploy sandbox smoke: passed\n'
