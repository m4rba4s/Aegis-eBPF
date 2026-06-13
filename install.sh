#!/bin/bash
# Aegis XDP Firewall - Installer and maintenance script
# Contains install handlers for multiple distributions. Runtime support remains
# limited to targets with commit-specific load/attach/replay evidence.
# Init systems: systemd, openrc, sysvinit
#
# Usage:
#   sudo ./install.sh              # Full build + install
#   sudo ./install.sh --update     # Update from the tracked source tree
#   sudo ./install.sh --check      # Dry-run: validate all prerequisites
#   sudo ./install.sh --install-only  # Install pre-built binaries only
#   sudo ./install.sh --uninstall  # Remove Aegis completely

set -euo pipefail

AEGIS_REPO_URL="${AEGIS_REPO_URL:-https://github.com/m4rba4s/Aegis-eBPF.git}"
AEGIS_TARBALL_URL="${AEGIS_TARBALL_URL:-https://github.com/m4rba4s/Aegis-eBPF/archive/refs/heads/main.tar.gz}"

bootstrap_from_stdin() {
    local tmpdir
    tmpdir=$(mktemp -d /tmp/aegis-ebpf-install.XXXXXX)

    echo "Aegis installer is running from stdin; fetching source into $tmpdir"

    if command -v git >/dev/null 2>&1; then
        if git clone --depth 1 "$AEGIS_REPO_URL" "$tmpdir"; then
            exec bash "$tmpdir/install.sh" "$@"
        fi
        echo "git clone failed; trying source tarball..." >&2
    fi

    if command -v curl >/dev/null 2>&1 && command -v tar >/dev/null 2>&1; then
        if curl -fsSL "$AEGIS_TARBALL_URL" | tar -xz -C "$tmpdir" --strip-components=1; then
            exec bash "$tmpdir/install.sh" "$@"
        fi
    fi

    echo "ERROR: one-line install requires git, or curl + tar." >&2
    exit 1
}

SCRIPT_PATH="${BASH_SOURCE[0]:-}"
if [[ -z "$SCRIPT_PATH" || ! -f "$SCRIPT_PATH" ]]; then
    bootstrap_from_stdin "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
INSTALL_DIR="/usr/local"
BIN_DIR="$INSTALL_DIR/bin"
SHARE_DIR="$INSTALL_DIR/share/aegis"
SERVICE_USER="${AEGIS_SERVICE_USER:-aegis}"
SERVICE_GROUP="${AEGIS_SERVICE_GROUP:-aegis}"
RUST_TOOLCHAIN_CHANNEL="nightly-2026-02-12"
BPF_LINKER_VERSION="0.10.1"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}ℹ️  $1${NC}"; }
log_ok()    { echo -e "${GREEN}✅ $1${NC}"; }
log_warn()  { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }
log_step()  { echo -e "${BOLD}▶  $1${NC}"; }

# =============================================================================
# DETECTION FUNCTIONS
# =============================================================================

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

detect_init_system() {
    if command -v systemctl &>/dev/null && { [[ -d /run/systemd/system ]] || [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" == "systemd" ]]; }; then
        echo "systemd"
    elif command -v rc-service &>/dev/null; then
        echo "openrc"
    elif [[ -f /etc/init.d/functions ]]; then
        echo "sysvinit"
    else
        echo "unknown"
    fi
}

check_kernel_version() {
    local ver major minor
    ver=$(uname -r | cut -d. -f1-2)
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)

    if [[ "$major" -lt 5 ]] || { [[ "$major" -eq 5 ]] && [[ "$minor" -lt 4 ]]; }; then
        log_error "Kernel $ver is too old. Aegis requires >= 5.4"
        log_info "Upgrade your kernel or use a newer distro"
        return 1
    fi
    log_ok "Kernel version: $(uname -r)"
}

check_bpf_fs() {
    local check_only="${1:-false}"

    if awk '$2 == "/sys/fs/bpf" && $3 == "bpf" { found = 1 } END { exit !found }' /proc/mounts; then
        log_ok "BPF filesystem mounted at /sys/fs/bpf"
        return 0
    fi

    if [[ "$check_only" == "true" ]]; then
        log_error "BPF filesystem not mounted at /sys/fs/bpf"
        log_info "Mount it with: sudo mount -t bpf bpf /sys/fs/bpf"
        return 1
    fi

    log_warn "BPF filesystem not mounted at /sys/fs/bpf"
    log_info "Attempting to mount..."
    mkdir -p /sys/fs/bpf
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || {
        log_error "Failed to mount BPF filesystem"
        log_info "Try manually: sudo mount -t bpf bpf /sys/fs/bpf"
        return 1
    }

    if ! awk '$2 == "/sys/fs/bpf" && $3 == "bpf" { found = 1 } END { exit !found }' /proc/mounts; then
        log_error "/sys/fs/bpf exists but is not mounted as bpffs"
        return 1
    fi

    log_ok "BPF filesystem mounted at /sys/fs/bpf"
}

check_runtime_tools() {
    local missing=()
    local tools=(ip tc mount uname)

    if [[ "$(detect_init_system)" == "systemd" ]]; then
        tools+=(systemctl)
    fi

    for tool in "${tools[@]}"; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing runtime tools: ${missing[*]}"
        log_info "Install iproute2/systemd tools for your distro, then re-run this script"
        return 1
    fi

    if command -v bpftool &>/dev/null; then
        log_ok "bpftool: $(command -v bpftool)"
    else
        log_warn "bpftool not found; install it for verifier diagnostics and release validation"
    fi

    log_ok "Runtime tools available: ${tools[*]}"
}

# =============================================================================
# SYSTEM DEPENDENCIES (runs BEFORE any Rust operations)
# =============================================================================

install_system_deps() {
    log_step "Installing system dependencies..."
    local distro
    distro=$(detect_distro)

    case "$distro" in
        fedora|rhel|centos|rocky|alma)
            if command -v dnf &>/dev/null; then
                dnf install -y \
                    gcc make pkg-config \
                    llvm clang llvm-devel \
                    elfutils-libelf-devel \
                    protobuf-compiler \
                    iproute \
                    curl wget git
            elif command -v yum &>/dev/null; then
                yum install -y \
                    gcc make pkgconfig \
                    llvm clang llvm-devel \
                    elfutils-libelf-devel \
                    protobuf-compiler \
                    iproute \
                    curl wget git
            else
                log_warn "dnf/yum not found; install system dependencies manually"
            fi
            ;;
        ubuntu|debian|pop|linuxmint)
            apt-get update -qq
            apt-get install -y \
                build-essential pkg-config \
                llvm clang libelf-dev \
                protobuf-compiler \
                iproute2 \
                curl wget git
            ;;
        arch|manjaro|endeavouros)
            pacman -Sy --noconfirm --needed \
                base-devel llvm clang libelf \
                protobuf \
                iproute2 \
                curl wget git
            ;;
        opensuse*|sles)
            zypper install -y \
                gcc make pkg-config \
                llvm clang libelf-devel \
                protobuf-devel \
                iproute2 \
                curl wget git
            ;;
        alpine)
            apk add \
                build-base musl-dev linux-headers \
                llvm clang elfutils-dev \
                protobuf \
                iproute2 \
                curl wget git
            ;;
        *)
            log_warn "Unknown distro '$distro' — install manually: gcc, llvm, clang, libelf-dev, iproute2, curl, git"
            ;;
    esac

    # Validate critical tools
    local missing=()
    command -v gcc &>/dev/null || missing+=("gcc")
    command -v clang &>/dev/null || missing+=("clang")
    command -v git &>/dev/null || missing+=("git")
    command -v curl &>/dev/null || missing+=("curl")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing critical tools: ${missing[*]}"
        log_info "Install them manually and re-run this script"
        return 1
    fi

    log_ok "System dependencies installed ($distro)"
}

install_runtime_deps() {
    log_step "Installing runtime dependencies..."
    local distro
    distro=$(detect_distro)

    case "$distro" in
        fedora|rhel|centos|rocky|alma)
            if command -v dnf &>/dev/null; then
                dnf install -y iproute curl ca-certificates psmisc util-linux
            elif command -v yum &>/dev/null; then
                yum install -y iproute curl ca-certificates psmisc util-linux
            else
                log_warn "dnf/yum not found; install runtime dependencies manually"
            fi
            ;;
        ubuntu|debian|pop|linuxmint)
            apt-get update -qq
            apt-get install -y iproute2 curl ca-certificates procps psmisc util-linux
            ;;
        arch|manjaro|endeavouros)
            pacman -Sy --noconfirm --needed iproute2 curl ca-certificates procps-ng util-linux
            ;;
        opensuse*|sles)
            zypper install -y iproute2 curl ca-certificates psmisc util-linux
            ;;
        alpine)
            apk add --no-cache iproute2 curl ca-certificates psmisc util-linux
            ;;
        *)
            log_warn "Unknown distro '$distro' - install iproute2, curl, psmisc, and util-linux manually"
            ;;
    esac

    check_runtime_tools
    log_ok "Runtime dependencies installed ($distro)"
}

# =============================================================================
# SERVICE ACCOUNT
# =============================================================================

ensure_service_account() {
    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        if command -v groupadd >/dev/null 2>&1; then
            groupadd --system "$SERVICE_GROUP"
        elif command -v addgroup >/dev/null 2>&1; then
            addgroup -S "$SERVICE_GROUP"
        else
            log_error "Cannot create service group: groupadd/addgroup not found"
            return 1
        fi
    fi

    if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        local nologin_shell
        nologin_shell=$(command -v nologin 2>/dev/null || true)
        [[ -n "$nologin_shell" ]] || nologin_shell="/sbin/nologin"

        if command -v useradd >/dev/null 2>&1; then
            useradd --system --gid "$SERVICE_GROUP" --home-dir /var/lib/aegis \
                --no-create-home --shell "$nologin_shell" "$SERVICE_USER"
        elif command -v adduser >/dev/null 2>&1; then
            adduser -S -D -H -G "$SERVICE_GROUP" -h /var/lib/aegis \
                -s "$nologin_shell" "$SERVICE_USER"
        else
            log_error "Cannot create service user: useradd/adduser not found"
            return 1
        fi
    fi

    local service_uid service_gid expected_gid
    service_uid=$(id -u "$SERVICE_USER")
    service_gid=$(id -g "$SERVICE_USER")
    expected_gid=$(getent group "$SERVICE_GROUP" | cut -d: -f3)
    if [[ "$service_gid" != "$expected_gid" ]]; then
        log_error "Service user $SERVICE_USER must use $SERVICE_GROUP as its primary group"
        return 1
    fi

    install -d -o root -g "$SERVICE_GROUP" -m 0750 /etc/aegis
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 /var/log/aegis
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 /var/lib/aegis

    {
        printf 'SUDO_UID=%s\n' "$service_uid"
        printf 'SUDO_GID=%s\n' "$service_gid"
    } > /etc/aegis/service.env
    chown root:"$SERVICE_GROUP" /etc/aegis/service.env
    chmod 0640 /etc/aegis/service.env

    log_ok "Service account ready: $SERVICE_USER ($service_uid:$service_gid)"
}

# =============================================================================
# RUST TOOLCHAIN DETECTION & SETUP
# =============================================================================

cargo_bin_candidates() {
    # SUDO_USER's home is common when Rust was installed before running sudo.
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_home
        sudo_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6) || true
        [[ -n "$sudo_home" ]] && echo "$sudo_home/.cargo/bin"
    fi

    [[ -n "${HOME:-}" ]] && echo "$HOME/.cargo/bin"

    for d in /home/*/.cargo/bin; do
        [[ -d "$d" ]] && echo "$d"
    done

    echo "/root/.cargo/bin"
}

activate_cargo_bin_dir() {
    local cbd="$1"
    local home_dir

    export PATH="$cbd:$PATH"

    home_dir="${cbd%/.cargo/bin}"
    if [[ -d "$home_dir/.cargo" ]]; then
        export CARGO_HOME="$home_dir/.cargo"
    fi
    if [[ -d "$home_dir/.rustup" ]]; then
        export RUSTUP_HOME="$home_dir/.rustup"
    fi

    hash -r 2>/dev/null || true
}

source_rust_envs() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_home
        sudo_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6) || true
        if [[ -f "$sudo_home/.cargo/env" ]]; then
            # shellcheck disable=SC1091
            source "$sudo_home/.cargo/env"
        fi
    fi

    if [[ -f "${HOME:-}/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
    if [[ -f /root/.cargo/env ]]; then
        # shellcheck disable=SC1091
        source /root/.cargo/env
    fi

    hash -r 2>/dev/null || true
}

find_cargo() {
    # Already in PATH?
    if command -v cargo &>/dev/null; then
        return 0
    fi

    local cbd
    while IFS= read -r cbd; do
        if [[ -x "$cbd/cargo" ]]; then
            log_info "Found cargo in: $cbd"
            activate_cargo_bin_dir "$cbd"
            return 0
        fi
    done < <(cargo_bin_candidates)

    return 1
}

find_rustup() {
    if command -v rustup &>/dev/null; then
        return 0
    fi

    local cbd
    while IFS= read -r cbd; do
        if [[ -x "$cbd/rustup" ]]; then
            log_info "Found rustup in: $cbd"
            activate_cargo_bin_dir "$cbd"
            return 0
        fi
    done < <(cargo_bin_candidates)

    return 1
}

prefer_rustup_cargo_proxy() {
    local rustup_path rustup_dir

    rustup_path=$(command -v rustup 2>/dev/null || true)
    if [[ -n "$rustup_path" ]]; then
        rustup_dir=$(dirname "$rustup_path")
        if [[ -x "$rustup_dir/cargo" ]]; then
            activate_cargo_bin_dir "$rustup_dir"
        fi
    fi
}

install_rustup() {
    log_info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source_rust_envs

    if ! find_rustup; then
        log_error "rustup installation finished but rustup is still not in PATH"
        log_info "Try: source ~/.cargo/env && sudo env PATH=\$PATH ./install.sh"
        return 1
    fi

    prefer_rustup_cargo_proxy
}

ensure_rust_installed() {
    source_rust_envs

    local cargo_found=false
    if find_cargo; then
        cargo_found=true
    fi

    if ! find_rustup; then
        if $cargo_found; then
            log_warn "cargo exists, but rustup is missing. Fedora's cargo package cannot install nightly toolchains."
        else
            log_info "Rust not found."
        fi
        install_rustup
    fi

    prefer_rustup_cargo_proxy

    if ! find_cargo; then
        log_error "Rust installation succeeded but cargo still not found"
        log_info "Try: source ~/.cargo/env && sudo env PATH=\$PATH ./install.sh"
        return 1
    fi

    if ! cargo --version &>/dev/null; then
        log_info "Installing default stable Rust toolchain..."
        rustup toolchain install stable
        rustup default stable
    fi

    log_ok "cargo: $(cargo --version)"
    log_ok "rustup: $(rustup --version | head -n1)"
}

ensure_rust_toolchain() {
    log_step "Setting up Rust toolchain for eBPF..."

    if ! find_rustup; then
        log_error "rustup is required to install nightly and rust-src"
        log_info "Install rustup, then re-run: sudo ./install.sh"
        return 1
    fi

    prefer_rustup_cargo_proxy

    # Commit-pinned nightly toolchain from rust-toolchain.toml.
    if ! rustup toolchain list 2>/dev/null | grep -Fq "$RUST_TOOLCHAIN_CHANNEL"; then
        log_info "Installing Rust toolchain $RUST_TOOLCHAIN_CHANNEL..."
        rustup toolchain install "$RUST_TOOLCHAIN_CHANNEL" || {
            log_error "Failed to install Rust toolchain $RUST_TOOLCHAIN_CHANNEL"
            return 1
        }
    fi

    # rust-src component (required for -Zbuild-std=core)
    if ! rustup component list --toolchain "$RUST_TOOLCHAIN_CHANNEL" 2>/dev/null | grep -q 'rust-src (installed)'; then
        log_info "Installing rust-src for $RUST_TOOLCHAIN_CHANNEL..."
        rustup component add rust-src --toolchain "$RUST_TOOLCHAIN_CHANNEL" || {
            log_error "Failed to install rust-src"
            return 1
        }
    fi

    if ! cargo "+$RUST_TOOLCHAIN_CHANNEL" --version &>/dev/null; then
        log_error "cargo is not the rustup proxy, so the pinned toolchain cannot be selected"
        log_info "Try: sudo env PATH=\"\$HOME/.cargo/bin:\$PATH\" ./install.sh"
        return 1
    fi

    if [[ "$(detect_distro)" == "alpine" ]]; then
        local rust_llvm_major
        rust_llvm_major=$(
            rustc "+$RUST_TOOLCHAIN_CHANNEL" -vV |
                awk -F': ' '/^LLVM version:/ { split($2, version, "."); print version[1] }'
        )
        if [[ -z "$rust_llvm_major" ]] ||
            ! find /usr/lib -maxdepth 3 -name "libLLVM-${rust_llvm_major}*.so" -print -quit |
                grep -q .; then
            log_error "Alpine source builds require LLVM $rust_llvm_major to match the pinned Rust nightly"
            log_info "Use ./install.sh --install-only on stable Alpine, or build with a repository providing matching LLVM"
            return 1
        fi
    fi

    # bpf-linker
    local installed_bpf_linker_version=""
    if command -v bpf-linker &>/dev/null; then
        installed_bpf_linker_version="$(bpf-linker --version 2>/dev/null | awk '{print $2}')"
    fi
    if [[ "$installed_bpf_linker_version" != "$BPF_LINKER_VERSION" ]]; then
        log_info "Installing bpf-linker $BPF_LINKER_VERSION (this may take several minutes)..."
        local bpf_linker_status=0
        if [[ "$(detect_distro)" == "alpine" ]]; then
            # A fully static musl bpf-linker cannot dlopen Alpine's shared LLVM.
            RUSTFLAGS="-C target-feature=-crt-static" \
                cargo "+$RUST_TOOLCHAIN_CHANNEL" install bpf-linker \
                --version "$BPF_LINKER_VERSION" --locked --force ||
                bpf_linker_status=$?
        else
            cargo "+$RUST_TOOLCHAIN_CHANNEL" install bpf-linker \
                --version "$BPF_LINKER_VERSION" --locked --force ||
                bpf_linker_status=$?
        fi
        if [[ $bpf_linker_status -ne 0 ]]; then
            log_error "Failed to install bpf-linker"
            log_info "Common fix: ensure llvm and clang are installed"
            log_info "Manual: cargo +$RUST_TOOLCHAIN_CHANNEL install bpf-linker --version $BPF_LINKER_VERSION --locked"
            return 1
        fi
    fi

    log_ok "$RUST_TOOLCHAIN_CHANNEL + rust-src + bpf-linker $BPF_LINKER_VERSION ready"
}

# =============================================================================
# SYSTEMD SERVICE
# =============================================================================

install_systemd_service() {
    cat > /etc/systemd/system/aegis@.service << 'EOF'
[Unit]
Description=Aegis eBPF XDP Firewall
Documentation=https://github.com/m4rba4s/Aegis-eBPF
After=network.target
Wants=network.target

[Service]
Type=simple
WorkingDirectory=/etc/aegis
EnvironmentFile=-/etc/aegis/service.env
ExecStart=/usr/local/bin/aegis-cli -i %i daemon
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
UMask=0077

# ============================================================
# SECURITY HARDENING
# ============================================================

# Capabilities - minimum required for eBPF/XDP/TC
# CAP_BPF: load BPF programs (kernel 5.8+)
# CAP_NET_ADMIN: attach XDP/TC, manage network
# CAP_SETUID/CAP_SETGID/CAP_SETPCAP: required only while the CLI drops
# privileges to the dedicated service account after loading/attaching eBPF.
# The CLI then retains only CAP_BPF and CAP_NET_ADMIN.
# CAP_PERFMON: perf_event_open for eBPF stats.
# No CAP_SYS_ADMIN fallback in production.
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SETUID CAP_SETGID CAP_SETPCAP
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SETUID CAP_SETGID CAP_SETPCAP

# Filesystem protection
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=false
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ReadWritePaths=/var/log/aegis /var/lib/aegis /sys/fs/bpf
RuntimeDirectory=aegis/instances/%i
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=restart

# Process isolation
NoNewPrivileges=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
PrivateUsers=false
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

# Namespace restrictions (need network namespace access)
RestrictNamespaces=cgroup ipc pid user uts

# System call filtering
# @system-service: basic service calls
# @network-io: network operations
# bpf: eBPF operations
SystemCallFilter=@system-service @network-io bpf perf_event_open
SystemCallErrorNumber=EPERM

# Network (needs full access for XDP)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

# ============================================================
# RESOURCE LIMITS
# ============================================================
LimitNOFILE=65536
LimitMEMLOCK=infinity

# ============================================================
# LOGGING
# ============================================================
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegis

[Install]
WantedBy=multi-user.target
EOF
    install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 /var/log/aegis

    systemctl daemon-reload
    log_ok "Systemd service installed: aegis@<interface>.service"
}

install_systemd_timer() {
    # Service to update feeds
    cat > /etc/systemd/system/aegis-feeds.service << 'EOF'
[Unit]
Description=Aegis Threat Feed Auto-Refresh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/etc/aegis
ExecStart=/usr/local/bin/aegis-cli feeds update
ExecStart=/usr/local/bin/aegis-cli feeds load
EOF

    # Timer to trigger the service daily
    cat > /etc/systemd/system/aegis-feeds.timer << 'EOF'
[Unit]
Description=Run Aegis Threat Feed Auto-Refresh daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable aegis-feeds.timer
    systemctl start aegis-feeds.timer
    log_ok "Systemd timer installed: aegis-feeds.timer (daily refresh)"
}

install_logrotate() {
    local config_file="/etc/logrotate.d/aegis"

    cat > "$config_file" << 'LOGRATEEOF'
/var/log/aegis/aegis.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 aegis aegis
    postrotate
        if command -v systemctl >/dev/null 2>&1; then
            systemctl try-restart 'aegis@*.service' >/dev/null 2>&1 || true
        fi
    endscript
}
LOGRATEEOF
    chmod 644 "$config_file"
    log_ok "Logrotate config installed: $config_file"
}

# =============================================================================
# OPENRC SERVICE
# =============================================================================

install_openrc_service() {
    cat > /etc/init.d/aegis << 'INITEOF'
#!/sbin/openrc-run
# Aegis eBPF Firewall

description="Aegis eBPF Firewall"

# Set interface via /etc/conf.d/aegis: AEGIS_INTERFACE=eth0
: ${AEGIS_INTERFACE:=eth0}

command="/usr/local/bin/aegis-cli"
command_args="-i ${AEGIS_INTERFACE} daemon"
directory="/etc/aegis"
export SUDO_UID SUDO_GID
command_background=true
pidfile="/run/aegis.pid"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --owner aegis:aegis --mode 0750 /var/log/aegis
}
INITEOF
    chmod +x /etc/init.d/aegis

    cat > /etc/conf.d/aegis << 'CONFEOF'
# Aegis configuration
# Interface to protect
AEGIS_INTERFACE=eth0
CONFEOF
    {
        printf 'SUDO_UID=%s\n' "$(id -u "$SERVICE_USER")"
        printf 'SUDO_GID=%s\n' "$(id -g "$SERVICE_USER")"
    } >> /etc/conf.d/aegis

    log_ok "OpenRC service installed"
}

# =============================================================================
# SYSVINIT SERVICE
# =============================================================================

install_sysvinit_service() {
    cat > /etc/init.d/aegis << 'INITEOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          aegis
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Aegis eBPF Firewall
### END INIT INFO

AEGIS_INTERFACE=${AEGIS_INTERFACE:-eth0}
DAEMON=/usr/local/bin/aegis-cli
PIDFILE=/run/aegis.pid

if [ -r /etc/aegis/service.env ]; then
    set -a
    # shellcheck disable=SC1091
    . /etc/aegis/service.env
    set +a
fi

cd /etc/aegis || exit 1

case "$1" in
    start)
        echo "Starting Aegis..."
        "$DAEMON" -i "$AEGIS_INTERFACE" daemon &
        echo $! > "$PIDFILE"
        ;;
    stop)
        echo "Stopping Aegis..."
        [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" && rm -f "$PIDFILE"
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac
INITEOF
    chmod +x /etc/init.d/aegis
    log_ok "SysVinit script installed"
}

# =============================================================================
# SERVICE MANAGEMENT
# =============================================================================

stop_running_services() {
    local init_system
    init_system=$(detect_init_system)

    case "$init_system" in
        systemd)
            local services
            services=$(systemctl list-units --full --all --no-legend "aegis@*" 2>/dev/null | awk '{print $1}') || true
            if [[ -n "$services" ]]; then
                log_info "Stopping active Aegis services..."
                for svc in $services; do
                    systemctl stop "$svc" 2>/dev/null || true
                done
            fi
            ;;
        openrc)
            rc-service aegis stop 2>/dev/null || true
            ;;
        sysvinit)
            /etc/init.d/aegis stop 2>/dev/null || true
            ;;
    esac
}

restart_services() {
    local init_system
    init_system=$(detect_init_system)

    case "$init_system" in
        systemd)
            local services
            services=$(systemctl list-units --full --all --no-legend "aegis@*" 2>/dev/null | awk '{print $1}') || true
            if [[ -n "$services" ]]; then
                log_info "Restarting Aegis services..."
                for svc in $services; do
                    systemctl start "$svc" 2>/dev/null || true
                done
            fi
            ;;
    esac
}

# =============================================================================
# INSTALLATION
# =============================================================================

show_banner() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  🛡️  AEGIS eBPF FIREWALL — RELEASE INSTALLER"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
}

install_prebuilt() {
    log_step "Installing pre-built binaries..."

    mkdir -p "$BIN_DIR" "$SHARE_DIR"

    local cli_bin=""
    local xdp_obj=""
    local tc_obj=""

    for path in \
        "$SCRIPT_DIR/aegis-cli" \
        "$SCRIPT_DIR/target/release/aegis-cli" \
        "./aegis-cli"
    do
        [[ -f "$path" ]] && cli_bin="$path" && break
    done

    for path in \
        "$SCRIPT_DIR/aegis.o" \
        "$SCRIPT_DIR/target/bpfel-unknown-none/release/aegis" \
        "./aegis.o"
    do
        [[ -f "$path" ]] && xdp_obj="$path" && break
    done

    for path in \
        "$SCRIPT_DIR/aegis-tc.o" \
        "$SCRIPT_DIR/target/bpfel-unknown-none/release/aegis-tc" \
        "./aegis-tc.o"
    do
        [[ -f "$path" ]] && tc_obj="$path" && break
    done

    if [[ -z "$cli_bin" ]]; then
        log_error "aegis-cli binary not found!"
        log_info "Build first: cargo run --locked -p xtask -- build-all && cargo build --locked --release -p aegis-cli"
        return 1
    fi

    if [[ -z "$xdp_obj" ]]; then
        log_error "XDP eBPF object not found!"
        log_info "Expected one of: $SCRIPT_DIR/aegis.o, $SCRIPT_DIR/target/bpfel-unknown-none/release/aegis, ./aegis.o"
        log_info "Build first: cargo run --locked -p xtask -- build-all --profile release"
        return 1
    fi

    if [[ -z "$tc_obj" ]]; then
        log_error "TC eBPF object not found; TC egress is required by default."
        log_info "Expected one of: $SCRIPT_DIR/aegis-tc.o, $SCRIPT_DIR/target/bpfel-unknown-none/release/aegis-tc, ./aegis-tc.o"
        log_info "Build first: cargo run --locked -p xtask -- build-all --profile release"
        return 1
    fi

    install -m 0755 "$cli_bin" "$BIN_DIR/aegis-cli.new"
    mv -f "$BIN_DIR/aegis-cli.new" "$BIN_DIR/aegis-cli"
    log_ok "Installed: $BIN_DIR/aegis-cli"

    install -m 0644 "$xdp_obj" "$SHARE_DIR/aegis.o.new"
    mv -f "$SHARE_DIR/aegis.o.new" "$SHARE_DIR/aegis.o"
    log_ok "Installed: $SHARE_DIR/aegis.o"

    install -m 0644 "$tc_obj" "$SHARE_DIR/aegis-tc.o.new"
    mv -f "$SHARE_DIR/aegis-tc.o.new" "$SHARE_DIR/aegis-tc.o"
    log_ok "Installed: $SHARE_DIR/aegis-tc.o"

    if [[ ! -x "$BIN_DIR/aegis-cli" \
          || ! -s "$SHARE_DIR/aegis.o" \
          || ! -s "$SHARE_DIR/aegis-tc.o" ]]; then
        log_error "Installed command/object path validation failed"
        return 1
    fi

    "$BIN_DIR/aegis-cli" --iface lo daemon --help >/dev/null
    "$BIN_DIR/aegis-cli" --iface lo --no-tc daemon --help >/dev/null
    log_ok "Installed CLI command syntax validated"
}

build_and_install() {
    log_step "Building from source..."

    # 1. Find/install Rust
    ensure_rust_installed

    # 2. Ensure nightly + bpf-linker
    ensure_rust_toolchain

    cd "$SCRIPT_DIR"

    # 3. Build eBPF programs (release profile — debug panics bpf-linker)
    log_info "Building eBPF programs (release)..."
    cargo run --locked -p xtask -- build-all --profile release

    # 4. Build CLI (eBPF bytecode gets embedded by build.rs)
    log_info "Building aegis-cli..."
    cargo build --locked --release -p aegis-cli

    # 5. Install the built binary
    install_prebuilt
}

cleanup_owned_pins() {
    local iface="$1"
    local pin_dir="/sys/fs/bpf/aegis/${iface}/abi-v1"
    local marker="/run/aegis/instances/${iface}/abi-v1/ownership.json"
    local cleanup_cli=""
    local cleanup_args=(--iface "$iface" cleanup-pins)

    if [[ ! -d "$pin_dir" && ! -e "$marker" ]]; then
        return 0
    fi

    for path in \
        "$SCRIPT_DIR/aegis-cli" \
        "$SCRIPT_DIR/target/release/aegis-cli" \
        "$BIN_DIR/aegis-cli"
    do
        if [[ -x "$path" ]]; then
            cleanup_cli="$path"
            break
        fi
    done

    if [[ -z "$cleanup_cli" ]]; then
        log_error "Cannot safely clean Aegis pins for interface $iface: compatible aegis-cli not found"
        log_info "Pins were preserved at $pin_dir"
        return 1
    fi

    if [[ ! -e "$marker" ]]; then
        cleanup_args+=(--force-orphaned)
    fi

    if ! "$cleanup_cli" "${cleanup_args[@]}"; then
        log_error "Bounded pin cleanup failed for interface $iface"
        log_info "Inspect before retrying: find '$pin_dir' -maxdepth 1 -ls"
        return 1
    fi
    log_ok "BPF maps cleaned for owned instance $iface"
}

cleanup_old_install() {
    local iface=""

    if [[ -r /etc/aegis/config.toml ]]; then
        iface="$(awk -F'"' '/^interface[[:space:]]*=/{print $2; exit}' /etc/aegis/config.toml)"
    fi
    iface="${iface:-eth0}"
    cleanup_owned_pins "$iface"
}

# =============================================================================
# POST-INSTALL: CONFIG, COMPLETIONS, GEOIP
# =============================================================================

install_default_config() {
    local config_dir="/etc/aegis"
    local system_config="$config_dir/config.toml"
    local rule_config="$config_dir/aegis.yaml"
    local config_group="root"

    if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        config_group="$SERVICE_GROUP"
    fi
    install -d -o root -g "$config_group" -m 0750 "$config_dir"

    if [[ -f "$system_config" ]]; then
        log_ok "Config exists: $system_config (preserved)"
    else
        cat > "$system_config" << 'CONFIGEOF'
# Aegis eBPF Firewall Configuration
# https://github.com/m4rba4s/Aegis-eBPF

interface = "eth0"

[modules]
port_scan = true
rate_limit = true
threat_feeds = true
conn_track = true
scan_detect = true
verbose = false
entropy = false     # WARNING: blocks TLS/SSH when enabled

[autoban]
enabled = true
max_entries = 512

[feeds]
enabled = true
max_download_bytes = 10485760

[logging]
level = "info"
json = false

[allowlist]
ips = []

[webhooks]
enabled = false
slack_url = ""
pagerduty_key = ""
generic_url = ""
min_severity = "high"

[dpi]
enabled = false
auto_block_threshold = 80
rules_path = "/etc/aegis/rules"

[fleet]
enabled = false
endpoint = "http://127.0.0.1:50051"
token = ""

[pcap]
enabled = false
CONFIGEOF
        log_ok "Default config: $system_config"
    fi

    if [[ -f "$rule_config" ]]; then
        log_ok "Config exists: $rule_config (preserved)"
    else
        cat > "$rule_config" << 'RULESEOF'
# Aegis rule configuration.
rules: []
egress_rules: []
egress_cidrs: []
blocked_countries: []
RULESEOF
        log_ok "Default config: $rule_config"
    fi

    chown root:"$config_group" "$system_config" "$rule_config"
    chmod 0640 "$system_config" "$rule_config"
}

install_completions() {
    local bin="$BIN_DIR/aegis-cli"
    [[ ! -x "$bin" ]] && return 0

    # Bash
    if [[ -d /etc/bash_completion.d ]]; then
        "$bin" completions bash > /etc/bash_completion.d/aegis-cli 2>/dev/null && \
            log_ok "Bash completions installed"
    fi

    # Zsh
    if [[ -d /usr/share/zsh/site-functions ]]; then
        "$bin" completions zsh > /usr/share/zsh/site-functions/_aegis-cli 2>/dev/null && \
            log_ok "Zsh completions installed"
    fi

    # Fish
    if [[ -d /usr/share/fish/vendor_completions.d ]]; then
        "$bin" completions fish > /usr/share/fish/vendor_completions.d/aegis-cli.fish 2>/dev/null && \
            log_ok "Fish completions installed"
    fi
}

install_geoip_db() {
    local db_dir="/var/lib/aegis"
    local db_file="$db_dir/GeoLite2-City.mmdb"

    mkdir -p "$db_dir"

    if [[ -f "$db_file" ]]; then
        log_ok "GeoIP database exists: $db_file"
        return 0
    fi

    log_info "Downloading GeoIP database..."
    local url="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"

    # Try curl first (more universal), fall back to wget
    if command -v curl &>/dev/null; then
        if curl -fsSL --connect-timeout 15 --max-time 120 "$url" -o "$db_file" 2>/dev/null; then
            log_ok "GeoIP database installed"
            return 0
        fi
    fi

    if command -v wget &>/dev/null; then
        if wget -q --timeout=15 "$url" -O "$db_file" 2>/dev/null; then
            log_ok "GeoIP database installed"
            return 0
        fi
    fi

    log_warn "Failed to download GeoIP database (non-fatal)"
    log_warn "Place GeoLite2-City.mmdb in $db_dir manually"
    rm -f "$db_file"  # clean partial download
}

# =============================================================================
# CHECK MODE (dry-run prerequisite validation)
# =============================================================================

run_checks() {
    show_banner
    echo "  Running prerequisite checks..."
    echo ""

    local errors=0

    # Kernel
    check_kernel_version || ((++errors))

    # BPF filesystem
    check_bpf_fs true || ((++errors))

    # Runtime tools
    check_runtime_tools || ((++errors))

    # System tools
    local tools=("gcc" "clang" "llvm-config" "curl" "git")
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "$tool: $(command -v "$tool")"
        else
            log_error "$tool: NOT FOUND"
            ((++errors))
        fi
    done

    # Rust
    if find_cargo; then
        local cargo_version
        if cargo_version=$(cargo --version 2>/dev/null); then
            log_ok "cargo: $cargo_version"
        else
            log_error "cargo exists but cannot execute successfully"
            ((++errors))
        fi

        if find_rustup; then
            local rustup_version
            if rustup_version=$(rustup --version 2>/dev/null); then
                log_ok "rustup: ${rustup_version%%$'\n'*}"
            else
                log_error "rustup exists but cannot execute successfully"
                ((++errors))
            fi
        else
            log_warn "rustup: NOT installed (will be auto-installed)"
        fi

        # Nightly
        if rustup toolchain list 2>/dev/null | grep -q nightly; then
            log_ok "nightly toolchain: installed"
        else
            log_warn "nightly toolchain: NOT installed (will be auto-installed)"
        fi

        # bpf-linker
        if command -v bpf-linker &>/dev/null; then
            log_ok "bpf-linker: installed"
        else
            log_warn "bpf-linker: NOT installed (will be auto-installed)"
        fi
    else
        log_error "cargo: NOT FOUND"
        log_info "Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        ((++errors))
    fi

    echo ""
    if [[ $errors -eq 0 ]]; then
        echo "═══════════════════════════════════════════════════════════"
        echo "  ✅ ALL CHECKS PASSED — ready to install"
        echo "═══════════════════════════════════════════════════════════"
    else
        echo "═══════════════════════════════════════════════════════════"
        echo "  ❌ $errors CHECK(S) FAILED — fix issues above first"
        echo "═══════════════════════════════════════════════════════════"
    fi
    return $errors
}

# =============================================================================
# UNINSTALL
# =============================================================================

uninstall_aegis() {
    show_banner
    log_info "Uninstalling Aegis..."

    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi

    stop_running_services

    local iface=""
    if [[ -r /etc/aegis/config.toml ]]; then
        iface="$(awk -F'"' '/^interface[[:space:]]*=/{print $2; exit}' /etc/aegis/config.toml)"
    fi
    iface="${iface:-eth0}"
    cleanup_owned_pins "$iface"

    local init_system
    init_system=$(detect_init_system)
    case "$init_system" in
        systemd)
            local unit
            while IFS= read -r unit; do
                [[ -n "$unit" ]] && systemctl disable "$unit" 2>/dev/null || true
            done < <(systemctl list-unit-files --no-legend "aegis@*.service" 2>/dev/null | awk '{print $1}')
            systemctl disable --now aegis-feeds.timer 2>/dev/null || true
            rm -f /etc/systemd/system/aegis@.service
            rm -f /etc/systemd/system/aegis-feeds.service
            rm -f /etc/systemd/system/aegis-feeds.timer
            systemctl daemon-reload 2>/dev/null || true
            log_ok "Systemd service removed"
            ;;
        openrc)
            rc-update del aegis 2>/dev/null || true
            rm -f /etc/init.d/aegis /etc/conf.d/aegis
            log_ok "OpenRC service removed"
            ;;
        sysvinit)
            update-rc.d aegis remove 2>/dev/null || true
            rm -f /etc/init.d/aegis
            log_ok "SysVinit service removed"
            ;;
    esac

    rm -f "$BIN_DIR/aegis-cli"
    log_ok "Binary removed"

    rm -rf "$SHARE_DIR"
    log_ok "Shared data removed"

    rm -f /etc/bash_completion.d/aegis-cli 2>/dev/null
    rm -f /usr/share/zsh/site-functions/_aegis-cli 2>/dev/null
    rm -f /usr/share/fish/vendor_completions.d/aegis-cli.fish 2>/dev/null
    rm -f /etc/logrotate.d/aegis 2>/dev/null
    rm -f /etc/periodic/weekly/aegis-logclean 2>/dev/null

    if [[ -d /etc/aegis ]]; then
        if [[ -t 0 ]]; then
            echo ""
            read -rp "  Remove config (/etc/aegis)? [y/N] " ans
            [[ "$ans" =~ ^[Yy]$ ]] && rm -rf /etc/aegis && log_ok "Config removed"
        else
            log_info "Non-interactive: preserving /etc/aegis (use rm -rf /etc/aegis to remove)"
        fi
    fi

    if [[ -d /var/log/aegis ]]; then
        if [[ -t 0 ]]; then
            read -rp "  Remove logs (/var/log/aegis)? [y/N] " ans
            [[ "$ans" =~ ^[Yy]$ ]] && rm -rf /var/log/aegis && log_ok "Logs removed"
        else
            log_info "Non-interactive: preserving /var/log/aegis"
        fi
    fi

    if [[ -d /var/lib/aegis ]]; then
        if [[ -t 0 ]]; then
            read -rp "  Remove GeoIP data (/var/lib/aegis)? [y/N] " ans
            [[ "$ans" =~ ^[Yy]$ ]] && rm -rf /var/lib/aegis && log_ok "GeoIP data removed"
        else
            log_info "Non-interactive: preserving /var/lib/aegis"
        fi
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✅ AEGIS UNINSTALLED"
    echo "═══════════════════════════════════════════════════════════"
}

# =============================================================================
# UPDATE (in-place upgrade, preserves config)
# =============================================================================

update_aegis() {
    show_banner

    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi

    # Get current version
    local old_version="unknown"
    if command -v aegis-cli &>/dev/null; then
        old_version=$(aegis-cli --version 2>/dev/null | head -1 || echo "unknown")
    fi
    log_info "Current version: $old_version"

    # Pull latest source
    cd "$SCRIPT_DIR"
    if [[ -d ".git" ]]; then
        log_step "Pulling latest changes..."
        local before_hash after_hash
        before_hash=$(git rev-parse HEAD 2>/dev/null || echo "none")

        if ! git pull --ff-only 2>/dev/null; then
            log_warn "Fast-forward pull failed, trying rebase..."
            git pull --rebase || {
                log_error "Git pull failed. Resolve conflicts manually."
                exit 1
            }
        fi

        after_hash=$(git rev-parse HEAD 2>/dev/null || echo "none")
        if [[ "$before_hash" == "$after_hash" ]]; then
            log_info "Already up-to-date ($before_hash)"
            if [[ ! -t 0 ]]; then
                log_ok "Nothing to do."
                exit 0
            fi
            read -rp "  Force rebuild anyway? [y/N] " ans
            if [[ ! "$ans" =~ ^[Yy]$ ]]; then
                log_ok "Nothing to do."
                exit 0
            fi
        else
            log_ok "Updated: ${before_hash:0:8} → ${after_hash:0:8}"
            git log --oneline "${before_hash}..${after_hash}" 2>/dev/null | head -10
        fi
    else
        log_warn "Not a git repo — downloading latest tarball..."
        local tmpdir
        tmpdir=$(mktemp -d /tmp/aegis-update.XXXXXX)
        if curl -fsSL "$AEGIS_TARBALL_URL" | tar -xz -C "$tmpdir" --strip-components=1; then
            # Copy new source files over (preserve local config)
            if command -v rsync >/dev/null 2>&1; then
                rsync -a --exclude='.git' --exclude='target' "$tmpdir/" "$SCRIPT_DIR/"
            else
                tar -C "$tmpdir" --exclude='.git' --exclude='target' -cf - . |
                    tar -C "$SCRIPT_DIR" -xf -
            fi
            rm -rf "$tmpdir"
            log_ok "Source updated from tarball"
        else
            rm -rf "$tmpdir"
            log_error "Failed to download update"
            exit 1
        fi
    fi

    # Validate kernel
    check_kernel_version
    check_bpf_fs

    # Stop running instances
    stop_running_services
    # Also kill any manual aegis-cli processes (graceful first, then force)
    if command -v killall &>/dev/null && killall -0 aegis-cli 2>/dev/null; then
        killall aegis-cli 2>/dev/null || true
        sleep 3
        killall -9 aegis-cli 2>/dev/null || true
    fi
    sleep 1

    # Clean stale BPF pins (map definitions may have changed)
    cleanup_old_install

    # Rebuild
    build_and_install

    # Restart services
    restart_services

    # Show result
    local new_version="unknown"
    if command -v aegis-cli &>/dev/null; then
        new_version=$(aegis-cli --version 2>/dev/null | head -1 || echo "unknown")
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✅ AEGIS UPDATED"
    echo "  Old: $old_version"
    echo "  New: $new_version"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "  Config preserved: /etc/aegis/config.toml"
    echo "  GeoIP preserved:  /var/lib/aegis/"
    echo ""
    echo "  Restart manually if needed:"
    echo "    sudo systemctl restart aegis@eth0"
    echo "    sudo aegis-cli -i eth0 tui"
    echo ""
}

# =============================================================================
# USAGE BANNER
# =============================================================================

show_usage() {
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✅ INSTALLATION COMPLETE"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    echo "  Quick Start:"
    echo "    sudo aegis-cli -i eth0 tui     # Interactive TUI"
    echo "    sudo aegis-cli -i wg0 daemon   # Background daemon"
    echo ""
    echo "  Service Management ($(detect_init_system)):"

    case "$(detect_init_system)" in
        systemd)
            echo "    sudo systemctl enable aegis@eth0"
            echo "    sudo systemctl start aegis@eth0"
            ;;
        openrc)
            echo "    sudo rc-update add aegis default"
            echo "    sudo rc-service aegis start"
            ;;
        sysvinit)
            echo "    sudo update-rc.d aegis defaults"
            echo "    sudo /etc/init.d/aegis start"
            ;;
    esac
    echo ""
}

# =============================================================================
# ENTRY POINT
# =============================================================================

main() {
    local install_only=false
    local skip_service=false
    local check_only=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-only) install_only=true; shift ;;
            --skip-service) skip_service=true; shift ;;
            --check)        check_only=true; shift ;;
            --uninstall)    uninstall_aegis; exit 0 ;;
            --update)       update_aegis; exit 0 ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  (no args)        Full build from source + install"
                echo "  --update         Update from the tracked source tree (preserves config)"
                echo "  --check          Dry-run: validate prerequisites"
                echo "  --install-only   Install pre-built binaries only"
                echo "  --skip-service   Don't install init service"
                echo "  --uninstall      Remove Aegis completely"
                echo "  --help           Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                log_info "Run '$0 --help' for supported options"
                exit 2
                ;;
        esac
    done

    if $check_only; then
        run_checks
        exit $?
    fi

    show_banner

    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        log_info "Usage: sudo $0"
        exit 1
    fi

    # Detect environment
    local distro init_system
    distro=$(detect_distro)
    init_system=$(detect_init_system)

    log_info "Distro: $distro | Init: $init_system | Kernel: $(uname -r)"

    # Validate kernel + BPF
    check_kernel_version
    check_bpf_fs

    if $install_only; then
        install_runtime_deps
    else
        # Install build dependencies before Rust and eBPF compilation.
        install_system_deps
        check_runtime_tools
    fi

    if ! $skip_service; then
        stop_running_services
        cleanup_old_install
        ensure_service_account
    else
        log_info "Leaving existing services and BPF pins untouched (--skip-service)"
    fi

    # Build or install
    if $install_only; then
        install_prebuilt
    else
        build_and_install
    fi

    # Post-install
    install_default_config
    install_completions
    install_geoip_db
    if ! $skip_service && [[ "$init_system" == "systemd" ]]; then
        install_systemd_timer
    elif $skip_service; then
        log_info "Skipping feed timer because --skip-service was requested"
    else
        log_info "Skipping systemd feed timer for init system: $init_system"
    fi
    install_logrotate

    # Init service
    if ! $skip_service; then
        case "$init_system" in
            systemd)  install_systemd_service ;;
            openrc)   install_openrc_service ;;
            sysvinit) install_sysvinit_service ;;
            *)        log_warn "Unknown init system, skipping service" ;;
        esac
    fi

    if ! $skip_service; then
        restart_services
    fi
    show_usage
}

if [[ "${AEGIS_INSTALLER_SOURCE_ONLY:-false}" != "true" ]]; then
    main "$@"
fi
