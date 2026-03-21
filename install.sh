#!/bin/bash
# Aegis XDP Firewall - Universal Installer
# Supports: Ubuntu, Debian, Fedora, CentOS, RHEL, Arch, Alpine, OpenSUSE
# Init systems: systemd, openrc, sysvinit
#
# Usage:
#   sudo ./install.sh              # Full build + install
#   sudo ./install.sh --check      # Dry-run: validate all prerequisites
#   sudo ./install.sh --install-only  # Install pre-built binaries only
#   sudo ./install.sh --uninstall  # Remove Aegis completely

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local"
BIN_DIR="$INSTALL_DIR/bin"
SHARE_DIR="$INSTALL_DIR/share/aegis"

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
    if command -v systemctl &>/dev/null && systemctl is-system-running &>/dev/null 2>&1; then
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
    if [[ ! -d /sys/fs/bpf ]]; then
        log_warn "BPF filesystem not mounted at /sys/fs/bpf"
        log_info "Attempting to mount..."
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null || {
            log_error "Failed to mount BPF filesystem"
            log_info "Try manually: mount -t bpf bpf /sys/fs/bpf"
            return 1
        }
    fi
    log_ok "BPF filesystem available"
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
            dnf install -y \
                gcc make pkg-config \
                llvm clang llvm-devel \
                elfutils-libelf-devel \
                curl wget git \
                2>/dev/null || \
            yum install -y \
                gcc make pkgconfig \
                llvm clang llvm-devel \
                elfutils-libelf-devel \
                curl wget git \
                2>/dev/null || true
            ;;
        ubuntu|debian|pop|linuxmint)
            apt-get update -qq
            apt-get install -y \
                build-essential pkg-config \
                llvm clang libelf-dev \
                curl wget git \
                2>/dev/null || true
            ;;
        arch|manjaro|endeavouros)
            pacman -Sy --noconfirm --needed \
                base-devel llvm clang libelf \
                curl wget git \
                2>/dev/null || true
            ;;
        opensuse*|sles)
            zypper install -y \
                gcc make pkg-config \
                llvm clang libelf-devel \
                curl wget git \
                2>/dev/null || true
            ;;
        alpine)
            apk add \
                build-base musl-dev linux-headers \
                llvm clang libelf-dev \
                curl wget git \
                2>/dev/null || true
            ;;
        *)
            log_warn "Unknown distro '$distro' — install manually: gcc, llvm, clang, libelf-dev, curl, git"
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

# =============================================================================
# RUST TOOLCHAIN DETECTION & SETUP
# =============================================================================

find_cargo() {
    # Already in PATH?
    if command -v cargo &>/dev/null; then
        return 0
    fi

    # Build a list of candidate directories
    local candidates=()

    # 1. SUDO_USER's home (most common case: user installed rustup, runs sudo)
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_home
        sudo_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6) || true
        [[ -n "$sudo_home" ]] && candidates+=("$sudo_home/.cargo/bin")
    fi

    # 2. Current $HOME
    [[ -d "$HOME/.cargo/bin" ]] && candidates+=("$HOME/.cargo/bin")

    # 3. Scan /home/*
    for d in /home/*/.cargo/bin; do
        [[ -d "$d" ]] && candidates+=("$d")
    done

    # 4. Root's cargo
    [[ -d /root/.cargo/bin ]] && candidates+=("/root/.cargo/bin")

    # Try each candidate
    for cbd in "${candidates[@]}"; do
        if [[ -x "$cbd/cargo" ]]; then
            log_info "Found cargo in: $cbd"
            export PATH="$cbd:$PATH"

            # Also set RUSTUP_HOME + CARGO_HOME so rustup works correctly
            local home_dir
            home_dir="${cbd%/.cargo/bin}"
            if [[ -d "$home_dir/.rustup" ]]; then
                export RUSTUP_HOME="$home_dir/.rustup"
                export CARGO_HOME="$home_dir/.cargo"
            fi
            return 0
        fi
    done

    return 1
}

ensure_rust_installed() {
    if ! find_cargo; then
        log_info "Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        # Source the new environment
        if [[ -n "${SUDO_USER:-}" ]]; then
            local sudo_home
            sudo_home=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6) || true
            [[ -f "$sudo_home/.cargo/env" ]] && source "$sudo_home/.cargo/env"
        fi
        [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

        if ! find_cargo; then
            log_error "Rust installation succeeded but cargo still not found"
            log_info "Try: source ~/.cargo/env && sudo env PATH=\$PATH ./install.sh"
            return 1
        fi
    fi
    log_ok "cargo: $(cargo --version)"
}

ensure_rust_toolchain() {
    log_step "Setting up Rust toolchain for eBPF..."

    # Nightly toolchain
    if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
        log_info "Installing nightly toolchain..."
        rustup toolchain install nightly || {
            log_error "Failed to install nightly toolchain"
            return 1
        }
    fi

    # rust-src component (required for -Zbuild-std=core)
    if ! rustup component list --toolchain nightly 2>/dev/null | grep -q 'rust-src (installed)'; then
        log_info "Installing rust-src for nightly..."
        rustup component add rust-src --toolchain nightly || {
            log_error "Failed to install rust-src"
            return 1
        }
    fi

    # bpf-linker
    if ! command -v bpf-linker &>/dev/null; then
        log_info "Installing bpf-linker (this may take several minutes)..."
        cargo install bpf-linker || {
            log_error "Failed to install bpf-linker"
            log_info "Common fix: ensure llvm and clang are installed"
            log_info "Manual: cargo +nightly install bpf-linker"
            return 1
        }
    fi

    log_ok "Nightly + rust-src + bpf-linker ready"
}

# =============================================================================
# SYSTEMD SERVICE
# =============================================================================

install_systemd_service() {
    cat > /etc/systemd/system/aegis@.service << 'EOF'
[Unit]
Description=Aegis eBPF Firewall on %i
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-cli -i %i daemon
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity

# Logging
StandardOutput=append:/var/log/aegis/aegis.log
StandardError=append:/var/log/aegis/aegis.log

# Security hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=false
ReadWritePaths=/var/log/aegis /var/lib/aegis /sys/fs/bpf

# Capability restrictions
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_PERFMON
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF CAP_PERFMON

# Additional hardening
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
ProtectClock=true
ProtectKernelLogs=true

[Install]
WantedBy=multi-user.target
EOF
    mkdir -p /var/log/aegis
    chmod 755 /var/log/aegis

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
    create 0640 root root
    postrotate
        systemctl try-restart aegis@*.service >/dev/null 2>&1 || true
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
command_background=true
pidfile="/run/aegis.pid"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --owner root:root --mode 0755 /var/log/aegis
}
INITEOF
    chmod +x /etc/init.d/aegis

    cat > /etc/conf.d/aegis << 'CONFEOF'
# Aegis configuration
# Interface to protect
AEGIS_INTERFACE=eth0
CONFEOF

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

case "$1" in
    start)
        echo "Starting Aegis..."
        $DAEMON -i $AEGIS_INTERFACE daemon &
        echo $! > $PIDFILE
        ;;
    stop)
        echo "Stopping Aegis..."
        [ -f $PIDFILE ] && kill $(cat $PIDFILE) && rm -f $PIDFILE
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
    echo "  🛡️  AEGIS eBPF FIREWALL — UNIVERSAL INSTALLER"
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
        log_info "Build first: cargo run -p xtask -- build-all && cargo build --release -p aegis-cli"
        return 1
    fi

    cp "$cli_bin" "$BIN_DIR/aegis-cli"
    chmod +x "$BIN_DIR/aegis-cli"
    log_ok "Installed: $BIN_DIR/aegis-cli"

    if [[ -n "$xdp_obj" ]]; then
        cp "$xdp_obj" "$SHARE_DIR/aegis.o"
        log_ok "Installed: $SHARE_DIR/aegis.o"
    fi

    if [[ -n "$tc_obj" ]]; then
        cp "$tc_obj" "$SHARE_DIR/aegis-tc.o"
        log_ok "Installed: $SHARE_DIR/aegis-tc.o"
    fi
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
    cargo run -p xtask -- build-all --profile release

    # 4. Build CLI (eBPF bytecode gets embedded by build.rs)
    log_info "Building aegis-cli..."
    cargo build --release -p aegis-cli

    # 5. Install the built binary
    install_prebuilt
}

cleanup_old_install() {
    if [[ -d "/sys/fs/bpf/aegis" ]]; then
        log_info "Cleaning up pinned BPF maps..."
        rm -rf /sys/fs/bpf/aegis
    fi
}

# =============================================================================
# POST-INSTALL: CONFIG, COMPLETIONS, GEOIP
# =============================================================================

install_default_config() {
    local config_dir="/etc/aegis"
    local config_file="$config_dir/config.toml"

    mkdir -p "$config_dir"

    if [[ -f "$config_file" ]]; then
        log_ok "Config exists: $config_file (preserved)"
        return 0
    fi

    cat > "$config_file" << 'CONFIGEOF'
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
CONFIGEOF

    chmod 0640 "$config_file"
    log_ok "Default config: $config_file"
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
    check_kernel_version || ((errors++))

    # BPF filesystem
    check_bpf_fs || ((errors++))

    # System tools
    local tools=("gcc" "clang" "llvm-config" "curl" "git")
    for tool in "${tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "$tool: $(command -v "$tool")"
        else
            log_error "$tool: NOT FOUND"
            ((errors++))
        fi
    done

    # Rust
    if find_cargo; then
        log_ok "cargo: $(cargo --version)"

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
        ((errors++))
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

    local init_system
    init_system=$(detect_init_system)
    case "$init_system" in
        systemd)
            systemctl disable "aegis@*" 2>/dev/null || true
            rm -f /etc/systemd/system/aegis@.service
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

    if [[ -d /sys/fs/bpf/aegis ]]; then
        rm -rf /sys/fs/bpf/aegis
        log_ok "BPF maps cleaned"
    fi

    rm -f /etc/bash_completion.d/aegis-cli 2>/dev/null
    rm -f /usr/share/zsh/site-functions/_aegis-cli 2>/dev/null
    rm -f /usr/share/fish/vendor_completions.d/aegis-cli.fish 2>/dev/null
    rm -f /etc/logrotate.d/aegis 2>/dev/null
    rm -f /etc/systemd/system/aegis-feeds.service 2>/dev/null
    rm -f /etc/systemd/system/aegis-feeds.timer 2>/dev/null
    rm -f /etc/periodic/weekly/aegis-logclean 2>/dev/null

    if [[ -d /etc/aegis ]]; then
        echo ""
        read -rp "  Remove config (/etc/aegis)? [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] && rm -rf /etc/aegis && log_ok "Config removed"
    fi

    if [[ -d /var/log/aegis ]]; then
        read -rp "  Remove logs (/var/log/aegis)? [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] && rm -rf /var/log/aegis && log_ok "Logs removed"
    fi

    if [[ -d /var/lib/aegis ]]; then
        read -rp "  Remove GeoIP data (/var/lib/aegis)? [y/N] " ans
        [[ "$ans" =~ ^[Yy]$ ]] && rm -rf /var/lib/aegis && log_ok "GeoIP data removed"
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "  ✅ AEGIS UNINSTALLED"
    echo "═══════════════════════════════════════════════════════════"
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
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  (no args)        Full build from source + install"
                echo "  --check          Dry-run: validate prerequisites"
                echo "  --install-only   Install pre-built binaries only"
                echo "  --skip-service   Don't install init service"
                echo "  --uninstall      Remove Aegis completely"
                echo "  --help           Show this help"
                exit 0
                ;;
            *) shift ;;
        esac
    done

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

    # Check-only mode
    if $check_only; then
        run_checks
        exit $?
    fi

    # Validate kernel + BPF
    check_kernel_version
    check_bpf_fs

    # Install system deps FIRST (gcc, clang, llvm, curl, etc.)
    install_system_deps

    # Stop running services
    stop_running_services
    cleanup_old_install

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
    install_systemd_timer
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

    restart_services
    show_usage
}

main "$@"
