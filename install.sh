    #!/bin/bash
# Aegis XDP Firewall - Universal Installer
# Supports: Ubuntu, Debian, Fedora, CentOS, RHEL, Arch, Alpine, OpenSUSE
# Init systems: systemd, openrc, sysvinit

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local"
BIN_DIR="$INSTALL_DIR/bin"
SHARE_DIR="$INSTALL_DIR/share/aegis"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info()  { echo -e "${CYAN}ℹ️  $1${NC}"; }
log_ok()    { echo -e "${GREEN}✅ $1${NC}"; }
log_warn()  { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

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
    local ver=$(uname -r | cut -d. -f1-2)
    local major=$(echo "$ver" | cut -d. -f1)
    local minor=$(echo "$ver" | cut -d. -f2)

    if [[ "$major" -lt 5 ]] || { [[ "$major" -eq 5 ]] && [[ "$minor" -lt 4 ]]; }; then
        log_error "Kernel $ver is too old. Aegis requires >= 5.4"
        exit 1
    fi
    log_ok "Kernel version: $(uname -r)"
}

check_bpf_fs() {
    if [[ ! -d /sys/fs/bpf ]]; then
        log_error "BPF filesystem not mounted at /sys/fs/bpf"
        log_info "Try: mount -t bpf bpf /sys/fs/bpf"
        exit 1
    fi
    log_ok "BPF filesystem available"
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

# Capability restrictions (BPF requires SYS_ADMIN + NET_ADMIN + BPF + PERFMON)
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
    # Ensure log directory exists
    mkdir -p /var/log/aegis
    chmod 755 /var/log/aegis

    systemctl daemon-reload
    log_ok "Systemd service installed: aegis@<interface>.service"
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

    # Config file
    cat > /etc/conf.d/aegis << 'CONFEOF'
# Aegis configuration
# Interface to protect
AEGIS_INTERFACE=eth0
CONFEOF

    log_ok "OpenRC service installed: /etc/init.d/aegis"
    log_info "Configure interface in /etc/conf.d/aegis"
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
    log_ok "SysVinit script installed: /etc/init.d/aegis"
}

# =============================================================================
# MANAGE RUNNING SERVICES
# =============================================================================

stop_running_services() {
    local init_system=$(detect_init_system)

    case "$init_system" in
        systemd)
            local services=$(systemctl list-units --full --all --no-legend "aegis@*" 2>/dev/null | awk '{print $1}')
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
    local init_system=$(detect_init_system)

    case "$init_system" in
        systemd)
            local services=$(systemctl list-units --full --all --no-legend "aegis@*" 2>/dev/null | awk '{print $1}')
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
# MAIN INSTALLATION
# =============================================================================

show_banner() {
    echo "═══════════════════════════════════════════════════════════"
    echo "  🛡️  AEGIS eBPF FIREWALL - UNIVERSAL INSTALLER"
    echo "═══════════════════════════════════════════════════════════"
}

install_prebuilt() {
    log_info "Installing pre-built binaries..."

    mkdir -p "$BIN_DIR" "$SHARE_DIR"

    # Check for pre-built binaries
    local cli_bin=""
    local xdp_obj=""
    local tc_obj=""

    # Check local paths (from Docker or manual build)
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
        log_info "Build first: cargo build --release -p aegis-cli"
        exit 1
    fi

    cp "$cli_bin" "$BIN_DIR/aegis-cli"
    chmod +x "$BIN_DIR/aegis-cli"
    log_ok "Installed: $BIN_DIR/aegis-cli"

    # XDP/TC objects are optional (embedded in binary)
    if [[ -n "$xdp_obj" ]]; then
        cp "$xdp_obj" "$SHARE_DIR/aegis.o"
        log_ok "Installed: $SHARE_DIR/aegis.o"
    fi

    if [[ -n "$tc_obj" ]]; then
        cp "$tc_obj" "$SHARE_DIR/aegis-tc.o"
        log_ok "Installed: $SHARE_DIR/aegis-tc.o"
    fi
}

ensure_build_deps() {
    # bpf-linker needs LLVM/clang to compile
    if command -v clang &>/dev/null && command -v llvm-config &>/dev/null; then
        return 0
    fi

    log_info "Installing LLVM/clang (needed for bpf-linker)..."
    local distro=$(detect_distro)
    case "$distro" in
        fedora|rhel|centos|rocky|alma)
            dnf install -y llvm clang llvm-devel elfutils-libelf-devel 2>/dev/null || \
            yum install -y llvm clang llvm-devel elfutils-libelf-devel 2>/dev/null || true
            ;;
        ubuntu|debian|pop|linuxmint)
            apt-get update -qq && apt-get install -y llvm clang libelf-dev build-essential pkg-config 2>/dev/null || true
            ;;
        arch|manjaro|endeavouros)
            pacman -S --noconfirm --needed llvm clang libelf 2>/dev/null || true
            ;;
        opensuse*|sles)
            zypper install -y llvm clang libelf-devel 2>/dev/null || true
            ;;
        alpine)
            apk add llvm clang libelf-dev linux-headers musl-dev build-base 2>/dev/null || true
            ;;
        *)
            log_warn "Unknown distro '$distro' — please install llvm and clang manually"
            ;;
    esac
}

ensure_rust_toolchain() {
    # eBPF build uses: cargo +nightly -Zbuild-std=core
    # This requires: nightly toolchain + rust-src component + bpf-linker
    if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
        log_info "Installing nightly toolchain..."
        rustup toolchain install nightly || {
            log_error "Failed to install nightly toolchain"
            exit 1
        }
    fi

    if ! rustup component list --toolchain nightly 2>/dev/null | grep -q 'rust-src (installed)'; then
        log_info "Installing rust-src for nightly..."
        rustup component add rust-src --toolchain nightly || {
            log_error "Failed to install rust-src"
            exit 1
        }
    fi

    if ! command -v bpf-linker &>/dev/null; then
        log_info "Installing bpf-linker (eBPF linker)..."
        ensure_build_deps
        cargo +nightly install bpf-linker || {
            log_error "Failed to install bpf-linker"
            log_info "Try manually: cargo +nightly install bpf-linker"
            exit 1
        }
    fi

    log_ok "Nightly toolchain + rust-src + bpf-linker ready"
}

build_and_install() {
    log_info "Building from source..."

    # Find cargo — check multiple locations and explicitly add to PATH
    # (sourcing .cargo/env alone is insufficient under sudo with secure_path)
    local cargo_bin_dirs=(
        "$HOME/.cargo/bin"
    )
    if [[ -n "$SUDO_USER" ]]; then
        local _sudo_home
        _sudo_home=$(getent passwd "$SUDO_USER" | cut -d: -f6 2>/dev/null)
        [[ -n "$_sudo_home" ]] && cargo_bin_dirs+=("$_sudo_home/.cargo/bin")
    fi
    # Scan all home directories as last resort
    for d in /home/*/.cargo/bin; do
        [[ -d "$d" ]] && cargo_bin_dirs+=("$d")
    done

    for cbd in "${cargo_bin_dirs[@]}"; do
        if [[ -x "$cbd/cargo" ]]; then
            log_info "Found cargo in: $cbd"
            export PATH="$cbd:$PATH"
            # Also set RUSTUP_HOME so rustup finds the correct toolchain
            local rustup_dir="${cbd%/.cargo/bin}/.rustup"
            if [[ -d "$rustup_dir" ]]; then
                export RUSTUP_HOME="$rustup_dir"
                log_info "Using RUSTUP_HOME: $rustup_dir"
            fi
            break
        fi
    done

    if ! command -v cargo &>/dev/null; then
        log_error "cargo not found!"
        log_info "Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        log_info "Or use --install-only with pre-built binaries"
        exit 1
    fi

    cd "$SCRIPT_DIR"

    # Ensure nightly toolchain + rust-src (required for -Zbuild-std=core)
    ensure_rust_toolchain

    # Build eBPF programs
    log_info "Building eBPF programs..."
    cargo run -p xtask -- build-all --profile release

    # Build CLI
    log_info "Building CLI..."
    cargo build --release -p aegis-cli

    # Now install
    install_prebuilt
}

cleanup_old_install() {
    # Clean BPF maps
    if [[ -d "/sys/fs/bpf/aegis" ]]; then
        log_info "Cleaning up pinned BPF maps..."
        rm -rf /sys/fs/bpf/aegis
    fi
}

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
# CONFIG & COMPLETIONS
# =============================================================================

install_default_config() {
    local config_dir="/etc/aegis"
    local config_file="$config_dir/config.toml"

    mkdir -p "$config_dir"

    if [[ -f "$config_file" ]]; then
        log_ok "Config exists: $config_file"
        return 0
    fi

    cat > "$config_file" << 'CONFIGEOF'
# Aegis eBPF Firewall Configuration
# https://github.com/m4rba4s/Aegis-Portable-Demo

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
    log_ok "Default config created: $config_file"
}

install_completions() {
    local bin="$BIN_DIR/aegis-cli"

    if [[ ! -x "$bin" ]]; then
        return 0
    fi

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
    # Try to download from repo (demo DB)
    if wget -q --show-progress "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" -O "$db_file"; then
        log_ok "GeoIP database installed"
    else
        log_warn "Failed to download GeoIP database."
        log_warn "Please manually place GeoLite2-City.mmdb in $db_dir"
    fi
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

    # Stop services
    stop_running_services

    # Remove service files
    local init_system=$(detect_init_system)
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

    # Remove binary
    rm -f "$BIN_DIR/aegis-cli"
    log_ok "Binary removed"

    # Remove shared data
    rm -rf "$SHARE_DIR"
    log_ok "Shared data removed"

    # Clean BPF maps
    if [[ -d /sys/fs/bpf/aegis ]]; then
        rm -rf /sys/fs/bpf/aegis
        log_ok "BPF maps cleaned"
    fi

    # Remove completions
    rm -f /etc/bash_completion.d/aegis-cli 2>/dev/null
    rm -f /usr/share/zsh/site-functions/_aegis-cli 2>/dev/null
    rm -f /usr/share/fish/vendor_completions.d/aegis-cli.fish 2>/dev/null

    # Remove logrotate
    rm -f /etc/logrotate.d/aegis 2>/dev/null
    rm -f /etc/periodic/weekly/aegis-logclean 2>/dev/null

    # Interactive prompts for user data
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
# ENTRY POINT
# =============================================================================

main() {
    local install_only=false
    local skip_service=false

    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-only) install_only=true; shift ;;
            --skip-service) skip_service=true; shift ;;
            --uninstall)    uninstall_aegis; exit 0 ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --install-only   Install pre-built binaries (no cargo build)"
                echo "  --skip-service   Don't install init system service"
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
        exit 1
    fi

    # Detect environment
    local distro=$(detect_distro)
    local init_system=$(detect_init_system)

    log_info "Detected distro: $distro"
    log_info "Detected init: $init_system"

    # Validate kernel
    check_kernel_version
    check_bpf_fs

    # Stop running services
    stop_running_services
    cleanup_old_install

    # Install
    if $install_only; then
        install_prebuilt
    else
        build_and_install
    fi

    # Post-install tasks
    install_default_config
    install_completions
    install_geoip_db
    install_logrotate

    # Install init service
    if ! $skip_service; then
        case "$init_system" in
            systemd) install_systemd_service ;;
            openrc)  install_openrc_service ;;
            sysvinit) install_sysvinit_service ;;
            *)
                log_warn "Unknown init system, skipping service installation"
                ;;
        esac
    fi

    # Restart services
    restart_services

    show_usage
}

main "$@"
