#!/bin/bash
# Aegis XDP Firewall - Install Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source cargo if available
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

# Check for cargo
if ! command -v cargo &> /dev/null; then
    echo "❌ cargo not found. Run this script without sudo first to build:"
    echo "   cargo run -p xtask -- build-ebpf --profile release"
    echo "   cargo build --release -p aegis-cli"
    echo "Then run: sudo ./install.sh --install-only"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  🛡️  AEGIS XDP FIREWALL - INSTALLER"
echo "═══════════════════════════════════════════════════════"

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (sudo)"
   exit 1
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p /usr/local/share/aegis
mkdir -p /usr/local/bin

# Build eBPF (XDP + TC)
echo "🔨 Building eBPF programs..."
cd "$SCRIPT_DIR"
cargo run -p xtask -- build-all --profile release

# Build CLI
echo "🔨 Building CLI..."
cargo build --release -p aegis-cli

# Helper: Detect active aegis services
detect_services() {
    systemctl list-units --full --all --no-legend "aegis@*" | awk '{print $1}'
}

# Stop running services
SERVICES=$(detect_services)
if [[ -n "$SERVICES" ]]; then
    echo "🛑 Stopping active Aegis services..."
    for svc in $SERVICES; do
        echo "   - Stopping $svc"
        systemctl stop "$svc"
    done
fi

# Clean up old maps if they exist (prevents schematic mismatch errors)
if [[ -d "/sys/fs/bpf/aegis" ]]; then
    echo "🧹 Cleaning up pinned BPF maps..."
    rm -rf /sys/fs/bpf/aegis
fi

# Install
echo "📦 Installing..."
# BPF binaries are in workspace target (xtask builds from workspace root)
cp "$SCRIPT_DIR/target/bpfel-unknown-none/release/aegis" /usr/local/share/aegis/aegis.o
# Install TC program if built
if [[ -f "$SCRIPT_DIR/target/bpfel-unknown-none/release/aegis-tc" ]]; then
    cp "$SCRIPT_DIR/target/bpfel-unknown-none/release/aegis-tc" /usr/local/share/aegis/aegis-tc.o
    echo "📦 TC Egress program installed"
fi
cp "$SCRIPT_DIR/target/release/aegis-cli" /usr/local/bin/aegis-cli
chmod +x /usr/local/bin/aegis-cli

# Restart services
if [[ -n "$SERVICES" ]]; then
    echo "🚀 Restarting Aegis services..."
    for svc in $SERVICES; do
        echo "   - Starting $svc"
        systemctl start "$svc"
    done
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ✅ INSTALLATION COMPLETE"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Usage:"
echo "    sudo aegis-cli -i wg0-mullvad tui"
echo "    sudo aegis-cli -i eth0 tui"
echo ""
echo "  TUI Controls:"
echo "    ↑/↓  Navigate connections"
echo "    SPACE Block/Unblock IP"
echo "    q    Quit"
echo ""
