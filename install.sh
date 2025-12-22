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

# Build eBPF
echo "🔨 Building eBPF program..."
cd "$SCRIPT_DIR"
cargo run -p xtask -- build-ebpf --profile release

# Build CLI
echo "🔨 Building CLI..."
cargo build --release -p aegis-cli

# Install
echo "📦 Installing..."
cp "$SCRIPT_DIR/target/bpfel-unknown-none/release/aegis" /usr/local/share/aegis/aegis.o
cp "$SCRIPT_DIR/target/release/aegis-cli" /usr/local/bin/aegis-cli
chmod +x /usr/local/bin/aegis-cli

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
