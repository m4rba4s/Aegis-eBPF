#!/bin/bash
# Aegis eBPF Firewall - Production Install Script
# Run with sudo: sudo ./deploy.sh [interface]

set -e

INTERFACE="${1:-wg0-mullvad}"
INSTALL_DIR="/usr/local"
CONFIG_DIR="/etc/aegis"
LOG_DIR="/var/log/aegis"
DATA_DIR="/var/lib/aegis"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "╔════════════════════════════════════════════════╗"
echo "║     AEGIS eBPF FIREWALL - PRODUCTION DEPLOY    ║"
echo "╚════════════════════════════════════════════════╝"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root (sudo)"
    exit 1
fi

echo "📦 Installing Aegis for interface: $INTERFACE"
echo ""

# Create directories
echo "📁 Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$INSTALL_DIR/share/aegis"

# Check if binaries exist
if [[ ! -f "$PROJECT_DIR/target/bpfel-unknown-none/release/aegis" ]]; then
    echo "❌ eBPF binary not found. Build first with:"
    echo "   cargo run -p xtask -- build-all --profile release"
    exit 1
fi

if [[ ! -f "$PROJECT_DIR/target/bpfel-unknown-none/release/aegis-tc" ]]; then
    echo "❌ TC eBPF binary not found. Build first with:"
    echo "   cargo run -p xtask -- build-all --profile release"
    exit 1
fi

if [[ ! -f "$PROJECT_DIR/target/release/aegis-cli" ]]; then
    echo "❌ CLI binary not found. Build first with:"
    echo "   cargo build --release -p aegis-cli"
    exit 1
fi

# Install binaries
echo "📋 Installing binaries..."
cp "$PROJECT_DIR/target/bpfel-unknown-none/release/aegis" "$INSTALL_DIR/share/aegis/aegis.o"
cp "$PROJECT_DIR/target/bpfel-unknown-none/release/aegis-tc" "$INSTALL_DIR/share/aegis/aegis-tc.o"
cp "$PROJECT_DIR/target/release/aegis-cli" "$INSTALL_DIR/bin/aegis-cli"
chmod +x "$INSTALL_DIR/bin/aegis-cli"

if [[ ! -x "$INSTALL_DIR/bin/aegis-cli" \
      || ! -f "$INSTALL_DIR/share/aegis/aegis.o" \
      || ! -f "$INSTALL_DIR/share/aegis/aegis-tc.o" ]]; then
    echo "❌ Installed command/object path validation failed"
    exit 1
fi

# Install config (don't overwrite existing)
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
    echo "📋 Installing default configuration..."
    cp "$SCRIPT_DIR/config.yaml" "$CONFIG_DIR/config.yaml"
    # Update interface in config
    sed -i "s/interface:.*/interface: $INTERFACE/" "$CONFIG_DIR/config.yaml"
else
    echo "⚠️  Config exists, skipping (backup and remove to reinstall)"
fi

# Install systemd service
echo "📋 Installing systemd service..."
cp "$SCRIPT_DIR/aegis@.service" /etc/systemd/system/
systemctl daemon-reload

# Enable and start service
echo "🚀 Enabling and starting aegis@$INTERFACE..."
systemctl enable "aegis@$INTERFACE"
systemctl start "aegis@$INTERFACE" || {
    echo "⚠️  Service failed to start. Check with:"
    echo "   journalctl -u aegis@$INTERFACE -f"
}

echo ""
echo "╔════════════════════════════════════════════════╗"
echo "║              INSTALLATION COMPLETE             ║"
echo "╚════════════════════════════════════════════════╝"
echo ""
echo "📍 Binaries:  $INSTALL_DIR/bin/aegis-cli"
echo "📍 XDP eBPF:  $INSTALL_DIR/share/aegis/aegis.o"
echo "📍 TC eBPF:   $INSTALL_DIR/share/aegis/aegis-tc.o"
echo "📍 Config:    $CONFIG_DIR/config.yaml"
echo "📍 Logs:      $LOG_DIR/"
echo ""
echo "🔧 Commands:"
echo "   sudo systemctl status aegis@$INTERFACE   # Check status"
echo "   sudo systemctl restart aegis@$INTERFACE  # Restart"
echo "   sudo journalctl -u aegis@$INTERFACE -f   # View logs"
echo "   sudo aegis-cli -i $INTERFACE tui         # Interactive TUI"
echo ""
echo "✅ Aegis is now protecting interface: $INTERFACE"
