#!/bin/bash
# Aegis Firewall Launcher

IFACE="wg0-mullvad"

echo "🛡️  Starting Aegis Firewall on $IFACE..."
echo "📊 Mode: TUI (Generic XDP)"
echo ""

sudo ./target/release/aegis-cli --iface $IFACE tui
