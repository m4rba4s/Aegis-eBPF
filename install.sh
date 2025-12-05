#!/bin/bash
set -e

echo "🛡️  Installing Aegis eBPF Firewall..."

# 1. Build eBPF First (Required for include_bytes!)
echo "[*] Building eBPF Program..."
cargo run --package xtask -- build-ebpf --profile release

# 2. Build CLI
echo "[*] Building Release Binary..."
cargo build --release

# 3. Stop existing service
echo "[*] Stopping existing service..."
sudo systemctl stop aegis || true

# 4. Install Binary (Stealth Mode)
echo "[*] Installing to /usr/local/bin/kworker-u4..."
sudo cp target/release/aegis-cli /usr/local/bin/kworker-u4
sudo chmod +x /usr/local/bin/kworker-u4

# 4b. Install eBPF Object
echo "[*] Installing eBPF object..."
sudo mkdir -p /usr/local/share/aegis
sudo cp target/bpfel-unknown-none/release/aegis /usr/local/share/aegis/aegis.o

# 5. Install Service
echo "[*] Installing Systemd Service..."
# Detect interface (default to eth0 if not found)
IFACE=$(ip -o -4 route show to default | awk '{print $5}')
if [ -z "$IFACE" ]; then
    IFACE="eth0"
fi
echo "    Detected Interface: $IFACE"

# Patch service file with detected interface
sed "s/eth0/$IFACE/g" aegis.service > /tmp/aegis.service
sudo cp /tmp/aegis.service /etc/systemd/system/aegis.service

# 6. Enable & Start
echo "[*] Enabling Service..."
sudo systemctl daemon-reload
sudo systemctl enable aegis
sudo systemctl restart aegis

echo "✅ Installation Complete!"
echo "   Status: sudo systemctl status aegis"
echo "   Logs:   sudo journalctl -u aegis -f"
