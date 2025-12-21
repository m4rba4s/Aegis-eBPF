#!/bin/bash
# Aegis XDP Firewall Stress Test
# Run this from ANOTHER machine targeting your IP

set -e

TARGET="${1:-127.0.0.1}"
DURATION="${2:-30}"

echo "═══════════════════════════════════════════════════"
echo "  🔥 AEGIS STRESS TEST"
echo "  Target: $TARGET"
echo "  Duration: ${DURATION}s per test"
echo "═══════════════════════════════════════════════════"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  Run with sudo for full nmap features"
fi

echo ""
echo "▶ [1/5] SYN Flood Test (hping3)"
echo "─────────────────────────────────────────────────"
if command -v hping3 &>/dev/null; then
    timeout $DURATION hping3 -S -p 80 --flood "$TARGET" 2>/dev/null &
    sleep 5
    pkill hping3 2>/dev/null || true
    echo "✓ SYN flood sent for 5 seconds"
else
    echo "⚠ hping3 not installed, skipping"
fi

echo ""
echo "▶ [2/5] Port Scan (nmap -p 1-100)"
echo "─────────────────────────────────────────────────"
nmap -p 1-100 --open "$TARGET" 2>/dev/null | head -20
echo "✓ Port scan complete"

echo ""
echo "▶ [3/5] Xmas Scan (nmap -sX)"
echo "─────────────────────────────────────────────────"
sudo nmap -sX -p 22,80,443 "$TARGET" 2>/dev/null | head -15
echo "✓ Xmas scan complete"

echo ""
echo "▶ [4/5] Null Scan (nmap -sN)"
echo "─────────────────────────────────────────────────"
sudo nmap -sN -p 22,80,443 "$TARGET" 2>/dev/null | head -15
echo "✓ Null scan complete"

echo ""
echo "▶ [5/5] Aggressive Scan (nmap -A)"
echo "─────────────────────────────────────────────────"
nmap -A -p 80,443 --script=default "$TARGET" 2>/dev/null | head -30
echo "✓ Aggressive scan complete"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✅ STRESS TEST COMPLETE"
echo "  Check Aegis TUI for blocked packets!"
echo "═══════════════════════════════════════════════════"
