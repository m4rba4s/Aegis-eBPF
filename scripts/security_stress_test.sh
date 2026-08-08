#!/bin/bash
# ==============================================================================
# Aegis eBPF/XDP Firewall - Security Stress Test & Fuzzing Script
# ==============================================================================
# This script generates traffic to test security policies:
# SEC-001: TC egress fail-closed (truncated packets)
# SEC-002: IPv6 SYN flood rate limiting
# SEC-004: Port scan detection (stride-256)
# General: SYN flood, Xmas, Null, SYN+FIN, Fragmentation, VLAN injection
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

IFACE=${1:-lo}
TARGET_IPV4="127.0.0.1"
TARGET_IPV6="::1"

pass=0
fail=0

log_pass() { echo -e "${GREEN}[PASS] $1${NC}"; ((pass++)); }
log_fail() { echo -e "${RED}[FAIL] $1${NC}"; ((fail++)); }
log_info() { echo -e "${BLUE}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }

echo -e "${BLUE}=== Aegis Security Stress Test & Fuzzing ===${NC}"
echo "Target Interface : $IFACE"
echo "Target IPv4      : $TARGET_IPV4"
echo "Target IPv6      : $TARGET_IPV6"
echo "============================================"

# Dependency Check
for cmd in python3 hping3 nping; do
    if ! command -v "$cmd" &> /dev/null; then
        log_warn "$cmd is not installed. Some tests may fail or be skipped."
    fi
done

# Scapy inline script for complex packet generation (truncated, custom strides, VLANs)
cat << 'EOF' > /tmp/aegis_scapy_fuzz.py
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import *
except ImportError:
    print("SCAPY_MISSING")
    sys.exit(1)

test_name = sys.argv[1]
iface = sys.argv[2]
target_ip = sys.argv[3]

try:
    if test_name == "sec001_truncated":
        # Send a severely truncated Ethernet frame (less than standard 14 byte header)
        sendp(Raw(b'\x00'*10), iface=iface, verbose=0)
        print("PASS")
    
    elif test_name == "sec004_portscan":
        # Stride-256 port scan pattern
        pkts = [IP(dst=target_ip)/TCP(dport=port, flags="S") for port in range(100, 1000, 256)]
        send(pkts, verbose=0)
        print("PASS")

    elif test_name == "vlan_tagged":
        # Send a packet with VLAN encapsulation (dot1q)
        sendp(Ether()/Dot1Q(vlan=10)/IP(dst=target_ip)/ICMP(), iface=iface, verbose=0)
        print("PASS")
    else:
        print("UNKNOWN_TEST")
except Exception as e:
    print("FAIL")
EOF

run_scapy_test() {
    local test_name=$1
    local res
    res=$(python3 /tmp/aegis_scapy_fuzz.py "$test_name" "$IFACE" "$TARGET_IPV4" 2>/dev/null)
    if [ "$res" == "SCAPY_MISSING" ]; then
        log_warn "Scapy is missing (pip install scapy). Skipping $test_name."
    elif [ "$res" == "PASS" ]; then
        log_pass "Generated traffic for $test_name."
    else
        log_fail "Failed to generate traffic for $test_name."
    fi
}

# -------------------------------------------------------------------------
# Test Cases
# -------------------------------------------------------------------------

log_info "\n--- [SEC-001] TC Egress Fail-Closed (Truncated/Malformed packets) ---"
run_scapy_test "sec001_truncated"
echo " -> Verify in dmesg or trace_pipe that the packet was dropped by Aegis TC program."

log_info "\n--- [SEC-002] IPv6 SYN Flood Rate Limiting ---"
if command -v nping &> /dev/null; then
    nping -c 2000 --tcp -p 80 --flags syn --rate 10000 -6 "$TARGET_IPV6" -e "$IFACE" -q >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_pass "IPv6 SYN burst generated."
        echo " -> Verify in Aegis map counters that IPv6 rate limiting was triggered."
    else
        log_fail "Failed to execute nping for IPv6 SYN flood."
    fi
else
    log_warn "Skipping nping IPv6 flood."
fi

log_info "\n--- [SEC-004] Port Scan Detection (Stride-256) ---"
run_scapy_test "sec004_portscan"
echo " -> Verify in Aegis events that the stride-based port scan was detected."

log_info "\n--- [GENERAL] SYN Flood Stress ---"
if command -v hping3 &> /dev/null; then
    hping3 -c 3000 -d 120 -S -w 64 -p 80 --flood --rand-source "$TARGET_IPV4" 2>/dev/null &
    HPING_PID=$!
    sleep 3
    kill $HPING_PID 2>/dev/null
    log_pass "SYN flood attack vector generated."
else
    log_warn "Skipping hping3 SYN flood."
fi

log_info "\n--- [GENERAL] TCP Xmas Scan ---"
if command -v nping &> /dev/null; then
    nping -c 100 --tcp --flags fin,psh,urg "$TARGET_IPV4" -e "$IFACE" -q >/dev/null 2>&1
    log_pass "Xmas scan packets generated."
fi

log_info "\n--- [GENERAL] TCP Null Scan ---"
if command -v nping &> /dev/null; then
    nping -c 100 --tcp --flags 0 "$TARGET_IPV4" -e "$IFACE" -q >/dev/null 2>&1
    log_pass "Null scan packets generated."
fi

log_info "\n--- [GENERAL] TCP SYN+FIN Attack ---"
if command -v nping &> /dev/null; then
    nping -c 100 --tcp --flags syn,fin "$TARGET_IPV4" -e "$IFACE" -q >/dev/null 2>&1
    log_pass "SYN+FIN packets generated."
fi

log_info "\n--- [GENERAL] Fragmented Packets ---"
if command -v hping3 &> /dev/null; then
    hping3 -c 100 -f -1 "$TARGET_IPV4" 2>/dev/null >/dev/null
    log_pass "Fragmented ICMP packets generated."
fi

log_info "\n--- [GENERAL] VLAN-tagged Frames ---"
run_scapy_test "vlan_tagged"

echo -e "\n============================================"
echo -e "Summary: ${GREEN}$pass Tests Executed${NC}, ${RED}$fail Errors in Generation${NC}"
echo -e "============================================"
echo -e "${YELLOW}Note: This script blindly generates malicious traffic. True verification requires reading Aegis's eBPF map telemetry, log streams, or /sys/kernel/debug/tracing/trace_pipe to ensure these vectors were successfully matched and dropped.${NC}"
