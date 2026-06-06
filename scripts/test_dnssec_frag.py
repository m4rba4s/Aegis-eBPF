from scapy.all import *

# Construct a large DNSSEC response (mock)
# A typical DNSSEC response can be > 1500 bytes (MTU), forcing IPv6 fragmentation
dns_payload = b"A" * 1600

# The router/server fragments it into two packets
pkt = IPv6(src="2001:db8::8888", dst="2001:db8::1234") / UDP(sport=53, dport=53333) / dns_payload
frags = fragment6(pkt, 1280)

print("--- DNSSEC Response Fragmentation ---")
print(f"Original Packet Size: {len(pkt)}")
print(f"Number of fragments generated: {len(frags)}")

print("\n--- Fragment 1 ---")
frags[0].show()
print(f"\nNext Header in Fragment 1 Base IPv6: {frags[0][IPv6].nh} (44 = Fragment Header)")

print("\n--- Fragment 2 ---")
frags[1].show()
print(f"\nNext Header in Fragment 2 Base IPv6: {frags[1][IPv6].nh} (44 = Fragment Header)")

print("\n--- Aegis eBPF Behavior ---")
print("Aegis unconditionally drops packets where NEXTHDR == 44.")
print("Both Fragment 1 and Fragment 2 will be DROPPED by Aegis.")
print("Result: Legitimate DNSSEC query fails, breaking domain resolution.")
