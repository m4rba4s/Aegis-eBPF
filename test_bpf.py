import struct
import socket

ip = "198.51.100.10"
ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
# Key for BLOCKLIST: src_ip (u32, NBO), dst_port (u16), proto (u8), pad (u8)
key_bytes = struct.pack("!I H B B", ip_int, 0, 0, 0)
print("BLOCKLIST KEY:", " ".join(f"{b:02x}" for b in key_bytes))

# Key for CIDR_BLOCKLIST: prefixlen (u32, native), ip (u32, NBO)
key_bytes = struct.pack("=I", 24) + struct.pack("!I", ip_int)
print("CIDR KEY:", " ".join(f"{b:02x}" for b in key_bytes))
