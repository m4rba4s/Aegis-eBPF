import socket
import threading
import time

# Synthetic TLS ClientHello matching Cobalt Strike HTTPS beacon pattern
# ContentType=0x16 (Handshake), TLS 1.2 (0x0303), HandshakeType=0x01 (ClientHello)
CS_PAYLOAD = bytes.fromhex(
    "16030100c6"       # TLS Record: Handshake, TLS 1.0 record version, length=198
    "010000c2"         # ClientHello, length=194
    "0303"             # ClientHello version: TLS 1.2
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"  # Random (32 bytes)
    "00"               # Session ID length: 0
    "0014"             # Cipher suites length: 20 (10 suites)
    "c028c027c014c013009d009c003d003c0035002f"  # Cipher suites
    "0100"             # Compression methods: 1 method, null
    "0085"             # Extensions length: 133
    "00000000"         # SNI extension (empty)
    "00050000"         # Status request
    "000a00080006001700180019"  # Supported groups
    "000b00020100"     # EC point formats
    "000d0000"         # Signature algorithms (empty)
    "00230000"         # Session ticket
    "ff01000100"       # Renegotiation info
)

def dummy_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('127.0.0.1', 443))
        server.listen(1)
        conn, addr = server.accept()
        conn.recv(1024)
        conn.close()
    except Exception as e:
        print(f"Dummy Server Error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    print("[*] Starting local HTTPS interceptor port (443)...")
    threading.Thread(target=dummy_server, daemon=True).start()
    time.sleep(0.5)

    print("[*] Injecting Cobalt Strike HTTPS Beacon ClientHello...")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('127.0.0.1', 443))
        client.send(CS_PAYLOAD)
        time.sleep(0.5)
        client.close()
        print("[+] Payload injected successfully! Check Aegis logs or TUI.")
    except Exception as e:
        print(f"[-] Client Error: {e}\n(Did you run with sudo? Port 443 needs root)")
