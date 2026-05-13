import socket
import threading
import time

target_ip = "127.0.0.1"
target_port = 80
threads = 100
running = True

def attack():
    while running:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, target_port))
            s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            s.close()
        except:
            pass

print(f"Starting {threads} threads for stress test...")
thread_list = []
for i in range(threads):
    t = threading.Thread(target=attack)
    t.start()
    thread_list.append(t)

try:
    time.sleep(10)
except KeyboardInterrupt:
    pass

running = False
print("Stopping threads...")
for t in thread_list:
    t.join()
print("Stress test finished.")
