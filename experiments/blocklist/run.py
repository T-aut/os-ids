from scapy.all import IP, UDP, send
import time
from datetime import datetime

IP_FILE = "ips.txt"
DEST_IP = "127.0.0.1"
DEST_PORT = 3000

with open(IP_FILE) as f:
    ips = [line.strip() for line in f if line.strip()]

total = len(ips)
step = total // 20

print(f"[INFO] Total ips: {total}")
for index, ip in enumerate(ips):
    pkt = IP(src=ip, dst=DEST_IP) / UDP(sport=12345, dport=DEST_PORT) / b"test"
    send(pkt, verbose=False)

    if index % step == 0:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Progress: {((index+1) * 100) // total}%\tPackets sent: {index+1}")
    # time.sleep(0.01)
