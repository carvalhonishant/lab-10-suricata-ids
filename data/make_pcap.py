#!/usr/bin/env python3
"""
Build a small attack capture for a Suricata IDS lab.

Two attacks are in it:
  1. A TCP SYN port scan: one host sweeps many ports on a target.
  2. A malicious HTTP request: sqlmap tool with a SQL injection in the URI,
     sent over a complete TCP session so Suricata can parse the HTTP.

Everything uses documentation IP ranges, no real hosts.
"""

from scapy.all import IP, TCP, Raw, wrpcap
import time

ATTACKER = "198.51.100.66"
TARGET = "192.0.2.5"
pkts = []
t = time.time()

# --- Attack 1: SYN port scan, attacker sweeps 40 ports on the target ---
sport = 40000
for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
             995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
             9200, 27017, 20, 69, 111, 161, 389, 636, 873, 2049, 5060,
             5985, 5986, 7001, 8000, 8888, 11211]:
    p = IP(src=ATTACKER, dst=TARGET) / TCP(sport=sport, dport=port, flags="S", seq=1000)
    p.time = t
    pkts.append(p)
    sport += 1
    t += 0.05

# --- Attack 2: a real TCP session carrying a sqlmap SQL injection request ---
t += 1
cport = 44444
# three-way handshake
syn = IP(src=ATTACKER, dst=TARGET) / TCP(sport=cport, dport=80, flags="S", seq=1000)
synack = IP(src=TARGET, dst=ATTACKER) / TCP(sport=80, dport=cport, flags="SA", seq=5000, ack=1001)
ack = IP(src=ATTACKER, dst=TARGET) / TCP(sport=cport, dport=80, flags="A", seq=1001, ack=5001)

http_req = (
    "GET /products.php?id=1'%20OR%20'1'='1 HTTP/1.1\r\n"
    "Host: shop.victim.example\r\n"
    "User-Agent: sqlmap/1.8#stable (https://sqlmap.org)\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n\r\n"
)
req = IP(src=ATTACKER, dst=TARGET) / TCP(sport=cport, dport=80, flags="PA", seq=1001, ack=5001) / Raw(load=http_req)

http_resp = (
    "HTTP/1.1 200 OK\r\n"
    "Server: Apache\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 13\r\n\r\n"
    "SQL error here"
)
resp = IP(src=TARGET, dst=ATTACKER) / TCP(sport=80, dport=cport, flags="PA", seq=5001, ack=1001 + len(http_req)) / Raw(load=http_resp)

for p in (syn, synack, ack, req, resp):
    p.time = t
    pkts.append(p)
    t += 0.1

wrpcap("attack.pcap", pkts)
print(f"Wrote attack.pcap with {len(pkts)} packets")
print("Attack 1: SYN scan of 40 ports from", ATTACKER, "to", TARGET)
print("Attack 2: sqlmap SQL injection GET to", TARGET)
