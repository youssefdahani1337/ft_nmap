#!/usr/bin/env python3
"""Sniff loopback and validate the probes ft_nmap sends.
usage: capture_check.py <seconds> <target_port>
Prints READY once listening, then one unique line per probe type seen:
    TCP flags=<FIN+PSH+URG|SYN|none|...> cksum=<VALID|BAD>
    UDP cksum=<VALID|BAD>
A probe = packet from our source-port range (>= 33000) to <target_port>."""
import socket, struct, sys, time

duration, target = float(sys.argv[1]), int(sys.argv[2])
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
sock.bind(("lo", 0))
sock.settimeout(0.2)
print("READY", flush=True)

def cksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

NAMES = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"))
seen = set()
end = time.time() + duration
while time.time() < end:
    try:
        pkt = sock.recv(65535)
    except socket.timeout:
        continue
    ip = pkt[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] not in (6, 17):
        continue
    ihl = (ip[0] & 15) * 4
    total_len = struct.unpack("!H", ip[2:4])[0]
    seg = ip[ihl:total_len]
    if len(seg) < 8:
        continue
    sport, dport = struct.unpack("!HH", seg[:4])
    if sport < 33000 or dport != target:
        continue
    pseudo = ip[12:16] + ip[16:20] + struct.pack("!BBH", 0, ip[9], len(seg))
    ok = "VALID" if cksum(pseudo + seg) == 0 else "BAD"
    if ip[9] == 6:
        flags = seg[13]
        if flags == 0x04:          # kernel's own RST after a SYN+ACK: not our probe
            continue
        names = "+".join(n for bit, n in NAMES if flags & bit) or "none"
        seen.add("TCP flags=%s cksum=%s" % (names, ok))
    else:
        seen.add("UDP cksum=%s" % ok)
for line in sorted(seen):
    print(line, flush=True)
