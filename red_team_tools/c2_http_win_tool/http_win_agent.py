import socket
import subprocess

SERVER_IP = "192.168.1.78"   # server
SERVER_PORT = 9001

HTTP_TARGET_IP = "192.168.1.37"
HTTP_TARGET_PORT = 80

def fake_http_get():
    try:
        s = socket.create_connection((HTTP_TARGET_IP, HTTP_TARGET_PORT), timeout=3)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {HTTP_TARGET_IP}\r\n\r\n".encode())
        s.close()
        return "HTTP GET sent"
    except Exception as e:
        return str(e)

def sniff_http():
    try:
        output = subprocess.check_output(
            f"netstat -an | findstr :{HTTP_TARGET_PORT}",
            shell=True)
        return output.decode(errors="ignore") or "No connections found"
    except:
        return "No HTTP traffic seen"

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, SERVER_PORT))
    print("[+] Connected to server")

    while True:
        cmd = s.recv(1024).decode().strip().upper()

        if cmd == "EXIT":
            break
        elif cmd == "FAKE_HTTP_GET":
            out = fake_http_get()
        elif cmd == "SNIFF_HTTP":
            out = sniff_http()
        else:
            out = "Commands: FAKE_HTTP_GET, SNIFF_HTTP, EXIT"

        s.send(out.encode())

    s.close()

if __name__ == "__main__":
    main()
