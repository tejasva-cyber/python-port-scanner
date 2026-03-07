import socket
import threading
from queue import Queue
import sys
import re

# ─── Configuration ─────────────────────────────────────────────
MAX_THREADS = 100          # Thread pool size (safe for most systems)
TIMEOUT     = 0.5
BANNER_TIMEOUT = 1.0

# ─── Validation ────────────────────────────────────────────────
def is_valid_ip(ip):
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, ip):
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

# ─── Banner Grabbing ────────────────────────────────────────────
def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(BANNER_TIMEOUT)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner.split("\n")[0][:60]  # First line, max 60 chars
    except Exception:
        return ""

# ─── Core Scanner ──────────────────────────────────────────────
def scan_port(ip, port, open_ports, lock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    result = sock.connect_ex((ip, port))
    sock.close()

    if result == 0:
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        banner = grab_banner(ip, port)
        banner_str = f"  ↳ Banner: {banner}" if banner else ""

        with lock:
            print(f"  [OPEN]  Port {port:>5}  →  {service:<15}{banner_str}")
            open_ports.append(port)

# ─── Thread Pool Worker ─────────────────────────────────────────
def worker(ip, queue, open_ports, lock):
    while not queue.empty():
        try:
            port = queue.get_nowait()
        except Exception:
            break
        scan_port(ip, port, open_ports, lock)
        queue.task_done()

# ─── Main ───────────────────────────────────────────────────────
while True:
    print("\n" + "=" * 50)
    raw_target = input("Enter target IP or hostname (or 'quit'): ").strip()

    if raw_target.lower() == "quit":
        print("[*] Exiting.")
        sys.exit(0)

    # ⚠️  Ethical warning
    print("\n[!] WARNING: Only scan systems you own or have explicit written permission to scan.")
    confirm = input("    Do you have authorization? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("[✗] Scan aborted. Unauthorized scanning is illegal.")
        continue

    # Resolve hostname to IP
    ip = resolve_target(raw_target)
    if not ip:
        print(f"[✗] Could not resolve '{raw_target}'. Check the address and try again.")
        continue
    if raw_target != ip:
        print(f"[*] Resolved {raw_target} → {ip}")

    # Port range input
    try:
        start = int(input("Start port [default 1]: ").strip() or "1")
        end   = int(input("End port [default 1024]: ").strip() or "1024")
        if not (1 <= start <= end <= 65535):
            raise ValueError
    except ValueError:
        print("[✗] Invalid port range. Use 1–65535.")
        continue

    open_ports = []
    lock = threading.Lock()
    queue = Queue()

    for port in range(start, end + 1):
        queue.put(port)

    print(f"\n[*] Scanning {ip} — ports {start} to {end} with {MAX_THREADS} threads")
    print("-" * 50)

    threads = []
    for _ in range(min(MAX_THREADS, end - start + 1)):
        t = threading.Thread(target=worker, args=(ip, queue, open_ports, lock))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("-" * 50)
    if open_ports:
        print(f"[+] Scan complete. {len(open_ports)} open port(s): {sorted(open_ports)}")
    else:
        print("[!] No open ports found in range.")