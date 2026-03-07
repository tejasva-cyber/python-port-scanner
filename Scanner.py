import socket
import threading

while True:
    target = input("Enter target IP address: ").strip()

    START_PORT = 1
    END_PORT   = 1024
    TIMEOUT    = 0.5

    open_ports = []
    lock = threading.Lock()

    print(f"\n[*] Scanning {target} — ports {START_PORT} to {END_PORT}")
    print("-" * 45)

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((target, port))

        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            with lock:
                print(f"  [OPEN]  Port {port:>4}  →  {service}")
                open_ports.append(port)

        sock.close()

    threads = []
    for port in range(START_PORT, END_PORT + 1):
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("-" * 45)
    if open_ports:
        print(f"[+] Scan complete. {len(open_ports)} open port(s) found: {sorted(open_ports)}")
    else:
        print("[!] No open ports found in range.")

    print("\n" + "=" * 45 + "\n")  # divider before next scan starts