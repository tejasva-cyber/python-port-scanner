#!/usr/bin/env python3
"""
Advanced multithreaded TCP port scanner.

Educational / authorized-testing use only: scan only hosts that you own or
have explicit written permission to test.

Examples
--------
    # Scan the default range (1-1024) on a host
    python Scanner.py scanme.nmap.org

    # Scan specific ports / ranges, faster, with banner grabbing
    python Scanner.py 192.168.1.10 -p 22,80,443,8000-8100 -w 400

    # Quick scan of common ports only, JSON output
    python Scanner.py example.com --top --json

    # No arguments -> interactive mode (prompts for a target)
    python Scanner.py
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_PORTS = "1-1024"
DEFAULT_TIMEOUT = 0.5
DEFAULT_WORKERS = 200
BANNER_TIMEOUT = 1.0

# A compact list of frequently interesting ports for --top quick scans.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
]

# Ports where a light HTTP probe usually elicits a useful banner.
HTTP_PORTS = {80, 8000, 8080, 8888}


# ---------------------------------------------------------------------------
# Terminal colouring (auto-disabled when not writing to a TTY)
# ---------------------------------------------------------------------------
class Color:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    enabled = True

    @classmethod
    def wrap(cls, text, code):
        if not cls.enabled:
            return text
        return f"{code}{text}{cls.RESET}"


def eprint(*args, **kwargs):
    """Print to stderr so it never pollutes --json / piped stdout."""
    print(*args, file=sys.stderr, **kwargs)


# ---------------------------------------------------------------------------
# Port-spec parsing
# ---------------------------------------------------------------------------
def parse_ports(spec):
    """Turn a spec like '22,80,443,8000-8100' into a sorted list of ports.

    Accepts single ports, comma-separated lists, and 'lo-hi' ranges (in any
    order). Raises ValueError on anything malformed or out of the 1-65535
    range.
    """
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_str, hi_str = chunk.split("-", 1)
            lo, hi = int(lo_str), int(hi_str)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))

    if not ports:
        raise ValueError("no ports specified")
    out_of_range = [p for p in ports if not 1 <= p <= 65535]
    if out_of_range:
        raise ValueError(f"port(s) out of range 1-65535: {sorted(out_of_range)}")
    return sorted(ports)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def grab_banner(sock, port):
    """Best-effort read of a short service banner from an open socket."""
    try:
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        sock.settimeout(BANNER_TIMEOUT)
        data = sock.recv(256)
    except OSError:
        return ""
    if not data:
        return ""
    lines = data.decode("utf-8", errors="replace").strip().splitlines()
    # Keep it to a single, tidy line.
    return lines[0] if lines else ""


def scan_port(target, port, timeout, do_banner):
    """Return a result dict if the port is open, else None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((target, port)) != 0:
            return None
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"
        banner = grab_banner(sock, port) if do_banner else ""
        return {"port": port, "service": service, "banner": banner}


def resolve(target):
    """Resolve a hostname/IP to an IPv4 address, or None if it can't be."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def print_open(result, stream):
    """Print one open-port line to the given stream."""
    port = result["port"]
    service = result["service"]
    tag = Color.wrap("[OPEN]", Color.GREEN + Color.BOLD)
    line = f"  {tag}  Port {port:>5}  ->  {service}"
    if result["banner"]:
        line += Color.wrap(f"   ({result['banner']})", Color.DIM)
    print(line, file=stream)


def scan(target, ports, timeout, workers, do_banner, json_mode=False):
    """Scan `ports` on `target`. Returns a list of open-port result dicts.

    In JSON mode the live open-port lines go to stderr so that stdout holds
    only the final JSON payload.
    """
    ip = resolve(target)
    if ip is None:
        eprint(Color.wrap(f"[!] Could not resolve '{target}'.", Color.RED))
        return None

    label = target if target == ip else f"{target} ({ip})"
    eprint(Color.wrap(
        f"\n[*] Scanning {label} -- {len(ports)} port(s), "
        f"{workers} workers, {timeout}s timeout", Color.CYAN))
    eprint("-" * 55)

    open_results = []
    total = len(ports)
    done = 0
    start = time.time()
    open_stream = sys.stderr if json_mode else sys.stdout

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(scan_port, ip, p, timeout, do_banner): p
                for p in ports
            }
            for future in as_completed(futures):
                done += 1
                result = future.result()
                if result:
                    open_results.append(result)
                    print_open(result, open_stream)
                # Lightweight progress indicator on stderr.
                if done % 200 == 0 or done == total:
                    eprint(Color.wrap(
                        f"\r    ...{done}/{total} scanned", Color.DIM), end="")
    except KeyboardInterrupt:
        eprint(Color.wrap("\n[!] Scan interrupted by user.", Color.YELLOW))

    elapsed = time.time() - start
    eprint("\n" + "-" * 55)
    if open_results:
        found = ", ".join(str(r["port"]) for r in sorted(
            open_results, key=lambda r: r["port"]))
        eprint(Color.wrap(
            f"[+] Done in {elapsed:.2f}s. "
            f"{len(open_results)} open port(s): {found}", Color.GREEN))
    else:
        eprint(Color.wrap(
            f"[!] Done in {elapsed:.2f}s. No open ports found.", Color.YELLOW))
    return open_results


# ---------------------------------------------------------------------------
# CLI / entry points
# ---------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        description="Advanced multithreaded TCP port scanner "
                    "(authorized testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?",
                        help="target IP or hostname (omit for interactive mode)")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS,
                        help=f"port spec, e.g. '22,80,443,8000-8100' "
                             f"(default: {DEFAULT_PORTS})")
    parser.add_argument("--top", action="store_true",
                        help="scan a preset list of common ports (overrides -p)")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"connect timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"concurrent workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--no-banner", action="store_true",
                        help="skip banner grabbing (faster)")
    parser.add_argument("--json", action="store_true",
                        help="print results as JSON to stdout")
    parser.add_argument("--no-color", action="store_true",
                        help="disable coloured output")
    return parser


def resolve_ports(args):
    if args.top:
        return sorted(TOP_PORTS)
    return parse_ports(args.ports)


def emit_json(target, ports, results):
    import json
    payload = {
        "target": target,
        "scanned_ports": len(ports),
        "open_ports": [
            {"port": r["port"], "service": r["service"], "banner": r["banner"]}
            for r in sorted(results, key=lambda r: r["port"])
        ],
    }
    print(json.dumps(payload, indent=2))


def run_once(target, args):
    ports = resolve_ports(args)
    results = scan(target, ports, args.timeout, args.workers,
                   do_banner=not args.no_banner, json_mode=args.json)
    if results is None:
        return 1
    if args.json:
        emit_json(target, ports, results)
    return 0


def interactive_loop(args):
    eprint(Color.wrap(
        "TCP Port Scanner -- interactive mode "
        "(blank line or 'q' to quit)", Color.BOLD))
    while True:
        try:
            target = input("Enter target IP/hostname: ").strip()
        except (EOFError, KeyboardInterrupt):
            eprint("\n[*] Exiting.")
            return 0
        if not target or target.lower() in ("q", "quit", "exit"):
            eprint("[*] Exiting.")
            return 0
        run_once(target, args)
        eprint("\n" + "=" * 55 + "\n")


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        Color.enabled = False

    # Validate the port spec up front so bad input fails fast and clearly.
    try:
        resolve_ports(args)
    except ValueError as exc:
        eprint(Color.wrap(f"[!] Invalid port spec: {exc}", Color.RED))
        return 2

    if args.target:
        return run_once(args.target, args)
    return interactive_loop(args)


if __name__ == "__main__":
    sys.exit(main())
