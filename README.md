# Python Port Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)

An advanced multithreaded TCP port scanner built from scratch in Python — pure
standard library, no external dependencies.

It started as a basic script that spawned 1024 raw threads and grew into a full
command-line tool with a bounded thread pool, banner grabbing, flexible port
specs, and JSON output.

---

## Features

- **Command-line interface** — `python Scanner.py <target> -p 1-1024` — or run
  it with no arguments to drop into an interactive prompt
- **Flexible port specs** — single ports, lists, and ranges:
  `80`, `1-1024`, `22,80,443`, `1-100,443,8000-8100`
- **`--top` quick scan** — a preset list of the most common ports
- **Thread pool** — a bounded, configurable worker pool (`-w`) via
  `ThreadPoolExecutor`, instead of one raw thread per port
- **Banner grabbing** — a light HTTP probe identifies the actual running service
- **Hostname resolution** — scan `scanme.nmap.org`, not just raw IPs
- **JSON output** — `--json` prints clean, machine-readable results to stdout
- **Polished UX** — live progress, scan timing, colored output (auto-disabled
  when piped), and graceful `Ctrl+C` handling
- **Ethical safeguard** — interactive mode asks for authorization before scanning

---

## Usage

```bash
# Clone the repo
git clone https://github.com/tejasva-cyber/python-port-scanner.git
cd python-port-scanner

# Interactive mode (prompts for a target)
python Scanner.py

# Scan the default range (1-1024) on a host
python Scanner.py scanme.nmap.org

# Specific ports / ranges, more workers, with banner grabbing
python Scanner.py 192.168.1.10 -p 22,80,443,8000-8100 -w 400

# Quick scan of common ports, JSON output
python Scanner.py example.com --top --json
```

### Options

| Flag | Description |
|------|-------------|
| `-p`, `--ports` | Port spec, e.g. `22,80,443,8000-8100` (default: `1-1024`) |
| `--top` | Scan a preset list of common ports (overrides `-p`) |
| `-t`, `--timeout` | Connect timeout in seconds (default: `0.5`) |
| `-w`, `--workers` | Number of concurrent workers (default: `200`) |
| `--no-banner` | Skip banner grabbing (faster) |
| `--json` | Print results as JSON to stdout |
| `--no-color` | Disable colored output |

---

## Output

<img width="1416" height="471" alt="Scanner output" src="https://github.com/user-attachments/assets/c770cd66-9a62-4a89-ae54-1237ede57c8f" />

---

## Legal Notice

Only use on systems you own or have explicit written permission to scan.
Unauthorized port scanning is illegal under the IT Act 2000 (India) §66.

---

## Built With

Python · socket · concurrent.futures · argparse
