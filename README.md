#  Python Port Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A multithreaded TCP port scanner built from scratch in Python.  
Started as a basic script → improved after finding critical flaws in v1.


##  Versions

| Version | File | Description |

| v1 | Scanner.py | Basic scanner — 1024 raw threads, ports 1–1024 |
| v2 | scanner2.py | Thread pool + banner grabbing + hostname support + validation |

---

##  What I Improved (v1 → v2)

- **Fixed thread exhaustion:** v1 spawned 1024 threads at once → v2 uses 100 pooled threads via Queue
- **Added hostname resolution:** Can now scan `scanme.nmap.org`, not just IPs
- **Added banner grabbing:** Identifies actual running service, not just port name
- **Added input validation:** No more crashes on bad input
- **Added ethical auth prompt:** Legal safeguard before scanning

---

##  How to Run
```bash
# Clone the repo
git clone https://github.com/tejasva-cyber/python-port-scanner.git
cd python-port-scanner

# Run v1 (basic)
python Scanner.py

# Run v2 (enhanced)
python scanner2.py
```

##  Output
![Scanner Output](./Screenshot%202026-03-08%20014452.png)



##  Legal Notice
Only use on systems you own or have explicit written permission to scan.  
Unauthorized port scanning is illegal under the IT Act 2000 (India) §66.

---

##  Built With
Python | socket | threading | queue
2. Run the scanner
