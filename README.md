# Simple-firewall-
# Simple Firewall System in Python (Rule-Based)

A simple **rule-based firewall simulation** built using Python.  
This project is designed for **Bachelor of IT / CS students** to understand how firewall rule matching works (ALLOW/DENY, default policy, logging, and first-match rule priority).

✅ **Key idea:** This is an **application-layer firewall engine**, not a kernel/OS-level firewall.  
It *simulates* firewall decisions on traffic packets/events and logs them for auditing.

---

## Features

- ✅ Rule-based filtering (ALLOW / DENY)
- ✅ Matches using:
  - Source IP range (CIDR)
  - Destination IP range (CIDR)
  - Source port
  - Destination port
  - Protocol (TCP / UDP / ANY)
  - Direction (IN / OUT / ANY)
- ✅ **First-Match Wins** rule priority (like real firewalls)
- ✅ Default policy (ALLOW or DENY)
- ✅ Logs every decision in JSON format (`firewall.log`)
- ✅ Rules loaded from an external JSON file (`rules.json`)

---

## Project Structure
simple_py_firewall/
firewall/
init.py
rules.py
engine.py
logger.py
main.py
rules.json
requirements.txt
README.md

---

## Requirements

- Python **3.9+**
- No external libraries required ✅

---

## Setup & Run

### 1) Clone / Download Project
Place the project folder anywhere on your computer.

### 2) Run the firewall demo
```bash
python main.py
