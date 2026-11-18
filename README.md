# sqlmap
# SQLMAP X ULTIMATE — Python Database Security Auditor

A lightweight, single-file, **safe-mode** database security auditing tool
for Linux, Android Termux and Pydroid 3.

## ⚠️ Disclaimer
This tool performs **non-destructive, indicator-based** checks only.
Use it **only** on systems you own or have explicit written permission
to test. No exploitation, dumping, or credential extraction is performed.

## Features
- URL security inspection & HTTP response analysis
- SQL error fingerprint detection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- SQL injection *risk indicators* (reflection analysis — no payloads sent)
- GET/POST parameter inspection, HTTP header & cookie security analysis
- Security misconfiguration detection
- Reports: HTML / TXT / JSON  ·  Scan history  ·  Logging
- Proxy support, custom User-Agent, configurable timeout
- Animated hacker-style terminal dashboard (ANSI colors)

## Installation (Termux)
```bash
pkg update && pkg upgrade -y
pkg install python git -y
git clone https://github.com/YOUR_USER/sqlmap-x-ultimate
cd sqlmap-x-ultimate
pip install -r requirements.txt
python sqlmap.py
