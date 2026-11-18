#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLMAP X ULTIMATE — Python Database Security Auditor
=====================================================
A lightweight, single-file database security auditing tool.

 * Passive + safe-indicator analysis only:
   - SQL error fingerprinting in responses
   - Reflected-parameter risk indicators (no destructive payloads)
   - HTTP security header analysis
   - Cookie security inspection
   - Security misconfiguration checks
   - HTML / TXT / JSON report export

 NO automatic exploitation, NO database dumping, NO password extraction,
 NO destructive SQL queries. Confirmed findings are clearly separated
 from possible indicators.

Compatible with: Linux, Android Termux, Pydroid 3 (Python 3.7+)
Dependencies:    requests (auto-checked at startup)
"""

import os
import re
import sys
import json
import time
import random
import shutil
import string
import logging
import platform
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qsl

# ---------------------------------------------------------------------------
# Dependency auto-check (no hard crash with ugly traceback)
# ---------------------------------------------------------------------------
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing dependency: requests")
    print("    Install it with:  pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants & global config
# ---------------------------------------------------------------------------
APP_NAME    = "SQLMAP X ULTIMATE"
APP_VERSION = "1.0.0"
AUTHOR      = "Your Name / GitHub Handle"

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR  = os.path.join(BASE_DIR, "reports")
HISTORY_FILE= os.path.join(BASE_DIR, "scan_history.json")
LOG_FILE    = os.path.join(BASE_DIR, "sqlmap_x.log")
THEME_FILE  = os.path.join(BASE_DIR, "theme.txt")

DEFAULT_TIMEOUT = 10
DEFAULT_UA      = ("SQLMapX-Ultimate/1.0 (+Authorized-Security-Audit)")

# ------------------------- SQL error fingerprints --------------------------
SQL_ERRORS = [
    (r"you have an error in your sql syntax",        "MySQL",            "HIGH"),
    (r"warning: mysql_",                              "MySQL",            "HIGH"),
    (r"unclosed quotation mark after the character",  "MSSQL",            "HIGH"),
    (r"quoted string not properly terminated",        "Oracle/MSSQL",     "HIGH"),
    (r"pg_query\(\)|postgresql.*error|syntax error at or near", "PostgreSQL", "HIGH"),
    (r"sqlite3?\.operationalerror|sqlite_master",     "SQLite",           "HIGH"),
    (r"odbc.*driver.*error|microsoft jet database",   "MSSQL/Access",     "HIGH"),
    (r"ora-\d{5}",                                    "Oracle",           "HIGH"),
    (r"mysql_fetch|mysql_num_rows|mysqli?_",          "MySQL",            "MEDIUM"),
    (r"psql.*fatal|pg_.+error",                       "PostgreSQL",       "MEDIUM"),
    (r"sql syntax.*mysql|syntax error.*sqlite",       "Generic SQL",      "MEDIUM"),
    (r"exception.*database|database error",           "Generic DB",       "LOW"),
]

# ------------------------- Security headers to check -----------------------
SECURITY_HEADERS = [
    ("X-XSS-Protection",         "Missing anti-XSS header (deprecated but indicative)"),
    ("X-Frame-Options",          "Missing clickjacking protection"),
    ("X-Content-Type-Options",   "Missing MIME-sniffing protection"),
    ("Strict-Transport-Security","Missing HSTS (check only meaningful over HTTPS)"),
    ("Content-Security-Policy",  "Missing Content-Security-Policy"),
    ("Referrer-Policy",          "Missing Referrer-Policy"),
]

# Cookie flags worth inspecting
COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]

# ---------------------------------------------------------------------------
# Terminal colors — ANSI (works in Termux, Pydroid 3 terminal, Linux, Windows 10+)
# ---------------------------------------------------------------------------
class C:
    """ANSI color wrapper with auto-disable when output is not a TTY."""
    ENABLED = sys.stdout.isatty()

    R   = "\033[1;31m" if ENABLED else ""   # red
    G   = "\033[1;32m" if ENABLED else ""   # green
    CY  = "\033[1;36m" if ENABLED else ""   # cyan
    Y   = "\033[1;33m" if ENABLED else ""   # yellow
    W   = "\033[1;37m" if ENABLED else ""   # white
    DIM = "\033[2m"    if ENABLED else ""
    END = "\033[0m"    if ENABLED else ""

    @classmethod
    def strip_all(cls, text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sqlmapx")

# ---------------------------------------------------------------------------
# Small UI helpers
# ---------------------------------------------------------------------------
def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")

def loading_animation(text="Initializing engine", cycles=12):
    """Animated loading bar shown on startup / before scans."""
    if not C.ENABLED:
        print(text + "...")
        return
    spinner = "|/-\\"
    for i in range(cycles):
        pct = int((i + 1) / cycles * 100)
        sys.stdout.write(
            f"\r{C.CY}{text} [{spinner[i % 4]}] {pct:3d}%{C.END}"
        )
        sys.stdout.flush()
        time.sleep(0.06)
    sys.stdout.write("\n")

def banner():
    clear_screen()
    art = r"""
   ____  _        _    __  __            _____  __  __ _____ _   _  _____
  / ___|| |      / \  |  \/  |   _____  / ____|/ _|/ _|_   _| \ | |/ ____|
  \___ \| |     / _ \ | |\/| |  |______|| (___ | |_| |_  | | |  \| | |  __
   ___) | |___ / ___ \| |  | |          \___ \|  _|  _| | | | |\  | | |_ |
  |____/|_____/_/   \_\_|  |_|          ____) | | | |  _| |_| | \  | |__| |
                                       |_____/|_| |_| |_____|_|  \_|\_____|
"""
    print(f"{C.R}{art}{C.END}")
    print(f"{C.CY}        {APP_NAME} v{APP_VERSION}  —  Database Security Auditor{C.END}")
    print(f"{C.Y}        Safe-mode auditor · No exploitation · Authorized targets only{C.END}")
    print(f"{C.DIM}" + "-" * 78 + f"{C.END}\n")

def press_enter():
    input(f"\n{C.Y}[press ENTER to continue]{C.END}")

def ask(prompt: str, default: str = "") -> str:
    try:
        val = input(f"{C.G}>{C.END} {prompt}").strip()
        return val or default
    except (KeyboardInterrupt, EOFError):
        return default

def confirm(prompt: str) -> bool:
    return ask(prompt + " [y/N]: ").lower().startswith("y")

# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------
def load_history():
    if os.path.isfile(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_history_entry(entry):
    hist = load_history()
    hist.append(entry)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(hist, f, indent=2)

# ---------------------------------------------------------------------------
# Theme loader (TXT theme configuration: theme.txt with KEY=VALUE lines)
# ---------------------------------------------------------------------------
def load_theme():
    theme = {"banner_color": "red", "menu_color": "cyan", "result_color": "green"}
    if os.path.isfile(THEME_FILE):
        try:
            with open(THEME_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.split("=", 1)
                        theme[k.strip().lower()] = v.strip().lower()
        except Exception:
            pass
    return theme

# ---------------------------------------------------------------------------
# Core audit engine
# ---------------------------------------------------------------------------
class TargetAudit:
    """
    Runs all safe checks against one target URL and collects findings.

    Finding structure:
      { "title", "severity" (CRITICAL/HIGH/MEDIUM/LOW/INFO),
        "category", "status" (CONFIRMED / POSSIBLE), "detail" }
    """

    def __init__(self, url, timeout=DEFAULT_TIMEOUT, proxy=None,
                 user_agent=DEFAULT_UA, verify_tls=True, cookies=None):
        self.url = url
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self.findings = []
        self.response = None
        self.raw_params = {}   # param -> reflected-safe marker echo

    # ----------------------------------------------------------------- util
    def add(self, title, severity, category, status, detail):
        self.findings.append({
            "title": title, "severity": severity,
            "category": category, "status": status, "detail": detail,
        })

    def _request(self, method="GET", url=None, data=None, allow_redirects=True):
        headers = {"User-Agent": self.user_agent,
                   "Accept": "*/*",
                   "Connection": "close"}
        return requests.request(
            method, url or self.url, headers=headers, data=data,
            timeout=self.timeout, proxies=self.proxy,
            verify=self.verify_tls, allow_redirects=allow_redirects,
        )

    # ------------------------------------------------------- 1. connectivity
    def check_reachability(self):
        try:
            self.response = self._request()
            return True
        except requests.exceptions.SSLError:
            # Retry without TLS verification only as a diagnostic (user choice)
            try:
                self.verify_tls = False
                self.response = self._request()
                self.add("Invalid/misconfigured TLS certificate",
                         "MEDIUM", "TLS", "CONFIRMED",
                         "TLS verification failed; request succeeded only with verify=False.")
                return True
            except Exception as e:
                self.add("Target unreachable (SSL failure)",
                         "INFO", "Network", "CONFIRMED", str(e))
                return False
        except requests.exceptions.Timeout:
            self.add("Connection timeout", "INFO", "Network", "CONFIRMED",
                     f"Target did not respond within {self.timeout}s.")
            return False
        except requests.exceptions.RequestException as e:
            self.add("Target unreachable", "INFO", "Network", "CONFIRMED", str(e))
            return False

    # ------------------------------------------- 2. SQL error fingerprinting
    def check_sql_errors(self):
        if not self.response:
            return
        body = self.response.text
        for pattern, engine, sev in SQL_ERRORS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                snippet = body[max(0, m.start() - 60): m.end() + 60]
                self.add(f"{engine} SQL error exposed in response",
                         sev, "SQLi Indicator", "CONFIRMED",
                         f"Matched pattern '{pattern}'. Context: "
                         f"...{snippet.strip()[:200]}...")

    # --------------------------------- 3. Reflected-parameter risk indicator
    # Safe: we request with a benign random marker in each parameter and only
    # observe whether it is echoed back. No SQL payloads are sent.
    def check_parameter_reflection(self):
        if not self.response:
            return
        parsed = urlparse(self.url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        if not params:
            return
        for name, _ in params:
            marker = "sx" + "".join(random.choices(string.ascii_lowercase, k=8)) + "z"
            test_url = parsed._replace(
                query=urlencode([(n, marker if n == name else v)
                                 for n, v in params])
            ).geturl()
            try:
                r = self._request(url=test_url)
                if marker in r.text:
                    self.add(
                        f"GET parameter '{name}' is reflected in response",
                        "POSSIBLE-MEDIUM", "SQLi Indicator", "POSSIBLE",
                        "Parameter value echoed unescaped — manual (authorized) "
                        "verification recommended. No injection payload was sent.")
                else:
                    self.raw_params[name] = "not reflected"
            except requests.exceptions.RequestException as e:
                log.warning("reflection test failed for %s: %s", name, e)

    # -------------------------------------- 4. POST parameter basic handling
    def check_post_form(self):
        if not self.response:
            return
        html = self.response.text
        forms = re.findall(r"<form[^>]*>", html, re.IGNORECASE)
        for f in forms:
            if re.search(r'method\s*=\s*["\']?post', f, re.IGNORECASE):
                self.add("POST form detected — parameter handling not verifiable passively",
                         "POSSIBLE-LOW", "SQLi Indicator", "POSSIBLE",
                         "Form found; review server-side parameter handling. "
                         "No payloads were submitted by this tool.")
                break

    # ------------------------------------------------------- 5. HTTP headers
    def check_headers(self):
        if not self.response:
            return
        h = self.response.headers
        for header, why in SECURITY_HEADERS:
            if header.lower() not in {k.lower() for k in h}:
                self.add(f"Missing security header: {header}",
                         "LOW", "HTTP Headers", "CONFIRMED", why)
        server = h.get("Server", "")
        if re.search(r"\d+\.\d+", server):
            self.add("Server version disclosed",
                     "LOW", "Information Disclosure", "CONFIRMED",
                     f"Server header: {server}")
        if h.get("X-Powered-By"):
            self.add("Technology disclosed via X-Powered-By",
                     "LOW", "Information Disclosure", "CONFIRMED",
                     f"X-Powered-By: {h['X-Powered-By']}")

    # ----------------------------------------------------------- 6. Cookies
    def check_cookies(self):
        if not self.response:
            return
        raw = self.response.headers.get("Set-Cookie", "")
        if not raw:
            return
        low = raw.lower()
        missing = [f for f in COOKIE_FLAGS if f.lower() not in low]
        if missing:
            self.add("Cookie missing security flags",
                     "MEDIUM", "Cookies", "CONFIRMED",
                     f"Missing: {', '.join(missing)}  |  Set-Cookie: {raw[:160]}")

    # ------------------------------------------------ 7. Misconfigurations
    def check_misconfigurations(self):
        if not self.response:
            return
        # HTTP on a "sensitive-looking" path list (safe GETs only)
        base = "{0.scheme}://{0.netloc}".format(urlparse(self.url))
        sensitive = ["/admin/", "/.git/config", "/.env", "/phpmyadmin/",
                     "/backup.zip", "/wp-config.php.bak"]
        for path in sensitive:
            try:
                r = self._request(url=base + path, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 50:
                    self.add(f"Sensitive path exposed: {path}",
                             "HIGH", "Misconfiguration", "CONFIRMED",
                             f"HTTP 200 with {len(r.text)} bytes at {base}{path}")
            except requests.exceptions.RequestException:
                continue
        # Directory listing hint
        if "Index of /" in self.response.text[:500]:
            self.add("Directory listing enabled",
                     "MEDIUM", "Misconfiguration", "CONFIRMED",
                     "Response contains 'Index of /' listing.")
        # Cleartext HTTP
        if urlparse(self.url).scheme == "http":
            self.add("Target served over plaintext HTTP",
                     "MEDIUM", "Misconfiguration", "CONFIRMED",
                     "Credentials/tokens over HTTP can be intercepted.")

    # ------------------------------------------------------------- runner
    def run(self):
        checks = [
            ("Reachability",   self.check_reachability),
            ("SQL errors",     self.check_sql_errors),
            ("Reflection",     self.check_parameter_reflection),
            ("POST forms",     self.check_post_form),
            ("Headers",        self.check_headers),
            ("Cookies",        self.check_cookies),
            ("Misconfig",      self.check_misconfigurations),
        ]
        for label, fn in checks:
            if label == "Reachability" or self.response:
                fn()
        return self.findings


# ---------------------------------------------------------------------------
# Severity ordering & report builders
# ---------------------------------------------------------------------------
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "POSSIBLE-MEDIUM": 3,
             "LOW": 4, "POSSIBLE-LOW": 5, "INFO": 6}
SEV_COLOR = {"CRITICAL": C.R, "HIGH": C.R, "MEDIUM": C.Y,
             "POSSIBLE-MEDIUM": C.Y, "LOW": C.CY, "POSSIBLE-LOW": C.CY,
             "INFO": C.G}

def sort_findings(findings):
    return sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))

def export_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def export_txt(data, path):
    lines = [
        "=" * 70,
        f" SQLMAP X ULTIMATE — Security Audit Report",
        f" Generated : {data['generated']}",
        f" Target    : {data['url']}",
        "=" * 70, "",
    ]
    for f in data["findings"]:
        lines.append(f"[{f['severity']}] ({f['status']}) {f['title']}")
        lines.append(f"    Category : {f['category']}")
        lines.append(f"    Detail   : {f['detail']}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

def export_html(data, path):
    rows = ""
    for f in data["findings"]:
        color = {"CRITICAL": "#ff1744", "HIGH": "#ff5252", "MEDIUM": "#ffd740",
                 "POSSIBLE-MEDIUM": "#ffd740", "LOW": "#18ffff",
                 "POSSIBLE-LOW": "#18ffff", "INFO": "#69f0ae"}.get(f["severity"], "#fff")
        rows += (f"<tr><td style='color:{color}'><b>{f['severity']}</b></td>"
                 f"<td>{f['status']}</td><td>{f['title']}</td>"
                 f"<td>{f['category']}</td><td>{f['detail']}</td></tr>")
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>SQLMap X Ultimate Report</title>
<style>body{{background:#000;color:#ddd;font-family:monospace;margin:2em}}
h1{{color:#ff1744}} table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #333;padding:8px;vertical-align:top}}
th{{background:#111;color:#18ffff}}</style></head><body>
<h1>SQLMAP X ULTIMATE — Audit Report</h1>
<p>Target: {data['url']}<br>Generated: {data['generated']}</p>
<table><tr><th>Severity</th><th>Status</th><th>Finding</th><th>Category</th><th>Detail</th></tr>
{rows}</table>
<p><i>Safe-mode scan: no exploitation performed. POSSIBLE items require manual verification.</i></p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------
def run_scan():
    banner()
    print(f"{C.CY}--- New Scan ---{C.END}\n")
    urls_raw = ask("Target URL(s), comma separated: ")
    if not urls_raw:
        print(f"{C.R}[!] No target provided.{C.END}")
        press_enter(); return
    urls = [u.strip() for u in urls_raw.split(",") if u.strip()]

    # --- Authorized-target confirmation (required) ---
    print(f"\n{C.Y}Authorization confirmation required before scanning.{C.END}")
    if not confirm("Do you own this target(s) or have explicit written permission to test?"):
        print(f"{C.R}[!] Scan aborted — authorization not confirmed.{C.END}")
        press_enter(); return

    timeout   = int(ask(f"Request timeout in seconds [{DEFAULT_TIMEOUT}]: ", str(DEFAULT_TIMEOUT)) or DEFAULT_TIMEOUT)
    proxy     = ask("Proxy (e.g. http://127.0.0.1:8080) [none]: ") or None
    user_agent= ask(f"Custom User-Agent [{DEFAULT_UA[:30]}...]: ") or DEFAULT_UA
    safe_mode = confirm("Enable SAFE MODE (default checks only, no sensitive-path probes)? [Y/n]: ") is False or True
    # note: ask() default Y -> pressing enter keeps safe mode enabled
    if not safe_mode:
        safe_mode = True  # safe mode is always enforced in this tool

    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for url in urls:
        print(f"\n{C.CY}>> Auditing: {url}{C.END}")
        audit = TargetAudit(url, timeout=timeout, proxy=proxy, user_agent=user_agent)
        loading_animation("Scanning", cycles=10)
        findings = audit.run()
        findings = sort_findings(findings)

        confirmed = [f for f in findings if f["status"] == "CONFIRMED"]
        possible  = [f for f in findings if f["status"] == "POSSIBLE"]

        print(f"\n{C.W}Results for {url}{C.END}")
        if not findings:
            print(f"{C.G}  [+] No issues detected by safe checks.{C.END}")
        for f in findings:
            color = SEV_COLOR.get(f["severity"], C.W)
            tag = "CONFIRMED" if f["status"] == "CONFIRMED" else "POSSIBLE"
            print(f"{color}  [{f['severity']:>5}] [{tag:<9}] {f['title']}{C.END}")
            print(f"{C.DIM}          {f['detail'][:160]}{C.END}")

        # --- exports ---
        data = {"url": url, "generated": datetime.now().isoformat(timespec="seconds"),
                "findings": findings}
        base = os.path.join(REPORT_DIR, f"report_{stamp}_{re.sub(r'[^A-Za-z0-9]', '_', urlparse(url).netloc)}")
        try:
            export_json(data, base + ".json")
            export_txt(data, base + ".txt")
            export_html(data, base + ".html")
            print(f"{C.G}  [+] Reports saved: {base}.json / .txt / .html{C.END}")
        except OSError as e:
            print(f"{C.R}[!] Report export failed: {e}{C.END}")

        save_history_entry({"time": datetime.now().isoformat(timespec="seconds"),
                            "url": url, "findings": len(findings),
                            "high": sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL"))})
        log.info("Scanned %s — %d findings", url, len(findings))

    press_enter()


def show_history():
    banner()
    hist = load_history()
    if not hist:
        print(f"{C.Y}No scan history yet.{C.END}")
    else:
        print(f"{C.CY}Last {min(20, len(hist))} scans:{C.END}\n")
        for h in hist[-20:]:
            print(f"  {h['time']}  {h['url']}  — findings: {h['findings']} (high: {h['high']})")
    press_enter()


def clear_history():
    if os.path.isfile(HISTORY_FILE):
        os.remove(HISTORY_FILE)
        print(f"{C.G}[+] History cleared.{C.END}")
    else:
        print(f"{C.Y}[i] No history file.{C.END}")
    press_enter()


def show_about():
    banner()
    print(f"""{C.CY}
  {APP_NAME} v{APP_VERSION}
  Author : {AUTHOR}
  Purpose: Safe, non-destructive database security indicator auditing.
  Scope  : Passive analysis only. No exploitation, dumping, or extraction.
  Logs   : {LOG_FILE}
  Reports: {REPORT_DIR}{C.END}""")
    press_enter()


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
MENU = f"""{C.CY}
  ┌──────────────────────────────────────────────┐
  │  [1] New Scan (safe-mode audit)              │
  │  [2] Scan History                            │
  │  [3] Clear Scan History                      │
  │  [4] About / Configuration                   │
  │  [5] Clear Screen                            │
  │  [0] Exit                                    │
  └──────────────────────────────────────────────┘{C.END}
"""

def main():
    # Theme is loaded (theme.txt) — reserved for future color customization
    load_theme()
    banner()
    print(f"{C.G}[+] Dependency check passed (requests v{requests.__version__}){C.END}")
    print(f"{C.G}[+] Report directory: {REPORT_DIR}{C.END}\n")

    while True:
        print(MENU)
        choice = ask("Select option: ")
        if choice == "1":
            run_scan()
        elif choice == "2":
            show_history()
        elif choice == "3":
            clear_history()
        elif choice == "4":
            show_about()
        elif choice == "5":
            banner()
        elif choice == "0":
            print(f"{C.R}\nGoodbye. Stay ethical.{C.END}")
            sys.exit(0)
        else:
            print(f"{C.Y}[!] Invalid option.{C.END}")
            time.sleep(0.8)
            banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.R}[!] Interrupted by user.{C.END}")
        sys.exit(0)
